import json
import csv
import random
import string
import os.path
import tempfile
import humanize
import time
import requests
from datetime import datetime
from collections import OrderedDict

from django.shortcuts import render
from django.shortcuts import redirect
from django.template import loader
from django.urls import reverse
from django.http import HttpResponse
from django.http import StreamingHttpResponse
from django.http import FileResponse
from django.http import Http404
from django.contrib.auth.decorators import login_required
from django.middleware.csrf import get_token
from django.db.models import Q, Count, BinaryField
from django.db.models.functions import Cast
from django.db import connection
from django.contrib import messages
from django.db.utils import OperationalError
from django.contrib.admin.views.decorators import staff_member_required

from django.shortcuts import get_object_or_404

from operator import itemgetter

from Nodes.models import Node
from .models import Hashfile, Session, Hash, Search

from Utils.hashcatAPI import HashcatAPI
from Utils.hashcat import Hashcat
from Utils.utils import init_hashfile_locks
from Utils.utils import Echo
from Utils.tasks import import_hashfile_task, run_search_task
# Create your views here.

@login_required
def dashboard(request):
    context = {}
    context["Section"] = "Dashboard"

    template = loader.get_template('Hashcat/dashboard.html')
    return HttpResponse(template.render(context, request))

@login_required
def hashfiles(request):
    context = {}
    context["Section"] = "Hashes"

    if request.method == 'POST':
        if request.POST["action"] == "add":
            hash_type=int(request.POST["hash_type"])

            hashfile_name = ''.join(random.choice(string.ascii_uppercase + string.digits) for _ in range(12)) + ".hashfile"
            hashfile_path = os.path.join(os.path.dirname(__file__), "..", "Files", "Hashfiles", hashfile_name)

            hashes = request.POST["hashes"]
            f = open(hashfile_path, 'w')
            if len(hashes) == 0 and "hashfile" in request.FILES:
                for chunk in request.FILES['hashfile'].chunks():
                    f.write(chunk.decode('UTF-8', 'backslashreplace'))
            else:
                f.write(hashes.strip())
            f.close()

            username_included = "username_included" in request.POST

            hashfile = Hashfile(
                owner=request.user,
                name=request.POST['name'],
                hashfile=hashfile_name,
                hash_type=hash_type,
                line_count=0,
                cracked_count = 0,
                username_included=username_included,
            )
            hashfile.save()
            init_hashfile_locks(hashfile)

            # Update the new file with the potfile, this may take a while, but it is processed in a background task
            import_hashfile_task.delay(hashfile.id)

            if hash_type != -1: # if != plaintext
                messages.success(request, "Hashfile successfully added")
            else:
                messages.success(request, "Plaintext file successfully added")

    context["node_list"] = Node.objects.all()
    context["hash_type_list"] = [{'id': -1, 'name': 'Plaintext'}] + sorted(list(Hashcat.get_hash_types().values()), key=itemgetter('name'))
    context["rule_list"] = [{'name': None}] + sorted(Hashcat.get_rules(detailed=False), key=itemgetter('name'))
    context["mask_list"] = sorted(Hashcat.get_masks(detailed=False), key=itemgetter('name'))
    context["wordlist_list"] = sorted(Hashcat.get_wordlists(detailed=False), key=itemgetter('name'))

    template = loader.get_template('Hashcat/hashes.html')
    return HttpResponse(template.render(context, request))

@login_required
def search(request):
    context = {}
    context["Section"] = "Search"

    context["hashfile_list"] = Hashfile.objects.order_by('name')
    if request.method == 'POST':
        search_info = {}
        if len(request.POST["search_pattern"]) != 0:
            search_info["pattern"] = request.POST["search_pattern"]

        hashfile_list = []
        if "all_hashfiles" in request.POST:
            for hashfile in Hashfile.objects.all():
                if hashfile.owner == request.user or request.user.is_staff:
                    hashfile_list.append(hashfile.id)
        else:
            for hashfile_id in request.POST.getlist("hashfile_search[]"):
                hashfile = Hashfile.objects.get(id=int(hashfile_id))

                if hashfile != None:
                    if hashfile.owner == request.user or request.user.is_staff:
                        hashfile_list.append(int(hashfile_id))
        search_info["hashfiles"] = hashfile_list

        if "ignore_uncracked" in request.POST:
            search_info["ignore_uncracked"] = True

        print(search_info)

        search_filename = ''.join(random.choice(string.ascii_uppercase + string.digits) for _ in range(12)) + ".csv"
        output_file = os.path.join(os.path.dirname(__file__), "..", "Files", "Searches", search_filename)

        search = Search(
            owner=request.user,
            name=request.POST['search_name'],
            status="Starting",
            output_lines=None,
            output_file=output_file,
            json_search_info=json.dumps(search_info),
        )
        search.save()

        run_search_task.delay(search.id)

    template = loader.get_template('Hashcat/search.html')
    return HttpResponse(template.render(context, request))

@login_required
@staff_member_required
def files(request):
    context = {}
    context["Section"] = "Files"

    if request.method == 'POST':
        if request.POST["action"] == "remove":
            if request.POST["filetype"] == "rule":
                Hashcat.remove_rule(request.POST["filename"])
            elif request.POST["filetype"] == "mask":
                Hashcat.remove_mask(request.POST["filename"])
            elif request.POST["filetype"] == "wordlist":
                Hashcat.remove_wordlist(request.POST["filename"])

    context["rule_list"] = Hashcat.get_rules()
    context["mask_list"] = Hashcat.get_masks()
    context["wordlist_list"] = Hashcat.get_wordlists()

    template = loader.get_template('Hashcat/files.html')
    return HttpResponse(template.render(context, request))

@login_required
def new_session(request):
    if request.method == 'POST':
        #session_name = request.POST["name"]

        node_name = request.POST["node"]
        node = get_object_or_404(Node, name=node_name)

        hashfile = get_object_or_404(Hashfile, id=request.POST['hashfile_id'])

        # Check if the user owns the Hashfile or Staff
        if request.user != hashfile.owner and not request.user.is_staff:
            raise Http404("You do not have permission to view this object")

        crack_type = request.POST["crack_type"]
        if crack_type == "dictionary":
            rule = request.POST["rule"] if request.POST["rule"] != "None" else None
            wordlist = request.POST["wordlist"]
        elif crack_type == "mask":
            mask = request.POST["mask"]

        device_type = int(request.POST["device_type"])
        brain_mode = int(request.POST["brain_mode"])

        if request.POST["end_datetime"]:
            end_timestamp = int(datetime.strptime(request.POST["end_datetime"], "%m/%d/%Y %I:%M %p").timestamp())
        else:
            end_timestamp = None

        session_name = ("%s-%s" % (hashfile.name, ''.join(random.choice(string.ascii_uppercase + string.digits) for _ in range(12)))).replace(" ", "_")

        if "debug" in request.POST:
            hashcat_debug_file = True
        else:
            hashcat_debug_file = False

        try:
            hashcat_api = HashcatAPI(node.hostname, node.port, node.username, node.password)
            if crack_type == "dictionary":
                res = hashcat_api.create_dictionary_session(session_name, hashfile, rule, wordlist, device_type, brain_mode, end_timestamp, hashcat_debug_file)
            elif crack_type == "mask":
                res = hashcat_api.create_mask_session(session_name, hashfile, mask, device_type, brain_mode, end_timestamp, hashcat_debug_file)
        except requests.exceptions.ConnectionError: 
            messages.error(request, "Node %s not accessible" % node_name)
            return redirect('Hashcat:hashfiles')

        if res["response"] == "error":
            messages.error(request, res["message"])
            return redirect('Hashcat:hashfiles')

        messages.success(request, "Session successfully created")

        session = Session(
                name=session_name,
                hashfile=hashfile,
                node = node,
                potfile_line_retrieved=0,
        )
        session.save()

    return redirect('Hashcat:hashfiles')

@login_required
@staff_member_required
def upload_rule(request):
    if request.method == 'POST':
        name = request.POST["name"]

        if "file" in request.FILES:
            # get from file
            f = request.FILES["file"]
            rule_file = f.read()

            Hashcat.upload_rule(name, rule_file)

    return redirect('Hashcat:files')

@login_required
@staff_member_required
def upload_mask(request):
    if request.method == 'POST':
        name = request.POST["name"]

        if "file" in request.FILES:
            # get from file
            f = request.FILES["file"]
            mask_file = f.read()

            Hashcat.upload_mask(name, mask_file)


    return redirect('Hashcat:files')

@login_required
@staff_member_required
def upload_wordlist(request):
    if request.method == 'POST':
        name = request.POST["name"]

        if "file" in request.FILES:
            # get from file
            f = request.FILES["file"]
            wordlist_file = f.read()

            Hashcat.upload_wordlist(name, wordlist_file)

    return redirect('Hashcat:files')

@login_required
def hashfile(request, hashfile_id, error_msg=''):
    context = {}
    context["Section"] = "Hashfile"

    hashfile = get_object_or_404(Hashfile, id=hashfile_id)

    # Check if the user owns the Hashfile or Staff
    if request.user != hashfile.owner and not request.user.is_staff:
        raise Http404("You do not have permission to view this object")

    context['hashfile'] = hashfile
    context['lines'] = humanize.intcomma(hashfile.line_count)
    context['recovered'] = "%s (%.2f%%)" % (humanize.intcomma(hashfile.cracked_count), hashfile.cracked_count/hashfile.line_count*100) if hashfile.line_count != 0 else "0"
    context['hash_type'] = "Plaintext" if hashfile.hash_type == -1 else Hashcat.get_hash_types()[hashfile.hash_type]["name"]

    template = loader.get_template('Hashcat/hashfile.html')
    return HttpResponse(template.render(context, request))

@login_required
def export_cracked(request, hashfile_id):
    hashfile = get_object_or_404(Hashfile, id=hashfile_id)

    # Check if the user owns the Hashfile or Staff
    if request.user != hashfile.owner and not request.user.is_staff:
        raise Http404("You do not have permission to view this object")

    cracked_hashes = Hash.objects.filter(hashfile_id=hashfile.id, password__isnull=False)

    if hashfile.username_included:
        response = StreamingHttpResponse(("%s:%s\n" % (item.username, item.password) for item in cracked_hashes), content_type="text/txt")
    else:
        response = StreamingHttpResponse(("%s:%s\n" % (item.hash, item.password) for item in cracked_hashes), content_type="text/txt")

    response['Content-Disposition'] = 'attachment; filename="cracked.txt"'
    return response

@login_required
def export_uncracked(request, hashfile_id):
    hashfile = get_object_or_404(Hashfile, id=hashfile_id)

    # Check if the user owns the Hashfile or Staff
    if request.user != hashfile.owner and not request.user.is_staff:
        raise Http404("You do not have permission to view this object")



    uncracked_hashes = Hash.objects.filter(hashfile_id=hashfile.id, password__isnull=True)

    if hashfile.username_included:
        response = StreamingHttpResponse(("%s:%s\n" % (item.username, item.hash) for item in uncracked_hashes), content_type="text/txt")
    else:
        response = StreamingHttpResponse(("%s\n" % (item.hash,) for item in uncracked_hashes), content_type="text/txt")

    response['Content-Disposition'] = 'attachment; filename="uncracked.txt"'
    return response

@login_required
def csv_masks(request, hashfile_id):
    hashfile = get_object_or_404(Hashfile, id=hashfile_id)

    # Check if the user owns the Hashfile or Staff
    if request.user != hashfile.owner and not request.user.is_staff:
        raise Http404("You do not have permission to view this object")

    # didn't found the correct way in pure django...
    rows = Hash.objects.raw("SELECT 1 AS id, MAX(password_mask) AS password_mask, COUNT(*) AS count FROM Hashcat_hash WHERE hashfile_id=%s AND password_mask IS NOT NULL GROUP BY password_mask ORDER BY count DESC", [hashfile.id])

    pseudo_buffer = Echo()
    writer = csv.writer(pseudo_buffer)

    response = StreamingHttpResponse((writer.writerow([item.password_mask, item.count]) for item in rows), content_type="text/csv")

    response['Content-Disposition'] = 'attachment; filename="masks.csv"'
    return response

@login_required
def export_search(request, search_id):
    search = get_object_or_404(Search, id=search_id)

    # Check if the user owns the Hashfile or Staff
    if request.user != search.owner and not request.user.is_staff:
        raise Http404("You do not have permission to view this object")

    response = FileResponse(open(search.output_file, 'rb'), content_type="text/csv")

    response['Content-Disposition'] = 'attachment; filename="search.csv"'
    return response



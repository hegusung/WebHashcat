import json
import csv
import random
import string
import os.path
import tempfile
import humanize
import time
from collections import OrderedDict

from django.shortcuts import render
from django.shortcuts import redirect
from django.template import loader
from django.urls import reverse
from django.http import HttpResponse
from django.contrib.auth.decorators import login_required
from django.middleware.csrf import get_token
from django.db.models import Q, Count, BinaryField
from django.db.models.functions import Cast
from django.db import connection
from django.contrib import messages
from django.db.utils import OperationalError

from django.shortcuts import get_object_or_404

from operator import itemgetter

from Nodes.models import Node
from .models import Hashfile, Session, Cracked

from Utils.hashcatAPI import HashcatAPI
from Utils.hashcat import Hashcat
from Utils.utils import init_hashfile_locks
# Create your views here.

@login_required
def hashfiles(request):
    context = {}
    context["Section"] = "Hashes"

    if request.method == 'POST':
        if request.POST["action"] == "add":
            hashfile_name = ''.join(random.choice(string.ascii_uppercase + string.digits) for _ in range(12)) + ".hashfile"
            crackedfile_name = ''.join(random.choice(string.ascii_uppercase + string.digits) for _ in range(12)) + ".crackedfile"

            hashfile_path = os.path.join(os.path.dirname(__file__), "..", "Files", "Hashfiles", hashfile_name)
            crackedfile_path = os.path.join(os.path.dirname(__file__), "..", "Files", "Crackedfiles", crackedfile_name)

            hashes = request.POST["hashes"]
            f = open(hashfile_path, 'w')
            if len(hashes) == 0 and "hashfile" in request.FILES:
                f.write(request.FILES['hashfile'].read().decode())
            else:
                f.write(hashes.strip())
            f.close()

            hash_type=int(request.POST["hash_type"])
            username_included = "username_included" in request.POST

            line_count = sum(1 for _ in open(hashfile_path, errors="backslashreplace"))

            hashfile = Hashfile(
                name=request.POST['name'],
                hashfile=hashfile_name,
                crackedfile=crackedfile_name,
                hash_type=hash_type,
                line_count=line_count,
                cracked_count = 0,
                username_included=username_included,
            )
            hashfile.save()
            init_hashfile_locks(hashfile)

            # Update the new file with the potfile, this may take a while
            updated = False
            while not updated:
                try:
                    Hashcat.compare_potfile(hashfile)
                    updated = True
                except OperationalError:
                    # db locked, try again !!!
                    pass

            messages.success(request, "Hashfile successfully added")

    context["node_list"] = Node.objects.all()
    context["hash_type_list"] = Hashcat.get_hash_types().values()
    context["rule_list"] = [{'name': None}] + Hashcat.get_rules(detailed=False)
    context["mask_list"] = Hashcat.get_masks(detailed=False)
    context["wordlist_list"] = Hashcat.get_wordlists(detailed=False)

    template = loader.get_template('Hashcat/hashes.html')
    return HttpResponse(template.render(context, request))

@login_required
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

        crack_type = request.POST["crack_type"]
        if crack_type == "dictionary":
            rule = request.POST["rule"] if request.POST["rule"] != "None" else None
            wordlist = request.POST["wordlist"]
        elif crack_type == "mask":
            mask = request.POST["mask"]

        session_name = ("%s-%s" % (hashfile.name, ''.join(random.choice(string.ascii_uppercase + string.digits) for _ in range(12)))).replace(" ", "_")

        hashcat_api = HashcatAPI(node.hostname, node.port, node.username, node.password)
        if crack_type == "dictionary":
            res = hashcat_api.create_dictionary_session(session_name, hashfile, rule, wordlist)
        elif crack_type == "mask":
            res = hashcat_api.create_mask_session(session_name, hashfile, mask)

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

    context['hashfile'] = hashfile
    context['lines'] = humanize.intcomma(hashfile.line_count)
    context['recovered'] = "%s (%.2f%%)" % (humanize.intcomma(hashfile.cracked_count), hashfile.cracked_count/hashfile.line_count*100)
    context['hash_type'] = Hashcat.get_hash_types()[hashfile.hash_type]["name"]

    template = loader.get_template('Hashcat/hashfile.html')
    return HttpResponse(template.render(context, request))

@login_required
def export_cracked(request, hashfile_id):
    hashfile = get_object_or_404(Hashfile, id=hashfile_id)

    crackedfile_path = os.path.join(os.path.dirname(__file__), "..", "Files", "Crackedfiles", hashfile.crackedfile)
    cracked_hashes = open(crackedfile_path).read()

    response = HttpResponse(cracked_hashes, content_type='application/force-download') # mimetype is replaced by content_type for django 1.7
    response['Content-Disposition'] = 'attachment; filename=%s_cracked.txt' % hashfile.name.replace(" ", "_")
    return response

@login_required
def export_uncracked(request, hashfile_id):
    hashfile = get_object_or_404(Hashfile, id=hashfile_id)

    uncrackedfile_path = os.path.join(os.path.dirname(__file__), "..", "Files", "Hashfiles", hashfile.hashfile)
    uncracked_hashes = open(uncrackedfile_path).read()

    response = HttpResponse(uncracked_hashes, content_type='application/force-download') # mimetype is replaced by content_type for django 1.7
    response['Content-Disposition'] = 'attachment; filename=%s_uncracked.txt' % hashfile.name.replace(" ", "_")
    return response

@login_required
def csv_masks(request, hashfile_id):
    hashfile = get_object_or_404(Hashfile, id=hashfile_id)

    # didn't found the correct way in pure django...
    res = Cracked.objects.raw("SELECT id, password_mask, COUNT(*) AS count FROM Hashcat_cracked USE INDEX (hashfileid_id_index) WHERE hashfile_id=%s GROUP BY password_mask ORDER BY count DESC", [hashfile.id])

    fp = tempfile.SpooledTemporaryFile(mode='w')
    csvfile = csv.writer(fp, quotechar='"', quoting=csv.QUOTE_ALL)
    for item in res:
        csvfile.writerow([item.count, item.password_mask])
    fp.seek(0)   # rewind the file handle

    csvfile_data = fp.read()

    for query in connection.queries[-1:]:
        print(query["sql"])
        print(query["time"])

    response = HttpResponse(csvfile_data, content_type='application/force-download') # mimetype is replaced by content_type for django 1.7
    response['Content-Disposition'] = 'attachment; filename=%s_masks.csv' % hashfile.name
    return response

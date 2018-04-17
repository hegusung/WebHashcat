import json
import csv
import random
import string
import os
import os.path
import tempfile
import humanize
import time
import traceback
import datetime
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
from django.db.models import Sum

from django.shortcuts import get_object_or_404

from operator import itemgetter

from Hashcat.models import Hashfile, Session, Hash, Search
from Nodes.models import Node
from Utils.models import Task

from Utils.hashcatAPI import HashcatAPI
from Utils.hashcat import Hashcat
from Utils.utils import del_hashfile_locks, Echo
from Utils.tasks import remove_hashfile_task
from Utils.tasks import run_search_task
# Create your views here.

@login_required
def api_node_status(request):
    if request.method == "POST":
        params = request.POST
    else:
        params = request.GET

    result = {
        "draw": params["draw"],
    }

    node_object_list = Node.objects.all()

    data = []
    for node in node_object_list:
        try:
            hashcat_api = HashcatAPI(node.hostname, node.port, node.username, node.password)
            node_data = hashcat_api.get_hashcat_info()

            status = "Stopped"
            for session in node_data["sessions"]:
                if session["status"] == "Running":
                    status = "Running"
                    break

            data.append([
                node.name,
                node_data["version"],
                status,
            ])
        except ConnectionRefusedError:
            data.append([
                node.name,
                "",
                "Error",
            ])

    result["data"] = data

    for query in connection.queries[-1:]:
        print(query["sql"])
        print(query["time"])

    return HttpResponse(json.dumps(result), content_type="application/json")

@login_required
def api_statistics(request):
    if request.method == "POST":
        params = request.POST
    else:
        params = request.GET

    result = {
        "draw": params["draw"],
    }

    data = []

    count_lines = Hashfile.objects.aggregate(Sum('line_count'))["line_count__sum"]
    count_cracked = Hashfile.objects.aggregate(Sum('cracked_count'))["cracked_count__sum"]
    data.append(["<b>Lines</b>", humanize.intcomma(count_lines)])
    data.append(["<b>Cracked</b>", "%s (%.2f%%)" % (humanize.intcomma(count_cracked), count_cracked/count_lines*100.0)])
    data.append(["<b>Hashfiles</b>", Hashfile.objects.count()])
    data.append(["<b>Nodes</b>", Node.objects.count()])

    result["data"] = data

    return HttpResponse(json.dumps(result), content_type="application/json")

@login_required
def api_cracked_ratio(request):
    if request.method == "POST":
        params = request.POST
    else:
        params = request.GET

    count_lines = Hashfile.objects.aggregate(Sum('line_count'))["line_count__sum"]
    count_cracked = Hashfile.objects.aggregate(Sum('cracked_count'))["cracked_count__sum"]

    result = [
        ["Cracked", count_cracked/count_lines*100.0],
        ["Uncracked", (1-count_cracked/count_lines)*100.0],
    ]

    return HttpResponse(json.dumps(result), content_type="application/json")


@login_required
def api_running_sessions(request):
    if request.method == "POST":
        params = request.POST
    else:
        params = request.GET

    result = {
        "draw": params["draw"],
    }

    data = []
    for session in Session.objects.all():
        node = session.node

        try:
            hashcat_api = HashcatAPI(node.hostname, node.port, node.username, node.password)
            session_info = hashcat_api.get_session_info(session.name)

            if session_info["status"] == "Running":
                if session_info["crack_type"] == "dictionary":
                    rule_mask = session_info["rule"]
                    wordlist = session_info["wordlist"]
                elif session_info["crack_type"] == "mask":
                    rule_mask = session_info["mask"]
                    wordlist = ""

                data.append({
                    "hashfile": session.hashfile.name,
                    "node": node.name,
                    "type": session_info["crack_type"],
                    "rule_mask": rule_mask,
                    "wordlist": wordlist,
                    "remaining": session_info["time_estimated"],
                    "progress": "%s %%" % session_info["progress"],
                    "speed": session_info["speed"].split('@')[0].strip(),
                })
        except ConnectionRefusedError:
            pass

    result["data"] = data

    return HttpResponse(json.dumps(result), content_type="application/json")

@login_required
def api_error_sessions(request):
    if request.method == "POST":
        params = request.POST
    else:
        params = request.GET

    result = {
        "draw": params["draw"],
    }

    data = []
    for session in Session.objects.all():
        node = session.node

        try:
            hashcat_api = HashcatAPI(node.hostname, node.port, node.username, node.password)
            session_info = hashcat_api.get_session_info(session.name)

            if not session_info["status"] in ["Not started", "Running", "Paused", "Done"]:
                if session_info["crack_type"] == "dictionary":
                    rule_mask = session_info["rule"]
                    wordlist = session_info["wordlist"]
                elif session_info["crack_type"] == "mask":
                    rule_mask = session_info["mask"]
                    wordlist = ""

                data.append({
                    "hashfile": session.hashfile.name,
                    "node": node.name,
                    "type": session_info["crack_type"],
                    "rule_mask": rule_mask,
                    "wordlist": wordlist,
                    "status": session_info["status"],
                    "reason": "TODO",
                })
        except ConnectionRefusedError:
            pass

    result["data"] = data

    return HttpResponse(json.dumps(result), content_type="application/json")



@login_required
def api_hashfiles(request):
    if request.method == "POST":
        params = request.POST
    else:
        params = request.GET

    result = {
        "draw": params["draw"],
    }

    session_status = {}

    node_object_list = Node.objects.all()
    for node in node_object_list:
        try:
            hashcat_api = HashcatAPI(node.hostname, node.port, node.username, node.password)
            hashcat_info = hashcat_api.get_hashcat_info()
            for session in hashcat_info["sessions"]:
                session_status[session["name"]] = session["status"]
        except ConnectionRefusedError:
            pass

    sort_index = ["name", "name", "hash_type", "line_count", "cracked_count", "name", "name", "name"][int(params["order[0][column]"])]
    sort_index = "-" + sort_index if params["order[0][dir]"] == "desc" else sort_index
    hashfile_list = Hashfile.objects.filter(name__contains=params["search[value]"]).order_by(sort_index)[int(params["start"]):int(params["start"])+int(params["length"])]

    data = []
    for hashfile in hashfile_list:
            buttons = "<a href='%s'><button title='Export cracked results' class='btn btn-info btn-xs' ><span class='glyphicon glyphicon-download-alt'></span></button></a>" % reverse('Hashcat:export_cracked', args=(hashfile.id,))
            buttons += "<button title='Create new cracking session' style='margin-left: 5px' class='btn btn-primary btn-xs' data-toggle='modal' data-target='#action_new' data-hashfile='%s' data-hashfile_id=%d ><span class='glyphicon glyphicon-plus'></span></button>" % (hashfile.name, hashfile.id)
            buttons += "<button title='Remove hashfile' style='margin-left: 5px' type='button' class='btn btn-danger btn-xs' onClick='hashfile_action(%d, \"%s\")'><span class='glyphicon glyphicon-remove'></span></button>" % (hashfile.id, "remove")

            buttons = "<div style='float: right'>%s</div>" % buttons

            running_session_count = 0
            total_session_count =  Session.objects.filter(hashfile_id=hashfile.id).count()
            for session in Session.objects.filter(hashfile_id=hashfile.id):
                try:
                    if session_status[session.name] == "Running":
                        running_session_count += 1
                except KeyError:
                    pass


            data.append({
                "DT_RowId": "row_%d" % hashfile.id,
                "name": "<a href='%s'>%s<a/>" % (reverse('Hashcat:hashfile', args=(hashfile.id,)), hashfile.name),
                "type": "Plaintext" if hashfile.hash_type == -1 else Hashcat.get_hash_types()[hashfile.hash_type]["name"],
                "line_count": humanize.intcomma(hashfile.line_count),
                "cracked": "%s (%.2f%%)" % (humanize.intcomma(hashfile.cracked_count), hashfile.cracked_count/hashfile.line_count*100) if hashfile.line_count > 0 else "0",
                "username_included": "yes" if hashfile.username_included else "no",
                "sessions_count": "%d / %d" % (running_session_count, total_session_count),
                "buttons": buttons,
            })

    result["data"] = data
    result["recordsTotal"] = Hashfile.objects.all().count()
    result["recordsFiltered"] = Hashfile.objects.filter(name__contains=params["search[value]"]).count()

    for query in connection.queries[-4:]:
        print(query["sql"])
        print(query["time"])

    return HttpResponse(json.dumps(result), content_type="application/json")

@login_required
def api_hashfile_sessions(request):
    if request.method == "POST":
        params = request.POST
    else:
        params = request.GET

    result = {
        "draw": params["draw"],
    }

    hashfile_id = int(params["hashfile_id"][4:] if params["hashfile_id"].startswith("row_") else params["hashfile_id"])

    data = []
    for session in Session.objects.filter(hashfile_id=hashfile_id):
        node = session.node

        try:
            hashcat_api = HashcatAPI(node.hostname, node.port, node.username, node.password)
            session_info = hashcat_api.get_session_info(session.name)

            if session_info["status"] == "Not started":
                buttons =  "<button title='Start session' type='button' class='btn btn-success btn-xs' onClick='session_action(\"%s\", \"%s\")'><span class='glyphicon glyphicon-play'></span></button>" % (session.name, "start")
                buttons +=  "<button title='Remove session' style='margin-left: 5px' type='button' class='btn btn-danger btn-xs' onClick='session_action(\"%s\", \"%s\")'><span class='glyphicon glyphicon-remove'></span></button>" % (session.name, "remove")
            elif session_info["status"] == "Running":
                buttons =  "<button title='Pause session' type='button' class='btn btn-warning btn-xs' onClick='session_action(\"%s\", \"%s\")'><span class='glyphicon glyphicon-pause'></span></button>" % (session.name, "pause")
                buttons +=  "<button title='Stop session' style='margin-left: 5px' type='button' class='btn btn-danger btn-xs' onClick='session_action(\"%s\", \"%s\")'><span class='glyphicon glyphicon-stop'></span></button>" % (session.name, "quit")
            elif session_info["status"] == "Paused":
                buttons =  "<button title='Resume session' type='button' class='btn btn-success btn-xs' onClick='session_action(\"%s\", \"%s\")'><span class='glyphicon glyphicon-play'></span></button>" % (session.name, "resume")
                buttons +=  "<button title='Stop session' style='margin-left: 5px' type='button' class='btn btn-danger btn-xs' onClick='session_action(\"%s\", \"%s\")'><span class='glyphicon glyphicon-stop'></span></button>" % (session.name, "quit")
            else:
                buttons =  "<button title='Start session' type='button' class='btn btn-success btn-xs' onClick='session_action(\"%s\", \"%s\")'><span class='glyphicon glyphicon-play'></span></button>" % (session.name, "start")
                buttons +=  "<button title='Remove session' style='margin-left: 5px' type='button' class='btn btn-danger btn-xs' onClick='session_action(\"%s\", \"%s\")'><span class='glyphicon glyphicon-remove'></span></button>" % (session.name, "remove")

            buttons = "<div style='float: right'>%s</div>" % buttons

            if session_info["crack_type"] == "dictionary":
                rule_mask = session_info["rule"]
                wordlist = session_info["wordlist"]
            elif session_info["crack_type"] == "mask":
                rule_mask = session_info["mask"]
                wordlist = ""

            data.append({
                "node": node.name,
                "type": session_info["crack_type"],
                "rule_mask": rule_mask,
                "wordlist": wordlist,
                "status": session_info["status"],
                "remaining": session_info["time_estimated"],
                "progress": "%s %%" % session_info["progress"],
                "speed": session_info["speed"],
                "buttons": buttons,
            })
        except ConnectionRefusedError:
            data.append({
                "node": node.name,
                "type": "",
                "rule_mask": "",
                "wordlist": "",
                "status": "",
                "remaining": "",
                "progress": "",
                "speed": "",
                "buttons": "",
            })

    result["data"] = data

    for query in connection.queries[-1:]:
        print(query["sql"])
        print(query["time"])

    return HttpResponse(json.dumps(result), content_type="application/json")

@login_required
def api_hashfile_cracked(request, hashfile_id):
    if request.method == "POST":
        params = request.POST
    else:
        params = request.GET

    hashfile = get_object_or_404(Hashfile, id=hashfile_id)

    result = {
        "draw": params["draw"],
    }

    if hashfile.username_included:
        sort_index = ["username", "password"][int(params["order[0][column]"])]
        sort_index = "-" + sort_index if params["order[0][dir]"] == "desc" else sort_index
    else:
        sort_index = ["hash", "password"][int(params["order[0][column]"])]
        sort_index = "-" + sort_index if params["order[0][dir]"] == "desc" else sort_index

    total_count = Hash.objects.filter(password__isnull=False, hashfile_id=hashfile.id).count()

    if len(params["search[value]"]) == 0:
        if hashfile.username_included:
            cracked_list = Hash.objects.filter(password__isnull=False, hashfile_id=hashfile.id).order_by(sort_index)[int(params["start"]):int(params["start"])+int(params["length"])]
            filtered_count = total_count
        else:
            cracked_list = Hash.objects.filter(password__isnull=False, hashfile_id=hashfile.id).order_by(sort_index)[int(params["start"]):int(params["start"])+int(params["length"])]
            filtered_count = total_count
    else:
        if hashfile.username_included:
            cracked_list = Hash.objects.filter(Q(username__contains=params["search[value]"]) | Q(password__contains=params["search[value]"]), password__isnull=False, hashfile_id=hashfile.id).order_by(sort_index)[int(params["start"]):int(params["start"])+int(params["length"])]
            filtered_count = Hash.objects.filter(Q(username__contains=params["search[value]"]) | Q(password__contains=params["search[value]"]), password__isnull=False, hashfile_id=hashfile.id).count()
        else:
            cracked_list = Hash.objects.filter(Q(hash__contains=params["search[value]"]) | Q(password__contains=params["search[value]"]), password__isnull=False, hashfile_id=hashfile.id).order_by(sort_index)[int(params["start"]):int(params["start"])+int(params["length"])]
            filtered_count = Hash.objects.filter(Q(hash__contains=params["search[value]"]) | Q(password__contains=params["search[value]"]), password__isnull=False, hashfile_id=hashfile.id).count()

    data = []
    for cracked in cracked_list:
        if hashfile.username_included:
            data.append([cracked.username, cracked.password])
        else:
            data.append([cracked.hash, cracked.password])

    for query in connection.queries[-3:]:
        print(query["sql"])
        print(query["time"])

    result["data"] = data
    result["recordsTotal"] = total_count
    result["recordsFiltered"] = filtered_count

    return HttpResponse(json.dumps(result), content_type="application/json")

@login_required
def api_hashfile_top_password(request, hashfile_id, N):
    if request.method == "POST":
        params = request.POST
    else:
        params = request.GET

    hashfile = get_object_or_404(Hashfile, id=hashfile_id)

    pass_count_list = Hash.objects.raw("SELECT 1 AS id, MAX(password) AS password, COUNT(*) AS count FROM Hashcat_hash WHERE hashfile_id=%s AND password IS NOT NULL GROUP BY BINARY password ORDER BY count DESC LIMIT 10", [hashfile.id])

    top_password_list = []
    count_list = []
    for item in pass_count_list:
        top_password_list.append(item.password)
        count_list.append(item.count)

    res = {
        "top_password_list": top_password_list,
        "count_list": count_list,
    }

    for query in connection.queries[-1:]:
        print(query["sql"])
        print(query["time"])

    return HttpResponse(json.dumps(res), content_type="application/json")

@login_required
def api_hashfile_top_password_len(request, hashfile_id, N):
    if request.method == "POST":
        params = request.POST
    else:
        params = request.GET

    hashfile = get_object_or_404(Hashfile, id=hashfile_id)

    # didn't found the correct way in pure django...
    pass_count_list = Hash.objects.raw("SELECT 1 AS id, MAX(password_len) AS password_len, COUNT(*) AS count FROM Hashcat_hash WHERE hashfile_id=%s AND password IS NOT NULL GROUP BY password_len", [hashfile.id])

    min_len = None
    max_len = None
    len_count = {}
    for item in pass_count_list:
        if min_len == None:
            min_len = item.password_len
        else:
            min_len = min(min_len, item.password_len)
        if max_len == None:
            max_len = item.password_len
        else:
            max_len = min(max_len, item.password_len)
        len_count[item.password_len] = item.count

    if min_len != None and max_len != None:
        for length in range(min_len, max_len+1):
            if not length in len_count:
                len_count[length] = 0

    len_count = OrderedDict(sorted(len_count.items()))

    res = {
        "password_length_list": list(len_count.keys()),
        "count_list": list(len_count.values()),
    }

    for query in connection.queries[-1:]:
        print(query["sql"])
        print(query["time"])

    return HttpResponse(json.dumps(res), content_type="application/json")

@login_required
def api_hashfile_top_password_charset(request, hashfile_id, N):
    if request.method == "POST":
        params = request.POST
    else:
        params = request.GET

    hashfile = get_object_or_404(Hashfile, id=hashfile_id)

    # didn't found the correct way in pure django...
    pass_count_list = Hash.objects.raw("SELECT 1 AS id, MAX(password_charset) AS password_charset, COUNT(*) AS count FROM Hashcat_hash WHERE hashfile_id=%s AND password IS NOT NULL GROUP BY password_charset ORDER BY count DESC LIMIT 10", [hashfile.id])

    password_charset_list = []
    count_list = []
    for item in pass_count_list:
        password_charset_list.append(item.password_charset)
        count_list.append(item.count)

    res = {
        "password_charset_list": password_charset_list,
        "count_list": count_list,
    }

    for query in connection.queries[-1:]:
        print(query["sql"])
        print(query["time"])

    return HttpResponse(json.dumps(res), content_type="application/json")

@login_required
def api_session_action(request):
    if request.method == "POST":
        params = request.POST
    else:
        params = request.GET

    session = get_object_or_404(Session, name=params["session_name"])
    node = session.node

    hashcat_api = HashcatAPI(node.hostname, node.port, node.username, node.password)
    res = hashcat_api.action(session.name, params["action"])

    if params["action"] == "remove":
        session.delete()

    return HttpResponse(json.dumps(res), content_type="application/json")

@login_required
def api_hashfile_action(request):
    if request.method == "POST":
        params = request.POST
    else:
        params = request.GET

    hashfile = get_object_or_404(Hashfile, id=params["hashfile_id"])

    print("Hashfile %s action %s" % (hashfile.name, params["action"])) 

    if params["action"] == "remove":
        remove_hashfile_task.delay(hashfile.id)

    return HttpResponse(json.dumps({"result": "success"}), content_type="application/json")

def api_get_messages(request):
    if request.method == "POST":
        params = request.POST
    else:
        params = request.GET

    message_list = []
    for task in Task.objects.all():
        message_list.append({"message": task.message})

    return HttpResponse(json.dumps({"result": "success", "messages": message_list}), content_type="application/json")

@login_required
def api_search_list(request):
    if request.method == "POST":
        params = request.POST
    else:
        params = request.GET

    result = {
        "draw": params["draw"],
    }

    sort_index = ["name", "status", "output_lines"][int(params["order[0][column]"])]
    sort_index = "-" + sort_index if params["order[0][dir]"] == "desc" else sort_index
    search_list = Search.objects.filter(name__contains=params["search[value]"]).order_by(sort_index)[int(params["start"]):int(params["start"])+int(params["length"])]

    data = []
    for search in search_list:
        buttons = ""
        if os.path.exists(search.output_file):
            buttons = "<a href='%s'><button title='Export search results' class='btn btn-info btn-xs' ><span class='glyphicon glyphicon-download-alt'></span></button></a>" % reverse('Hashcat:export_search', args=(search.id,))
        if search.status in ["Done", "Aborted"]:
            buttons += "<button title='Restart search' style='margin-left: 5px' type='button' class='btn btn-primary btn-xs' onClick='search_action(%d, \"%s\")'><span class='glyphicon glyphicon-refresh'></span></button>" % (search.id, "reload")
            buttons += "<button title='Remove search' style='margin-left: 5px' type='button' class='btn btn-danger btn-xs' onClick='search_action(%d, \"%s\")'><span class='glyphicon glyphicon-remove'></span></button>" % (search.id, "remove")

        buttons = "<div style='float: right'>%s</div>" % buttons

        data.append([
            search.name,
            search.status,
            humanize.intcomma(search.output_lines) if search.output_lines != None else "",
            str(datetime.timedelta(seconds=search.processing_time)) if search.processing_time != None else "",
            buttons,
        ])

    result["data"] = data
    result["recordsTotal"] = Search.objects.all().count()
    result["recordsFiltered"] = Search.objects.filter(name__contains=params["search[value]"]).count()

    return HttpResponse(json.dumps(result), content_type="application/json")

@login_required
def api_search_action(request):
    if request.method == "POST":
        params = request.POST
    else:
        params = request.GET

    search = get_object_or_404(Search, id=params["search_id"])

    if params["action"] == "remove":
        if os.path.exists(search.output_file):
            os.remove(search.output_file)
        search.delete()
    elif params["action"] == "reload":
        run_search_task.delay(search.id)

    return HttpResponse(json.dumps({"result": "success"}), content_type="application/json")

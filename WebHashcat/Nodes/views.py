import json
import csv
import random
import string
import os.path
import tempfile
import humanize
import time
from collections import OrderedDict

import plotly.offline as opy
import plotly.graph_objs as go
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

from django.shortcuts import get_object_or_404

from operator import itemgetter

from .models import Node

from Utils.hashcatAPI import HashcatAPI
from Utils.hashcat import Hashcat

# Create your views here.

@login_required
def nodes(request):

    context = {}
    context["Section"] = "Nodes"

    context["node_list"] = Node.objects.all()

    template = loader.get_template('Nodes/nodes.html')
    return HttpResponse(template.render(context, request))

@login_required
def node(request, node_name, error_msg=""):

    context = {}
    context["Section"] = "Nodes"

    if len(error_msg) != 0:
        context["error_message"] = error_msg

        template = loader.get_template('Nodes/node.html')
        return HttpResponse(template.render(context, request))

    node_item = get_object_or_404(Node, name=node_name)

    context["node_name"] = node_item.name
    context["hostname"] = node_item.hostname
    context["port"] = node_item.port

    if request.method == 'POST':
        if request.POST["action"] == "synchronize":

            hashcat_api = HashcatAPI(node_item.hostname, node_item.port, node_item.username, node_item.password)
            node_data = hashcat_api.get_hashcat_info()

            rule_list = Hashcat.get_rules()
            mask_list = Hashcat.get_masks()
            wordlist_list = Hashcat.get_wordlists()

            for rule in rule_list:
                if not rule["name"] in node_data["rules"]:
                    print(hashcat_api.upload_rule(rule["name"], open(rule["path"], 'rb').read()))
                elif node_data["rules"][rule["name"]]["md5"] != rule["md5"]:
                    print(hashcat_api.upload_rule(rule["name"], open(rule["path"], 'rb').read()))

            for mask in mask_list:
                if not mask["name"] in node_data["masks"]:
                    print(hashcat_api.upload_mask(mask["name"], open(mask["path"], 'rb').read()))
                elif node_data["masks"][mask["name"]]["md5"] != mask["md5"]:
                    print(hashcat_api.upload_mask(mask["name"], open(mask["path"], 'rb').read()))

            for wordlist in wordlist_list:
                if not wordlist["name"] in node_data["wordlists"]:
                    print(hashcat_api.upload_wordlist(wordlist["name"], open(wordlist["path"], 'rb').read()))
                elif node_data["wordlists"][wordlist["name"]]["md5"] != wordlist["md5"]:
                    print(hashcat_api.upload_wordlist(wordlist["name"], open(wordlist["path"], 'rb').read()))

    hashcat_api = HashcatAPI(node_item.hostname, node_item.port, node_item.username, node_item.password)
    node_data = hashcat_api.get_hashcat_info()

    if node_data["response"] == "error":
        return node(request, node_name, error_msg=node_data["message"])

    rule_list = Hashcat.get_rules()
    mask_list = Hashcat.get_masks()
    wordlist_list = Hashcat.get_wordlists()

    for rule in rule_list:
        if not rule["name"] in node_data["rules"]:
            rule["synchro"] = False
        elif node_data["rules"][rule["name"]]["md5"] != rule["md5"]:
            rule["synchro"] = False
        else:
            rule["synchro"] = True

    for mask in mask_list:
        if not mask["name"] in node_data["masks"]:
            mask["synchro"] = False
        elif node_data["masks"][mask["name"]]["md5"] != mask["md5"]:
            mask["synchro"] = False
        else:
            mask["synchro"] = True

    for wordlist in wordlist_list:
        if not wordlist["name"] in node_data["wordlists"]:
            wordlist["synchro"] = False
        elif node_data["wordlists"][wordlist["name"]]["md5"] != wordlist["md5"]:
            wordlist["synchro"] = False
        else:
            wordlist["synchro"] = True

    hash_type_list = sorted(node_data["hash_types"], key=itemgetter('id'))

    context["version"] = node_data["version"]
    context["rule_list"] = rule_list
    context["mask_list"] = mask_list
    context["wordlist_list"] = wordlist_list
    context["hash_type_list"] = hash_type_list

    template = loader.get_template('Nodes/node.html')
    return HttpResponse(template.render(context, request))


@login_required
def new_node(request):
    if request.method == 'POST':
        node_name = request.POST["name"]
        hostname = request.POST["hostname"]
        port = request.POST["port"]
        username = request.POST["username"]
        password = request.POST["password"]

        try:
            port = int(port)
        except ValueError:
            port = -1

        if port > 0 and port < 65636:
            Node.objects.update_or_create(name=node_name,
                    defaults={
                        'name': node_name,
                        'hostname': hostname,
                        'port': port,
                        'username': username,
                        'password': password,
                        }
            )
        return redirect('Nodes:nodes')

@login_required
def delete_node(request, node_name):

    try:
        obj = Node.objects.get(name=node_name)
        obj.delete()
    except Node.DoesNotExist:
        pass

    return redirect('Nodes:nodes')

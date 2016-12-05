import plotly.offline as opy
import plotly.graph_objs as go
from django.shortcuts import render
from django.shortcuts import redirect
from django.template import loader
from django.http import HttpResponse
from django.contrib.auth.decorators import login_required

from django.shortcuts import get_object_or_404

from operator import itemgetter

from .models import Node

from Utils.hashcatAPI import HashcatAPI
# Create your views here.

@login_required
def index(request, error_msg=''):

    context = {}
    context["Section"] = "Sessions"

    if len(error_msg) != 0:
        context["error_message"] = error_msg

    node_object_list = Node.objects.all()

    session_list = []
    rule_list = []
    mask_list = []
    hash_type_list = {}
    node_list = []
    wordlist_list = []

    connection_error_nodes = []

    for node in node_object_list:
        try:
            hashcat_api = HashcatAPI(node.hostname, node.port, node.username, node.password)
            node_data = hashcat_api.get_hashcat_info()

            node_list.append(node.name)

            for session in node_data["sessions"]:
                session_list.append({
                    "name": session["name"],
                    "node": node.name,
                    "crack_type": session["crack_type"],
                    "status": session["status"],
                    "cracked": int(session["cracked"]),
                    "progress": session["progress"],
                })

            rule_list += node_data["rules"]
            mask_list += node_data["masks"]
            wordlist_list += node_data["wordlists"]

            for hash_type in node_data["hash_types"]:
                hash_type_list[hash_type["id"]] = hash_type
        except ConnectionRefusedError:
            connection_error_nodes.append(node.name)

    rule_list = list(set(rule_list))
    rule_list.sort()
    mask_list = list(set(mask_list))
    mask_list.sort()
    wordlist_list = list(set(wordlist_list))
    wordlist_list.sort()
    hash_type_list = sorted(list(hash_type_list.values()), key=itemgetter('name'))

    context["node_list"] = node_list
    context["session_list"] = session_list
    context["rule_list"] = rule_list
    context["mask_list"] = mask_list
    context["wordlist_list"] = wordlist_list
    context["hash_type_list"] = hash_type_list

    if len(connection_error_nodes) != 0:
        context["error_message"] = "Connection error with the following nodes : %s" % ", ".join(connection_error_nodes)

    template = loader.get_template('Hashcat/index.html')
    return HttpResponse(template.render(context, request))

@login_required
def new_session(request):
    if request.method == 'POST':
        session_name = request.POST["name"]
        node_name = request.POST["node"]
        hash_type_id = request.POST["hash_type"]
        crack_type = request.POST["crack_type"]
        if crack_type == "rule":
            rule = request.POST["rule"]
            wordlist = request.POST["wordlist"]
        elif crack_type == "mask":
            mask = request.POST["mask"]
        hashes = request.POST["hashes"]
        username_included = "username_included" in request.POST

        if len(hashes) == 0 and "hash_file" in request.FILES:
            # get from file
            f = request.FILES["hash_file"]
            hashes = f.read().decode()

        node = get_object_or_404(Node, name=node_name)

        hashcat_api = HashcatAPI(node.hostname, node.port, node.username, node.password)
        if crack_type == "rule":
            res = hashcat_api.create_rule_session(session_name, hash_type_id, rule, wordlist, hashes, username_included)
        elif crack_type == "mask":
            res = hashcat_api.create_mask_session(session_name, hash_type_id, mask, hashes, username_included)

        if res["response"] == "error":
            return index(request, error_msg=res["message"])

    return redirect('index')

@login_required
def upload_rule(request):
    if request.method == 'POST':
        node_name = request.POST["node"]
        name = request.POST["name"]

        if "file" in request.FILES:
            # get from file
            f = request.FILES["file"]
            rule_file = f.read().decode()

            node_item = get_object_or_404(Node, name=node_name)

            hashcat_api = HashcatAPI(node_item.hostname, node_item.port, node_item.username, node_item.password)
            res = hashcat_api.upload_rule(name, rule_file)

            if res["response"] == "error":
                return node(request, node_name, error_msg=res["message"])

    return redirect('node', node_name)

@login_required
def upload_mask(request):
    if request.method == 'POST':
        node_name = request.POST["node"]
        name = request.POST["name"]

        if "file" in request.FILES:
            # get from file
            f = request.FILES["file"]
            rule_file = f.read().decode()

            node_item = get_object_or_404(Node, name=node_name)

            hashcat_api = HashcatAPI(node_item.hostname, node_item.port, node_item.username, node_item.password)
            res = hashcat_api.upload_mask(name, rule_file)

            if res["response"] == "error":
                return node(request, node_name, error_msg=res["message"])

    return redirect('node', node_name)

@login_required
def upload_wordlist(request):
    if request.method == 'POST':
        node_name = request.POST["node"]
        name = request.POST["name"]

        if "file" in request.FILES:
            # get from file
            f = request.FILES["file"]
            rule_file = f.read().decode()

            node_item = get_object_or_404(Node, name=node_name)

            hashcat_api = HashcatAPI(node_item.hostname, node_item.port, node_item.username, node_item.password)
            res = hashcat_api.upload_wordlist(name, rule_file)

            if res["response"] == "error":
                return node(request, node_name, error_msg=res["message"])

    return redirect('node', node_name)




@login_required
def action(request, node_name, session_name, action):
    node = get_object_or_404(Node, name=node_name)

    hashcat_api = HashcatAPI(node.hostname, node.port, node.username, node.password)
    res = hashcat_api.action(session_name, action)

    if res["response"] == "error":
        return index(request, error_msg=res["message"])

    return redirect('index')

@login_required
def action_session(request, node_name, session_name, action):
    node = get_object_or_404(Node, name=node_name)

    hashcat_api = HashcatAPI(node.hostname, node.port, node.username, node.password)
    res = hashcat_api.action(session_name, action)

    if res["response"] == "error":
        return session(request, node_name, session_name, error_msg=res["message"])

    return redirect('session', node_name, session_name)

@login_required
def remove(request, node_name, session_name):
    node = get_object_or_404(Node, name=node_name)

    hashcat_api = HashcatAPI(node.hostname, node.port, node.username, node.password)
    res = hashcat_api.remove(session_name)

    if res["response"] == "error":
        return index(request, error_msg=res["message"])

    return redirect('index')

@login_required
def session(request, node_name, session_name, error_msg=''):
    context = {}
    context["Section"] = "Sessions"

    if len(error_msg) != 0:
        context["error_message"] = error_msg

        template = loader.get_template('Hashcat/session.html')
        return HttpResponse(template.render(context, request))

    node = get_object_or_404(Node, name=node_name)

    hashcat_api = HashcatAPI(node.hostname, node.port, node.username, node.password)
    session_info = hashcat_api.get_session_info(session_name)

    if session_info["response"] == "error":
        return session(request, node_name, session_name, error_msg=session_info["message"])

    context["node"] = node_name
    context["session"] = session_name
    context["crack_type"] = session_info["crack_type"]
    context["status"] = session_info["status"]
    context["time_started"] = session_info["time_started"]
    context["time_estimated"] = session_info["time_estimated"]
    context["speed"] = session_info["speed"]
    context["recovered"] = session_info["recovered"]
    context["progress"] = session_info["progress"]
    context["results"] = session_info["results"]

    # top10 graph
    data = [go.Bar(
                    x=[item[1] for item in session_info["top10_passwords"]][::-1],
                    y=[item[0] for item in session_info["top10_passwords"]][::-1],
                    orientation = 'h'
    )]
    layout=go.Layout(title="Top 10 passwords", margin=go.Margin(
            l=150,
            r=0,
            pad=4
        ),)
    figure=go.Figure(data=data,layout=layout)
    div = opy.plot(figure, auto_open=False, output_type='div', show_link=False)

    context['top10_graph'] = div

    # password_lengths graph
    data = [go.Bar(
                    x=[item[1] for item in session_info["password_lengths"]][::-1],
                    y=[item[0] for item in session_info["password_lengths"]][::-1],
                    orientation = 'h'
    )]
    layout=go.Layout(title="Password lengths", margin=go.Margin(
            l=150,
            r=0,
            pad=4
        ),)
    figure=go.Figure(data=data,layout=layout)
    div = opy.plot(figure, auto_open=False, output_type='div', show_link=False)

    context['pass_len_graph'] = div

    # password_charset graph
    data = [go.Bar(
                    x=[item[1] for item in session_info["password_charsets"]][::-1],
                    y=[item[0] for item in session_info["password_charsets"]][::-1],
                    orientation = 'h'
    )]
    layout=go.Layout(title="Password charsets", margin=go.Margin(
            l=150,
            r=0,
            pad=4
        ),)
    figure=go.Figure(data=data,layout=layout)
    div = opy.plot(figure, auto_open=False, output_type='div', show_link=False)

    context['pass_charset_graph'] = div

    template = loader.get_template('Hashcat/session.html')
    return HttpResponse(template.render(context, request))

@login_required
def export(request, node_name, session_name):
    node = get_object_or_404(Node, name=node_name)

    hashcat_api = HashcatAPI(node.hostname, node.port, node.username, node.password)
    cracked_file = hashcat_api.get_cracked_file(session_name)

    if cracked_file["response"] == "error":
        return session(request, node_name, session_name, error_msg=cracked_file["message"])

    response = HttpResponse(cracked_file["cracked"], content_type='application/force-download') # mimetype is replaced by content_type for django 1.7
    response['Content-Disposition'] = 'attachment; filename=%s' % "cracked.txt"
    return response

@login_required
def nodes(request):

    context = {}
    context["Section"] = "Nodes"

    context["node_list"] = Node.objects.all()

    template = loader.get_template('Hashcat/nodes.html')
    return HttpResponse(template.render(context, request))

@login_required
def node(request, node_name, error_msg=""):

    context = {}
    context["Section"] = "Nodes"

    if len(error_msg) != 0:
        context["error_message"] = error_msg

        template = loader.get_template('Hashcat/node.html')
        return HttpResponse(template.render(context, request))

    node_item = get_object_or_404(Node, name=node_name)

    context["node_name"] = node_item.name
    context["hostname"] = node_item.hostname
    context["port"] = node_item.port

    hashcat_api = HashcatAPI(node_item.hostname, node_item.port, node_item.username, node_item.password)
    node_data = hashcat_api.get_hashcat_info()

    if node_data["response"] == "error":
        return node(request, node_name, error_msg=node_data["message"])

    rule_list = node_data["rules"]
    rule_list.sort()
    mask_list = node_data["masks"]
    mask_list.sort()
    wordlist_list = node_data["wordlists"]
    wordlist_list.sort()
    hash_type_list = sorted(node_data["hash_types"], key=itemgetter('id'))

    context["version"] = node_data["version"]
    context["rule_list"] = rule_list
    context["mask_list"] = mask_list
    context["wordlist_list"] = wordlist_list
    context["hash_type_list"] = hash_type_list

    template = loader.get_template('Hashcat/node.html')
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
    return redirect('nodes')

@login_required
def delete_node(request, node_name):

    try:
        obj = Node.objects.get(name=node_name)
        obj.delete()
    except Node.DoesNotExist:
        pass

    return redirect('nodes')

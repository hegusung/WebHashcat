import os
import base64
from django.shortcuts import render
from django.shortcuts import redirect
from django.template import loader
from django.http import HttpResponse
from django.contrib.auth import authenticate, login


def auth(request):

    context = {
        "Section": "Auth",
    }

    if request.method == "POST":
        user = authenticate(username=request.POST["username"], password=request.POST["password"])
        if user is not None:
            # the password verified for the user
            if user.is_active:
                login(request, user)
                return redirect('Hashcat:index')
            else:
                context["error_message"] = "The password is valid, but the account has been disabled!"
        else:
            context["error_message"] = "The username and password were incorrect."

    template = loader.get_template('Auth/auth.html')
    return HttpResponse(template.render(context, request))


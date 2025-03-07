"""WebHashcat URL Configuration

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/1.9/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  url(r'^$', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  url(r'^$', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.conf.urls import url, include
    2. Add a URL to urlpatterns:  url(r'^blog/', include('blog.urls'))
"""
from django.urls import include,re_path,path
from django.contrib import admin
from django.views.generic import RedirectView

urlpatterns = [
    re_path(r'^Auth/', include('Auth.urls', namespace='Auth')),
    re_path(r'^Nodes/', include('Nodes.urls', namespace='Nodes')),
    re_path(r'^', include('Hashcat.urls', namespace='Hashcat')),
    re_path(r'^api/', include('API.urls', namespace='API')),
    path("admin/", admin.site.urls),
]

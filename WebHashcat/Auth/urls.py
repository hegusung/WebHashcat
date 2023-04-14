from django.urls import re_path

from . import views

app_name = 'Auth'
urlpatterns = [
        re_path(r'^$', views.auth, name='auth'),
]


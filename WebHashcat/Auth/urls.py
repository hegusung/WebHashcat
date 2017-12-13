from django.conf.urls import url

from . import views

app_name = 'Auth'
urlpatterns = [
        url(r'^$', views.auth, name='auth'),
]


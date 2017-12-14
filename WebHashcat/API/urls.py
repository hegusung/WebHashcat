from django.conf.urls import url

from . import views

app_name = 'API'
urlpatterns = [
        url(r'^node_status$', views.api_node_status, name='api_node_status'),
        url(r'^hashfiles$', views.api_hashfiles, name='api_hashfiles'),
        url(r'^hashfile_sessions$', views.api_hashfile_sessions, name='api_hashfile_sessions'),
        url(r'^session_action$', views.api_session_action, name='api_session_action'),
        url(r'^hashfile_action$', views.api_hashfile_action, name='api_hashfile_action'),
        url(r'^hashfile_cracked/(.*)$', views.api_hashfile_cracked, name='api_hashfile_cracked'),
        url(r'^hashfile_top_password/(.*)/(.*)$', views.api_hashfile_top_password, name='api_hashfile_top_password'),
        url(r'^hashfile_top_password_len/(.*)/(.*)$', views.api_hashfile_top_password_len, name='api_hashfile_top_password_len'),
        url(r'^hashfile_top_password_charset/(.*)/(.*)$', views.api_hashfile_top_password_charset, name='api_hashfile_top_password_charset'),
        url(r'^update_hashfiles$', views.api_update_hashfiles, name='api_update_hashfiles'),
]


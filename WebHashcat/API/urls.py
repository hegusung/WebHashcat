from django.urls import re_path

from . import views

app_name = 'API'
urlpatterns = [
        re_path(r'^statistics$', views.api_statistics, name='api_statistics'),
        re_path(r'^cracked_ratio$', views.api_cracked_ratio, name='api_cracked_ratio'),
        re_path(r'^running_sessions$', views.api_running_sessions, name='api_running_sessions'),
        re_path(r'^error_sessions$', views.api_error_sessions, name='api_error_sessions'),
        re_path(r'^node_status$', views.api_node_status, name='api_node_status'),
        re_path(r'^hashfiles$', views.api_hashfiles, name='api_hashfiles'),
        re_path(r'^hashfile_sessions$', views.api_hashfile_sessions, name='api_hashfile_sessions'),
        re_path(r'^session_action$', views.api_session_action, name='api_session_action'),
        re_path(r'^hashfile_action$', views.api_hashfile_action, name='api_hashfile_action'),
        re_path(r'^hashfile_cracked/(.*)$', views.api_hashfile_cracked, name='api_hashfile_cracked'),
        re_path(r'^hashfile_top_password/(.*)/(.*)$', views.api_hashfile_top_password, name='api_hashfile_top_password'),
        re_path(r'^hashfile_top_password_len/(.*)/(.*)$', views.api_hashfile_top_password_len, name='api_hashfile_top_password_len'),
        re_path(r'^hashfile_top_password_charset/(.*)/(.*)$', views.api_hashfile_top_password_charset, name='api_hashfile_top_password_charset'),
        re_path(r'^get_messages$', views.api_get_messages, name='api_get_messages'),
        re_path(r'^search_list$', views.api_search_list, name='api_search_list'),
        re_path(r'^search_action$', views.api_search_action, name='api_search_action'),
        # Uses basic authentication
        re_path(r'^upload_file$', views.api_upload_file, name='api_upload_file'),
]


from django.conf.urls import url

from . import views

app_name = 'API'
urlpatterns = [
        url(r'^statistics$', views.api_statistics, name='api_statistics'),
        url(r'^cracked_ratio$', views.api_cracked_ratio, name='api_cracked_ratio'),
        url(r'^running_sessions$', views.api_running_sessions, name='api_running_sessions'),
        url(r'^error_sessions$', views.api_error_sessions, name='api_error_sessions'),
        url(r'^node_status$', views.api_node_status, name='api_node_status'),
        url(r'^hashfiles$', views.api_hashfiles, name='api_hashfiles'),
        url(r'^hashfile_sessions$', views.api_hashfile_sessions, name='api_hashfile_sessions'),
        url(r'^session_action$', views.api_session_action, name='api_session_action'),
        url(r'^hashfile_action$', views.api_hashfile_action, name='api_hashfile_action'),
        url(r'^hashfile_cracked/(.*)$', views.api_hashfile_cracked, name='api_hashfile_cracked'),
        url(r'^hashfile_top_password/(.*)/(.*)$', views.api_hashfile_top_password, name='api_hashfile_top_password'),
        url(r'^hashfile_top_password_len/(.*)/(.*)$', views.api_hashfile_top_password_len, name='api_hashfile_top_password_len'),
        url(r'^hashfile_top_password_charset/(.*)/(.*)$', views.api_hashfile_top_password_charset, name='api_hashfile_top_password_charset'),
        url(r'^get_messages$', views.api_get_messages, name='api_get_messages'),
        url(r'^search_list$', views.api_search_list, name='api_search_list'),
        url(r'^search_action$', views.api_search_action, name='api_search_action'),
        # Uses basic authentication
        url(r'^upload_file$', views.api_upload_file, name='api_upload_file'),
]


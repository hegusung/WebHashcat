from django.urls import re_path

from . import views

app_name = 'Hashcat'
urlpatterns = [
        re_path(r'^$', views.dashboard, name='index'),
        re_path(r'^hashfiles$', views.hashfiles, name='hashfiles'),
        re_path(r'^search$', views.search, name='search'),
        re_path(r'^files$', views.files, name='files'),
        re_path(r'^new_session$', views.new_session, name='new_session'),
        re_path(r'^upload_rule$', views.upload_rule, name='upload_rule'),
        re_path(r'^upload_mask$', views.upload_mask, name='upload_mask'),
        re_path(r'^upload_wordlist$', views.upload_wordlist, name='upload_wordlist'),
        re_path(r'^hashfile/(.*)$', views.hashfile, name='hashfile'),
        re_path(r'^file/cracked/(.*)$', views.export_cracked, name='export_cracked'),
        re_path(r'^file/uncracked/(.*)$', views.export_uncracked, name='export_uncracked'),
        re_path(r'^csv/masks/(.*)$', views.csv_masks, name='csv_masks'),
        re_path(r'^export_search/(.*)$', views.export_search, name='export_search'),
]


from django.conf.urls import url

from . import views

app_name = 'Hashcat'
urlpatterns = [
        url(r'^$', views.hashfiles, name='index'),
        url(r'^hashfiles$', views.hashfiles, name='hashfiles'),
        url(r'^files$', views.files, name='files'),
        url(r'^new_session$', views.new_session, name='new_session'),
        url(r'^upload_rule$', views.upload_rule, name='upload_rule'),
        url(r'^upload_mask$', views.upload_mask, name='upload_mask'),
        url(r'^upload_wordlist$', views.upload_wordlist, name='upload_wordlist'),
        url(r'^hashfile/(.*)$', views.hashfile, name='hashfile'),
        url(r'^file/cracked/(.*)$', views.export_cracked, name='export_cracked'),
        url(r'^file/uncracked/(.*)$', views.export_uncracked, name='export_uncracked'),
        url(r'^csv/masks/(.*)$', views.csv_masks, name='csv_masks'),
]


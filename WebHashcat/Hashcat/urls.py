from django.conf.urls import url

from . import views

urlpatterns = [
        url(r'^$', views.index, name='index'),
        url(r'^new_session$', views.new_session, name='new_session'),
        url(r'^action/(.*)/(.*)/(.*)$', views.action, name='action'),
        url(r'^action_session/(.*)/(.*)/(.*)$', views.action_session, name='action_session'),
        url(r'^session/(.*)/(.*)$', views.session, name='session'),
        url(r'^export/(.*)/(.*)$', views.export, name='export'),
        url(r'^remove/(.*)/(.*)$', views.remove, name='remove'),
        url(r'^nodes$', views.nodes, name='nodes'),
        url(r'^node/(.*)$', views.node, name='node'),
        url(r'^new_node$', views.new_node, name='new_node'),
        url(r'^delete_node/(.*)$', views.delete_node, name='delete_node'),
        url(r'^upload_rule$', views.upload_rule, name='upload_rule'),
        url(r'^upload_mask$', views.upload_mask, name='upload_mask'),
        url(r'^upload_wordlist$', views.upload_wordlist, name='upload_wordlist'),
]


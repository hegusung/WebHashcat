from django.urls import re_path

from . import views

app_name = 'Nodes'
urlpatterns = [
        re_path(r'^nodes$', views.nodes, name='nodes'),
        re_path(r'^node/(.*)$', views.node, name='node'),
        re_path(r'^new_node$', views.new_node, name='new_node'),
        re_path(r'^delete_node/(.*)$', views.delete_node, name='delete_node'),
]


from django.conf.urls import url

from . import views

app_name = 'Nodes'
urlpatterns = [
        url(r'^nodes$', views.nodes, name='nodes'),
        url(r'^node/(.*)$', views.node, name='node'),
        url(r'^new_node$', views.new_node, name='new_node'),
        url(r'^delete_node/(.*)$', views.delete_node, name='delete_node'),
]


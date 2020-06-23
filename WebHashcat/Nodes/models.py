from django.db import models

# Create your models here.

class Node(models.Model):
    name = models.CharField(max_length=30)
    hostname = models.CharField(max_length=255)
    port = models.IntegerField()
    username = models.CharField(max_length=30)
    password = models.CharField(max_length=255)

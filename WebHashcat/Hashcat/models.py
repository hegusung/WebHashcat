from django.db import models

from Nodes.models import Node

# Create your models here.

class Hashfile(models.Model):
    name = models.CharField(max_length=30)
    hashfile = models.CharField(max_length=30)
    hash_type = models.IntegerField()
    line_count = models.IntegerField()
    cracked_count = models.IntegerField(default=0)
    username_included = models.BooleanField()

class Session(models.Model):
    name = models.CharField(max_length=100)
    hashfile = models.ForeignKey(Hashfile, on_delete=models.CASCADE)
    node = models.ForeignKey(Node, on_delete=models.CASCADE)
    potfile_line_retrieved = models.IntegerField()

class Hash(models.Model):
    hashfile = models.ForeignKey(Hashfile, on_delete=models.CASCADE)
    username = models.CharField(max_length=190, null=True)
    password = models.CharField(max_length=190, null=True)
    hash = models.CharField(max_length=190, null=True)
    password_len = models.IntegerField(null=True)
    password_charset = models.CharField(max_length=100, null=True)
    password_mask = models.CharField(null=True, max_length=190)

    class Meta:
        indexes = [
            models.Index(fields=['hashfile_id'], name="hashfileid_id_index"),
        ]


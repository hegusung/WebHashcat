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
    hash_type = models.IntegerField()
    username = models.CharField(max_length=190, null=True)
    password = models.CharField(max_length=190, null=True)
    hash = models.TextField(max_length=4096, null=True) # Changed from char to text
    hash_hash = models.CharField(max_length=190, null=True) # sha1 of the hash for joins
    password_len = models.IntegerField(null=True)
    password_charset = models.CharField(max_length=100, null=True)
    password_mask = models.CharField(null=True, max_length=190)

    class Meta:
        indexes = [
            models.Index(fields=['hashfile'], name="hashfileid_index"),
            models.Index(fields=['hashfile', 'hash_hash'], name="hashfileid_hash_index"),
            models.Index(fields=['hash_hash', 'hash_type'], name="hash_index"),
        ]

class Search(models.Model):
    name = models.CharField(max_length=100)
    status = models.CharField(max_length=100)
    output_lines = models.IntegerField(null=True)
    output_file = models.TextField()
    processing_time = models.IntegerField(null=True)
    json_search_info = models.TextField()

class Wordlist(models.Model):
    name = models.CharField(max_length=255, unique=True)
    file_hash = models.CharField(max_length=50)
    path = models.CharField(max_length=255)
    lines = models.IntegerField()

class Rule(models.Model):
    name = models.CharField(max_length=255, unique=True)
    file_hash = models.CharField(max_length=50)
    path = models.CharField(max_length=255)
    lines = models.IntegerField()

class Mask(models.Model):
    name = models.CharField(max_length=255, unique=True)
    file_hash = models.CharField(max_length=50)
    path = models.CharField(max_length=255)
    lines = models.IntegerField()

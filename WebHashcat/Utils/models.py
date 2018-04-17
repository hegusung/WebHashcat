from django.db import models

from Hashcat.models import Hashfile

# Create your models here.

# Table used to prevent concurrent access to files
# possible lock_ressource values:
#   - potfile
#   - hashfile
#   - crackedfile
class Lock(models.Model):
    hashfile = models.ForeignKey(Hashfile, on_delete=models.CASCADE)
    lock_ressource = models.CharField(max_length=30)

class Task(models.Model):
    time = models.DateTimeField()
    message = models.TextField()

from django.db import transaction
from .models import Lock

def init_hashfile_locks(hashfile):
    # Create locks in database

    lock_potfile = Lock(
        hashfile = hashfile,
        lock_ressource="potfile",
    )
    lock_potfile.save()

    lock_hashfile = Lock(
        hashfile = hashfile,
        lock_ressource="hashfile",
    )
    lock_hashfile.save()

def del_hashfile_locks(hashfile):
    # Remove locks in database

    with transaction.atomic():
        for lock in Lock.objects.select_for_update().filter(hashfile_id=hashfile.id):
            lock.delete()

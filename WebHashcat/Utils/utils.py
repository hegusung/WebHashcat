import functools
import redis
import hashlib
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

def calculate_md5(hashfile):
    file_hash = hashlib.md5()
    with open(hashfile, "rb") as f:
        while True:
            chunk = f.read(8192)
            if not chunk:
                break
            file_hash.update(chunk)

    return file_hash.hexdigest()

class Echo:
    """An object that implements just the write method of the file-like
    interface.
    """
    def write(self, value):
        """Write the value by returning it, instead of storing in a buffer."""
        return value


from WebHashcat.settings import CELERY_BROKER_URL
REDIS_CLIENT = redis.Redis.from_url(CELERY_BROKER_URL)

def only_one(function=None, key="", timeout=None):
    """Enforce only one celery task at a time."""

    def _dec(run_func):
        """Decorator."""

        def _caller(*args, **kwargs):
            """Caller."""
            ret_value = None
            have_lock = False
            lock = REDIS_CLIENT.lock(key, timeout=timeout)
            try:
                have_lock = lock.acquire(blocking=False)
                if have_lock:
                    ret_value = run_func(*args, **kwargs)
            finally:
                if have_lock:
                    lock.release()

            return ret_value

        return _caller

    return _dec(function) if function is not None else _dec

import datetime
import traceback
from celery.task.schedules import crontab
from celery.decorators import task
from celery.decorators import periodic_task
from celery.utils.log import get_task_logger

from Hashcat.models import Session, Hashfile, Hash
from Utils.hashcat import Hashcat
from Utils.models import Task

logger = get_task_logger(__name__)

@task(name="import_hashfile_task")
def import_hashfile_task(hashfile_id):

    hashfile = Hashfile.objects.get(id=hashfile_id)

    task = Task(
        time = datetime.datetime.now(),
        message = "Importing hash file %s..." % hashfile.name
    )
    task.save()

    try:

        if hashfile.hash_type != -1: # if != plaintext
            task.message = "Importing hash file %s..." % hashfile.name
            task.save()

            Hashcat.insert_hashes(hashfile)

            task.message = "Comparing hash file %s to potfile..." % hashfile.name
            task.save()

            Hashcat.compare_potfile(hashfile)
        else:
            task.message = "Importing plaintext file %s..." % hashfile.name
            task.save()

            Hashcat.insert_plaintext(hashfile)
    except Exception as e:
        traceback.print_exc()
    finally:
        task.delete()

@task(name="remove_hashfile_task")
def remove_hashfile_task(hashfile_id):

    hashfile = Hashfile.objects.get(id=hashfile_id)

    task = Task(
        time = datetime.datetime.now(),
        message = "Removing hash file %s..." % hashfile.name
    )
    task.save()

    Hashcat.remove_hashfile(hashfile)

    task.delete()

@periodic_task(
    run_every=(crontab(minute='*/5')),
    name="update_potfile_task",
    ignore_result=True
)
def update_potfile_task():
    Hashcat.update_potfile()

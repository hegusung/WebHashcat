import datetime
import traceback
from celery.task.schedules import crontab
from celery.decorators import task
from celery.decorators import periodic_task
from celery.utils.log import get_task_logger
from celery.signals import celeryd_after_setup

from Hashcat.models import Session, Hashfile, Hash
from Utils.hashcat import Hashcat
from Utils.models import Task
from Utils.utils import only_one

logger = get_task_logger(__name__)

@celeryd_after_setup.connect
def cleanup_tasks(sender, instance, **kwargs):
    for task in Task.objects.all():
        task.delete()

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

    try:
        Hashcat.remove_hashfile(hashfile)
    except Exception as e:
        traceback.print_exc()
    finally:
        task.delete()

@periodic_task(
    run_every=(crontab(minute='*/5')),
    name="update_potfile_task",
    ignore_result=True
)
@only_one(key="UpdatePotfile", timeout=6*60*60)
def update_potfile_task():
    Hashcat.update_hashfiles()

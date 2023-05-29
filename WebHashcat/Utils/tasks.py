import datetime
import sys
import traceback
import json
import os
import os.path
import tempfile
import string
import random
import csv
import time
from shutil import copyfile
#from celery import Celery
from WebHashcat.celery import app
from celery.schedules import crontab
from celery.utils.log import get_task_logger
from celery.signals import celeryd_after_setup
from django.db import connection

from Hashcat.models import Session, Hashfile, Hash, Search
from Utils.hashcat import Hashcat
from Utils.models import Task
from Utils.utils import only_one

logger = get_task_logger(__name__)

@app.on_after_finalize.connect
def setup_periodic_tasks(sender, **kwargs):
    print("setup_periodic_tasks")
    sender.add_periodic_task(1*60, update_potfile_task.s())  # Every 5 minutes
    sender.add_periodic_task(2*60*60, update_cracked_count.s()) # Every 2 Hours
    sender.add_periodic_task(3*60*60, optimize_potfile.s()) # Every 3 Hours

@celeryd_after_setup.connect
def cleanup_tasks(sender, instance, **kwargs):
    for task in Task.objects.all():
        task.delete()

    # Set all "Running" and "Starting" searches to aborted
    for search in Search.objects.filter(status__in=["Starting", "Running"]):
        search.status = "Aborted"
        search.save()

@app.task(name="import_hashfile_task")
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

@app.task(name="remove_hashfile_task")
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

@app.task(name="run_search_task")
def run_search_task(search_id):

    search = Search.objects.get(id=search_id)

    task = Task(
        time = datetime.datetime.now(),
        message = "Running search %s..." % search.name
    )
    task.save()

    if os.path.exists(search.output_file):
        os.remove(search.output_file)

    try:
        search.status = "Running"
        search.output_lines = None
        search.processing_time = None
        search.save()
        search_info = json.loads(search.json_search_info)

        start_time = time.time()

        cursor = connection.cursor()

        args = []
        columns = ["hashfile_id", "username", "password", "hash_type", "hash"]

        query = "SELECT %s FROM Hashcat_hash" % ",".join(columns)

        if "pattern" in search_info or not "all_hashfiles" in search_info or "ignore_uncracked" in search_info:
            query += " WHERE "

        if "pattern" in search_info:
            query_pattern_list = []
            for pattern in search_info["pattern"].split(';'):
                query_pattern_list.append("username LIKE %s")
                args.append("%" + pattern + "%")

            query += "(" + " OR ".join(query_pattern_list) + ")"

            if not "all_hashfiles" in search_info or "ignore_uncracked" in search_info:
                query += " AND "

        if not "all_hashfiles" in search_info:
            query += "hashfile_id IN (%s)" % ','.join(['%s'] * len(search_info["hashfiles"]))
            args += [int(i) for i in search_info["hashfiles"]]

            if "ignore_uncracked" in search_info:
                query += " AND "

        if "ignore_uncracked" in search_info:
            query += "password IS NOT NULL"

        tmpfile_name = ''.join([random.choice(string.ascii_lowercase) for i in range(16)])
        tmp_file = os.path.join(os.path.dirname(__file__), "..", "Files", "tmp", tmpfile_name)
        f = open(tmp_file, "w")
        csv_writer = csv.writer(f)

        # We remove this so we don't need specific rights in mysql (maybe do a test ?)
        #query += " INTO OUTFILE %s FIELDS TERMINATED BY ',' OPTIONALLY ENCLOSED BY '\"' LINES TERMINATED BY '\\n'"
        #args.append(tmp_file)
        
        rows = cursor.execute(query, args)
        
        for row in cursor.fetchall():
            csv_writer.writerow(row)
        f.close()
        cursor.close()

        if os.path.exists(tmp_file):
            hash_types_dict = Hashcat.get_hash_types()
            hashfile_dict = {}
            for hashfile in Hashfile.objects.all():
                hashfile_dict[hashfile.id] = hashfile.name

            with open(search.output_file, 'w', newline='') as out_csvfile:
                spamwriter = csv.writer(out_csvfile, delimiter=',', quotechar='"', quoting=csv.QUOTE_MINIMAL)
                spamwriter.writerow(["Hashfile", "Username", "Password", "Hash format", "Hash"])
                with open(tmp_file, 'r', newline='') as csvfile:
                    spamreader = csv.reader(csvfile, delimiter=',', quotechar='"')
                    for row in spamreader:
                        try:
                            row[0] = hashfile_dict[int(row[0])]
                        except KeyError:
                            pass
                        try:
                            row[3] = hash_types_dict[int(row[3])]['name'] if int(row[3]) != -1 else "Plaintext"
                        except KeyError:
                            pass
                        except ValueError:
                            pass
                        except IndexError:
                            pass
                        spamwriter.writerow(row)

            os.remove(tmp_file)

        end_time = time.time()

        search.status = "Done"
        search.output_lines = int(rows)
        search.processing_time = int(end_time - start_time)
        search.save()

    except Exception as e:
        traceback.print_exc()

        end_time = time.time()

        search.status = "Error"
        search.output_lines = 0
        search.processing_time = int(end_time - start_time)
        search.save()
    finally:
        task.delete()

@app.task(name="update_potfile_task")
def update_potfile_task():
    print("Updating potfile")
    Hashcat.update_hashfiles()

@app.task(name="update_cracked_count")
def update_cracked_count():
    for hashfile in Hashfile.objects.all():
        if not hashfile.hash_type in [-1,]:
            hashfile.cracked_count = Hash.objects.filter(hashfile_id=hashfile.id, password__isnull=False).count()
            hashfile.save()

@app.task(name="optimize_potfile")
def optimize_potfile():
        Hashcat.optimize_potfile()


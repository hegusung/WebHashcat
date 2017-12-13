import time
import os
import threading
import schedule
from threading import Lock
from django.apps import AppConfig

class HashcatConfig(AppConfig):
    name = 'Hashcat'

    def ready(self):
        # Run it only once, autoreload makes it run twice see https://stackoverflow.com/questions/28489863/why-is-run-called-twice-in-the-django-dev-server/28504072#28504072
        if os.environ.get('RUN_MAIN') != 'true':
            print("Init locks")
            from Utils.hashcat import Hashcat
            # Initialise a lock for each hashfile
            Hashcat.init_locks()

            print("Starting scheduler")
            schedule.every(1).minutes.do(job)

            t = threading.Thread(target=schedule_thread, daemon=True)
            t.start()


def job():
    from Utils.hashcat import Hashcat
    Hashcat.backup_potfile()
    Hashcat.update_potfile()

def schedule_thread():
    while True:
        schedule.run_pending()
        time.sleep(1)

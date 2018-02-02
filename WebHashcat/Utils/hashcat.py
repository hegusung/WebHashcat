#!/usr/bin/python3
import os
import sys
import re
import time
import string
import random
import subprocess
import logging
import configparser
import threading
import tempfile
import traceback
import humanize
from shutil import copyfile
from os import listdir
from os.path import isfile, join
from operator import itemgetter
from django.db.utils import ProgrammingError
from django.contrib import messages
from django.db import transaction
from django.db.utils import OperationalError

from Utils.models import Lock
from Hashcat.models import Session, Hashfile, Cracked
from Utils.hashcatAPI import HashcatAPI

class Hashcat(object):
    _hash_types = {}

    """
    @classmethod
    def init_locks(self):
        # Create a lock for each hashfile
        try:
            for hashfile in Hashfile.objects.all():
                self.hashfile_locks[hashfile.id] = threading.Lock()
        except ProgrammingError:
            pass
    """

    @classmethod
    def get_binary(self):
        config = configparser.ConfigParser()
        utils_dir = os.path.dirname(__file__)
        config.read(os.path.join(utils_dir, '..', 'settings.ini'))

        return config["Hashcat"]["binary"]

    @classmethod
    def get_potfile(self):
        config = configparser.ConfigParser()
        utils_dir = os.path.dirname(__file__)
        config.read(os.path.join(utils_dir, '..', 'settings.ini'))

        return config["Hashcat"]["potfile"]

    @classmethod
    def get_hash_types(self):
        if len(self._hash_types) == 0:
            self.parse_help()

        return self._hash_types

    """
        Parse hashcat version
    """
    @classmethod
    def parse_version(self):

        hashcat_version = subprocess.Popen([self.get_binary(), '-V'] , stdout=subprocess.PIPE)
        self.version = hashcat_version.communicate()[0].decode()

    """
        Parse hashcat help
    """
    @classmethod
    def parse_help(self):

        help_section = None
        help_section_regex = re.compile("^- \[ (?P<section_name>.*) \] -$")
        hash_mode_regex = re.compile("^\s*(?P<id>\d+)\s+\|\s+(?P<name>.+)\s+\|\s+(?P<description>.+)\s*$")

        hashcat_help = subprocess.Popen([self.get_binary(), '--help'], stdout=subprocess.PIPE)
        for line in hashcat_help.stdout:
            line = line.decode()
            line = line.rstrip()

            if len(line) == 0:
                continue

            section_match = help_section_regex.match(line)
            if section_match:
                help_section = section_match.group("section_name")
                continue

            if help_section == "Hash modes":
                hash_mode_match = hash_mode_regex.match(line)
                if hash_mode_match:
                    self._hash_types[int(hash_mode_match.group("id"))] = {
                        "id": int(hash_mode_match.group("id")),
                        "name": hash_mode_match.group("name"),
                        "description": hash_mode_match.group("description"),
                    }

    @classmethod
    def compare_potfile(self, hashfile, potfile=None):
        if not potfile:
            potfile = self.get_potfile()

        with transaction.atomic():
            # Lock: lock all the potfiles, this way only one instance of hashcat will be running at a time, the --left option eats a lot of RAM...
            potfile_locks = list(Lock.objects.select_for_update().filter(lock_ressource="potfile"))
            # Lock: prevent hashes file from being processed
            hashfile_lock = Lock.objects.select_for_update().filter(hashfile_id=hashfile.id, lock_ressource="hashfile")[0]
            # Lock: prevent cracked file from being processed
            crackedfile_lock = Lock.objects.select_for_update().filter(hashfile_id=hashfile.id, lock_ressource="crackedfile")[0]

            hashfile_path = os.path.join(os.path.dirname(__file__), "..", "Files", "Hashfiles", hashfile.hashfile)
            crackedfile_path = os.path.join(os.path.dirname(__file__), "..", "Files", "Crackedfiles", hashfile.crackedfile)

            # trick to allow multiple instances of hashcat
            session_name = ''.join(random.choice(string.ascii_uppercase + string.digits) for _ in range(12))

            # Get cracked hashes 
            cmd_line = [self.get_binary(), '--show', '-m', str(hashfile.hash_type), hashfile_path, '-o', crackedfile_path, '--session', session_name]
            cmd_line += ['--outfile-format', '3']
            if hashfile.username_included:
                cmd_line += ['--username']
            if potfile:
                cmd_line += ['--potfile-path', potfile]
            print("%s: Command: %s" % (hashfile.name, " ".join(cmd_line)))
            p = subprocess.Popen(cmd_line, stdout=subprocess.DEVNULL, stderr=subprocess.STDOUT)
            p.wait()

            # Remove cracked hashes from list
            f = tempfile.NamedTemporaryFile(delete=False)
            f.close()
            cmd_line = [self.get_binary(), '--left', '-m', str(hashfile.hash_type), hashfile_path, '-o', f.name, '--session', session_name]
            cmd_line += ['--outfile-format', '1']
            if hashfile.username_included:
                cmd_line += ['--username']
            if potfile:
                cmd_line += ['--potfile-path', potfile]
            print("%s: Command: %s" % (hashfile.name, " ".join(cmd_line)))
            p = subprocess.Popen(cmd_line, stdout=subprocess.DEVNULL, stderr=subprocess.STDOUT)
            p.wait()

            # hashcat over, remove lock on potfile and hashfile
            del hashfile_lock
            del potfile_locks

            copyfile(f.name, hashfile_path)
            os.remove(f.name)

            if os.path.exists(crackedfile_path):
                try:
                    batch_create_list = []
                    for index, line in enumerate(open(crackedfile_path, encoding='utf-8')):
                        if index < hashfile.cracked_count:
                            continue

                        line = line.strip()
                        password = line.split(":")[-1]
                        if hashfile.username_included:
                            username = line.split(":")[0]
                            password_hash = ":".join(line.split(":")[1:-1])
                        else:
                            username = None
                            password_hash = ":".join(line.split(":")[0:-1])

                        pass_len, pass_charset, _, pass_mask, _ = analyze_password(password)

                        cracked = Cracked(
                                hashfile=hashfile,
                                username=username,
                                password=password,
                                hash=password_hash,
                                password_len=pass_len,
                                password_charset=pass_charset,
                                password_mask=pass_mask,
                        )
                        batch_create_list.append(cracked)

                        if len(batch_create_list) >= 1000:
                            Cracked.objects.bulk_create(batch_create_list)
                            hashfile.cracked_count += len(batch_create_list)
                            hashfile.save()
                            batch_create_list = []
                    Cracked.objects.bulk_create(batch_create_list)
                    hashfile.cracked_count += len(batch_create_list)
                    hashfile.save()

                except Exception as e:
                    traceback.print_exc()

            # Crackedfile processing if over, remove lock
            del crackedfile_lock

    @classmethod
    def insert_plaintext(self, crackedfile):
        with transaction.atomic():
            # Lock: prevent cracked file from being processed
            crackedfile_lock = Lock.objects.select_for_update().filter(hashfile_id=crackedfile.id, lock_ressource="crackedfile")[0]

            crackedfile_path = os.path.join(os.path.dirname(__file__), "..", "Files", "Crackedfiles", crackedfile.crackedfile)
            if os.path.exists(crackedfile_path):
                try:
                    batch_create_list = []
                    for index, line in enumerate(open(crackedfile_path, encoding='utf-8')):
                        if index < crackedfile.cracked_count:
                            continue

                        line = line.strip()
                        password = line.split(":")[-1]
                        if crackedfile.username_included:
                            username = line.split(":")[0]
                            password_hash = ""
                        else:
                            username = None
                            password_hash = ""

                        pass_len, pass_charset, _, pass_mask, _ = analyze_password(password)

                        cracked = Cracked(
                                hashfile=crackedfile,
                                username=username,
                                password=password,
                                hash=password_hash,
                                password_len=pass_len,
                                password_charset=pass_charset,
                                password_mask=pass_mask,
                        )
                        batch_create_list.append(cracked)

                        if len(batch_create_list) >= 1000:
                            Cracked.objects.bulk_create(batch_create_list)
                            crackedfile.cracked_count += len(batch_create_list)
                            crackedfile.save()
                            batch_create_list = []
                    Cracked.objects.bulk_create(batch_create_list)
                    crackedfile.cracked_count += len(batch_create_list)
                    crackedfile.save()

                except Exception as e:
                    traceback.print_exc()



            # Crackedfile processing if over, remove lock
            del crackedfile_lock

    @classmethod
    def get_rules(self, detailed=True):

        res = []
        if not detailed:
            path = os.path.join(os.path.dirname(__file__), "..", "Files", "Rulefiles")
            res = [{"name": f} for f in listdir(path) if isfile(join(path, f)) and f.endswith(".rule")]
        else:
            path = os.path.join(os.path.dirname(__file__), "..", "Files", "Rulefiles", "*")
            # use md5sum instead of python code for performance issues on a big file
            result = subprocess.run('md5sum %s' % path, shell=True, stdout=subprocess.PIPE).stdout.decode()

            for line in result.split("\n"):
                items = line.split()
                if len(items) == 2:
                    res.append({
                        "name": items[1].split("/")[-1],
                        "md5": items[0],
                        "path": items[1],
                        })

        return sorted(res, key=itemgetter('name'))

    @classmethod
    def get_masks(self, detailed=True):

        res = []
        if not detailed:
            path = os.path.join(os.path.dirname(__file__), "..", "Files", "Maskfiles")
            res = [{"name": f} for f in listdir(path) if isfile(join(path, f)) and f.endswith(".hcmask")]
        else:
            path = os.path.join(os.path.dirname(__file__), "..", "Files", "Maskfiles", "*")
            # use md5sum instead of python code for performance issues on a big file
            result = subprocess.run('md5sum %s' % path, shell=True, stdout=subprocess.PIPE).stdout.decode()

            for line in result.split("\n"):
                items = line.split()
                if len(items) == 2:
                    res.append({
                        "name": items[1].split("/")[-1],
                        "md5": items[0],
                        "path": items[1],
                        })

        return sorted(res, key=itemgetter('name'))

    @classmethod
    def get_wordlists(self, detailed=True):

        res = []
        if not detailed:
            path = os.path.join(os.path.dirname(__file__), "..", "Files", "Wordlistfiles")

            res = [{"name": f} for f in listdir(path) if isfile(join(path, f)) and f.endswith(".wordlist")]
        else:
            path = os.path.join(os.path.dirname(__file__), "..", "Files", "Wordlistfiles", "*")
            # use md5sum instead of python code for performance issues on a big file
            result = subprocess.run('md5sum %s' % path, shell=True, stdout=subprocess.PIPE).stdout.decode()

            for line in result.split("\n"):
                items = line.split()
                if len(items) == 2:
                    info = {
                        "name": items[1].split("/")[-1],
                        "md5": items[0],
                        "path": items[1],
                    }

                    try:
                        info["lines"] = humanize.intcomma(sum(1 for _ in open(items[1], errors="backslashreplace")))
                    except UnicodeDecodeError:
                        print("Unicode decode error in file %s" % items[1])
                        info["lines"] = "error"
                    res.append(info)


        return sorted(res, key=itemgetter('name'))

    @classmethod
    def upload_rule(self, name, file):
        if not name.endswith(".rule"):
            name = "%s.rule" % name
        name = name.replace(" ", "_")

        path = os.path.join(os.path.dirname(__file__), "..", "Files", "Rulefiles", name)

        with open(path, "wb") as f:
            f.write(file)

    @classmethod
    def upload_mask(self, name, file):
        if not name.endswith(".hcmask"):
            name = "%s.hcmask" % name
        name = name.replace(" ", "_")

        path = os.path.join(os.path.dirname(__file__), "..", "Files", "Maskfiles", name)

        with open(path, "wb") as f:
            f.write(file)

    @classmethod
    def upload_wordlist(self, name, file):
        if not name.endswith(".wordlist"):
            name = "%s.wordlist" % name
        name = name.replace(" ", "_")

        path = os.path.join(os.path.dirname(__file__), "..", "Files", "Wordlistfiles", name)

        with open(path, "wb") as f:
            f.write(file)

    @classmethod
    def remove_rule(self, name):
        name = name.split("/")[-1]
        path = os.path.join(os.path.dirname(__file__), "..", "Files", "Rulefiles", name)

        try:
            os.remove(path)
        except Exception as e:
            pass

    @classmethod
    def remove_mask(self, name):
        name = name.split("/")[-1]
        path = os.path.join(os.path.dirname(__file__), "..", "Files", "Maskfiles", name)

        try:
            os.remove(path)
        except Exception as e:
            pass

    @classmethod
    def remove_wordlist(self, name):
        name = name.split("/")[-1]
        path = os.path.join(os.path.dirname(__file__), "..", "Files", "Wordlistfiles", name)

        try:
            os.remove(path)
        except Exception as e:
            pass

    @classmethod
    def update_hashfiles(self):

        self.backup_potfile()

        updated_hash_type = self.update_potfile()

        # now the potfile has been updated, update the cracked files
        for hashfile in Hashfile.objects.all():
            if hashfile.hash_type in updated_hash_type:
                try:
                    self.compare_potfile(hashfile)
                except OperationalError:
                    # Probably already being updated, no need to process it again
                    pass

    @classmethod
    def update_potfile(self):

        updated_hash_type = []

        with transaction.atomic():
            potfile_locks = list(Lock.objects.select_for_update().filter(lock_ressource="potfile"))

            print("Updating potfile")

            # update the potfile
            for session in Session.objects.all():
                try:
                    node = session.node

                    hashcat_api = HashcatAPI(node.hostname, node.port, node.username, node.password)

                    # Lock: prevent the potfile from being modified


                    remaining = True
                    while(remaining):
                        potfile_data = hashcat_api.get_potfile(session.name, session.potfile_line_retrieved)

                        if potfile_data["response"] == "ok" and potfile_data["line_count"] > 0:
                            updated_hash_type.append(session.hashfile.hash_type)

                            f = open(self.get_potfile(), "a", encoding='utf-8')
                            f.write(potfile_data["potfile_data"])
                            f.close()

                            session.potfile_line_retrieved += potfile_data["line_count"]
                            session.save()

                            remaining = potfile_data["remaining_data"]

                            # Probably quicker than a python equivalent code
                            tmp_potfile = "/tmp/webhashcat_potfile"
                            os.system("sort %s | uniq > %s; mv %s %s" % (Hashcat.get_potfile(), tmp_potfile, tmp_potfile, Hashcat.get_potfile()))
                        else:
                            remaining = False

                except ConnectionRefusedError:
                    pass

            print("Done updating potfile")

            del potfile_locks

        return updated_hash_type

    @classmethod
    def backup_potfile(self):
        potfile_path = self.get_potfile()
        potfile_backup_path = potfile_path + ".bkp"

        if os.path.exists(potfile_path):
            potfile_line_count = sum(1 for _ in open(potfile_path, errors="backslashreplace"))
        else:
            potfile_line_count = 0

        if os.path.exists(potfile_backup_path):
            potfile_backup_line_count = sum(1 for _ in open(potfile_backup_path, errors="backslashreplace"))
        else:
            potfile_backup_line_count = 0

        if potfile_line_count > potfile_backup_line_count:
            copyfile(potfile_path, potfile_backup_path)
        elif potfile_line_count < potfile_backup_line_count:
            # It can happen when the RAW is full, hashcat fails and the potfile might get corrupted
            print("ERROR: potfile corrupted !!!!")

# This function is taken from https://github.com/iphelix/pack

def analyze_password(password):

    # Password length
    if password.startswith("$HEX["):
        pass_length = (len(password)-6)/2
        return (pass_length, "unknown", None, None, None)
    else:
        pass_length = len(password)

    # Character-set and policy counters
    digit = 0
    lower = 0
    upper = 0
    special = 0

    simplemask = list()
    advancedmask_string = ""

    # Detect simple and advanced masks
    for letter in password:

        if letter in string.digits:
            digit += 1
            advancedmask_string += "?d"
            if not simplemask or not simplemask[-1] == 'digit': simplemask.append('digit')

        elif letter in string.ascii_lowercase:
            lower += 1
            advancedmask_string += "?l"
            if not simplemask or not simplemask[-1] == 'string': simplemask.append('string')


        elif letter in string.ascii_uppercase:
            upper += 1
            advancedmask_string += "?u"
            if not simplemask or not simplemask[-1] == 'string': simplemask.append('string')

        else:
            special += 1
            advancedmask_string += "?s"
            if not simplemask or not simplemask[-1] == 'special': simplemask.append('special')


    # String representation of masks
    simplemask_string = ''.join(simplemask) if len(simplemask) <= 3 else 'othermask'

    # Policy
    policy = (digit,lower,upper,special)

    # Determine character-set
    if   digit and not lower and not upper and not special: charset = 'numeric'
    elif not digit and lower and not upper and not special: charset = 'loweralpha'
    elif not digit and not lower and upper and not special: charset = 'upperalpha'
    elif not digit and not lower and not upper and special: charset = 'special'

    elif not digit and lower and upper and not special:     charset = 'mixedalpha'
    elif digit and lower and not upper and not special:     charset = 'loweralphanum'
    elif digit and not lower and upper and not special:     charset = 'upperalphanum'
    elif not digit and lower and not upper and special:     charset = 'loweralphaspecial'
    elif not digit and not lower and upper and special:     charset = 'upperalphaspecial'
    elif digit and not lower and not upper and special:     charset = 'specialnum'

    elif not digit and lower and upper and special:         charset = 'mixedalphaspecial'
    elif digit and not lower and upper and special:         charset = 'upperalphaspecialnum'
    elif digit and lower and not upper and special:         charset = 'loweralphaspecialnum'
    elif digit and lower and upper and not special:         charset = 'mixedalphanum'
    else:                                                   charset = 'all'

    return (pass_length, charset, simplemask_string, advancedmask_string, policy)



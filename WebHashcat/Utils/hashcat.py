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
from hashlib import sha1
from operator import itemgetter
from django.db.utils import ProgrammingError
from django.contrib import messages
from django.db import transaction
from django.db import connection
from django.db.utils import OperationalError

from Utils.models import Lock
from Hashcat.models import Session, Hashfile, Hash
from Utils.hashcatAPI import HashcatAPI
from Utils.utils import del_hashfile_locks

class ClassProperty(property):
    def __get__(self, cls, owner):
        return self.fget.__get__(None, owner)()

class Hashcat(object):
    _hash_types = {}
    _version = None

    @classmethod
    def get_binary(self):
        config = configparser.ConfigParser()
        utils_dir = os.path.dirname(os.path.abspath( __file__ ))
        config.read(os.path.join(utils_dir, '..', 'settings.ini'))

        return config["Hashcat"]["binary"]

    @classmethod
    def get_potfile(self):
        config = configparser.ConfigParser()
        utils_dir =  os.path.dirname(os.path.abspath( __file__ ))
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
        self._version = hashcat_version.communicate()[0].decode()

    @ClassProperty
    @classmethod
    def version(self):
        if not self._version:
            self.parse_version()

        return self._version

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
                        "name": "%s (%d)" % (hash_mode_match.group("name"), int(hash_mode_match.group("id"))),
                        "description": hash_mode_match.group("description"),
                    }

    @classmethod
    def compare_potfile(self, hashfile, potfile=None):
        if not potfile:
            potfile = self.get_potfile()

        with transaction.atomic():
            locked = False
            while not locked:
                try:
                    # Lock: lock all the potfiles, this way only one instance of hashcat will be running at a time, the --left option eats a lot of RAM...
                    potfile_locks = list(Lock.objects.select_for_update().filter(lock_ressource="potfile"))
                    # Lock: prevent hashes file from being processed
                    hashfile_lock = Lock.objects.select_for_update().filter(hashfile_id=hashfile.id, lock_ressource="hashfile")[0]

                    locked = True
                except OperationalError as e:
                    continue

        hashfile_path = os.path.join(os.path.dirname(__file__), "..", "Files", "Hashfiles", hashfile.hashfile)

        # trick to allow multiple instances of hashcat
        session_name = ''.join(random.choice(string.ascii_uppercase + string.digits) for _ in range(12))

        cracked_file = tempfile.NamedTemporaryFile(delete=False)

        hashcat_big_version = int(self.version[1:].split('.')[0])

        # is there a way to combine --show and --remove in hashcat ?

        # Get cracked hashes
        cmd_line = [self.get_binary(), '--show', '-m', str(hashfile.hash_type), hashfile_path, '-o', cracked_file.name, '--session', session_name]
        if hashcat_big_version >= 6:
            cmd_line += ['--outfile-format', '1,2']
        else:
            cmd_line += ['--outfile-format', '3']
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
        if potfile:
            cmd_line += ['--potfile-path', potfile]
        print("%s: Command: %s" % (hashfile.name, " ".join(cmd_line)))
        p = subprocess.Popen(cmd_line, stdout=subprocess.DEVNULL, stderr=subprocess.STDOUT)
        p.wait()

        copyfile(f.name, hashfile_path)
        os.remove(f.name)

        # hashcat over, remove lock on potfile and hashfile
        del potfile_locks
        del hashfile_lock

        if os.path.exists(cracked_file.name):
            start = time.perf_counter()

            cursor = connection.cursor()
            tmp_table_name = "tmp_table_%s" % ''.join(random.choice(string.ascii_lowercase+string.digits) for i in range(10))
            try:
                # create temporary table
                cursor.execute("BEGIN;")
                cursor.execute("CREATE TEMPORARY TABLE " + tmp_table_name + " (hash_hash varchar(190) PRIMARY KEY, hash LONGTEXT, password varchar(190) NOT NULL, pass_len INTEGER, pass_charset varchar(190), pass_mask varchar(190));")
                cursor.execute("SET unique_checks=0;")

                bulk_insert_list = []
                nb_insert = 0
                for index, line in enumerate(open(cracked_file.name, encoding='utf-8')):
                    line = line.strip()
                    password = line.split(":")[-1]
                    password_hash = ":".join(line.split(":")[0:-1])
                    password_hash_hash = sha1(password_hash.encode()).hexdigest()

                    pass_len, pass_charset, _, pass_mask, _ = analyze_password(password)

                    bulk_insert_list += [password_hash_hash, password_hash, password, pass_len, pass_charset, pass_mask]
                    nb_insert += 1

                    if nb_insert >= 1000:
                        cursor.execute("INSERT INTO " + tmp_table_name + " VALUES " + ", ".join(["(%s, %s, %s, %s, %s, %s)"]*nb_insert) + ";", bulk_insert_list)
                        bulk_insert_list = []
                        nb_insert = 0

                    # insert into table every 100K rows will prevent MySQL from raising "The number of locks exceeds the lock table size"
                    if index % 100000 == 0:
                        cursor.execute("UPDATE " + tmp_table_name + " b JOIN Hashcat_hash a ON a.hash_hash = b.hash_hash AND a.hash_type=%s SET a.password = b.password, a.password_len = b.pass_len, a.password_charset = b.pass_charset, a.password_mask = b.pass_mask;", [hashfile.hash_type])
                        cursor.execute("DELETE FROM " + tmp_table_name + ";")
                        cursor.execute("COMMIT;")

                if len(bulk_insert_list) != 0:
                    cursor.execute("INSERT INTO " + tmp_table_name + " VALUES " + ", ".join(["(%s, %s, %s, %s, %s, %s)"]*nb_insert) + ";", bulk_insert_list)

                cursor.execute("UPDATE " + tmp_table_name + " b JOIN Hashcat_hash a ON a.hash_hash = b.hash_hash AND a.hash_type=%s SET a.password = b.password, a.password_len = b.pass_len, a.password_charset = b.pass_charset, a.password_mask = b.pass_mask;", [hashfile.hash_type])
                cursor.execute("COMMIT;")
            except Exception as e:
                traceback.print_exc()
            finally:
                cursor.execute("SET unique_checks=1;")
                cursor.execute("DROP TABLE %s;" % tmp_table_name)
                cursor.execute("COMMIT;")
                cursor.close()

                hashfile.cracked_count = Hash.objects.filter(hashfile_id=hashfile.id, password__isnull=False).count()
                hashfile.save()

            end = time.perf_counter()
            print("Update password time: %fs" % (end-start,))

            os.remove(cracked_file.name)

    # executed only when file is uploaded
    @classmethod
    def insert_hashes(self, hashfile):

        with transaction.atomic():
            locked = False
            while not locked:
                try:
                    # Lock: prevent cracked file from being processed
                    hashfile_lock = Lock.objects.select_for_update().filter(hashfile_id=hashfile.id, lock_ressource="hashfile")[0]

                    locked = True
                except OperationalError as e:
                    continue

        hashfile_path = os.path.join(os.path.dirname(__file__), "..", "Files", "Hashfiles", hashfile.hashfile)
        if os.path.exists(hashfile_path):


            try:
                # 0 - Hashcat can change the hash output (upper/lower chars), lets pass them through hashcat first

                f = tempfile.NamedTemporaryFile(delete=False)
                f.close()
                cmd_line = [self.get_binary(), '--left', '-m', str(hashfile.hash_type), hashfile_path, '-o', f.name]
                cmd_line += ['--outfile-format', '1']
                cmd_line += ['--potfile-path', '/dev/null']
                if hashfile.username_included:
                    cmd_line += ['--username']

                print("%s: Command: %s" % (hashfile.name, " ".join(cmd_line)))
                p = subprocess.Popen(cmd_line, stdout=subprocess.DEVNULL, stderr=subprocess.STDOUT)
                p.wait()

                # 1 - import hashfile to database

                start = time.perf_counter()

                batch_create_list = []
                hash_count = 0
                for index, line in enumerate(open(f.name, encoding='utf-8')):
                    try:
                        line = line.strip()
                        if hashfile.username_included:
                            username = line.split(":")[0]
                            password_hash = ":".join(line.split(":")[1:])
                        else:
                            username = None
                            password_hash = line
                    except IndexError:
                        continue

                    if len(password_hash) == 0:
                        continue

                    # SHA1 of the hash for joins in MySQL
                    password_hash_hash = sha1(password_hash.encode()).hexdigest()

                    h = Hash(
                            hashfile=hashfile,
                            hash_type=hashfile.hash_type,
                            username=username,
                            hash=password_hash,
                            hash_hash=password_hash_hash,
                            password=None,
                            password_len=None,
                            password_charset=None,
                            password_mask=None,
                    )
                    batch_create_list.append(h)

                    if len(batch_create_list) >= 100000:
                        hashfile.line_count += len(batch_create_list)
                        while len(batch_create_list) != 0:
                            Hash.objects.bulk_create(batch_create_list[:1000])
                            batch_create_list = batch_create_list[1000:]
                        hashfile.save()

                os.remove(f.name)

                hashfile.line_count += len(batch_create_list)
                while len(batch_create_list) != 0:
                    Hash.objects.bulk_create(batch_create_list[:1000])
                    batch_create_list = batch_create_list[1000:]
                hashfile.save()

                end = time.perf_counter()
                print("Inserted hashes in : %fs" % (end-start,))

                # 2 - if username in hashfile, delete file and create one with only the hashes, 
                #     --username takes a lot of RAM with hashcat, this method is better when processing huge hashfiles

                start = time.perf_counter()

                if hashfile.username_included:
                    os.remove(hashfile_path)

                    tmpfile_name = ''.join([random.choice(string.ascii_lowercase) for i in range(16)])
                    tmpfile_path = os.path.join(os.path.dirname(__file__), "..", "Files", "tmp", tmpfile_name)

                    f = open(tmpfile_path, "w")

                    cursor = connection.cursor()
                    #cursor.execute("SELECT DISTINCT hash FROM Hashcat_hash WHERE hashfile_id=%s INTO OUTFILE %s", [hashfile.id, tmpfile_path])
                    cursor.execute("SELECT DISTINCT hash FROM Hashcat_hash WHERE hashfile_id=%s", [hashfile.id])
                    for row in cursor.fetchall():
                        f.write("%s\n" % row[0])
                    cursor.close()

                    f.close()

                    copyfile(tmpfile_path, hashfile_path)
                    os.remove(tmpfile_path)

                end = time.perf_counter()
                print("Wrote hashfile on disk in : %fs" % (end-start,))

            except Exception as e:
                traceback.print_exc()
        else:
            print("Error: hashfile doesn't exists")

        # Crackedfile processing if over, remove lock
        del hashfile_lock

    # executed only when file is uploaded
    @classmethod
    def insert_plaintext(self, hashfile):

        with transaction.atomic():
            locked = False
            while not locked:
                try:
                    # Lock: prevent cracked file from being processed
                    hashfile_lock = Lock.objects.select_for_update().filter(hashfile_id=hashfile.id, lock_ressource="hashfile")[0]

                    locked = True
                except OperationalError as e:
                    continue

        hashfile_path = os.path.join(os.path.dirname(__file__), "..", "Files", "Hashfiles", hashfile.hashfile)
        if os.path.exists(hashfile_path):
            try:
                batch_create_list = []
                for index, line in enumerate(open(hashfile_path, encoding='utf-8')):
                    if index < hashfile.cracked_count:
                        continue

                    line = line.strip()
                    password = line.split(":")[-1]
                    if hashfile.username_included:
                        username = line.split(":")[0]
                        password_hash = ""
                    else:
                        username = None
                        password_hash = ""

                    pass_len, pass_charset, _, pass_mask, _ = analyze_password(password)

                    h = Hash(
                            hashfile=hashfile,
                            hash_type=hashfile.hash_type,
                            username=username,
                            password=password,
                            hash=password_hash,
                            password_len=pass_len,
                            password_charset=pass_charset,
                            password_mask=pass_mask,
                    )
                    batch_create_list.append(h)

                    if len(batch_create_list) >= 100000:
                        hashfile.line_count += len(batch_create_list)
                        hashfile.cracked_count += len(batch_create_list)
                        while len(batch_create_list) != 0:
                            Hash.objects.bulk_create(batch_create_list[:1000])
                            batch_create_list = batch_create_list[1000:]
                        hashfile.save()

                hashfile.line_count += len(batch_create_list)
                hashfile.cracked_count += len(batch_create_list)
                while len(batch_create_list) != 0:
                    Hash.objects.bulk_create(batch_create_list[:1000])
                    batch_create_list = batch_create_list[1000:]
                hashfile.save()

            except Exception as e:
                traceback.print_exc()

            # Crackedfile processing if over, remove lock
            del hashfile_lock

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

        updated_hashfile_ids = self.update_potfile()
        print(updated_hashfile_ids)

        for hashfile_id in updated_hashfile_ids:
            hashfile = Hashfile.objects.get(id=hashfile_id)
            try:
                self.compare_potfile(hashfile)
            except OperationalError:
                # Probably already being updated, no need to process it again
                pass

    @classmethod
    def update_potfile(self):

        updated_hashfile_ids = []

        with transaction.atomic():
            try:
                # Lock: prevent the potfile from being modified
                potfile_locks = list(Lock.objects.select_for_update().filter(lock_ressource="potfile"))

                # update the potfile
                for session in Session.objects.all():
                    try:
                        node = session.node

                        hashcat_api = HashcatAPI(node.hostname, node.port, node.username, node.password)

                        remaining = True
                        while(remaining):
                            potfile_data = hashcat_api.get_potfile(session.name, session.potfile_line_retrieved)
                            if potfile_data != None and potfile_data["response"] == "ok" and potfile_data["line_count"] > 0:
                                f = open(self.get_potfile(), "a", encoding='utf-8')
                                f.write(potfile_data["potfile_data"])
                                f.close()

                                session.potfile_line_retrieved += potfile_data["line_count"]
                                session.save()

                                remaining = potfile_data["remaining_data"]

                                updated_hashfile_ids.append(session.hashfile.id)
                            else:
                                remaining = False

                    except ConnectionRefusedError:
                        pass

                del potfile_locks
            except OperationalError as e:
                # potfile is locked, no need to be concerned about it, this function is executed regularly
                print("Error: potfile locked")

        return list(set(updated_hashfile_ids))

    @classmethod
    def optimize_potfile(self):

        self.backup_potfile()

        optimized = False
        while not optimized:
            with transaction.atomic():
                try:
                    # Lock: prevent the potfile from being modified
                    potfile_locks = list(Lock.objects.select_for_update().filter(lock_ressource="potfile"))

                    # Probably quicker than a python equivalent code
                    tmp_potfile = "/tmp/webhashcat_potfile"
                    os.system("sort %s | uniq > %s; mv %s %s" % (Hashcat.get_potfile(), tmp_potfile, tmp_potfile, Hashcat.get_potfile()))

                    del potfile_locks

                    optimized = True

                except OperationalError as e:
                    pass


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

    @classmethod
    def remove_hashfile(self, hashfile):
        # Check if there is a running session
        for session in Session.objects.filter(hashfile_id=hashfile.id):
            node = session.node

            try:
                hashcat_api = HashcatAPI(node.hostname, node.port, node.username, node.password)
                hashcat_api.action(session.name, "remove")
            except Exception as e:
                traceback.print_exc()

        hashfile_path = os.path.join(os.path.dirname(__file__), "..", "Files", "Hashfiles", hashfile.hashfile)

        # remove from disk
        try:
            os.remove(hashfile_path)
        except Exception as e:
            pass

        del_hashfile_locks(hashfile)

        start = time.perf_counter()
        # deletion is faster using raw SQL queries
        cursor = connection.cursor()
        cursor.execute("DELETE FROM Hashcat_session WHERE hashfile_id = %s", [hashfile.id])
        cursor.execute("DELETE FROM Hashcat_hash WHERE hashfile_id = %s", [hashfile.id])
        cursor.close()
        hashfile.delete()
        end = time.perf_counter()
        print(">>> Hashfile %s deleted from database in %fs" % (hashfile.name, end-start))

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




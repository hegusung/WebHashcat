#!/usr/bin/python3
import os
import sys
import re
import time
import subprocess
import logging
from os import listdir
from os.path import isfile, join
from datetime import datetime
import threading
import random
import string
import operator
from peewee import Model, SqliteDatabase, CharField, DateTimeField, ForeignKeyField, IntegerField, BooleanField, TextField, BlobField, FloatField
from fcntl import fcntl, F_GETFL, F_SETFL
from os import O_NONBLOCK, read

database = SqliteDatabase(os.path.dirname(__file__) + os.sep + "hashcatnode.db")

class Hashcat(object):

    hash_modes = {}
    rules = {}
    masks = {}
    wordlists = {}
    sessions = {}
    workload_profile = 3 # default hashcat value

    """
        Parse hashcat version
    """
    @classmethod
    def parse_version(self):

        hashcat_version = subprocess.Popen([self.binary, '-V'] , stdout=subprocess.PIPE)
        self.version = hashcat_version.communicate()[0].decode()

    """
        Parse hashcat help
    """
    @classmethod
    def parse_help(self):

        help_section = None
        help_section_regex = re.compile("^- \[ (?P<section_name>.*) \] -$")
        hash_mode_regex = re.compile("^\s*(?P<id>\d+)\s+\|\s+(?P<name>.+)\s+\|\s+(?P<description>.+)\s*$")

        hashcat_help = subprocess.Popen([self.binary, '--help'], stdout=subprocess.PIPE)
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
                    self.hash_modes[int(hash_mode_match.group("id"))] = {
                        "id": int(hash_mode_match.group("id")),
                        "name": hash_mode_match.group("name"),
                        "description": hash_mode_match.group("description"),
                    }
    """
        Parse rule directory
    """
    @classmethod
    def parse_rules(self):
        self.rules = {}

        path = os.path.join(self.rules_dir, "*")

        # use md5sum instead of python code for performance issues on a big file
        result = subprocess.run('md5sum %s' % path, shell=True, stdout=subprocess.PIPE).stdout.decode()

        for line in result.split("\n"):
            items = line.split()
            if len(items) == 2:
                self.rules[items[1].split("/")[-1]] = {
                        "name": items[1].split("/")[-1],
                        "md5": items[0],
                        "path": items[1],
                    }

    """
        Parse wordlist directory
    """
    @classmethod
    def parse_wordlists(self):
        self.wordlists = {}

        path = os.path.join(self.wordlist_dir, "*")

        # use md5sum instead of python code for performance issues on a big file
        result = subprocess.run('md5sum %s' % path, shell=True, stdout=subprocess.PIPE).stdout.decode()

        for line in result.split("\n"):
            items = line.split()
            if len(items) == 2:
                self.wordlists[items[1].split("/")[-1]] = {
                        "name": items[1].split("/")[-1],
                        "md5": items[0],
                        "path": items[1],
                    }

    """
        Parse mask directory
    """
    @classmethod
    def parse_masks(self):
        self.masks = {}

        path = os.path.join(self.mask_dir, "*")

        # use md5sum instead of python code for performance issues on a big file
        result = subprocess.run('md5sum %s' % path, shell=True, stdout=subprocess.PIPE).stdout.decode()

        for line in result.split("\n"):
            items = line.split()
            if len(items) == 2:
                self.masks[items[1].split("/")[-1]] = {
                        "name": items[1].split("/")[-1],
                        "md5": items[0],
                        "path": items[1],
                    }

    """
        Create a new session
    """
    @classmethod
    def create_session(self, name, crack_type, hash_file, hash_mode_id, wordlist, rule, mask, username_included, device_type, end_timestamp):

        if name in self.sessions:
            raise Exception("This session name has already been used")

        if not hash_mode_id in self.hash_modes:
            raise Exception("Inexistant hash mode, did you upgraded hashcat ?")

        if not crack_type in ["dictionary", "mask"]:
            raise Exception("Unsupported cracking type: %s" % crack_type)

        if not device_type in [1, 2, 3]:
            raise Exception("Unsupported device type: %d" % device_type)

        if crack_type == "dictionary":
            if rule != None and not rule in self.rules:
                raise Exception("Inexistant rule, did you synchronise the files on your node ?")
            elif rule == None:
                rule_path = None
            else:
                rule_path = self.rules[rule]["path"]

            if wordlist == None or not wordlist in self.wordlists:
                raise Exception("Inexistant wordlist, did you synchronise the files on your node ?")
            wordlist_path = self.wordlists[wordlist]["path"]

            mask_path = None
        elif crack_type == "mask":
            if mask == None or not mask in self.masks:
                raise Exception("Inexistant mask, did you synchronise the files on your node ?")
            mask_path = self.masks[mask]["path"]
            rule_path = None
            wordlist_path = None

        pot_file = os.path.join(os.path.dirname(__file__), "potfiles", ''.join(random.choice(string.ascii_uppercase + string.digits) for _ in range(12)) + ".potfile")

        session = Session(
            name=name,
            crack_type=crack_type,
            hash_file=hash_file,
            pot_file = pot_file,
            hash_mode_id=hash_mode_id,
            wordlist_file=wordlist_path,
            rule_file=rule_path,
            mask_file=mask_path,
            username_included=username_included,
            device_type=device_type,
            end_timestamp=end_timestamp,
            session_status="Not started",
            time_started=None,
            progress=0,
            reason="",
        )
        self.sessions[session.name] = session
        session.setup()
        session.save()

        logging.info("Session %s created" % name)

        return session

    """
        Remove a session
    """
    @classmethod
    def remove_session(self, name):

        if not name in self.sessions:
            raise Exception("This session name doesn't exists")

        self.sessions[name].remove()
        self.sessions[name].delete_instance()

        del self.sessions[name]

        logging.info("Session %s removed" % name)

    """
        Reload sessions
    """
    @classmethod
    def reload_sessions(self):

        for session in Session.select():
            if session.session_status in ["Running", "Paused"]:
                session.session_status = "Aborted"
                session.reason = ""
                session.save()
            self.sessions[session.name] = session
            session.setup()

    """
        Upload a new rule file
    """
    @classmethod
    def upload_rule(self, name, rules):

        name = name.split("/")[-1]

        if not name.endswith(".rule"):
            name += ".rule"

        path = os.path.join(self.rules_dir, name)

        if name in self.rules:
            try:
                os.remove(path)
            except Exception as e:
                pass

        f = open(path, "wb")
        f.write(rules)
        f.close()

        self.parse_rules()

        logging.info("Rule file %s uploaded" % name)

    """
        Upload a new mask file
    """
    @classmethod
    def upload_mask(self, name, masks):

        name = name.split("/")[-1]

        if not name.endswith(".hcmask"):
            name += ".hcmask"

        path = os.path.join(self.mask_dir, name)

        if name in self.masks:
            try:
                os.remove(path)
            except Exception as e:
                pass

        f = open(path, "wb")
        f.write(masks)
        f.close()

        self.parse_masks()

        logging.info("Mask file %s uploaded" % name)

    """
        Upload a new wordlist file
    """
    @classmethod
    def upload_wordlist(self, name, wordlists):

        name = name.split("/")[-1]

        if not name.endswith(".wordlist"):
            name += ".wordlist"

        path = os.path.join(self.wordlist_dir, name)

        if name in self.wordlists:
            try:
                os.remove(path)
            except Exception as e:
                pass

        f = open(path, "wb")
        f.write(wordlists)
        f.close()

        self.parse_wordlists()

        logging.info("Wordlist file %s uploaded" % name)


class Session(Model):
    name = CharField(unique=True)
    crack_type = CharField()
    hash_file = CharField()
    pot_file = CharField()
    hash_mode_id = IntegerField()
    rule_file = CharField(null=True)
    wordlist_file = CharField(null=True)
    mask_file = CharField(null=True)
    username_included = BooleanField()
    device_type = IntegerField()
    end_timestamp = IntegerField(null=True)
    session_status = CharField()
    time_started = DateTimeField(null=True)
    progress = FloatField()
    reason = TextField()

    class Meta:
        database = database

    def setup(self):
        # File to store the processes output
        random_name = ''.join(random.choice(string.ascii_uppercase + string.digits) for _ in range(12))
        self.result_file = os.path.join("/tmp", random_name+".cracked")

        # File to store the hashcat output
        random_name = ''.join(random.choice(string.ascii_uppercase + string.digits) for _ in range(12))
        self.hashcat_output_file = os.path.join("/tmp", random_name+".hashcat")
        open(self.hashcat_output_file,'a').close()

        self.hash_type = "N/A"
        self.time_estimated = "N/A"
        self.speed = "N/A"
        self.recovered = "N/A"

    def start(self):
        self.thread = threading.Thread(target=self.session_thread)
        self.thread.start()

        # Little delay to ensure the process if properly launched
        time.sleep(1)

        self.status()

    def session_thread(self):
        # Prepare regex to parse the main hashcat process output
        regex_list = [
            ("hash_type", re.compile("^Hash\.Type\.+: (.*)\s*$")),
            ("speed", re.compile("^Speed\.Dev\.#1\.+: (.*)\s*$")),
        ]
        if self.crack_type == "dictionary":
            regex_list.append(("progress", re.compile("^Progress\.+: \d+/\d+ \((\S+)%\)\s*$")))
            regex_list.append(("time_estimated", re.compile("^Time\.Estimated\.+: (.*)\s*$")))
        elif self.crack_type == "mask":
            regex_list.append(("progress", re.compile("^Input\.Mode\.+:\s+Mask\s+\(\S+\)\s+\[\d+\]\s+\((\S+)%\)\s*$")))

        self.time_started = str(datetime.now())

        if not self.session_status in ["Aborted"]:
            # Command lines used to crack the passwords
            if self.crack_type == "dictionary":
                if self.rule_file != None:
                    cmd_line = [Hashcat.binary, '--session', self.name, '--status', '-a', '0', '-m', str(self.hash_mode_id), self.hash_file, self.wordlist_file, '-r', self.rule_file]
                else:
                    cmd_line = [Hashcat.binary, '--session', self.name, '--status', '-a', '0', '-m', str(self.hash_mode_id), self.hash_file, self.wordlist_file]
            if self.crack_type == "mask":
                cmd_line = [Hashcat.binary, '--session', self.name, '--status', '-a', '3', '-m', str(self.hash_mode_id), self.hash_file, self.mask_file]
            if self.username_included:
                cmd_line += ["--username"]
            if self.device_type:
                cmd_line += ["-D", str(self.device_type)]
            # workload profile
            cmd_line += ["--workload-profile", Hashcat.workload_profile]
            # set pot file
            cmd_line += ["--potfile-path", self.pot_file]
        else:
            # resume previous session
            cmd_line = [Hashcat.binary, '--session', self.name, '--restore']

        print("Session:%s, startup command:%s" % (self.name, " ".join(cmd_line)))
        logging.debug("Session:%s, startup command:%s" % (self.name, " ".join(cmd_line)))
        with open(self.hashcat_output_file, "a") as f:
            f.write("Command: %s\n" % " ".join(cmd_line))

        self.session_status = "Running"
        self.time_started = datetime.utcnow()
        self.save()

        self.session_process = subprocess.Popen(cmd_line, stdout=subprocess.PIPE, stdin=subprocess.PIPE, stderr=subprocess.PIPE)

        self.update_session()

        for line in self.session_process.stdout:
            with open(self.hashcat_output_file, "ab") as f:
                f.write(line)

            line = line.decode()
            line = line.rstrip()

            if line == "Resumed":
                self.session_status = "Running"
                self.save()

            if line == "Paused":
                self.session_status = "Paused"
                self.save()

            for var_regex in regex_list:
                var = var_regex[0]
                regex = var_regex[1]

                m = regex.match(line)
                if m:
                    setattr(self, var, m.group(1))

            # check timestamp
            if self.end_timestamp:
                current_timestamp = int(datetime.utcnow().timestamp())

                if current_timestamp > self.end_timestamp:
                    self.session_process.stdin.write(b'q')
                    self.session_process.stdin.flush()
                    break


        return_code = self.session_process.wait()
        # The cracking ended, set the parameters accordingly
        if return_code in [255,254]:
            self.session_status = "Error"
            if return_code == 254:
                self.reason = "GPU-watchdog alarm"
            else:
                ansi_escape = re.compile(r'\x1B\[[0-?]*[ -/]*[@-~]')
                error_msg = self.session_process.stderr.read().decode()
                error_msg = ansi_escape.sub('', error_msg).strip()
                self.reason = error_msg
        elif return_code in [2,3,4]:
            self.session_status = "Aborted"
            self.reason = ""
        else:
            self.session_status = "Done"
            self.reason = ""
        self.time_estimated = "N/A"
        self.speed = "N/A"
        self.save()

    def details(self):
        return {
            "name": self.name,
            "crack_type": self.crack_type,
            "device_type": self.device_type,
            "rule": self.rule_file.split("/")[-1][:-5] if self.rule_file else None,
            "mask": self.mask_file.split("/")[-1][:-7] if self.mask_file else None,
            "wordlist": self.wordlist_file.split("/")[-1][:-1*len(".wordlist")] if self.wordlist_file else None,
            "status": self.session_status,
            "time_started": str(self.time_started),
            "time_estimated": self.time_estimated,
            "speed": self.speed,
            "progress": self.progress,
            "reason": self.reason,
        }

    """
        Returns the first 100000 lines from the potfile starting from a specific line
    """
    def get_potfile(self, from_line):
        line_count = 0
        selected_line_count = 0
        potfile_data = ""
        complete = True
        if os.path.exists(self.pot_file):
            for line in open(self.pot_file, encoding="utf-8"):
                if not line.endswith("\n"):
                    complete = True
                    break

                if line_count >= from_line:
                    potfile_data += line
                    selected_line_count += 1

                if selected_line_count >= 100000:
                    complete = False
                    break

                line_count += 1

            return {
                "line_count": selected_line_count,
                "remaining_data": not complete,
                "potfile_data": potfile_data,
            }
        else:
            return {
                "line_count": 0,
                "remaining_data": False,
                "potfile_data": "",
            }


    """
        Returns hashcat output file
    """
    def hashcat_output(self):
        return open(self.hashcat_output_file).read()

    """
        Returns hashes file
    """
    def hashes(self):
        return open(self.hash_file).read()


    """
        Cleanup the session before deleting it
    """
    def remove(self):
        self.quit()

        try:
            os.remove(self.result_file)
        except:
            pass
        try:
            os.remove(self.pot_file)
        except:
            pass
        try:
            os.remove(self.hash_file)
        except:
            pass
        try:
            os.remove(self.hashcat_output_file)
        except:
            pass

    """
        Return cracked passwords
    """
    def cracked(self):

        # gather cracked passwords
        cmd_line = [Hashcat.binary, '--show', '-m', str(self.hash_mode_id), self.hash_file, '-o', self.result_file]
        if self.username_included:
            cmd_line += ["--username", "--outfile-format", "2"]
        else:
            cmd_line += ["--outfile-format", "3"]
        cmd_line += ["--potfile-path", self.pot_file]
        p = subprocess.Popen(cmd_line)
        p.wait()

        return open(self.result_file).read()

    """
        Update the session
    """
    def update_session(self):
        self.status()

    """
        Update the session
    """
    def status(self):
        if not self.session_status in ["Paused", "Running"]:
            return

        self.session_process.stdin.write(b's')
        self.session_process.stdin.flush()

    """
        Pause the session
    """
    def pause(self):
        if not self.session_status in ["Paused", "Running"]:
            return

        while self.session_status != "Paused":
            self.session_process.stdin.write(b'p')
            self.session_process.stdin.flush()

            self.update_session()

            time.sleep(0.1)

    """
        Resume the session
    """
    def resume(self):
        if not self.session_status in ["Paused", "Running"]:
            return

        while self.session_status != "Running":
            self.session_process.stdin.write(b'r')
            self.session_process.stdin.flush()

            self.update_session()

            time.sleep(0.1)

    """
        Quit the session
    """
    def quit(self):
        if not self.session_status in ["Paused", "Running"]:
            return

        self.session_process.stdin.write(b'q')
        self.session_process.stdin.flush()

        self.thread.join()

        self.session_status = "Aborted"
        self.save()

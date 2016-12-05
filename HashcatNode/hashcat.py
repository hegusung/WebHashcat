#!/usr/bin/python3
import os
import sys
import re
import time
import subprocess
from os import listdir
from os.path import isfile, join
from datetime import datetime
import threading
import random
import string
import operator

class Hashcat(object):

    def __init__(self, binary, rules_dir, wordlist_dir, mask_dir):
        self.binary = binary
        self.rules_dir = rules_dir
        self.wordlist_dir = wordlist_dir
        self.mask_dir = mask_dir

        self.hash_modes = {}
        self.rules = {}
        self.masks = {}
        self.wordlists = {}
        self.sessions = {}

        self.parse_version()
        self.parse_help()
        self.parse_rules()
        self.parse_masks()
        self.parse_wordlists()

    """
        Parse hashcat version
    """
    def parse_version(self):

        hashcat_version = subprocess.Popen([self.binary, '-V'] , stdout=subprocess.PIPE)
        self.version = hashcat_version.communicate()[0].decode()

    """
        Parse hashcat help
    """
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
    def parse_rules(self):
        rule_files = [join(self.rules_dir, f) for f in listdir(self.rules_dir) if isfile(join(self.rules_dir, f))]

        for rule_file in rule_files:
            if rule_file.endswith(".rule"):
                rule_name = rule_file.split("/")[-1][:-5]
                self.rules[rule_name] = rule_file

    """
        Parse wordlist directory
    """
    def parse_wordlists(self):
        wordlist_files = [join(self.wordlist_dir, f) for f in listdir(self.wordlist_dir) if isfile(join(self.wordlist_dir, f))]

        for wordlist_file in wordlist_files:
            if wordlist_file.endswith(".wordlist"):
                wordlist_name = wordlist_file.split("/")[-1][:-1*len(".wordlist")]
                self.wordlists[wordlist_name] = wordlist_file

    """
        Parse mask directory
    """
    def parse_masks(self):
        mask_files = [join(self.mask_dir, f) for f in listdir(self.mask_dir) if isfile(join(self.mask_dir, f))]

        for mask_file in mask_files:
            if mask_file.endswith(".hcmask"):
                mask_name = mask_file.split("/")[-1][:-1*len(".hcmask")]
                self.masks[mask_name] = mask_file

    """
        Create a new session
    """
    def create_session(self, name, crack_type, hash_file, hash_mode_id, wordlist, rule, mask, username_included):

        if name in self.sessions:
            raise Exception("This session name has already been used")

        if not hash_mode_id in self.hash_modes:
            raise Exception("Wrong hash mode")

        if not crack_type in ["rule", "mask"]:
            raise Exception("Unsupported cracking type")

        if crack_type == "rule":
            if rule == None or not rule in self.rules:
                raise Exception("Wrong rule")
            rule_path = self.rules[rule]

            if wordlist == None or not wordlist in self.wordlists:
                raise Exception("Wrong wordlist")
            wordlist_path = self.wordlists[wordlist]

            mask_path = None
        elif crack_type == "mask":
            if mask == None or not mask in self.masks:
                raise Exception("Wrong mask")
            mask_path = self.masks[mask]
            rule_path = None
            wordlist_path = None

        session = Session(self, name, crack_type, hash_file, hash_mode_id, wordlist_path, rule_path, mask_path, username_included)
        self.sessions[session.name] = session

        return session

    """
        Remove a session
    """
    def remove_session(self, name):

        if not name in self.sessions:
            raise Exception("This session name doesn't exists")

        self.sessions[name].remove()

        del self.sessions[name]

    """
        Upload a new rule file
    """
    def upload_rule(self, name, rules):

        name = name.split("/")[-1]

        if not name.endswith(".rule"):
            name += ".rule"

        if name[:-5] in self.rules:
            raise Exception("This rule name is already used")

        path = os.path.join(self.rules_dir, name)

        f = open(path, "w")
        f.write(rules)
        f.close()

        self.rules[name[:-5]] = path

    """
        Upload a new mask file
    """
    def upload_mask(self, name, masks):

        name = name.split("/")[-1]

        if not name.endswith(".hcmask"):
            name += ".hcmask"

        if name[:-7] in self.masks:
            raise Exception("This mask name is already used")

        path = os.path.join(self.mask_dir, name)

        f = open(path, "w")
        f.write(masks)
        f.close()

        self.masks[name[:-7]] = path

    """
        Upload a new wordlist file
    """
    def upload_wordlist(self, name, wordlists):

        name = name.split("/")[-1]

        if not name.endswith(".wordlist"):
            name += ".wordlist"

        if name[:-9] in self.wordlists:
            raise Exception("This wordlist name is already used")

        path = os.path.join(self.wordlist_dir, name)

        f = open(path, "w")
        f.write(wordlists)
        f.close()

        self.wordlists[name[:-9]] = path



class Session(object):
    def __init__(self, hashcat, name, crack_type, hash_file, hash_mode_id, wordlist_file, rule_file, mask_file, username_included):
        self.hashcat = hashcat
        self.name = name
        self.crack_type = crack_type
        self.hash_file = hash_file
        self.hash_mode_id = hash_mode_id
        self.rule_file = rule_file
        self.wordlist_file = wordlist_file
        self.mask_file = mask_file
        self.username_included = username_included

        # Session values before being started
        self.session_status = "Not started"

        self.hash_type = "N/A"
        self.time_started = "N/A"
        self.time_estimated = "N/A"
        self.speed = "N/A"
        self.recovered = "N/A"
        self.progress = "0"

        # File to store the processes output
        random_name = ''.join(random.choice(string.ascii_uppercase + string.digits) for _ in range(12))
        self.result_file = os.path.join("/tmp", random_name+".cracked")

        # Get a list of hashes already cracked
        cmd_line = [self.hashcat.binary, '--show', '-m', str(self.hash_mode_id), self.hash_file, '-o', self.result_file, '--outfile-format', '2']
        if self.username_included:
            cmd_line += ["--username"]
        p = subprocess.Popen(cmd_line, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        stdout, stderr = p.communicate()

        # Check if the hashes are correct
        wrong_hash_type_regex = re.compile("^WARNING: .*: Line-length exception$")

        for line in stdout.decode().split('\n'):
            line = line.rstrip()
            m = wrong_hash_type_regex.match(line)
            if m != None:
                raise Exception("Wrong hash type")

        self.current_cracked = sum(1 for line in open(self.result_file))
        self.total_hashes = sum(1 for line in open(hash_file))

    def start(self):
        self.thread = threading.Thread(target=self.session_thread)
        self.thread.start()

        self.session_status = "Running"

        # Little delay to ensure the process if properly launched
        time.sleep(1)

        self.status()

    def session_thread(self):
        # Prepare regex to parse the main hashcat process output
        regex_list = [
            ("hash_type", re.compile("^Hash\.Type\.\.\.\.\.\.: (.*)\s*$")),
            ("speed", re.compile("^Speed\.Dev\.#1\.\.\.: (.*)\s*$")),
            ("recovered", re.compile("^Recovered\.\.\.\.\.\.: (.*)\s*$")),
            ("current_cracked", re.compile("^Recovered\.\.\.\.\.\.: (\d+)/\d+ .*\s*$")),
            ("total_hashes", re.compile("^Recovered\.\.\.\.\.\.: \d+/(\d+) .*\s*$")),
        ]
        if self.crack_type == "rule":
            regex_list.append(("progress", re.compile("^Progress\.\.\.\.\.\.\.: \d+/\d+ \((\S+)%\)\s*$")))
            regex_list.append(("time_estimated", re.compile("^Time\.Estimated\.: (.*)\s*$")))
        elif self.crack_type == "mask":
            regex_list.append(("progress", re.compile("^Input\.Mode\.\.\.\.\.:\s+Mask\s+\(\S+\)\s+\[\d+\]\s+\((\S+)%\)\s*$")))

        self.time_started = str(datetime.now())

        # Command lines used to crack the passwords
        if self.crack_type == "rule":
            cmd_line = [self.hashcat.binary, '--session', self.name, '--status', '-a', '0', '-m', str(self.hash_mode_id), self.hash_file, self.wordlist_file, '-r', self.rule_file]
        if self.crack_type == "mask":
            cmd_line = [self.hashcat.binary, '--session', self.name, '--status', '-a', '3', '-m', str(self.hash_mode_id), self.hash_file, self.mask_file]
        if self.username_included:
            cmd_line += ["--username"]

        self.session_process = subprocess.Popen(cmd_line, stdout=subprocess.PIPE, stdin=subprocess.PIPE, stderr=subprocess.PIPE)

        self.update()

        for line in self.session_process.stdout:
            line = line.decode()
            line = line.rstrip()

            if line == "Resumed":
                self.session_status = "Running"

            if line == "Paused":
                self.session_status = "Paused"

            for var_regex in regex_list:
                var = var_regex[0]
                regex = var_regex[1]

                m = regex.match(line)
                if m:
                    setattr(self, var, m.group(1))

        # The cracking ended, set the parameters accordingly
        self.progress = "100"
        self.session_status = "Done"
        self.time_estimated = "N/A"
        self.speed = "N/A"

    def details(self):
        # remove the previous result file
        try:
            os.remove(self.result_file)
        except:
            pass

        cmd_line = [self.hashcat.binary, '--show', '-m', str(self.hash_mode_id), self.hash_file, '-o', self.result_file, '--outfile-format', '2']
        if self.username_included:
            cmd_line += ["--username"]
        p = subprocess.Popen(cmd_line)
        p.wait()

        # parse the result file
        top10_pass, pass_len, pass_charset = analyse_password_file(self.result_file, self.username_included)

        # remove the previous result file
        try:
            os.remove(self.result_file)
        except:
            pass

        # get cracked password with their corresponsing username/hash
        cmd_line = [self.hashcat.binary, '--show', '-m', str(self.hash_mode_id), self.hash_file, '-o', self.result_file]
        if self.username_included:
            cmd_line += ["--username", "--outfile-format", "2"]
        else:
            cmd_line += ["--outfile-format", "3"]
        p = subprocess.Popen(cmd_line)
        p.wait()

        return {
            "name": self.name,
            "crack_type": self.crack_type,
            "status": self.session_status,
            "time_started": self.time_started,
            "time_estimated": self.time_estimated,
            "speed": self.speed,
            "recovered": self.recovered,
            "progress": self.progress,
            "results": open(self.result_file).read(),
            "top10_passwords": top10_pass,
            "password_lengths": pass_len,
            "password_charsets": pass_charset,
        }

    """
        Cleanup the session before deleting it
    """
    def remove(self):
        try:
            os.remove(self.result_file)
        except:
            pass
        try:
            os.remove(self.hash_file)
        except:
            pass

    """
        Return cracked passwords
    """
    def cracked(self):

        # gather cracked passwords
        cmd_line = [self.hashcat.binary, '--show', '-m', str(self.hash_mode_id), self.hash_file, '-o', self.result_file]
        if self.username_included:
            cmd_line += ["--username", "--outfile-format", "2"]
        else:
            cmd_line += ["--outfile-format", "3"]
        p = subprocess.Popen(cmd_line)
        p.wait()

        return open(self.result_file).read()

    """
        Update the session
    """
    def update(self):
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

            self.update()

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

            self.update()

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

        self.session_status == "Aborted"

def analyse_password_file(path, username_included):

    top_passwords = {}
    password_lengths = {}
    password_charsets = {}

    f = open(path)

    for line in f:
        password = line.rstrip()
        if username_included:
            password = ":".join(password.split(":")[1:])


        if not password in top_passwords:
            top_passwords[password] = 1
        else:
            top_passwords[password] += 1

        pass_len, charset, _, _, _ = analyze_password(password)

        if not pass_len in password_lengths:
            password_lengths[pass_len] = 1
        else:
            password_lengths[pass_len] += 1

        if not charset in password_charsets:
            password_charsets[charset] = 1
        else:
            password_charsets[charset] += 1

    f.close()

    top10_pass = sorted(top_passwords.items(), key=operator.itemgetter(1), reverse=True)[:10]
    top10_len = sorted(password_lengths.items(), key=operator.itemgetter(1), reverse=True)[:10]
    top10_charset = sorted(password_charsets.items(), key=operator.itemgetter(1), reverse=True)[:10]

    return top10_pass, top10_len, top10_charset

# This function is taken from https://github.com/iphelix/pack

def analyze_password(password):

    # Password length
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



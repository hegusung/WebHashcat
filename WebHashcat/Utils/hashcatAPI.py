import socket
import http.client
import ssl
#from urllib.request import Request, urlopen
import struct
import json
import base64

class HashcatAPI(object):

    def __init__(self, ip, port, username, password):
        self.ip = ip
        self.port = port
        self.key = base64.b64encode(("%s:%s" % (username, password)).encode("ascii")).decode("ascii")

    def get_hashcat_info(self):
        return self.send("/hashcatInfo")

    def create_rule_session(self, session_name, hash_type_id, rule, wordlist, hashes, username_included):
        payload = {
            "name": session_name,
            "crack_type": "rule",
            "hash_mode_id": hash_type_id,
            "rule": rule,
            "wordlist": wordlist,
            "hashes": hashes,
            "username_included": username_included,
        }

        return self.send("/createSession", data=payload)

    def create_mask_session(self, session_name, hash_type_id, mask, hashes, username_included):
        payload = {
            "name": session_name,
            "crack_type": "mask",
            "hash_mode_id": hash_type_id,
            "mask": mask,
            "hashes": hashes,
            "username_included": username_included,
        }

        return self.send("/createSession", data=payload)


    def action(self, session_name, action):
        payload = {
            "session": session_name,
            "action": action,
        }

        return self.send("/action", data=payload)

    def get_session_info(self, session_name):
        return self.send("/sessionInfo/%s" % session_name)

    def remove(self, session_name):
        return self.send("/removeSession/%s" % session_name)

    def get_cracked_file(self, session_name):
        return self.send("/cracked/%s" % session_name)

    def get_hashcat_output(self, session_name):
        return self.send("/hashcatOutput/%s" % session_name)

    def get_hashes(self, session_name):
        return self.send("/hashes/%s" % session_name)


    def upload_rule(self, name, rule_file):
        payload = {
            "name": name,
            "rules": rule_file,
        }

        return self.send("/uploadRule", data=payload)

    def upload_mask(self, name, mask_file):
        payload = {
            "name": name,
            "masks": mask_file,
        }

        return self.send("/uploadMask", data=payload)

    def upload_wordlist(self, name, wordlist_file):
        payload = {
            "name": name,
            "wordlists": wordlist_file,
        }

        return self.send("/uploadWordlist", data=payload)

    def send(self, url, data=None):
        headers = {
            "Content-Type": "text/plain; charset=utf-8",
            "Accept-Encoding": "text/plain",
            "Authorization": "Basic %s" % self.key,
        }

        gcontext = ssl.SSLContext(ssl.PROTOCOL_TLSv1)  # disable certif validation
        conn = http.client.HTTPSConnection(self.ip, self.port, context=gcontext)

        if data == None:
            conn.request("GET", url, headers=headers)
        else:
            conn.request("POST", url, "%s\r\n\r\n" % json.dumps(data), headers)

        res = conn.getresponse()

        data = res.read()

        conn.close()
        return json.loads(data.decode("ascii"))


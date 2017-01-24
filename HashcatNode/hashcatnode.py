#!/usr/bin/python3
import os
import configparser

from httpapi import Server
from hashcat import Hashcat

def main():
    config = configparser.ConfigParser()

    current_dir = os.path.dirname(__file__)

    config.read(current_dir + os.sep + 'settings.ini')

    bind_address = config["Server"]["bind"]
    bind_port = config["Server"]["port"]
    username = config["Server"]["username"]
    password = config["Server"]["password"]

    binary = config["Hashcat"]["binary"]
    hashes_dir = config["Hashcat"]["hashes_dir"]
    rules_dir = config["Hashcat"]["rule_dir"]
    mask_dir = config["Hashcat"]["mask_dir"]
    wordlist_dir = config["Hashcat"]["wordlist_dir"]

    Hashcat.binary = binary
    Hashcat.rules_dir = rules_dir
    Hashcat.wordlist_dir = wordlist_dir
    Hashcat.mask_dir = mask_dir

    Hashcat.parse_version()
    Hashcat.parse_help()
    Hashcat.parse_rules()
    Hashcat.parse_masks()
    Hashcat.parse_wordlists()

    Hashcat.reload_sessions()

    httpsServer = Server(bind_address, bind_port, username, password, hashes_dir)
    httpsServer.start_server()

if __name__ == "__main__":
    main()


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
    rule_dir = config["Hashcat"]["rule_dir"]
    mask_dir = config["Hashcat"]["mask_dir"]
    wordlist_dir = config["Hashcat"]["wordlist_dir"]

    hashcat = Hashcat(binary, rule_dir, wordlist_dir, mask_dir)

    httpsServer = Server(bind_address, bind_port, username, password, hashcat)
    httpsServer.start_server()

if __name__ == "__main__":
    main()


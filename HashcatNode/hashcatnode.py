#!/usr/bin/python3
import os
import configparser
import logging

from httpapi import Server
from hashcat import Hashcat

def main(run_server=True):

    # Config

    config = configparser.ConfigParser()

    current_dir = os.path.dirname(os.path.abspath( __file__ ))

    config.read(current_dir + os.sep + 'settings.ini')

    loglevel_str = config["General"]["loglevel"]

    bind_address = config["Server"]["bind"]
    bind_port = config["Server"]["port"]
    # Docker support
    username = config["Server"]["username"]
    username_hash = config["Server"]["sha256hash"]
    if username == 'DOCKER_ENV':
        username = os.environ.get("HASHCATNODE_USERNAME")
        if username == None:
            raise Exception('HASHCATNODE_USERNAME environment variable not defined')
    if username_hash == 'DOCKER_ENV':
        username_hash = os.environ.get("HASHCATNODE_HASH")
        if username_hash == None:
            raise Exception('HASHCATNODE_HASH environment variable not defined')

    binary = config["Hashcat"]["binary"]
    hashes_dir = config["Hashcat"]["hashes_dir"]
    rules_dir = config["Hashcat"]["rule_dir"]
    mask_dir = config["Hashcat"]["mask_dir"]
    wordlist_dir = config["Hashcat"]["wordlist_dir"]
    workload_profile = config["Hashcat"]["workload_profile"]

    # Logging

    loglevel_dict = {
        "debug": logging.DEBUG,
        "info": logging.INFO,
        "warning": logging.WARNING,
        "error": logging.ERROR,
        "critical": logging.CRITICAL,
    }

    logfile = os.path.dirname(os.path.abspath( __file__ )) + os.sep + 'hashcatnode.log'

    logging.basicConfig(
        filename=logfile,
        format = '%(asctime)s\t%(levelname)s\t%(message)s',
        level=loglevel_dict[loglevel_str]
    )

    # Startup

    logging.info("Hashcat node starting")

    Hashcat.binary = binary
    Hashcat.rules_dir = rules_dir
    Hashcat.wordlist_dir = wordlist_dir
    Hashcat.mask_dir = mask_dir
    Hashcat.workload_profile = workload_profile

    Hashcat.parse_version()
    Hashcat.parse_help()
    Hashcat.parse_rules()
    Hashcat.parse_masks()
    Hashcat.parse_wordlists()

    Hashcat.reload_sessions()

    if run_server:
        httpsServer = Server(bind_address, bind_port, username, username_hash, hashes_dir)
        httpsServer.start_server()

    return Hashcat

if __name__ == "__main__":
    main()


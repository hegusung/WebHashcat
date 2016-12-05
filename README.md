# WebHashcat
Hashcat web interface

This project is composed of 2 parts: 
- WebHashcat, the web interface made with the django framework 
- HashcatNode, A hashcat wrapper with creates an API over the Hashcat tool

The web interface can connect back to multiple nodes to create new cracking session, view their results...

Currently WebHashcat supports rule-based and mask-based attack mode

## Install

### HashcatNode

Rename the settings.ini.sample file to settings.ini and fill the parameters accordingly.

The rules, mask and wordlist directory must be writable by the user running hashcatnode

the hashcatnode can be run simply by running `./hashcatnode.py`

### WebHashcat

To be done

## Dependencies

- python3
- django
- flask
- flask-basicauth
- hashcat 3

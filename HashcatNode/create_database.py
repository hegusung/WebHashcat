#!/usr/bin/python3

from hashcat import Session

try:
    Session.drop_table()
except:
    pass
try:
    Session.create_table()
except:
    pass

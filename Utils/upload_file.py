#!/usr/bin/python3
import os
import sys
import argparse
import requests
from urllib.parse import urljoin
from requests.auth import HTTPBasicAuth
from requests_toolbelt.multipart.encoder import MultipartEncoder

def main():
    parser = argparse.ArgumentParser(description='Upload file to WebHashcat', formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    parser.add_argument('--url', help='URL to WebHashcat interface', type=str, default='http://127.0.0.1:8000/', dest='url')
    parser.add_argument('--username', '-u', help='WebHashcat username', type=str, dest='username')
    parser.add_argument('--password', '-p', help='WebHashcat password', type=str, dest='password')
    parser.add_argument('--name', '-n', help='Uploaded name', type=str, dest='name')
    # Hashfile
    parser.add_argument('--hashfile', help='hashfile to be uploaded', type=str, dest='hashfile')
    parser.add_argument('--hashtype', help='hashfile hash type (hashcat integer, -1 for plaintext)', type=int, dest='hashtype')
    parser.add_argument('--username-included', help='the hashfile includes the username (format username:hash)', action='store_true', dest='username_included')
    # Wordlist
    parser.add_argument('--wordlist', nargs='+', help='wordlist to be uploaded', type=str, dest='wordlist')
    parser.add_argument('--mask', nargs='+', help='mask to be uploaded', type=str, dest='mask')
    parser.add_argument('--rule', nargs='+', help='rule to be uploaded', type=str, dest='rule')

    args = parser.parse_args()

    if args.username == None or args.password == None:
        print("Please specify a username and password")
        return

    if args.hashfile != None:
        if not os.path.exists(args.hashfile):
            print("Please specify an existing hashfile to upload")
            return
        if args.hashtype == None:
            print("Please specify the hash type")
            return
        if args.name == None:
            name = os.path.basename(args.hashfile)
        else:
            name = args.name
        values={'name' : name, 'type': 'hashfile', 'hash_type': args.hashtype}
        if args.username_included:
            values['username_included'] = True
        values['file'] = (os.path.basename(args.hashfile), open(args.hashfile, 'rb'), 'text/plain')
        m = MultipartEncoder(fields=values)
        #files={'file': open(args.hashfile, 'rb')}
        try:
            res = requests.post(urljoin(args.url, '/api/upload_file'), auth=HTTPBasicAuth(args.username, args.password), data=m, headers={'Content-Type': m.content_type})
            print(res.text)
        except MemoryError:
            print("File too big to fit in memory")
    elif args.rule != None:
        for rule in args.rule:
            if not os.path.exists(rule):
                print("Please specify an existing rule to upload (%s)" % rule)
                continue
            if args.name == None:
                name = os.path.basename(rule)
            values={'name' : name, 'type': 'rule'}
            files={'file': open(rule, 'rb')}

            print("Uploading %s" % os.path.basename(rule))
            try:
                res = requests.post(urljoin(args.url, '/api/upload_file'), auth=HTTPBasicAuth(args.username, args.password), files=files, data=values)
                print(res.text)
            except MemoryError:
                print("File too big to fit in memory")
    elif args.mask != None:
        for mask in args.mask:
            if not os.path.exists(mask):
                print("Please specify an existing mask to upload (%s)" % mask)
                continue
            if args.name == None:
                name = os.path.basename(mask)
            values={'name' : name, 'type': 'mask'}
            files={'file': open(mask, 'rb')}

            print("Uploading %s" % os.path.basename(mask))
            try:
                res = requests.post(urljoin(args.url, '/api/upload_file'), auth=HTTPBasicAuth(args.username, args.password), files=files, data=values)
                print(res.text)
            except MemoryError:
                print("File too big to fit in memory")
    elif args.wordlist != None:
        for wordlist in args.wordlist:
            if not os.path.exists(wordlist):
                print("Please specify an existing wordlist to upload (%s)" % wordlist)
                continue
            if args.name == None:
                name = os.path.basename(wordlist)
            values={'name' : name, 'type': 'wordlist'}
            #files={'file': open(wordlist, 'rb')}
            values['file'] = (os.path.basename(wordlist), open(wordlist, 'rb'), 'text/plain')
            m = MultipartEncoder(fields=values)

            print("Uploading %s" % os.path.basename(wordlist))
            try:
                res = requests.post(urljoin(args.url, '/api/upload_file'), auth=HTTPBasicAuth(args.username, args.password), data=m, headers={'Content-Type': m.content_type})
                print(res.text)
            except MemoryError:
                print("File too big to fit in memory")
    else:
        print("Please specify a file to upload")


if __name__ == '__main__':
    main()

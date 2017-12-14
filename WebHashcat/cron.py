#!/usr/bin/python3
import time
import argparse
import requests
import schedule

def update_webhashcat(host, port, ssl):

    url = "%s://%s:%d/api/update_hashfiles" % ("https" if ssl else "http", host, port)

    try:
        res = requests.get(url)
    except requests.exceptions.ConnectionError:
        print("Unable to connect to webhashcat")

if __name__=="__main__":
    parser = argparse.ArgumentParser(description='WebHashcat cron', formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    parser.add_argument('host', help='webhashcat hostname', nargs='?')
    parser.add_argument('port', help='webhashcat port', nargs='?')
    parser.add_argument('--ssl', help='https connection', action='store_true', dest='ssl')
    parser.add_argument('--standalone', help='use it without cron', action='store_true', dest='standalone')

    args = parser.parse_args()

    if not args.standalone:
        update_webhashcat(args.host, int(args.port), args.ssl)
    else:
        schedule.every(1).minutes.do(update_webhashcat, args.host, int(args.port), args.ssl)

        while True:
            schedule.run_pending()
            time.sleep(1)


#!/usr/bin/env python

#
# (c) 2016, Area 1 Security
#
# Sample code demonstrating the Area 1 Security remote API.
# Version 1.3
#
#

from __future__ import print_function
import os, sys, time, argparse
import ast
import unicodecsv as csv
import datetime as dt
import itertools as it
import urllib2
import base64

a1s_url = 'https://papillon.area1security.com/'

BLOCKABLE_RESULTS_CSV = 'Blockable-results.csv'
MALICIOUS_RESULTS_CSV = 'Malicious-results.csv'

# Column header keyword fragments that indicate timestamps
TS_NAMES = ['first_detected', 'interval']

def getURL(URL, creds):
    theURL = urllib2.Request(URL)
    theURL.add_header('Authorization', 'Basic {}'.format(creds))
    try:
        resp = urllib2.urlopen(theURL)
        results = ast.literal_eval(resp.read())
        return results
    except urllib2.HTTPError as e:
        #print(e.read())
        print("Status Code: %d." % e.code, end='')
        if e.code == 401:
            print(' Failed to Authenticate.', end='')
        print()
        sys.exit(1)

def json_to_dicts(objects):
    return [dict(kv_pairs(obj)) for obj in objects]

def kv_pairs(source, ancestors=[], key_delim='_'):
    if hasattr(source, "keys"):
        result = [kv_pairs(source[key], ancestors + [key]) for key in source.keys()]
        return list(it.chain.from_iterable(result))
    elif (not hasattr(source, "strip") and hasattr(source, "__getitem__") or hasattr(source, "__iter__")):
        result = [kv_pairs(item, ancestors + [str(index)]) for (index, item) in enumerate(source)]
        return list(it.chain.from_iterable(result))
    else:
        return [(key_delim.join(ancestors), source)]

def dicts_to_csv(source, outfile, convts):
    keys = sorted(set(it.chain.from_iterable([o.keys() for o in source])))
    rows = [[d.get(k, "") for k in keys] for d in source]

    colts = []
    #if 'convert timestamp' is true, make a list of fields to be converted.
    if convts is True:
        for i,k in enumerate(keys):
            if any([(t in k) for t in TS_NAMES]):
                colts.append(i)

    cw = csv.writer(outfile)
    cw.writerow(keys)

    for row in rows:
        orow = []
        for i,val in enumerate(row):
            if isinstance(val, int):
                if i in colts:
                    conv = time.strftime('%m/%d/%Y', time.gmtime(val/1000.))
                else:
                    conv = val
            else:
                conv = unicode(val, 'utf-8')
            orow.append(conv)
        cw.writerow( orow )


if __name__ == "__main__":

    parser = argparse.ArgumentParser(description=
             'Return Blockable and Malicious Indicators from Area 1 Security. '
             'UUID and Password must be set in environment variables.')
    parser.add_argument('-s', '--since-date',  help='Since date; yyyy-mm-dd. Default- today.', required=False)
    parser.add_argument('-e', '--end-date',    help='End date; yyyy-mm-dd. Default- today.', required=False)
    parser.add_argument('-b', '--blockable',   help='Blockable Indicators only.', action='store_true')
    parser.add_argument('-m', '--malicious',   help='Malicious Indicators only.', action='store_true')
    parser.add_argument('-t', '--convertts',   help='Convert Timestamps to Human Readable.', action='store_true')
    args = parser.parse_args()

    try:
        creds = base64.b64encode('{}:{}'.format(os.environ['A1S_USER_UUID'],os.environ['A1S_USER_PASSWORD']))
    except KeyError:
        print('A1S_USER_UUID and A1S_USER_PASSWORD environment variables must be setup properly.')
        sys.exit(1)

    if not args.blockable and not args.malicious:
        print('Please select -b and/or -m.')
        sys.exit(1)

    today = dt.date.today()

    if args.since_date:
        s = args.since_date
    else:
        s = str(today)

    if args.end_date:
        e = args.end_date
    else:
        e = str(today)

    ts = time.mktime(dt.datetime.strptime(s, '%Y-%m-%d').timetuple())
    since_date = int(ts)
    ts = time.mktime(dt.datetime.strptime(e, '%Y-%m-%d').timetuple())
    end_date = int(ts)

    if args.blockable:
        bInd = a1s_url + 'blockable-indicators?since={}&end={}'.format(str(since_date), str(end_date))
        indicators = getURL(bInd, creds)
        print(indicators)
        dicts = json_to_dicts(indicators)    
        with open(BLOCKABLE_RESULTS_CSV, "w") as ofn:
            dicts_to_csv(dicts, ofn, args.convertts)

    if args.malicious:
        mInd = a1s_url + 'malicious-indicators?since={}'.format(str(since_date))
        indicators = getURL(mInd, creds)
        dicts = json_to_dicts(indicators)
        with open(MALICIOUS_RESULTS_CSV, "w") as ofn:
            dicts_to_csv(dicts, ofn, args.convertts)

    sys.exit(0)

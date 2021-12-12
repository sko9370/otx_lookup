#!/usr/bin/env python3

import csv
import sys
import random
from otx.OTXv2 import OTXv2
import otx.check_iocs as check_iocs
import otx.ioc_utils as ioc_utils

# Your API key(s) in a comma-separated string, ex. 'keyA,keyB,keyC,keyD,keyETC'
API_KEYS  = ''

OTX_SERVER = 'https://otx.alienvault.com/'

def main():
    if len(sys.argv) != 3:
        print("Usage: python otx_hash.py [IOC field] [Results field]")
        sys.exit(1)

    ioc_field = sys.argv[1]
    results_field= sys.argv[2]

    infile = sys.stdin
    outfile = sys.stdout

    r = csv.DictReader(infile)
    w = csv.DictWriter(outfile, fieldnames=r.fieldnames)
    w.writeheader()

    ioc_field = r.fieldnames[0]

    for value in r:
        tpy = ioc_utils.indicator_type(value[ioc_field])
        if tpy not in ['hash', 'ip', 'host']:
            continue
        otx = OTXv2(random.choice(API_KEYS).strip(), server=OTX_SERVER)
        value[results_field] = check_iocs.checkIOC(value[ioc_field], tpy, otx)
        w.writerow(value)

main()
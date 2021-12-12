#!/usr/bin/env python
import otx.get_malicious as getMal
import hashlib
import json

def checkIOC(val, tpy, otx):
    val = val.strip()
    tpy = tpy.strip()
    
    res = {}
    
    if tpy =='ip':
        alerts = getMal.ip(otx, val)
        if len(alerts) > 0:
            res = json.dumps(alerts, indent=4, sort_keys=True)
        else:
            res = {'Info': 'Unknown or not identified as malicious'}
    
    if tpy =='host':
        alerts = getMal.hostname(otx, val)
        if len(alerts) > 0:
            res = json.dumps(alerts, indent=4, sort_keys=True)
        else:
            res = {'Info': 'Unknown or not identified as malicious'}
    
    if tpy =='url':
        alerts = getMal.url(otx, val)
        if len(alerts) > 0:
            res = json.dumps(alerts, indent=4, sort_keys=True)
        else:
            res = {'Info': 'Unknown or not identified as malicious'}
    
    if tpy =='hash':
        alerts =  getMal.file(otx, val)
        if len(alerts) > 0:
            res = json.dumps(alerts, indent=4, sort_keys=True)
        else:
            res = {'Info': 'Unknown or not identified as malicious'}
    
    if tpy =='file':
        hash = hashlib.md5(open(val, 'rb').read()).hexdigest()
        alerts =  getMal.file(otx, hash)
        if len(alerts) > 0:
            res = json.dumps(alerts, indent=4, sort_keys=True)
        else:
            res = {'Info': 'Unknown or not identified as malicious'}

    return res
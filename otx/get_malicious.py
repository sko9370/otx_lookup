#!/usr/bin/env python

import otx.IndicatorTypes as IndicatorTypes
from io import open
import json

# Get a nested key from a dict, without having to do loads of ifs
def getValue(results, keys):
    if type(keys) is list and len(keys) > 0:

        if type(results) is dict:
            key = keys.pop(0)
            if key in results:
                return getValue(results[key], keys)
            else:
                return None
        else:
            if type(results) is list and len(results) > 0:
                return getValue(results[0], keys)
            else:
                return results
    else:
        return results

def hostname(otx, hostname):
    alerts = []
    result = otx.get_indicator_details_by_section(IndicatorTypes.HOSTNAME, hostname, 'general')

    # Return nothing if it's in the whitelist
    validation = getValue(result, ['validation'])
    if not validation:
        pulses = getValue(result, ['pulse_info', 'pulses'])
        if pulses:
            for pulse in pulses:
                if 'name' in pulse:
                    data = {'ioc':hostname, 'created' : pulse['created'], 'id' : pulse['id'], 'name' : pulse['name']}
                    alerts.append(data)             

    result = otx.get_indicator_details_by_section(IndicatorTypes.DOMAIN, hostname, 'general')
    
    # Return nothing if it's in the whitelist
    validation = getValue(result, ['validation'])
    if not validation:
        pulses = getValue(result, ['pulse_info', 'pulses'])
        if pulses:
            for pulse in pulses:
                if 'name' in pulse:
                    data = {'ioc':hostname, 'created' : pulse['created'], 'id' : pulse['id'], 'name' : pulse['name']}
                    alerts.append(data)                   


    return alerts


def ip(otx, ip):
    alerts = []
    result = otx.get_indicator_details_by_section(IndicatorTypes.IPv4, ip, 'general')

    # Return nothing if it's in the whitelist
    validation = getValue(result, ['validation'])
    if not validation:
        pulses = getValue(result, ['pulse_info', 'pulses'])
        if pulses:
            for pulse in pulses:
                if 'name' in pulse:
                    data = {'ioc':ip, 'created':pulse['created'], 'id':pulse['id'], 'name':pulse['name']}
                    alerts.append(data)

    return alerts


def url(otx, url):
    alerts = []
    result = otx.get_indicator_details_full(IndicatorTypes.URL, url)
    
    google = getValue( result, ['url_list', 'url_list', 'result', 'safebrowsing'])
    if google and 'response_code' in str(google):
        alerts.append({'ioc':url, 'google_safebrowsing': 'malicious'})

    clamav = getValue( result, ['url_list', 'url_list', 'result', 'multiav','matches','clamav'])
    if clamav:
        alerts.append({'ioc':url, 'clamav': clamav})

    avast = getValue( result, ['url_list', 'url_list', 'result', 'multiav','matches','avast'])
    if avast:
        alerts.append({'ioc':url, 'avast': avast})
   
    # Get the file analysis too, if it exists
    has_analysis = getValue( result,  ['url_list','url_list', 'result', 'urlworker', 'has_file_analysis'])
    if has_analysis:
        hash = getValue( result,  ['url_list','url_list', 'result', 'urlworker', 'sha256'])
        file_alerts = file(otx, hash, url)
        if file_alerts:
            for alert in file_alerts:
                alerts.append(alert)
    return alerts

def file(otx, hash, url=''):

    alerts = []

    hash_type = IndicatorTypes.FILE_HASH_MD5
    if len(hash) == 64:
        hash_type = IndicatorTypes.FILE_HASH_SHA256
    if len(hash) == 40:
        hash_type = IndicatorTypes.FILE_HASH_SHA1

    result = otx.get_indicator_details_full(hash_type, hash)
    
    avg = getValue( result, ['analysis','analysis','plugins','avg','results','detection'])
    if avg:
        alerts.append({'url':url, 'ioc':hash, 'avg': avg})

    clamav = getValue( result, ['analysis','analysis','plugins','clamav','results','detection'])
    if clamav:
        alerts.append({'url':url, 'ioc':hash, 'clamav': clamav})

    avast = getValue( result, ['analysis','analysis','plugins','avast','results','detection'])
    if avast:
        alerts.append({'url':url, 'ioc':hash, 'avast': avast})

    microsoft = getValue( result, ['analysis','analysis','plugins','cuckoo','result','virustotal','scans','Microsoft','result'])
    if microsoft:
        alerts.append({'url':url, 'ioc':hash, 'microsoft': microsoft})

    symantec = getValue( result, ['analysis','analysis','plugins','cuckoo','result','virustotal','scans','Symantec','result'])
    if symantec:
        alerts.append({'url':url, 'ioc':hash, 'symantec': symantec})

    kaspersky = getValue( result, ['analysis','analysis','plugins','cuckoo','result','virustotal','scans','Kaspersky','result'])
    if kaspersky:
        alerts.append({'url':url, 'ioc':hash, 'kaspersky': kaspersky})

    suricata = getValue( result, ['analysis','analysis','plugins','cuckoo','result','suricata','rules','name'])
    if suricata and 'trojan' in str(suricata).lower():
        alerts.append({'url':url, 'ioc':hash, 'suricata': suricata})

    return alerts

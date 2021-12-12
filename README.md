# OTX Splunk External Lookup

## Dependencies
- pytz
- python-dateutil
- requests

## Setup
- acquire OTX AlienVault API keys and add them to "API_KEYS" variable in otx_lookup.py
- copy files to $SPLUNK_DIR/etc/system/bin
- in the web gui, go to Settings -> Lookups
- Lookup definitions
- New Lookup Definition
- make 3 different lookup definitions
    - all 3 will have these settings
        - Type: External
        - Command: otx_lookup.py IOC Results
            - IOC is just a placeholder for now, doesn't actually matter, will be removed in future updates
    - otx_hash
        - Supported fields: md5, Results
    - otx_ip
        - Supported fields: id.resp_h, id.orig_h, Results
    - otx_host
        - Supported fields: query, Results

- example Splunk query
    - index=zeek_file sourcetype="zeek:file:json" | fields md5 | dedup md5 | lookup otx_hash md5 | table md5 Results
    - index=zeek_conn sourcetype="zeek:conn:json" | fields id.resp_h | dedup id.resp_h | lookup otx_ip id.resp_h | table id.resp_h Results
    - index=zeek_dns sourcetype="zeek:dns:json" | fields query | dedup query | lookup otx_host query | table query Results

## References
- https://splunkbase.splunk.com/app/5422/
- https://dev.splunk.com/enterprise/docs/devtools/externallookups/createexternallookup/
- https://otx.alienvault.com/api
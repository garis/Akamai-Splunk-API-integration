
# encoding = utf-8

import os
import sys
import time
import datetime
import requests
import hashlib
import json
import re
from time import sleep
from akamai.edgegrid import EdgeGridAuth  # from https://github.com/akamai/AkamaiOPEN-edgegrid-python

# Special thanks to A.M. (aka Pastea) for the help with all this code

'''
    IMPORTANT
    Edit only the validate_input and collect_events functions.
    Do not edit any other part in this file.
    This file is generated only once when creating the modular input.
'''

def validate_input(helper, definition):
    """Implement your own validation logic to validate the input stanza configurations"""
    pass

def formatDomain(obj_dict):
    if isinstance(obj_dict,dict):
        keys = list(obj_dict.keys())
        for k in keys:
            if k in ["links"]:
                obj_dict.pop("links",None)
                continue
            if isinstance(obj_dict[k],dict):
                formatDomain(obj_dict[k])
            elif isinstance(obj_dict[k],list):
                for e in obj_dict[k]:
                    formatDomain(e)

# a lot of parsing to trasform the zone dump of a domain in a JSON easy to work in Splunk.
# Regex man was here :)
# In regex man I trust
def formatMasterZoneFile(zone,file,helper):
    lines = file.splitlines()
    output = []
    origin="%s." % zone
    for idx, l in enumerate(lines):
        l = l.strip()
        helper.log_debug(l)
        if l.startswith(";;"):
            file_generated = re.match("^;; File Generated at (?P<DATETIME>.*?)$",l)
            if file_generated:
                file_generated = file_generated.group("DATETIME")
            last_modified = re.match("^;; Last Modified at (?P<DATETIME>.*?)\[.*?$",l)
            if last_modified:
                last_modified = last_modified.group("DATETIME")
            custom = re.match("^;; Akamai (?P<CLASS>.*?) record for (?P<FQDN>.*?) points to (?P<TYPE>.*?) (?P<VALUE>.*?)$",l)
            if custom:
                d = {"LAST_MODIFIED":"%s" % last_modified, "ZONE":"%s" % origin, "NAME":"%s" % custom["FQDN"],"CLASS":"%s" % custom["CLASS"],"TYPE":"%s" % custom["TYPE"], "VALUE":"%s" % custom["VALUE"], "FQDN":"%s" % custom["FQDN"]}
                output.append(d)
        elif l.startswith("$"):
            origin = re.match("^\$ORIGIN\s+(?P<FQDN>.*?)$",l)
            if origin:
                origin = origin.group("FQDN")
        else:
            row = re.match("^(?P<NAME>.*?)\s+(?P<TTL>.*?)\s+(?P<CLASS>.*?)\s+(?P<TYPE>.*?)\s+(?P<VALUE>.*?)$",l)
            d = {"LAST_MODIFIED":"%s" % last_modified, "ZONE":"%s" % origin, "NAME":"%s" % row["NAME"],"TTL":"%s" % row["TTL"],"CLASS":"%s" % row["CLASS"],"TYPE":"%s" % row["TYPE"], "VALUE":"%s" % row["VALUE"]}
            if d["NAME"][-1]!="." and not "._" in d["NAME"]:
                d["FQDN"]="%s.%s" % (d["NAME"],origin)
            else:
                d["FQDN"]=d["NAME"]
            output.append(d)
    return output
    
def collect_events(helper, ew):
    
    # setup for the proxy variables if needed
    proxy = helper.get_proxy()
    proxies = None
    if proxy:
        proxies = \
                {'https': '{}://{}:{}@{}:{}/'.format(proxy['proxy_type'
                 ], proxy['proxy_username'], proxy['proxy_password'],
                 proxy['proxy_url'], proxy['proxy_port']),
                 'http': '{}://{}:{}@{}:{}/'.format(proxy['proxy_type'
                 ], proxy['proxy_username'], proxy['proxy_password'],
                 proxy['proxy_url'], proxy['proxy_port'])}
    
    # get all the input variables configured
    opt_api_base_url = helper.get_arg('api_base_url')
    opt_api_client_token = helper.get_arg('api_client_token')
    opt_api_client_secret = helper.get_arg('api_client_secret')
    opt_api_access_token = helper.get_arg('api_access_token')
    opt_gtm_configuration = helper.get_arg("gtm_configuration")
    opt_dns_zones = helper.get_arg("dns_zones")
    global_sslcertverification = helper.get_global_setting("sslcertverification")
    
    # variable to save the current time and use it for the event time when logging
    logTime = int(time.time())
    
    if opt_gtm_configuration == True:
        
        # run if the input is configured to collect the GTM config from the API
        
        akamaiAPIsession = requests.Session()
        akamaiAPIsession.auth = EdgeGridAuth(opt_api_client_token,opt_api_client_secret, opt_api_access_token)
        
        # first get all the domains...
        url = opt_api_base_url+"/config-gtm/v1/domains" 
        result = akamaiAPIsession.get(url,proxies=proxies,verify=global_sslcertverification)
    
        helper.log_debug('sent GTM GET request domains')

        if result.status_code == 200:
            
            # ... and now that we have the list of all the domains
            helper.log_debug('GET GTM response 200')
            domains_list = result.json()

            for d in domains_list["items"]:
    
                # ... dump the GTM config for each one
                helper.log_debug('logging '+d["name"])
                url = opt_api_base_url+"/config-gtm/v1/domains/"+d["name"]
                    
                result = akamaiAPIsession.get(url,proxies=proxies,verify=global_sslcertverification)
                helper.log_debug('sent GET request domain details')
                if result.status_code == 200:

                    helper.log_debug('GET response 200 domains details')
                
                    domain = result.json()
                    
                    # do a minimal parsing to have each record in a single JSON line
                    formatDomain(domain)
                    event = helper.new_event(time=logTime, source=helper.get_input_type(), index=helper.get_output_index(), sourcetype=helper.get_sourcetype(), data=json.dumps(domain))
                    # and log the data
                    ew.write_event(event)
                else:
                    # dump the error in the logs
                    helper.log_error(result.text)
        else:
            # dump the error in the logs
            helper.log_error(result.text)
            
    if opt_dns_zones == True:
        
        # run if the input is configured to collect the DNS zones from the API
        akamaiAPIsession = requests.Session()
        akamaiAPIsession.auth = EdgeGridAuth(opt_api_client_token,
            opt_api_client_secret, opt_api_access_token)
    
        helper.log_debug('sent GET DNS request domains')
        url = opt_api_base_url+"/config-dns/v2/zones?showAll=true"
        result = akamaiAPIsession.get(url,proxies=proxies, verify=global_sslcertverification)
        zones_list = result.json()
        if result.status_code == 200:
            
            # for each zone that we got from the previous request ...
            helper.log_debug('GET DNS response 200')
            for z in zones_list["zones"]:
                # log taht zone
                event = helper.new_event(time=logTime, source=helper.get_input_type(), index=helper.get_output_index(), sourcetype=helper.get_sourcetype(), data=json.dumps(z))
                ew.write_event(event)
        
                # and try to dump the entire zone file
                attempt=0
                # since the DNS zone files are a lot of data sometimes there are errors.
                # This will retry to get the zone with an exponential backoff if case of problems
                while True:
                    try:
                        url = opt_api_base_url+"/config-dns/v2/zones/"+z["zone"]+"/zone-file"
                        result = akamaiAPIsession.get(url,proxies=proxies,headers={"Accept":"text/dns"},verify=global_sslcertverification)
                        helper.log_debug(z["zone"]+" status: "+str(result.status_code))
                        if result.status_code in [200,404]:
                            break
                        else:
                            raise Exception
                    except Exception as e:
                        # log the error
                        helper.log_info("Exception " + str(result.status_code))
                        # and create a new session object
                        akamaiAPIsession = requests.Session()
                        akamaiAPIsession.auth = EdgeGridAuth(opt_api_client_token, opt_api_client_secret, opt_api_access_token)
                        # it will work eventually
                        attempt=attempt+1
                        # or stall forever and ever
                        sleep(attempt*1)
                        pass

                if result.status_code == 200:
                    # now we have the zone dump
                    helper.log_debug('GET DNS response 200')
                    # perform a clean up and trasform in JSON
                    record_set = formatMasterZoneFile(z["zone"],result.text,helper)
                    for r in record_set:
                        #and log the data
                        event = helper.new_event(time=logTime, source=helper.get_input_type(), index=helper.get_output_index(), sourcetype=helper.get_sourcetype(), data=json.dumps(r))
                        ew.write_event(event)
                else:
                    # dump the error in the logs
                    helper.log_error(result.text)    
        else:
            # dump the error in the logs
            helper.log_error(result.text)
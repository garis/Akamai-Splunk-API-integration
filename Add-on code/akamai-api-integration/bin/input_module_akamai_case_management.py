
# encoding = utf-8

import os
import sys
import time
import datetime
import requests
import hashlib
import json
from akamai.edgegrid import EdgeGridAuth  # from https://github.com/akamai/AkamaiOPEN-edgegrid-python

'''
    IMPORTANT
    Edit only the validate_input and collect_events functions.
    Do not edit any other part in this file.
    This file is generated only once when creating the modular input.
'''
'''
# For advanced users, if you want to create single instance mod input, uncomment this method.
def use_single_instance_mode():
    return True
'''

def validate_input(helper, definition):
    pass

# based on the selected behaviour from use_helperCheckpoint this function will
# use the helper get_check_point function (based on KV store) or fallback to
# a JSON file to get the checkpoints for the attacks
def helper_getCheckpoint(helper, use_helperCheckpoint, key, filenameID):
    if use_helperCheckpoint:
        return helper.get_check_point(key)
    else:
        # get this python script path
        scriptPath=os.path.dirname(os.path.realpath(__file__))
        # ... create ...
        filePath=scriptPath+ "/tickets_"+filenameID+".json"
        fileExists=os.path.exists(filePath)
        # ... load ...
        data={}
        if fileExists:
            data = json.load(open(filePath))
        else:
            data={}
        # ... and return the key value of the checkpoint
        return data.get(key)
        
# based on the selected behaviour from use_helperCheckpoint this function will
# use the helper save_check_point function (based on KV store) or fallback to
# a JSON file to save the checkpoints for the attacks
def helper_setCheckpoint(helper, use_helperCheckpoint, key, value, filenameID):
    if use_helperCheckpoint:
        return helper.save_check_point(key, str(value))
    else:
        # get this python script path
        scriptPath=os.path.dirname(os.path.realpath(__file__))
        # ... create ...
        filePath=scriptPath+ "/tickets_"+filenameID+".json"
        fileExists=os.path.exists(filePath)
        data={}
        # ... load ...
        if fileExists:
            data = json.load(open(filePath))
        else:
            data={}
        data[key]=value
        # ... and save checkpoints on a JSON file
        json.dump(data, open(filePath, 'w' ))

def collect_events(helper, ew):
    
    helper.log_info("Input {} has started.".format(str(helper.get_input_stanza_names())))
    
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
    
    helper.log_debug('start: collect_events')
    
    # get all the input variables configured
    opt_api_base_url = helper.get_arg('api_base_url')
    opt_api_client_token = helper.get_arg('api_client_token')
    opt_api_client_secret = helper.get_arg('api_client_secret')
    opt_api_access_token = helper.get_arg('api_access_token')
    opt_api_client_days = helper.get_arg('api_client_days')
    opt_use_splunk_helper_checkpoint = helper.get_arg('use_splunk_helper_checkpoint')
    global_sslcertverification = helper.get_global_setting("sslcertverification")
    
    # variable to save the current time and use it for the event time when logging
    logTime = int(time.time())
    
    # run if the input is configured to collect the critical events from the API
    helper.log_debug('akamai requests.Session() for tickets events case-management v2)')
    
    # create a session object using the Akamai python helper
    akamaiAPIsession = requests.Session()
    helper.log_debug('akamai EdgeGridAuth() for critical events')
    akamaiAPIsession.auth = EdgeGridAuth(opt_api_client_token,
        opt_api_client_secret, opt_api_access_token)
        
    # for every contract perform an API call
    helper.log_debug('send GET case-management v2 request')
    
    # run the GET request
    result = akamaiAPIsession.get(opt_api_base_url+('/case-management/v2/cases?duration='+opt_api_client_days), proxies=proxies,verify=global_sslcertverification)
    
    if(result.status_code==200):
        
        # now that we have a response is simply a matter of parsing the
        # the returned JSON object to get the data that we want in a JSON
        # format (one event for every line).
        # Special attention is dedicated to avoid logging events already
        # logged (with the help of checkpoints).
        helper.log_debug('GET critical events response 200')
        
        # hash of the event name to better idenfity the checkpoint
        inputHash = hashlib.md5(str(helper.get_input_stanza_names()).encode('utf-8')).hexdigest()
        responseJSON = result.json()
        
        for ticket in responseJSON:
            str_ticket = json.dumps(ticket)
            # create an hash containing the eventID
            checkpointKey = hashlib.md5(("ticket"+ticket["caseId"]).encode('utf-8')).hexdigest()
            # use it to retrieve the event hash
            eventCheckpointHash = helper_getCheckpoint(helper,opt_use_splunk_helper_checkpoint,checkpointKey,inputHash)
            if eventCheckpointHash == None:
                eventCheckpointHash = "0"
            
            # compute the event hash received from the API call
            eventHash = hashlib.md5(str(str_ticket).encode('utf-8')).hexdigest()
            if eventHash != eventCheckpointHash:
                # if the hash is different from the one retrieve from the checkpoint
                # log the new event...
                helper.log_debug('new ticket or update found, logging '+str(ticket["caseId"]))
                event = helper.new_event(time=logTime, source=helper.get_input_type(),
                            index=helper.get_output_index(),
                            sourcetype=helper.get_sourcetype(),
                            data=str_ticket)
                ew.write_event(event)
                
                # ... and register the new hash so it wont be logged again next time
                helper_setCheckpoint(helper, opt_use_splunk_helper_checkpoint,checkpointKey,eventHash,inputHash)
                # dump everything on that ticket again since the hash changed
                
                for ticket_content in ticket['links']:
                    helper.log_debug('dumping ticket contentwith {}'.format(str(ticket_content['href'])))
                    result = akamaiAPIsession.get(opt_api_base_url+ticket_content['href'], proxies=proxies,verify=global_sslcertverification)
                    if(result.status_code==200):
                        str_ticket = json.dumps(result.json())
                        event = helper.new_event(time=logTime, source=helper.get_input_type(),
                            index=helper.get_output_index(),
                            sourcetype=helper.get_sourcetype(),
                            data=str_ticket)
                        ew.write_event(event)
                    else:
                        # dump the error in the logs
                        helper.log_error(result.text)
            else:
                # nothing to do, the event hash was already registrered
                helper.log_debug('ticket hash found, skip logging')
    else:
        # dump the error in the logs
        helper.log_error(result.text)
    
    helper.log_info("Input {} has ended.".format(str(helper.get_input_stanza_names())))
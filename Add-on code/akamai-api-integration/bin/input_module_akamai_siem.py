
# encoding = utf-8

import os
import sys
import time
import datetime
import requests
import sys
import json
import time
import re
import hashlib
import base64
from akamai.edgegrid import EdgeGridAuth  # from https://github.com/akamai/AkamaiOPEN-edgegrid-python
from urllib.parse import unquote

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
    """Implement your own validation logic to validate the input stanza configurations"""
    # This example accesses the modular input variable
    # api_base_url = definition.parameters.get('api_base_url', None)
    # api_client_token = definition.parameters.get('api_client_token', None)
    # api_client_secret = definition.parameters.get('api_client_secret', None)
    # api_access_token = definition.parameters.get('api_access_token', None)
    # api_configid = definition.parameters.get('api_configid', None)
    # api_limit = definition.parameters.get('api_limit', None)
    # time_limit = definition.parameters.get('time_limit', None)
    # use_splunk_helper_checkpoint = definition.parameters.get('use_splunk_helper_checkpoint', None)
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
        filePath=scriptPath+ "/siem_"+filenameID+".json"
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
        filePath=scriptPath+ "/siem_"+filenameID+".json"
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
                 
    opt_api_base_url = helper.get_arg('api_base_url')
    opt_api_client_token = helper.get_arg('api_client_token')
    opt_api_client_secret = helper.get_arg('api_client_secret')
    opt_api_access_token = helper.get_arg('api_access_token')
    opt_api_configid = helper.get_arg('api_configid')
    opt_api_limit = int(helper.get_arg('api_limit'))
    opt_time_limit = int(helper.get_arg('time_limit'))
    opt_use_splunk_helper_checkpoint = helper.get_arg('use_splunk_helper_checkpoint')
    global_sslcertverification = helper.get_global_setting("sslcertverification")
    
    # create a session object using the Akamai python helper
    akamaiAPIsession = requests.Session()
    helper.log_debug('Akamai EdgeGridAuth() for SIEM events')
    akamaiAPIsession.auth = EdgeGridAuth(opt_api_client_token, opt_api_client_secret, opt_api_access_token)
    
    start_time = int(time.time())
    
    configIDhash = hashlib.md5((str(opt_api_configid)).encode('utf-8')).hexdigest()
    
    eventCheckpoint = helper_getCheckpoint(helper, opt_use_splunk_helper_checkpoint,configIDhash,configIDhash)
    if eventCheckpoint == None:
        helper.log_debug('Checkpoint not found')
        eventCheckpoint = "NULL"
    
    helper.log_debug('Checkpoint is '+eventCheckpoint)
    
    while int(time.time()) - start_time < opt_time_limit:
        
        helper.log_debug('Send GET SIEM request')
        
        result = akamaiAPIsession.get(opt_api_base_url+'siem/v1/configs/'+str(opt_api_configid)+'?offset='+eventCheckpoint+'&limit='+str(int(opt_api_limit)), proxies=proxies,verify=global_sslcertverification)
        
        if result.status_code==200:
            
            helper.log_debug('GET SIEM response 200')
            helper.log_debug('Parsing event JSON data')
            
            # split every line is a single object...
            JSONobjects=result.text.splitlines()
            
            # ... and iterate over them
            for event in JSONobjects:
                # valid attack event
                if "attackData" in event:
                    
                    eventJSON=json.loads(event)
                    rules_array = []
                    other_data = {}
                    for member in eventJSON["attackData"]:
                        # if the field start with "rule" we need a special parsing
                        # code adapted from the official API docs
                        if member[0:4] == 'rule':
                            # Alternate field name converted from plural:
                            member_as_singular = re.sub("s$", "", member)
                            url_decoded = unquote(eventJSON["attackData"][member])
                            # remove empty strings
                            member_array = list(filter(None, url_decoded.split(";")))
                            if not len(rules_array):
                                for i in range(len(member_array)):
                                    rules_array.append({})
                            i = 0
                            for item in member_array:
                                rules_array[i][member_as_singular] = base64.b64decode(item).decode("UTF-8",errors='replace')
                                i += 1
                        # if doesn't start with "rule" is data we need to keep for later
                        else:
                            other_data[member]=eventJSON["attackData"][member]
                    # replace the rules data with the parsed format...
                    eventJSON["attackData"]=rules_array
                    # ... and add other data
                    eventJSON["attackData"].append(other_data)
                    
                    # remove some fields
                    eventJSON.pop("format", None)
                    eventJSON.pop("type", None)
                    eventJSON.pop("version", None) 
                
                    # log the data with the time taken from the JSON event
                    data = json.dumps(eventJSON)
                    event = helper.new_event(time=int(eventJSON["httpMessage"]["start"]), source=helper.get_input_type(),
                        index=helper.get_output_index(),
                        sourcetype=helper.get_sourcetype(),
                        data=data)
                    ew.write_event(event)
                # if the obejct contain an offset, save it
                elif "offset" in event:
                    eventJSON=json.loads(event)
                    eventCheckpoint=eventJSON["offset"]
                    helper.log_debug("Fetched " + str(eventJSON["total"]) + " events with final offset " + eventJSON["offset"])
                    helper_setCheckpoint(helper, opt_use_splunk_helper_checkpoint,configIDhash,eventCheckpoint,configIDhash)
                    
                    # if we collected 0 events end the script
                    if eventJSON["total"] == 0:
                        helper.log_debug("Ending the collection script")
                        opt_time_limit=0
                # shoul never go here, log in case it happens
                else:
                    helper.log_debug("Unknown data "+event)
        elif result.status_code==416:
            # dump the error in the logs
            helper.log_error(result.text)
            # in case of old offset (result code=416) set offset=NULL for a fresh restart
            helper.log_debug("Old offset, setting offset=NULL to restart")
            eventCheckpoint="NULL"
            helper_setCheckpoint(helper, opt_use_splunk_helper_checkpoint,configIDhash,eventCheckpoint,configIDhash)
            
        else:
            # dump the error in the logs
            helper.log_error(result.text)
            # exit the loop
            opt_time_limit=0
    
    helper.log_info("Input {} has ended.".format(str(helper.get_input_stanza_names())))
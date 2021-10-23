 

# encoding = utf-8

import os
import sys
import time
import datetime
import requests
import hashlib
import json
# standard Akamai helper python script
from akamai.edgegrid import EdgeGridAuth  # from https://github.com/akamai/AkamaiOPEN-edgegrid-python

def validate_input(helper, definition):
    # just check it's an INT
    api_sample = int(definition.parameters.get('api_sample', None))
    # more checks can be done if needed
    pass

# based on the selected behaviour from use_helperCheckpoint this function will
# use the helper get_check_point function (based on KV store) or fallback to
# a JSON file to get the checkpoints
def helper_getCheckpoint(helper, use_helperCheckpoint, key, filenameID):
    if use_helperCheckpoint:
        return helper.get_check_point(key)
    else:
        # get this python script path
        scriptPath=os.path.dirname(os.path.realpath(__file__))
        # ... create ...
        filePath=scriptPath+ "/metrics_"+filenameID+".json"
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
# a JSON file to save the checkpoints
def helper_setCheckpoint(helper, use_helperCheckpoint, key, value, filenameID):
    if use_helperCheckpoint:
        return helper.save_check_point(key, str(value))
    else:
        # get this python script path
        scriptPath=os.path.dirname(os.path.realpath(__file__))
        # ... create ...
        filePath=scriptPath+ "/metrics_"+filenameID+".json"
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
    opt_metric = helper.get_arg('metrics')
    opt_api_monitored_contractids = \
        helper.get_arg('api_monitored_contractids')
    opt_api_sample = helper.get_arg('api_sample')
    opt_use_splunk_helper_checkpoint = helper.get_arg('use_splunk_helper_checkpoint')
    opt_time_series = helper.get_arg('time_series')
    opt_api_ip_assets = helper.get_arg('api_ip_assets')
    global_sslcertverification = helper.get_global_setting("sslcertverification")

    if opt_metric == True:
        # run if the input is configured to collect the metrics from the API
        helper.log_debug('akamai requests.Session() metrics')
        
        # create a session object using the Akamai python helper
        akamaiAPIsession = requests.Session()
        helper.log_debug('akamai EdgeGridAuth() metrics')
        akamaiAPIsession.auth = EdgeGridAuth(opt_api_client_token,
            opt_api_client_secret, opt_api_access_token)
        helper.log_debug('create POST request JSON  metrics')

        # prolexic-analytics/v2/metrics require a POST request with a JSON
        # containing the time interval and a sample rate. 
        # The sample rate is fixed to one every minute
        # The latest event is fixed to at most two minutes ago (rounded to the minute)
        # The first sample is calculate by going back for the desidered amount
        # of minutes configured in the input with the variable opt_api_sample
        epochTimeEnd = int(time.time()) - 60
        
        # round to the previous minute
        epochTimeEnd = epochTimeEnd - epochTimeEnd % 60
        samplesMinutes = int(opt_api_sample)
        
        # go back samplesMinutes minutes
        epochTimeStart = epochTimeEnd - 60 * (samplesMinutes) + 60

        helper.log_debug('requesting  metrics data from ' + str(epochTimeStart)
                     + ' until ' + str(epochTimeEnd) + ' sampled at ' + str(opt_api_sample))

        # we need to do an API call for every single contract
        contracts = opt_api_monitored_contractids.split(',')
        for contract in contracts:
        
            # create the JSON for the POST request, other metrics are available
            # but the ones below are the most stalbe
            POSTdata = {
                'contract': contract,
                'start': epochTimeStart,
                'end': epochTimeEnd,
                'samples': samplesMinutes,
                'type': {'mitigationPost': ['bandwidth', 'packets'],
                         'mitigationPre': ['bandwidth', 'packets']},
                }
    
            helper.log_debug('send POST request')
        
            # launch the POST request
            result = akamaiAPIsession.post(opt_api_base_url
                    + 'prolexic-analytics/v2/metrics', proxies=proxies,
                    json=POSTdata, verify=global_sslcertverification)

            if result.status_code == 200:
            
                helper.log_debug('POST  metrics response 200')
            
                # now that we have a response is simply a matter of parsing the
                # the returned JSON object to get the data that we want in a JSON
                # format in which every line represent a single time instance of
                # a single metric. Special attention is dedicated to avoid logging
                # events already logged (with the help of checkpoints)
                responseJSON = result.json()
                for metric in responseJSON['data']:
                
                    # sort the data by the epoch provided just in case
                    lines = sorted(metric['points'], key=lambda k: int(k[0]), reverse=False)
                
                    # the hash of the contract is a good value to keep the checkpoint
                    # files separated to avoid conflicts with multiple inputs
                    contractHash = hashlib.md5((contract).encode('utf-8')).hexdigest()
                    
                    # a good hash to identify the specific metric which will be logged.
                    # In this case [CONTRACT_ID][SERVICE][METRIC]
                    checkpointKey = hashlib.md5(str(responseJSON['currentContract']+metric['service']+metric['metric']).encode('utf-8')).hexdigest()
                    currentMetricCheckpoint = helper_getCheckpoint(helper, opt_use_splunk_helper_checkpoint,checkpointKey,contractHash)
                    
                    # if we can't find a checkpoint the code start with a default time of 0
                    if currentMetricCheckpoint == None:
                        currentMetricCheckpoint = '0'
                    newMetricCheckpoint = currentMetricCheckpoint
        
                    for point in lines:
                        # sometimes the returned value are invalid so we set them to -1
                        if point[1] == None:
                            point[1] = "-1"
                        
                        # create the JSON object
                        data={}
                        data["epochTimestamp"]=int(point[0])
                        data["DC"]=responseJSON['currentContract']
                        data["metric_name"]=metric['service']
                        data["metric_measure"]=metric['metric']
                        data["metric_value"]=float(point[1])
                    
                        # create the event to be logged
                        event = \
                            helper.new_event(time=float(point[0]),source=helper.get_input_type(),
                                index=helper.get_output_index(),
                                sourcetype=helper.get_sourcetype(),
                                data=json.dumps(data))
                    
                        # now we check that the event that we want to be logged
                        # is newer than what we already have logged (the checkpoint
                        # is the last epoch logged for this specific metric in this contract)
                        if int(point[0]) > int(currentMetricCheckpoint):
                            helper.log_debug('new metric or update found, logging')
                            # the event is newer so we log it and update the checkpoint
                            ew.write_event(event)
                            if int(point[0]) > int(newMetricCheckpoint):
                                    newMetricCheckpoint=point[0]
                    # now we have the checkpoint for the most recent epoch logged and
                    # we must save it
                    helper_setCheckpoint(helper, opt_use_splunk_helper_checkpoint,checkpointKey,str(newMetricCheckpoint),contractHash)
            else:
                # dump the error in the logs
                helper.log_error(result.text)
    
    if opt_time_series == True:
        # run if the input is configured to collect the time series data
        helper.log_debug('akamai requests.Session() time series')
        
        # create a session object using the Akamai python helper
        akamaiAPIsession = requests.Session()
        helper.log_debug('akamai EdgeGridAuth() time series')
        akamaiAPIsession.auth = EdgeGridAuth(opt_api_client_token,
                opt_api_client_secret, opt_api_access_token)
    
        # prolexic-analytics/v2/time-series-data require a GET request containing
        # the time interval and a sample rate. 
        # The sample rate is fixed to one every minute
        # The latest event is fixed to at most two minutes ago (rounded to the minute)
        # The first sample is calculate by going back for the desidered amount
        # of minutes configured in the input with the variable opt_api_sample
        epochTimeEnd = int(time.time()) - 60
        epochTimeEnd = epochTimeEnd - epochTimeEnd % 60
        samplesMinutes = int(opt_api_sample)
        epochTimeStart = epochTimeEnd - 60 * (samplesMinutes) + 60

        helper.log_debug('requesting time series data from ' + str(epochTimeStart)
                     + ' until ' + str(epochTimeEnd) + ' sampled at ' + str(opt_api_sample))

        # every subnet require an API call, but every IP can be done in single
        # API call (if they are not too many). Start by getting all the IP and subnets
        ipList=""
        subnets = opt_api_ip_assets.split(',')
        helper.log_debug('starting logging subnets')
        for subnet in subnets:
        
            if "/" in subnet:
                #if we have a subnet we are good to go for an API call
                helper.log_debug('send GET time series request for subnet '+subnet)
        
                # fill the fields correctly. locations=agr is to get the aggregate metrics (others are available)
                result = akamaiAPIsession.get(opt_api_base_url+('prolexic-analytics/v2/time-series-data?destinations='+subnet+'&endTime='+str(epochTimeEnd)+'&locations=agr&samplingSize='+str(samplesMinutes)+'&startTime='+str(epochTimeStart)), proxies=proxies,verify=global_sslcertverification)

                if result.status_code == 200:
                    # now that we have a response is simply a matter of parsing the
                    # the returned JSON object to get the data that we want in a JSON
                    # format in which every line represent a single time instance of
                    # a single metric. Special attention is dedicated to avoid logging
                    # events already logged (with the help of checkpoints)
                    helper.log_debug('GET time series response 200')
                    responseJSON = result.json()
                    for resource in responseJSON:
                        for metric in responseJSON[resource]:
                    
                            # the hash of the subnet is a good value to keep the checkpoint
                            # files separated to avoid conflicts with multiple inputs
                            subnetHash = hashlib.md5((subnet).encode('utf-8')).hexdigest()
                            
                            # a good hash to identify the specific metrics which will be logged.
                            # In this case IP-METRIC
                            checkpointKey = hashlib.md5((subnet+"-"+metric).encode('utf-8')).hexdigest()
                            
                            currentMetricCheckpoint = helper_getCheckpoint(helper, opt_use_splunk_helper_checkpoint,checkpointKey,subnetHash)
                            
                            # if we can't find a checkpoint the code start with a default time of 0
                            if currentMetricCheckpoint == None:
                                currentMetricCheckpoint = '0'
                            newMetricCheckpoint = currentMetricCheckpoint
                            
                            # sort the data by the epoch provided just in case
                            lines = sorted(responseJSON[resource][metric], key=lambda k: int(k), reverse=False)
                    
                            for value in lines:
                                # now we check that the event that we want to be logged
                                # is newer than what we already have logged (the checkpoint
                                # is the last epoch logged for this specific metric in this subnet)
                                if int(value) > int(currentMetricCheckpoint):
                                    helper.log_debug('new time series or update found, logging')
                                
                                    # create the JSON object
                                    data={}
                                    data["epochTimestamp"]=int(str(value)[:-3])
                                    data["asset"]=resource
                                    data["time_serie_name"]=metric
                                    data["time_serie_value"]=float(responseJSON[resource][metric][value])
                                
                                    # create the event to be logged
                                    event = helper.new_event(time=int(str(value)[:-3]),source=helper.get_input_type(),
                                        index=helper.get_output_index(),
                                        sourcetype=helper.get_sourcetype(),
                                        data=json.dumps(data))
                                    ew.write_event(event)
                                    
                                    # and save the new epoch if it's newer than what we have
                                    if int(value) > int(newMetricCheckpoint):
                                        newMetricCheckpoint=value
                            # now we have the checkpoint for the most recent epoch logged and
                            # we must save it
                            helper_setCheckpoint(helper, opt_use_splunk_helper_checkpoint,checkpointKey,newMetricCheckpoint,subnetHash)
                else:
                    # dump the error in the logs
                    helper.log_error(result.text)
            else:
                # if we don't have a subnet (so an IP) we fill an array with all of them
                helper.log_debug('keeping '+subnet+ ' for later')
                ipList=ipList+subnet+","
    
        # just remove the last character (a comma)
        ipList = ipList[:-1]
    
        # start again a single API call similar to what we did for the subnets
        # but with a small formatting difference in the response
        helper.log_debug('starting time series logging for IPs: '+ipList)

        result = akamaiAPIsession.get(opt_api_base_url+"prolexic-analytics/v2/time-series-data?destinations="+ipList+"&endTime="+str(epochTimeEnd)+"&locations=agr&samplingSize="+str(samplesMinutes)+"&startTime="+str(epochTimeStart), proxies=proxies,verify=global_sslcertverification)

        if result.status_code == 200:
            
            # now that we have a response is simply a matter of parsing the
            #  the returned JSON object to get the data that we want in a JSON
            # format in which every line represent a single time instance of
            # a single metric. Special attention is dedicated to avoid logging
            # events already logged (with the help of checkpoints)
            helper.log_debug('GET time series response 200')
            responseJSON = result.json()
        
            for asset in responseJSON:
                for metric in responseJSON[asset]:
                    
                    # the hash of the subnets and IP is a good value to keep the checkpoint
                    # files separated to avoid conflicts with multiple inputs
                    assetHash = hashlib.md5((opt_api_ip_assets).encode('utf-8')).hexdigest()
                    
                    # a good hash to identify the specific metrics which will be logged.
                    # In this case IP-METRIC
                    checkpointKey = hashlib.md5((asset+"-"+metric).encode('utf-8')).hexdigest()
                    currentMetricCheckpoint = helper_getCheckpoint(helper, opt_use_splunk_helper_checkpoint,checkpointKey,assetHash)

                    # if we can't find a checkpoint the code start with a default time of 0
                    if currentMetricCheckpoint == None:
                        currentMetricCheckpoint = '0'
                    newMetricCheckpoint = currentMetricCheckpoint
                
                    # sort the data by the epoch provided just in case
                    lines = sorted(responseJSON[asset][metric], key=lambda k: int(k), reverse=False)
                
                    for value in lines:
                        # now we check that the event that we want to be logged
                        # is newer than what we already have logged (the checkpoint
                        # is the last epoch logged for this specific metric in this IP list)
                        if int(value) > int(currentMetricCheckpoint):
                            helper.log_debug('new time series  or update found, logging')
                        
                            # create the JSON object
                            data={}
                            data["epochTimestamp"]=int(str(value)[:-3])
                            data["asset"]=asset
                            data["time_serie_name"]=metric
                            data["time_serie_value"]=float(responseJSON[asset][metric][value])
                            
                            # create the event to be logged
                            event = helper.new_event(time=int(str(value)[:-3]),source=helper.get_input_type(),
                                index=helper.get_output_index(),
                                sourcetype=helper.get_sourcetype(),
                                data=json.dumps(data))
                            ew.write_event(event)
                            
                            # and save the new epoch if it's newer than what we have
                            if int(value) > int(newMetricCheckpoint):
                                newMetricCheckpoint=value
                     # now we have the checkpoint for the most recent epoch logged and
                    # we must save it
                    helper_setCheckpoint(helper, opt_use_splunk_helper_checkpoint,checkpointKey,newMetricCheckpoint,assetHash)
        else:
            # dump the error in the logs
            helper.log_error(result.text)
    
    helper.log_info("Input {} has ended.".format(str(helper.get_input_stanza_names())))
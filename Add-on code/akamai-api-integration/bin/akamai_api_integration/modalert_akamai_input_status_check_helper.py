
# encoding = utf-8

import sys
import urllib
import requests
from xml.dom import minidom

def process_event(helper, *args, **kwargs):
    """
    # IMPORTANT
    # Do not remove the anchor macro:start and macro:end lines.
    # These lines are used to generate sample code. If they are
    # removed, the sample code will not be updated when configurations
    # are updated.

    [sample_code_macro:start]

    # The following example sends rest requests to some endpoint
    # response is a response object in python requests library
    response = helper.send_http_request("http://www.splunk.com", "GET", parameters=None,
                                        payload=None, headers=None, cookies=None, verify=True, cert=None, timeout=None, use_proxy=True)
    # get the response headers
    r_headers = response.headers
    # get the response body as text
    r_text = response.text
    # get response body as json. If the body text is not a json string, raise a ValueError
    r_json = response.json()
    # get response cookies
    r_cookies = response.cookies
    # get redirect history
    historical_responses = response.history
    # get response status code
    r_status = response.status_code
    # check the response status, if the status is not sucessful, raise requests.HTTPError
    response.raise_for_status()


    # The following example gets and sets the log level
    helper.set_log_level(helper.log_level)

    # The following example gets account information
    user_account = helper.get_user_credential("<account_name>")

    # The following example gets the setup parameters and prints them to the log
    sslcertverification = helper.get_global_setting("sslcertverification")
    helper.log_info("sslcertverification={}".format(sslcertverification))

    # The following example gets the alert action parameters and prints them to the log
    username = helper.get_param("username")
    helper.log_info("username={}".format(username))

    base_url = helper.get_param("base_url")
    helper.log_info("base_url={}".format(base_url))

    input_type = helper.get_param("input_type")
    helper.log_info("input_type={}".format(input_type))

    input_name = helper.get_param("input_name")
    helper.log_info("input_name={}".format(input_name))


    # The following example adds two sample events ("hello", "world")
    # and writes them to Splunk
    # NOTE: Call helper.writeevents() only once after all events
    # have been added
    helper.addevent("hello", sourcetype="sample_sourcetype")
    helper.addevent("world", sourcetype="sample_sourcetype")
    helper.writeevents(index="summary", host="localhost", source="localhost")

    # The following example gets the events that trigger the alert
    events = helper.get_events()
    for event in events:
        helper.log_info("event={}".format(event))

    # helper.settings is a dict that includes environment configuration
    # Example usage: helper.settings["server_uri"]
    helper.log_info("server_uri={}".format(helper.settings["server_uri"]))
    [sample_code_macro:end]
    """

    helper.log_info("Alert action reload_input started.")

    # TODO: Implement your alert action logic here

    user_account = helper.get_user_credential(str(helper.get_param("username")))
    
    clientid=user_account["username"]
    secret=user_account["password"]
    
    #helper.log_info("user_account={}".format(user_account))

    input_type = str(helper.get_param("input_type"))    
    input_name = str(helper.get_param("input_name"))
    helper.log_info("input_name={}".format(input_name))
    
    base_url = str(helper.get_param("base_url"))

    helper.log_info("base_url={}".format(base_url))
    
    # something like -> https://localhost:8089/servicesNS/nobody/akamai-api-integration/data/inputs/akamai_siem/Test
    url = base_url + "/servicesNS/" + clientid +"/akamai-api-integration/data/inputs/"+ input_type + "/" + input_name
    
    payload={}
    
    helper.log_info("AKAMAI API INTEGRATION ACTION: Username: "+ clientid + " Input: " + input_name + " URL: " + url )
    
    def splunk_auth():
        data = {'username': clientid, 'password': secret}
        auth_url = base_url + "/services/auth/login"
        
        helper.log_info("data={}".format(data))
        helper.log_info("auth_url={}".format(auth_url))
        
        session_response = ""
        session_response_text = ""
        
        try:
            servercontent = requests.post(base_url+'/services/auth/login', data=data, verify=False)  
            session_response = str(servercontent.status_code)
            session_response_text = str(servercontent.text)
            helper.log_info("servercontent.text={}".format(servercontent.text))
        except:
            e = sys.exc_info()[0]
            helper.log_error('AKAMAI API INTEGRATION ACTION: Unable to authenticate to Splunk API.')
            helper.log_info('AKAMAI API INTEGRATION ACTION: Exception accessing Splunk API: ' + str(e))
            helper.log_info('AKAMAI API INTEGRATION ACTION: Exception accessing Splunk API: ' + session_response_text)
        
        if session_response.startswith('20'):       
            sessionkey = minidom.parseString(servercontent.text).getElementsByTagName('sessionKey')[0].childNodes[0].nodeValue
            helper.log_info('AKAMAI API INTEGRATION ACTION: Successfully acquired Splunk authentication token.')
            print('got session key')
        else:
            helper.log_error('AKAMAI API INTEGRATION ACTION: Unable to acquire Splunk authentication token.')
            helper.log_error('AKAMAI API INTEGRATION ACTION: '+session_response_text)
            print('could not pull session key')
            sys.exit()
        
        return sessionkey

    def disable_input(session_key):
        disable_url = url + '/disable'
        helper.log_info('AKAMAI API INTEGRATION ACTION: Sending disable request: ' + str(disable_url))

        disable_response = ""
        try:    
            headers={'Authorization': 'Splunk %s' % session_key}
            disable_response = requests.request("POST", disable_url, headers=headers, verify=False).text
        
        except:
            e = sys.exc_info()[0]
            helper.log_error('AKAMAI API INTEGRATION ACTION: Unable to disable input.')
            helper.log_debug('AKAMAI API INTEGRATION ACTION: Error response was: ' + str(e))
        
        helper.log_info('AKAMAI API INTEGRATION ACTION: Disable request response: ' + str(disable_response))

    
    def enable_input(session_key):
        headers={'Authorization': 'Splunk %s' % session_key}
        enable_url = url + '/enable' 
        helper.log_info('AKAMAI API INTEGRATION ACTION: Sending enable request: ' + str(enable_url))
        
        enable_response = ""

        try:
            enable_response = requests.request("POST", enable_url, headers=headers, verify=False).text
            
        except:
            e = sys.exc_info()[0]
            helper.log_error('AKAMAI API INTEGRATION ACTION: Unable to enable input.')
            helper.log_debug('AKAMAI API INTEGRATION ACTION: Error response was: ' + str(e))
            
        helper.log_info('AKAMAI API INTEGRATION ACTION: Enable request response: ' + str(enable_response))

    session_key=splunk_auth()
    disable_input(session_key)
    enable_input(session_key)

    return 0

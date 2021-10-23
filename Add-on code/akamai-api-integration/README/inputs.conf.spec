[conf_domains://<name>]
api_base_url = https://akab-yyyyyyyyyyyyyyyy-xxxxxxxxxxxxxxxx.luna.akamaiapis.net/
api_client_token = 
api_client_secret = 
api_access_token = 
gtm_configuration = Check for GTM config
dns_zones = Check for DNS zones

[prolexic_events://<name>]
api_base_url = https://akab-yyyyyyyyyyyyyyyy-xxxxxxxxxxxxxxxx.luna.akamaiapis.net/
api_client_token = 
api_client_secret = 
api_access_token = 
api_monitored_contractids = Comma separated list of monitored contracts
use_splunk_helper_checkpoint = If possible leave checked to use Splunk helper checkpoint. If not it will fall back with files
events = Log events
critical_events = Log critical events
attack_reports = Log attack reports
api_minutes = Retrieve events in the last X minutes

[akamai_siem://<name>]
api_base_url = https://akab-yyyyyyyyyyyyyyyy-xxxxxxxxxxxxxxxx.luna.akamaiapis.net/
api_client_token = 
api_client_secret = 
api_access_token = 
api_configid = Unique identifier for each security configuration. To report on more than one configuration, separate integer identifiers with semicolons.
api_limit = Defines the approximate maximum number of security events each fetch returns.
time_limit = Time limit in seconds after witch the log collection will stop
use_splunk_helper_checkpoint = If possible leave checked to use Splunk helper checkpoint. If not it will fall back with files

[prolexic_metrics://<name>]
api_base_url = https://akab-yyyyyyyyyyyyyyyy-xxxxxxxxxxxxxxxx.luna.akamaiapis.net/
api_client_token = 
api_client_secret = 
api_access_token = 
metrics = Log metrics
api_monitored_contractids = Comma separated list of monitored contracts
time_series = Log time series
api_ip_assets = Comma separated list of monitored IP assets. One API call for each subnet and a final single API call for all remaining IPs. 1.1.1.0/24,1.1.2.0/24,1.1.1.1,1.1.3.1 -> 3 API calls.
api_sample = 
use_splunk_helper_checkpoint = If possible leave checked to use Splunk helper checkpoint. If not it will fall back with files
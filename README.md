# Akamai-Splunk-API-integration
**Unofficial** Splunk add on for Akamai prolexic, DNS and GTM ingestion written in Python 3.7

![Dashboard example](https://github.com/garis/Akamai-Splunk-API-integration/blob/main/images/dashboard.png)

# Inputs
| Input Name | Source Type | Description |
|---|---|---|
| prolexic_metrics | akamai:json_metrics | Akamai Prolexic Analytics APIv2 metrics add on for Splunk |
| conf_domains | akamai:json_conf | Akamai Edge DNS Zone and GTM Management API v2 add on for Splunk |
| prolexic_events | akamai:json_event | Akamai Prolexic Analytics APIv2 events add on for Splunk |

*akamai:json_metrics* and *akamai:json_event* are designed to be resilient. If the API or the connectivity fails the next scheduled run is able to recover what wasn't logged before.

## High level overview

### akamai:json_metrics

Collect Prolexic metrics using:

[Prolexic API docs](https://developer.akamai.com/api/cloud_security/prolexic_analytics/v2.html)

All data is logged as JSON objects. The ingestion is performed once for every run of the input but for only metrics with a new timestamp.
For each metric the input keeps track of the last epoch timestamp logged  so for each metric-contract/subnet only the new events are logged to avoid duplicates.

This input has two sub-input that can be enabled with *opt_metric* or *opt_time_series* (checkboxes available in the Splunk GUI).

#### opt_metric

Using "prolexic-analytics/v2/metrics" both measures *bandwidth* and *packets* will be downloaded for *mitigationPost* and *mitigationPre* for each defined contract ID.

The value *opt_api_sample* define how many minutes will be requested. 
Using the checkpoints values only the new values will be logged. So if we have 10 samples with timestamps 10,11,12,13,14,15,16,17,18,19,20 and a checkpoint with value 19 then only the metrics with time 20 will be logged.

#### opt_time_series

Using "prolexic-analytics/v2/time-series-data" the aggregated mesures (*agr*) will be downloaded for each subnet or IP specified. For some reason the API allow only one request for each subnet but for IP a single request can contain multiple IPs.
As for *opt_metric* *opt_api_sample* a similar logic has been implemented and checkpoints are used to log only new events. 

## akamai:json_conf

Collects GTM and DNS zones using:

[Akamai GTM API docs](https://developer.akamai.com/api/web_performance/global_traffic_management/v1.html)

[Akamai DNS API docs](https://developer.akamai.com/api/cloud_security/edge_dns_zone_management/v2.html)

All data is logged as JSON objects. The ingestion is performed once for every run of the input.

This input has two sub-input that can be enabled with *opt_gtm_configuration* or *opt_dns_zones* (checkboxes available in the Splunk GUI).

#### opt_gtm_configuration

Using "config-gtm/v1/domains" (to obtain the resources) and "config-gtm/v1/domains" (to obtain the GTM config of each resource previously found) the entire GTM config will be logged in each execution.

#### opt_dns_zones

Using "config-dns/v2/zones" (to obtain the zones) and "config-dns/v2/zones/{ZONE}/zone-file" (to obtain the zone dump of each zone previously found) the entire DNS zone for each domain will be logged in each execution.

## akamai:json_event

Collects Prolexic events using:

[Prolexic API docs](https://developer.akamai.com/api/cloud_security/prolexic_analytics/v2.html)

All data is logged as JSON objects. The ingestion is performed once for every run of the input but for only new or updated events.
The input calculate and saves an hash for each events (using the helper checkpoint functions from Splunk or by falling back to a local file). Only events with new hashes are logged to avoid duplicates.

This input has three sub-input that can be enabled with *opt_critical_events*, *opt_attack_reports* or *opt_events* (checkboxes available in the Splunk GUI).

For all three the logic is the same:

1) get the event list given a contract ID or a timerange if necessary.
2) for each single JSON event:
  -) compute the hash of the entire event
  -) log only if the hash is new or different (usefull mainly for the attack reports since usually are updated by the operators)
 
# FAQ

## what does it means "Use Splunk helper checkpoint"?

The checkpoint mechanism implemented works in two modes:
1) helper function provided by Splunk (Docs)[https://docs.splunk.com/Documentation/AddonBuilder/4.0.0/UserGuide/PythonHelperFunctions]
2) local and custom JSON file

Method 1 rely on a KV store, method 2 rely on a local file in the bin folder. The second method must be used if, for some reason, a KV store cannot be used.
Method 1 is the suggested one.

#### Special thanks to [Pastea](https://github.com/Pastea) for the help.

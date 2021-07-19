# Akamai-Splunk-API-integration
Unofficial Splunk add on for Akamai prolexic, DNS and GTM ingestion written in Python 3.7

![Dashboard example](https://github.com/garis/Akamai-Splunk-API-integration/blob/main/images/dashboard.png)

# Inputs
| Input Name | Source Type | Description |
|---|---|---|
| prolexic_metrics | akamai:json_metrics | Akamai Prolexic Analytics APIv2 metrics add on for Splunk |
| conf_domains | akamai:json_conf | Akamai Edge DNS Zone and GTM Management API v2 add on for Splunk |
| prolexic_events | akamai:json_event | Akamai Prolexic Analytics APIv2 events add on for Splunk |

*akamai:json_metrics* and *akamai:json_event* are designed to be resistant to network problems. If the API or the connectivity fails the next ones are able to recover what wasn't logged before.

## akamai:json_metrics

Collect Prolexic metrics using:

[Prolexic API docs](https://developer.akamai.com/api/cloud_security/prolexic_analytics/v2.html)

All data is logged as JSON objects. The ingestion is performed once for every run of the input but for only new or updated metrics.
For each metric the input keeps track of the last epoch timestamp logged for each metric-contract/subnet and only the recents events are logged to avoid duplicates.

## akamai:json_conf

Collects GTM and DNS zones using:

[Akamai GTM API docs](https://developer.akamai.com/api/web_performance/global_traffic_management/v1.html)

[Akamai DNS API docs](https://developer.akamai.com/api/cloud_security/edge_dns_zone_management/v2.html)

All data is logged as JSON objects. The ingestion is performed once for every run of the input.

## akamai:json_event

Collects Prolexic events using:

[Prolexic API docs](https://developer.akamai.com/api/cloud_security/prolexic_analytics/v2.html)

All data is logged as JSON objects. The ingestion is performed once for every run of the input but for only new or updated events.
The input calculate and saves and hash for each events (using the helper checkpoint functions from Splunk or by falling back to a local file). Only events with new hashes are logged to avoid duplicates.

#### Special thanks to [Pastea](https://github.com/Pastea) for the help

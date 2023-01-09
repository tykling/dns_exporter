# dns_exporter
A Blackbox-style Prometheus exporter with a focus on DNS monitoring. Built on the excellent https://github.com/rthalley/dnspython and https://github.com/prometheus/client_python

Following the `Multi Target Exporter Pattern` described in https://prometheus.io/docs/guides/multi-target-exporter/ `dns_exporter` can query any DNS server and return metrics based on the response.

Note: The well known `Blackbox Exporter` also supports DNS probes and exports metrics about DNS lookups. The `dns_exporter` was made with an exclusive focus on DNS monitoring. As always use the tool which is the best fit for your usecase :)

## Installation
Installation can be done using `pip`:

    pip install dns_exporter

A config file is not required for basic operation. Almost all functionality (except answer validation) can be used by passing URL arguments. But defining a config file with one or more modules (groups of settings) makes it possible to reuse settings between scrape jobs. It also makes the Prometheus config much shorter.


## Exporter Configuration
The config file is a yaml file where a root element named `modules` will be read and added to the configuration. Given an example config file with the following settings:


`dns_exporter.yml`:
```
---
modules:
  tcp4_ns:
    protocol: "tcp"
    family: "ipv4"
    query_type: "ns"
```

Then the two following scrape requests are identical:

Without any module:
```
http://192.0.2.42:15353/query?protocol=tcp&family=ipv4&query_type=ns&target=dns.google&query_name=eff.org
```

Using the `tcp4_ns` module:
```
http://192.0.2.42:15353/query?module=tcp4_ns&target=dns.google&query_name=eff.org
```

Using yaml anchors and merges means modules can be reused and extended. The package install contains an example config with the filename `dns_exporter_example.yml` which can be used as-is or adapted for your needs. It can also be found on Github at https://github.com/tykling/dns_exporter/blob/develop/dns_exporter/dns_exporter_example.yml

You are encouraged to contribute nice modules as a PR to the example config.


## Prometheus Configuration
The `dns_exporter` follows the same Multi Target Exporter Pattern as Blackbox so the same principles apply regarding rewriting targets. The following is an example where the `dns_exporter` is running at `dnsexp.example.com:15353` and since we will be using the relabel config a few times we defined a yaml anchor named `dnsexp_relabel` which we can reuse in all the scrape jobs:

`prometheus.yml`:
```
dnsexp_relabel: &dnsexp_relabel
  - source_labels:
      - '__address__'
    target_label: '__param_target'
  - source_labels:
      - '__param_target'
    target_label: 'instance'
  - target_label: '__address__'
    replacement: 'dnsexp.example.com:15353'
```

We will also be reusing the targets so define an anchor for those too:

`prometheus.yml`:
```
mytargets: &dns_targets
  - "dns.google"
  - "1dot1dot1dot1.cloudflare-dns.com"
  - "dns.quad9.net"
```

And finally the scrape config:

`prometheus.yml`:
```
scrape_configs:
  - name: 'dns_exporter_dot4'
    scheme: 'https'
    scrape_interval: '10s'
    metrics_path: "/query"
    params:
      module:
        - "dot"
      family:
        - "ipv4"
      query_name:
        - "eff.org"
    targets: *dns_targets
    relabel_configs: *dnsexp_relabel

  - name: 'dns_exporter_dot6'
    scheme: 'https'
    scrape_interval: '10s'
    metrics_path: "/query"
    params:
      module:
        - "dot"
      family:
        - "ipv6"
      query_name:
        - "eff.org"
    targets: *dns_targets
    relabel_configs: *dnsexp_relabel
```

This config will result in Prometheus scraping so the `dns_exporter` does a DoT query over v4 and v6 for `eff.org` to each of the three targets every 10 seconds.


# Metrics
The `dns_exporter` returns two or three metrics for each valid scrape request to `/query`:

* `dns_query_time_seconds` is a timing histogram with a bunch of labels about the DNS query and response
* `dns_query_success` is always 0 or 1
* `dns_query_failure_reason` is an enum which carries information about why a query failed. This is only included when `dns_query_success` is 0.

This is an example of the metrics returned from a random query:

```
$ curl "http://127.0.0.1:15353/query?module=dot&target=dns.google&query_name=eff.org"
# TYPE dns_query_success gauge
dns_query_success 1.0
# HELP dns_query_time_seconds DNS query time in seconds.
# TYPE dns_query_time_seconds histogram
dns_query_time_seconds_bucket{additional="0",answer="1",authority="0",family="ipv4",flags="QR RA RD",ip="8.8.4.4",le="0.005",nsid="gpdns-ham",opcode="QUERY",protocol="dot",query_name="eff.org",query_type="A",rcode="NOERROR",target="dns.google"} 0.0
dns_query_time_seconds_bucket{additional="0",answer="1",authority="0",family="ipv4",flags="QR RA RD",ip="8.8.4.4",le="0.01",nsid="gpdns-ham",opcode="QUERY",protocol="dot",query_name="eff.org",query_type="A",rcode="NOERROR",target="dns.google"} 0.0
dns_query_time_seconds_bucket{additional="0",answer="1",authority="0",family="ipv4",flags="QR RA RD",ip="8.8.4.4",le="0.025",nsid="gpdns-ham",opcode="QUERY",protocol="dot",query_name="eff.org",query_type="A",rcode="NOERROR",target="dns.google"} 0.0
dns_query_time_seconds_bucket{additional="0",answer="1",authority="0",family="ipv4",flags="QR RA RD",ip="8.8.4.4",le="0.05",nsid="gpdns-ham",opcode="QUERY",protocol="dot",query_name="eff.org",query_type="A",rcode="NOERROR",target="dns.google"} 0.0
dns_query_time_seconds_bucket{additional="0",answer="1",authority="0",family="ipv4",flags="QR RA RD",ip="8.8.4.4",le="0.075",nsid="gpdns-ham",opcode="QUERY",protocol="dot",query_name="eff.org",query_type="A",rcode="NOERROR",target="dns.google"} 1.0
dns_query_time_seconds_bucket{additional="0",answer="1",authority="0",family="ipv4",flags="QR RA RD",ip="8.8.4.4",le="0.1",nsid="gpdns-ham",opcode="QUERY",protocol="dot",query_name="eff.org",query_type="A",rcode="NOERROR",target="dns.google"} 1.0
dns_query_time_seconds_bucket{additional="0",answer="1",authority="0",family="ipv4",flags="QR RA RD",ip="8.8.4.4",le="0.25",nsid="gpdns-ham",opcode="QUERY",protocol="dot",query_name="eff.org",query_type="A",rcode="NOERROR",target="dns.google"} 1.0
dns_query_time_seconds_bucket{additional="0",answer="1",authority="0",family="ipv4",flags="QR RA RD",ip="8.8.4.4",le="0.5",nsid="gpdns-ham",opcode="QUERY",protocol="dot",query_name="eff.org",query_type="A",rcode="NOERROR",target="dns.google"} 1.0
dns_query_time_seconds_bucket{additional="0",answer="1",authority="0",family="ipv4",flags="QR RA RD",ip="8.8.4.4",le="0.75",nsid="gpdns-ham",opcode="QUERY",protocol="dot",query_name="eff.org",query_type="A",rcode="NOERROR",target="dns.google"} 1.0
dns_query_time_seconds_bucket{additional="0",answer="1",authority="0",family="ipv4",flags="QR RA RD",ip="8.8.4.4",le="1.0",nsid="gpdns-ham",opcode="QUERY",protocol="dot",query_name="eff.org",query_type="A",rcode="NOERROR",target="dns.google"} 1.0
dns_query_time_seconds_bucket{additional="0",answer="1",authority="0",family="ipv4",flags="QR RA RD",ip="8.8.4.4",le="2.5",nsid="gpdns-ham",opcode="QUERY",protocol="dot",query_name="eff.org",query_type="A",rcode="NOERROR",target="dns.google"} 1.0
dns_query_time_seconds_bucket{additional="0",answer="1",authority="0",family="ipv4",flags="QR RA RD",ip="8.8.4.4",le="5.0",nsid="gpdns-ham",opcode="QUERY",protocol="dot",query_name="eff.org",query_type="A",rcode="NOERROR",target="dns.google"} 1.0
dns_query_time_seconds_bucket{additional="0",answer="1",authority="0",family="ipv4",flags="QR RA RD",ip="8.8.4.4",le="7.5",nsid="gpdns-ham",opcode="QUERY",protocol="dot",query_name="eff.org",query_type="A",rcode="NOERROR",target="dns.google"} 1.0
dns_query_time_seconds_bucket{additional="0",answer="1",authority="0",family="ipv4",flags="QR RA RD",ip="8.8.4.4",le="10.0",nsid="gpdns-ham",opcode="QUERY",protocol="dot",query_name="eff.org",query_type="A",rcode="NOERROR",target="dns.google"} 1.0
dns_query_time_seconds_bucket{additional="0",answer="1",authority="0",family="ipv4",flags="QR RA RD",ip="8.8.4.4",le="+Inf",nsid="gpdns-ham",opcode="QUERY",protocol="dot",query_name="eff.org",query_type="A",rcode="NOERROR",target="dns.google"} 1.0
dns_query_time_seconds_count{additional="0",answer="1",authority="0",family="ipv4",flags="QR RA RD",ip="8.8.4.4",nsid="gpdns-ham",opcode="QUERY",protocol="dot",query_name="eff.org",query_type="A",rcode="NOERROR",target="dns.google"} 1.0
dns_query_time_seconds_sum{additional="0",answer="1",authority="0",family="ipv4",flags="QR RA RD",ip="8.8.4.4",nsid="gpdns-ham",opcode="QUERY",protocol="dot",query_name="eff.org",query_type="A",rcode="NOERROR",target="dns.google"} 0.0638432502746582
# HELP dns_query_time_seconds_created DNS query time in seconds.
# TYPE dns_query_time_seconds_created gauge
dns_query_time_seconds_created{additional="0",answer="1",authority="0",family="ipv4",flags="QR RA RD",ip="8.8.4.4",nsid="gpdns-ham",opcode="QUERY",protocol="dot",query_name="eff.org",query_type="A",rcode="NOERROR",target="dns.google"} 1.67321186737803e+09
$
```

The labels returned by the `dns_query_time_seconds` histogram are:
* `target` (from request): The DNS server used for the query
* `ip` (from request): The IP used for the query
* `family` (from request): Either `ipv4` or `ipv6`
* `protocol` (from request) Either `udp`, `tcp`, `dot`, `doh`, or `doq`
* `query_name` (from request)
* `query_type` (from request)
* `flags` (from response): The DNS header flags
* `opcode` (from response): The opcode is usually `QUERY`
* `rcode` (from response): The rcode like `NOERROR` or `NXDOMAIN`
* `nsid` (from response): The `nsid` string if nsid was requested
* `answer` (from response): The number of answer section RRs
* `authority` (from response): The number of authority section RRs
* `additional` (from response): The number of additional section RRs


Additionally, when a failure is encountered the `dns_query_failure_reason` enum is included in the response to give an idea of what went wrong, in this case an unexpected `NXDOMAIN` instead of `NOERROR` as `rcode`:
```
$ curl "http://127.0.0.1:15353/query?module=dot&target=dns.google&query_name=effff.org" | grep failure
# HELP dns_query_failure_reason The reason this DNS query failed
# TYPE dns_query_failure_reason gauge
dns_query_failure_reason{dns_query_failure_reason="invalid_request_module"} 0.0
dns_query_failure_reason{dns_query_failure_reason="invalid_request_target"} 0.0
dns_query_failure_reason{dns_query_failure_reason="invalid_request_family"} 0.0
dns_query_failure_reason{dns_query_failure_reason="invalid_request_ip"} 0.0
dns_query_failure_reason{dns_query_failure_reason="invalid_request_protocol"} 0.0
dns_query_failure_reason{dns_query_failure_reason="timeout"} 0.0
dns_query_failure_reason{dns_query_failure_reason="invalid_response_rcode"} 1.0
dns_query_failure_reason{dns_query_failure_reason="invalid_response_flags"} 0.0
dns_query_failure_reason{dns_query_failure_reason="invalid_response_answer_rrs"} 0.0
dns_query_failure_reason{dns_query_failure_reason="invalid_response_authority_rrs"} 0.0
dns_query_failure_reason{dns_query_failure_reason="invalid_response_additional_rrs"} 0.0
dns_query_failure_reason{dns_query_failure_reason="other"} 0.0
$
```


Finally, the following persistent metrics are also kept by the exporter and returned by the `/metrics` endpoint (as well as the normal Python process metrics exported by the Prometheus python_client):

```
$ curl -s "http://127.0.0.1:15353/metrics" | grep -v python
# HELP dns_exporter_build_version_info The version of dns_exporter
# TYPE dns_exporter_build_version_info gauge
dns_exporter_build_version_info{version="0.2.0b2"} 1.0
# HELP up Is the dns_exporter up and running? 1 for yes and 0 for no.
# TYPE up gauge
up 1.0
# HELP dns_exporter_http_requests_total The total number of HTTP requests received by this exporter since start. This counter is increased every time any HTTP request is received by the dns_exporter.
# TYPE dns_exporter_http_requests_total counter
dns_exporter_http_requests_total{path="/query"} 72790.0
dns_exporter_http_requests_total{path="/metrics"} 9.0
# HELP dns_exporter_http_requests_created The total number of HTTP requests received by this exporter since start. This counter is increased every time any HTTP request is received by the dns_exporter.
# TYPE dns_exporter_http_requests_created gauge
dns_exporter_http_requests_created{path="/query"} 1.673211814111238e+09
dns_exporter_http_requests_created{path="/metrics"} 1.6732127021289015e+09
# HELP dns_exporter_http_responses_total The total number of HTTP responses sent by this exporter since start. This counter is increased every time an HTTP response is sent from the dns_exporter.
# TYPE dns_exporter_http_responses_total counter
dns_exporter_http_responses_total{path="/query",response_code="200"} 72790.0
dns_exporter_http_responses_total{path="/metrics",response_code="200"} 8.0
# HELP dns_exporter_http_responses_created The total number of HTTP responses sent by this exporter since start. This counter is increased every time an HTTP response is sent from the dns_exporter.
# TYPE dns_exporter_http_responses_created gauge
dns_exporter_http_responses_created{path="/query",response_code="200"} 1.6732118142182536e+09
dns_exporter_http_responses_created{path="/metrics",response_code="200"} 1.6732127021304686e+09
# HELP dns_exporter_dns_queries_total The total number of DNS queries sent by this exporter since start. This counter is increased every time the dns_exporter sends out a DNS query.
# TYPE dns_exporter_dns_queries_total counter
dns_exporter_dns_queries_total 72790.0
# HELP dns_exporter_dns_queries_created The total number of DNS queries sent by this exporter since start. This counter is increased every time the dns_exporter sends out a DNS query.
# TYPE dns_exporter_dns_queries_created gauge
dns_exporter_dns_queries_created 1.6732118126893325e+09
# HELP dns_exporter_dns_query_responses_total The total number of DNS query responses received since start. This counter is increased every time the dns_exporter receives a query response (before timeout).
# TYPE dns_exporter_dns_query_responses_total counter
dns_exporter_dns_query_responses_total 72790.0
# HELP dns_exporter_dns_query_responses_created The total number of DNS query responses received since start. This counter is increased every time the dns_exporter receives a query response (before timeout).
# TYPE dns_exporter_dns_query_responses_created gauge
dns_exporter_dns_query_responses_created 1.6732118126896229e+09
# HELP dns_exporter_dns_query_failures_total The total number of DNS queries considered failed. This counter is increased every time a DNS query is sent out and a valid response is not received.
# TYPE dns_exporter_dns_query_failures_total counter
dns_exporter_dns_query_failures_total 0.0
# HELP dns_exporter_dns_query_failures_created The total number of DNS queries considered failed. This counter is increased every time a DNS query is sent out and a valid response is not received.
# TYPE dns_exporter_dns_query_failures_created gauge
dns_exporter_dns_query_failures_created 1.6732118126896834e+09
```

# Versioning and Releases of dns_exporter
Versioning, branching and tagging of `dns_exporter` is done based on https://semver.org/ and https://nvie.com/posts/a-successful-git-branching-model/

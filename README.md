# dns_exporter
A Blackbox-style Prometheus exporter with a focus on DNS monitoring. Built on the excellent https://github.com/rthalley/dnspython and https://github.com/prometheus/client_python

Following the `Multi Target Exporter Pattern` described in https://prometheus.io/docs/guides/multi-target-exporter/ `dns_exporter` can query any DNS server and return metrics based on the response.

Note: The well known `Blackbox Exporter` also supports DNS probes and exports metrics about DNS lookups. The `dns_exporter` was made with an exclusive focus on DNS monitoring. As always use the tool which is the best fit for your usecase :)

## Versioning and Releases
Versioning, branching and tagging is done based on https://semver.org/ and https://nvie.com/posts/a-successful-git-branching-model/

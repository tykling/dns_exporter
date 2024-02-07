![Tox main](https://github.com/tykling/dns_exporter/actions/workflows/tox.yml/badge.svg?branch=main)
[![codecov](https://codecov.io/gh/tykling/dns_exporter/graph/badge.svg?token=OKP40B9H10)](https://codecov.io/gh/tykling/dns_exporter)
[![Documentation Status](https://readthedocs.org/projects/dns-exporter/badge/?version=latest)](https://dns-exporter.readthedocs.io/en/latest/?badge=latest)


# dns_exporter
`dns_exporter` is a [multi-target](https://prometheus.io/docs/guides/multi-target-exporter/) [Prometheus](https://prometheus.io/) exporter with an exclusive focus on DNS monitoring. It is built on the excellent libraries [dnspython](https://github.com/rthalley/dnspython) and [the Prometheus Python client library](https://github.com/prometheus/client_python).

`dns_exporter` can be used to monitor availability and performance of DNS servers, and to validate the responses they return. It can monitor recursive and authoritative servers regardless of the software they run. You can use it to make sure your (or your providers) DNS servers are sending the replies you expect and configure [Prometheus](https://prometheus.io/) and [Alertmanager](https://prometheus.io/docs/alerting/latest/alertmanager/) to notify you if something stops working.

`dns_exporter` works similar to the [Blackbox exporter](https://github.com/prometheus/blackbox_exporter) where Prometheus asks the exporter to scrape the target, rather than the exporter itself being the target. This is called the [Multi Target Exporter Pattern](https://prometheus.io/docs/guides/multi-target-exporter/). It is typically used in black-box style exporters where 1) the thing you are monitoring is not under your control, or 2) you want to measure the path as well. Often when monitoring DNS both 1) and 2) are relevant.

This means that for each scrape Prometheus speaks HTTP to the `dns_exporter` which then speaks DNS with the target DNS server and returns the resulting metrics over HTTP to Prometheus. `dns_exporter` supports doing DNS queries over plain port 53 `UDP` and `TCP`, as well as `DoT`, `DoH` and `DoQ`.


# Documentation
The documentation is available on [ReadTheDocs](https://dns-exporter.readthedocs.io/en/latest/?badge=latest)


# Versioning and Releases of dns_exporter
Versioning, branching and tagging of `dns_exporter` is done based on https://semver.org/ and https://nvie.com/posts/a-successful-git-branching-model/

# Fancy Repo Activity Graphics
![Alt](https://repobeats.axiom.co/api/embed/3c531c8db07c5982061d4c6e800238c7ddf8ab59.svg "Repobeats analytics image")

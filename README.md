[![Run Tox CI](https://github.com/tykling/dns_exporter/actions/workflows/tox.yml/badge.svg?branch=main)](https://github.com/tykling/dns_exporter/actions/workflows/tox.yml)
[![Documentation Status](https://readthedocs.org/projects/dns-exporter/badge/?version=latest)](https://dns-exporter.readthedocs.io/latest/)
[![Ruff](https://img.shields.io/endpoint?url=https://raw.githubusercontent.com/astral-sh/ruff/main/assets/badge/v2.json)](https://github.com/astral-sh/ruff)
[![codecov](https://codecov.io/gh/tykling/dns_exporter/graph/badge.svg?token=OKP40B9H10)](https://codecov.io/gh/tykling/dns_exporter)
[![PyPI version](https://badge.fury.io/py/dns-exporter.svg)](https://pypi.org/project/dns-exporter/)
[![Docker Image Version (latest semver)](https://img.shields.io/docker/v/tykling/dns_exporter)](https://hub.docker.com/r/tykling/dns_exporter)

# dns_exporter
`dns_exporter` is a [multi-target](https://prometheus.io/docs/guides/multi-target-exporter/) [Prometheus](https://prometheus.io/) exporter with an exclusive focus on DNS monitoring. It is built on the excellent libraries [dnspython](https://github.com/rthalley/dnspython) and [the Prometheus Python client library](https://github.com/prometheus/client_python).

`dns_exporter` can be used to monitor availability and performance of DNS servers, and to validate the responses they return. It can monitor recursive and authoritative servers regardless of the software they run. You can use it to make sure your (or your providers) DNS servers are sending the replies you expect and configure [Prometheus](https://prometheus.io/) and [Alertmanager](https://prometheus.io/docs/alerting/latest/alertmanager/) to notify you if something stops working.

`dns_exporter` works similar to the [Blackbox exporter](https://github.com/prometheus/blackbox_exporter) where Prometheus asks the exporter to scrape the target, rather than the exporter itself being the target. This is called the [Multi Target Exporter Pattern](https://prometheus.io/docs/guides/multi-target-exporter/). It is typically used in black-box style exporters where 1) the thing you are monitoring is not under your control, or 2) you want to measure the path as well. Often when monitoring DNS both 1) and 2) are relevant.

This means that for each scrape Prometheus speaks HTTP to the `dns_exporter` which then speaks DNS with the target DNS server and returns the resulting metrics over HTTP to Prometheus. `dns_exporter` supports doing DNS queries over plain port 53 `UDP` and `TCP`, as well as `DoT`, `DoH`, `DoH3`, and `DoQ`.

# Installation
`dns_exporter` is not yet in any OS package managers but installing `dns_exporter` can be done from pypi. This is the recommended way to install for now:

`pip install dns_exporter`

There is also a Docker image so you can get your container on:

`docker run -p 15353:15353 tykling/dns_exporter:latest`


# Documentation
The documentation is available on [ReadTheDocs](https://dns-exporter.readthedocs.io/latest/)

# Grafana Dashboard
There is a [Grafana dashboard](https://grafana.com/grafana/dashboards/20617-dns-exporter/) you can use as a starting point for your own dashboards.

# Fancy Repo Activity Graphics
![Alt](https://repobeats.axiom.co/api/embed/3c531c8db07c5982061d4c6e800238c7ddf8ab59.svg "Repobeats analytics image")

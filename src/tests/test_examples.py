# type: ignore
"""tests for example configuration snippets."""
import time

import pytest
import requests


@pytest.mark.parametrize(
    "prometheus_server", ["list_of_servers/prometheus.yml"], indirect=True
)
@pytest.mark.parametrize(
    "dns_exporter_param_config", ["list_of_servers/dns_exporter.yml"], indirect=True
)
def test_list_of_servers(prometheus_server, dns_exporter_param_config):
    """Test the list_of_servers snippets from the docs."""
    for _ in range(15):
        r = requests.get(
            'http://127.0.0.1:9091/api/v1/query?query={job="dnsexp_doh_gmail_mx", dnsexp_dns_query_failure_reason="no_failure", instance=~"dns.google|dns.quad9.net"}'
        )
        if len(r.json()["data"]["result"]) == 2:
            break
        time.sleep(1)
    else:
        assert False, "expected result not found in prom"


@pytest.mark.parametrize(
    "prometheus_server", ["list_of_names/prometheus.yml"], indirect=True
)
@pytest.mark.parametrize(
    "dns_exporter_param_config", ["list_of_names/dns_exporter.yml"], indirect=True
)
def test_list_of_names(caplog, prometheus_server, dns_exporter_param_config):
    """Test the list_of_names snippets from the docs."""
    for _ in range(15):
        r = requests.get(
            'http://127.0.0.1:9091/api/v1/query?query={job="dnsexp_quad9_mx", dnsexp_dns_query_failure_reason="no_failure", instance=~"gmail.com|outlook.com"}'
        )
        if len(r.json()["data"]["result"]) == 2:
            break
        time.sleep(1)
    else:
        assert False, "expected result not found in prom"

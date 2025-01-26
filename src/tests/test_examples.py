"""tests for example configuration snippets."""

import shutil
import time

import pytest
import requests

# the tests in this module require Prometheus to be installed and in $PATH
prom = shutil.which("prometheus")
if prom is None:
    pytest.skip(
        "Skipping example tests because Prometheus is not installed",
        allow_module_level=True,
    )


@pytest.mark.parametrize(
    "prometheus_server",
    ["list_of_servers/prometheus.yml"],
    indirect=True,
)
@pytest.mark.parametrize(
    "dns_exporter_param_config",
    ["list_of_servers/dns_exporter.yml"],
    indirect=True,
)
def test_list_of_servers(prometheus_server, dns_exporter_param_config):
    """Test the list_of_servers snippets from the docs."""
    for _ in range(15):
        r = requests.get(
            "http://127.0.0.1:9092/api/v1/query?query=dnsexp_dns_query_success==1",
        )
        if len(r.json()["data"]["result"]) > 0 and r.json()["data"]["result"][0]["value"][1] == "1":
            break
        time.sleep(1)
    else:
        pytest.fail("expected result not found in prom")


@pytest.mark.parametrize(
    "prometheus_server",
    ["list_of_names/prometheus.yml"],
    indirect=True,
)
@pytest.mark.parametrize(
    "dns_exporter_param_config",
    ["list_of_names/dns_exporter.yml"],
    indirect=True,
)
def test_list_of_names(caplog, prometheus_server, dns_exporter_param_config):
    """Test the list_of_names snippets from the docs."""
    for _ in range(15):
        r = requests.get(
            "http://127.0.0.1:9092/api/v1/query?query=dnsexp_dns_query_success==1",
        )
        if len(r.json()["data"]["result"]) > 0 and r.json()["data"]["result"][0]["value"][1] == "1":
            break
        time.sleep(1)
    else:
        pytest.fail("expected result not found in prom")

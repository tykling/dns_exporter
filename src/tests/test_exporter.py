# type: ignore
"""dns_exporter test suite extravaganza."""
import requests

from dns_exporter.exporter import DNSExporter


def test_noconfig_server(dns_exporter_no_main_no_config, caplog):
    """Test basic lookup functionality."""
    r = requests.get(
        "http://127.0.0.1:15353/query",
        params={
            "query_name": "example.com",
            "target": "dns.google",
            "family": "ipv4",
        },
    )
    assert r.status_code == 200, "basic noconfig lookup failed with non-200 returncode"


def test_config_server(dns_exporter_example_config, caplog):
    """Test basic lookup functionality."""
    r = requests.get(
        "http://127.0.0.1:25353/query",
        params={
            "query_name": "example.com",
            "target": "dns.google",
            "family": "ipv4",
        },
    )
    assert r.status_code == 200, "basic lookup failed with non-200 returncode"


def test_config_stuff(dns_exporter_example_config, caplog):
    """Test various config scenarios."""
    exporter = DNSExporter
    exporter.configure(
        configs={
            "test": {
                "query_type": "MX",
            }
        }
    )
    r = requests.get(
        "http://127.0.0.1:25353/config",
        params={
            "target": "dns.google",
            "query_name": "example.com",
        },
    )
    config = r.json()
    assert config["target"] == "udp://dns.google"
    assert config["query_name"] == "example.com"

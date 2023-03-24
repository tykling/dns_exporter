# type: ignore
"""dns_exporter test suite extravaganza."""
import logging

import requests

from dns_exporter.exporter import DNSExporter, __version__


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


def test_config_endpoint(dns_exporter_example_config, caplog):
    """Test the /config endpoint."""
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

    r = requests.get(
        "http://127.0.0.1:25353/config",
        params={
            "config": "cf_doh",
        },
    )
    config = r.json()
    assert config["protocol"] == "doh"
    assert config["target"] == "https://1dot1dot1dot1.cloudflare-dns.com/dns-query"
    assert config["query_name"] == "bornhack.dk"
    assert config["query_type"] == "NS"
    assert config["validate_response_flags"]["fail_if_any_absent"] == ["AD"]


def test_invalid_qs_ip(dns_exporter_example_config):
    r = requests.get(
        "http://127.0.0.1:25353/query",
        params={
            "target": "dns.google",
            "query_name": "example.com",
            "ip": "notanip",
        },
    )
    assert r.status_code == 200, "non-200 returncode"
    assert (
        'dns_query_failure_reason{dns_query_failure_reason="invalid_request_ip"} 1.0'
        in r.text
    )


def test_invalid_configfile_ip(caplog):
    exporter = DNSExporter
    exporter.configure(configs={"test": {"ip": "notanip"}})
    assert "Unable to parse IP address notanip" in caplog.text


def test_missing_query_name(dns_exporter_example_config):
    r = requests.get(
        "http://127.0.0.1:25353/query",
        params={
            "target": "dns.google",
        },
    )
    assert r.status_code == 200, "non-200 returncode"
    assert (
        'dns_query_failure_reason{dns_query_failure_reason="invalid_request_query_name"} 1.0'
        in r.text
    )


def test_missing_target(dns_exporter_example_config):
    r = requests.get(
        "http://127.0.0.1:25353/query",
        params={
            "query_name": "example.com",
        },
    )
    assert r.status_code == 200, "non-200 returncode"
    assert (
        'dns_query_failure_reason{dns_query_failure_reason="invalid_request_target"} 1.0'
        in r.text
    )


def test_undefined_config(dns_exporter_example_config, caplog):
    r = requests.get(
        "http://127.0.0.1:25353/query",
        params={
            "config": "notaconfig",
        },
    )
    assert r.status_code == 200, "non-200 returncode"
    assert (
        'dns_query_failure_reason{dns_query_failure_reason="invalid_request_config"} 1.0'
        in r.text
    )


def test_unknown_config_key(dns_exporter_example_config, caplog):
    r = requests.get(
        "http://127.0.0.1:25353/query",
        params={
            "target": "dns.google",
            "foo": "bar",
        },
    )
    assert r.status_code == 200, "non-200 returncode"
    assert (
        'dns_query_failure_reason{dns_query_failure_reason="invalid_request_config"} 1.0'
        in r.text
    )


def test_ip_family_conflict(dns_exporter_example_config, caplog):
    r = requests.get(
        "http://127.0.0.1:25353/query",
        params={
            "target": "dns.google",
            "query_name": "example.com",
            "family": "ipv6",
            "ip": "192.0.2.53",
        },
    )
    assert r.status_code == 200, "non-200 returncode"
    assert (
        'dns_query_failure_reason{dns_query_failure_reason="invalid_request_ip"} 1.0'
        in r.text
    )


def test_ip_conflict(dns_exporter_example_config, caplog):
    r = requests.get(
        "http://127.0.0.1:25353/query",
        params={
            "target": "192.0.2.1",
            "query_name": "example.com",
            "ip": "192.0.2.53",
            "family": "ipv4",
        },
    )
    assert r.status_code == 200, "non-200 returncode"
    assert (
        'dns_query_failure_reason{dns_query_failure_reason="invalid_request_ip"} 1.0'
        in r.text
    )


def test_ip_and_hostname(dns_exporter_example_config, caplog):
    caplog.set_level(logging.DEBUG)
    r = requests.get(
        "http://127.0.0.1:25353/query",
        params={
            "target": "dns.google",
            "query_name": "example.com",
            "ip": "8.8.4.4",
            "family": "ipv4",
        },
    )
    assert r.status_code == 200, "non-200 returncode"
    assert (
        "Using target IP 8.8.4.4 (from config) for the DNS server connection"
        in caplog.text
    )


def test_unresolvable_target(dns_exporter_example_config, caplog):
    caplog.set_level(logging.DEBUG)
    r = requests.get(
        "http://127.0.0.1:25353/query",
        params={
            "target": "notatarget.example",
            "query_name": "example.com",
        },
    )
    assert r.status_code == 200, "non-200 returncode"
    assert (
        'dns_query_failure_reason{dns_query_failure_reason="invalid_request_target"} 1.0'
        in r.text
    )


def test_ipv6_family(dns_exporter_example_config, caplog):
    caplog.set_level(logging.DEBUG)
    r = requests.get(
        "http://127.0.0.1:25353/query",
        params={
            "target": "dns.google",
            "query_name": "example.com",
            "ip": "2001:4860:4860::8888",
            "timeout": 0.1,
        },
    )
    assert r.status_code == 200, "non-200 returncode"
    assert (
        "Using target IP 2001:4860:4860::8888 (from config) for the DNS server connection"
        in caplog.text
    )


def test_ipv7_family(dns_exporter_example_config, caplog):
    caplog.set_level(logging.DEBUG)
    r = requests.get(
        "http://127.0.0.1:25353/query",
        params={
            "target": "dns.google",
            "query_name": "example.com",
            "family": "ipv7",
        },
    )
    assert r.status_code == 200, "non-200 returncode"
    assert (
        'dns_query_failure_reason{dns_query_failure_reason="invalid_request_family"} 1.0'
        in r.text
    )


def test_internal_metrics(dns_exporter_example_config, caplog):
    r = requests.get(
        "http://127.0.0.1:25353/metrics",
    )
    assert r.status_code == 200, "non-200 returncode"
    assert f'dns_exporter_build_version_info{{version="{__version__}"}} 1.0' in r.text
    assert "Returning exporter metrics for request to /metrics" in caplog.text


def test_index(dns_exporter_example_config, caplog):
    r = requests.get(
        "http://127.0.0.1:25353/",
    )
    assert r.status_code == 200, "non-200 returncode"
    assert "DNS Exporter" in r.text
    assert "Returning index page for request to /" in caplog.text


def test_404(dns_exporter_example_config, caplog):
    r = requests.get(
        "http://127.0.0.1:25353/notfound",
    )
    assert r.status_code == 404, "non-404 returncode"
    assert "404 not found" in r.text
    assert "Unknown endpoint '/notfound' returning 404" in caplog.text


def test_tcp(dns_exporter_example_config, caplog):
    r = requests.get(
        "http://127.0.0.1:25353/query",
        params={
            "target": "dns.google",
            "query_name": "example.com",
            "protocol": "tcp",
            "family": "ipv4",
        },
    )
    assert r.status_code == 200, "non-200 returncode"
    assert 'transport="TCP"' in r.text
    assert "Protocol tcp got a DNS query response over TCP" in caplog.text


def test_udptcp(dns_exporter_example_config, caplog):
    r = requests.get(
        "http://127.0.0.1:25353/query",
        params={
            "target": "dns.google",
            "query_name": "example.com",
            "protocol": "udptcp",
            "family": "ipv4",
        },
    )
    assert r.status_code == 200, "non-200 returncode"
    assert 'transport="UDP"' in r.text
    assert "Protocol udptcp got a DNS query response over UDP" in caplog.text


def test_dot(dns_exporter_example_config, caplog):
    r = requests.get(
        "http://127.0.0.1:25353/query",
        params={
            "target": "dns.google",
            "query_name": "example.com",
            "protocol": "dot",
            "family": "ipv4",
        },
    )
    assert r.status_code == 200, "non-200 returncode"
    assert 'transport="TCP"' in r.text
    assert "Protocol dot got a DNS query response over TCP" in caplog.text


def test_doh(dns_exporter_example_config, caplog):
    r = requests.get(
        "http://127.0.0.1:25353/query",
        params={
            "target": "dns.google",
            "query_name": "example.com",
            "protocol": "doh",
            "family": "ipv4",
        },
    )
    assert r.status_code == 200, "non-200 returncode"
    assert 'transport="TCP"' in r.text
    assert "Protocol doh got a DNS query response over TCP" in caplog.text

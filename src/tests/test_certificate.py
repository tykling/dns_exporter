"""Certificate related tests."""

import logging
import ssl

import pytest
import requests


@pytest.mark.parametrize("protocol", ["dot", "doh", "doh3", "doq"])
def test_cert_verify_fail(dns_exporter_example_config, protocol, caplog):
    """Test cert verify functionality when there is a certificate<>hostname mismatch."""
    caplog.clear()
    caplog.set_level(logging.DEBUG)
    r = requests.get(
        "http://127.0.0.1:25353/query",
        params={
            "server": "91.239.100.100",
            "query_name": "example.com",
            "protocol": protocol,
            "family": "ipv4",
        },
    )
    assert "dnsexp_dns_query_success 0.0" in r.text


@pytest.mark.parametrize("protocol", ["dot", "doh", "doh3", "doq"])
def test_cert_verify_fail_custom_ca(dns_exporter_example_config, protocol, caplog):
    """Test cert verify functionality with a selfsigned cert as CA."""
    caplog.clear()
    caplog.set_level(logging.DEBUG)
    r = requests.get(
        "http://127.0.0.1:25353/query",
        params={
            "server": "dns-unfiltered.adguard.com",
            "query_name": "example.com",
            "protocol": protocol,
            "family": "ipv4",
            "verify_certificate_path": "tests/certificates/test.crt",
        },
    )
    assert "dnsexp_dns_query_success 0.0" in r.text


@pytest.mark.parametrize("protocol", ["dot", "doh", "doh3", "doq"])
def test_cert_verify_false(dns_exporter_example_config, protocol, caplog):
    """Test cert verify functionality disabled allows lookups with bad certs for doh."""
    caplog.clear()
    caplog.set_level(logging.DEBUG)
    r = requests.get(
        "http://127.0.0.1:25353/query",
        params={
            "server": "94.140.14.141",  # dns-unfiltered.adguard.com
            "query_name": "example.com",
            "protocol": protocol,
            "family": "ipv4",
            "verify_certificate": False,
        },
    )
    assert "dnsexp_dns_query_success 1.0" in r.text


@pytest.mark.parametrize("protocol", ["dot", "doh", "doh3", "doq"])
def test_cert_verify_invalid_path(dns_exporter_example_config, protocol, caplog):
    """Test cert verify functionality when an invalid CA path is provided."""
    caplog.clear()
    caplog.set_level(logging.DEBUG)
    r = requests.get(
        "http://127.0.0.1:25353/query",
        params={
            "server": "91.239.100.100",
            "query_name": "example.com",
            "protocol": protocol,
            "family": "ipv4",
            "verify_certificate_path": "/nonexistant",
        },
    )
    assert "FailCollector returning failure reason: invalid_request_path" in caplog.text
    assert "dnsexp_dns_query_success 0.0" in r.text


@pytest.mark.parametrize(
    "protocol",
    [
        "dot",
        "doh",
        pytest.param("doh3", marks=pytest.mark.xfail(reason="https://github.com/tykling/dns_exporter/issues/132")),
        pytest.param("doq", marks=pytest.mark.xfail(reason="https://github.com/tykling/dns_exporter/issues/132")),
    ],
)
def test_cert_verify_custom_ca_dir(dns_exporter_example_config, protocol, caplog):
    """Test cert verify functionality with a custom CA dir."""
    caplog.clear()
    caplog.set_level(logging.DEBUG)
    r = requests.get(
        "http://127.0.0.1:25353/query",
        params={
            "server": "anycast.censurfridns.dk",
            "query_name": "example.com",
            "protocol": protocol,
            "family": "ipv4",
            "verify_certificate_path": ssl.get_default_verify_paths().capath,
        },
    )
    assert "dnsexp_dns_query_success 1.0" in r.text

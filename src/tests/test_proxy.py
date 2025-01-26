"""Unit tests for proxy functionality."""

import logging

import pytest
import requests

###################################################################################


@pytest.mark.parametrize(
    ("protocol", "server"),
    [
        ("udp", "dns.google"),
        ("tcp", "dns.google"),
        ("doh", "anycast.uncensoreddns.org"),
        ("doh3", "anycast.uncensoreddns.org"),
        ("doq", "anycast.uncensoreddns.org"),
    ],
)
def test_proxy(dns_exporter_example_config, proxy_server, protocol, server):
    """Test proxy functionality for all protocols."""
    r = requests.get(
        "http://127.0.0.1:25353/query",
        params={
            "query_name": "example.com",
            "server": server,
            "family": "ipv4",
            "protocol": protocol,
            "proxy": "socks5://127.0.0.1:1080",
        },
    )
    assert 'proxy="socks5://127.0.0.1:1080"' in r.text
    assert f'server="{protocol}://{server}:' in r.text


###################################################################################


@pytest.mark.parametrize("protocol", ["udp", "tcp", "doh", "doh3", "doq"])
def test_proxy_fail(dns_exporter_example_config, proxy_server, protocol):
    """Test proxy failure for all protocols."""
    r = requests.get(
        "http://127.0.0.1:25353/query",
        params={
            "query_name": "example.com",
            "server": "dns.google",
            "family": "ipv4",
            "protocol": protocol,
            "proxy": "socks5://127.0.0.1:1081",
        },
    )
    assert "dnsexp_dns_query_success 0.0" in r.text


###################################################################################


def test_proxy_without_scheme(dns_exporter_example_config):
    """Trigger an invalid_request_proxy failure by providing a proxy without a scheme."""
    r = requests.get(
        "http://127.0.0.1:25353/query",
        params={
            "query_name": "example.com",
            "server": "dns.google",
            "proxy": "127.0.0.1:1080",
        },
    )
    assert r.status_code == 200, "non-200 returncode"


def test_proxy_unknown_scheme(dns_exporter_example_config):
    """Trigger an invalid_request_proxy failure by providing a proxy with an unknown scheme."""
    r = requests.get(
        "http://127.0.0.1:25353/query",
        params={
            "query_name": "example.com",
            "server": "dns.google",
            "proxy": "foo://127.0.0.1:1080",
        },
    )
    assert r.status_code == 200, "non-200 returncode"


def test_exporter_modules_none(caplog, exporter):
    """Make sure calling configure() with modules=None works."""
    caplog.clear()
    caplog.set_level(logging.DEBUG)
    exporter.configure(modules=None)
    assert "0 module(s) loaded OK, total modules: 0." in caplog.text


def test_proxy_module(dns_exporter_example_config, proxy_server):
    """Test proxy functionality for udp protocol."""
    r = requests.get(
        "http://127.0.0.1:25353/query",
        params={
            "query_name": "example.com",
            "server": "dns.google",
            "family": "ipv4",
            "protocol": "udp",
            "module": "socks1080",
        },
    )
    assert 'proxy="socks5://127.0.0.1:1080"' in r.text
    assert 'server="udp://dns.google:53"' in r.text

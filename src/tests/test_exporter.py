# type: ignore
"""dns_exporter test suite extravaganza."""
import logging

import cryptography
import pytest
import requests

from dns_exporter.config import RFValidator, RRValidator
from dns_exporter.entrypoint import main
from dns_exporter.exporter import DNSExporter
from dns_exporter.version import __version__


class TestExporter(DNSExporter):
    """This is just here so tests can mess around with cls.modules without changing the global DNSExporter class."""

    __test__ = False


def test_main_no_config(dns_exporter_main_no_config_no_debug, caplog):
    caplog.clear()
    caplog.set_level(logging.DEBUG)
    r = requests.get(
        "http://127.0.0.1:35353/query",
        params={
            "server": "dns.google",
            "query_name": "example.com",
            "family": "ipv4",
        },
    )
    assert r.status_code == 200, "non-200 returncode"
    assert 'dnsexp_failures_total{reason="timeout"} 0.0' in r.text


def test_timeout(dns_exporter_main_no_config_no_debug):
    r = requests.get(
        "http://127.0.0.1:35353/query",
        params={
            "server": "dns.google",
            "query_name": "example.com",
            "family": "ipv4",
            "timeout": 0.001,
        },
    )
    assert r.status_code == 200, "non-200 returncode"
    assert 'dnsexp_failures_total{reason="timeout"} 1.0' in r.text


def test_noconfig_server(dns_exporter_no_main_no_config):
    """Test basic lookup functionality."""
    r = requests.get(
        "http://127.0.0.1:45353/query",
        params={
            "query_name": "example.com",
            "server": "dns.google",
            "family": "ipv4",
        },
    )
    assert r.status_code == 200, "basic noconfig lookup failed with non-200 returncode"


def test_config_server(dns_exporter_example_config):
    """Test basic lookup functionality."""
    r = requests.get(
        "http://127.0.0.1:25353/query",
        params={
            "query_name": "example.com",
            "server": "dns.google",
            "family": "ipv4",
        },
    )
    assert r.status_code == 200, "basic lookup failed with non-200 returncode"


def test_config_endpoint(dns_exporter_example_config):
    """Test the /config endpoint."""
    r = requests.get(
        "http://127.0.0.1:25353/config",
        params={
            "server": "dns.google",
            "query_name": "example.com",
        },
    )
    config = r.json()
    assert config["server"] == "udp://dns.google:53"
    assert config["query_name"] == "example.com"

    r = requests.get(
        "http://127.0.0.1:25353/config",
        params={
            "module": "cf_doh",
        },
    )
    config = r.json()
    assert config["protocol"] == "doh"
    assert config["server"] == "https://1dot1dot1dot1.cloudflare-dns.com:443/dns-query"
    assert config["query_name"] == "bornhack.dk"
    assert config["query_type"] == "NS"
    assert config["validate_response_flags"]["fail_if_any_absent"] == ["AD"]


def test_invalid_qs_ip(dns_exporter_example_config):
    r = requests.get(
        "http://127.0.0.1:25353/query",
        params={
            "server": "dns.google",
            "query_name": "example.com",
            "ip": "notanip",
        },
    )
    assert r.status_code == 200, "non-200 returncode"
    assert 'dnsexp_failures_total{reason="invalid_request_ip"} 1.0' in r.text


def test_invalid_configfile_ip(caplog):
    caplog.clear()
    exporter = TestExporter
    exporter.configure(modules={"test": {"ip": "notanip"}})
    assert "Unable to parse IP address notanip" in caplog.text


def test_missing_query_name(dns_exporter_example_config):
    r = requests.get(
        "http://127.0.0.1:25353/query",
        params={
            "server": "dns.google",
        },
    )
    assert r.status_code == 200, "non-200 returncode"
    assert 'dnsexp_failures_total{reason="invalid_request_query_name"} 1.0' in r.text


def test_missing_server(dns_exporter_example_config):
    r = requests.get(
        "http://127.0.0.1:25353/query",
        params={
            "query_name": "example.com",
        },
    )
    assert r.status_code == 200, "non-200 returncode"
    assert 'dnsexp_failures_total{reason="invalid_request_server"} 1.0' in r.text


def test_undefined_module(dns_exporter_example_config, caplog):
    r = requests.get(
        "http://127.0.0.1:25353/query",
        params={
            "module": "notamodule",
        },
    )
    assert r.status_code == 200, "non-200 returncode"
    assert 'dnsexp_failures_total{reason="invalid_request_module"} 1.0' in r.text


def test_unknown_config_key(dns_exporter_example_config, caplog):
    r = requests.get(
        "http://127.0.0.1:25353/query",
        params={
            "server": "dns.google",
            "foo": "bar",
        },
    )
    assert r.status_code == 200, "non-200 returncode"
    assert 'dnsexp_failures_total{reason="invalid_request_config"} 1.0' in r.text


def test_ip_family_conflict(dns_exporter_example_config, caplog):
    r = requests.get(
        "http://127.0.0.1:25353/query",
        params={
            "server": "dns.google",
            "query_name": "example.com",
            "family": "ipv6",
            "ip": "192.0.2.53",
        },
    )
    assert r.status_code == 200, "non-200 returncode"
    assert 'dnsexp_failures_total{reason="invalid_request_ip"} 1.0' in r.text


def test_ip_conflict(dns_exporter_example_config, caplog):
    r = requests.get(
        "http://127.0.0.1:25353/query",
        params={
            "server": "192.0.2.1",
            "query_name": "example.com",
            "ip": "192.0.2.53",
            "family": "ipv4",
        },
    )
    assert r.status_code == 200, "non-200 returncode"
    assert 'dnsexp_failures_total{reason="invalid_request_ip"} 1.0' in r.text


def test_ip_and_hostname(dns_exporter_example_config, caplog):
    caplog.clear()
    caplog.set_level(logging.DEBUG)
    r = requests.get(
        "http://127.0.0.1:25353/query",
        params={
            "server": "dns.google",
            "query_name": "example.com",
            "ip": "8.8.4.4",
            "family": "ipv4",
        },
    )
    assert r.status_code == 200, "non-200 returncode"
    assert (
        "Using server IP 8.8.4.4 (from config) for the DNS server connection"
        in caplog.text
    )


def test_unresolvable_server(dns_exporter_example_config, caplog):
    caplog.clear()
    caplog.set_level(logging.DEBUG)
    r = requests.get(
        "http://127.0.0.1:25353/query",
        params={
            "server": "notaserver.example",
            "query_name": "example.com",
        },
    )
    assert r.status_code == 200, "non-200 returncode"
    assert 'dnsexp_failures_total{reason="invalid_request_server"} 1.0' in r.text


def test_ipv6_family(dns_exporter_example_config, caplog):
    caplog.clear()
    caplog.set_level(logging.DEBUG)
    r = requests.get(
        "http://127.0.0.1:25353/query",
        params={
            "server": "dns.google",
            "query_name": "example.com",
            "ip": "2001:4860:4860::8888",
            "timeout": 0.1,
        },
    )
    assert r.status_code == 200, "non-200 returncode"
    assert (
        "Using server IP 2001:4860:4860::8888 (from config) for the DNS server connection"
        in caplog.text
    )


def test_ipv7_family(dns_exporter_example_config, caplog):
    caplog.clear()
    caplog.set_level(logging.DEBUG)
    r = requests.get(
        "http://127.0.0.1:25353/query",
        params={
            "server": "dns.google",
            "query_name": "example.com",
            "family": "ipv7",
        },
    )
    assert r.status_code == 200, "non-200 returncode"
    assert 'dnsexp_failures_total{reason="invalid_request_family"} 1.0' in r.text


# run this test last
@pytest.mark.order(-1)
def test_internal_metrics(dns_exporter_example_config, caplog):
    caplog.clear()
    caplog.set_level(logging.DEBUG)
    r = requests.get(
        "http://127.0.0.1:25353/metrics",
    )
    assert r.status_code == 200, "non-200 returncode"
    assert f'dnsexp_build_version_info{{version="{__version__}"}} 1.0' in r.text
    assert "Returning exporter metrics for request to /metrics" in caplog.text
    for metric in """dnsexp_http_requests_total{path="/notfound"} 1.0
dnsexp_http_requests_total{path="/query"} 38.0
dnsexp_http_requests_total{path="/config"} 2.0
dnsexp_http_requests_total{path="/"} 1.0
dnsexp_http_requests_total{path="/metrics"} 1.0
dnsexp_http_responses_total{path="/notfound",response_code="404"} 1.0
dnsexp_http_responses_total{path="/query",response_code="200"} 38.0
dnsexp_http_responses_total{path="/",response_code="200"} 1.0
dnsexp_dns_queries_total 28.0
dnsexp_dns_responsetime_seconds_bucket{additional="0",answer="1",authority="0",family="ipv4",flags="QR RA RD",ip="8.8.4.4",le="0.005",nsid="no_nsid",opcode="QUERY",port="53",protocol="udp",query_name="example.com",query_type="A",rcode="NOERROR",server="udp://dns.google:53",transport="UDP"}
dnsexp_scrape_failures_total{reason="timeout"} 1.0
dnsexp_scrape_failures_total{reason="invalid_response_flags"} 6.0
dnsexp_scrape_failures_total{reason="invalid_response_answer_rrs"} 3.0
dnsexp_scrape_failures_total{reason="invalid_response_rcode"} 1.0
dnsexp_scrape_failures_total{reason="invalid_response_additional_rrs"} 1.0
dnsexp_scrape_failures_total{reason="invalid_request_server"} 2.0
dnsexp_scrape_failures_total{reason="invalid_request_module"} 1.0
dnsexp_scrape_failures_total{reason="invalid_request_config"} 2.0
dnsexp_scrape_failures_total{reason="invalid_request_ip"} 3.0
dnsexp_scrape_failures_total{reason="invalid_request_family"} 1.0
dnsexp_scrape_failures_total{reason="other_failure"} 1.0
dnsexp_scrape_failures_total{reason="invalid_request_query_name"} 1.0""".split(
        "\n"
    ):
        assert metric in r.text


def test_index(dns_exporter_example_config, caplog):
    caplog.clear()
    caplog.set_level(logging.DEBUG)
    r = requests.get(
        "http://127.0.0.1:25353/",
    )
    assert r.status_code == 200, "non-200 returncode"
    assert "DNS Exporter" in r.text
    assert "Returning index page for request to /" in caplog.text


def test_404(dns_exporter_example_config, caplog):
    caplog.clear()
    caplog.set_level(logging.DEBUG)
    r = requests.get(
        "http://127.0.0.1:25353/notfound",
    )
    assert r.status_code == 404, "non-404 returncode"
    assert "404 not found" in r.text
    assert "Unknown endpoint '/notfound' returning 404" in caplog.text


def test_tcp(dns_exporter_example_config, caplog):
    caplog.clear()
    caplog.set_level(logging.DEBUG)
    r = requests.get(
        "http://127.0.0.1:25353/query",
        params={
            "server": "dns.google",
            "query_name": "example.com",
            "protocol": "tcp",
            "family": "ipv4",
        },
    )
    assert r.status_code == 200, "non-200 returncode"
    assert 'transport="TCP"' in r.text
    assert "Protocol tcp got a DNS query response over TCP" in caplog.text


def test_udptcp(dns_exporter_example_config, caplog):
    caplog.clear()
    caplog.set_level(logging.DEBUG)
    r = requests.get(
        "http://127.0.0.1:25353/query",
        params={
            "server": "dns.google",
            "query_name": "example.com",
            "protocol": "udptcp",
            "family": "ipv4",
        },
    )
    assert r.status_code == 200, "non-200 returncode"
    assert 'transport="UDP"' in r.text
    assert "Protocol udptcp got a DNS query response over UDP" in caplog.text


def test_dot(dns_exporter_example_config, caplog):
    caplog.clear()
    caplog.set_level(logging.DEBUG)
    r = requests.get(
        "http://127.0.0.1:25353/query",
        params={
            "server": "dns.google",
            "query_name": "example.com",
            "protocol": "dot",
            "family": "ipv4",
        },
    )
    assert r.status_code == 200, "non-200 returncode"
    assert 'transport="TCP"' in r.text
    assert "Protocol dot got a DNS query response over TCP" in caplog.text


def test_doh(dns_exporter_example_config, caplog):
    caplog.clear()
    caplog.set_level(logging.DEBUG)
    r = requests.get(
        "http://127.0.0.1:25353/query",
        params={
            "server": "dns.google",
            "query_name": "example.com",
            "protocol": "doh",
            "family": "ipv4",
        },
    )
    assert r.status_code == 200, "non-200 returncode"
    assert 'transport="TCP"' in r.text
    assert 'protocol="doh"' in r.text
    assert "Protocol doh got a DNS query response over TCP" in caplog.text


def test_doq(dns_exporter_example_config, caplog):
    # this silences the warning for py3.12
    # with pytest.deprecated_call():
    # this silences the warning for py3.9-py3.11 but not for py3.12
    with pytest.warns(cryptography.utils.CryptographyDeprecationWarning):
        caplog.clear()
        caplog.set_level(logging.DEBUG)
        r = requests.get(
            "http://127.0.0.1:25353/query",
            params={
                "server": "quic://dns-unfiltered.adguard.com",
                "query_name": "example.com",
                "protocol": "doq",
                "family": "ipv4",
            },
        )
        assert r.status_code == 200, "non-200 returncode"
        assert 'transport="UDP"' in r.text
        assert 'protocol="doq"' in r.text
        assert "Protocol doq got a DNS query response over UDP" in caplog.text


def test_validate_rcode(dns_exporter_example_config, caplog):
    r = requests.get(
        "http://127.0.0.1:25353/query",
        params={
            "server": "dns.google",
            "query_name": "404.example.com",
            "family": "ipv4",
        },
    )
    assert r.status_code == 200, "non-200 returncode"
    assert 'dnsexp_failures_total{reason="invalid_response_rcode"} 1.0' in r.text
    assert 'rcode="NXDOMAIN"' in r.text


def test_validate_flags_fail_if_any_absent(dns_exporter_example_config, caplog):
    r = requests.get(
        "http://127.0.0.1:25353/query",
        params={
            "server": "dns.google",
            "query_name": "google.com",
            "family": "ipv4",
            "module": "has_ad",
        },
    )
    assert r.status_code == 200, "non-200 returncode"
    assert 'dnsexp_failures_total{reason="invalid_response_flags"} 1.0' in r.text


def test_validate_flags_fail_if_any_present(dns_exporter_example_config, caplog):
    r = requests.get(
        "http://127.0.0.1:25353/query",
        params={
            "server": "dns.google",
            "query_name": "ripe.net",
            "family": "ipv4",
            "module": "has_no_ad",
        },
    )
    assert r.status_code == 200, "non-200 returncode"
    assert 'dnsexp_failures_total{reason="invalid_response_flags"} 1.0' in r.text


def test_validate_flags_fail_if_all_present(dns_exporter_example_config, caplog):
    r = requests.get(
        "http://127.0.0.1:25353/query",
        params={
            "server": "dns.google",
            "query_name": "google.com",
            "family": "ipv4",
            "module": "fail_auth",
        },
    )
    assert r.status_code == 200, "non-200 returncode"
    assert 'dnsexp_failures_total{reason="invalid_response_flags"} 1.0' in r.text


def test_validate_flags_fail_if_all_absent(dns_exporter_example_config, caplog):
    r = requests.get(
        "http://127.0.0.1:25353/query",
        params={
            "server": "dns.google",
            "query_name": "google.com",
            "family": "ipv4",
            "module": "fail_recursive",
        },
    )
    assert r.status_code == 200, "non-200 returncode"
    assert 'dnsexp_failures_total{reason="invalid_response_flags"} 1.0' in r.text


def test_validate_flags_fail_if_all_present_2(dns_exporter_example_config, caplog):
    r = requests.get(
        "http://127.0.0.1:25353/query",
        params={
            "server": "dns.google",
            "query_name": "google.com",
            "family": "ipv4",
            "module": "fail_auth",
        },
    )
    assert r.status_code == 200, "non-200 returncode"
    assert 'dnsexp_failures_total{reason="invalid_response_flags"} 1.0' in r.text


def test_validate_flags_fail_if_all_absent_2(dns_exporter_example_config, caplog):
    r = requests.get(
        "http://127.0.0.1:25353/query",
        params={
            "server": "dns.google",
            "query_name": "google.com",
            "family": "ipv4",
            "module": "fail_recursive",
        },
    )
    assert r.status_code == 200, "non-200 returncode"
    assert 'dnsexp_failures_total{reason="invalid_response_flags"} 1.0' in r.text


def test_validate_flags_fail_if_all_present_3(dns_exporter_example_config, caplog):
    r = requests.get(
        "http://127.0.0.1:25353/query",
        params={
            "server": "k.root-servers.net",
            "query_name": ".",
            "query_type": "NS",
            "family": "ipv4",
            "module": "fail_recursive",
        },
    )
    assert r.status_code == 200, "non-200 returncode"


def test_validate_flags_fail_if_all_absent_3(dns_exporter_example_config, caplog):
    r = requests.get(
        "http://127.0.0.1:25353/query",
        params={
            "server": "k.root-servers.net",
            "query_name": ".",
            "family": "ipv4",
            "module": "fail_auth",
        },
    )
    assert r.status_code == 200, "non-200 returncode"


def test_validate_rr_fail_if_matches_regexp(dns_exporter_example_config, caplog):
    r = requests.get(
        "http://127.0.0.1:25353/query",
        params={
            "server": "k.root-servers.net",
            "query_name": ".",
            "family": "ipv4",
            "query_type": "NS",
            "module": "fail_auth_k_root",
        },
    )
    assert r.status_code == 200, "non-200 returncode"
    assert 'dnsexp_failures_total{reason="invalid_response_answer_rrs"} 1.0' in r.text


def test_validate_rrs_fail_if_all_match_regexp(dns_exporter_example_config, caplog):
    r = requests.get(
        "http://127.0.0.1:25353/query",
        params={
            "server": "k.root-servers.net",
            "query_name": ".",
            "family": "ipv4",
            "query_type": "NS",
            "module": "fail_additional_root",
        },
    )
    assert r.status_code == 200, "non-200 returncode"
    assert (
        'dnsexp_failures_total{reason="invalid_response_additional_rrs"} 1.0' in r.text
    )


def test_validate_rrs_fail_if_all_match_regexp_2(dns_exporter_example_config, caplog):
    r = requests.get(
        "http://127.0.0.1:25353/query",
        params={
            "server": "k.root-servers.net",
            "query_name": "example.com",
            "family": "ipv4",
            "query_type": "NS",
            "module": "fail_additional_root",
        },
    )
    assert r.status_code == 200, "non-200 returncode"


def test_validate_rrs_fail_if_not_matches_regexp(dns_exporter_example_config, caplog):
    r = requests.get(
        "http://127.0.0.1:25353/query",
        params={
            "server": "dns.google",
            "query_name": "example.com",
            "family": "ipv4",
            "query_type": "NS",
            "module": "fail_answer_root",
        },
    )
    assert r.status_code == 200, "non-200 returncode"
    assert 'dnsexp_failures_total{reason="invalid_response_answer_rrs"} 1.0' in r.text


def test_validate_rrs_fail_if_none_matches_regexp(dns_exporter_example_config, caplog):
    r = requests.get(
        "http://127.0.0.1:25353/query",
        params={
            "server": "dns.google",
            "query_name": "example.com",
            "family": "ipv4",
            "query_type": "NS",
            "module": "fail_answer_root_none",
        },
    )
    assert r.status_code == 200, "non-200 returncode"
    assert 'dnsexp_failures_total{reason="invalid_response_answer_rrs"} 1.0' in r.text


def test_validate_rrs_fail_if_none_matches_regexp_2(
    dns_exporter_example_config, caplog
):
    r = requests.get(
        "http://127.0.0.1:25353/query",
        params={
            "server": "dns.google",
            "query_name": ".",
            "family": "ipv4",
            "query_type": "NS",
            "module": "fail_answer_root_none",
        },
    )
    assert r.status_code == 200, "non-200 returncode"


def test_edns_pad(dns_exporter_example_config, caplog):
    r = requests.get(
        "http://127.0.0.1:25353/query",
        params={
            "server": "dns.google",
            "query_name": "example.com",
            "family": "ipv4",
            "edns_pad": 20,
        },
    )
    assert r.status_code == 200, "non-200 returncode"


def test_no_edns(dns_exporter_example_config, caplog):
    r = requests.get(
        "http://127.0.0.1:25353/query",
        params={
            "server": "dns.google",
            "query_name": "example.com",
            "family": "ipv4",
            "ip": "8.8.4.4",
            "edns": False,
        },
    )
    assert r.status_code == 200, "non-200 returncode"


def test_version(capsys):
    with pytest.raises(SystemExit) as E:
        main(["-v"])
    assert E.type == SystemExit, f"Exit was not as expected, it was {E.type}"
    captured = capsys.readouterr()
    assert __version__ in captured.out


def test_broken_yaml_config(caplog, dns_exporter_broken_yaml_configfile):
    caplog.clear()
    caplog.set_level(logging.DEBUG)
    with pytest.raises(SystemExit) as E:
        main(["-c", str(dns_exporter_broken_yaml_configfile)])
    assert E.type == SystemExit, f"Exit was not as expected, it was {E.type}"
    assert "Unable to parse YAML config file" in caplog.text
    assert E.value.code == 1, "Exit code not 1 as expected with broken yaml config"


def test_empty_yaml_config(caplog, dns_exporter_empty_yaml_configfile):
    caplog.clear()
    caplog.set_level(logging.DEBUG)
    with pytest.raises(SystemExit) as E:
        main(["-c", str(dns_exporter_empty_yaml_configfile)])
    assert E.type == SystemExit, f"Exit was not as expected, it was {E.type}"
    assert "Invalid config file" in caplog.text
    assert E.value.code == 1, "Exit code not 1 as expected with empty yaml config"


def test_invalid_yaml_config(caplog, dns_exporter_invalid_yaml_configfile):
    caplog.clear()
    caplog.set_level(logging.DEBUG)
    with pytest.raises(SystemExit) as E:
        main(["-c", str(dns_exporter_invalid_yaml_configfile)])
    assert E.type == SystemExit, f"Exit was not as expected, it was {E.type}"
    assert "An error occurred while configuring dns_exporter" in caplog.text
    assert E.value.code == 1, "Exit code not 1 as expected with invalid yaml config"


def test_configure(caplog):
    caplog.clear()
    caplog.set_level(logging.DEBUG)
    exporter = TestExporter
    exporter.modules = {}
    exporter.configure(modules={"test": {"ip": "127.0.0.1"}})
    assert len(exporter.modules) == 1
    assert "1 module(s) loaded OK, total modules: 1." in caplog.text


def test_invalid_integer(dns_exporter_example_config, caplog):
    caplog.clear()
    caplog.set_level(logging.DEBUG)
    r = requests.get(
        "http://127.0.0.1:25353/query",
        params={
            "server": "dns.google",
            "query_name": "example.com",
            "edns_bufsize": "foo",
        },
    )
    assert r.status_code == 200, "non-200 returncode"
    assert "Unable to parse integer for key edns_bufsize: foo" in caplog.text
    assert "ValueError: invalid literal for int() with base 10: 'foo'" in caplog.text
    assert 'dnsexp_failures_total{reason="invalid_request_config"} 1.0' in r.text


def test_configure_rrvalidator(caplog):
    caplog.clear()
    caplog.set_level(logging.DEBUG)
    exporter = TestExporter
    exporter.modules = {}
    exporter.configure(
        modules={
            "test": {"validate_answer_rrs": RRValidator.create({"fail_if_count_eq": 4})}
        }
    )
    assert len(exporter.modules) == 1
    assert "1 module(s) loaded OK, total modules: 1." in caplog.text


def test_configure_rfvalidator(caplog):
    caplog.clear()
    caplog.set_level(logging.DEBUG)
    exporter = TestExporter
    exporter.modules = {}
    exporter.configure(
        modules={
            "test": {
                "validate_response_flags": RFValidator.create(
                    {"fail_if_any_absent": ["peace", "love"]}
                )
            }
        }
    )
    assert len(exporter.modules) == 1
    assert "1 module(s) loaded OK, total modules: 1." in caplog.text


def test_configure_bad_module(caplog):
    caplog.clear()
    caplog.set_level(logging.DEBUG)
    exporter = TestExporter
    exporter.modules = {}
    exporter.configure(modules={"test": {"query_class": "OUT"}})
    assert len(exporter.modules) == 0
    assert (
        "Invalid value found while building config {'query_class': 'OUT'}"
        in caplog.text
    )

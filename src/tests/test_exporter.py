"""dnsexporter tests for the exporter module."""

import logging

import pytest
import requests

from dns_exporter.config import RFValidator, RRValidator
from dns_exporter.entrypoint import main


def test_main_no_config(dns_exporter_main_no_config_no_debug):
    """Test basic functionality on a debug-less instance with no modules loaded."""
    r = requests.get(
        "http://127.0.0.1:35353/query",
        params={
            "server": "dns.google",
            "query_name": "example.com",
            "family": "ipv4",
        },
    )
    assert r.status_code == 200, "non-200 returncode"
    assert "dnsexp_dns_query_success 1.0" in r.text


def test_noconfig_server(dns_exporter_no_main_no_config):
    """Test basic lookup functionality on an instance with debug enabled and no modules loaded."""
    r = requests.get(
        "http://127.0.0.1:45353/query",
        params={
            "query_name": "example.com",
            "server": "dns.google",
            "family": "ipv4",
        },
    )
    assert "dnsexp_dns_query_success 1.0" in r.text


def test_config_server(dns_exporter_example_config):
    """Test basic lookup functionality on an instance with modules loaded."""
    r = requests.get(
        "http://127.0.0.1:25353/query",
        params={
            "query_name": "example.com",
            "server": "dns.google",
            "family": "ipv4",
        },
    )
    assert "dnsexp_dns_query_success 1.0" in r.text


def test_config_endpoint(dns_exporter_example_config):
    """Test the /config endpoint."""
    r = requests.get(
        "http://127.0.0.1:25353/config",
        params={
            "server": "dns.google",
            "query_name": "example.com",
            "protocol": "tcp",
            "proxy": "socks5://127.0.0.1:1081",
        },
    )
    config = r.json()
    assert config["server"] == "tcp://dns.google:53"
    assert config["query_name"] == "example.com"


def test_config_endpoint_2(dns_exporter_example_config):
    """Test the /config endpoint some more."""
    r = requests.get(
        "http://127.0.0.1:25353/config",
        params={
            "module": "cf_doh",
        },
    )
    config = r.json()
    assert config["protocol"] == "doh"
    assert config["server"] == "doh://1dot1dot1dot1.cloudflare-dns.com:443/dns-query"
    assert config["query_name"] == "bornhack.dk"
    assert config["query_type"] == "NS"
    assert config["validate_response_flags"]["fail_if_any_absent"] == ["AD"]


def test_invalid_qs_ip(dns_exporter_example_config):
    """Trigger an invalid_request_ip failure."""
    r = requests.get(
        "http://127.0.0.1:25353/query",
        params={
            "server": "dns.google",
            "query_name": "example.com",
            "ip": "notanip",
        },
    )
    assert "dnsexp_dns_query_success 0.0" in r.text


def test_invalid_configfile_ip(caplog, exporter):
    """Make sure a message is logged when parsing an IP fails."""
    caplog.clear()
    exporter.configure(modules={"test": {"ip": "notanip"}})
    assert "Unable to parse IP address notanip" in caplog.text


def test_missing_query_name(dns_exporter_example_config):
    """Trigger an invalid_request_query_name failure."""
    r = requests.get(
        "http://127.0.0.1:25353/query",
        params={
            "server": "dns.google",
        },
    )
    assert "dnsexp_dns_query_success 0.0" in r.text


def test_missing_server(dns_exporter_example_config):
    """Trigger an invalid_request_server failure."""
    r = requests.get(
        "http://127.0.0.1:25353/query",
        params={
            "query_name": "example.com",
        },
    )
    assert "dnsexp_dns_query_success 0.0" in r.text


def test_undefined_module(dns_exporter_example_config, caplog):
    """Trigger an invalid_request_module failure."""
    r = requests.get(
        "http://127.0.0.1:25353/query",
        params={
            "module": "notamodule",
        },
    )
    assert "dnsexp_dns_query_success 0.0" in r.text


def test_unknown_config_key(dns_exporter_example_config, caplog):
    """Trigger an invalid_request_config failure by providing an unknown key."""
    r = requests.get(
        "http://127.0.0.1:25353/query",
        params={
            "server": "dns.google",
            "foo": "bar",
        },
    )
    assert "dnsexp_dns_query_success 0.0" in r.text


def test_ip_family_conflict(dns_exporter_example_config, caplog):
    """Trigger an invalid_request_ip failure by providing a v4 ip and v6 family."""
    r = requests.get(
        "http://127.0.0.1:25353/query",
        params={
            "server": "dns.google",
            "query_name": "example.com",
            "family": "ipv6",
            "ip": "192.0.2.53",
        },
    )
    assert "dnsexp_dns_query_success 0.0" in r.text


def test_ip_conflict(dns_exporter_example_config, caplog):
    """Trigger an invalid_request_ip failure by providing a server ip and a conflicting ip."""
    r = requests.get(
        "http://127.0.0.1:25353/query",
        params={
            "server": "192.0.2.1",
            "query_name": "example.com",
            "ip": "192.0.2.53",
            "family": "ipv4",
        },
    )
    assert "dnsexp_dns_query_success 0.0" in r.text


def test_ip_and_hostname(dns_exporter_example_config, caplog):
    """Make sure using an IP and hostname results in the IP overriding the server hostname DNS lookup."""
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
    assert "Using server IP 8.8.4.4 (from config) for the DNS server connection" in caplog.text
    assert "dnsexp_dns_query_success 1.0" in r.text


def test_unresolvable_server(dns_exporter_example_config, caplog):
    """Trigger an invalid_request_server failure by providing an unresolvable server hostname."""
    caplog.clear()
    caplog.set_level(logging.DEBUG)
    r = requests.get(
        "http://127.0.0.1:25353/query",
        params={
            "server": "notaserver.example",
            "query_name": "example.com",
        },
    )
    assert "dnsexp_dns_query_success 0.0" in r.text


def test_ipv6_family(dns_exporter_example_config, caplog):
    """Test IP override for ipv6 family."""
    caplog.clear()
    caplog.set_level(logging.DEBUG)
    requests.get(
        "http://127.0.0.1:25353/query",
        params={
            "server": "dns.google",
            "query_name": "example.com",
            "ip": "2001:4860:4860::8888",
            "timeout": 0.1,
        },
    )
    assert "Using server IP 2001:4860:4860::8888 (from config) for the DNS server connection" in caplog.text


def test_ipv7_family(dns_exporter_example_config, caplog):
    """Trigger an invalid_request_family failure with ipv7."""
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
    assert "dnsexp_dns_query_success 0.0" in r.text


def test_index(dns_exporter_example_config, caplog):
    """Test the index page served at /."""
    caplog.clear()
    caplog.set_level(logging.DEBUG)
    r = requests.get(
        "http://127.0.0.1:25353/",
    )
    assert r.status_code == 200, "non-200 returncode"
    assert "DNS Exporter" in r.text
    assert "Returning index page for request to /" in caplog.text


def test_404(dns_exporter_example_config, caplog):
    """Make sure a 404 is returned from unknown endpoints."""
    caplog.clear()
    caplog.set_level(logging.DEBUG)
    r = requests.get(
        "http://127.0.0.1:25353/notfound",
    )
    assert r.status_code == 404, "non-404 returncode"
    assert "404 not found" in r.text
    assert "Unknown endpoint '/notfound' returning 404" in caplog.text


def test_tcp(dns_exporter_example_config, caplog):
    """Test basic tcp protocol functionality."""
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
    assert 'transport="TCP"' in r.text
    assert "Protocol tcp got a DNS query response over TCP" in caplog.text
    assert "dnsexp_dns_query_success 1.0" in r.text


def test_udptcp(dns_exporter_example_config, caplog):
    """Test basic udptcp functionality."""
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
    assert 'transport="UDP"' in r.text
    assert "Protocol udptcp got a DNS query response over UDP" in caplog.text
    assert "dnsexp_dns_query_success 1.0" in r.text


def test_dot(dns_exporter_example_config, caplog):
    """Test basic DoT functionality."""
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
    assert 'transport="TCP"' in r.text
    assert "Protocol dot got a DNS query response over TCP" in caplog.text
    assert "dnsexp_dns_query_success 1.0" in r.text


def test_doh(dns_exporter_example_config, caplog):
    """Test basic DoH functionality."""
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
    assert 'transport="TCP"' in r.text
    assert 'protocol="doh"' in r.text
    assert "Protocol doh got a DNS query response over TCP" in caplog.text
    assert "dnsexp_dns_query_success 1.0" in r.text


def test_doh3(dns_exporter_example_config, caplog):
    """Test basic DoH3 functionality."""
    caplog.clear()
    caplog.set_level(logging.DEBUG)
    r = requests.get(
        "http://127.0.0.1:25353/query",
        params={
            "server": "dns-unfiltered.adguard.com",
            "query_name": "example.com",
            "protocol": "doh3",
            "family": "ipv4",
        },
    )
    assert 'transport="QUIC"' in r.text
    assert 'protocol="doh3"' in r.text
    assert "Protocol doh3 got a DNS query response over QUIC" in caplog.text
    assert "dnsexp_dns_query_success 1.0" in r.text


def test_doq(dns_exporter_example_config, caplog, recwarn):
    """Test basic DoQ functionality."""
    caplog.clear()
    caplog.set_level(logging.DEBUG)
    r = requests.get(
        "http://127.0.0.1:25353/query",
        params={
            "server": "dns-unfiltered.adguard.com",
            "query_name": "example.com",
            "protocol": "doq",
            "family": "ipv4",
        },
    )
    assert 'transport="QUIC"' in r.text
    assert 'protocol="doq"' in r.text
    assert "Protocol doq got a DNS query response over QUIC" in caplog.text
    assert "dnsexp_dns_query_success 1.0" in r.text


def test_validate_rcode(dns_exporter_example_config, caplog):
    """Trigger an invalid_response_rcode error by asking for an NXDOMAIN."""
    r = requests.get(
        "http://127.0.0.1:25353/query",
        params={
            "server": "dns.google",
            "query_name": "404.example.com",
            "family": "ipv4",
        },
    )
    assert 'rcode="NXDOMAIN"' in r.text
    assert "dnsexp_dns_query_success 0.0" in r.text


def test_validate_flags_fail_if_any_absent(dns_exporter_example_config, caplog):
    """Trigger an invalid_response_flags failure by checking for AD flag on google.com."""
    r = requests.get(
        "http://127.0.0.1:25353/query",
        params={
            "server": "dns.google",
            "query_name": "google.com",
            "family": "ipv4",
            "module": "has_ad",
        },
    )
    assert "dnsexp_dns_query_success 0.0" in r.text


def test_validate_flags_fail_if_any_present(dns_exporter_example_config, caplog):
    """Trigger an invalid_response_flags failure by checking for no AD flag on ripe.net."""
    r = requests.get(
        "http://127.0.0.1:25353/query",
        params={
            "server": "dns.google",
            "query_name": "ripe.net",
            "family": "ipv4",
            "module": "has_no_ad",
        },
    )
    assert "dnsexp_dns_query_success 0.0" in r.text


def test_validate_flags_fail_if_all_present(dns_exporter_example_config, caplog):
    """Trigger an invalid_response_flags failure by requiring AA flag from a recursor."""
    r = requests.get(
        "http://127.0.0.1:25353/query",
        params={
            "server": "dns.google",
            "query_name": "google.com",
            "family": "ipv4",
            "module": "fail_not_auth",
        },
    )
    assert "dnsexp_dns_query_success 0.0" in r.text


def test_validate_flags_fail_if_all_absent(dns_exporter_example_config, caplog):
    """Trigger an invalid_response_flags failure by asking a recursor and expecting no RA flag."""
    r = requests.get(
        "http://127.0.0.1:25353/query",
        params={
            "server": "dns.google",
            "query_name": "google.com",
            "family": "ipv4",
            "module": "fail_recursive",
        },
    )
    assert "dnsexp_dns_query_success 0.0" in r.text


def test_validate_flags_fail_if_all_present_2(dns_exporter_example_config, caplog):
    """Trigger an invalid_response_flags failure by expecting an AA+AD response from a recursor."""
    r = requests.get(
        "http://127.0.0.1:25353/query",
        params={
            "server": "dns.quad9.net",
            "query_name": "google.com",
            "family": "ipv4",
            "module": "fail_not_auth",
        },
    )
    assert "dnsexp_dns_query_success 0.0" in r.text


def test_validate_flags_fail_if_all_absent_2(dns_exporter_example_config, caplog):
    """Trigger an invalid_response_flags failure by not expecting recursive flags from a recursor."""
    r = requests.get(
        "http://127.0.0.1:25353/query",
        params={
            "server": "dns.google",
            "query_name": "wikipedia.org",
            "family": "ipv4",
            "module": "fail_recursive",
        },
    )
    assert "dnsexp_dns_query_success 0.0" in r.text


def test_validate_flags_fail_if_all_present_3(dns_exporter_example_config, caplog):
    """Test a module using fail_if_all_present without failing by asking an auth and failing on recursive flags."""
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
    assert "dnsexp_dns_query_success 1.0" in r.text


def test_validate_flags_fail_if_all_absent_3(dns_exporter_example_config, caplog):
    """Test a module using fail_if_all_absent without failing by asking a root server for . and failing if AA and AD are missing."""
    r = requests.get(
        "http://127.0.0.1:25353/query",
        params={
            "server": "k.root-servers.net",
            "query_name": ".",
            "family": "ipv4",
            "module": "fail_not_auth",
        },
    )
    assert "dnsexp_dns_query_success 1.0" in r.text


def test_validate_rr_fail_if_matches_regexp(dns_exporter_example_config, caplog):
    """Trigger an invalid_response_answer_rrs failure by asking for root NS and failing on seeing k.root-servers.net. in the result."""
    r = requests.get(
        "http://127.0.0.1:25353/query",
        params={
            "server": "l.root-servers.net",
            "query_name": ".",
            "family": "ipv4",
            "query_type": "NS",
            "module": "fail_auth_k_root",
        },
    )
    assert "dnsexp_dns_query_success 0.0" in r.text


def test_validate_rrs_fail_if_all_match_regexp(dns_exporter_example_config, caplog):
    """Trigger an invalid_response_additional_rrs by asking for root NS and failing on seeing root servers in ADDITIONAL section."""
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
    assert "dnsexp_dns_query_success 0.0" in r.text


def test_validate_rrs_fail_if_all_match_regexp_2(dns_exporter_example_config, caplog):
    """Test a module using fail_if_all_match_regexp without failing."""
    r = requests.get(
        "http://127.0.0.1:25353/query",
        params={
            "server": "dns.google",
            "query_name": "example.com",
            "family": "ipv4",
            "query_type": "NS",
            "module": "fail_additional_root",
        },
    )
    assert "dnsexp_dns_query_success 1.0" in r.text


def test_validate_rrs_fail_if_not_matches_regexp(dns_exporter_example_config, caplog):
    """Trigger an invalid_response_answer_rrs by asking for example.com NS and failing on NOT seeing root servers in ANSWER section."""
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
    assert "dnsexp_dns_query_success 0.0" in r.text


def test_validate_rrs_fail_if_none_matches_regexp(dns_exporter_example_config, caplog):
    """Trigger an invalid_response_answer_rrs by asking for example.com NS and failing on NOT seeing root servers in ANSWER section."""
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
    assert "dnsexp_dns_query_success 0.0" in r.text


def test_validate_rrs_fail_if_none_matches_regexp_2(
    dns_exporter_example_config,
    caplog,
):
    """Trigger an invalid_response_answer_rrs by asking for example.com NS and failing on NOT seeing root servers in ANSWER section."""
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
    assert "dnsexp_dns_query_success 0.0" in r.text


def test_edns_pad(dns_exporter_example_config, caplog):
    """Test edns_pad config setting."""
    r = requests.get(
        "http://127.0.0.1:25353/query",
        params={
            "server": "dns.google",
            "query_name": "example.com",
            "family": "ipv4",
            "edns_pad": 20,
        },
    )
    assert "dnsexp_dns_query_success 1.0" in r.text


def test_no_edns(dns_exporter_example_config, caplog):
    """Test disabling EDNS."""
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
    assert "dnsexp_dns_query_success 1.0" in r.text
    assert 'nsid="no_nsid"' in r.text


def test_broken_yaml_config(caplog, dns_exporter_broken_yaml_configfile):
    """Test loading a broken yaml config file."""
    caplog.clear()
    caplog.set_level(logging.DEBUG)
    with pytest.raises(SystemExit) as e:
        main(["-c", str(dns_exporter_broken_yaml_configfile)])
    assert "Unable to parse YAML config file" in caplog.text
    assert e.value.code == 1, "Exit code not 1 as expected with broken yaml config"


def test_empty_yaml_config(caplog, dns_exporter_empty_yaml_configfile):
    """Test loading an empty yaml config file."""
    caplog.clear()
    caplog.set_level(logging.DEBUG)
    with pytest.raises(SystemExit) as e:
        main(["-c", str(dns_exporter_empty_yaml_configfile)])
    assert "Invalid config file" in caplog.text
    assert e.value.code == 1, "Exit code not 1 as expected with empty yaml config"


def test_invalid_yaml_config(caplog, dns_exporter_invalid_yaml_configfile):
    """Test loading a yaml config file with invalid config options in it."""
    caplog.clear()
    caplog.set_level(logging.DEBUG)
    with pytest.raises(SystemExit) as e:
        main(["-c", str(dns_exporter_invalid_yaml_configfile)])
    assert "An error occurred while configuring dns_exporter" in caplog.text
    assert e.value.code == 1, "Exit code not 1 as expected with invalid yaml config"


def test_configure(caplog, exporter):
    """Test calling configure() on the DNSExporter class."""
    caplog.clear()
    caplog.set_level(logging.DEBUG)
    exporter.modules = {}
    exporter.configure(modules={"test": {"ip": "127.0.0.1"}})
    assert len(exporter.modules) == 1
    assert "1 module(s) loaded OK, total modules: 1." in caplog.text


def test_invalid_integer(dns_exporter_example_config, caplog):
    """Test passing an invalid integer to an integer setting."""
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
    assert "Unable to validate integer for key edns_bufsize" in caplog.text
    assert "ValueError: invalid literal for int() with base 10: 'foo'" in caplog.text
    assert "dnsexp_dns_query_success 0.0" in r.text


def test_configure_rrvalidator(caplog, exporter):
    """Test loading a config which creates an RRValidator object."""
    caplog.clear()
    caplog.set_level(logging.DEBUG)
    exporter.modules = {}
    exporter.configure(
        modules={
            "test": {"validate_answer_rrs": RRValidator.create({"fail_if_count_eq": 4})},
        },
    )
    assert len(exporter.modules) == 1
    assert "1 module(s) loaded OK, total modules: 1." in caplog.text


def test_configure_rfvalidator(caplog, exporter):
    """Test loading a config which creates an RFValidator object."""
    caplog.clear()
    caplog.set_level(logging.DEBUG)
    exporter.modules = {}
    exporter.configure(
        modules={
            "test": {
                "validate_response_flags": RFValidator.create(
                    {"fail_if_any_absent": ["peace", "love"]},
                ),
            },
        },
    )
    assert len(exporter.modules) == 1
    assert "1 module(s) loaded OK, total modules: 1." in caplog.text


def test_configure_bad_module(caplog, exporter):
    """Test the configure() method with an invalid module."""
    caplog.clear()
    caplog.set_level(logging.DEBUG)
    exporter.modules = {}
    exporter.configure(modules={"test": {"query_class": "OUT"}})
    assert len(exporter.modules) == 0
    assert "Invalid value found while building config {'query_class': 'OUT'}" in caplog.text


def test_catch_unknown_exception(
    dns_exporter_example_config,
    mock_collect_zerodivisionerror,
):
    """Trigger an other_failure failure by raising a ValueError from get_dns_response()."""
    r = requests.get(
        "http://127.0.0.1:25353/query",
        params={
            "query_name": "example.com",
            "server": "dns.google",
            "ip": "8.8.8.8",
            "family": "ipv4",
            "protocol": "doh",
        },
    )
    assert "dnsexp_dns_query_success 0.0" in r.text


### ttl tests
def test_ttl(dns_exporter_example_config, caplog):
    """Test collecting ttl metrics."""
    caplog.clear()
    caplog.set_level(logging.DEBUG)
    r = requests.get(
        "http://127.0.0.1:25353/query",
        params={
            "server": "dns.google",
            "query_name": "anycast.censurfridns.dk",
            "family": "ipv4",
        },
    )
    assert 'rr_value="91.239.100.100"' in r.text
    assert "dnsexp_dns_query_success 1.0" in r.text


def test_no_ttl(dns_exporter_no_main_no_config, caplog):
    """Test not collecting ttl metrics."""
    caplog.clear()
    caplog.set_level(logging.DEBUG)
    r = requests.get(
        "http://127.0.0.1:45353/query",
        params={
            "server": "dns.google",
            "query_name": "anycast.censurfridns.dk",
            "family": "ipv4",
            "collect_ttl": False,
        },
    )
    assert 'rr_value="91.239.100.100"' not in r.text
    assert "dnsexp_dns_query_success 1.0" in r.text


### connection refused


@pytest.mark.parametrize("protocol", ["udp", "tcp", "udptcp", "dot", "doh", "doq"])
def test_connection_error_server(dns_exporter_example_config, caplog, protocol):
    """Trigger a connection_error failure for each protocol by connecting to something not listening."""
    caplog.clear()
    caplog.set_level(logging.DEBUG)
    r = requests.get(
        "http://127.0.0.1:25353/query",
        params={
            "server": "192.0.2.42:420",
            "protocol": protocol,
            "query_name": "example.org",
            "timeout": 1,
        },
    )
    assert "dnsexp_dns_query_success 0.0" in r.text


@pytest.mark.parametrize("protocol", ["udp", "tcp", "udptcp", "dot", "doh", "doq"])
def test_timeout_server(dns_exporter_example_config, caplog, protocol):
    """Trigger a timeout failure for each protocol by connecting to something not reachable."""
    caplog.clear()
    caplog.set_level(logging.DEBUG)
    r = requests.get(
        "http://127.0.0.1:25353/query",
        params={
            "server": "192.0.2.42:420",
            "protocol": protocol,
            "query_name": "example.org",
            "timeout": 0.00001,
        },
    )
    assert "dnsexp_dns_query_success 0.0" in r.text


def test_collect_ttl_value_length(dns_exporter_example_config, caplog):
    """Test the collect_ttl_value_length setting."""
    caplog.clear()
    caplog.set_level(logging.DEBUG)
    r = requests.get(
        "http://127.0.0.1:25353/query",
        params={
            "server": "dns.quad9.net",
            "query_name": "dns.google",
            "family": "ipv4",
            "collect_ttl_rr_value_length": 3,
        },
    )
    assert 'rr_value="8.8"' in r.text
    assert "dnsexp_dns_query_success 1.0" in r.text


def test_doh_bad_statuscode(dns_exporter_example_config, mock_dns_query_https_valuerror, caplog):
    """Test DoH fail with a bad statuscode."""
    caplog.clear()
    caplog.set_level(logging.DEBUG)
    r = requests.get(
        "http://127.0.0.1:25353/query",
        params={
            "server": "dns.google",
            "ip": "8.8.8.8",
            "query_name": "example.com",
            "protocol": "doh",
            "family": "ipv4",
        },
    )
    assert "dnsexp_dns_query_success 0.0" in r.text
    assert "failure reason is 'invalid_response_statuscode'" in caplog.text


def test_doh_timeout(dns_exporter_example_config, mock_dns_query_httpx_connecttimeout, caplog):
    """Test DoH fail with a timeout."""
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
    assert "dnsexp_dns_query_success 0.0" in r.text
    assert "failure reason is 'timeout'" in caplog.text


def test_nsid(dns_exporter_example_config, caplog):
    """Test edns nsid functionality."""
    caplog.clear()
    caplog.set_level(logging.DEBUG)
    r = requests.get(
        "http://127.0.0.1:25353/query",
        params={
            "server": "unicast.censurfridns.dk",
            "query_name": "example.com",
            "protocol": "dot",
            "family": "ipv4",
        },
    )
    assert 'transport="TCP"' in r.text
    assert "Protocol dot got a DNS query response over TCP" in caplog.text
    assert "dnsexp_dns_query_success 1.0" in r.text
    assert 'nsid="unicast2.servers.censurfridns.dk"' in r.text

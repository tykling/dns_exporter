"""dnsexporter tests for validator code."""

import logging
from contextlib import nullcontext as does_not_raise

import pytest
import requests
from dns.message import from_text

from dns_exporter.collector import DNSCollector
from dns_exporter.config import Config, RRValidator
from dns_exporter.exceptions import ValidationError

test_dns_response = from_text("""id 0
opcode QUERY
rcode NOERROR
flags QR RD RA
;QUESTION
www.example.com. IN A
;ANSWER
www.example.com. 1800 IN CNAME www.example.com.edgekey.net.
www.example.com.edgekey.net. 18416 IN CNAME www.example.com.edgekey.net.globalredir.exampledns.net.
www.example.com.edgekey.net.globalredir.exampledns.net. 900 IN CNAME abc.dscc.exampleedge.net.
abc.dscc.exampleedge.net. 20 IN A 10.8.23.42
;AUTHORITY
;ADDITIONAL
""")


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


def test_validate_rcode_2(dns_exporter_example_config, caplog):
    """Trigger an invalid_response_rcode error by asking for an NXDOMAIN."""
    r = requests.get(
        "http://127.0.0.1:25353/query",
        params={
            "server": "dns.google",
            "query_name": "404.example.com",
            "family": "ipv4",
            "valid_rcodes": "NXDOMAIN,NOERROR",
        },
    )
    assert 'rcode="NXDOMAIN"' in r.text
    assert "dnsexp_dns_query_success 1.0" in r.text


# validate_flags fail_if_any_absent


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


def test_validate_flags_fail_if_any_absent_2(dns_exporter_example_config, caplog):
    """Test invalid_response_flags fail_if_any_absent without failing."""
    r = requests.get(
        "http://127.0.0.1:25353/query",
        params={
            "server": "dns.google",
            "query_name": "bornhack.dk",
            "family": "ipv4",
            "module": "has_ad",
        },
    )
    assert "dnsexp_dns_query_success 1.0" in r.text


# validate_flags fail_if_any_present


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


def test_validate_flags_fail_if_any_present_2(dns_exporter_example_config, caplog):
    """Test invalid_response_flags fail_if_any_present without failing."""
    r = requests.get(
        "http://127.0.0.1:25353/query",
        params={
            "server": "dns.google",
            "query_name": "google.com",
            "family": "ipv4",
            "module": "has_no_ad",
        },
    )
    assert "dnsexp_dns_query_success 1.0" in r.text


# validate_flags fail_if_all_present


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


# validate_flags fail_if_all_absent


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


# validate_rrs fail_if_matches_regexp


def test_validate_rrs_fail_if_matches_regexp(dns_exporter_example_config, caplog):
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


def test_validate_rrs_fail_if_matches_regexp_2(dns_exporter_example_config, caplog):
    """Test invalid_response_answer_rrs fail_if_matches_regexp without failing."""
    r = requests.get(
        "http://127.0.0.1:25353/query",
        params={
            "server": "dns.google",
            "query_name": "example.com",
            "family": "ipv4",
            "query_type": "NS",
            "module": "fail_auth_k_root",
        },
    )
    assert "dnsexp_dns_query_success 1.0" in r.text


# validate_rrs fail_if_all_match_regexp


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


# validate_rrs fail_if_not_matches_regexp


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


def test_validate_rrs_fail_if_not_matches_regexp_2(dns_exporter_example_config, caplog):
    """Test invalid_response_answer_rrs fail_if_not_matches_regexp without failing."""
    r = requests.get(
        "http://127.0.0.1:25353/query",
        params={
            "server": "dns.google",
            "query_name": ".",
            "family": "ipv4",
            "query_type": "NS",
            "module": "fail_additional_root",
        },
    )
    assert "dnsexp_dns_query_success 1.0" in r.text


# validate_rrs fail_if_none_matches_regexp


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
    """Trigger an invalid_response_answer_rrs by asking for root NS and failing on NOT seeing root servers in ANSWER section."""
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


def test_validate_rrs_fail_if_none_matches_regexp_3(dns_exporter_example_config, caplog):
    """Test fail_if_none_matches with a successful query, make sure k-root is one of the root NS."""
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
    assert "dnsexp_dns_query_success 1.0" in r.text


@pytest.mark.parametrize(
    ("regex_list", "expectation"),
    [
        ([".*"], pytest.raises(ValidationError)),
        ([".*10.8.23.42"], pytest.raises(ValidationError)),
        ([".*127.0.0.1", ".*CNAME\\sabc.dscc.exampleedge.net"], pytest.raises(ValidationError)),
        ([".*127.0.0.1"], does_not_raise()),
        ([".*127.0.0.1", "192.168.32.42"], does_not_raise()),
    ],
)
def test_fail_if_matches_regexp(regex_list, expectation, caplog):
    """Call DNSCollector.validate_response_rrs() with config for fail_if_matches_regexp.

    consider request failed if any answer rr matches one of these regexes
    """
    test_config = {"name": "test", "validate_answer_rrs": RRValidator.create(fail_if_matches_regexp=regex_list)}

    expected_exception = "Response validator fail_if_matches_regexp failed with reason invalid_response_answer_rrs"

    c = DNSCollector(Config.create(**test_config), 2, 3)

    caplog.clear()
    caplog.set_level(logging.DEBUG)

    with expectation as e:
        c.validate_response_rrs(test_dns_response)

    assert isinstance(expectation, does_not_raise) or expected_exception in str(e)


@pytest.mark.parametrize(
    ("regex_list", "expectation"),
    [
        ([".*"], pytest.raises(ValidationError)),
        ([".*10.8.23.42", ".*CNAME.*"], pytest.raises(ValidationError)),
        ([".*10.8.23.42"], does_not_raise()),
        ([".*127.0.0.1"], does_not_raise()),
        ([".*127.0.0.1", ".*CNAME.*"], does_not_raise()),
    ],
)
def test_fail_if_all_match_regexp(regex_list, expectation, caplog):
    """Call DNSCollector.validate_response_rrs() with config for fail_if_all_match_regexp.

    consider request failed if all answer rrs match one of these regexes
    """
    test_config = {"name": "test", "validate_answer_rrs": RRValidator.create(fail_if_all_match_regexp=regex_list)}

    expected_exception = "Response validator fail_if_all_match_regexp failed with reason invalid_response_answer_rrs"

    c = DNSCollector(Config.create(**test_config), 2, 3)

    caplog.clear()
    caplog.set_level(logging.DEBUG)

    with expectation as e:
        c.validate_response_rrs(test_dns_response)

    assert isinstance(expectation, does_not_raise) or expected_exception in str(e)


@pytest.mark.parametrize(
    ("regex_list", "expectation"),
    [
        ([".*"], does_not_raise()),
        ([".*10.8.23.42"], pytest.raises(ValidationError)),
        ([".*10.8.23.42", ".*CNAME.*"], does_not_raise()),
        ([".*10.8.23.42", ".*127.0.0.1"], pytest.raises(ValidationError)),
        ([".*127.0.0.1"], pytest.raises(ValidationError)),
    ],
)
def test_fail_if_not_matches_regexp(regex_list, expectation, caplog):
    """Call DNSCollector.validate_response_rrs() with config for fail_if_not_matches_regexp.

    consider request failed if any answer rr does not match one of these regexes
    """
    test_config = {"name": "test", "validate_answer_rrs": RRValidator.create(fail_if_not_matches_regexp=regex_list)}

    expected_exception = "Response validator fail_if_not_matches_regexp failed with reason invalid_response_answer_rrs"

    c = DNSCollector(Config.create(**test_config), 2, 3)

    caplog.clear()
    caplog.set_level(logging.DEBUG)

    with expectation as e:
        c.validate_response_rrs(test_dns_response)

    assert isinstance(expectation, does_not_raise) or expected_exception in str(e)


@pytest.mark.parametrize(
    ("regex_list", "expectation"),
    [
        ([".*"], does_not_raise()),
        ([".*10.8.23.42"], does_not_raise()),
        ([".*10.8.23.42", ".*CNAME.*"], does_not_raise()),
        ([".*10.8.23.42", ".*127.0.0.1"], does_not_raise()),
        ([".*127.0.0.1"], pytest.raises(ValidationError)),
        ([".*127.0.0.1", ".*ABC"], pytest.raises(ValidationError)),
    ],
)
def test_fail_if_none_matches_regexp(regex_list, expectation, caplog):
    """Call DNSCollector.validate_response_rrs() with config for fail_if_none_matches_regexp.

    consider request failed if none of the answer rrs match one of these regexes
    """
    test_config = {"name": "test", "validate_answer_rrs": RRValidator.create(fail_if_none_matches_regexp=regex_list)}

    expected_exception = "Response validator fail_if_none_matches_regexp failed with reason invalid_response_answer_rrs"

    c = DNSCollector(Config.create(**test_config), 2, 3)

    caplog.clear()
    caplog.set_level(logging.DEBUG)

    with expectation as e:
        c.validate_response_rrs(test_dns_response)

    assert isinstance(expectation, does_not_raise) or expected_exception in str(e)

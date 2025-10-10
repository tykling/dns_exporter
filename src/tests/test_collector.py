"""Unit tests for DNSCollector and other collector.py code."""

import logging
from contextlib import nullcontext as does_not_raise

import pytest
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


def test_invalid_failure_reason(caplog):
    """Call DNSCollector.yield_failure_reason_metric() with an unknown reason."""

    class Conf:
        proxy = None

    mock_conf = Conf()
    c = DNSCollector(mock_conf, 2, 3)
    with pytest.raises(Exception, match="Unknown failure_reason foo - please file a bug!") as e:
        list(c.increase_failure_reason_metric(failure_reason="foo", labels={}))
    assert str(e.value) == "Unknown failure_reason foo - please file a bug!"


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

"""Unit tests for DNSCollector and other collector.py code."""

import logging

import pytest

from dns_exporter.collector import DNSCollector
from dns_exporter.exceptions import ConfigTypeError, LabelsTypeError, QueryTypeError


def test_invalid_failure_reason(config, query):
    """Call DNSCollector.yield_failure_reason_metric() with an unknown reason."""
    c = DNSCollector(config, query, {})
    with pytest.raises(Exception, match="Unknown failure_reason foo - please file a bug!") as e:
        list(c.increase_failure_reason_metric(failure_reason="foo", labels={}))
    assert str(e.value) == "Unknown failure_reason foo - please file a bug!"


def test_invalid_config_type(query):
    """Test exception when passing the wrong config type to DNSCollector()."""
    with pytest.raises(ConfigTypeError):
        DNSCollector(42, query, {})


def test_invalid_query_type(config):
    """Test exception when passing the wrong query type to DNSCollector()."""
    with pytest.raises(QueryTypeError):
        DNSCollector(config, 42, {})


def test_invalid_labels_type(config, query):
    """Test exception when passing the wrong labels type to DNSCollector()."""
    with pytest.raises(LabelsTypeError):
        DNSCollector(config, query, 42)


def test_get_dns_response_connectionrefusederror(
    config, query, labels, mock_get_dns_response_connectionrefusederror, caplog
):
    """Test exception when get_dns_response() raises ConnectionRefusedError."""
    caplog.set_level(logging.DEBUG)
    c = DNSCollector(config, query, labels)
    list(c.collect_dns())
    assert "failure reason is 'connection_error'" in caplog.text


def test_get_dns_response_oserror(config, query, labels, mock_get_dns_response_oserror, caplog):
    """Test exception when get_dns_response() raises OSError."""
    caplog.set_level(logging.DEBUG)
    c = DNSCollector(config, query, labels)
    list(c.collect_dns())
    assert "failure reason is 'connection_error'" in caplog.text

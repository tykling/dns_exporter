"""Unit tests for DNSCollector and other collector.py code."""

import pytest

from dns_exporter.collector import DNSCollector


def test_invalid_failure_reason(config, query, caplog):
    """Call DNSCollector.yield_failure_reason_metric() with an unknown reason."""
    c = DNSCollector(config, query, {})
    with pytest.raises(Exception, match="Unknown failure_reason foo - please file a bug!") as e:
        list(c.increase_failure_reason_metric(failure_reason="foo", labels={}))
    assert str(e.value) == "Unknown failure_reason foo - please file a bug!"

# type: ignore
"""dns_exporter tests for the config module."""
import pytest

from dns_exporter.config import Config, ConfigDict, ConfigError
from dns_exporter.exporter import DNSExporter


def test_nonbool_bool():
    """Test a bool which is not a bool."""
    prepared = DNSExporter.prepare_config(ConfigDict(edns_do=42))
    with pytest.raises(ConfigError):
        Config.create(name="test", **prepared)


def test_negative_int():
    """Test a negative int."""
    prepared = DNSExporter.prepare_config(ConfigDict(edns_pad=-1))
    with pytest.raises(ConfigError):
        Config.create(name="test", **prepared)


def test_invalid_protocol():
    """Test with an unknown protocol."""
    prepared = DNSExporter.prepare_config(ConfigDict(protocol="sctp"))
    with pytest.raises(ConfigError):
        Config.create(name="test", **prepared)


def test_invalid_class():
    """Test with an unknown class."""
    prepared = DNSExporter.prepare_config(ConfigDict(query_class="OUT"))
    with pytest.raises(ConfigError):
        Config.create(name="test", **prepared)


def test_invalid_qtype():
    """Test with an unknown qtype."""
    prepared = DNSExporter.prepare_config(ConfigDict(query_type="B"))
    with pytest.raises(ConfigError):
        Config.create(name="test", **prepared)


def test_invalid_timeout():
    """Test with an invalid float."""
    with pytest.raises(ConfigError):
        DNSExporter.prepare_config(ConfigDict(timeout="timein"))


def test_invalid_rrvalidator():
    """Test with something not an RRValidator object."""
    with pytest.raises(ConfigError):
        DNSExporter.prepare_config(ConfigDict(validate_answer_rrs=42))


def test_invalid_rfvalidator():
    """Test with something not an RFValidator object."""
    with pytest.raises(ConfigError):
        DNSExporter.prepare_config(ConfigDict(validate_response_flags=42))


def test_invalid_rcode():
    """Test with an invalid RCODE."""
    prepared = DNSExporter.prepare_config(ConfigDict(valid_rcodes="YESERROR"))
    with pytest.raises(ConfigError):
        Config.create(name="test", **prepared)


def test_edns_string():
    """Test when edns is a string."""
    prepared = DNSExporter.prepare_config(ConfigDict(edns="true"))
    c = Config.create(name="test", **prepared)
    assert c.edns is True


def test_edns_do_false():
    """Test when edns_do is set to a string."""
    prepared = DNSExporter.prepare_config(ConfigDict(edns_do="false"))
    c = Config.create(name="test", **prepared)
    assert c.edns_do is False


def test_edns_do_true():
    """Test when edns_do is set to a string."""
    prepared = DNSExporter.prepare_config(ConfigDict(edns_do="true"))
    c = Config.create(name="test", **prepared)
    assert c.edns_do is True


def test_rd_true():
    """Test when recursion_desired is set to a string."""
    prepared = DNSExporter.prepare_config(ConfigDict(recursion_desired="true"))
    c = Config.create(name="test", **prepared)
    assert c.recursion_desired is True


def test_rd_false():
    """Test when recursion_desired is set to a string."""
    prepared = DNSExporter.prepare_config(ConfigDict(recursion_desired="false"))
    c = Config.create(name="test", **prepared)
    assert c.recursion_desired is False

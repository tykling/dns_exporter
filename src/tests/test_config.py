"""dns_exporter tests for the config module."""

from ipaddress import IPv4Address

import pytest

from dns_exporter.config import Config, ConfigDict, ConfigError


def test_nonbool_bool(exporter):
    """Test a bool which is not a bool."""
    with pytest.raises(ConfigError):
        exporter.prepare_config(ConfigDict(edns_do=42))


def test_negative_int(exporter):
    """Test a negative int."""
    prepared = exporter.prepare_config(ConfigDict(edns_pad=-1))
    with pytest.raises(ConfigError):
        Config.create(name="test", **prepared)


def test_invalid_protocol(exporter):
    """Test with an unknown protocol."""
    prepared = exporter.prepare_config(ConfigDict(protocol="sctp"))
    with pytest.raises(ConfigError):
        Config.create(name="test", **prepared)


def test_invalid_class(exporter):
    """Test with an unknown class."""
    prepared = exporter.prepare_config(ConfigDict(query_class="OUT"))
    with pytest.raises(ConfigError):
        Config.create(name="test", **prepared)


def test_invalid_qtype(exporter):
    """Test with an unknown qtype."""
    prepared = exporter.prepare_config(ConfigDict(query_type="B"))
    with pytest.raises(ConfigError):
        Config.create(name="test", **prepared)


def test_invalid_timeout(exporter):
    """Test with an invalid float."""
    with pytest.raises(ConfigError):
        exporter.prepare_config(ConfigDict(timeout="timein"))


def test_invalid_rrvalidator(exporter):
    """Test with something not an RRValidator object."""
    with pytest.raises(ConfigError):
        exporter.prepare_config(ConfigDict(validate_answer_rrs=42))


def test_invalid_rfvalidator(exporter):
    """Test with something not an RFValidator object."""
    with pytest.raises(ConfigError):
        exporter.prepare_config(ConfigDict(validate_response_flags=42))


def test_invalid_rcode(exporter):
    """Test with an invalid RCODE."""
    prepared = exporter.prepare_config(ConfigDict(valid_rcodes="YESERROR"))
    with pytest.raises(ConfigError):
        Config.create(name="test", **prepared)


def test_edns_string(exporter):
    """Test when edns is a string."""
    prepared = exporter.prepare_config(ConfigDict(edns="true"))
    c = Config.create(name="test", **prepared)
    assert c.edns is True


def test_edns_do_false(exporter):
    """Test when edns_do is set to a string."""
    prepared = exporter.prepare_config(ConfigDict(edns_do="false"))
    c = Config.create(name="test", **prepared)
    assert c.edns_do is False


def test_edns_do_true(exporter):
    """Test when edns_do is set to a string."""
    prepared = exporter.prepare_config(ConfigDict(edns_do="true"))
    c = Config.create(name="test", **prepared)
    assert c.edns_do is True


def test_rd_true(exporter):
    """Test when recursion_desired is set to a string."""
    prepared = exporter.prepare_config(ConfigDict(recursion_desired="true"))
    c = Config.create(name="test", **prepared)
    assert c.recursion_desired is True


def test_rd_false(exporter):
    """Test when recursion_desired is set to a string."""
    prepared = exporter.prepare_config(ConfigDict(recursion_desired="false"))
    c = Config.create(name="test", **prepared)
    assert c.recursion_desired is False


def test_proxy_for_unsupported_protocol(exporter):
    """Test proxy with a protocol not supported."""
    prepared = exporter.prepare_config(
        ConfigDict(protocol="dot", proxy="socks5://127.0.0.1"),
    )
    with pytest.raises(ConfigError):
        Config.create(name="test", **prepared)


def test_prepare_config_ip_real_ipaddress(caplog, exporter):
    """Make sure a ConfigDict with a real ipaddress.IPv4Address or ipaddress.IPv6Address object works as intended."""
    indict = ConfigDict(ip=IPv4Address("127.0.0.1"))
    outdict = exporter.prepare_config_ip(config=indict)
    assert isinstance(outdict["ip"], IPv4Address)


def test_prepare_config_ip_badtype(caplog, exporter):
    """Make sure a ConfigDict with an integer ip fails as intended."""
    indict = ConfigDict(ip=42)
    with pytest.raises(TypeError):
        exporter.prepare_config_ip(config=indict)


def test_edns_bufsize_nonint(exporter, caplog):
    """Test when edns_bufsize is set to a wrong type."""
    with pytest.raises(ConfigError):
        exporter.prepare_config(ConfigDict(edns_bufsize=[1, 2, 3]))
    assert "Unable to validate integer for key edns_bufsize" in caplog.text


def test_timeout_nofloat(exporter, caplog):
    """Test when timeout is set to neither a string or a float."""
    with pytest.raises(ConfigError):
        exporter.prepare_config(ConfigDict(timeout=["foo"]))
    assert "Unable to validate float for key timeout" in caplog.text


def test_int_server(exporter, caplog):
    """Test when server is set to a wrong type."""
    with pytest.raises(ConfigError):
        exporter.prepare_config(ConfigDict(server=42, protocol="udp"))


def test_int_proxy(exporter, caplog):
    """Test when proxy is set to a wrong type."""
    with pytest.raises(ConfigError):
        exporter.prepare_config(ConfigDict(proxy=42))


def test_wrongtype_bool(exporter):
    """Test a bool of wrong type."""
    prepared = exporter.prepare_config(ConfigDict(edns_do=True))
    prepared["edns_do"] = 42
    with pytest.raises(ConfigError):
        Config.create(name="test", **prepared)

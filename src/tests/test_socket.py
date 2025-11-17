"""Unit tests for ``dns_exporter.socket_cache`` related functionality."""

import logging
import socket
import ssl
import subprocess
import sys
import time
from concurrent.futures import ThreadPoolExecutor

import httpx
import pytest
import requests
from dns.quic._sync import SyncQuicConnection

from dns_exporter.config import Config, ConfigDict
from dns_exporter.socket_cache import DoHSocket, DoTSocket, PlainSocket, QUICSocket, SocketCache


@pytest.mark.parametrize(
    ("protocol", "server"),
    [
        ("udp", "dns.google"),
        ("tcp", "dns.google"),
        ("udptcp", "dns.google"),
        ("dot", "anycast.uncensoreddns.org"),
        ("doh", "anycast.uncensoreddns.org"),
        ("doq", "dns-unfiltered.adguard.com"),
        ("doh3", "dns-unfiltered.adguard.com"),
    ],
)
def test_socket_reuse_enabled(dns_exporter_example_config, protocol, server):
    """Test socket reuse enabled for all protocols."""
    r = requests.get(
        "http://127.0.0.1:25353/query",
        params={
            "query_name": "example.com",
            "server": server,
            "family": "ipv4",
            "protocol": protocol,
            "connection_reuse": True,
        },
    )
    assert f'server="{protocol}://{server}:' in r.text
    assert "dnsexp_dns_query_success 1.0" in r.text
    assert "connection=" not in r.text


def test_socket_reuse_enabled_udptcp_large_reply(dns_exporter_example_config):
    """Test fallback to TCP with a large reply (dr.dk TXT is around 4kb)."""
    r = requests.get(
        "http://127.0.0.1:25353/query",
        params={
            "query_name": "dr.dk",
            "query_type": "txt",
            "server": "dns.google",
            "family": "ipv4",
            "protocol": "udptcp",
            "connection_reuse": True,
        },
    )
    assert 'transport="TCP"' in r.text


@pytest.mark.parametrize(
    ("protocol", "server"),
    [
        ("udp", "dns.google"),
        ("tcp", "dns.google"),
        ("udptcp", "dns.google"),
        ("dot", "anycast.uncensoreddns.org"),
        ("doh", "anycast.uncensoreddns.org"),
        ("doq", "dns-unfiltered.adguard.com"),
        ("doh3", "dns-unfiltered.adguard.com"),
    ],
)
def test_socket_reuse_disabled(dns_exporter_example_config, protocol, server):
    """Test socket reuse disabled for all protocols."""
    r = requests.get(
        "http://127.0.0.1:25353/query",
        params={
            "query_name": "example.com",
            "server": server,
            "family": "ipv4",
            "protocol": protocol,
            "connection_reuse": False,
        },
    )
    assert f'server="{protocol}://{server}:' in r.text
    assert "dnsexp_dns_query_success 1.0" in r.text


@pytest.mark.usefixtures("dns_exporter_example_config_connection_label")
@pytest.mark.parametrize(
    ("protocol", "server"),
    [
        ("udp", "dns.google"),
        ("tcp", "dns.google"),
        ("udptcp", "dns.google"),
        ("dot", "anycast.uncensoreddns.org"),
        ("doh", "anycast.uncensoreddns.org"),
        ("doq", "dns-unfiltered.adguard.com"),
        ("doh3", "dns-unfiltered.adguard.com"),
    ],
)
def test_connection_label_reuse_false(protocol, server):
    """Make sure a connection label is added."""
    r = requests.get(
        "http://127.0.0.1:15353/query",
        params={
            "query_name": "example.com",
            "server": server,
            "family": "ipv4",
            "protocol": protocol,
            "connection_reuse": False,
        },
    )
    assert f'server="{protocol}://{server}:' in r.text
    assert "dnsexp_dns_query_success 1.0" in r.text
    assert "connection=" in r.text


@pytest.mark.usefixtures("dns_exporter_example_config_connection_label")
@pytest.mark.parametrize(
    ("protocol", "server"),
    [
        ("udp", "dns.google"),
        ("tcp", "dns.google"),
        ("udptcp", "dns.google"),
        ("dot", "anycast.uncensoreddns.org"),
        ("doh", "anycast.uncensoreddns.org"),
        ("doq", "dns-unfiltered.adguard.com"),
        ("doh3", "dns-unfiltered.adguard.com"),
    ],
)
def test_connection_label_reuse_true(protocol, server):
    """Make sure a connection label is added."""
    r = requests.get(
        "http://127.0.0.1:15353/query",
        params={
            "query_name": "example.com",
            "server": server,
            "family": "ipv4",
            "protocol": protocol,
            "connection_reuse": True,
        },
    )
    assert f'server="{protocol}://{server}:' in r.text
    assert "dnsexp_dns_query_success 1.0" in r.text
    assert "connection=" in r.text


def test_connection_reuse_retry(caplog, dns_exporter_example_config, mock_get_dns_response_tcp_eoferror):
    """Make sure a socket error is returned if a socket in the cache has been closed."""
    caplog.set_level(logging.DEBUG)
    requests.get(
        "http://127.0.0.1:25353/query",
        params={
            "query_name": "example.com",
            "server": "dns.google",
            "ip": "8.8.8.8",
            "family": "ipv4",
            "protocol": "tcp",
            "connection_reuse": True,
        },
    )
    assert "failure reason is 'socket_error'" in caplog.text


def test_no_connection_reuse_retry(caplog, dns_exporter_example_config, mock_get_dns_response_tcp_eoferror):
    """Make sure an exception is raised on EOFError when conn reuse is disabled."""
    caplog.set_level(logging.DEBUG)
    requests.get(
        "http://127.0.0.1:25353/query",
        params={
            "query_name": "example.com",
            "server": "dns.google",
            "ip": "8.8.8.8",
            "family": "ipv4",
            "protocol": "tcp",
            "connection_reuse": False,
        },
    )
    assert "failure reason is 'socket_error'" in caplog.text


def test_plain_socket_cache_delete(exporter, caplog):
    """Make sure deleting from the socket cache works for plaintext sockets."""
    socket_cache = SocketCache()
    prepared = exporter.prepare_config(
        ConfigDict(
            protocol="tcp",
            server="dns.google",
            query_name="example.com",
            ip="8.8.8.8",
            family="ipv4",
        )
    )
    config = Config.create(name="test", **prepared)
    sock = socket_cache.get_plaintext_socket(config=config)
    assert isinstance(sock, PlainSocket)
    assert isinstance(sock.socket, socket.socket)
    assert len(socket_cache.plain_sockets) == 1
    socket_cache.delete_socket(socket_cache.get_cache_key(config=config))
    assert len(socket_cache.plain_sockets) == 0


def test_dot_socket_cache_delete(exporter, caplog):
    """Make sure deleting from the socket cache works for dot sockets."""
    socket_cache = SocketCache()
    prepared = exporter.prepare_config(
        ConfigDict(
            protocol="dot",
            server="dns.google",
            query_name="example.com",
            ip="8.8.8.8",
            family="ipv4",
        )
    )
    config = Config.create(name="test", **prepared)
    sock = socket_cache.get_dot_socket(config=config, verify=True)
    assert isinstance(sock, DoTSocket)
    assert isinstance(sock.socket, ssl.SSLSocket)
    assert len(socket_cache.dot_sockets) == 1
    socket_cache.delete_socket(socket_cache.get_cache_key(config=config))
    assert len(socket_cache.dot_sockets) == 0


def test_doh_socket_cache_delete(exporter, caplog):
    """Make sure deleting from the socket cache works for doh2 sockets."""
    socket_cache = SocketCache()
    prepared = exporter.prepare_config(
        ConfigDict(
            protocol="doh",
            server="dns.google",
            query_name="example.com",
            ip="8.8.8.8",
            family="ipv4",
        )
    )
    config = Config.create(name="test", **prepared)
    sock = socket_cache.get_doh_socket(config=config, verify=True)
    assert isinstance(sock, DoHSocket)
    assert isinstance(sock.socket, httpx.Client)
    assert len(socket_cache.doh_sockets) == 1
    socket_cache.delete_socket(socket_cache.get_cache_key(config=config))
    assert len(socket_cache.doh_sockets) == 0


def test_quic_socket_cache_delete(exporter, caplog):
    """Make sure deleting from the socket cache works for quic sockets."""
    caplog.clear()
    caplog.set_level(logging.DEBUG)
    socket_cache = SocketCache()
    prepared = exporter.prepare_config(
        ConfigDict(
            protocol="doq",
            server="dns-unfiltered.adguard.com",
            query_name="example.com",
            ip="94.140.14.140",
            family="ipv4",
        )
    )
    config = Config.create(name="test", **prepared)
    sock = socket_cache.get_quic_socket(config=config, verify=True)
    assert isinstance(sock, QUICSocket)
    assert isinstance(sock.socket, SyncQuicConnection)
    assert len(socket_cache.quic_sockets) == 1

    # make sure detecting a closed connection works
    sock.socket._done = True  # noqa: SLF001
    sock = socket_cache.get_quic_socket(config=config, verify=True)
    assert "Deleting stale QUIC socket" in caplog.text
    assert len(socket_cache.quic_sockets) == 1
    socket_cache.delete_socket(socket_cache.get_cache_key(config=config))
    assert len(socket_cache.quic_sockets) == 0


def test_plain_socket_cache_key_equality(exporter, caplog):
    """Test comparing socket cache keys."""
    socket_cache = SocketCache()
    prepared = exporter.prepare_config(
        ConfigDict(
            protocol="tcp",
            server="dns.google",
            query_name="example.com",
            ip="8.8.8.8",
            family="ipv4",
        )
    )
    config = Config.create(name="test", **prepared)
    key1 = socket_cache.get_cache_key(config=config)
    key2 = socket_cache.get_cache_key(config=config)
    assert key1 == key2, "__eq__ in SocketCacheKey doesn't eq"
    assert key1.__hash__() == key2.__hash__(), "__hash__ in SocketCacheKey doesn't hash"
    assert not key1.__eq__(config)
    config.ip = "8.8.4.4"
    key3 = socket_cache.get_cache_key(config=config)
    assert key1 != key3


def test_cache_key_labels(exporter):
    """Make sure the labels property works."""
    socket_cache = SocketCache()
    prepared = exporter.prepare_config(
        ConfigDict(
            protocol="tcp",
            server="dns.google",
            query_name="example.com",
            ip="8.8.8.8",
            family="ipv4",
        )
    )
    config = Config.create(name="test", **prepared)
    key = socket_cache.get_cache_key(config=config)
    assert key.labels == (key.protocol, key.server, key.ip, key.verify, key.proxy)


def test_cache_metrics(exporter, caplog):
    """Try calling the cache metrics update method."""
    caplog.set_level(logging.DEBUG)
    socket_cache = SocketCache()
    prepared = exporter.prepare_config(
        ConfigDict(
            protocol="tcp",
            server="dns.google",
            query_name="example.com",
            ip="8.8.8.8",
            family="ipv4",
        )
    )
    config = Config.create(name="test", **prepared)
    socket_cache.get_plaintext_socket(config=config)
    socket_cache.update_metrics()
    assert "Updating SocketCache metrics for 1 plain_sockets" in caplog.text


def test_socket_locking(dns_exporter_example_config_connection_label):
    """Test socket locking under parallel use."""
    qnames = ["example.com", "example.net", "example.org"]
    with ThreadPoolExecutor(max_workers=3) as executor:
        results = list(executor.map(tcp_query, qnames))
    for r in results:
        assert "dnsexp_dns_query_success 1.0" in r.text


def tcp_query(qname) -> requests.get:
    """Do a TCP query."""
    return requests.get(
        "http://127.0.0.1:15353/query",
        params={
            "query_name": qname,
            "server": "dns.google",
            "family": "ipv4",
            "protocol": "tcp",
            "connection_reuse": True,
            "ip": "8.8.8.8",
        },
    )


def test_plain_socket_cache_delete_oserror(exporter, caplog, mock_socket_close_oserror):
    """Make sure deleting from the plain socket cache handles OSErrors."""
    socket_cache = SocketCache()
    prepared = exporter.prepare_config(
        ConfigDict(
            protocol="tcp",
            server="dns.google",
            query_name="example.com",
            ip="8.8.8.8",
            family="ipv4",
        )
    )
    config = Config.create(name="test", **prepared)
    sock = socket_cache.get_plaintext_socket(config=config)
    assert isinstance(sock, PlainSocket)
    assert isinstance(sock.socket, socket.socket)
    assert len(socket_cache.plain_sockets) == 1
    socket_cache.delete_socket(socket_cache.get_cache_key(config=config))
    assert len(socket_cache.plain_sockets) == 0


def test_dot_socket_cache_delete_oserror(exporter, caplog, mock_socket_close_oserror):
    """Make sure deleting from the dot socket cache handles OSErrors."""
    socket_cache = SocketCache()
    prepared = exporter.prepare_config(
        ConfigDict(
            protocol="dot",
            server="dns.google",
            query_name="example.com",
            ip="8.8.8.8",
            family="ipv4",
        )
    )
    config = Config.create(name="test", **prepared)
    sock = socket_cache.get_dot_socket(config=config, verify=True)
    assert isinstance(sock, DoTSocket)
    assert isinstance(sock.socket, ssl.SSLSocket)
    assert len(socket_cache.dot_sockets) == 1
    socket_cache.delete_socket(socket_cache.get_cache_key(config=config))
    assert len(socket_cache.dot_sockets) == 0


@pytest.mark.skipif(
    sys.version_info[:2] == (3, 12),
    reason="Test is slow and weird on 3.12, skip for now https://github.com/tykling/dns_exporter/issues/203",
)
def test_socket_cache_cleanup_thread_age():
    """Make sure socket cache housekeeping works for old sockets."""
    with subprocess.Popen(
        args=[
            "dns_exporter",
            "-p",
            "15354",
            "--connection-cleanup-interval-seconds",
            "1",
            "--connection-max-idle-seconds",
            "1",
            "--debug",
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    ) as proc:
        time.sleep(1)
        if proc.poll():
            # process didn't start properly, bail out
            pytest.fail(
                "Unable to create test instance on 127.0.0.1:15354",
            )
        ######################################
        requests.get(
            "http://127.0.0.1:15354/query",
            params={
                "query_name": "example.com",
                "server": "dns.google",
                "family": "ipv4",
                "ip": "8.8.8.8",
                "connection_reuse": "true",
            },
        )
        r = requests.get(
            "http://127.0.0.1:15354/metrics",
        )
        assert (
            'dnsexp_socket_uses_total{ip="8.8.8.8",protocol="udp",proxy="none",server="udp://dns.google:53",verify="none"} 1.0'
            in r.text
        )
        time.sleep(3)
        r = requests.get(
            "http://127.0.0.1:15354/metrics",
        )
        assert (
            'dnsexp_socket_uses_total{ip="8.8.8.8",protocol="udp",proxy="none",server="udp://dns.google:53",verify="none"} 1.0'
            not in r.text
        )
        ######################################
        proc.terminate()
        output = proc.stderr.read().decode()
        assert (
            "Deleting socket SocketCacheKey(protocol='udp', server='udp://dns.google:53', ip='8.8.8.8', verify='none', proxy='none') due to age"
            in output
        )


@pytest.mark.skipif(
    sys.version_info[:2] == (3, 12),
    reason="Test is slow and weird on 3.12, skip for now https://github.com/tykling/dns_exporter/issues/203",
)
def test_socket_cache_cleanup_thread_idle():
    """Make sure socket cache housekeeping works for idle sockets."""
    with subprocess.Popen(
        args=[
            "dns_exporter",
            "-p",
            "15354",
            "--connection-cleanup-interval-seconds",
            "1",
            "--connection-max-idle-seconds",
            "1",
            "--debug",
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    ) as proc:
        time.sleep(1)
        if proc.poll():
            # process didn't start properly, bail out
            pytest.fail(
                "Unable to create test instance on 127.0.0.1:15354",
            )
        ######################################
        requests.get(
            "http://127.0.0.1:15354/query",
            params={
                "query_name": "example.com",
                "server": "dns.google",
                "family": "ipv4",
                "ip": "8.8.8.8",
                "connection_reuse": "true",
            },
        )
        r = requests.get(
            "http://127.0.0.1:15354/metrics",
        )
        assert (
            'dnsexp_socket_uses_total{ip="8.8.8.8",protocol="udp",proxy="none",server="udp://dns.google:53",verify="none"} 1.0'
            in r.text
        )
        time.sleep(3)
        r = requests.get(
            "http://127.0.0.1:15354/metrics",
        )
        assert (
            'dnsexp_socket_uses_total{ip="8.8.8.8",protocol="udp",proxy="none",server="udp://dns.google:53",verify="none"} 1.0'
            not in r.text
        )
        ######################################
        proc.terminate()
        output = proc.stderr.read().decode()
        assert (
            "Deleting socket SocketCacheKey(protocol='udp', server='udp://dns.google:53', ip='8.8.8.8', verify='none', proxy='none') with idle time"
            in output
        )

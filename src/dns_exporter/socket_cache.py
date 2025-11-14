"""``dns_exporter.socket_cache`` contains connection reuse related code.

The socket cache is only used when connection reuse is enabled for a query.
"""
# mypy: disable-error-code="no-untyped-call"
# ruff: noqa: SLF001

from __future__ import annotations

import logging
import socket
import threading
import time
from dataclasses import dataclass
from typing import TYPE_CHECKING

import dns.query
import dns.quic
import httpx
from typing_extensions import Self

from dns_exporter.metrics import (
    dnsexp_socket_age_seconds,
    dnsexp_socket_receive_bytes_total,
    dnsexp_socket_transmit_bytes_total,
    dnsexp_socket_uses_total,
)

if TYPE_CHECKING:
    import ssl
    import urllib.parse

    from dns.quic._sync import SyncQuicConnection

    from dns_exporter.config import Config

logger = logging.getLogger(f"dns_exporter.{__name__}")


@dataclass
class SocketCacheKey:
    """Dict keys used to identify sockets in the SocketCache."""

    protocol: str
    server: str
    ip: str
    verify: str
    proxy: str

    def __eq__(self, other: object) -> bool:
        """Consider two cache keys identical only if all values match."""
        if isinstance(other, SocketCacheKey):
            return all(
                [
                    self.protocol == other.protocol,
                    self.server == other.server,
                    self.ip == other.ip,
                    self.verify == other.verify,
                    self.proxy == other.proxy,
                ]
            )
        return False

    def __hash__(self) -> int:
        """Hash all values to make these suitable for use as dict keys."""
        return hash((self.protocol, self.server, self.ip, self.verify, self.proxy))

    @property
    def labels(self) -> tuple[str, str, str, str, str]:
        """Return socket values in a format suitable for use as prometheus labels."""
        return (
            self.protocol,
            self.server,
            self.ip,
            "none" if self.verify is None else self.verify,
            self.proxy,
        )

    @property
    def kind(self) -> socket.SocketKind:
        """Return the kind of socket."""
        return socket.SOCK_STREAM if self.protocol in ["tcp", "dot", "doh"] else socket.SOCK_DGRAM


@dataclass(kw_only=True)
class BaseSocket:
    """Baseclass used by the real classes each representing a single reusable socket."""

    create_timestamp: float | None = None
    last_use_timestamp: float | None = None
    use_count: int = 0
    bytes_sent: int = 0
    bytes_received: int = 0
    lock = threading.Lock()

    def __post_init__(self) -> None:
        """Set socket creation time."""
        if not self.create_timestamp:
            self.create_timestamp = time.time()

    def register_use(self, bytes_sent: int, bytes_received: int) -> None:
        """Called whenever a socket was used. Update use_count, last_use_time, and byte counters."""
        self.use_count += 1
        self.last_use_timestamp = time.time()
        self.bytes_sent += bytes_sent
        self.bytes_received += bytes_received


@dataclass
class PlainSocket(BaseSocket):
    """Plaintext TCP or UDP, v4 or v6 reusable socket."""

    socket: socket.socket


@dataclass
class DoTSocket(BaseSocket):
    """DoT v4 or v6 reusable socket."""

    socket: ssl.SSLSocket


@dataclass
class DoHSocket(BaseSocket):
    """DoH v4 or v6 reusable socket."""

    socket: httpx.Client


@dataclass
class QUICSocket(BaseSocket):
    """DoQ or DoH3 v4 or v6 reusable socket."""

    socket: SyncQuicConnection


class Singleton:
    """Thread safe singleton class used by SocketCache."""

    _instance = None
    _lock = threading.Lock()

    def __new__(cls) -> Self:
        """Make sure we only ever have one instance of this class."""
        if cls._instance is None:
            with cls._lock:
                # Another thread could have created the instance
                # before we acquired the lock. So check that the
                # instance is still nonexistent.
                if not cls._instance:
                    cls._instance = super().__new__(cls)
        return cls._instance


class SocketCache(Singleton):
    """Singleton socket cache."""

    # protocols tcp+udp
    plain_sockets: dict[SocketCacheKey, PlainSocket]
    # protocol dot
    dot_sockets: dict[SocketCacheKey, DoTSocket]
    # protocol doh
    doh_sockets: dict[SocketCacheKey, DoHSocket]
    # protocols doq+doh3
    quic_sockets: dict[SocketCacheKey, QUICSocket]

    def __init__(self) -> None:
        """Initialise socket cache."""
        self.plain_sockets = {}
        self.dot_sockets = {}
        self.doh_sockets = {}
        self.quic_sockets = {}

    def get_cache_key(self, config: Config, force_protocol: str = "") -> SocketCacheKey:
        """Return a SocketCacheKey for identifying a socket."""
        protocol = force_protocol if force_protocol else config.protocol
        if TYPE_CHECKING:  # pragma: no cover
            assert isinstance(config.server, urllib.parse.SplitResult)
        return SocketCacheKey(
            protocol=protocol,
            server=config.server.geturl(),
            ip=str(config.ip),
            verify=str(config.verify),
            proxy=config.proxy.geturl() if config.proxy else "none",
        )

    def delete_socket(self, config: Config) -> None:
        """Delete a socket from cache."""
        cachekey = self.get_cache_key(config=config)
        if config.protocol in ["tcp", "udp", "udptcp"] and cachekey in self.plain_sockets:
            try:
                # be nice and close sockets right
                self.plain_sockets[cachekey].socket.shutdown(socket.SHUT_RDWR)
                self.plain_sockets[cachekey].socket.close()
            except OSError:
                # Ignore OSErrors here (socket might be closed already) and delete the socket anyway
                pass
            del self.plain_sockets[cachekey]

        if config.protocol == "dot" and cachekey in self.dot_sockets:
            try:
                # be nice and close sockets right
                self.dot_sockets[cachekey].socket.shutdown(how=socket.SHUT_RDWR)
                self.dot_sockets[cachekey].socket.close()
            except OSError:
                # Ignore OSErrors here (socket might be closed already) and delete the socket anyway
                pass
            del self.dot_sockets[cachekey]

        if config.protocol in ["doh3", "doq"] and cachekey in self.quic_sockets:
            self.quic_sockets[cachekey].socket.close()
            del self.quic_sockets[cachekey]

        if config.protocol == "doh" and cachekey in self.doh_sockets:
            self.doh_sockets[cachekey].socket.close()
            del self.doh_sockets[cachekey]

    def get_plaintext_socket(self, *, config: Config, force_new: bool = False, force_protocol: str = "") -> PlainSocket:
        """Create+connect new or return existing TCP or UDP PlainSocket."""
        protocol = force_protocol if force_protocol else config.protocol
        cachekey = self.get_cache_key(config=config, force_protocol=protocol)
        sockets = self.plain_sockets
        if force_new or cachekey not in sockets:
            # create new socket
            sockets[cachekey] = PlainSocket(socket=dns.query.make_socket(af=config.socket_family, type=cachekey.kind))
            if protocol == "tcp":
                self.connect_tcp_socket(config=config, sock=sockets[cachekey].socket)
        return sockets[cachekey]

    def get_dot_socket(self, *, config: Config, verify: str | bool, force_new: bool = False) -> DoTSocket:
        """Create+connect new or return existing DoTSocket."""
        cachekey = self.get_cache_key(config=config)
        sockets = self.dot_sockets
        if force_new or cachekey not in sockets:
            # create TLS context
            context = dns.query.make_ssl_context(verify=verify, check_hostname=bool(verify), alpns=["dot"])
            # create new ssl.SSLSocket
            sockets[cachekey] = DoTSocket(
                socket=dns.query.make_ssl_socket(
                    af=config.socket_family,
                    type=socket.SOCK_STREAM,
                    ssl_context=context,
                    server_hostname=config.server.hostname if config.server and verify else None,
                )
            )
            # connect and TLS handshake new socket
            self.connect_tcp_socket(config=config, sock=sockets[cachekey].socket)
            dns.query._tls_handshake(s=sockets[cachekey].socket, expiration=time.time() + config.timeout)
        return sockets[cachekey]

    def get_doh_socket(
        self, *, config: Config, verify: str | ssl.SSLContext | bool, force_new: bool = False
    ) -> DoHSocket:
        """Create+connect new or return existing DoHSocket."""
        cachekey = self.get_cache_key(config=config)
        sockets = self.doh_sockets
        if force_new or cachekey not in sockets:
            transport = dns.query._HTTPTransport(
                http1=False,
                http2=True,
                verify=verify,
                bootstrap_address=str(config.ip),
                family=config.family,
            )
            sockets[cachekey] = DoHSocket(
                socket=httpx.Client(http1=False, http2=True, verify=verify, transport=transport)
            )
        return sockets[cachekey]

    def get_quic_socket(self, *, config: Config, verify: str | bool, force_new: bool = False) -> QUICSocket:
        """Create+connect new or return existing QUIC connection for doq or doh3."""
        cachekey = self.get_cache_key(config=config)
        sockets = self.quic_sockets
        if cachekey in sockets and sockets[cachekey].socket._done:
            logger.debug(f"Deleting stale QUIC socket {cachekey}")
            self.delete_socket(config=config)
        if force_new or cachekey not in sockets:
            # create+connect+handshake new QUIC socket/connection for DoQ/DoH3
            manager = dns.quic.SyncQuicManager(
                verify_mode=verify,
                server_name=config.server.hostname if config.server else None,
                h3=config.protocol == "doh3",
            )
            sockets[cachekey] = QUICSocket(socket=manager.connect(*config.dest))
        return sockets[cachekey]

    def connect_tcp_socket(self, config: Config, sock: socket.socket | ssl.SSLSocket) -> None:
        """Connect and handshake TCP sockets."""
        cachekey = self.get_cache_key(config=config)
        logger.debug(f"Connecting {cachekey} socket to {config.dest} ...")
        dns.query._connect(
            s=sock,
            address=config.dest,
            expiration=time.time() + config.timeout,
        )
        # set TCP_NODELAY on TCP sockets to make it go brrr
        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)

    def update_metrics(self) -> None:
        """Update metrics for the SocketCache."""
        for sockettype in ["plain_sockets", "dot_sockets", "quic_sockets", "doh_sockets"]:
            sockets = getattr(self, sockettype)
            logger.debug(f"Updating SocketCache metrics for {len(sockets)} {sockettype}")
            for key, dnssocket in sockets.items():
                dnsexp_socket_age_seconds.labels(*key.labels).set(time.time() - dnssocket.create_timestamp)
                dnsexp_socket_transmit_bytes_total.labels(*key.labels).set(dnssocket.bytes_sent)
                dnsexp_socket_receive_bytes_total.labels(*key.labels).set(dnssocket.bytes_received)
                dnsexp_socket_uses_total.labels(*key.labels).set(dnssocket.use_count)

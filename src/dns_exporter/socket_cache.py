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
from collections import deque
from dataclasses import dataclass
from typing import TYPE_CHECKING, NamedTuple

import dns.query
import dns.quic
import httpx
from typing_extensions import Self

from dns_exporter.metrics import (
    dnsexp_socket_age_seconds,
    dnsexp_socket_count_total,
    dnsexp_socket_idle_seconds,
    dnsexp_socket_receive_bytes_total,
    dnsexp_socket_transmit_bytes_total,
    dnsexp_socket_uses_total,
)

if TYPE_CHECKING:
    import ssl
    import urllib.parse
    from collections.abc import Mapping

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
            self.verify,
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
    serial: int
    cachekey: SocketCacheKey
    lock: threading.Lock
    use_count: int = 0
    bytes_sent: int = 0
    bytes_received: int = 0

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


class PlainSockLock(NamedTuple):
    """Tuple of a deque() of PlainSockets and a lock to use when adding/reordering/deleting sockets in the deque()."""

    sockets: deque[PlainSocket]
    lock: threading.Lock


@dataclass
class DoTSocket(BaseSocket):
    """DoT v4 or v6 reusable socket."""

    socket: ssl.SSLSocket


class DoTSockLock(NamedTuple):
    """Tuple of a deque() of DoTSockets and a lock to use when adding/reordering/deleting sockets in the deque()."""

    sockets: deque[DoTSocket]
    lock: threading.Lock


@dataclass
class DoHSocket(BaseSocket):
    """DoH v4 or v6 reusable socket."""

    socket: httpx.Client


class DoHSockLock(NamedTuple):
    """Tuple of a deque() of DoHSockets and a lock to use when adding/reordering/deleting sockets in the deque()."""

    sockets: deque[DoHSocket]
    lock: threading.Lock


@dataclass
class QUICSocket(BaseSocket):
    """DoQ or DoH3 v4 or v6 reusable socket."""

    socket: SyncQuicConnection


class QUICSockLock(NamedTuple):
    """Tuple of a deque() of QUICSockets and a lock to use when adding/reordering/deleting sockets in the deque()."""

    sockets: deque[QUICSocket]
    lock: threading.Lock


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
    plain_sockets: dict[SocketCacheKey, PlainSockLock]
    # protocol dot
    dot_sockets: dict[SocketCacheKey, DoTSockLock]
    # protocol doh
    doh_sockets: dict[SocketCacheKey, DoHSockLock]
    # protocols doq+doh3
    quic_sockets: dict[SocketCacheKey, QUICSockLock]

    def __init__(self) -> None:
        """Initialise socket cache."""
        self.plain_sockets = {}
        self.dot_sockets = {}
        self.doh_sockets = {}
        self.quic_sockets = {}
        # max. socket age
        self.socket_max_age_seconds: int = 0
        # max. socket idle time
        self.socket_max_idle_seconds: int = 3600
        # housekeeping interval
        self.housekeeping_interval: int = 600
        # set this to ask the socketcache to exit the housekeeping loop
        self.housekeeping_exit_event = threading.Event()

    def get_cache_key(self, config: Config, force_protocol: str = "") -> SocketCacheKey:
        """Return a SocketCacheKey for identifying a socket."""
        protocol = force_protocol if force_protocol else config.protocol
        if TYPE_CHECKING:  # pragma: no cover
            assert isinstance(config.server, urllib.parse.SplitResult)
        return SocketCacheKey(
            protocol=protocol,
            server=config.server.geturl().replace("udptcp://", f"{protocol}://", 1),
            ip=str(config.ip),
            verify="none" if config.verify is None else str(config.verify),
            proxy=config.proxy.geturl() if config.proxy else "none",
        )

    def get_plaintext_socket(self, *, config: Config, force_protocol: str = "") -> tuple[PlainSocket, bool]:
        """Create+connect new/return existing locked+connected TCP or UDP PlainSocket object."""
        protocol = force_protocol if force_protocol else config.protocol
        cachekey = self.get_cache_key(config=config, force_protocol=protocol)
        # check for existing socket
        if cachekey not in self.plain_sockets:
            self.plain_sockets[cachekey] = PlainSockLock(sockets=deque(), lock=threading.Lock())
        sock_lock: PlainSockLock = self.plain_sockets[cachekey]

        # loop over existing sockets
        for sock in list(sock_lock.sockets):
            # looking for an unlocked socket
            if sock.lock.acquire(blocking=False):
                # socket lock acquired, lock the deque and move this socket to the end
                with sock_lock.lock:
                    sock_lock.sockets.remove(sock)
                    sock_lock.sockets.append(sock)
                return sock, True

        # no available socket found, lock the deque and add a new socket
        with sock_lock.lock:
            # sockets are numbered from 0 and up, find an unused serial
            i = 0
            while i in [s.serial for s in sock_lock.sockets]:
                i += 1
            # create and lock socket
            sock = PlainSocket(
                socket=dns.query.make_socket(af=config.socket_family, type=cachekey.kind),
                serial=i,
                cachekey=cachekey,
                lock=threading.Lock(),
            )
            sock.lock.acquire()
            # append new socket to the end of the deque
            sock_lock.sockets.append(sock)
        if protocol == "tcp":
            self.connect_tcp_socket(config=config, sock=sock.socket)
        return sock, False

    def get_dot_socket(self, *, config: Config, verify: str | bool) -> tuple[DoTSocket, bool]:
        """Create+connect new or return existing DoTSocket."""
        cachekey = self.get_cache_key(config=config)
        if cachekey not in self.dot_sockets:
            # this is the first time this cachekey is seen, initialise deque and lock
            self.dot_sockets[cachekey] = DoTSockLock(sockets=deque(), lock=threading.Lock())
        sock_lock: DoTSockLock = self.dot_sockets[cachekey]

        # loop over existing sockets
        for sock in list(sock_lock.sockets):
            # looking for an unlocked socket
            if sock.lock.acquire(blocking=False):
                # socket lock acquired, lock the deque and move this socket to the end
                with sock_lock.lock:
                    sock_lock.sockets.remove(sock)
                    sock_lock.sockets.append(sock)
                return sock, True

        # no available socket found, lock the deque and add a new socket
        with sock_lock.lock:
            # sockets are numbered from 0 and up, find an unused serial
            i = 0
            while i in [s.serial for s in sock_lock.sockets]:
                i += 1
            # create and lock socket
            context = dns.query.make_ssl_context(verify=verify, check_hostname=bool(verify), alpns=["dot"])
            sock = DoTSocket(
                socket=dns.query.make_ssl_socket(
                    af=config.socket_family,
                    type=socket.SOCK_STREAM,
                    ssl_context=context,
                    server_hostname=config.server.hostname if config.server and verify else None,
                ),
                serial=i,
                cachekey=cachekey,
                lock=threading.Lock(),
            )
            sock.lock.acquire()
            # append new socket to the end of the deque
            sock_lock.sockets.append(sock)
        # connect and TLS handshake socket and return
        self.connect_tcp_socket(config=config, sock=sock.socket)
        dns.query._tls_handshake(s=sock.socket, expiration=time.time() + config.timeout)
        return sock, False

    def get_doh_socket(self, *, config: Config, verify: str | ssl.SSLContext | bool) -> tuple[DoHSocket, bool]:
        """Create+connect new or return existing DoHSocket."""
        cachekey = self.get_cache_key(config=config)
        if cachekey not in self.doh_sockets:
            # this is the first time this cachekey is seen, initialise deque and lock
            self.doh_sockets[cachekey] = DoHSockLock(sockets=deque(), lock=threading.Lock())
        sock_lock = self.doh_sockets[cachekey]

        # loop over existing sockets
        for sock in list(sock_lock.sockets):
            # looking for an unlocked socket
            if sock.lock.acquire(blocking=False):
                # socket lock acquired, lock the deque and move this socket to the end
                with sock_lock.lock:
                    sock_lock.sockets.remove(sock)
                    sock_lock.sockets.append(sock)
                return sock, True

        # no available socket found, lock the deque and add a new socket
        with sock_lock.lock:
            # sockets are numbered from 0 and up, find an unused serial
            i = 0
            while i in [s.serial for s in sock_lock.sockets]:
                i += 1
            # create and lock socket
            transport = dns.query._HTTPTransport(
                http1=False,
                http2=True,
                verify=verify,
                bootstrap_address=str(config.ip),
                family=config.family,
            )
            sock = DoHSocket(
                socket=httpx.Client(http1=False, http2=True, verify=verify, transport=transport),
                serial=i,
                cachekey=cachekey,
                lock=threading.Lock(),
            )
            sock.lock.acquire()
            # append new socket to the end of the deque
            sock_lock.sockets.append(sock)
        return sock, False

    def get_quic_socket(self, *, config: Config, verify: str | bool) -> tuple[QUICSocket, bool]:
        """Create+connect new or return existing QUIC connection for doq or doh3."""
        cachekey = self.get_cache_key(config=config)
        if cachekey not in self.quic_sockets:
            # this is the first time this cachekey is seen, initialise deque and lock
            self.quic_sockets[cachekey] = QUICSockLock(sockets=deque(), lock=threading.Lock())
        logger.debug(f"Inside get_quic_socket with cachekey {cachekey}")
        sock_lock: QUICSockLock = self.quic_sockets[cachekey]

        # loop over existing sockets
        for sock in list(sock_lock.sockets):
            if sock.socket._done:
                # this socket has been closed by remote end, delete and continue
                logger.debug(f"Deleting stale QUIC socket {sock}")
                self.delete_socket(sock=sock)
                continue
            # looking for an unlocked socket
            if sock.lock.acquire(blocking=False):
                # socket lock acquired, lock the deque and move this socket to the end
                with sock_lock.lock:
                    sock_lock.sockets.remove(sock)
                    sock_lock.sockets.append(sock)
                return sock, True

        # no available socket found, lock the deque and add a new socket
        with sock_lock.lock:
            # sockets are numbered from 0 and up, find an unused serial
            i = 0
            while i in [s.serial for s in sock_lock.sockets]:
                i += 1
            # create and lock a new socket
            manager = dns.quic.SyncQuicManager(
                verify_mode=verify,
                server_name=config.server.hostname if config.server else None,
                h3=config.protocol == "doh3",
            )
            sock = QUICSocket(socket=manager.connect(*config.dest), serial=i, cachekey=cachekey, lock=threading.Lock())
            sock.lock.acquire()
            # append new socket to the end of the deque
            sock_lock.sockets.append(sock)
        return sock, False

    def connect_tcp_socket(self, config: Config, sock: socket.socket | ssl.SSLSocket) -> None:
        """Connect and handshake TCP sockets. Used for protocols tcp and dot."""
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
            for key, sock_lock in sockets.items():
                # get the number of identical sockets
                dnsexp_socket_count_total.labels(*key.labels).set(len(sock_lock.sockets))
                # loop over each and get metrics for the specific socket
                for sock in list(sock_lock.sockets):
                    # include sock.serial in labels for the rest of the metrics
                    labels = [*key.labels, str(sock.serial)]
                    dnsexp_socket_age_seconds.labels(*labels).set(time.time() - sock.create_timestamp)
                    if sock.last_use_timestamp:
                        dnsexp_socket_idle_seconds.labels(*labels).set(time.time() - sock.last_use_timestamp)
                    dnsexp_socket_transmit_bytes_total.labels(*labels).set(sock.bytes_sent)
                    dnsexp_socket_receive_bytes_total.labels(*labels).set(sock.bytes_received)
                    dnsexp_socket_uses_total.labels(*labels).set(sock.use_count)

    def delete_socket(
        self, *, sock: PlainSocket | DoTSocket | DoHSocket | QUICSocket, delete_metrics: bool = True
    ) -> None:
        """Delete a socket from the cache."""
        if isinstance(sock, PlainSocket):
            try:
                # be nice and close sockets properly
                sock.socket.shutdown(socket.SHUT_RDWR)
                sock.socket.close()
            except OSError:
                # Ignore OSErrors here (socket might be closed already) and delete the socket anyway
                pass
            # remove socket from deque
            with self.plain_sockets[sock.cachekey].lock:
                self.plain_sockets[sock.cachekey].sockets.remove(sock)

        if isinstance(sock, DoTSocket):
            try:
                # be nice and close sockets right
                sock.socket.shutdown(how=socket.SHUT_RDWR)
                sock.socket.close()
            except OSError:
                # Ignore OSErrors here (socket might be closed already) and delete the socket anyway
                pass
            # remove socket from deque
            with self.dot_sockets[sock.cachekey].lock:
                self.dot_sockets[sock.cachekey].sockets.remove(sock)

        if isinstance(sock, DoHSocket):
            sock.socket.close()
            # remove socket from deque
            with self.doh_sockets[sock.cachekey].lock:
                self.doh_sockets[sock.cachekey].sockets.remove(sock)

        if isinstance(sock, QUICSocket):
            sock.socket.close()
            # remove socket from deque
            with self.quic_sockets[sock.cachekey].lock:
                self.quic_sockets[sock.cachekey].sockets.remove(sock)

        if delete_metrics:
            self.delete_metric(sock=sock)

    def delete_all_sockets(self, *, delete_metrics: bool = True) -> None:
        """Delete all sockets from socket cache."""
        for socklock in [
            *self.plain_sockets.values(),
            *self.dot_sockets.values(),
            *self.doh_sockets.values(),
            *self.quic_sockets.values(),
        ]:
            for sock in list(socklock.sockets):  # type: ignore[attr-defined]
                self.delete_socket(sock=sock, delete_metrics=delete_metrics)

    def delete_metric(self, sock: PlainSocket | DoTSocket | DoHSocket | QUICSocket) -> None:
        """Delete metrics for a socketcache entry."""
        dnsexp_socket_count_total.remove(*sock.cachekey.labels)
        labels = [*sock.cachekey.labels, sock.serial]
        dnsexp_socket_age_seconds.remove(*labels)
        dnsexp_socket_idle_seconds.remove(*labels)
        dnsexp_socket_transmit_bytes_total.remove(*labels)
        dnsexp_socket_receive_bytes_total.remove(*labels)
        dnsexp_socket_uses_total.remove(*labels)

    def housekeeping(self) -> None:
        """Housekeeping method to clean old or idle sockets."""
        # loop forever
        while True:
            # start by waiting the configured interval
            if self.housekeeping_exit_event.wait(timeout=self.housekeeping_interval):
                # exit was requested, break out of the loop
                break
            # do the housekeeping
            logger.debug("SocketCache cleanup task running...")
            self.cleanup_sockets(sockets=self.plain_sockets)
            self.cleanup_sockets(sockets=self.dot_sockets)
            self.cleanup_sockets(sockets=self.doh_sockets)
            self.cleanup_sockets(sockets=self.quic_sockets)
            # log a message and retart the loop
            logger.debug(f"SocketCache cleanup task done, will run again in {self.housekeeping_interval} seconds.")

    def cleanup_sockets(
        self, sockets: Mapping[SocketCacheKey, PlainSockLock | DoTSockLock | DoHSockLock | QUICSockLock]
    ) -> None:
        """Do housekeeping for a dict of sockets."""
        now = time.time()
        keys = list(sockets.keys())
        for cachekey in keys:
            for dnssocket in list(sockets[cachekey].sockets):
                if TYPE_CHECKING:
                    assert dnssocket.create_timestamp is not None
                    assert dnssocket.last_use_timestamp is not None
                    assert isinstance(dnssocket, PlainSocket | DoTSocket | DoHSocket | QUICSocket)
                # check socket age?
                if self.socket_max_age_seconds:
                    socket_age = int(now - dnssocket.create_timestamp)
                    if socket_age > self.socket_max_age_seconds:
                        logger.debug(
                            f"Deleting socket {cachekey} index {dnssocket.serial} due to age "
                            f"{socket_age} seconds > max. age {self.socket_max_age_seconds} seconds"
                        )
                        self.delete_socket(sock=dnssocket)
                        continue

                # check socket idle time?
                if self.socket_max_idle_seconds and dnssocket.last_use_timestamp:
                    socket_idle = now - dnssocket.last_use_timestamp
                    if socket_idle > self.socket_max_idle_seconds:
                        logger.debug(
                            f"Deleting socket {cachekey} index {dnssocket.serial} with "
                            f"idle time {socket_idle} seconds > max. idle "
                            f"{self.socket_max_idle_seconds} seconds"
                        )
                        self.delete_socket(sock=dnssocket)


def cleanup_socket_cache(socket_cache: SocketCache, housekeeping_thread: threading.Thread | None) -> None:
    """Close and delete all sockets and stop the housekeeping thread. Used on exit."""
    logger.debug("SocketCache cleanup running")
    if housekeeping_thread:
        logger.debug("Asking housekeeping thread to exit...")
        socket_cache.housekeeping_exit_event.set()
        logger.debug("Waiting for SocketCache housekeeping thread to exit...")
        housekeeping_thread.join()
        logger.debug("The SocketCache housekeeping thread exited cleanly.")
    if (
        len(socket_cache.plain_sockets)
        + len(socket_cache.dot_sockets)
        + len(socket_cache.doh_sockets)
        + len(socket_cache.quic_sockets)
    ):
        logger.debug(
            "Closing and deleting "
            f"{len(socket_cache.plain_sockets)} plain sockets, "
            f"{len(socket_cache.dot_sockets)} DoT sockets, "
            f"{len(socket_cache.doh_sockets)} DoH sockets, and "
            f"{len(socket_cache.quic_sockets)} QUIC sockets in the SocketCache..."
        )
        # do not waste time deleting metrics before exiting, just close sockets
        socket_cache.delete_all_sockets(delete_metrics=False)
    logger.debug("SocketCache cleanup done.")

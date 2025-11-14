"""``dns_exporter.collector`` contains the DNSCollector class used by the DNSExporter during scrapes."""

from __future__ import annotations

import contextlib
import logging
import re
import socket
import ssl
import time
import traceback
import urllib
from dataclasses import dataclass
from typing import TYPE_CHECKING

import dns.edns
import dns.exception
import dns.flags
import dns.inet
import dns.opcode
import dns.query
import dns.quic
import dns.rcode
import dns.rdatatype
import dns.resolver
import httpx
import socks  # type: ignore[import-untyped]
from dns.message import Message, QueryMessage
from prometheus_client.core import CounterMetricFamily, GaugeMetricFamily
from prometheus_client.registry import Collector

from dns_exporter.config import Config
from dns_exporter.exceptions import (
    ConfigTypeError,
    LabelsTypeError,
    ProtocolSpecificError,
    QueryTypeError,
    UnknownFailureReasonError,
    ValidationError,
)
from dns_exporter.metrics import (
    FAILURE_REASONS,
    TTL_LABELS,
    dnsexp_dns_queries_total,
    dnsexp_dns_responsetime_seconds,
    dnsexp_scrape_failures_total,
    get_dns_qtime_metric,
    get_dns_success_metric,
    get_dns_ttl_metric,
)
from dns_exporter.socket_cache import SocketCache
from dns_exporter.version import __version__

if TYPE_CHECKING:  # pragma: no cover
    import threading
    import urllib.parse
    from collections.abc import Iterator
    from ipaddress import IPv4Address, IPv6Address

    from dns.message import Message

    from dns_exporter.config import RRValidator

logger = logging.getLogger(f"dns_exporter.{__name__}")

socket_cache = SocketCache()


@dataclass
class DNSResponse:
    """Class to hold the result of a lookup."""

    message: Message | None
    transport: str  # TCP, UDP, or QUIC
    socket_reused: bool

    def __bool__(self) -> bool:
        """Be falsy when there is no message."""
        return bool(self.message)


class DNSCollector(Collector):
    """Custom collector class which does DNS lookups and returns metrics."""

    # set the version on the class
    __version__: str = __version__

    # used to store the socket lock during queries
    socket_lock: contextlib.nullcontext[None] | threading.Lock

    def __init__(
        self,
        config: Config,
        query: QueryMessage,
        labels: dict[str, str],
    ) -> None:
        """Save config and q object as class attributes for use later."""
        # make sure config is valid
        if isinstance(config, Config):
            self.config = config
        else:
            raise ConfigTypeError

        # make sure query is valid
        if isinstance(query, QueryMessage):
            self.query = query
        else:
            raise QueryTypeError

        # make sure labels is a list of strings
        if isinstance(labels, dict):
            self.labels = {k: str(v) for k, v in labels.items()}
        else:
            raise LabelsTypeError

        # set proxy?
        if self.config.proxy:
            socks.set_default_proxy(
                proxy_type=getattr(socks, self.config.proxy.scheme.upper()),
                addr=self.config.proxy.hostname,
                port=self.config.proxy.port,
            )
            if self.config.protocol in ["doh3", "doq"]:
                dns.quic._sync.socket_factory = socks.socksocket  # noqa: SLF001
            else:
                dns.query.socket_factory = socks.socksocket
            logger.debug(f"Using proxy {self.config.proxy.geturl()}")
        else:
            # no proxy, make sure sockets are reset to socket.socket
            dns.query.socket_factory = socket.socket
            dns.quic._sync.socket_factory = socket.socket  # noqa: SLF001
            logger.debug("Not using a proxy for this request")

    def describe(self) -> Iterator[CounterMetricFamily | GaugeMetricFamily]:
        """Describe the metrics that are to be returned by this collector."""
        yield get_dns_qtime_metric()
        yield get_dns_success_metric()
        yield get_dns_ttl_metric()
        yield from self.collect_up()

    def collect(
        self,
    ) -> Iterator[CounterMetricFamily | GaugeMetricFamily]:
        """Do DNS lookup and yield metrics."""
        yield from self.collect_dns()
        yield from self.collect_up()
        logger.debug("Done, returning HTTP response")

    def collect_up(self) -> Iterator[GaugeMetricFamily]:
        """Yield the up metric."""
        yield GaugeMetricFamily(
            "up",
            "The value of this Gauge is always 1 when the dns_exporter is up",
            value=1,
        )

    def collect_dns(self) -> Iterator[CounterMetricFamily | GaugeMetricFamily]:
        """Collect and yield DNS metrics."""
        # pleasing mypy
        if TYPE_CHECKING:  # pragma: no cover
            assert isinstance(self.config.ip, IPv4Address | IPv6Address)
            assert isinstance(self.config.server, urllib.parse.SplitResult)
            assert isinstance(self.config.server.port, int)

        r = None
        # mark the start time and do the request
        start = time.time()
        try:
            r = self.get_dns_response(query=self.query)
            logger.debug(
                f"Protocol {self.config.protocol} got a DNS query response over {r.transport}",
            )
        except dns.exception.Timeout:
            # configured timeout was reached before a response arrived
            reason = "timeout"
            self.increase_failure_reason_metric(failure_reason=reason, labels=self.labels)
        except ConnectionRefusedError:
            # server actively refused the connection
            reason = "connection_error"
            self.increase_failure_reason_metric(
                failure_reason=reason,
                labels=self.labels,
            )
        except OSError as e:
            # raised by multiple protocols on ICMP unreach
            logger.debug(f"Protocol {self.config.protocol} got OSError '{e}', exception follows", exc_info=True)
            reason = "connection_error"
            self.increase_failure_reason_metric(
                failure_reason=reason,
                labels=self.labels,
            )
        except ProtocolSpecificError as e:
            # a protocol specific exception was raised, log and re-raise
            logger.debug(
                f"Protocol {self.config.protocol} raised exception, returning failure reason {e}",
                exc_info=True,
            )
            reason = str(e)
            self.increase_failure_reason_metric(failure_reason=reason, labels=self.labels)
        except Exception:  # noqa: BLE001
            logger.warning(
                f"""Caught an unknown exception while looking up qname {self.config.query_name} using server
                {self.config.server.geturl()} and proxy {self.config.proxy.geturl() if self.config.proxy else "none"}
                - exception details follow, returning other_failure""",
                exc_info=True,
            )
            reason = "other_failure"
            self.increase_failure_reason_metric(failure_reason=reason, labels=self.labels)

        # clock it
        qtime = time.time() - start

        # did we get a response?
        if not r or r.message is None:
            logger.warning(
                f"No DNS response received from server {self.config.server.geturl()} - failure reason is '{reason}'..."
            )
            yield from (
                get_dns_qtime_metric(),
                get_dns_ttl_metric(),
                get_dns_success_metric(value=0),
            )
            return None

        # parse response (if any) and yield metrics
        yield from self.handle_response(
            response=r.message, transport=r.transport, connection_reused=r.socket_reused, qtime=qtime
        )

    def handle_response(
        self, *, response: Message, transport: str, connection_reused: bool, qtime: float
    ) -> Iterator[CounterMetricFamily | GaugeMetricFamily]:
        """Do response processing and yield metrics."""
        # convert response flags to sorted text
        flags = dns.flags.to_text(response.flags).split(" ")
        flags.sort()

        # update labels with data from the response
        self.labels.update(
            {
                "transport": transport,
                "opcode": dns.opcode.to_text(response.opcode()),
                "rcode": dns.rcode.to_text(response.rcode()),
                "flags": " ".join(flags),
                "answer": str(sum([len(rrset) for rrset in response.answer])),
                "authority": str(len(response.authority)),
                "additional": str(len(response.additional)),
                "nsid": "no_nsid",
            },
        )

        # does the answer have nsid?
        self.handle_response_options(response=response)

        # include connection label?
        if "connection" in self.labels:  # pragma: no cover
            self.labels["connection"] = "reused" if connection_reused else "new"

        # labels complete, yield timing metric
        qtime_metric = get_dns_qtime_metric()
        qtime_metric.add_metric(labels=list(self.labels.values()), value=qtime)
        yield qtime_metric

        # update internal exporter metric
        dnsexp_dns_responsetime_seconds.labels(**self.labels).observe(qtime)

        yield from self.yield_ttl_metrics(response=response)

        # validate response and yield remaining metrics
        logger.debug("Validating response and yielding remaining metrics")
        try:
            self.validate_response(response=response)
            self.increase_failure_reason_metric(failure_reason="", labels=self.labels)
            yield get_dns_success_metric(1)
        except ValidationError as E:
            logger.exception(f"Validation failed: {E.args[1]}")
            self.increase_failure_reason_metric(failure_reason=E.args[1], labels=self.labels)
            yield get_dns_success_metric(0)

    def handle_response_options(self, response: Message) -> None:
        """Handle response edns."""
        for opt in response.options:
            if opt.otype == dns.edns.NSID:
                nsid = opt.to_text()
                if nsid.startswith("NSID"):
                    nsid = nsid[5:]
                # do we have an NSID string? then overwrite the default 'no_nsid' string
                if nsid:
                    self.labels.update({"nsid": nsid})
                break

    def yield_ttl_metrics(self, response: Message) -> Iterator[GaugeMetricFamily]:
        """Register TTL of response RRs and yield ttl metric."""
        ttl = get_dns_ttl_metric()
        if self.config.collect_ttl:
            for section in ["answer", "authority", "additional"]:
                logger.debug(f"processing section {section}")
                rrsets = getattr(response, section)
                for rrset in rrsets:
                    logger.debug(f"processing rrset {rrset}...")
                    for rr in rrset:
                        logger.debug(f"processing rr {rr}")
                        self.labels.update(
                            {
                                "rr_section": section,
                                "rr_name": str(rrset.name),
                                "rr_type": dns.rdatatype.to_text(rr.rdtype),
                                "rr_value": rr.to_text()[: self.config.collect_ttl_rr_value_length],
                            },
                        )
                        ttl.add_metric(list(self.labels.values()), rrset.ttl)
        # yield all the ttl metrics
        logger.debug("yielding ttl metrics")
        yield ttl

    def get_dns_response(  # noqa: PLR0911 C901
        self,
        *,
        query: Message,
        retry: bool = False,
    ) -> DNSResponse:
        """Perform a DNS query with the configured server and protocol."""
        if not retry:
            # increase query counter
            dnsexp_dns_queries_total.inc()

        # get proxy string for logging
        proxy = self.config.proxy.geturl() if self.config.proxy else "is not active"

        if TYPE_CHECKING:  # pragma: no cover
            # please mypy
            assert self.config.server is not None
            assert isinstance(self.config.server.port, int)

        # prepare variables
        ip = str(self.config.ip)
        port = int(self.config.server.port)

        logger.debug(
            f"Doing DNS query {query.question} with server {self.config.server.geturl()} "
            f"(using IP {self.config.ip}) and proxy {proxy}"
        )

        try:
            if self.config.protocol == "udp":
                # plain UDP lookup, nothing fancy here
                return self.get_dns_response_udp(
                    query=query,
                    ip=ip,
                    port=port,
                )

            if self.config.protocol == "tcp":
                # plain TCP lookup, nothing fancy here
                return self.get_dns_response_tcp(
                    query=query,
                    ip=ip,
                    port=port,
                )

            if self.config.protocol == "udptcp":
                # plain UDP lookup with fallback to TCP lookup
                return self.get_dns_response_udptcp(
                    query=query,
                    ip=ip,
                    port=port,
                )

            if self.config.protocol == "dot":
                return self.get_dns_response_dot(
                    query=query,
                    ip=ip,
                    port=port,
                    server=self.config.server,
                    verify=self.config.get_tls_verify(),
                )

            if self.config.protocol == "doh":
                return self.get_dns_response_doh(
                    query=query,
                    ip=ip,
                    port=port,
                    server=self.config.server,
                    verify=self.config.get_tls_context(),
                )

            if self.config.protocol == "doh3":
                return self.get_dns_response_doh3(
                    query=query,
                    ip=ip,
                    port=port,
                    server=self.config.server,
                    verify=self.config.get_tls_verify(),
                )

            if self.config.protocol == "doq":
                return self.get_dns_response_doq(
                    query=query,
                    ip=ip,
                    port=port,
                    server=self.config.server,
                    verify=self.config.get_tls_verify(),
                )

        except (EOFError, OSError) as e:
            # EOFError can happen when reusing an old socket that has been closed from
            # the remote end, but might also in rare cases happen for new sockets.
            # OSError happens under circumstances I don't fully understand. Retry those too.
            ex = "".join(traceback.format_exception_only(e)).strip()
            if not self.config.connection_reuse:
                logger.debug(
                    f"Protocol {self.config.protocol} raised {ex}, returning socket_error",
                )
                raise ProtocolSpecificError("socket_error") from e

            # if this is the second attempt then bail out now
            if retry:
                logger.debug(
                    "Protocol {self.config.protocol} raised {ex} after retry with new socket, returning socket_error",
                )
                raise ProtocolSpecificError("socket_error") from e

            logger.debug(
                f"Protocol {self.config.protocol} raised {ex} with existing socket, retrying with new socket...",
            )
            # first attempt failed, delete existing socket
            socket_cache.delete_socket(config=self.config)
            # try again
            return self.get_dns_response(query=query, retry=True)

        # unknown protocol, we will never get here, but mypy wants a return statement
        return DNSResponse(message=None, transport="", socket_reused=False)  # pragma: no cover

    def get_dns_response_udp(self, *, query: Message, ip: str, port: int) -> DNSResponse:
        """Perform a DNS query with the udp protocol."""
        # get reusable socket?
        if self.config.connection_reuse:
            sock = socket_cache.get_plaintext_socket(config=self.config)
            self.socket_lock = sock.lock
        else:
            self.socket_lock = contextlib.nullcontext()
        # do the query
        with self.socket_lock:
            r = dns.query.udp(
                q=query,
                where=ip,
                port=port,
                timeout=self.config.timeout,
                one_rr_per_rrset=True,
                sock=sock.socket if self.config.connection_reuse else None,
            )
        if self.config.connection_reuse:
            # update the socket stats
            sock.register_use(bytes_sent=len(query.to_wire()), bytes_received=len(r.to_wire()))
        return DNSResponse(
            message=r, transport="UDP", socket_reused=sock.use_count > 1 if self.config.connection_reuse else False
        )

    def get_dns_response_tcp(self, *, query: Message, ip: str, port: int) -> DNSResponse:
        """Perform a DNS query with the tcp protocol."""
        # get reusable socket?
        if self.config.connection_reuse:
            sock = socket_cache.get_plaintext_socket(config=self.config)
            self.socket_lock = sock.lock
        else:
            self.socket_lock = contextlib.nullcontext()
        # do the query
        with self.socket_lock:
            r = dns.query.tcp(
                q=query,
                where=ip,
                port=port,
                timeout=self.config.timeout,
                one_rr_per_rrset=True,
                sock=sock.socket if self.config.connection_reuse else None,
            )
        if self.config.connection_reuse:
            # update the socket stats
            sock.register_use(bytes_sent=len(query.to_wire()), bytes_received=len(r.to_wire()))
        return DNSResponse(
            message=r, transport="TCP", socket_reused=sock.use_count > 1 if self.config.connection_reuse else False
        )

    def get_dns_response_udptcp(self, *, query: Message, ip: str, port: int) -> DNSResponse:
        """Perform a DNS query with the udptcp protocol (with fallback to TCP)."""
        if self.config.connection_reuse:
            sock = socket_cache.get_plaintext_socket(config=self.config, force_protocol="tcp")
            self.socket_lock = sock.lock
        else:
            self.socket_lock = contextlib.nullcontext()
        # do the query
        with self.socket_lock:
            r, tcp = dns.query.udp_with_fallback(
                q=query,
                where=ip,
                port=port,
                timeout=self.config.timeout,
                one_rr_per_rrset=True,
                tcp_sock=sock.socket if self.config.connection_reuse else None,
                udp_sock=None,
            )
        if tcp:
            # increase the query counter by one extra since tcp fallback was done
            dnsexp_dns_queries_total.inc()
            if self.config.connection_reuse:
                sock.register_use(bytes_sent=len(query.to_wire()), bytes_received=len(r.to_wire()))
        return DNSResponse(
            message=r,
            transport="TCP" if tcp else "UDP",
            socket_reused=sock.use_count > 1 if self.config.connection_reuse and tcp else False,
        )

    def get_dns_response_dot(
        self,
        *,
        query: Message,
        ip: str,
        port: int,
        server: urllib.parse.SplitResult,
        verify: str | bool,
    ) -> DNSResponse:
        """Perform a DNS query with the dot protocol and catch protocol specific exceptions."""
        if self.config.connection_reuse:
            sock = socket_cache.get_dot_socket(config=self.config, verify=verify)
            self.socket_lock = sock.lock
        else:
            self.socket_lock = contextlib.nullcontext()
        try:
            with self.socket_lock:
                # DoT query, use the ip for where= and set tls hostname with server_hostname=
                r = dns.query.tls(
                    q=query,
                    where=ip,
                    port=port,
                    server_hostname=server.hostname if verify else None,
                    timeout=self.config.timeout,
                    verify=verify,
                    one_rr_per_rrset=True,
                    sock=sock.socket if self.config.connection_reuse else None,
                )
            if self.config.connection_reuse:
                # update the socket stats
                sock.register_use(bytes_sent=len(query.to_wire()), bytes_received=len(r.to_wire()))
            return DNSResponse(
                message=r, transport="TCP", socket_reused=sock.use_count > 1 if self.config.connection_reuse else False
            )
        except ssl.SSLCertVerificationError as e:
            # raised by dot on certificate verification error
            logger.debug(
                "Protocol dot raised ssl.SSLCertVerificationError, returning certificate_error",
            )
            raise ProtocolSpecificError("certificate_error") from e

    def get_dns_response_doh(  # noqa: PLR0913
        self,
        *,
        query: Message,
        ip: str,
        port: int,
        http_version: dns.query.HTTPVersion = dns.query.HTTPVersion.HTTP_2,
        server: urllib.parse.SplitResult,
        verify: str | ssl.SSLContext | bool,
    ) -> DNSResponse:
        """Perform a DNS query with the doh protocol (tcp+http1/2), catch protocol specific exceptions."""
        if self.config.connection_reuse:
            sock = socket_cache.get_doh_socket(config=self.config, verify=verify)
            self.socket_lock = sock.lock
        else:
            self.socket_lock = contextlib.nullcontext()
        try:
            # DoH query, use the url for where= and use bootstrap_address= for the ip
            url = f"https://{server.hostname}{server.path}"
            with self.socket_lock:
                r = dns.query.https(
                    q=query,
                    where=url,
                    bootstrap_address=ip,
                    port=port,
                    timeout=self.config.timeout,
                    verify=verify,
                    one_rr_per_rrset=True,
                    # https://github.com/tykling/dns_exporter/issues/201
                    http_version=http_version,
                    session=sock.socket if self.config.connection_reuse else None,
                )
            return DNSResponse(
                message=r,
                transport="TCP",
                socket_reused=sock.use_count > 1 if self.config.connection_reuse else False,
            )
        except httpx.ConnectError as e:
            # raised by doh on both certificate errors and other connection issues
            reason = "certificate_error" if "CERTIFICATE_VERIFY_FAILED" in str(e) else "connection_error"
            logger.debug(f"Protocol doh raised exception, returning {reason}")
            raise ProtocolSpecificError(reason) from e
        except httpx.ConnectTimeout as e:
            # raised by doh on timeouts
            reason = "timeout"
            logger.debug(f"Protocol doh raised exception, returning {reason}")
            raise ProtocolSpecificError(reason) from e
        except ValueError as e:
            # raised by doh when the server response with a non-2XX HTTP status code
            logger.debug(
                "Protocol doh raised ValueErrror due to non-2XX status_code - returning invalid_response_statuscode"
            )
            raise ProtocolSpecificError("invalid_response_statuscode") from e

    def get_dns_response_doh3(
        self,
        *,
        query: Message,
        ip: str,
        port: int,
        server: urllib.parse.SplitResult,
        verify: str | bool,
    ) -> DNSResponse:
        """Perform a DNS query with the doh3 protocol."""
        if self.config.connection_reuse:
            sock = socket_cache.get_quic_socket(config=self.config, verify=verify)
            self.socket_lock = sock.lock
        else:
            self.socket_lock = contextlib.nullcontext()
        # DoH3 query, use the url for where= and use bootstrap_address= for the ip
        url = f"https://{server.hostname}{server.path}"
        with self.socket_lock:
            r = dns.query.https(
                q=query,
                where=url,
                bootstrap_address=ip,
                port=port,
                timeout=self.config.timeout,
                verify=verify,
                one_rr_per_rrset=True,
                http_version=dns.query.HTTPVersion.HTTP_3,
                session=sock.socket if self.config.connection_reuse else None,
            )
        return DNSResponse(
            message=r,
            transport="QUIC",
            socket_reused=sock.use_count > 1 if self.config.connection_reuse else False,
        )

    def get_dns_response_doq(
        self,
        *,
        query: Message,
        ip: str,
        port: int,
        server: urllib.parse.SplitResult,
        verify: str | bool,
    ) -> DNSResponse:
        """Perform a DNS query with the doq protocol and catch protocol specific exceptions."""
        # DoQ query, use the IP for where= and use server_hostname for the hostname
        if self.config.connection_reuse:
            sock = socket_cache.get_quic_socket(config=self.config, verify=verify)
            self.socket_lock = sock.lock
        else:
            self.socket_lock = contextlib.nullcontext()
        with self.socket_lock:
            r = dns.query.quic(
                q=query,
                where=ip,
                port=port,
                server_hostname=server.hostname if verify else None,
                timeout=self.config.timeout,
                verify=verify,
                one_rr_per_rrset=True,
                connection=sock.socket if self.config.connection_reuse else None,
            )
        return DNSResponse(
            message=r, transport="QUIC", socket_reused=sock.use_count > 1 if self.config.connection_reuse else False
        )

    def validate_response_rcode(self, response: Message) -> None:
        """Validate response RCODE."""
        # get the rcode from the respose and validate it
        rcode = dns.rcode.to_text(response.rcode())
        if rcode not in self.config.valid_rcodes:
            raise ValidationError(
                "rcode_validator",
                "invalid_response_rcode",
            )

    def validate_response_flags(self, response: Message) -> None:  # noqa: PLR0912 C901
        """Validate response flags."""
        # create a list of flags as text like ["QR", "AD"]
        flags = dns.flags.to_text(response.flags).split(" ")

        if self.config.validate_response_flags.fail_if_any_present:
            for flag in self.config.validate_response_flags.fail_if_any_present:
                # if any of these flags are found in the response validation fails
                if flag in flags:
                    raise ValidationError(
                        "fail_if_any_present",
                        "invalid_response_flags",
                    )

        if self.config.validate_response_flags.fail_if_all_present:
            for flag in self.config.validate_response_flags.fail_if_all_present:
                # if all these flags are found in the response then fail
                if flag not in flags:
                    break
            else:
                # all the flags are present
                raise ValidationError(
                    "fail_if_all_present",
                    "invalid_response_flags",
                )

        if self.config.validate_response_flags.fail_if_any_absent:
            for flag in self.config.validate_response_flags.fail_if_any_absent:
                # if any of these flags is missing from the response then fail
                if flag not in flags:
                    raise ValidationError(
                        "fail_if_any_absent",
                        "invalid_response_flags",
                    )

        if self.config.validate_response_flags.fail_if_all_absent:
            for flag in self.config.validate_response_flags.fail_if_all_absent:
                # if all these flags are missing from the response then fail
                if flag in flags:
                    break
            else:
                # all the flags are missing
                raise ValidationError(
                    "fail_if_all_absent",
                    "invalid_response_flags",
                )

    def check_regexes(
        self,
        validators: RRValidator,
        validator: str,
        rrs: str,
        section: str,
    ) -> None:
        """Loop over response RRs and check for regex matches."""
        logger.debug(
            f"{validator} validating {len(rrs)} rrs from {section} section "
            f"with {len(getattr(validators, validator))} regexes..."
        )

        num_matches_per_rrs = {str(rr): 0 for rr in rrs}

        for regex in getattr(validators, validator):
            p = re.compile(regex)
            for rr in rrs:
                result = p.match(str(rr))
                log_entry = f"matching '{rr}' against '{regex}': " + ("success" if result else "failed")
                logger.debug(log_entry)
                if result:
                    num_matches_per_rrs[str(rr)] = +1

        # consider request failed if any answer rr matches one of these regexes
        # -> no regex matches any rr
        if validator == "fail_if_matches_regexp" and sum(num_matches_per_rrs.values()) == 0:
            return

        # consider request failed if all answer rrs match one of these regexes
        # -> all regex dit not match at least one rr
        if validator == "fail_if_all_match_regexp" and 0 in num_matches_per_rrs.values():
            return

        # consider request failed if any answer rr does not match one of these regexes
        # -> any regex matched at least one rr
        if validator == "fail_if_not_matches_regexp" and min(num_matches_per_rrs.values()) > 0:
            return

        # consider request failed if none of the answer rrs match one of these regexes
        # -> one regex mathed at least one rr
        if validator == "fail_if_none_matches_regexp" and sum(num_matches_per_rrs.values()) > 0:
            return

        raise ValidationError(validator, f"invalid_response_{section}_rrs")

    def validate_response_rrs(self, response: Message) -> None:
        """Validate response RRs."""
        for section in ["answer", "authority", "additional"]:
            key = f"validate_{section}_rrs"
            rrs = getattr(response, section)
            if getattr(self.config, key):
                validators: RRValidator = getattr(self.config, key)
                if rrs and validators.fail_if_matches_regexp:
                    self.check_regexes(
                        validators=validators,
                        validator="fail_if_matches_regexp",
                        rrs=rrs,
                        section=section,
                    )

                if rrs and validators.fail_if_all_match_regexp:
                    self.check_regexes(
                        validators=validators,
                        validator="fail_if_all_match_regexp",
                        rrs=rrs,
                        section=section,
                    )

                if validators.fail_if_not_matches_regexp:
                    self.check_regexes(
                        validators=validators,
                        validator="fail_if_not_matches_regexp",
                        rrs=rrs,
                        section=section,
                    )

                if validators.fail_if_none_matches_regexp:
                    self.check_regexes(
                        validators=validators,
                        validator="fail_if_none_matches_regexp",
                        rrs=rrs,
                        section=section,
                    )

    def validate_response(self, response: Message) -> None:
        """Validate the DNS response using the validation config in the config."""
        # validate the response rcode?
        if self.config.valid_rcodes:
            self.validate_response_rcode(response=response)

        # validate flags?
        if self.config.validate_response_flags:
            self.validate_response_flags(response=response)

        # check response rr validation
        self.validate_response_rrs(response=response)

    @staticmethod
    def increase_failure_reason_metric(failure_reason: str, labels: dict[str, str]) -> None:
        """This method is used to maintain failure metrics.

        If an empty string is passed as failure_reason (meaning success) the failure counters will not be incremented.
        """
        # was there a failure?
        if not failure_reason:
            return

        # is it a valid failure reason?
        if failure_reason not in FAILURE_REASONS:
            # unknown failure_reason, this is a bug
            raise UnknownFailureReasonError(failure_reason)

        # delete unwelcome labels
        for key in TTL_LABELS:
            with contextlib.suppress(KeyError):
                del labels[key]

        # build a dict with reason first and the rest of the labels after
        labeldict = {"reason": failure_reason}
        labeldict.update(labels)
        logger.debug(labeldict)
        # increase the global failure counter
        dnsexp_scrape_failures_total.labels(**labeldict).inc()
        return


class FailCollector(DNSCollector):
    """Custom collector class used to handle pre-DNSCollector failures, like configuration issues."""

    def __init__(self, failure_reason: str, labels: dict[str, str]) -> None:
        """Save failure reason for use later."""
        self.reason = failure_reason
        self.labels = labels

    def collect_dns(
        self,
    ) -> Iterator[CounterMetricFamily | GaugeMetricFamily]:
        """Do not collect anything, just return the error message."""
        logger.debug(f"FailCollector returning failure reason: {self.reason}")
        yield get_dns_qtime_metric()
        yield get_dns_ttl_metric()
        yield get_dns_success_metric(value=0)
        self.increase_failure_reason_metric(failure_reason=self.reason, labels=self.labels)

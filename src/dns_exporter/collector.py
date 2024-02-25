"""``dns_exporter.collector contains the DNSCollector custom Collector class used by the DNSExporter during scrapes."""

from __future__ import annotations

import logging
import re
import socket
import time
from typing import TYPE_CHECKING

import dns.edns
import dns.exception
import dns.flags
import dns.opcode
import dns.query
import dns.quic
import dns.rcode
import dns.rdatatype
import dns.resolver
import httpx  # type: ignore[import]
import socks  # type: ignore[import]
from prometheus_client.core import CounterMetricFamily, GaugeMetricFamily
from prometheus_client.registry import Collector

from dns_exporter.exceptions import ValidationError
from dns_exporter.metrics import (
    FAILURE_REASONS,
    dnsexp_dns_queries_total,
    dnsexp_dns_responsetime_seconds,
    dnsexp_scrape_failures_total,
    get_dns_failure_metric,
    get_dns_qtime_metric,
    get_dns_success_metric,
    get_dns_ttl_metric,
)
from dns_exporter.version import __version__

if TYPE_CHECKING:  # pragma: no cover
    import urllib.parse
    from collections.abc import Iterator
    from ipaddress import IPv4Address, IPv6Address

    from dns.message import Message, QueryMessage

    from dns_exporter.config import Config, RRValidator

logger = logging.getLogger(f"dns_exporter.{__name__}")


class DNSCollector(Collector):
    """Custom collector class which does DNS lookups and returns metrics."""

    # set the version on the class
    __version__: str = __version__

    def __init__(
        self,
        config: Config,
        query: QueryMessage,
        labels: dict[str, str],
    ) -> None:
        """Save config and q object as class attributes for use later."""
        self.config = config
        self.query = query
        self.labels = labels
        # set proxy?
        if self.config.proxy:
            socks.set_default_proxy(
                proxy_type=getattr(socks, self.config.proxy.scheme.upper()),
                addr=self.config.proxy.hostname,
                port=self.config.proxy.port,
            )
            dns.query.socket_factory = socks.socksocket
            logger.debug(f"Using proxy {self.config.proxy.geturl()}")
        else:
            dns.query.socket_factory = socket.socket
            logger.debug("Not using a proxy for this request")

    def describe(self) -> Iterator[CounterMetricFamily | GaugeMetricFamily]:
        """Describe the metrics that are to be returned by this collector."""
        yield get_dns_qtime_metric()
        yield get_dns_success_metric()
        yield get_dns_failure_metric()
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
            assert isinstance(self.config.ip, (IPv4Address, IPv6Address))
            assert isinstance(self.config.server, urllib.parse.SplitResult)
            assert isinstance(self.config.server.port, int)

        r = None
        # mark the start time and do the request
        start = time.time()
        try:
            r, transport = self.get_dns_response(
                protocol=str(self.config.protocol),
                server=self.config.server,
                ip=self.config.ip,
                port=self.config.server.port,
                query=self.query,
                timeout=float(str(self.config.timeout)),
            )
            logger.debug(
                f"Protocol {self.config.protocol} got a DNS query response over {transport}",
            )
        except dns.exception.Timeout:
            # configured timeout was reached before a response arrived
            yield from self.yield_failure_reason_metric(failure_reason="timeout")
        except ConnectionRefusedError:
            # server actively refused the connection
            yield from self.yield_failure_reason_metric(
                failure_reason="connection_refused",
            )
        except httpx.ConnectError:
            # there was an error while establishing the connection
            yield from self.yield_failure_reason_metric(
                failure_reason="connection_error",
            )
        except Exception:
            logger.exception(
                f"""Caught an unknown exception while looking up qname {self.config.query_name} using server
                {self.config.server.geturl()} and proxy {self.config.proxy.geturl() if self.config.proxy else 'none'}
                - exception details follow, returning other_failure""",
            )
            yield from self.yield_failure_reason_metric(failure_reason="other_failure")
        # clock it
        qtime = time.time() - start

        if r is None:
            logger.debug("Returning DNS query metrics - no response received :(")
            yield get_dns_qtime_metric()
            yield get_dns_ttl_metric()
            yield get_dns_success_metric(value=0)
            return None

        # convert response flags to sorted text
        flags = dns.flags.to_text(r.flags).split(" ")
        flags.sort()

        # update labels with data from the response
        self.labels.update(
            {
                "transport": transport,
                "opcode": dns.opcode.to_text(r.opcode()),
                "rcode": dns.rcode.to_text(r.rcode()),
                "flags": " ".join(flags),
                "answer": str(sum([len(rrset) for rrset in r.answer])),
                "authority": str(len(r.authority)),
                "additional": str(len(r.additional)),
                "nsid": "no_nsid",
            },
        )

        # does the answer have nsid?
        self.handle_response_options(response=r)

        # labels complete, yield timing metric
        qtime_metric = get_dns_qtime_metric()
        qtime_metric.add_metric(labels=list(self.labels.values()), value=qtime)
        yield qtime_metric

        # update internal exporter metric
        dnsexp_dns_responsetime_seconds.labels(**self.labels).observe(qtime)

        yield from self.yield_ttl_metrics(response=r)

        # validate response and yield remaining metrics
        logger.debug("Validating response and yielding remaining metrics")
        try:
            self.validate_response(response=r)
            yield from self.yield_failure_reason_metric(failure_reason="")
            yield get_dns_success_metric(1)
        except ValidationError as E:
            logger.exception(f"Validation failed: {E.args[1]}")
            yield from self.yield_failure_reason_metric(failure_reason=E.args[1])
            yield get_dns_success_metric(0)

    def handle_response_options(self, response: Message) -> None:
        """Handle response edns."""
        for opt in response.options:
            if opt.otype == dns.edns.NSID:
                if hasattr(opt, "data"):  # pragma: no cover
                    # dnspython < 2.6.0 compatibility
                    # treat nsid as ascii text for prom labels
                    self.labels.update({"nsid": opt.data.decode("ASCII")})
                else:
                    # for dnspython 2.6.0+
                    self.labels.update({"nsid": opt.to_text()})
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
                                "rr_value": rr.to_text()[:255],
                            },
                        )
                        ttl.add_metric(list(self.labels.values()), rrset.ttl)
        # yield all the ttl metrics
        logger.debug("yielding ttl metrics")
        yield ttl

    def get_dns_response(  # noqa: PLR0913
        self,
        protocol: str,
        server: urllib.parse.SplitResult,
        ip: IPv4Address | IPv6Address,
        port: int,
        query: Message,
        timeout: float,
    ) -> tuple[Message | None, str]:
        """Perform a DNS query with the specified server and protocol."""
        # increase query counter
        dnsexp_dns_queries_total.inc()
        # return None on unsupported protocol
        r = None
        # the transport protocol, TCP or UDP
        transport: str = "TCP"
        proxy = self.config.proxy.geturl() if self.config.proxy else "is not active"
        logger.debug(
            f"Doing DNS query {query.question} with server {server.geturl()} (using IP {ip}) and proxy {proxy}",
        )

        if protocol == "udp":
            # plain UDP lookup, nothing fancy here
            r = dns.query.udp(
                q=query,
                where=str(ip),
                port=port,
                timeout=timeout,
                one_rr_per_rrset=True,
            )
            transport = "UDP"

        elif protocol == "tcp":
            # plain TCP lookup, nothing fancy here
            r = dns.query.tcp(
                q=query,
                where=str(ip),
                port=port,
                timeout=timeout,
                one_rr_per_rrset=True,
            )

        elif protocol == "udptcp":
            # plain UDP lookup with fallback to TCP lookup
            r, tcp = dns.query.udp_with_fallback(
                q=query,
                where=str(ip),
                port=port,
                timeout=timeout,
                one_rr_per_rrset=True,
            )
            transport = "TCP" if tcp else "UDP"

        elif protocol == "dot":
            # DoT query, use the ip for where= and set tls hostname with server_hostname=
            r = dns.query.tls(
                q=query,
                where=str(ip),
                port=port,
                server_hostname=server.hostname,
                timeout=timeout,
                one_rr_per_rrset=True,
            )

        elif protocol == "doh":
            # DoH query, use the url for where= and use bootstrap_address= for the ip
            url = f"https://{server.hostname}{server.path}"
            r = dns.query.https(
                q=query,
                where=url,
                bootstrap_address=str(ip),
                port=port,
                timeout=timeout,
                one_rr_per_rrset=True,
            )

        elif protocol == "doq":
            # DoQ query, use the IP for where= and use server_hostname for the hostname
            r = dns.query.quic(
                q=query,
                where=str(ip),
                port=port,
                server_hostname=server.hostname,
                timeout=timeout,
                one_rr_per_rrset=True,
            )
            transport = "UDP"
        return r, transport

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

    def check_regexes(  # noqa: PLR0913
        self,
        *,
        validators: RRValidator,
        validator: str,
        rrs: str,
        section: str,
        fail_on_match: bool = False,
        invert: bool = False,
    ) -> None:
        """Loop over response RRs and check for regex matches."""
        for regex in getattr(validators, validator):
            p = re.compile(regex)
            for rr in rrs:
                m = p.match(str(rr))
                if m and fail_on_match or not m and not fail_on_match:
                    raise ValidationError(validator, f"invalid_response_{section}_rrs")
            if invert:
                raise ValidationError(validator, f"invalid_response_{section}_rrs")

    def validate_response_rrs(self, response: Message) -> None:
        """Validate response RRs."""
        for section in ["answer", "authority", "additional"]:
            key = f"validate_{section}_rrs"
            rrs = getattr(response, section)
            if getattr(self.config, key):
                validators: RRValidator = getattr(self.config, key)
                if rrs and validators.fail_if_matches_regexp:
                    logger.debug(
                        f"fail_if_matches_regexp validating {len(rrs)} rrs from {section} section...",
                    )
                    self.check_regexes(
                        validators=validators,
                        validator="fail_if_matches_regexp",
                        rrs=rrs,
                        section=section,
                        fail_on_match=True,
                        invert=False,
                    )

                if rrs and validators.fail_if_all_match_regexp:
                    logger.debug(
                        f"fail_if_all_match_regexp validating {len(rrs)} rrs from {section} section...",
                    )
                    self.check_regexes(
                        validators=validators,
                        validator="fail_if_all_match_regexp",
                        rrs=rrs,
                        section=section,
                        fail_on_match=False,
                        invert=True,
                    )

                if validators.fail_if_not_matches_regexp:
                    logger.debug(
                        f"fail_if_not_matches_regexp validating {len(rrs)} rrs from {section} section...",
                    )
                    self.check_regexes(
                        validators=validators,
                        validator="fail_if_not_matches_regexp",
                        rrs=rrs,
                        section=section,
                        fail_on_match=False,
                        invert=False,
                    )

                if validators.fail_if_none_matches_regexp:
                    logger.debug(
                        f"fail_if_none_matches_regexp validating {len(rrs)} rrs from {section} section...",
                    )
                    self.check_regexes(
                        validators=validators,
                        validator="fail_if_none_matches_regexp",
                        rrs=rrs,
                        section=section,
                        fail_on_match=False,
                        invert=True,
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

        # all validation ok

    @staticmethod
    def yield_failure_reason_metric(
        failure_reason: str,
    ) -> Iterator[CounterMetricFamily]:
        """This method is used to maintain failure metrics.

        If an empty string is passed as failure_reason (meaning success) the failure counters will not be increased.
        """
        if failure_reason:
            # also increase the global failure counter
            dnsexp_scrape_failures_total.labels(reason=failure_reason).inc()
        # get the failure metric
        fail = get_dns_failure_metric()
        # initialise all labels in the per-scrape metric,
        # loop over known failure reasons
        for reason in FAILURE_REASONS:
            # set counter to 1 on match (custom collector - the metrics only exist during the scrape)
            if reason == failure_reason:
                fail.add_metric([reason], 1)
            else:
                fail.add_metric([reason], 0)
        yield fail


class FailCollector(DNSCollector):
    """Custom collector class used to handle pre-DNSCollector failures, like configuration issues."""

    def __init__(self, failure_reason: str) -> None:
        """Save failure reason for use later."""
        self.reason = failure_reason

    def collect_dns(
        self,
    ) -> Iterator[CounterMetricFamily | GaugeMetricFamily]:
        """Do not collect anything, just return the error message."""
        logger.debug(f"FailCollector returning failure reason: {self.reason}")
        yield get_dns_qtime_metric()
        yield get_dns_ttl_metric()
        yield get_dns_success_metric(value=0)
        yield from self.yield_failure_reason_metric(failure_reason=self.reason)

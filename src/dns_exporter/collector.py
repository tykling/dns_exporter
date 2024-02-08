import logging
import re
import time
import typing as t
import urllib.parse
from ipaddress import IPv4Address, IPv6Address
from typing import Iterator, Optional, Union

import dns.edns
import dns.exception
import dns.flags
import dns.opcode
import dns.query
import dns.rcode
import dns.rdatatype
import dns.resolver
from dns.message import Message, QueryMessage
from prometheus_client.core import CounterMetricFamily, GaugeMetricFamily
from prometheus_client.registry import Collector

from dns_exporter.config import Config, RRValidator
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

logger = logging.getLogger(f"dns_exporter.{__name__}")


class DNSCollector(Collector):
    """Custom collector class which does DNS lookups and returns metrics."""

    # set the version on the class
    __version__: str = __version__

    def __init__(
        self, config: Config, query: QueryMessage, labels: dict[str, str]
    ) -> None:
        """Save config and q object as class attributes for use later."""
        self.config = config
        self.query = query
        self.labels = labels

    # def describe(self) -> Iterator[Union[CounterMetricFamily, GaugeMetricFamily]]:
    def describe(self) -> list[GaugeMetricFamily]:
        """Describe the metrics that are to be returned by this collector."""
        # TODO: figure out why this doesn't work
        # yield get_dns_qtime_metric()
        # yield get_dns_success_metric()
        # yield get_dns_failure_metric()
        # yield get_dns_ttl_metric()
        return []

    def collect(
        self, mock_output: Union[str, None] = None
    ) -> Iterator[Union[CounterMetricFamily, GaugeMetricFamily]]:
        """Do DNS lookup and yield metrics."""
        yield from self.collect_dns()
        yield GaugeMetricFamily(
            "up",
            "The value of this Gauge is always 1 when the dns_exporter is up",
            value=1,
        )

    def collect_dns(self) -> Iterator[Union[CounterMetricFamily, GaugeMetricFamily]]:
        assert isinstance(self.config.ip, (IPv4Address, IPv6Address))  # mypy
        assert isinstance(self.config.server, urllib.parse.SplitResult)  # mypy
        assert isinstance(self.config.server.port, int)  # mypy
        r = None
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
                f"Protocol {self.config.protocol} got a DNS query response over {transport}"
            )
        except dns.exception.Timeout:
            # configured timeout was reached before a response arrived
            yield from self.yield_failure_reason_metric(failure_reason="timeout")
        except Exception:
            logger.exception(
                f"Got an exception while looking up qname {self.config.query_name} using server {self.config.server}"
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

        # make mypy happy
        assert hasattr(r, "opcode")
        assert hasattr(r, "rcode")
        assert hasattr(r, "answer")
        assert hasattr(r, "authority")
        assert hasattr(r, "additional")

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
            }
        )

        # does the answer have nsid?
        assert hasattr(r, "options")  # mypy
        for opt in r.options:
            if opt.otype == dns.edns.NSID:
                # treat nsid as ascii text for prom labels
                self.labels.update({"nsid": opt.data.decode("ASCII")})
                break

        # labels complete, yield timing metric
        qtime_metric = get_dns_qtime_metric()
        qtime_metric.add_metric(labels=list(self.labels.values()), value=qtime)
        yield qtime_metric

        # update internal exporter metric
        dnsexp_dns_responsetime_seconds.labels(**self.labels).observe(qtime)

        # register TTL of response RRs and yield ttl metric
        ttl = get_dns_ttl_metric()
        for section in ["answer", "authority", "additional"]:
            rrsets = getattr(r, section)
            for rrset in rrsets:
                rr = rrset[0]
                self.labels.update(
                    {
                        "rr_section": section,
                        "rr_name": str(rrset.name),
                        "rr_type": dns.rdatatype.to_text(rr.rdtype),
                        "rr_value": rr.to_text()[:255],
                    }
                )
                ttl.add_metric(list(self.labels.values()), rrset.ttl)
        # yield all the ttl metrics
        yield ttl

        # validate response and yield remaining metrics
        try:
            self.validate_dnsexp_response(response=r)
            yield from self.yield_failure_reason_metric(failure_reason="")
            yield get_dns_success_metric(1)
        except ValidationError as E:
            logger.warning(f"Validation failed: {E.args[1]}")
            yield from self.yield_failure_reason_metric(failure_reason=E.args[1])
            yield get_dns_success_metric(0)

    def get_dns_response(
        self,
        protocol: str,
        server: urllib.parse.SplitResult,
        ip: t.Union[IPv4Address, IPv6Address],
        port: int,
        query: Message,
        timeout: float,
    ) -> tuple[Optional[Message], str]:
        """Perform a DNS query with the specified server and protocol."""
        assert hasattr(query, "question")  # for mypy
        # increase query counter
        dnsexp_dns_queries_total.inc()
        # return None on unsupported protocol
        r = None
        # the transport protocol, TCP or UDP
        transport: str = "TCP"

        if protocol == "udp":
            # plain UDP lookup, nothing fancy here
            logger.debug(
                f"doing UDP lookup with server {server.netloc} (using IP {ip}) port {port} and query {query.question}"
            )
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
            logger.debug(
                f"doing TCP lookup with server {server.netloc} (using IP {ip}) port {port} and query {query.question}"
            )
            r = dns.query.tcp(
                q=query,
                where=str(ip),
                port=port,
                timeout=timeout,
                one_rr_per_rrset=True,
            )

        elif protocol == "udptcp":
            # plain UDP lookup with fallback to TCP lookup
            logger.debug(
                f"doing UDP>TCP lookup with server {server.netloc} (using IP {ip}) port {port} and query {query.question}"
            )
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
            logger.debug(
                f"doing DoT lookup with server {server.netloc} (using IP {ip}) port {port} and query {query.question}"
            )
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
            logger.debug(
                f"doing DoH lookup with url {url} (using IP {ip}) port {port} and query {query.question}"
            )
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
            logger.debug(
                f"doing DoQ lookup with server {server} (using IP {ip}) port {port} and query {query.question}"
            )
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

    def validate_dnsexp_response(self, response: Message) -> None:
        """Validate the DNS response using the validation config in the config."""
        # validate the response rcode?
        if self.config.valid_rcodes:
            # get the rcode from the respose and validate it
            rcode = dns.rcode.to_text(response.rcode())
            if rcode not in self.config.valid_rcodes:
                raise ValidationError(
                    f"rcode {rcode} not in {self.config.valid_rcodes}",
                    "invalid_response_rcode",
                )

        # validate flags?
        if self.config.validate_response_flags:
            # create e list of flags as text like ["QR", "AD"]
            flags = dns.flags.to_text(response.flags).split(" ")

            if self.config.validate_response_flags.fail_if_any_present:
                for flag in self.config.validate_response_flags.fail_if_any_present:
                    # if any of these flags are found in the response validation fails
                    if flag in flags:
                        raise ValidationError(
                            f"Flag {flag} found in fail_if_any_present",
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
                        "All flags in fail_if_all_present found",
                        "invalid_response_flags",
                    )

            if self.config.validate_response_flags.fail_if_any_absent:
                for flag in self.config.validate_response_flags.fail_if_any_absent:
                    # if any of these flags is missing from the response then fail
                    if flag not in flags:
                        raise ValidationError(
                            f"The flag {flag} is missing and in fail_if_any_absent",
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
                        "All flags in fail_if_all_absent are missing",
                        "invalid_response_flags",
                    )

        # check response rr validation?
        for section in ["answer", "authority", "additional"]:
            key = f"validate_{section}_rrs"
            rrs = getattr(response, section)
            if getattr(self.config, key):
                validators: RRValidator = getattr(self.config, key)
                if validators.fail_if_matches_regexp:
                    logger.debug(
                        f"fail_if_matches_regexp validating rrs from {section} section: {rrs}..."
                    )
                    for regex in validators.fail_if_matches_regexp:
                        p = re.compile(regex)
                        for rr in rrs:
                            m = p.match(str(rr))
                            if m:
                                # a match!
                                raise ValidationError(
                                    "rr match in fail_if_matches_regexp",
                                    f"invalid_response_{section}_rrs",
                                )

                if validators.fail_if_all_match_regexp:
                    logger.debug(
                        f"fail_if_all_match_regexp validating rrs from {section} section: {rrs}..."
                    )
                    for regex in validators.fail_if_all_match_regexp:
                        p = re.compile(regex)
                        logger.debug(rrs)
                        for rr in rrs:
                            logger.debug(f"validating rr {rr} with regex {regex}")
                            m = p.match(str(rr))
                            if not m:
                                # no match for this rr, break out of the loop
                                break
                            else:
                                # all rrs match this regex
                                raise ValidationError(
                                    "all rrs match fail_if_all_match_regexp",
                                    f"invalid_response_{section}_rrs",
                                )

                if validators.fail_if_not_matches_regexp:
                    logger.debug(
                        f"fail_if_not_matches_regexp validating rrs from {section} section: {rrs}..."
                    )
                    for regex in validators.fail_if_not_matches_regexp:
                        p = re.compile(regex)
                        for rr in rrs:
                            m = p.match(str(rr))
                            if not m:
                                # no match, raise
                                raise ValidationError(
                                    "rr doesn't match fail_if_not_matches_regexp",
                                    f"invalid_response_{section}_rrs",
                                )

                if validators.fail_if_none_matches_regexp:
                    logger.debug(
                        f"fail_if_none_matches_regexp validating rrs from {section} section: {rrs}..."
                    )
                    for regex in validators.fail_if_none_matches_regexp:
                        p = re.compile(regex)
                        for rr in rrs:
                            logger.debug(f"matching rr {rr} with regex {regex} ...")
                            m = p.match(str(rr))
                            if m:
                                # found a match for this rr, break out of the loop
                                break
                        else:
                            # none of the rrs match this regex
                            raise ValidationError(
                                "no rrs match the regex in fail_if_none_matches_regexp",
                                f"invalid_response_{section}_rrs",
                            )

        # all validation ok
        return

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

    def collect(
        self, mock_output: Union[str, None] = None
    ) -> Iterator[Union[CounterMetricFamily, GaugeMetricFamily]]:
        """Do not collect anything, just return the error message."""
        logger.debug(f"FailCollector returning failure reason: {self.reason}")
        yield get_dns_qtime_metric()
        yield get_dns_ttl_metric()
        yield get_dns_success_metric(value=0)
        yield from self.yield_failure_reason_metric(failure_reason=self.reason)

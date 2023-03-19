"""dns_exporter is a blackbox-style Prometheus exporter for DNS."""
import argparse
import ipaddress
import logging
import random
import re
import socket
import sys
import time
import typing as t
import urllib.parse
from dataclasses import asdict
from http.server import HTTPServer
from importlib.metadata import PackageNotFoundError, version
from ipaddress import IPv4Address, IPv6Address
from typing import Optional, Union

import dns.edns
import dns.exception
import dns.flags
import dns.opcode
import dns.query
import dns.rcode
import dns.rdatatype
import dns.resolver
import yaml
from dns.message import Message
from prometheus_client import (
    CollectorRegistry,
    Counter,
    Enum,
    Gauge,
    Histogram,
    Info,
    MetricsHandler,
    exposition,
)
from prometheus_client.registry import RestrictedRegistry

from dns_exporter.dns_config.config import Config, ConfigDict, RFValidator, RRValidator

# get version number from package metadata if possible
__version__: str = "0.0.0"
try:
    __version__ = version("dns_exporter")
except PackageNotFoundError:
    # package is not installed, get version from file
    try:
        from _version import version as __version__  # type: ignore
    except ImportError:
        # this must be a git checkout with no _version.py file, version unknown
        pass

# initialise logger
logger = logging.getLogger("dns_exporter")
logger.setLevel(logging.DEBUG)
ch = logging.StreamHandler()
ch.setLevel(logging.DEBUG)
formatter = logging.Formatter("%(asctime)s - %(name)s - %(levelname)s - %(message)s")
ch.setFormatter(formatter)
logger.addHandler(ch)

# create seperate registry for the dns query metrics
dns_registry = CollectorRegistry()

# define the timing histogram
QUERY_TIME = Histogram(
    "dns_query_time_seconds",
    "DNS query time in seconds.",
    [
        "protocol",
        "target",
        "family",
        "ip",
        "port",
        "query_name",
        "query_type",
        "opcode",
        "rcode",
        "flags",
        "nsid",
        "answer",
        "authority",
        "additional",
    ],
    registry=dns_registry,
)
# and the success gauge
QUERY_SUCCESS = Gauge(
    "dns_query_success",
    "Was this DNS query successful or not, 1 for success or 0 for failure.",
    registry=dns_registry,
)
# and the failure Enum
QUERY_FAILURE = Enum(
    "dns_query_failure_reason",
    "The reason this DNS query failed",
    states=[
        "no_failure",
        "invalid_request_config",  # one or more specified config(s) not found
        "invalid_request_target",  # dns issue resolving target hostname
        "invalid_request_family",  # family is not one of "ipv4" or "ipv6"
        "invalid_request_ip",  # ip is not valid
        "invalid_request_port",  # port parameter conflicts with port in target
        "invalid_request_path",  # path parameter conflicts with path in target
        "invalid_request_protocol",  # protocol is not one of "udp", "tcp", "udptcp", "dot", "doh", "doq"
        "invalid_request_query_name",  # query_name is invalid or missing
        "timeout",  # the configured timeout was reached before the dns server replied
        "invalid_response_rcode",  # the response RCODE was not as expected
        "invalid_response_flags",  # the response flags were not as expected
        "invalid_response_answer_rrs",  # the ANSWER rrs were not as expected
        "invalid_response_authority_rrs",  # the AUTHORITY rrs were not as expected
        "invalid_response_additional_rrs",  # the ADDITIONAL rrs were not as expected
        "other_failure",  # unknown error cases
    ],
    registry=dns_registry,
)

# now define the persistent metrics for the exporter itself
i = Info("dns_exporter_build_version", "The version of dns_exporter")
i.info({"version": __version__})

UP = Gauge(
    "up",
    "Is the dns_exporter up and running? 1 for yes and 0 for no.",
)
UP.set(1)

HTTP_REQUESTS = Counter(
    "dns_exporter_http_requests_total",
    "The total number of HTTP requests received by this exporter since start. This counter is increased every time any HTTP request is received by the dns_exporter.",
    ["path"],
)

HTTP_RESPONSES = Counter(
    "dns_exporter_http_responses_total",
    "The total number of HTTP responses sent by this exporter since start. This counter is increased every time an HTTP response is sent from the dns_exporter.",
    ["path", "response_code"],
)

DNS_QUERIES = Counter(
    "dns_exporter_dns_queries_total",
    "The total number of DNS queries sent by this exporter since start. This counter is increased every time the dns_exporter sends out a DNS query.",
)

DNS_RESPONSES = Counter(
    "dns_exporter_dns_query_responses_total",
    "The total number of DNS query responses received since start. This counter is increased every time the dns_exporter receives a query response (before timeout).",
)

DNS_FAILURES = Counter(
    "dns_exporter_dns_query_failures_total",
    "The total number of DNS queries considered failed. This counter is increased every time a DNS query is sent out and a valid response is not received.",
)

INDEX = """<!DOCTYPE html>
<html lang="en-US">
<html lang="en">
<head><title>DNS Exporter</title></head>
<body>
<h1>DNS Exporter</h1>
<p>Visit <a href="/query?target=dns.google&config=doh&query_name=example.com">/query?target=dns.google&config=doh&query_name=example.com</a> to do a DNS query and see metrics.</p>
<p>Visit <a href="/metrics">/metrics</a> to see metrics for the dns_exporter itself.</p>
</body>
</html>"""


class DNSRequestHandler(MetricsHandler):
    """MetricsHandler class for incoming scrape requests."""

    # the configs key is populated by configure() before the class is initialised
    configs: dict[str, Config] = {}

    @classmethod
    def configure(
        cls,
        configs: dict[str, ConfigDict] = {},
    ) -> bool:
        """Validate and create Config objects."""
        prepared = ConfigDict()
        for name, config in configs.items():
            for key, value in config.items():
                if key == "validate_answer_rrs":
                    # create RRValidator object
                    prepared["validate_answer_rrs"] = RRValidator.create(
                        t.cast(t.List[str], value)
                    )  # cast is for mypy
                elif key == "validate_authority_rrs":
                    # create RRValidator object
                    prepared["validate_authority_rrs"] = RRValidator.create(
                        t.cast(t.List[str], value)
                    )  # cast is for mypy
                elif key == "validate_additional_rrs":
                    # create RRValidator object
                    prepared["validate_additional_rrs"] = RRValidator.create(
                        t.cast(t.List[str], value)
                    )  # cast is for mypy
                elif key == "validate_response_flags":
                    # create RFValidator object
                    prepared["validate_response_flags"] = RFValidator.create(
                        t.cast(t.List[str], value)
                    )  # cast is for mypy
                elif key == "ip":
                    # make an ip object
                    try:
                        value = ipaddress.ip_address(str(value))
                    except ValueError:
                        logger.exception(f"Unable to parse IP address {value}")
                        return False
                else:
                    # just use the value as is
                    prepared[key] = value  # type: ignore

            cls.configs[name] = Config.create(name=name, **prepared)
        logger.info(f"{len(cls.configs)} configs loaded OK.")
        return True

    def parse_querystring(self) -> None:
        """Parse the incoming url and then the querystring."""
        # parse incoming request
        self.url = urllib.parse.urlsplit(self.path)
        qs = urllib.parse.parse_qs(self.url.query)
        # querystring values are all lists when returned from parse_qs(),
        # so take the first item only since we do not support multiple values,
        # except for the config parameter.
        # behold, a valid usecase for dict comprehension!
        self.qs: dict[str, Union[str, list[str]]] = {
            k: v[0] for k, v in qs.items() if k != "config"
        }
        # handle config seperate to allow multiple values
        if "config" in qs.keys():
            self.qs["config"] = qs["config"]

    @staticmethod
    def validate_querystring(qs: dict[str, t.Union[str, list[str]]]) -> bool:
        """Validate the request querystring."""
        # make sure we have a target
        if "target" not in qs:
            QUERY_SUCCESS.set(0)
            QUERY_FAILURE.state("invalid_request_target")
            return False

        # all good
        return True

    def prepare_config(self, config: ConfigDict) -> ConfigDict:
        """Make sure the configdict has the right types and objects."""
        # create RRValidator objects
        if "validate_answer_rrs" in config.keys() and not isinstance(
            config["validate_answer_rrs"], RRValidator
        ):
            config["validate_answer_rrs"] = RRValidator.create(
                config["validate_answer_rrs"]
            )
        if "validate_authority_rrs" in config.keys() and not isinstance(
            config["validate_authority_rrs"], RRValidator
        ):
            config["validate_authority_rrs"] = RRValidator.create(
                config["validate_authority_rrs"]
            )
        if "validate_additional_rrs" in config.keys() and not isinstance(
            config["validate_additional_rrs"], RRValidator
        ):
            config["validate_additional_rrs"] = RRValidator.create(
                config["validate_additional_rrs"]
            )

        # create RFValidator
        if "validate_response_flags" in config.keys() and not isinstance(
            config["validate_response_flags"], RFValidator
        ):
            config["validate_response_flags"] = RFValidator.create(
                config["validate_response_flags"]
            )

        # parse target
        if (
            "target" in config.keys()
            and config["target"]
            and not isinstance(config["target"], urllib.parse.SplitResult)
        ):
            # parse target into a SplitResult
            config["target"] = self.parse_target(
                target=config["target"], protocol=config["protocol"]
            )

        return config

    def validate_config(self) -> bool:
        """Validate various aspects of the config."""
        # make sure the target is valid, resolve ip if needed
        if not self.validate_target_ip():
            # something is wrong, reason has been set, just return
            return False

        # make sure we have a query_name in the config
        if not self.config.query_name:
            QUERY_SUCCESS.set(0)
            QUERY_FAILURE.state("invalid_request_query_name")
            return False

        return True

    def get_config(self, qs: dict[str, t.Union[str, list[str]]]) -> bool:
        """Construct the scrape config from defaults and values from the querystring."""
        # first get the defaults
        config = ConfigDict(**asdict(Config.create(name="defaults")))  # type: ignore

        # any configs specified in the querystring are applied in the order specified
        if "config" in qs:
            for template in qs["config"]:
                config.update(asdict(self.configs[template]))
            del qs["config"]

        # and the querystring from the scrape request has highest precedence
        config.update(qs)

        # prepare config dict
        config = self.prepare_config(config)
        config.update(name="configuration")

        # create the config object
        try:
            self.config = Config.create(**config)
        except TypeError:
            # querystring contains unknown fields
            logger.warning(f"Scrape request querystring contains unknown fields: {qs}")
            QUERY_SUCCESS.set(0)
            QUERY_FAILURE.state("invalid_request_config")
            return False

        # validate config
        if not self.validate_config():
            return False

        logger.debug(f"Final scrape configuration: {self.config}")
        return True

    @staticmethod
    def parse_target(target: str, protocol: str) -> urllib.parse.SplitResult:
        """Parse the target (add scheme to make urllib.parse play ball).

        The target at this point can be:
          - a v4 IP
          - a v6 IP
          - a v4 ip:port
          - a v6 ip:port
          - a hostname
          - a hostname:port
          - a https:// url with an IP and no port
          - a https:// url with an IP:port
          - a https:// url with a hostname and no port
          - a https:// url with a hostname:port

        Parse it with urllib.parse.urlsplit and return the result.
        """
        if "://" not in target:
            target = f"{protocol}://{target}"
        return urllib.parse.urlsplit(target)

    def validate_target_ip(self) -> bool:
        """Validate the target and resolve IP if needed."""
        assert isinstance(self.config.target, urllib.parse.SplitResult)  # mypy
        # do we already have an IP in the config?
        if self.config.ip:
            logger.debug(f"checking ip {self.config.ip} of type {type(self.config.ip)}")
            # make sure we have a syntactically valid IP
            try:
                self.config.ip = ipaddress.ip_address(self.config.ip)
            except ValueError:
                QUERY_SUCCESS.set(0)
                QUERY_FAILURE.state("invalid_request_ip")
                return False

            # make sure the ip matches the configured address family
            if not self.check_ip_family(ip=self.config.ip, family=self.config.family):
                # ip and family mismatch
                QUERY_SUCCESS.set(0)
                QUERY_FAILURE.state("invalid_request_ip")
                return False

            # self.config.target.hostname can be either a hostname or an ip,
            # if it is an ip make sure there is no conflict with ip arg
            try:
                targetip = ipaddress.ip_address(str(self.config.target.hostname))
                if targetip != self.config.ip:
                    QUERY_SUCCESS.set(0)
                    QUERY_FAILURE.state("invalid_request_ip")
                    return False
            except ValueError:
                # target host is a hostname not an ip,
                # the hostname will NOT be resolved, since we already have an ip to use
                pass
            method = "from config"
        else:
            try:
                # target host might be an ip, attempt to parse it as such
                self.config.ip = ipaddress.ip_address(str(self.config.target.hostname))
            except ValueError:
                # we have no ip in the config, we need to get ip by resolving target in dns
                self.config.ip = ipaddress.ip_address(
                    str(
                        self.resolve_ip_getaddrinfo(
                            hostname=str(self.config.target.hostname),
                            family=str(self.config.family),
                        )
                    )
                )
                if self.config.ip is None:
                    # unable to resolve target, bail out
                    QUERY_SUCCESS.set(0)
                    QUERY_FAILURE.state("invalid_request_target")
                    return False
            method = f"resolved from {self.config.target.hostname}"

        # we now know which IP we are using for this dns query
        logger.debug(
            f"Using target IP {self.config.ip} ({method}) for the DNS server connection"
        )
        return True

    @staticmethod
    def check_ip_family(ip: Union[IPv4Address, IPv6Address], family: str) -> bool:
        """Make sure the IP matches the address family."""
        if ip.version == 4 and family == "ipv4":
            return True
        elif ip.version == 6 and family == "ipv6":
            return True
        return False

    def resolve_ip_getaddrinfo(self, hostname: str, family: str) -> Optional[str]:
        """Resolve the IP of a DNS server hostname."""
        logger.debug(
            f"resolve_ip_getaddrinfo() called with hostname {hostname} and family {family}"
        )
        try:
            # do we want v4?
            if family == "ipv4":
                logger.debug(f"doing getaddrinfo for hostname {hostname} for ipv4")
                result = socket.getaddrinfo(hostname, 0, family=socket.AF_INET)
                return str(random.choice(result)[4][0])
            # do we want v6?
            elif family == "ipv6":
                logger.debug(f"doing getaddrinfo for hostname {hostname} for ipv6")
                result = socket.getaddrinfo(hostname, 0, family=socket.AF_INET6)
                return str(random.choice(result)[4][0])
            # unknown address family
            else:
                logger.error(f"Unknown address family {family}")
                QUERY_SUCCESS.set(0)
                QUERY_FAILURE.state("invalid_request_family")
                return None
        except socket.gaierror:
            logger.error(f"Unable to resolve server hostname {hostname}")
            QUERY_SUCCESS.set(0)
            QUERY_FAILURE.state("invalid_request_target")
            return None

    def get_dns_response(
        self,
        protocol: str,
        target: str,
        ip: t.Union[IPv4Address, IPv6Address],
        port: int,
        query: Message,
        timeout: float,
        dohpath: str,
    ) -> Optional[Message]:
        """Perform a DNS query with the specified server and protocol."""
        assert hasattr(query, "question")  # for mypy
        # increase query counter
        DNS_QUERIES.inc()
        # return None on unsupported protocol
        r = None

        if protocol == "udp":
            # plain UDP lookup, nothing fancy here
            logger.debug(
                f"doing UDP lookup with server {target} (using IP {ip}) port {port} and query {query.question}"
            )
            r = dns.query.udp(q=query, where=str(ip), port=port, timeout=timeout)

        elif protocol == "tcp":
            # plain TCP lookup, nothing fancy here
            logger.debug(
                f"doing TCP lookup with server {target} (using IP {ip}) port {port} and query {query.question}"
            )
            r = dns.query.tcp(q=query, where=str(ip), port=port, timeout=timeout)

        elif protocol == "udptcp":
            # plain UDP lookup with fallback to TCP lookup
            logger.debug(
                f"doing UDP>TCP lookup with server {target} (using IP {ip}) port {port} and query {query.question}"
            )
            # TODO maybe create a label for transport protocol = tcp or udp?
            r, tcp = dns.query.udp_with_fallback(  # type: ignore
                q=query, where=str(ip), port=port, timeout=timeout
            )

        elif protocol == "dot":
            # DoT query, use the ip for where= and set tls hostname with server_hostname=
            logger.debug(
                f"doing DoT lookup with server {target} (using IP {ip}) port {port} and query {query.question}"
            )
            r = dns.query.tls(
                q=query,
                where=str(ip),
                port=port,
                server_hostname=target,
                timeout=timeout,
            )

        elif protocol == "doh":
            # DoH query, use the url for where= and use bootstrap_address= for the ip
            url = f"https://{target}{dohpath}"
            logger.debug(
                f"doing DoH lookup with url {url} (using IP {ip}) port {port} and query {query.question}"
            )
            # TODO https://github.com/rthalley/dnspython/issues/875
            r = dns.query.https(
                q=query,
                where=url,
                bootstrap_address=str(ip),
                port=port,
                timeout=timeout,
            )

        elif protocol == "doq":
            # DoQ query, TODO figure out how to override IP for DoQ
            logger.debug(
                f"doing DoQ lookup with server {target} (using IP {ip}) port {port} and query {query.question}"
            )
            r = dns.query.quic(q=query, where=target, port=port, timeout=timeout)  # type: ignore
        return r

    def validate_dns_response(self, response: Message) -> bool:
        """Validate the DNS response using the validation config in the config."""
        # do we want to validate the response rcode?
        rcode = dns.rcode.to_text(response.rcode())  # type: ignore
        if self.config.valid_rcodes and rcode not in self.config.valid_rcodes:
            logger.debug(f"rcode {rcode} not in {self.config.valid_rcodes}")
            QUERY_FAILURE.state("invalid_response_rcode")
            return False

        # do we want to validate flags?
        if self.config.validate_response_flags:
            # we need a nice list of flags as text like ["QR", "AD"]
            flags = dns.flags.to_text(response.flags).split(" ")  # type: ignore

            if self.config.validate_response_flags.fail_if_any_present:
                for flag in self.config.validate_response_flags.fail_if_any_present:
                    # if either of these flags is found in the response we fail
                    if flag in flags:
                        QUERY_FAILURE.state("invalid_response_flags")
                        return False

            if self.config.validate_response_flags.fail_if_all_present:
                for flag in self.config.validate_response_flags.fail_if_all_present:
                    # if all these flags are found in the response we fail
                    if flag not in flags:
                        break
                else:
                    # all the flags are present
                    QUERY_FAILURE.state("invalid_response_flags")
                    return False

            if self.config.validate_response_flags.fail_if_any_absent:
                for flag in self.config.validate_response_flags.fail_if_any_absent:
                    # if any of these flags is missing from the response we fail
                    if flag not in flags:
                        QUERY_FAILURE.state("invalid_response_flags")
                        return False

            if self.config.validate_response_flags.fail_if_all_absent:
                for flag in self.config.validate_response_flags.fail_if_all_absent:
                    # if all these flags are missing from the response we fail
                    if flag in flags:
                        break
                else:
                    # all the flags are missing
                    QUERY_FAILURE.state("invalid_response_flags")
                    return False

        # do we want response rr validation?
        for section in ["answer", "authority", "additional"]:
            key = f"validate_{section}_rrs"
            if section == "answer":
                # the answer section has rrsets, flatten the list
                rrsets = getattr(response, "answer")
                # behold, a valid usecase for double list comprehension :D
                rrs = [rr for rrset in rrsets for rr in rrset]
            else:
                rrs = getattr(response, section)
            if getattr(self.config, key):
                validators: RRValidator = getattr(self.config, key)
                if validators.fail_if_matches_regexp:
                    for regex in validators.fail_if_matches_regexp:
                        p = re.compile(regex)
                        for rr in rrs:
                            m = p.match(str(rr))
                            if m:
                                # we have a match
                                QUERY_FAILURE.state(f"invalid_response_{section}_rrs")
                                return False

                if validators.fail_if_all_match_regexp:
                    for regex in validators.fail_if_all_match_regexp:
                        p = re.compile(regex)
                        for rr in rrs:
                            m = p.match(rr)
                            if not m:
                                # no match for this rr, break out of the loop
                                break
                            else:
                                # all rrs match this regex
                                QUERY_FAILURE.state(f"invalid_response_{section}_rrs")
                                return False

                if validators.fail_if_not_matches_regexp:
                    for regex in validators.fail_if_not_matches_regexp:
                        p = re.compile(regex)
                        for rr in rrs:
                            m = p.match(rr)
                            if not m:
                                # no match so we fail
                                QUERY_FAILURE.state(f"invalid_response_{section}_rrs")
                                return False

                if validators.fail_if_none_matches_regexp:
                    for regex in validators.fail_if_none_matches_regexp:
                        p = re.compile(regex)
                        for rr in rrs:
                            m = p.match(rr)
                            if m:
                                # we have a match for this rr, break out of the loop
                                break
                            else:
                                # none of the rrs match this regex
                                QUERY_FAILURE.state(f"invalid_response_{section}_rrs")
                                return False

        # all validation ok
        return True

    def send_error_response(self, messages: list[str]) -> None:
        """Send an HTTP 400 error message to the client."""
        self.send_response(400)
        self.end_headers()
        for line in messages:
            self.wfile.write(line.encode("utf-8"))
        HTTP_RESPONSES.labels(path=self.url.path, response_code=400).inc()
        return None

    def send_metric_response(
        self,
        registry: Union[CollectorRegistry, RestrictedRegistry],
        query: dict[str, t.Union[str, list[str]]],
        skip_metrics: Optional[list[str]] = [],
    ) -> None:
        """Bake and send output from the provided registry and querystring."""
        # do we want to skip any metrics?
        if skip_metrics:
            # we want to skip some metrics
            metrics = [x for x in list(registry._names_to_collectors.keys()) if x not in skip_metrics]  # type: ignore
            registry = registry.restricted_registry(names=metrics)  # type: ignore

        # Bake output
        status, headers, output = exposition._bake_output(  # type: ignore
            registry,
            self.headers.get("Accept"),
            self.headers.get("Accept-Encoding"),
            query,
            False,
        )

        # Return output
        self.send_response(int(status.split(" ")[0]))
        for header in headers:
            self.send_header(*header)
        self.end_headers()
        self.wfile.write(output)
        HTTP_RESPONSES.labels(path=self.url.path, response_code=200).inc()
        return None

    def do_GET(self) -> None:
        """Handle incoming scrape requests."""
        # first parse the scrape request url and querystring,
        # make them available as self.url and self.qs
        self.parse_querystring()
        HTTP_REQUESTS.labels(path=self.url.path).inc()

        # /query is for doing a DNS query, it returns metrics about just that one dns query
        if self.url.path == "/query":
            logger.debug(f"Got scrape request from client {self.client_address}")
            # this is a scrape request, prepare for doing a new dns query
            # clear the metrics, we don't want any history
            QUERY_TIME.clear()
            QUERY_FAILURE.clear()

            # do we have a valid scrape request including a target?
            if not self.validate_querystring(qs=self.qs):
                # something is wrong, reason was already set, just return
                self.send_metric_response(registry=dns_registry, query=self.qs)
                return

            # build and validate configuration for this scrape from defaults, config file and request querystring
            if not self.get_config(qs=self.qs):
                # something is wrong, reason was already set, just return
                self.send_metric_response(registry=dns_registry, query=self.qs)
                return

            # which port do we want?
            assert isinstance(self.config.target, urllib.parse.SplitResult)  # mypy
            if not self.config.target.port:
                if self.config.protocol in ["udp", "tcp", "udptcp"]:
                    # plain DNS
                    port = 53
                elif self.config.protocol in ["dot", "doq"]:
                    # DoT and DoQ
                    port = 853
                else:
                    # DoH
                    port = 443

            # config is ready for action, begin the labels dict
            labels: dict[str, str] = {
                "target": str(self.config.target),
                "ip": str(self.config.ip),
                "port": str(port),
                "protocol": str(self.config.protocol),
                "family": str(self.config.family),
                "query_name": str(self.config.query_name),
                "query_type": str(self.config.query_type),
            }

            # prepare query
            qname = dns.name.from_text(self.config.query_name)
            q = dns.message.make_query(qname=qname, rdtype=str(self.config.query_type))

            # use EDNS?
            if self.config.edns:
                # we want edns
                ednsargs: dict[
                    str, Union[str, int, bool, list[dns.edns.GenericOption]]
                ] = {"options": []}
                assert isinstance(ednsargs["options"], list)
                # do we want the DO bit?
                if self.config.edns_do:
                    ednsargs["ednsflags"] = dns.flags.DO
                # do we want nsid?
                if self.config.edns_nsid:
                    ednsargs["options"].append(
                        dns.edns.GenericOption(dns.edns.NSID, "")  # type: ignore
                    )
                # do we need to set bufsize/payload?
                if self.config.edns_bufsize:
                    # dnspython calls bufsize "payload"
                    ednsargs["payload"] = int(self.config.edns_bufsize)
                # do we want padding?
                if self.config.edns_pad:
                    ednsargs["pad"] = int(self.config.edns_pad)
                # enable edns with the chosen options
                q.use_edns(edns=0, **ednsargs)  # type: ignore
                logger.debug(f"using edns options {ednsargs}")
            else:
                # do not use edns
                q.use_edns(edns=False)  # type: ignore
                logger.debug("not using edns")

            # do it
            assert isinstance(self.config.ip, (IPv4Address, IPv6Address))  # mypy
            r = None
            start = time.time()
            try:
                r = self.get_dns_response(
                    protocol=str(self.config.protocol),
                    target=str(self.config.target.hostname),
                    ip=self.config.ip,
                    port=port,
                    query=q,
                    timeout=float(str(self.config.timeout)),
                    dohpath=self.config.target.path,
                )
                logger.debug("Got a DNS query response!")
            except dns.exception.Timeout:
                # configured timeout was reached before we got a response
                QUERY_FAILURE.state("timeout")
                logger.error("DNS query timeout was reached")
            except Exception:
                logger.exception(
                    f"Got an exception while looking up qname {self.config.query_name} using target {self.config.target}"
                )
                # unknown failure
                QUERY_FAILURE.state("other_failure")
            # clock it
            qtime = time.time() - start

            if r is None:
                # we did not get a response :(
                DNS_FAILURES.inc()
                QUERY_SUCCESS.set(0)
                self.send_metric_response(registry=dns_registry, query=self.qs)
                logger.debug("Returning DNS query metrics - no response received :(")
                return

            # we got a response, increase the response counter
            DNS_RESPONSES.inc()

            # make mypy happy
            assert hasattr(r, "opcode")
            assert hasattr(r, "rcode")
            assert hasattr(r, "answer")
            assert hasattr(r, "authority")
            assert hasattr(r, "additional")

            # convert response flags to sorted text
            flags = dns.flags.to_text(r.flags).split(" ")  # type: ignore
            flags.sort()

            # update labels with data from the response
            labels.update(
                {
                    "opcode": dns.opcode.to_text(r.opcode()),  # type: ignore
                    "rcode": dns.rcode.to_text(r.rcode()),  # type: ignore
                    "flags": " ".join(flags),
                    "answer": str(sum([len(rrset) for rrset in r.answer])),
                    "authority": str(len(r.authority)),
                    "additional": str(len(r.additional)),
                }
            )

            # did we get nsid?
            assert hasattr(r, "options")  # mypy
            for opt in r.options:
                if opt.otype == dns.edns.NSID:
                    # treat nsid as ascii, we need text for prom labels
                    labels.update({"nsid": opt.data.decode("ASCII")})
                    break

            # labels complete, observe timing metric
            QUERY_TIME.labels(**labels).observe(qtime)

            # validate response
            success = self.validate_dns_response(response=r)
            skip_metrics: list[str] = []
            if not success:
                # increase the global failure counter
                DNS_FAILURES.inc()

            # register success or not
            QUERY_SUCCESS.set(success)
            # send the response
            self.send_metric_response(
                registry=dns_registry, query=self.qs, skip_metrics=skip_metrics
            )
            logger.debug(f"Returning DNS query metrics - query success: {success}")
            return

        # this endpoint exposes metrics about the exporter itself and the python process
        elif self.url.path == "/metrics":
            self.send_metric_response(registry=self.registry, query=self.qs)
            logger.debug("Returning exporter metrics for request to /metrics")
            return

        # the root just returns a bit of informational html
        elif self.url.path == "/":
            # return a basic index page
            self.send_response(200)
            self.end_headers()
            self.wfile.write(INDEX.encode("utf-8"))
            HTTP_RESPONSES.labels(path="/", response_code=200).inc()
            logger.debug("Returning index page for request to /")

        # unknown endpoint
        else:
            self.send_response(404)
            self.end_headers()
            HTTP_RESPONSES.labels(path=self.url.path, response_code=404).inc()
            logger.debug(f"Unknown endpoint '{self.url.path}' returning 404")
            return None


def get_parser() -> argparse.ArgumentParser:
    """Create and return the argparse object."""
    parser = argparse.ArgumentParser(
        description=f"dns_exporter version {__version__}. See ReadTheDocs for more info."
    )

    # optional arguments
    parser.add_argument(
        "-c",
        "--config-file",
        dest="config-file",
        help="The path to the yaml config file to use. Only the root 'configs' key is read from the config file.",
        default=argparse.SUPPRESS,
    )
    parser.add_argument(
        "-d",
        "--debug",
        action="store_const",
        dest="log-level",
        const="DEBUG",
        help="Debug mode. Equal to setting --log-level=DEBUG.",
        default=argparse.SUPPRESS,
    )
    parser.add_argument(
        "-l",
        "--log-level",
        dest="log-level",
        choices=["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"],
        help="Logging level. One of DEBUG, INFO, WARNING, ERROR, CRITICAL. Defaults to INFO.",
        default=argparse.SUPPRESS,
    )
    parser.add_argument(
        "-q",
        "--quiet",
        action="store_const",
        dest="log-level",
        const="WARNING",
        help="Quiet mode. No output at all if there is nothing to do, and no errors are encountered. Equal to setting --log-level=WARNING.",
        default=argparse.SUPPRESS,
    )
    parser.add_argument(
        "-v",
        "--version",
        dest="version",
        action="store_true",
        help="Show version and exit.",
        default=argparse.SUPPRESS,
    )
    return parser


def parse_args(
    mockargs: Optional[list[str]] = None,
) -> tuple[argparse.ArgumentParser, argparse.Namespace]:
    """Create an argparse monster and parse mockargs or sys.argv[1:]."""
    parser = get_parser()
    args = parser.parse_args(mockargs if mockargs else sys.argv[1:])
    return parser, args


def main(mockargs: Optional[list[str]] = None) -> None:
    """Read config and start exporter."""
    logger.info(f"dns_exporter v{__version__} starting up")

    # get arpparser and parse args
    parser, args = parse_args(mockargs)

    # handle version check
    if hasattr(args, "version"):
        print(f"dns_exporter version {__version__}")
        sys.exit(0)

    if hasattr(args, "config-file"):
        with open(getattr(args, "config-file"), "r") as f:
            try:
                configfile = yaml.load(f, Loader=yaml.SafeLoader)
            except Exception:
                logger.exception(
                    f"Unable to parse YAML config file {getattr(args, 'config-file')} - bailing out."
                )
                sys.exit(1)
        if (
            not configfile
            or "configs" not in configfile
            or not isinstance(configfile["configs"], dict)
            or not configfile["configs"]
        ):
            # configfile is empty, missing "configs" key, or configs is empty or not a dict
            logger.error(
                f"Invalid config file {getattr(args, 'config-file')} - yaml was valid but no configs found"
            )
            sys.exit(1)
        logger.debug(
            f"Read {len(configfile['configs'])} configs from config file {getattr(args, 'config-file')}: {list(configfile['configs'].keys())}"
        )
    else:
        # we have no config file
        configfile = {"configs": {}}
        logger.debug(
            "No -c / --config-file found so a config file will not be used. No configs loaded."
        )

    # initialise handler and start HTTPServer
    handler = DNSRequestHandler
    if configfile["configs"]:
        if not handler.configure(
            configs={k: ConfigDict(**v) for k, v in configfile["configs"].items()}  # type: ignore
        ):
            logger.error(
                "An error occurred while configuring dns_exporter. Bailing out."
            )
            sys.exit(1)
    HTTPServer(("127.0.0.1", 15353), handler).serve_forever()


if __name__ == "__main__":
    main()

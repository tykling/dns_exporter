"""dns_exporter is a blackbox-style Prometheus exporter for DNS.

The config.py module contains configuration related stuff, metrics.py
contains the metric definitions, and this exporter.py module contains
the rest of the code.

- Repository: https://github.com/tykling/dns_exporter
- Pypi: https://pypi.org/project/dns-exporter/
- Docs: https://dns-exporter.readthedocs.io/en/latest/

"""
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
from prometheus_client import CollectorRegistry, Info, MetricsHandler, exposition
from prometheus_client.registry import RestrictedRegistry

from dns_exporter.config import Config, ConfigDict, RFValidator, RRValidator
from dns_exporter.metrics import dnsexp_dns_failure_reason  # per-scrape
from dns_exporter.metrics import dnsexp_dns_failures_total  # persistent
from dns_exporter.metrics import dnsexp_dns_queries_total  # persistent
from dns_exporter.metrics import dnsexp_dns_record_ttl_seconds  # per-scrape
from dns_exporter.metrics import dnsexp_dns_responses_total  # persistent
from dns_exporter.metrics import dnsexp_dns_success  # per-scrape
from dns_exporter.metrics import dnsexp_dns_time_seconds  # per-scrape
from dns_exporter.metrics import dnsexp_http_requests_total  # persistent
from dns_exporter.metrics import dnsexp_http_responses_total  # persistent
from dns_exporter.metrics import dnsexp_registry

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

# define the info metric with the build version
dnsexp_build_version = Info("dnsexp_build_version", "The version of dns_exporter")
dnsexp_build_version.info({"version": __version__})

# initialise logger initially at info level
logger = logging.getLogger("dns_exporter")

INDEX = """<!DOCTYPE html>
<html lang="en-US">
<html lang="en">
<head><title>DNS Exporter</title></head>
<body>
<h1>DNS Exporter</h1>
<p>Visit <a href="/query?target=dns.google&protocol=doh&query_name=example.com">/query?target=dns.google&protocol=doh&query_name=example.com</a> to do a DNS query and see metrics.</p>
<p>To debug configuration issues replace /query with /config to see the effective parsed configuration:</p>
<p>Visit <a href="/config?target=dns.google&protocol=doh&query_name=example.com">/config?target=dns.google&protocol=doh&query_name=example.com</a> to do a DNS query and see metrics.</p>
<p>Visit <a href="/metrics">/metrics</a> to see metrics for the dns_exporter itself.</p>
</body>
</html>"""


class DNSExporter(MetricsHandler):
    """Primary dns_exporter class.

    MetricsHandler subclass for incoming scrape requests. Initiated on each
    request as a handler by http.server.HTTPServer().

    The configure() classmethod can optionally be called to load configs before use.

    Attributes:
        configs: A dict of dns_exporter.config.Config instances to be used in scrape requests.
    """

    # the configs key is populated by configure() before the class is initialised
    configs: dict[str, Config] = {}

    @classmethod
    def configure(
        cls,
        configs: dict[str, ConfigDict] = {},
    ) -> bool:
        """Validate and create Config objects.

        Takes a dict of ConfigDict objects and runs cls.prepare_config() on each
        before creating a Config object and adding it to cls.configs

        If an error is encountered the process stops but configs loaded until the
        failure can still be used in cls.configs.

        Args:
            configs: A dict of names and corresponding ConfigDict objects.

        Returns:
            bool: True if all ConfigDict objects was validated and loaded OK, False
                if an error was encountered.
        """
        prepared: t.Optional[ConfigDict]
        for name, config in configs.items():
            prepared = cls.prepare_config(ConfigDict(**config))  # type: ignore
            if not prepared:
                # there is an issue with this config
                return False
            try:
                cls.configs[name] = Config.create(name=name, **prepared)
            except TypeError:
                logger.exception(f"Unable to parse config {prepared}")
                return False

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

    @classmethod
    def prepare_config(cls, config: ConfigDict) -> t.Optional[ConfigDict]:
        """Make sure the configdict has the right types and objects."""
        # create RRValidator objects
        if "validate_answer_rrs" in config.keys() and not isinstance(
            config["validate_answer_rrs"], RRValidator
        ):
            config["validate_answer_rrs"] = RRValidator.create(
                **config["validate_answer_rrs"]
            )

        if "validate_authority_rrs" in config.keys() and not isinstance(
            config["validate_authority_rrs"], RRValidator
        ):
            config["validate_authority_rrs"] = RRValidator.create(
                **config["validate_authority_rrs"]
            )

        if "validate_additional_rrs" in config.keys() and not isinstance(
            config["validate_additional_rrs"], RRValidator
        ):
            config["validate_additional_rrs"] = RRValidator.create(
                **config["validate_additional_rrs"]
            )

        # create RFValidator
        if "validate_response_flags" in config.keys() and not isinstance(
            config["validate_response_flags"], RFValidator
        ):
            config["validate_response_flags"] = RFValidator.create(
                **config["validate_response_flags"]
            )

        if (
            "ip" in config.keys()
            and config["ip"]
            and not isinstance(config["ip"], (IPv4Address, IPv6Address))
        ):
            # make an ip object
            try:
                config["ip"] = ipaddress.ip_address(config["ip"])
            except ValueError:
                logger.exception(f"Unable to parse IP address {config['ip']}")
                dnsexp_dns_success.set(0)
                dnsexp_dns_failure_reason.state("invalid_request_ip")
                logger.warning(
                    f"query failure, returning {dnsexp_dns_failure_reason._states[dnsexp_dns_failure_reason._value]}"
                )
                return None

        # parse target
        if (
            "target" in config.keys()
            and config["target"]
            and not isinstance(config["target"], urllib.parse.SplitResult)
            and "protocol" in config.keys()
        ):
            # parse target into a SplitResult
            config["target"] = cls.parse_target(
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
            dnsexp_dns_success.set(0)
            dnsexp_dns_failure_reason.state("invalid_request_query_name")
            logger.warning(
                f"query failure, returning {dnsexp_dns_failure_reason._states[dnsexp_dns_failure_reason._value]}"
            )
            return False

        return True

    def get_config(self, qs: dict[str, t.Union[str, list[str]]]) -> bool:
        """Construct the scrape config from defaults and values from the querystring."""
        # first get the defaults
        config = ConfigDict(**asdict(Config.create(name="defaults")))  # type: ignore

        # any configs specified in the querystring are applied in the order specified
        if "config" in qs:
            for template in qs["config"]:
                if template not in self.configs:
                    dnsexp_dns_success.set(0)
                    dnsexp_dns_failure_reason.state("invalid_request_config")
                    logger.warning(
                        f"query failure, returning {dnsexp_dns_failure_reason._states[dnsexp_dns_failure_reason._value]}"
                    )
                    return False
                config.update(asdict(self.configs[template]))
            del qs["config"]

        # and the querystring from the scrape request has highest precedence
        config.update(qs)

        # prepare config dict
        config = self.prepare_config(config)
        if not config:
            # config is not valid
            return False
        config.update(name="final")

        # create the config object
        try:
            self.config = Config.create(**config)
        except TypeError:
            # querystring contains unknown fields
            logger.warning(
                f"Scrape request querystring contains one or more unknown fields: {qs}"
            )
            dnsexp_dns_success.set(0)
            dnsexp_dns_failure_reason.state("invalid_request_config")
            logger.warning("queryset contains unknown fields")
            logger.warning(
                f"query failure, returning {dnsexp_dns_failure_reason._states[dnsexp_dns_failure_reason._value]}"
            )
            return False
        except ValueError as E:
            logger.warning("Config contains invalid values")
            dnsexp_dns_success.set(0)
            dnsexp_dns_failure_reason.state(E.args[1])
            logger.warning(
                f"query failure, returning {dnsexp_dns_failure_reason._states[dnsexp_dns_failure_reason._value]}"
            )
            return False

        # validate config
        if not self.validate_config():
            # config is not valid
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
          In the DoH https:// cases the url can be with or without a path.

        Parse it with urllib.parse.urlsplit and return the result.
        """
        if "://" not in target:
            target = f"{protocol}://{target}"
        splitresult = urllib.parse.urlsplit(target)
        if protocol == "doh" and not splitresult.path:
            # use the default DoH path
            splitresult = urllib.parse.urlsplit(
                urllib.parse.urlunsplit(
                    splitresult._replace(path="/dns-query", scheme="https")
                )
            )
        return splitresult

    def validate_target_ip(self) -> bool:
        """Validate the target and resolve IP if needed."""
        # do we have a target?
        if not self.config.target:
            dnsexp_dns_success.set(0)
            dnsexp_dns_failure_reason.state("invalid_request_target")
            logger.warning(
                f"query failure, returning {dnsexp_dns_failure_reason._states[dnsexp_dns_failure_reason._value]}"
            )
            return False

        assert isinstance(self.config.target, urllib.parse.SplitResult)  # mypy
        # do we already have an IP in the config?
        if self.config.ip:
            logger.debug(f"checking ip {self.config.ip} of type {type(self.config.ip)}")

            # make sure the ip matches the configured address family
            if not self.check_ip_family(ip=self.config.ip, family=self.config.family):
                # ip and family mismatch
                dnsexp_dns_success.set(0)
                dnsexp_dns_failure_reason.state("invalid_request_ip")
                logger.warning("IP family mismatch!")
                logger.warning(
                    f"query failure, returning {dnsexp_dns_failure_reason._states[dnsexp_dns_failure_reason._value]}"
                )
                return False

            # self.config.target.hostname can be either a hostname or an ip,
            # if it is an ip make sure there is no conflict with ip arg
            try:
                targetip = ipaddress.ip_address(str(self.config.target.hostname))
                if targetip != self.config.ip:
                    dnsexp_dns_success.set(0)
                    dnsexp_dns_failure_reason.state("invalid_request_ip")
                    logger.warning(
                        f"query failure, returning {dnsexp_dns_failure_reason._states[dnsexp_dns_failure_reason._value]}"
                    )
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
                resolved = self.resolve_ip_getaddrinfo(
                    hostname=str(self.config.target.hostname),
                    family=str(self.config.family),
                )
                if not resolved:
                    dnsexp_dns_success.set(0)
                    dnsexp_dns_failure_reason.state("invalid_request_target")
                    logger.warning("Unable to resolve target DNS server hostname")
                    logger.warning(
                        f"query failure, returning {dnsexp_dns_failure_reason._states[dnsexp_dns_failure_reason._value]}"
                    )
                    return False
                self.config.ip = ipaddress.ip_address(resolved)
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
        except socket.gaierror:
            logger.error(f"Unable to resolve server hostname {hostname}")
            dnsexp_dns_success.set(0)
            dnsexp_dns_failure_reason.state("invalid_request_target")
            logger.warning(
                f"query failure, returning {dnsexp_dns_failure_reason._states[dnsexp_dns_failure_reason._value]}"
            )
        return None

    def get_dnsexp_response(
        self,
        protocol: str,
        target: urllib.parse.SplitResult,
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
                f"doing UDP lookup with server {target.netloc} (using IP {ip}) port {port} and query {query.question}"
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
                f"doing TCP lookup with server {target.netloc} (using IP {ip}) port {port} and query {query.question}"
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
                f"doing UDP>TCP lookup with server {target.netloc} (using IP {ip}) port {port} and query {query.question}"
            )
            # TODO maybe create a label for transport protocol = tcp or udp?
            r, tcp = dns.query.udp_with_fallback(  # type: ignore
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
                f"doing DoT lookup with server {target.netloc} (using IP {ip}) port {port} and query {query.question}"
            )
            r = dns.query.tls(
                q=query,
                where=str(ip),
                port=port,
                server_hostname=target.hostname,
                timeout=timeout,
                one_rr_per_rrset=True,
            )

        elif protocol == "doh":
            # DoH query, use the url for where= and use bootstrap_address= for the ip
            url = f"https://{target.hostname}{target.path}"
            logger.debug(
                f"doing DoH lookup with url {url} (using IP {ip}) port {port} and query {query.question}"
            )
            r = dns.query.https(  # type: ignore
                q=query,
                where=url,
                bootstrap_address=str(ip),
                port=port,
                timeout=timeout,
                one_rr_per_rrset=True,
            )

        elif protocol == "doq":
            # DoQ query, TODO figure out how to override IP for DoQ
            logger.debug(
                f"doing DoQ lookup with server {target} (using IP {ip}) port {port} and query {query.question}"
            )
            r = dns.query.quic(q=query, where=target, port=port, timeout=timeout, one_rr_per_rrset=True)  # type: ignore
            transport = "UDP"
        return r, transport

    def validate_dnsexp_response(self, response: Message) -> bool:
        """Validate the DNS response using the validation config in the config."""
        # do we want to validate the response rcode?
        rcode = dns.rcode.to_text(response.rcode())  # type: ignore
        if self.config.valid_rcodes and rcode not in self.config.valid_rcodes:
            logger.debug(f"rcode {rcode} not in {self.config.valid_rcodes}")
            dnsexp_dns_failure_reason.state("invalid_response_rcode")
            logger.warning(
                f"query failure, returning {dnsexp_dns_failure_reason._states[dnsexp_dns_failure_reason._value]}"
            )
            return False

        # do we want to validate flags?
        if self.config.validate_response_flags:
            # we need a nice list of flags as text like ["QR", "AD"]
            flags = dns.flags.to_text(response.flags).split(" ")  # type: ignore

            if self.config.validate_response_flags.fail_if_any_present:
                for flag in self.config.validate_response_flags.fail_if_any_present:
                    # if either of these flags is found in the response we fail
                    if flag in flags:
                        dnsexp_dns_failure_reason.state("invalid_response_flags")
                        logger.warning(
                            f"query failure, returning {dnsexp_dns_failure_reason._states[dnsexp_dns_failure_reason._value]}"
                        )
                        return False

            if self.config.validate_response_flags.fail_if_all_present:
                for flag in self.config.validate_response_flags.fail_if_all_present:
                    # if all these flags are found in the response we fail
                    if flag not in flags:
                        break
                else:
                    # all the flags are present
                    dnsexp_dns_failure_reason.state("invalid_response_flags")
                    logger.warning(f"flag {flags}")
                    logger.warning(
                        f"query failure, returning {dnsexp_dns_failure_reason._states[dnsexp_dns_failure_reason._value]}"
                    )
                    return False

            if self.config.validate_response_flags.fail_if_any_absent:
                for flag in self.config.validate_response_flags.fail_if_any_absent:
                    # if any of these flags is missing from the response we fail
                    if flag not in flags:
                        dnsexp_dns_failure_reason.state("invalid_response_flags")
                        logger.warning(
                            f"query failure, returning {dnsexp_dns_failure_reason._states[dnsexp_dns_failure_reason._value]}"
                        )
                        return False

            if self.config.validate_response_flags.fail_if_all_absent:
                for flag in self.config.validate_response_flags.fail_if_all_absent:
                    # if all these flags are missing from the response we fail
                    if flag in flags:
                        break
                else:
                    # all the flags are missing
                    dnsexp_dns_failure_reason.state("invalid_response_flags")
                    logger.warning(
                        f"query failure, returning {dnsexp_dns_failure_reason._states[dnsexp_dns_failure_reason._value]}"
                    )
                    return False

        # do we want response rr validation?
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
                                # we have a match
                                dnsexp_dns_failure_reason.state(
                                    f"invalid_response_{section}_rrs"
                                )
                                logger.warning(
                                    f"query failure, returning {dnsexp_dns_failure_reason._states[dnsexp_dns_failure_reason._value]}"
                                )
                                return False

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
                                dnsexp_dns_failure_reason.state(
                                    f"invalid_response_{section}_rrs"
                                )
                                logger.warning(
                                    f"query failure, returning {dnsexp_dns_failure_reason._states[dnsexp_dns_failure_reason._value]}"
                                )
                                return False

                if validators.fail_if_not_matches_regexp:
                    logger.debug(
                        f"fail_if_not_matches_regexp validating rrs from {section} section: {rrs}..."
                    )
                    for regex in validators.fail_if_not_matches_regexp:
                        p = re.compile(regex)
                        for rr in rrs:
                            m = p.match(str(rr))
                            if not m:
                                # no match so we fail
                                dnsexp_dns_failure_reason.state(
                                    f"invalid_response_{section}_rrs"
                                )
                                logger.warning(
                                    f"query failure, returning {dnsexp_dns_failure_reason._states[dnsexp_dns_failure_reason._value]}"
                                )
                                return False

                if validators.fail_if_none_matches_regexp:
                    logger.debug(
                        f"fail_if_none_matches_regexp validating rrs from {section} section: {rrs}..."
                    )
                    for regex in validators.fail_if_none_matches_regexp:
                        p = re.compile(regex)
                        for rr in rrs:
                            print(f"matching rr {rr} with regex {regex} ...")
                            m = p.match(str(rr))
                            if m:
                                # we have a match for this rr, break out of the loop
                                break
                        else:
                            # none of the rrs match this regex
                            logger.warning(
                                f"query failure, returning {dnsexp_dns_failure_reason._states[dnsexp_dns_failure_reason._value]}"
                            )
                            dnsexp_dns_failure_reason.state(
                                f"invalid_response_{section}_rrs"
                            )
                            return False

        # all validation ok
        return True

    def send_metric_response(
        self,
        registry: Union[CollectorRegistry, RestrictedRegistry],
        query: dict[str, t.Union[str, list[str]]],
    ) -> None:
        """Bake and send output from the provided registry and querystring."""
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
        dnsexp_http_responses_total.labels(path=self.url.path, response_code=200).inc()
        return None

    def do_GET(self) -> None:
        """Handle incoming scrape requests."""
        # first parse the scrape request url and querystring,
        # make them available as self.url and self.qs
        self.parse_querystring()
        dnsexp_http_requests_total.labels(path=self.url.path).inc()

        # /query is for doing a DNS query, it returns metrics about just that one dns query
        if self.url.path == "/query" or self.url.path == "/config":
            logger.debug(
                f"Got {self.url.path} request from client {self.client_address}"
            )
            # this is a scrape request, prepare for doing a new dns query
            # clear the metrics, we don't want any history
            dnsexp_dns_time_seconds.clear()
            dnsexp_dns_failure_reason.clear()
            dnsexp_dns_record_ttl_seconds.clear()

            # build and validate configuration for this scrape from defaults, config file and request querystring
            if not self.get_config(qs=self.qs):
                # something is wrong, reason was already set, just return
                self.send_metric_response(registry=dnsexp_registry, query=self.qs)
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
                "target": str(self.config.target.geturl()),
                "ip": str(self.config.ip),
                "port": str(port),
                "protocol": str(self.config.protocol),
                "family": str(self.config.family),
                "query_name": str(self.config.query_name),
                "query_type": str(self.config.query_type),
            }

            # prepare query
            qname = dns.name.from_text(self.config.query_name)
            q = dns.message.make_query(
                qname=qname,
                rdtype=str(self.config.query_type),
                rdclass=self.config.query_class,
            )

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
                    ednsargs["options"].append(
                        dns.edns.GenericOption(  # type: ignore
                            dns.edns.PADDING, bytes(int(self.config.edns_pad))
                        )
                    )
                # enable edns with the chosen options
                q.use_edns(edns=0, **ednsargs)  # type: ignore
                logger.debug(f"using edns options {ednsargs}")
            else:
                # do not use edns
                q.use_edns(edns=False)  # type: ignore
                logger.debug("not using edns")

            # set RD flag?
            if self.config.recursion_desired:
                q.flags |= dns.flags.RD

            # if this is a config check return now
            if self.url.path == "/config":
                logger.debug("returning config")
                self.send_response(200)
                self.end_headers()
                self.wfile.write(self.config.json().encode("utf-8"))
                return

            # do it
            assert isinstance(self.config.ip, (IPv4Address, IPv6Address))  # mypy
            r = None
            start = time.time()
            try:
                r, transport = self.get_dnsexp_response(
                    protocol=str(self.config.protocol),
                    target=self.config.target,
                    ip=self.config.ip,
                    port=port,
                    query=q,
                    timeout=float(str(self.config.timeout)),
                )
                logger.debug(
                    f"Protocol {self.config.protocol} got a DNS query response over {transport}"
                )
            except dns.exception.Timeout:
                # configured timeout was reached before we got a response
                dnsexp_dns_failure_reason.state("timeout")
                logger.warning(
                    f"query failure, returning {dnsexp_dns_failure_reason._states[dnsexp_dns_failure_reason._value]}"
                )
            except Exception:
                logger.exception(
                    f"Got an exception while looking up qname {self.config.query_name} using target {self.config.target}"
                )
                # unknown failure
                logger.warning(
                    f"query failure, returning {dnsexp_dns_failure_reason._states[dnsexp_dns_failure_reason._value]}"
                )
                dnsexp_dns_failure_reason.state("other_failure")
            # clock it
            qtime = time.time() - start

            if r is None:
                # we did not get a response :(
                dnsexp_dns_failures_total.inc()
                dnsexp_dns_success.set(0)
                self.send_metric_response(registry=dnsexp_registry, query=self.qs)
                logger.debug("Returning DNS query metrics - no response received :(")
                return

            # we got a response, increase the response counter
            dnsexp_dns_responses_total.inc()

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
                    "transport": transport,
                    "opcode": dns.opcode.to_text(r.opcode()),  # type: ignore
                    "rcode": dns.rcode.to_text(r.rcode()),  # type: ignore
                    "flags": " ".join(flags),
                    "answer": str(sum([len(rrset) for rrset in r.answer])),
                    "authority": str(len(r.authority)),
                    "additional": str(len(r.additional)),
                    "nsid": "no_nsid",
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
            dnsexp_dns_time_seconds.labels(**labels).observe(qtime)

            # register TTL of response RRs
            for section in ["answer", "authority", "additional"]:
                rrsets = getattr(r, section)
                for rrset in rrsets:
                    rr = rrset[0]
                    labels.update(
                        {
                            "rr_section": section,
                            "rr_name": rrset.name,
                            "rr_type": dns.rdatatype.to_text(rr.rdtype),  # type: ignore
                            "rr_value": rr.to_text()[:255],
                        }
                    )
                    dnsexp_dns_record_ttl_seconds.labels(**labels).observe(rrset.ttl)

            # validate response
            success = self.validate_dnsexp_response(response=r)
            if not success:
                # increase the global failure counter
                dnsexp_dns_failures_total.inc()

            # register success or not
            dnsexp_dns_success.set(success)
            # send the response
            self.send_metric_response(registry=dnsexp_registry, query=self.qs)
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
            dnsexp_http_responses_total.labels(path="/", response_code=200).inc()
            logger.debug("Returning index page for request to /")

        # unknown endpoint
        else:
            self.send_response(404)
            self.end_headers()
            self.wfile.write("404 not found".encode("utf-8"))
            dnsexp_http_responses_total.labels(
                path=self.url.path, response_code=404
            ).inc()
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
        default="INFO",
    )
    parser.add_argument(
        "-p",
        "--port",
        dest="port",
        type=int,
        help="The port the exporter should listen for requests on. Default: 15353",
        default=15353,
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
    # get arpparser and parse args
    parser, args = parse_args(mockargs)

    # handle version check
    if hasattr(args, "version"):
        print(f"dns_exporter version {__version__}")
        sys.exit(0)

    # configure the log format and level
    console_logformat = "%(asctime)s dns_exporter %(levelname)s DNSExporter.%(funcName)s():%(lineno)i:  %(message)s"
    level = getattr(args, "log-level")
    logging.basicConfig(
        level=level,
        format=console_logformat,
        datefmt="%Y-%m-%d %H:%M:%S %z",
    )
    logger.setLevel(level)
    logger.info(f"dns_exporter v{__version__} starting up - logging at level {level}")

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
    handler = DNSExporter
    if configfile["configs"]:
        if not handler.configure(
            configs={k: ConfigDict(**v) for k, v in configfile["configs"].items()}  # type: ignore
        ):
            logger.error(
                "An error occurred while configuring dns_exporter. Bailing out."
            )
            sys.exit(1)
    logger.debug(f"Starting listener on 127.0.0.1 port {args.port}...")
    HTTPServer(("127.0.0.1", args.port), handler).serve_forever()


if __name__ == "__main__":
    main()

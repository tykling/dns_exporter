"""dns_exporter is a blackbox-style Prometheus exporter for DNS."""
import argparse
import ipaddress
import logging
import random
import re
import socket
import sys
import time
import urllib.parse
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
logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)
ch = logging.StreamHandler()
ch.setLevel(logging.DEBUG)
formatter = logging.Formatter("%(asctime)s - %(name)s - %(levelname)s - %(message)s")
ch.setFormatter(formatter)
logger.addHandler(ch)
logger.info(f"dns_exporter v{__version__} starting up")

# create seperate registry for the dns query metrics
dns_registry = CollectorRegistry()

# define the timing histogram
QUERY_TIME = Histogram(
    "dns_query_time_seconds",
    "DNS query time in seconds.",
    [
        "target",
        "protocol",
        "family",
        "query_name",
        "query_type",
        "ip",
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
        "invalid_request_module",
        "invalid_request_target",
        "invalid_request_family",
        "invalid_request_ip",
        "invalid_request_protocol",
        "timeout",
        "invalid_response_rcode",
        "invalid_response_flags",
        "invalid_response_answer_rrs",
        "invalid_response_authority_rrs",
        "invalid_response_additional_rrs",
        "other",
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
<p>Visit <a href="/query?target=dns.google&module=doh&query_name=example.com">/query?target=dns.google&module=doh&query_name=example.com</a> to do a DNS query and see metrics.</p>
<p>Visit <a href="/metrics">/metrics</a> to see metrics for the dns_exporter itself.</p>
</body>
</html>"""


class DNSRequestHandler(MetricsHandler):
    """MetricsHandler class for incoming scrape requests."""

    def parse_querystring(self) -> None:
        """Parse the incoming url and then the querystring."""
        # parse incoming request
        self.url = urllib.parse.urlsplit(self.path)
        # querystring values are all lists when returned from parse_qs(),
        # so take the first item only since we do not support multiple values.
        # behold, a valid usecase for dict comprehension
        qs = urllib.parse.parse_qs(self.url.query).items()
        self.qs: dict[str, str] = {k: v[0] for k, v in qs}

    def validate_request_querystring(
        self,
        query: dict[str, str],
        config: dict[str, Union[str, int, float, list[str], dict[str, str]]],
    ) -> bool:
        """Validate the incoming scrape HTTP request before doing the DNS query."""
        # do we have a module in the request?
        if "module" in query and ("modules" not in config or query["module"] not in config["modules"]):  # type: ignore
            logger.warning(
                "Scrape request contains a module '{query['module']}' but the module is unknown to this exporter."
            )
            QUERY_SUCCESS.set(0)
            QUERY_FAILURE.state("invalid_request_module")
            return False
        # all good
        return True

    def get_module(self, qs: dict[str, str]) -> None:
        """Construct the module from defaults, config file, and querystring."""
        # defaults have lowest precedence
        self.module: dict[
            str,
            Union[str, int, float, None, list[str], dict[str, Union[int, list[str]]]],
        ] = {
            "protocol": "udp",
            "query_type": "A",
            "query_class": "IN",
            "recursion_desired": True,
            "timeout": 5,
            "family": "ipv6",
            "edns": True,
            "edns_do": False,
            "edns_nsid": True,
            "edns_bufsize": 1232,
            "edns_pad": 0,
            "valid_rcodes": ["NOERROR"],
            "validate_response_flags": {},
            "validate_answer_rrs": {},
            "validate_authority_rrs": {},
            "validate_additional_rrs": {},
        }

        # the module from the config file has middle precedence,
        # if one was specified in the querystring
        if "module" in qs and hasattr(self, "config") and "modules" in self.config:
            self.module.update(self.config["modules"][qs["module"]])

        # and the querystring from the scrape request has highest precedence,
        # overruling values from defaults and module
        self.module.update(qs)
        return None

    def validate_module(self) -> bool:
        """Make sure the configuration module has all the required values."""
        # make sure protocol is valid
        if self.module["protocol"] not in ["udp", "tcp", "dot", "doh", "doq"]:
            QUERY_SUCCESS.set(0)
            QUERY_FAILURE.state("invalid_request_protocol")
            return False

        # make sure family is valid
        if self.module["family"] not in ["ipv4", "ipv6"]:
            QUERY_SUCCESS.set(0)
            QUERY_FAILURE.state("invalid_request_family")
            return False

        # make sure all bools are bools
        for key in ["recursion_desired", "edns", "edns_do", "edns_nsid"]:
            if not isinstance(self.module[key], bool):
                # we consider only the string "true" to mean True in url querystrings
                if self.module[key] == "true":
                    self.module[key] = True
                else:
                    self.module[key] = False

        # make sure all ints are ints
        for key in ["edns_bufsize", "edns_pad"]:
            if not isinstance(self.module[key], int):
                self.module[key] = int(self.module[key])  # type: ignore

        # make sure all floats are floats
        for key in ["timeout"]:
            if not isinstance(self.module[key], float):
                self.module[key] = float(self.module[key])  # type: ignore

        # do we already have an IP in the module?
        if "ip" in self.module.keys():
            # make sure we have a valid IP
            try:
                ip = ipaddress.ip_address(str(self.module["ip"]))
            except ValueError:
                QUERY_SUCCESS.set(0)
                QUERY_FAILURE.state("invalid_request_ip")
                return False
            # make sure the ip matches the configured address family
            if not self.check_ip_family(ip, str(self.module["family"])):
                # ip and family mismatch
                QUERY_SUCCESS.set(0)
                QUERY_FAILURE.state("invalid_request_ip")
                return False
        else:
            # we have no ip in the module, we need to get it from target
            self.module["ip"] = self.get_target_ip(
                target=str(self.module["target"]),
                family=str(self.module["family"]),
            )
            if self.module["ip"] is None:
                # unable to resolve target, bail out
                return False

        # we now know which IP we are using for this dns query
        logger.debug(f"Using target IP {self.module['ip']} for DNS query")

        # for DoH we need a valid URL in target
        if self.module["protocol"] == "doh":
            # TODO: this is the second time the target is parsed, be smarter about this somehow
            parsed_target = urllib.parse.urlsplit(str(self.module["target"]))
            if not parsed_target.hostname:
                # target is a hostname (not a URL), but protocol is DoH, so we need a proper URL,
                # https://github.com/rthalley/dnspython/issues/875
                # TODO: support custom URL endpoints here
                self.module["target"] = f"https://{self.module['target']}/dns-query"

        return True

    def check_ip_family(self, ip: Union[IPv4Address, IPv6Address], family: str) -> bool:
        """Make sure the IP matches the address family."""
        if ip.version == 4 and family == "ipv4":
            return True
        elif ip.version == 6 and family == "ipv6":
            return True
        return False

    def get_target_ip(self, target: str, family: str) -> Optional[str]:
        """Turn a target into an IP using a DNS lookup if needed.

        If target is a hostname or URL the hostname must be resolved.

        In the cases where this method does not return an IP it sets the
        QUERY_SUCCESS and QUERY_FAILURE metrics before returning.
        """
        # first try parsing target as an IP address
        ip: Optional[Union[IPv4Address, IPv6Address, str]]
        try:
            ip = ipaddress.ip_address(target)
            if self.check_ip_family(ip, family):
                return str(ip)
            else:
                QUERY_SUCCESS.set(0)
                QUERY_FAILURE.state("invalid_request_ip")
                return None
        except ValueError:
            pass

        # target is not a valid IP, it could be either a url or a hostname,
        # first try parsing as a url
        parsed_target = urllib.parse.urlsplit(target)
        if parsed_target.hostname:
            logger.debug(
                f"target is a url, resolving hostname {parsed_target.hostname} ..."
            )
            # target is a url, resolve the hostname
            ip = self.resolve_ip_getaddrinfo(
                hostname=parsed_target.hostname,
                family=family,
            )
            if not ip:
                QUERY_SUCCESS.set(0)
                QUERY_FAILURE.state("invalid_request_target")
        else:
            logger.debug(f"target might be a hostname, resolving hostname {target} ...")
            # target is not a url, it must be a hostname, try a DNS lookup
            ip = self.resolve_ip_getaddrinfo(
                hostname=target,
                family=family,
            )
        return ip

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
        self, protocol: str, target: str, ip: str, query: Message, timeout: float
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
                f"doing UDP lookup with server {target} (using IP {ip}) and query {query.question}"
            )
            r = dns.query.udp(q=query, where=ip, timeout=timeout)

        elif protocol == "tcp":
            # plain TCP lookup, nothing fancy here
            logger.debug(
                f"doing TCP lookup with server {target} (using IP {ip}) and query {query.question}"
            )
            r = dns.query.tcp(q=query, where=ip, timeout=timeout)

        elif protocol == "dot":
            # DoT query, use the ip for where= and set tls hostname with server_hostname=
            logger.debug(
                f"doing DoT lookup with server {target} (using IP {ip}) and query {query.question}"
            )
            r = dns.query.tls(
                q=query,
                where=ip,
                server_hostname=target,
                timeout=timeout,
            )

        elif protocol == "doh":
            # DoH query, use the url for where= and use bootstrap_address= for the ip
            logger.debug(
                f"doing DoH lookup with server {target} (using IP {ip}) and query {query.question}"
            )
            # TODO https://github.com/rthalley/dnspython/issues/875
            # r = dns.query.https(q=q, where=target, bootstrap_address=ip, **qarg
            r = dns.query.https(q=query, where=target, timeout=timeout)

        elif protocol == "doq":
            # DoQ query, TODO figure out how to override IP for DoQ
            logger.debug(
                f"doing DoQ lookup with server {target} (using IP {ip}) and query {query.question}"
            )
            r = dns.query.quic(q=query, where=ip, timeout=timeout)  # type: ignore
        return r

    def validate_dns_response(self, response: Message) -> bool:
        """Validate the DNS response using the validation config in the module."""
        # do we want to validate the response rcode?
        rcode = dns.rcode.to_text(response.rcode())  # type: ignore
        assert isinstance(self.module["valid_rcodes"], list)
        if self.module["valid_rcodes"] and rcode not in self.module["valid_rcodes"]:
            logger.debug(f"rcode {rcode} not in {self.module['valid_rcodes']}")
            QUERY_FAILURE.state("invalid_response_rcode")
            return False

        # do we want to validate flags?
        if self.module["validate_response_flags"]:
            assert isinstance(self.module["validate_response_flags"], dict)  # mypy
            # we need a nice list of flags as text like ["QR", "AD"]
            flags = dns.flags.to_text(response.flags).split(" ")  # type: ignore

            if "fail_if_any_present" in self.module["validate_response_flags"]:
                assert isinstance(
                    self.module["validate_response_flags"]["fail_if_any_present"], list
                )
                for flag in self.module["validate_response_flags"][
                    "fail_if_any_present"
                ]:
                    # if either of these flags is found in the response we fail
                    if flag in flags:
                        QUERY_FAILURE.state("invalid_response_flags")
                        return False

            if "fail_if_all_present" in self.module["validate_response_flags"]:
                assert isinstance(
                    self.module["validate_response_flags"]["fail_if_all_present"], list
                )
                for flag in self.module["validate_response_flags"][
                    "fail_if_all_present"
                ]:
                    # if all these flags are found in the response we fail
                    if flag not in flags:
                        break
                else:
                    # all the flags are present
                    QUERY_FAILURE.state("invalid_response_flags")
                    return False

            if "fail_if_any_absent" in self.module["validate_response_flags"]:
                assert isinstance(
                    self.module["validate_response_flags"]["fail_if_any_absent"], list
                )
                for flag in self.module["validate_response_flags"][
                    "fail_if_any_absent"
                ]:
                    # if any of these flags is missing from the response we fail
                    if flag not in flags:
                        QUERY_FAILURE.state("invalid_response_flags")
                        return False

            if "fail_if_all_absent" in self.module["validate_response_flags"]:
                assert isinstance(
                    self.module["validate_response_flags"]["fail_if_all_absent"], list
                )
                for flag in self.module["validate_response_flags"][
                    "fail_if_all_absent"
                ]:
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
                rrs = [rr for rrset in rrsets for rr in rrset]
            else:
                rrs = getattr(response, section)
            if self.module[key]:
                assert isinstance(self.module[key], dict)
                validators: dict[str, list[str]] = self.module[key]  # type: ignore
                if "fail_if_matches_regexp" in validators:
                    for regex in validators["fail_if_matches_regexp"]:
                        p = re.compile(regex)
                        for rr in rrs:
                            m = p.match(rr)
                            if m:
                                # we have a match
                                QUERY_FAILURE.state(f"invalid_response_{section}_rrs")
                                return False

                if "fail_if_all_match_regexp" in validators:
                    for regex in validators["fail_if_all_match_regexp"]:
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

                if "fail_if_not_matches_regexp" in validators:
                    for regex in validators["fail_if_not_matches_regexp"]:
                        p = re.compile(regex)
                        for rr in rrs:
                            m = p.match(rr)
                            if not m:
                                # no match so we fail
                                QUERY_FAILURE.state(f"invalid_response_{section}_rrs")
                                return False

                if "fail_if_none_matches_regexp" in validators:
                    for regex in validators["fail_if_none_matches_regexp"]:
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
        query: dict[str, str],
        skip_metrics: Optional[list[str]] = [],
    ) -> None:
        """Bake and send output from the provided registry and querystring."""
        # do we want to include QUERY_FAILURE enum?
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
            # this is a scrape request, prepare for doing a new dns query
            # clear the metrics, we don't want any history
            QUERY_TIME.clear()
            QUERY_FAILURE.clear()

            # validate the scrape request and bail out if any issues are found
            assert hasattr(self, "config")  # mypy
            if not self.validate_request_querystring(query=self.qs, config=self.config):
                # the validate method already did everything needed so just return
                logger.warning("invalid querystring, scrape failed")
                self.send_metric_response(registry=dns_registry, query=self.qs)
                return

            logger.debug(f"Got scrape request from client {self.client_address}")
            # assemble module (configuration for this scrape) from defaults, config file and request
            self.get_module(qs=self.qs)
            if not self.validate_module():
                # something is not right with the module config
                logger.warning("invalid module config, scrape failed")
                self.send_metric_response(registry=dns_registry, query=self.qs)
                return

            # module is ready for action,
            # begin the labels dict
            labels: dict[str, str] = {
                "target": str(self.module["target"]),
                "ip": str(self.module["ip"]),
                "protocol": str(self.module["protocol"]),
                "family": str(self.module["family"]),
                "query_name": str(self.module["query_name"]),
                "query_type": str(self.module["query_type"]),
            }

            # prepare query
            qname = dns.name.from_text(self.module["query_name"])
            q = dns.message.make_query(
                qname=qname, rdtype=str(self.module["query_type"])
            )

            # use EDNS?
            if self.module["edns"]:
                # we want edns
                ednsargs: dict[
                    str, Union[str, int, bool, list[dns.edns.GenericOption]]
                ] = {"options": []}
                # do we want the DO bit?
                if self.module["edns_do"]:
                    ednsargs["ednsflags"] = dns.flags.DO
                # do we want nsid?
                if self.module["edns_nsid"]:
                    assert isinstance(ednsargs["options"], list)
                    ednsargs["options"].append(dns.edns.GenericOption(dns.edns.NSID, ""))  # type: ignore
                # do we need to set bufsize/payload?
                if self.module["edns_bufsize"]:
                    assert isinstance(self.module["edns_bufsize"], int)
                    # dnspython calls bufsize "payload"
                    ednsargs["payload"] = int(self.module["edns_bufsize"])
                # do we want padding?
                if self.module["edns_pad"]:
                    assert isinstance(self.module["edns_pad"], int)
                    ednsargs["pad"] = int(self.module["edns_pad"])
                # enable edns with the chosen options
                q.use_edns(edns=0, **ednsargs)  # type: ignore
                logger.debug(f"using edns options {ednsargs}")
            else:
                # do not use edns
                q.use_edns(edns=False)  # type: ignore
                logger.debug("not using edns")

            # do it
            r = None
            start = time.time()
            try:
                r = self.get_dns_response(
                    protocol=str(self.module["protocol"]),
                    target=str(self.module["target"]),
                    ip=str(self.module["ip"]),
                    query=q,
                    timeout=float(str(self.module["timeout"])),
                )
                logger.debug("Got a DNS query response!")
            except dns.exception.Timeout:
                # configured timeout was reached before we got a response
                QUERY_FAILURE.state("timeout")
                logger.error("DNS query timeout was reached")
            except Exception:
                logger.exception(
                    f"Got an exception while module {self.qs['module']} was looking up qname {self.module['query_name']} using target {self.module['target']}"
                )
                # unknown failure
                QUERY_FAILURE.state("other")
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
            skip_metrics = []
            if success:
                # skip the failure reason enum when rendering metrics
                skip_metrics.append("dns_query_failure_reason")
            else:
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
        help="The path to the yaml config file to use. Only the root 'modules' key is read from the config file.",
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
    # get arpparser and parse args
    parser, args = parse_args(mockargs)

    # handle a couple of special cases before reading config
    if hasattr(args, "version"):
        print(f"dns_exporter version {__version__}")
        sys.exit(0)

    if hasattr(args, "config-file"):
        with open(getattr(args, "config-file"), "r") as f:
            try:
                config = yaml.load(f, Loader=yaml.SafeLoader)
            except Exception:
                logger.exception(
                    f"Unable to parse YAML config file {getattr(args, 'config-file')} - bailing out."
                )
                sys.exit(1)
        if (
            not config
            or "modules" not in config
            or not isinstance(config["modules"], dict)
            or not config["modules"]
        ):
            # config is empty, missing "modules" key, or modules is empty or not a dict
            logger.error(
                f"Invalid config file {getattr(args, 'config-file')} - yaml was valid but no modules found"
            )
            sys.exit(1)
        logger.debug(
            f"The following modules were loaded from config file {getattr(args, 'config-file')}: {list(config['modules'].keys())}"
        )
    else:
        # we have no config file
        config = {}
        logger.debug("No -c / --config-file found so a config file will not be used.")

    # initialise handler and start HTTPServer
    handler = DNSRequestHandler
    handler.config = config  # type: ignore
    HTTPServer(("127.0.0.1", 15353), handler).serve_forever()


if __name__ == "__main__":
    main()

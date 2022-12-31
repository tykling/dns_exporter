"""dns_exporter is a blackbox-style Prometheus exporter for DNS."""
import ipaddress
import logging
import random
import socket
import sys
import time
import urllib.parse
from http.server import HTTPServer
from ipaddress import IPv4Address, IPv6Address
from socket import AddressFamily, SocketKind
from typing import Optional, Tuple, Union

import dns.edns
import dns.exception
import dns.opcode
import dns.query
import dns.rcode
import dns.resolver
import yaml
from dns.message import Message
from prometheus_client import (
    CollectorRegistry,
    Counter,
    Gauge,
    Histogram,
    MetricsHandler,
    exposition,
)

GetAddrInfoReturnType = Tuple[AddressFamily, SocketKind, int, str, Tuple[str, int]]

logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)
ch = logging.StreamHandler()
ch.setLevel(logging.DEBUG)

# create formatter
formatter = logging.Formatter("%(asctime)s - %(name)s - %(levelname)s - %(message)s")

# add formatter to ch
ch.setFormatter(formatter)

# add ch to logger
logger.addHandler(ch)

logger.debug("debug message")
logger.info("info message")
logger.warning("warn message")
logger.error("error message")
logger.critical("critical message")

dns_registry = CollectorRegistry()

QTIME = Histogram(
    "dns_query_time_seconds",
    "DNS query time in seconds.",
    [
        "target",
        "protocol",
        "query_name",
        "query_type",
        "ip",
        "opcode",
        "rcode",
        "nsid",
        "answer",
        "authority",
        "additional",
    ],
    registry=dns_registry,
)

SUCCESS = Gauge(
    "probe_success",
    "Was the DNS query successful or not, 1 for success or 0 for failure.",
    [
        "target",
        "protocol",
    ],
    registry=dns_registry,
)

# metrics for the exporter itself
QUERIES = Counter("dns_queries_total", "DNS queries total.")
FAILURES = Counter("dns_query_failures_total", "DNS queries failed total.")


class DNSRequestHandler(MetricsHandler):
    """MetricsHandler class for incoming scrape requests."""

    def do_GET(self) -> None:
        """Handle incoming scrape requests."""
        # first parse the scrape request url and querystring,
        # made available as self.url and self.qs
        self.parse_querystring()

        # /query is for doing DNS lookups, /metrics is for this exporters own metrics
        if self.url.path == "/query":
            # validate the scrape request and bail out if any issues are found
            if not self.validate_query_request(query=self.qs, config=config):
                return

            # assemble module from defaults, config file and request
            self.get_module(qs=self.qs)
            if not self.validate_module():
                return

            # do we already have an IP in the module?
            if "ip" not in self.module.keys():
                self.module["ip"] = self.get_target_ip(
                    target=str(self.module["target"]),
                    force_address_family=str(self.module["force_address_family"]),
                )
                if self.module["ip"] is None:
                    # unable to resolve target, bail out
                    SUCCESS.labels(
                        target=self.module["target"], protocol=self.qs["module"]
                    ).set(False)
                    return
            logger.debug(f"Using target IP {self.module['ip']} for DNS query")

            # for DoH we need a valid URL in target
            # TODO: support custom URL endpoints here
            if self.module["protocol"] == "doh":
                # target is a hostname, but protocol is DoH, so we need a proper url
                # https://github.com/rthalley/dnspython/issues/875
                self.module["target"] = f"https://{self.module['target']}/dns-query"

            # module is ready for action,
            # begin the labels dict
            labels: dict[str, str] = {
                "target": str(self.module["target"]),
                "protocol": str(self.module["protocol"]),
                "query_name": str(self.module["query_name"]),
                "query_type": str(self.module["query_type"]),
            }

            # prepare query
            qname = dns.name.from_text(self.module["query_name"])
            q = dns.message.make_query(
                qname=qname, rdtype=str(self.module["query_type"])
            )
            # TODO: make EDNS configurable, for now always enable NSID
            q.use_edns(  # type: ignore
                payload=4096, options=[dns.edns.GenericOption(dns.edns.NSID, "")]  # type: ignore
            )

            # do it
            start = time.time()
            try:
                r = self.get_response(
                    protocol=str(self.module["protocol"]),
                    target=str(self.module["target"]),
                    ip=str(self.module["ip"]),
                    query=q,
                    timeout=float(str(self.module["timeout"])),
                )
            except Exception:
                logger.exception(
                    f"Got an exception while module {self.qs['module']} was looking up qname {self.module['query_name']} using target {self.module['target']}"
                )
                r = None
            qtime = time.time() - start

            # increase the query counter (regardless of the outcome)
            QUERIES.inc()

            # was the query a success?
            success = True
            if r is None:
                # we got an exception and no response
                success = False
            elif dns.rcode.to_text(r.rcode()) not in self.module["valid_rcodes"]:  # type: ignore
                # rcode was not as expected
                success = False

            # count failure
            if not success:
                FAILURES.inc()

            if r is not None:
                # make mypy happy
                assert hasattr(r, "options")
                assert hasattr(r, "opcode")
                assert hasattr(r, "rcode")
                assert hasattr(r, "answer")
                assert hasattr(r, "authority")
                assert hasattr(r, "additional")

                labels.update(
                    {
                        "ip": str(self.module["ip"]),
                        "opcode": dns.opcode.to_text(r.opcode()),  # type: ignore
                        "rcode": dns.rcode.to_text(r.rcode()),  # type: ignore
                        "answer": str(len(r.answer)),
                        "authority": str(len(r.authority)),
                        "additional": str(len(r.additional)),
                    }
                )

                # did we get nsid?
                for opt in r.options:
                    if opt.otype == dns.edns.NSID:
                        # treat as ascii, we need text for prom labels
                        labels.update({"nsid": opt.data.decode("ASCII")})
                        break

                # timing metric
                QTIME.clear()
                QTIME.labels(**labels).observe(qtime)

            SUCCESS.clear()
            SUCCESS.labels(
                target=self.module["target"], protocol=self.module["protocol"]
            ).set(success)
            self.send_output(registry=dns_registry, query=self.qs)
            return
        elif self.url.path == "/metrics":
            self.send_output(registry=self.registry, query=self.qs)
            return
        elif self.url.path == "/":
            # return a basic index page
            self.send_response(200)
            self.end_headers()
            self.wfile.write(
                """<html>
            <head><title>DNS Exporter</title></head>
            <body>
            <h1>DNS Exporter</h1>
            <p>Visit <a href="/query?target=dns.google&module=doh&query_name=example.com">/query?target=dns.google&module=doh&query_name=example.com</a> to do a DNS query and see metrics.</p>
            <p>Visit <a href="/metrics">/metrics</a> to see metrics for dns_exporter.</p>
            </body>
            </html>""".encode(
                    "utf-8"
                )
            )
        else:
            self.send_response(404)
            self.end_headers()
            return None

    def parse_querystring(self) -> None:
        """Parse the incoming url and then the querystring."""
        # parse incoming request
        self.url = urllib.parse.urlsplit(self.path)
        # querystring values are all lists, so take the first item only,
        # behold, a valid usecase for dict comprehension:
        self.qs: dict[str, str] = {
            k: v[0] for k, v in urllib.parse.parse_qs(self.url.query).items()
        }

    def validate_query_request(
        self,
        query: dict[str, str],
        config: dict[str, Union[str, int, float, list[str], dict[str, str]]],
    ) -> bool:
        """Validate the incoming request before doing the DNS lookup."""
        # do we have a module in the request?
        if "module" not in query or query["module"] not in config["modules"]:  # type: ignore
            self.send_error_response(
                [
                    "No module or invalid module specified.\n",
                    f"Available modules: {','.join(config['modules']).keys()}.\n",  # type: ignore
                ]
            )
            return False

        if "target" not in query:
            self.send_error_response(["No target specified."])
            return False

        # all good
        return True

    def get_module(self, qs: dict[str, str]) -> None:
        """Construct the module from defaults, config file, and querystring."""
        # get defaults
        self.module: dict[str, Union[str, int, float, None]] = {
            "timeout": 5,
            "force_address_family": "ipv6",
        }
        # get module config
        self.module.update(config["modules"][qs["module"]])
        # get querystring
        self.module.update(qs)
        return None

    def validate_module(self) -> bool:
        """Make sure the configuration module has all the required values."""
        if self.module["force_address_family"] not in ["ipv4", "ipv6"]:
            self.send_error_response(
                ["Invalid force_address_family, must be 'ipv4' or 'ipv6'"]
            )
            return False
        return True

    def get_target_ip(self, target: str, force_address_family: str) -> Optional[str]:
        """Determine if target is an IP, or a hostname, or a URL. If hostname or URL the hostname must be resolved."""
        # first try parsing target as an IP address
        ip: Optional[Union[IPv4Address, IPv6Address, str]]
        try:
            ip = ipaddress.ip_address(target)
            if ip is not None and ip.version == 4:
                if force_address_family == "ipv6":
                    self.send_error_response(
                        [
                            f"Unable to query ipv4 target {self.module['target']} with force_address_family=ipv6"
                        ]
                    )
                    return None
                return str(ip)
            elif ip is not None and ip.version == 6:
                if force_address_family == "ipv4":
                    self.send_error_response(
                        [
                            f"Unable to query ipv6 target {self.module['target']} with force_address_family=ipv4"
                        ]
                    )
                    return None
                return str(ip)
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
                force_address_family=force_address_family,
            )
        else:
            logger.debug(f"target might be a hostname, resolving hostname {target} ...")
            # target is not a url, it must be a hostname, try a DNS lookup
            ip = self.resolve_ip_getaddrinfo(
                hostname=target,
                force_address_family=force_address_family,
            )
        if ip is None:
            self.send_error_response([f"Unable to resolve target {target} IP address."])
        return ip

    def resolve_ip_getaddrinfo(
        self, hostname: str, force_address_family: str
    ) -> Optional[str]:
        """Resolve the IP of a DNS server hostname."""
        logger.debug(
            f"resolve_ip_getaddrinfo() called with hostname {hostname} and force_address_family {force_address_family}"
        )
        # do we want v4?
        if force_address_family == "ipv4":
            logger.debug(f"doing getaddrinfo for hostname {hostname} for ipv4")
            result = socket.getaddrinfo(hostname, 0, family=socket.AF_INET)
            return str(random.choice(result)[4][0])

        # do we want v6?
        elif force_address_family == "ipv6":
            logger.debug(f"doing getaddrinfo for hostname {hostname} for ipv6")
            result = socket.getaddrinfo(hostname, 0, family=socket.AF_INET6)
            return str(random.choice(result)[4][0])

        # unknown family
        else:
            logger.error(f"Unknown address family {force_address_family}")
            return None

    def get_response(
        self, protocol: str, target: str, ip: str, query: Message, timeout: float
    ) -> Optional[Message]:
        """Perform a DNS query with the specified server and protocol."""
        assert hasattr(query, "question")  # for mypy
        if protocol == "udp":
            logger.debug(
                f"doing UDP lookup with server {target} (using IP {ip}) and query {query.question}"
            )
            r = dns.query.udp(q=query, where=ip, timeout=timeout)
        elif protocol == "tcp":
            logger.debug(
                f"doing TCP lookup with server {target} (using IP {ip}) and query {query.question}"
            )
            r = dns.query.tcp(q=query, where=ip, timeout=timeout)
        elif protocol == "dot":
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
            logger.debug(
                f"doing DoH lookup with server {target} (using IP {ip}) and query {query.question}"
            )
            # https://github.com/rthalley/dnspython/issues/875
            # r = dns.query.https(q=q, where=target, bootstrap_address=ip, **qarg
            r = dns.query.https(q=query, where=target, timeout=timeout)
        elif protocol == "doq":
            logger.debug(
                f"doing DoQ lookup with server {target} (using IP {ip}) and query {query.question}"
            )
            r = dns.query.quic(q=query, where=ip, timeout=timeout)  # type: ignore
        else:
            self.send_error_response(
                ["Unsupported protocol, use one of: udp, tcp, dot, doh, doq"]
            )
            return None
        return r

    def send_error_response(self, messages: list[str]) -> None:
        """Send an HTTP 400 error message to the client."""
        self.send_response(400)
        self.end_headers()
        for line in messages:
            self.wfile.write(line.encode("utf-8"))
        return None

    def send_output(self, registry: CollectorRegistry, query: dict[str, str]) -> None:
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
        return


if __name__ == "__main__":
    with open("dns_exporter.yml") as f:
        try:
            config = yaml.load(f, Loader=yaml.SafeLoader)
        except Exception:
            logger.exception(
                "Unable to parse YAML config file dns_exporter.yml - bailing out."
            )
            sys.exit(1)
    HTTPServer(("127.0.0.1", 15353), DNSRequestHandler).serve_forever()

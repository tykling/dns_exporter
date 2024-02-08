"""``dns_exporter.exporter`` contains the DNSExporter class.


The config.py module contains configuration related stuff, metrics.py
contains the metric definitions, and this exporter.py module contains
the rest of the code.

    - Repository: https://github.com/tykling/dns_exporter
    - Pypi: https://pypi.org/project/dns-exporter/
    - Docs: https://dns-exporter.readthedocs.io/en/latest/

Made with love by Thomas Steen Rasmussen/Tykling, 2023.
"""
import ipaddress
import logging
import random
import socket
import typing as t
import urllib.parse
from dataclasses import asdict
from ipaddress import IPv4Address, IPv6Address
from typing import Union

import dns.edns
import dns.exception
import dns.flags
import dns.opcode
import dns.query
import dns.rcode
import dns.rdatatype
import dns.resolver
from prometheus_client import CollectorRegistry, MetricsHandler, exposition
from prometheus_client.registry import RestrictedRegistry

from dns_exporter.collector import DNSCollector, FailCollector
from dns_exporter.config import Config, ConfigDict, RFValidator, RRValidator
from dns_exporter.exceptions import ConfigError
from dns_exporter.metrics import dnsexp_http_requests_total, dnsexp_http_responses_total
from dns_exporter.version import __version__

logger = logging.getLogger(f"dns_exporter.{__name__}")

INDEX = """<!DOCTYPE html>
<html lang="en">
<head><title>DNS Exporter</title></head>
<body>
<h1>DNS Exporter</h1>
<p>Visit <a href="/query?server=dns.google&protocol=doh&query_name=example.com">/query?server=dns.google&protocol=doh&query_name=example.com</a> to do a DNS query and see metrics.</p>
<p>To debug configuration issues replace /query with /config to see the effective parsed configuration:</p>
<p>Visit <a href="/config?server=dns.google&protocol=doh&query_name=example.com">/config?server=dns.google&protocol=doh&query_name=example.com</a> to see the final scrape config without doing a DNS query.</p>
<p>Visit <a href="/metrics">/metrics</a> to see metrics for the dns_exporter itself.</p>
</body>
</html>"""


class DNSExporter(MetricsHandler):
    """Primary dns_exporter class.

    MetricsHandler subclass for incoming scrape requests. Initiated on each
    request as a handler by http.server.HTTPServer().

    The configure() classmethod can optionally be called to load modules before use.

    Attributes:
        modules: A dict of dns_exporter.config.Config instances to be used in scrape requests.
    """

    __version__ = __version__

    # the modules key is populated by configure() before the class is initialised
    modules: dict[str, Config] = {}

    @classmethod
    def prepare_config(cls, config: ConfigDict) -> ConfigDict:
        """Make sure the configdict has the right types and objects.

        This method is called from:
          - DNSExporter.configure() (before class initialisation, optional)
          - During each scrape request

        Args:
            config: A ConfigDict instance

        Returns:
            A ConfigDict instance

        Raises:
            ConfigError: If any issues are found with the ConfigDict
        """
        try:
            # create RRValidator objects
            for validator in [
                "validate_answer_rrs",
                "validate_authority_rrs",
                "validate_additional_rrs",
            ]:
                if validator in config.keys():
                    if isinstance(config[validator], dict):  # type: ignore
                        config[validator] = RRValidator.create(**config[validator])  # type: ignore
                    elif isinstance(config[validator], RRValidator):  # type: ignore
                        pass
                    else:
                        # unsupported type
                        raise TypeError(f"{validator} has invalid type")
            # create RFValidator
            if "validate_response_flags" in config.keys():
                if isinstance(config["validate_response_flags"], dict):
                    config["validate_response_flags"] = RFValidator.create(
                        **config["validate_response_flags"]
                    )
                elif isinstance(config["validate_response_flags"], RFValidator):
                    pass
                else:
                    # unsupported type
                    raise TypeError("validate_response_flags has invalid type")
        except TypeError:
            logger.exception("Unable to create validator object")
            raise ConfigError("invalid_request_config")

        # create IP objects
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
                raise ConfigError("invalid_request_ip")

        # validate type of integers edns_bufsize and edns_pad
        for key in ["edns_bufsize", "edns_pad"]:
            if (
                key in config.keys()
                and config[key]  # type: ignore
                and not isinstance(config[key], int)  # type: ignore
            ):
                try:
                    config[key] = int(config[key])  # type: ignore
                except ValueError:
                    logger.exception(
                        f"Unable to parse integer for key {key}: {config[key]}"  # type: ignore
                    )
                    raise ConfigError("invalid_request_config")

        # validate floats
        for key in ["timeout"]:
            if (
                key in config.keys()
                and config[key]  # type: ignore
                and not isinstance(config[key], float)  # type: ignore
            ):
                try:
                    config[key] = float(config[key])  # type: ignore
                except ValueError:
                    logger.exception("Invalid float")
                    raise ConfigError("invalid_request_config")

        # parse server?
        if (
            "server" in config.keys()
            and config["server"]
            and not isinstance(config["server"], urllib.parse.SplitResult)
            and "protocol" in config.keys()
        ):
            # parse server into a SplitResult
            config["server"] = cls.parse_server(
                server=config["server"], protocol=config["protocol"]
            )

        return config

    def validate_config(self) -> None:
        """Validate various aspects of the config."""
        # make sure the server is valid, resolve ip if needed
        self.validate_server_ip()

        # make sure there is a query_name in the config
        if not self.config.query_name:
            raise ConfigError("invalid_request_query_name")

    @staticmethod
    def handle_failure(fail_registry: CollectorRegistry, failure: str) -> None:
        """Handle various failure cases that can occur before the DNSCollector is called."""
        logger.debug(f"Initialising FailCollector to handle failure: {failure}")
        fail_collector = FailCollector(failure_reason=failure)
        logger.debug("Registering FailCollector in dnsexp_registry")
        fail_registry.register(fail_collector)

    def build_final_config(self, qs: dict[str, str]) -> None:
        """Construct the final effective scrape config from defaults and values from the querystring."""
        # first get the defaults
        config = ConfigDict(**asdict(Config.create(name="defaults")))  # type: ignore

        # if a module is specified in the querystring apply it first
        if "module" in qs:
            if qs["module"] not in self.modules:
                raise ConfigError("invalid_request_module")
            config.update(asdict(self.modules[qs["module"]]))
            del qs["module"]

        # and the querystring from the scrape request has highest precedence
        config.update(qs)

        # prepare config dict
        config = self.prepare_config(config)

        # the final config has the name "final"
        config.update(name="final")

        # create the config object
        try:
            self.config = Config.create(**config)
        except TypeError:
            logger.exception(
                "Exception while creating config - invalid field specified?"
            )
            raise ConfigError("invalid_request_config")

        # validate config
        self.validate_config()

        logger.debug(f"Final scrape configuration: {self.config}")

    @classmethod
    def configure(
        cls,
        modules: dict[str, ConfigDict] = {},
    ) -> bool:
        """Validate and create Config objects.

        Takes a dict of ConfigDict objects and runs cls.prepare_config() on each
        before creating a Config object and adding it to cls.modules

        If an error is encountered the process stops, but modules loaded until the
        failure can still be used in cls.modules.

        Args:
            modules: A dict of names and corresponding ConfigDict objects.

        Returns:
            bool: True if all ConfigDict objects was validated and loaded OK, False
                if an error was encountered.
        """
        prepared: t.Optional[ConfigDict]
        for name, config in modules.items():
            try:
                prepared = cls.prepare_config(ConfigDict(**config))  # type: ignore
            except ConfigError:
                logger.exception(f"There was an issue while preparing config {name}")
                return False
            try:
                cls.modules[name] = Config.create(name=name, **prepared)
            except TypeError:
                logger.exception(f"Unable to parse config {prepared}")
                return False
            except ConfigError:
                logger.exception(
                    f"Invalid value found while building config {prepared}"
                )
                return False

        logger.info(
            f"{len(modules)} module(s) loaded OK, total modules: {len(cls.modules)}."
        )
        return True

    @staticmethod
    def parse_server(server: str, protocol: str) -> urllib.parse.SplitResult:
        """Parse the server, add scheme (to make urllib.parse play ball), make port explicit.

        The server at this point can be:
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

        Parse it with urllib.parse.urlsplit, add port if needed, and return the result.
        """
        logger.debug(
            f"inside parse_server with server {server} and protocol {protocol}"
        )
        if "://" not in server:
            server = f"{protocol}://{server}"
        splitresult = urllib.parse.urlsplit(server)
        if protocol == "doh" and not splitresult.path:
            # use the default DoH path
            splitresult = urllib.parse.urlsplit(
                urllib.parse.urlunsplit(
                    splitresult._replace(path="/dns-query", scheme="https")
                )
            )
        # is there an explicit port in the configured server url? use default if not.
        if splitresult.port is None:
            if protocol in ["udp", "tcp", "udptcp"]:
                # plain DNS
                port = 53
            elif protocol in ["dot", "doq"]:
                # DoT and DoQ
                port = 853
            else:
                # DoH
                port = 443
            logger.debug(
                f"No explicit port in configured server, using default for protocol {protocol}: {port}"
            )
            splitresult = splitresult._replace(netloc=f"{splitresult.netloc}:{port}")
        # return the parsed server
        return splitresult

    def validate_server_ip(self) -> None:
        """Validate the server and resolve IP if needed."""
        # is there a server?
        if not self.config.server:
            logger.error("No server found in config")
            raise ConfigError("invalid_request_server")

        assert isinstance(self.config.server, urllib.parse.SplitResult)  # mypy
        # is there already an IP in the config?
        if self.config.ip:
            logger.debug(f"checking ip {self.config.ip} of type {type(self.config.ip)}")

            # make sure the ip matches the configured address family
            if not self.check_ip_family(ip=self.config.ip, family=self.config.family):
                raise ConfigError("invalid_request_ip")

            # self.config.server.hostname can be either a hostname or an ip,
            # if it is an ip make sure there is no conflict with ip arg
            try:
                serverip = ipaddress.ip_address(str(self.config.server.hostname))
                if serverip != self.config.ip:
                    raise ConfigError("invalid_request_ip")
            except ValueError:
                # server host is a hostname not an ip,
                # the hostname will NOT be resolved, since there already is an ip to use
                pass
            method = "from config"
        else:
            try:
                # server host might be an ip, attempt to parse it as such
                self.config.ip = ipaddress.ip_address(str(self.config.server.hostname))
            except ValueError:
                # there is no ip in the config, need to get ip by resolving server in dns
                resolved = self.resolve_ip_getaddrinfo(
                    hostname=str(self.config.server.hostname),
                    family=str(self.config.family),
                )
                self.config.ip = ipaddress.ip_address(resolved)
            method = f"resolved from {self.config.server.hostname}"

        logger.debug(
            f"Using server IP {self.config.ip} ({method}) for the DNS server connection"
        )

    @staticmethod
    def check_ip_family(ip: Union[IPv4Address, IPv6Address], family: str) -> bool:
        """Make sure the IP matches the address family."""
        if ip.version == 4 and family == "ipv4":
            return True
        elif ip.version == 6 and family == "ipv6":
            return True
        return False

    def resolve_ip_getaddrinfo(self, hostname: str, family: str) -> str:
        """Resolve the IP of a DNS server hostname."""
        logger.debug(
            f"resolve_ip_getaddrinfo() called with hostname {hostname} and family {family}"
        )
        try:
            # use v4?
            if family == "ipv4":
                logger.debug(f"doing getaddrinfo for hostname {hostname} for ipv4")
                result = socket.getaddrinfo(hostname, 0, family=socket.AF_INET)
                return str(random.choice(result)[4][0])
            # ok so use v6
            else:
                logger.debug(f"doing getaddrinfo for hostname {hostname} for ipv6")
                result = socket.getaddrinfo(hostname, 0, family=socket.AF_INET6)
                return str(random.choice(result)[4][0])
        except socket.gaierror:
            logger.error("Unable to resolve server")
            raise ConfigError("invalid_request_server")

    def parse_querystring(self) -> tuple[urllib.parse.SplitResult, dict[str, str]]:
        """Parse the incoming url and then the querystring."""
        # parse incoming request
        url = urllib.parse.urlsplit(self.path)
        parsed_qs = urllib.parse.parse_qs(url.query)
        # querystring values are all lists when returned from parse_qs(),
        # so take the first item only (since multiple values are not supported)
        # behold, a valid usecase for dict comprehension!
        qs: dict[str, str] = {k: v[0] for k, v in parsed_qs.items()}
        return url, qs

    def do_GET(self) -> None:
        """Handle incoming scrape requests."""
        # parse the scrape request url and querystring
        self.url, self.qs = self.parse_querystring()

        # increase the persistent http request metric
        dnsexp_http_requests_total.labels(path=self.url.path).inc()

        # /query is for doing a DNS query, it returns metrics about just that one dns query
        if self.url.path == "/query" or self.url.path == "/config":
            logger.debug(
                f"Got {self.url.path} request from client {self.client_address}"
            )

            logger.debug(
                "Initialising CollectorRegistry dnsexp_registry and fail_registry"
            )
            dnsexp_registry = CollectorRegistry()
            self.fail_registry = CollectorRegistry()

            # build and validate configuration for this scrape from defaults, config file and request querystring
            try:
                self.build_final_config(qs=self.qs)
            except ConfigError as E:
                self.handle_failure(self.fail_registry, str(E))
                # something is wrong with the config, send error response and bail out
                self.send_metric_response(registry=self.fail_registry, query=self.qs)
                return

            # if this is a config check return now
            if self.url.path == "/config":
                logger.debug("returning config")
                self.send_response(200)
                self.end_headers()
                self.wfile.write(self.config.json().encode("utf-8"))
                return

            # config is ready for action, begin the labels dict
            assert isinstance(self.config.server, urllib.parse.SplitResult)  # mypy
            labels: dict[str, str] = {
                "server": str(self.config.server.geturl()),
                "ip": str(self.config.ip),
                "port": str(self.config.server.port),
                "protocol": str(self.config.protocol),
                "family": str(self.config.family),
                "query_name": str(self.config.query_name),
                "query_type": str(self.config.query_type),
            }

            # prepare query
            qname = dns.name.from_text(str(self.config.query_name))
            q = dns.message.make_query(
                qname=qname,
                rdtype=str(self.config.query_type),
                rdclass=self.config.query_class,
            )

            # use EDNS?
            if self.config.edns:
                # use edns
                ednsargs: dict[
                    str, Union[str, int, bool, list[dns.edns.GenericOption]]
                ] = {"options": []}
                assert isinstance(ednsargs["options"], list)
                # use the DO bit?
                if self.config.edns_do:
                    ednsargs["ednsflags"] = dns.flags.DO
                # use nsid?
                if self.config.edns_nsid:
                    ednsargs["options"].append(
                        dns.edns.GenericOption(dns.edns.NSID, "")
                    )
                # set bufsize/payload?
                if self.config.edns_bufsize:
                    # dnspython calls bufsize "payload"
                    ednsargs["payload"] = int(self.config.edns_bufsize)
                # set edns padding?
                if self.config.edns_pad:
                    ednsargs["options"].append(
                        dns.edns.GenericOption(
                            dns.edns.PADDING, bytes(int(self.config.edns_pad))
                        )
                    )
                # enable edns with the chosen options
                q.use_edns(edns=0, **ednsargs)  # type: ignore
                logger.debug(f"using edns options {ednsargs}")
            else:
                # do not use edns
                q.use_edns(edns=False)
                logger.debug("not using edns")

            # set RD flag?
            if self.config.recursion_desired:
                q.flags |= dns.flags.RD

            # register the DNSCollector in dnsexp_registry
            dns_collector = DNSCollector(config=self.config, query=q, labels=labels)
            dnsexp_registry.register(dns_collector)
            # send the response (which triggers the collect)
            logger.debug("Returning DNS query metrics")
            self.send_metric_response(registry=dnsexp_registry, query=self.qs)
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

    def send_metric_response(
        self,
        registry: Union[CollectorRegistry, RestrictedRegistry],
        query: dict[str, str],
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

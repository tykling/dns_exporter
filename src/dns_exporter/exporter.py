"""``dns_exporter.exporter`` contains the DNSExporter class.

The config.py module contains configuration related stuff, metrics.py
contains the metric definitions, collector.py has the Collector and
and this exporter.py module contains most of the rest of the code.

    - Repository: https://github.com/tykling/dns_exporter
    - Pypi: https://pypi.org/project/dns-exporter/
    - Docs: https://dns-exporter.readthedocs.io/en/latest/

Made with love by Thomas Steen Rasmussen/Tykling, 2023.
"""
# mypy: disable-error-code="literal-required"

from __future__ import annotations

import ipaddress
import logging
import random
import socket
import urllib.parse
from dataclasses import asdict
from ipaddress import IPv4Address, IPv6Address
from typing import TYPE_CHECKING, Literal

import dns.edns
import dns.exception
import dns.flags
import dns.opcode
import dns.query
import dns.rcode
import dns.rdatatype
import dns.resolver
import socks  # type: ignore[import-untyped]
from prometheus_client import CollectorRegistry, MetricsHandler, exposition

from dns_exporter.collector import DNSCollector, FailCollector
from dns_exporter.config import Config, ConfigDict, RFValidator, RRValidator
from dns_exporter.exceptions import ConfigError
from dns_exporter.metrics import QTIME_LABELS, dnsexp_http_requests_total, dnsexp_http_responses_total
from dns_exporter.version import __version__

if TYPE_CHECKING:  # pragma: no cover
    from prometheus_client.registry import RestrictedRegistry

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
</html>"""  # noqa: E501


class DNSExporter(MetricsHandler):
    """Primary dns_exporter class.

    MetricsHandler subclass for incoming scrape requests. Initiated on each
    request as a handler by http.server.HTTPServer().

    The configure() classmethod can optionally be called to load modules before use.

    Attributes:
    -----------
        modules: A dict of dns_exporter.config.Config instances to be used in scrape requests.

    """

    __version__ = __version__

    # the modules key is populated by configure() before the class is initialised
    modules: dict[str, Config] | None = None

    @classmethod
    def prepare_config_rrvalidators(
        cls,
        config: ConfigDict,
    ) -> ConfigDict:
        """Parse and create RRValidator objects for the config."""
        tmp: ConfigDict = {}

        answer: Literal["validate_answer_rrs"] = "validate_answer_rrs"
        authority: Literal["validate_authority_rrs"] = "validate_authority_rrs"
        additional: Literal["validate_additional_rrs"] = "validate_additional_rrs"
        try:
            # create RRValidator objects
            for validator in [answer, authority, additional]:
                if validator in config:
                    if isinstance(config[validator], dict):
                        tmp[validator] = RRValidator.create(**config[validator])
                    elif isinstance(config[validator], RRValidator):
                        tmp[validator] = config[validator]
                    else:
                        # unsupported type
                        raise TypeError(validator)  # noqa: TRY301
        except TypeError as e:
            logger.exception("Unable to create RRValidator object")
            raise ConfigError("invalid_request_config") from e
        return tmp

    @classmethod
    def prepare_config_rfvalidator(
        cls,
        config: ConfigDict,
    ) -> ConfigDict:
        """Parse and create RFValidator object for the config."""
        tmp: ConfigDict = {}
        try:
            # create RFValidator
            if "validate_response_flags" in config:
                if isinstance(config["validate_response_flags"], dict):
                    tmp["validate_response_flags"] = RFValidator.create(**config["validate_response_flags"])
                elif isinstance(config["validate_response_flags"], RFValidator):
                    tmp["validate_response_flags"] = config["validate_response_flags"]
                else:
                    # unsupported type
                    raise TypeError("validate_response_flags")  # noqa: TRY301
        except TypeError as e:
            logger.exception("Unable to create validator object")
            raise ConfigError("invalid_request_config") from e
        return tmp

    @classmethod
    def prepare_config_ip(
        cls,
        config: ConfigDict,
    ) -> ConfigDict:
        """Parse IP address if needed."""
        tmp: ConfigDict = {}
        key = "ip"
        if config.get(key):
            if isinstance(config["ip"], IPv4Address | IPv6Address):
                # use as-is
                tmp[key] = config[key]
            elif isinstance(config[key], str):
                # make an ip object
                try:
                    tmp[key] = ipaddress.ip_address(config[key])
                except ValueError as e:
                    logger.exception(f"Unable to parse IP address {config[key]}")
                    raise ConfigError("invalid_request_ip") from e
            else:
                # unsupported type
                raise TypeError(key)
        return tmp

    @classmethod
    def prepare_config_integers(
        cls,
        config: ConfigDict,
    ) -> ConfigDict:
        """Parse and create integer objects for the config."""
        tmp: ConfigDict = {}
        collect_ttl_rr_value_length: Literal["collect_ttl_rr_value_length"] = "collect_ttl_rr_value_length"
        edns_bufsize: Literal["edns_bufsize"] = "edns_bufsize"
        edns_pad: Literal["edns_pad"] = "edns_pad"
        try:
            for key in [edns_bufsize, edns_pad, collect_ttl_rr_value_length]:
                if key in config:
                    if isinstance(config[key], str):
                        tmp[key] = int(config[key])
                    elif isinstance(config[key], int):
                        # use as-is
                        tmp[key] = config[key]
                    else:
                        # unsupported type
                        raise TypeError(key)  # noqa: TRY301
        except (ValueError, TypeError) as e:
            logger.exception(f"Unable to validate integer for key {key}")
            raise ConfigError("invalid_request_config") from e
        return tmp

    @classmethod
    def prepare_config_floats(
        cls,
        config: ConfigDict,
    ) -> ConfigDict:
        """Parse and create float objects for the config."""
        tmp: ConfigDict = {}
        # use literals for TypedDict keys to make mypy happy
        timeout: Literal["timeout"] = "timeout"
        try:
            for key in [timeout]:
                if key in config:
                    if isinstance(config[key], str):
                        tmp[key] = float(config[key])
                    elif isinstance(config[key], float):
                        # use as-is
                        tmp[key] = config[key]
                    else:
                        # unsupported type
                        raise TypeError(key)  # noqa: TRY301
        except (ValueError, TypeError) as e:
            logger.exception(f"Unable to validate float for key {key}")
            raise ConfigError("invalid_request_config") from e
        return tmp

    @classmethod
    def prepare_config_bools(
        cls,
        config: ConfigDict,
    ) -> ConfigDict:
        """Parse and create bool objects for the config."""
        tmp: ConfigDict = {}
        # use literals for TypedDict keys to make mypy happy
        collect_ttl: Literal["collect_ttl"] = "collect_ttl"
        edns: Literal["edns"] = "edns"
        edns_do: Literal["edns_do"] = "edns_do"
        recursion_desired: Literal["recursion_desired"] = "recursion_desired"
        verify_certificate: Literal["verify_certificate"] = "verify_certificate"
        try:
            for key in [collect_ttl, edns, edns_do, recursion_desired, verify_certificate]:
                if key not in config:
                    continue
                if isinstance(config[key], str):
                    # evaluate string as true if it feels truthy
                    tmp[key] = config[key].lower() in ("true", "t", "yes", "y")
                elif isinstance(config[key], bool):
                    # use as-is
                    tmp[key] = config[key]
                else:
                    # unsupported type
                    raise TypeError(key)  # noqa: TRY301
        except (ValueError, TypeError) as e:
            logger.exception(f"Unable to validate bool for key {key}")
            raise ConfigError("invalid_request_config") from e
        return tmp

    @classmethod
    def prepare_config_server(
        cls,
        config: ConfigDict,
    ) -> ConfigDict:
        """Parse server into a SplitResult and return it."""
        tmp: ConfigDict = {}
        key: Literal["server"] = "server"
        try:
            if config.get(key):
                server = config[key]
                if isinstance(server, str):
                    # parse server into a SplitResult
                    tmp[key] = cls.parse_server(
                        server=server,
                        protocol=config.get("protocol", "udp"),
                    )
                elif isinstance(server, urllib.parse.SplitResult):
                    # use as-is
                    tmp[key] = server
                else:
                    # unsupported type
                    raise TypeError(key)  # noqa: TRY301
        except TypeError as e:
            logger.exception("Unable to parse server")
            raise ConfigError("invalid_request_server") from e
        return tmp

    @classmethod
    def prepare_config_proxy(
        cls,
        config: ConfigDict,
    ) -> ConfigDict:
        """Parse proxy into a SplitResult and return it."""
        tmp: ConfigDict = {}
        key: Literal["proxy"] = "proxy"
        try:
            if config.get(key):
                proxy = config[key]
                if isinstance(proxy, str):
                    if "://" not in proxy:
                        logger.error("No scheme in proxy")
                        raise ConfigError("invalid_request_proxy")

                    # parse proxy into a SplitResult
                    splitresult = urllib.parse.urlsplit(proxy)
                    if not splitresult.scheme or splitresult.scheme.upper() not in socks.PROXY_TYPES:
                        logger.error(f"Invalid proxy scheme {splitresult}")
                        raise ConfigError("invalid_request_proxy")

                    # make port explicit
                    if splitresult.port is None:
                        # SOCKS4 and SOCKS5 default to port 1080
                        port = 8080 if splitresult.scheme == "http" else 1080
                        splitresult = splitresult._replace(
                            netloc=f"{splitresult.netloc}:{port}",
                        )

                    # keep only scheme and netloc
                    tmp[key] = urllib.parse.urlsplit(
                        splitresult.scheme + "://" + splitresult.netloc,
                    )
                    logger.debug(f"Using proxy {splitresult.geturl()!s}")
                elif isinstance(proxy, urllib.parse.SplitResult):
                    # use as-is
                    tmp[key] = proxy
                else:
                    # unsupported type
                    raise TypeError(key)  # noqa: TRY301
        except TypeError as e:
            logger.exception("Unable to parse proxy")
            raise ConfigError("invalid_request_proxy") from e
        return tmp

    @classmethod
    def prepare_config(cls, config: ConfigDict) -> ConfigDict:
        """Make sure the configdict has the right types and objects.

        This method is called from:
          - DNSExporter.configure() (before class initialisation, optional)
          - During each scrape request

        Args:
        -----
            config: A ConfigDict instance

        Returns:
        --------
            A ConfigDict instance

        Raises:
        -------
            ConfigError: If any issues are found with the ConfigDict

        """
        # parse and create RRValidator objects
        config.update(cls.prepare_config_rrvalidators(config))
        # parse and create RFValidator object
        config.update(cls.prepare_config_rfvalidator(config))
        # parse and create IP object
        config.update(cls.prepare_config_ip(config))
        # validate integer keys
        config.update(cls.prepare_config_integers(config))
        # validate float keys
        config.update(cls.prepare_config_floats(config))
        # validate bool keys
        config.update(cls.prepare_config_bools(config))
        # parse server
        config.update(cls.prepare_config_server(config))
        # parse proxy
        config.update(cls.prepare_config_proxy(config))
        # all done
        return config

    def validate_config(self) -> None:
        """Validate various aspects of the config."""
        # make sure the server is valid, resolve ip if needed
        self.validate_server_ip()

        # make sure there is a query_name in the config
        if not self.config.query_name:
            raise ConfigError("invalid_request_query_name")

    @staticmethod
    def handle_failure(fail_registry: CollectorRegistry, failure: str, labels: dict[str, str]) -> None:
        """Handle various failure cases that can occur before the DNSCollector is called."""
        logger.debug(f"Initialising FailCollector to handle failure: {failure}")
        fail_collector = FailCollector(failure_reason=failure, labels=labels)
        logger.debug("Registering FailCollector in dnsexp_registry")
        fail_registry.register(fail_collector)

    def build_final_config(self, qs: dict[str, str]) -> None:
        """Construct the final effective scrape config from defaults and values from the querystring."""
        # first get the defaults
        config = ConfigDict(**asdict(Config.create(name="defaults")))  # type: ignore[typeddict-item]

        # if a module is specified in the querystring apply it first
        if "module" in qs:
            if self.modules is None or qs["module"] not in self.modules:
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
        except TypeError as e:
            logger.exception(
                "Exception while creating config - invalid field specified?",
            )
            raise ConfigError("invalid_request_config") from e

        # validate config
        self.validate_config()

        logger.debug(f"Final scrape configuration: {self.config}")

    @classmethod
    def configure(
        cls,
        modules: dict[str, ConfigDict] | None = None,
    ) -> bool:
        """Validate and create Config objects.

        Takes a dict of ConfigDict objects and runs cls.prepare_config() on each
        before creating a Config object and adding it to cls.modules

        If an error is encountered the process stops, but modules loaded until the
        failure can still be used in cls.modules.

        Args:
        -----
            modules: A dict of names and corresponding ConfigDict objects.

        Returns:
        --------
            bool: True if all ConfigDict objects was validated and loaded OK, False
                  if an error was encountered.
        """
        prepared: ConfigDict | None
        if modules is None:
            modules = {}
        if cls.modules is None:
            cls.modules = {}
        for name, config in modules.items():
            try:
                prepared = cls.prepare_config(ConfigDict(**config))
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
                    f"Invalid value found while building config {prepared}",
                )
                return False

        logger.info(
            f"{len(modules)} module(s) loaded OK, total modules: {len(cls.modules)}.",
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

        In the DoH/DoH3 https:// cases the url can be with or without a path.

        Parse it with urllib.parse.urlsplit, add explicit port if needed, and return the result.
        """
        # make sure we always have a scheme to help the parser
        if "://" not in server:
            server = f"{protocol}://{server}"
        # parse the string
        splitresult = urllib.parse.urlsplit(server)
        # make sure scheme is the dns_exporter internal protocol identifier (not https://)
        splitresult = splitresult._replace(scheme=protocol)
        if protocol in ["doh", "doh3"] and not splitresult.path:
            # use the default DoH path
            splitresult = splitresult._replace(path="/dns-query")
        # is there an explicit port in the configured server url? use default if not.
        if splitresult.port is None:
            if protocol in ["udp", "tcp", "udptcp"]:
                # plain DNS
                port = 53
            elif protocol in ["dot", "doq"]:
                # DoT and DoQ
                port = 853
            else:
                # DoH or DoH3
                port = 443
            logger.debug(
                f"No explicit port in configured server, using default for protocol {protocol}: {port}",
            )
            splitresult = splitresult._replace(netloc=f"{splitresult.netloc}:{port}")
        # return the parsed server
        logger.debug(f"Using server {splitresult.geturl()!s}")
        return splitresult

    def validate_server_ip(self) -> None:
        """Validate the server and resolve IP if needed."""
        # is there a server?
        if not self.config.server:
            logger.error("No server found in config")
            raise ConfigError("invalid_request_server")

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
            f"Using server IP {self.config.ip} ({method}) for the DNS server connection",
        )

    @staticmethod
    def check_ip_family(ip: IPv4Address | IPv6Address, family: str) -> bool:
        """Make sure the IP matches the address family."""
        return (ip.version == 4 and family == "ipv4") or (ip.version == 6 and family == "ipv6")  # noqa: PLR2004

    def resolve_ip_getaddrinfo(self, hostname: str, family: str) -> str:
        """Resolve the IP of a DNS server hostname."""
        logger.debug(
            f"resolve_ip_getaddrinfo() called with hostname {hostname} and family {family}",
        )
        try:
            if family == "ipv4":
                logger.debug(f"doing getaddrinfo for hostname {hostname} for ipv4")
                result = socket.getaddrinfo(hostname, 0, family=socket.AF_INET)
                return str(random.choice(result)[4][0])  # noqa: S311
            logger.debug(f"doing getaddrinfo for hostname {hostname} for ipv6")
            result = socket.getaddrinfo(hostname, 0, family=socket.AF_INET6)
            return str(random.choice(result)[4][0])  # noqa: S311
        except socket.gaierror as e:
            logger.exception("Unable to resolve server")
            raise ConfigError("invalid_request_server") from e

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

    def handle_query_request(self) -> None:
        """Handle incoming HTTP GET requests to /query or /config."""
        logger.debug(
            f"Got {self.url.path} request from client {self.client_address}",
        )
        logger.debug(
            "Initialising CollectorRegistry dnsexp_registry and fail_registry",
        )
        dnsexp_registry = CollectorRegistry()
        self.fail_registry = CollectorRegistry()

        # begin labels dict
        self.labels: dict[str, str] = {}
        for key in QTIME_LABELS:
            # default all labels to the string "none"
            self.labels[key] = "none"

        # build and validate configuration for this scrape from defaults, config file and request querystring
        try:
            self.build_final_config(qs=self.qs)
        except ConfigError as E:
            self.handle_failure(self.fail_registry, str(E), labels=self.labels)
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
        self.labels.update(
            {
                "server": str(self.config.server.geturl()),  # type: ignore[union-attr]
                "ip": str(self.config.ip),
                "port": str(self.config.server.port),  # type: ignore[union-attr]
                "protocol": str(self.config.protocol),
                "family": str(self.config.family),
                "proxy": str(self.config.proxy.geturl()) if self.config.proxy else "none",
                "query_name": str(self.config.query_name),
                "query_type": str(self.config.query_type),
            }
        )

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
                str,
                str | int | bool | list[dns.edns.GenericOption],
            ] = {"options": []}
            # use the DO bit?
            if self.config.edns_do:
                ednsargs["ednsflags"] = dns.flags.DO
            # use nsid?
            if self.config.edns_nsid:
                ednsargs["options"].append(  # type: ignore[union-attr]
                    dns.edns.GenericOption(dns.edns.NSID, ""),
                )
            # set bufsize/payload?
            if self.config.edns_bufsize:
                # dnspython calls bufsize "payload"
                ednsargs["payload"] = int(self.config.edns_bufsize)
            # set edns padding?
            if self.config.edns_pad:
                ednsargs["options"].append(  # type: ignore[union-attr]
                    dns.edns.GenericOption(
                        dns.edns.PADDING,
                        bytes(int(self.config.edns_pad)),
                    ),
                )
            # enable edns with the chosen options
            q.use_edns(edns=0, **ednsargs)  # type: ignore[arg-type]
            logger.debug(f"using edns options {ednsargs}")
        else:
            # do not use edns
            q.use_edns(edns=False)
            logger.debug("not using edns")

        # set RD flag?
        if self.config.recursion_desired:
            q.flags |= dns.flags.RD

        # register the DNSCollector in dnsexp_registry
        dns_collector = DNSCollector(config=self.config, query=q, labels=self.labels)
        dnsexp_registry.register(dns_collector)
        # send the response (which triggers the collect)
        logger.debug("Returning DNS query metrics")
        self.send_metric_response(registry=dnsexp_registry, query=self.qs)

    def do_GET(self) -> None:  # noqa: N802
        """Handle incoming HTTP GET requests."""
        # parse the scrape request url and querystring
        self.url, self.qs = self.parse_querystring()
        logger.debug(
            f"Got HTTP request for {self.url.geturl()} - parsed qs is {self.qs}",
        )
        # increase the persistent http request metric
        dnsexp_http_requests_total.labels(path=self.url.path).inc()

        # /query is for doing a DNS query, it returns metrics about just that one dns query
        if self.url.path in ["/query", "/config"]:
            self.handle_query_request()

        # this endpoint exposes metrics about the exporter itself and the python process
        elif self.url.path == "/metrics":
            logger.debug("Returning exporter metrics for request to /metrics")
            self.send_metric_response(registry=self.registry, query=self.qs)

        # the root just returns a bit of informational html
        elif self.url.path == "/":
            # return a basic index page
            logger.debug("Returning index page for request to /")
            self.send_response(200)
            self.send_header("Content-Length", str(len(INDEX.encode("utf-8"))))
            self.end_headers()
            self.wfile.write(INDEX.encode("utf-8"))
            dnsexp_http_responses_total.labels(path="/", response_code=200).inc()

        # unknown endpoint
        else:
            logger.debug(f"Unknown endpoint '{self.url.path}' returning 404")
            self.send_response(404)
            msg = b"404 not found"
            self.send_header("Content-Length", str(len(msg)))
            self.end_headers()
            self.wfile.write(msg)
            dnsexp_http_responses_total.labels(
                path=self.url.path,
                response_code=404,
            ).inc()

    def send_metric_response(
        self,
        registry: CollectorRegistry | RestrictedRegistry,
        query: dict[str, str],
    ) -> None:
        """Bake and send output from the provided registry and querystring."""
        # Bake output
        status, headers, output = exposition._bake_output(  # type: ignore[no-untyped-call]  # noqa: SLF001
            registry=registry,
            accept_header=self.headers.get("Accept"),
            accept_encoding_header=self.headers.get("Accept-Encoding"),
            params=query,
            disable_compression=False,
        )
        headers.append(("Content-Length", str(len(output))))
        # Return output
        self.send_response(int(status.split(" ")[0]))
        for header in headers:
            self.send_header(*header)
        self.end_headers()
        self.wfile.write(output)
        dnsexp_http_responses_total.labels(path=self.url.path, response_code=200).inc()

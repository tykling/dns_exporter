"""``dns_exporter.config`` contains all the configuration related code for dns_exporter.

The primary class is the Config object and the two RRValidator and RFValidator objects.
"""

from __future__ import annotations

import json
import logging
import typing as t
from dataclasses import asdict, dataclass, field
from pathlib import Path

import dns.edns
import dns.exception
import dns.flags
import dns.opcode
import dns.query
import dns.rcode
import dns.rdatatype
import dns.resolver

from dns_exporter.exceptions import ConfigError

if t.TYPE_CHECKING:  # pragma: no cover
    import urllib.parse
    from ipaddress import IPv4Address, IPv6Address


# get logger
logger = logging.getLogger(f"dns_exporter.{__name__}")

# the currently supported protocols in dns_exporter
valid_protocols = [
    "udp",
    "tcp",
    "udptcp",
    "dot",
    "doh",
    "doh3",
    "doq",
]


@dataclass
class RRValidator:
    """``dns_exporter.config.RRValidator`` defines the structure used in ``Config`` objects to validate response RRs.

    It is used in the ``validate_(answer|authority|additional)_rrs`` settings in the config.

    Like the parent ``dns_exporter.config.Config`` class it consists of a bunch of attributes and the
    ``dns_exporter.config.RRValidator.create()`` method which returns an instance of this class.

    Each Config object can have up to three (3) instances of this class, one for validating RRs in each section
    of the response:

        - ``answer``
        - ``authority``
        - ``additional``
    """

    fail_if_matches_regexp: list[str]
    """``fail_if_matches_regexp`` is a list of regular expressions, fail the query if one of them matches
    an RR."""

    fail_if_all_match_regexp: list[str]
    """``fail_if_all_match_regexp`` is a list of regular expressions, fail the query if all of them matches
    an RR."""

    fail_if_not_matches_regexp: list[str]
    """``fail_if_not_matches_regexp`` is a list of regular expressions, fail the query if one of them does not match
    an RR."""

    fail_if_none_matches_regexp: list[str]
    """``fail_if_none_matches_regexp`` is a list of regular expressions, fail the query if all of them does not match
    an RR."""

    fail_if_count_eq: int | None
    """``fail_if_count_eq`` is an integer, fail the query if the number of RRs matches this number."""

    fail_if_count_ne: int | None
    """``fail_if_count_ne`` is an integer, fail the query if the number of RRs is not equal to this number."""

    fail_if_count_lt: int | None
    """``fail_if_count_lt`` is an integer, fail the query if the number of RRs is smaller than this number."""

    fail_if_count_gt: int | None
    """``fail_if_count_gt`` is an integer, fail the query if the number of RRs is larger than this number."""

    @classmethod
    def create(  # noqa: PLR0913
        cls: type[RRValidator],
        fail_if_matches_regexp: list[str] | None = None,
        fail_if_all_match_regexp: list[str] | None = None,
        fail_if_not_matches_regexp: list[str] | None = None,
        fail_if_none_matches_regexp: list[str] | None = None,
        fail_if_count_eq: int | None = None,
        fail_if_count_ne: int | None = None,
        fail_if_count_lt: int | None = None,
        fail_if_count_gt: int | None = None,
    ) -> RRValidator:
        """Return an instance of the RRValidator class with values from the provided parameters.

        The values are used as-is.
        """
        # immutable defaults
        if fail_if_matches_regexp is None:
            fail_if_matches_regexp = []
        if fail_if_all_match_regexp is None:
            fail_if_all_match_regexp = []
        if fail_if_not_matches_regexp is None:
            fail_if_not_matches_regexp = []
        if fail_if_none_matches_regexp is None:
            fail_if_none_matches_regexp = []
        return cls(
            fail_if_matches_regexp=fail_if_matches_regexp,
            fail_if_all_match_regexp=fail_if_all_match_regexp,
            fail_if_not_matches_regexp=fail_if_not_matches_regexp,
            fail_if_none_matches_regexp=fail_if_none_matches_regexp,
            fail_if_count_eq=fail_if_count_eq,
            fail_if_count_ne=fail_if_count_ne,
            fail_if_count_lt=fail_if_count_lt,
            fail_if_count_gt=fail_if_count_gt,
        )


@dataclass
class RFValidator:
    """``dns_exporter.config.RFValidator`` defines the structure used in ``Config`` objects to validate response flags.

    It is used in the ``validate_response_flags`` setting in the config.

    Like the parent ``dns_exporter.config.Config`` class it consists of a bunch of attributes and the
    ``dns_exporter.config.RFValidator.create()`` method which returns an instance of this class.
    """

    fail_if_any_present: list[str]
    """``fail_if_any_present`` is a list of flags as strings, fail if any of them are present in the response."""

    fail_if_all_present: list[str]
    """``fail_if_all_present`` is a list of flags as strings, fail if all of them are present in the response."""

    fail_if_any_absent: list[str]
    """``fail_if_any_absent`` is a list of flags as strings, fail if any of them are absent from the response."""

    fail_if_all_absent: list[str]
    """``fail_if_all_present`` is a list of flags as strings, fail if all of them are absent from the response."""

    @classmethod
    def create(
        cls: type[RFValidator],
        fail_if_any_present: list[str] | None = None,
        fail_if_all_present: list[str] | None = None,
        fail_if_any_absent: list[str] | None = None,
        fail_if_all_absent: list[str] | None = None,
    ) -> RFValidator:
        """Return an instance of the RFValidator class with values from the provided parameters.

        The values are used as-is.
        """
        # immutable defaults
        if fail_if_any_present is None:
            fail_if_any_present = []
        if fail_if_all_present is None:
            fail_if_all_present = []
        if fail_if_any_absent is None:
            fail_if_any_absent = []
        if fail_if_all_absent is None:
            fail_if_all_absent = []
        return cls(
            fail_if_any_present=fail_if_any_present,
            fail_if_all_present=fail_if_all_present,
            fail_if_any_absent=fail_if_any_absent,
            fail_if_all_absent=fail_if_all_absent,
        )


@dataclass
class Config:
    """``dns_exporter.config.Config`` defines the primary config structure used in dns_exporter.

    The defaults for each config key are defined in the ``dns_exporter.config.Config.create()`` method.

    The ``dns_exporter.exporter.DNSExporter.modules`` dict consists of string keys and instances of this class as
    values.
    """

    name: str
    """str: The name of this config. It is mostly included in the class for convenience."""

    # required
    collect_ttl: bool
    """bool: Set this bool to ``True`` to enable collection of per-RR TTL metrics for the DNS query, ``False`` to not
    collect per-RR TTL metrics. Default is ``True``"""

    collect_ttl_rr_value_length: int
    """int: Limits the length of the ``rr_value`` label when collecing per-RR TTL metrics. Default is ``50``"""

    edns: bool
    """bool: Set this bool to ``True`` to enable ``EDNS0`` for the DNS query, ``False`` to not use ``EDNS0``.
    Default is ``True``"""

    edns_do: bool
    """bool: Set this bool to ``True`` to set the ``EDNS0`` ``DO`` flag for the DNS query. Default is ``False``"""

    edns_nsid: bool
    """bool: Set this bool to ``True`` to set the ``EDNS0`` ``nsid`` option for the DNS query. Default is ``True``"""

    edns_bufsize: int
    """int: This int sets the ``EDNS0`` bufsize for the DNS query. Default is ``1232``"""

    edns_pad: int
    """int: This int sets the ``EDNS0`` padding size for the DNS query. Default is ``0``"""

    family: str
    """str: This string key must be set to either ``ipv6`` or ``ipv4``. It determines the address family used for the
    DNS query. Default is ``ipv6``"""

    protocol: str
    """str: This key must be set to one of ``udp``, ``tcp``, ``udptcp``, ``dot``, ``doh``, or ``doq``. It determines
    the protocol used for the DNS query. Default is ``udp``"""

    query_class: str
    """str: The query class used for this DNS query, typically ``IN`` but can also be ``CHAOS``. Default is ``IN``"""

    query_type: str
    """str: The query type used for this DNS query, like ``A`` or ``MX``. Default is ``A``"""

    proxy: urllib.parse.SplitResult | None
    """str: The proxy to use for this DNS query, for example ``socks5://127.0.0.1:5000``. Supported proxy types are
    SOCKS4, SOCKS5, and HTTP. Leave empty to use no proxy. Default is no proxy."""

    recursion_desired: bool
    """bool: Set this bool to ``True`` to set the ``RD`` flag in the DNS query. Default is ``True``"""

    timeout: float
    """float: This float determines how long the exporter will wait for a response before declaring the DNS query
    failed. Unit is seconds. Default is 5.0."""

    validate_answer_rrs: RRValidator
    """RRValidator: This object contains the validation config for the ``answer`` section of the response. Default
    is an empty ``RRValidator()``"""

    validate_authority_rrs: RRValidator
    """RRValidator: This object contains the validation config for the ``authority`` section of the response. Default
    is an empty ``RRValidator()``"""

    validate_additional_rrs: RRValidator
    """RRValidator: This object contains the validation config for the ``additional`` section of the response.
    Default is an empty ``RRValidator()``"""

    validate_response_flags: RFValidator
    """RFValidator: This object contains the validation config for the response flags. Default is an empty
    ``RFValidator()``"""

    valid_rcodes: list[str]
    """list[str]: A list of acceptable rcodes when validating the DNS response. Default is ``["NOERROR"]``."""

    verify_certificate: bool
    """bool: Set this bool to ``True`` to verify the certificate of the DNS server, set it to ``False`` to disable
    certificate verification. When enabled the default system CA can be overridden with the verify_certificate_path
    setting. Certificate validation is ignored for unencrypted protocols. Default is ``True``"""

    verify_certificate_path: str
    """bool: Set this to the path of a CA dir or CA file to override the default system CA when verifying certificates
    of encrypted DNS servers. Leave empty to use the default system CA path. Default is an empty string."""

    # optional settings (but required in final config)

    ip: IPv4Address | IPv6Address | None = field(
        default_factory=lambda: None,
    )
    """IPv4Address | IPv6Address | None: The IP to use instead of using IP or hostname from server. Default
    is ``None``"""

    server: urllib.parse.SplitResult | None = field(default_factory=lambda: None)
    """urllib.parse.SplitResult | None: The DNS server to use in parsed form. Default is ``None``"""

    query_name: str | None = field(default_factory=lambda: None)
    """str | None: The name to ask for in the DNS query. Default is ``None``"""

    def validate_bools(self) -> None:
        """Validate bools."""
        for key in ["collect_ttl", "edns", "edns_do", "edns_nsid", "recursion_desired", "verify_certificate"]:
            # validate bools
            if not isinstance(getattr(self, key), bool):
                logger.error(f"Not a bool: {key}")
                raise ConfigError("invalid_request_config")

    def validate_integers(self) -> None:
        """Validate integers."""
        for key in ["collect_ttl_rr_value_length", "edns_bufsize", "edns_pad"]:
            if not getattr(self, key) >= 0:
                logger.error("Invalid integer")
                raise ConfigError("invalid_request_config")

    def validate_protocol(self) -> None:
        """Validate protocol."""
        if self.protocol not in valid_protocols:
            raise ConfigError(
                "invalid_request_protocol",
            )

    def validate_valid_qtypes(self) -> None:
        """Validate query_type (make sure it is supported in dnspython)."""
        valid_qtypes = [dns.rdatatype.to_text(t) for t in dns.rdatatype.RdataType]
        if self.query_type not in valid_qtypes:
            raise ConfigError(
                "invalid_request_query_type",
            )

    def validate_valid_rcodes(self) -> None:
        """Validate valid_rcodes."""
        all_rcodes = [dns.rcode.to_text(x) for x in dns.rcode.Rcode]
        invalid_rcodes = set(self.valid_rcodes).difference(all_rcodes)
        if invalid_rcodes:
            logger.error("Invalid rcodes used")
            raise ConfigError(
                "invalid_request_config",
            )

    def validate_proxy(self) -> None:
        """Validate proxy."""
        if self.proxy and self.protocol in ["dot"]:
            # proxy support doesn't work for DoT for now
            # https://github.com/tykling/dns_exporter/issues/76
            logger.error(f"proxy not valid for protocol {self.protocol}")
            raise ConfigError(
                "invalid_request_config",
            )

    def __post_init__(self) -> None:
        """Validate as much as possible."""
        self.validate_bools()

        # validate integers
        self.validate_integers()

        # validate family
        if self.family not in ["ipv4", "ipv6"]:
            raise ConfigError("invalid_request_family")

        # validate protocol
        self.validate_protocol()

        # validate query_class
        if self.query_class not in ["IN", "CHAOS"]:
            raise ConfigError("invalid_request_query_class")

        # validate query_type
        self.validate_valid_qtypes()

        # validate valid_rcodes
        self.validate_valid_rcodes()

        # validate proxy
        self.validate_proxy()

        # validate ca path
        if self.verify_certificate_path:
            certpath = Path(self.verify_certificate_path)
            if not certpath.exists():
                raise ConfigError("invalid_request_path")

    @classmethod
    def create(  # noqa: PLR0913
        cls: type[Config],
        *,
        name: str,
        collect_ttl: bool = True,
        collect_ttl_rr_value_length: int = 50,
        edns: bool = True,
        edns_do: bool = False,
        edns_nsid: bool = True,
        edns_bufsize: int = 1232,
        edns_pad: int = 0,
        family: str = "ipv6",
        protocol: str = "udp",
        query_class: str = "IN",
        query_type: str = "A",
        recursion_desired: bool = True,
        proxy: urllib.parse.SplitResult | None = None,
        timeout: float = 5.0,
        validate_answer_rrs: RRValidator | None = None,
        validate_authority_rrs: RRValidator | None = None,
        validate_additional_rrs: RRValidator | None = None,
        validate_response_flags: RFValidator | None = None,
        valid_rcodes: list[str] | None = None,
        verify_certificate: bool = True,
        verify_certificate_path: str = "",
        ip: IPv4Address | IPv6Address | None = None,
        server: urllib.parse.SplitResult | None = None,
        query_name: str | None = None,
    ) -> Config:
        """Return an instance of the Config class with values from the provided parameters overriding the defaults."""
        logger.debug(f"creating config {name}...")
        # immutable defaults
        if valid_rcodes is None:
            valid_rcodes = ["NOERROR"]

        if validate_answer_rrs is None:
            validate_answer_rrs = RRValidator.create()

        if validate_authority_rrs is None:
            validate_authority_rrs = RRValidator.create()

        if validate_additional_rrs is None:
            validate_additional_rrs = RRValidator.create()

        if validate_response_flags is None:
            validate_response_flags = RFValidator.create()

        return cls(
            name=name,
            collect_ttl=collect_ttl,
            collect_ttl_rr_value_length=collect_ttl_rr_value_length,
            edns=edns,
            edns_do=edns_do,
            edns_nsid=edns_nsid,
            edns_bufsize=int(edns_bufsize),
            edns_pad=int(edns_pad),
            family=family,
            protocol=protocol,
            query_class=query_class.upper(),
            query_type=query_type.upper(),
            recursion_desired=recursion_desired,
            proxy=proxy,
            timeout=float(timeout),
            validate_answer_rrs=validate_answer_rrs,
            validate_authority_rrs=validate_authority_rrs,
            validate_additional_rrs=validate_additional_rrs,
            validate_response_flags=validate_response_flags,
            valid_rcodes=list(valid_rcodes),
            verify_certificate=verify_certificate,
            verify_certificate_path=verify_certificate_path,
            # fields with no defaults below here
            ip=ip,
            server=server,
            query_name=query_name,
        )

    def json(self) -> str:
        """Return a json version of the config. Mostly used in unit tests."""
        conf: dict[str, t.Any] = asdict(self)
        conf["ip"] = str(conf["ip"])
        conf["server"] = conf["server"].geturl()
        if conf["proxy"]:
            conf["proxy"] = conf["proxy"].geturl()
        return json.dumps(conf)


class ConfigDict(t.TypedDict, total=False):
    """A TypedDict to help hold config dicts before they become Config objects.

    ``dns_exporter.config.ConfigDict`` behaves like a regular dict but works better with mypy
    because the individual keys has been annotated.

    ``dns_exporter.config.ConfigDict`` has all the same keys and types as the real final
    ``dns_exporter.config.Config`` object does.
    """

    collect_ttl: bool
    collect_ttl_rr_value_length: bool
    edns: bool
    edns_do: bool
    edns_nsid: bool
    edns_bufsize: int
    edns_pad: int
    family: str
    protocol: str
    query_class: str
    query_type: str
    recursion_desired: bool
    timeout: float
    validate_answer_rrs: RRValidator
    validate_authority_rrs: RRValidator
    validate_additional_rrs: RRValidator
    validate_response_flags: RFValidator
    valid_rcodes: list[str]
    verify_certificate: bool
    verify_certificate_path: str
    ip: IPv4Address | IPv6Address | None
    server: urllib.parse.SplitResult | None
    query_name: str | None
    proxy: urllib.parse.SplitResult | None

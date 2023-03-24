"""Config related code for dns_exporter."""
import json
import logging
import typing as t
import urllib.parse
from dataclasses import asdict, dataclass, field
from ipaddress import IPv4Address, IPv6Address

import dns.edns
import dns.exception
import dns.flags
import dns.opcode
import dns.query
import dns.rcode
import dns.rdatatype
import dns.resolver

# initialise logger
logger = logging.getLogger("dns_exporter")


@dataclass
class RRValidator:
    """This dataclass defines the structure used in validate_(answer|authority|additional)_rrs in the configs."""

    fail_if_matches_regexp: list[str]
    fail_if_all_match_regexp: list[str]
    fail_if_not_matches_regexp: list[str]
    fail_if_none_matches_regexp: list[str]
    fail_if_count_eq: t.Optional[int]
    fail_if_count_ne: t.Optional[int]
    fail_if_count_lt: t.Optional[int]
    fail_if_count_gt: t.Optional[int]

    @classmethod
    def create(
        cls: t.Type["RRValidator"],
        fail_if_matches_regexp: list[str] = [],
        fail_if_all_match_regexp: list[str] = [],
        fail_if_not_matches_regexp: list[str] = [],
        fail_if_none_matches_regexp: list[str] = [],
        fail_if_count_eq: t.Optional[int] = None,
        fail_if_count_ne: t.Optional[int] = None,
        fail_if_count_lt: t.Optional[int] = None,
        fail_if_count_gt: t.Optional[int] = None,
    ) -> "RRValidator":
        """Return an instance of the RRValidator class with values from the provided conf dict."""
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
    """This dataclass defines the structure used in validate_response_flags in the configs."""

    fail_if_any_present: list[str]
    fail_if_all_present: list[str]
    fail_if_any_absent: list[str]
    fail_if_all_absent: list[str]

    @classmethod
    def create(
        cls: t.Type["RFValidator"],
        fail_if_any_present: list[str] = [],
        fail_if_all_present: list[str] = [],
        fail_if_any_absent: list[str] = [],
        fail_if_all_absent: list[str] = [],
    ) -> "RFValidator":
        """Return an instance of the RFValidator class with values from the provided conf dict."""
        return cls(
            fail_if_any_present=fail_if_any_present,
            fail_if_all_present=fail_if_all_present,
            fail_if_any_absent=fail_if_any_absent,
            fail_if_all_absent=fail_if_all_absent,
        )


@dataclass
class Config:
    """This dataclass defines the config structure used in dns_exporter."""

    name: str

    # required
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

    # optional settings (but required in final config)
    ip: t.Optional[t.Union[IPv4Address, IPv6Address]] = field(
        default_factory=lambda: None
    )
    target: t.Union[urllib.parse.SplitResult, None] = field(
        default_factory=lambda: None
    )
    query_name: t.Optional[str] = field(default_factory=lambda: None)

    def __post_init__(self) -> None:
        """Validate as much as possible."""
        logger.debug(f"validating config: {asdict(self)}")
        for key in ["edns", "edns_do", "edns_nsid", "recursion_desired"]:
            # validate bools
            if not isinstance(getattr(self, key), bool):
                raise ValueError(f"{key} must be a bool", "invalid_request_config")

        # validate integers
        # TODO: maybe check that edns_bufsize is not too big?
        for key in ["edns_bufsize", "edns_pad"]:
            if not isinstance(getattr(self, key), int):
                raise ValueError(
                    "edns_bufsize must be an integer", "invalid_request_config"
                )
            if not getattr(self, key) >= 0:
                raise ValueError("edns_bufsize must be >= 0", "invalid_request_config")

        # validate family
        if self.family not in ["ipv4", "ipv6"]:
            raise ValueError(
                "family must be one of: ipv4, ipv6", "invalid_request_family"
            )

        # validate protocol
        valid_protocols = [
            "udp",
            "tcp",
            "udptcp",
            "dot",
            "doh",
            "doq",
        ]
        if self.protocol not in valid_protocols:
            raise ValueError(
                f"protocol must be one of: {valid_protocols}",
                "invalid_request_protocol",
            )

        # validate query_class
        if self.query_class not in ["IN", "CHAOS"]:
            raise ValueError(
                "query_class must be one of: IN, CHAOS", "invalid_request_query_class"
            )

        # validate query_type
        valid_qtypes = [dns.rdatatype.to_text(t) for t in dns.rdatatype.RdataType]  # type: ignore
        if self.query_type not in valid_qtypes:
            raise ValueError(
                f"query_type {self.query_type} not found in list of valid query types: {valid_qtypes}",
                "invalid_request_query_type",
            )

        # validate timeout
        if not isinstance(self.timeout, float):
            raise ValueError("timeout must be a float", "invalid_request_config")

        # validate RRValidator fields
        for key in [
            "validate_answer_rrs",
            "validate_authority_rrs",
            "validate_additional_rrs",
        ]:
            if not isinstance(getattr(self, key), RRValidator):
                raise ValueError(
                    f"{key} is not a RRValidator object", "invalid_request_config"
                )

        # validate RFValidator
        if not isinstance(self.validate_response_flags, RFValidator):
            raise ValueError(
                "validate_response_flags is not a RFValidator object",
                "invalid_request_config",
            )

        # validate valid_rcodes
        all_rcodes = [dns.rcode.to_text(x) for x in dns.rcode.Rcode]  # type: ignore
        invalid_rcodes = set(self.valid_rcodes).difference(all_rcodes)
        if invalid_rcodes:
            raise ValueError(
                f"Invalid valid_rcodes setting in config '{self.name}': {list(invalid_rcodes)}. Supported rcodes: {all_rcodes}",
                "invalid_request_config",
            )

    @classmethod
    def create(
        cls: t.Type["Config"],
        name: str,
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
        timeout: float = 5.0,
        validate_answer_rrs: RRValidator = RRValidator.create(),
        validate_authority_rrs: RRValidator = RRValidator.create(),
        validate_additional_rrs: RRValidator = RRValidator.create(),
        validate_response_flags: RFValidator = RFValidator.create(),
        valid_rcodes: list[str] = ["NOERROR"],
        ip: t.Optional[t.Union[IPv4Address, IPv6Address]] = None,
        target: t.Optional[urllib.parse.SplitResult] = None,
        query_name: t.Optional[str] = None,
    ) -> "Config":
        """Return an instance of the Config class with values from the provided parameters overriding the defaults."""
        logger.debug(f"creating config {name}...")
        return cls(
            name=name,
            edns=edns,
            edns_do=edns_do,
            edns_nsid=edns_nsid,
            edns_bufsize=edns_bufsize,
            edns_pad=edns_pad,
            family=family,
            protocol=protocol,
            query_class=query_class.upper(),
            query_type=query_type.upper(),
            recursion_desired=recursion_desired,
            timeout=float(timeout),
            validate_answer_rrs=validate_answer_rrs,
            validate_authority_rrs=validate_authority_rrs,
            validate_additional_rrs=validate_additional_rrs,
            validate_response_flags=validate_response_flags,
            valid_rcodes=valid_rcodes,
            # fields with no defaults below here
            ip=ip,
            target=target,
            query_name=query_name,
        )

    def json(self) -> str:
        """Return a json version of the config."""
        conf: dict[str, t.Any] = asdict(self)
        conf["ip"] = str(conf["ip"])
        conf["target"] = conf["target"].geturl()
        return json.dumps(conf)


class ConfigDict(t.TypedDict, total=False):
    """A TypedDict to help hold config dicts before they become Config objects."""

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
    ip: t.Union[IPv4Address, IPv6Address, None]
    target: t.Union[urllib.parse.SplitResult, None]
    query_name: t.Optional[str]

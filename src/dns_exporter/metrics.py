"""The ``dns_exporter.metrics`` module contains definition of all the metrics for dns_exporter.

The metrics in this module are initialised when they are first imported inside
``dns_exporter.exporter``. Because the CollectorRegistry classes are global
importing this module multiple times does not cause problems.

All metrics exposed by ``dns_exporter`` are prefixed with ``dnsexp_`` (apart from ``up``
and the built-in Python metrics).
"""
from prometheus_client import CollectorRegistry, Counter, Enum, Gauge, Info

from dns_exporter.version import __version__

dnsexp_registry = CollectorRegistry()
"""dnsexp_registry is a seperate CollectorRegistry used for the DNS specific metrics.

The following metrics are created in this registry:

    - ``dns_exporter.metrics.dnsexp_dns_query_time_seconds``
    - ``dns_exporter.metrics.dnsexp_dns_query_success``
    - ``dns_exporter.metrics.dnsexp_dns_query_failure_reason``
    - ``dns_exporter.metrics.dnsexp_dns_response_rr_ttl_seconds``

The metrics in this registry are all cleared/reset between queries/scrapes.
"""


dnsexp_dns_query_time_seconds = Gauge(
    "dnsexp_dns_query_time_seconds",
    "DNS query time in seconds.",
    [
        "protocol",
        "server",
        "family",
        "ip",
        "port",
        "transport",
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
    registry=dnsexp_registry,
)
"""``dnsexp_dns_query_time_seconds`` is the gauge used as the primary timing metric for DNS queries.

Each DNS query duration is added to this gauge with the following labels to identify it:

    - ``protocol``
    - ``server``
    - ``family``
    - ``ip``
    - ``port``
    - ``transport``
    - ``query_name``
    - ``query_type``
    - ``opcode``
    - ``rcode``
    - ``flags``
    - ``nsid``
    - ``answer``
    - ``authority``
    - ``additional``

In some cases the ``nsid`` label has no value and the placeholder ``no_nsid`` is used instead.

This metric is cleared between scrapes.
"""


dnsexp_dns_query_success = Gauge(
    "dnsexp_dns_query_success",
    "Was this DNS query successful or not, 1 for success or 0 for failure.",
    registry=dnsexp_registry,
)
"""``dnsexp_dns_query_success`` is a Gauge set to 1 when a DNS query is successful, or 0 otherwise.

A DNS query is considered failed in the following cases:
    - Configuration issues preventing a DNS query
    - Network or server issues preventing a response from reaching the exporter
    - Response parsing issues
    - Response validation issues

A DNS query is considered a success if a DNS query response is received and any configured
validation logic passes.

This metrics has no labels, so it is not cleared between scrapes, as it only has the one state.
"""


dnsexp_dns_query_failure_reason = Enum(
    "dnsexp_dns_query_failure_reason",
    "The reason this DNS query failed",
    states=[
        "no_failure",  # initial state
        "invalid_request_module",  # the specified module was not found
        "invalid_request_config",  # one or more config keys not found
        "invalid_request_server",  # dns issue resolving server hostname
        "invalid_request_family",  # family is not one of "ipv4" or "ipv6"
        "invalid_request_ip",  # ip is not valid
        "invalid_request_port",  # port parameter conflicts with port in server
        "invalid_request_path",  # path parameter conflicts with path in server
        "invalid_request_protocol",  # protocol is not one of "udp", "tcp", "udptcp", "dot", "doh", "doq"
        "invalid_request_query_name",  # query_name is invalid or missing
        "invalid_request_query_type",  # query_type is invalid or missing
        "invalid_request_query_class",  # query_class is invalid or missing
        "timeout",  # the configured timeout was reached before the dns server replied
        "invalid_response_rcode",  # the response RCODE was not as expected
        "invalid_response_flags",  # the response flags were not as expected
        "invalid_response_answer_rrs",  # the ANSWER rrs were not as expected
        "invalid_response_authority_rrs",  # the AUTHORITY rrs were not as expected
        "invalid_response_additional_rrs",  # the ADDITIONAL rrs were not as expected
        "other_failure",  # unknown error cases
    ],
    registry=dnsexp_registry,
)
"""``dnsexp_dns_query_failure_reason`` is an Enum which is set to the failure reason whenever ``dnsexp_dns_query_success=0``.

This enum has the following states:

    - ``no_failure`` (initial state, meaning success)
    - ``invalid_request_module`` (the specified module not found)
    - ``invalid_request_config`` (one or more config keys not found)
    - ``invalid_request_server`` (dns issue resolving server hostname)
    - ``invalid_request_family`` (family is not one of "ipv4" or "ipv6")
    - ``invalid_request_ip`` (ip is not valid)
    - ``invalid_request_port`` (port parameter conflicts with port in server)
    - ``invalid_request_path`` (path parameter conflicts with path in server)
    - ``invalid_request_protocol`` (protocol is not one of "udp", "tcp", "udptcp", "dot", "doh", "doq")
    - ``invalid_request_query_name`` (query_name is invalid or missing)
    - ``invalid_request_query_type`` (query_type is invalid or missing)
    - ``invalid_request_query_class`` (query_class is invalid or missing)
    - ``timeout`` (the configured timeout was reached before the dns server replied)
    - ``invalid_response_rcode`` (the response RCODE was not as expected)
    - ``invalid_response_flags`` (the response flags were not as expected)
    - ``invalid_response_answer_rrs`` (the ANSWER rrs were not as expected)
    - ``invalid_response_authority_rrs`` (the AUTHORITY rrs were not as expected)
    - ``invalid_response_additional_rrs`` (the ADDITIONAL rrs were not as expected)
    - ``other_failure`` (unknown error cases)

This metric is reset to the initial state ``no_failure`` between scrapes.
"""


dnsexp_dns_response_rr_ttl_seconds = Gauge(
    "dnsexp_dns_response_rr_ttl_seconds",
    "DNS response RR TTL in seconds.",
    [
        "protocol",
        "server",
        "family",
        "ip",
        "port",
        "transport",
        "query_name",
        "query_type",
        "opcode",
        "rcode",
        "flags",
        "nsid",
        "answer",
        "authority",
        "additional",
        "rr_section",  # answer, authority or additional
        "rr_name",
        "rr_type",
        "rr_value",
    ],
    registry=dnsexp_registry,
)
"""``dnsexp_dns_response_rr_ttl_seconds`` is a Gauge which tracks the TTL of individual response RRs.

This metric will often be set multiple times during a scrape, whenever a DNS query results in multiple
RRs in the answer/authority/additional sections. For example, if a DNS query results in a response with
2 ``ANSWER``, 0 ``AUTHORITY`` and 4 ``ADDITIONAL`` then this metric will be set 6 times (with different labels).

This Gauge has the following labels, they are the same as ``dns_exporter.metrics.dnsexp_dns_query_time_seconds`` plus a few more:

    - ``protocol``
    - ``server``
    - ``family``
    - ``ip``
    - ``port``
    - ``transport``
    - ``query_name``
    - ``query_type``
    - ``opcode``
    - ``rcode``
    - ``flags``
    - ``nsid``
    - ``answer``
    - ``authority``
    - ``additional``
    - ``rr_section`` (answer, authority or additional)
    - ``rr_name`` (the RR name)
    - ``rr_type`` (the RR type)
    - ``rr_value`` (the first 255 chars of the RR value)

This metric is cleared between scrapes.
"""

# now define the persistent metrics for the exporter itself

# define the info metric with the build version
dnsexp_build_version = Info("dnsexp_build_version", "The version of dns_exporter")
"""``dnsexp_build_version`` is a persistent Info metric which contains the version of ``dns_exporter``.

The version is taken from the installed Python package if possible, and from _version.py written by ``setuptools_scm`` if the package is not installed, like when running from a Git checkout.
"""
dnsexp_build_version.info({"version": __version__})

dnsexp_http_requests_total = Counter(
    "dnsexp_http_requests_total",
    "The total number of HTTP requests received by this exporter since start. This counter is increased every time any HTTP request is received by the dns_exporter.",
    ["path"],
)
"""``dnsexp_http_requests_total`` is a persistent Counter keeping track of the total number of HTTP requests received by the exporter since start.

This metric has a single label, ``path`` which is set to the request path, usually ``/query`` (for making DNS queries) or ``/metrics`` (for getting the internal exporter metrics.
"""

dnsexp_http_responses_total = Counter(
    "dnsexp_http_responses_total",
    "The total number of HTTP responses sent by this exporter since start. This counter is increased every time an HTTP response is sent from the dns_exporter.",
    ["path", "response_code"],
)
"""``dnsexp_http_responses_total`` is a persistent Counter keeping track of the total number of HTTP responses sent by the exporter since start.

This metric has two labels:
    - ``path`` is set to the request path, usually ``/query`` (for making DNS queries) or ``/metrics`` (for getting the internal exporter metrics).
    - ``response_code`` is set to the HTTP response code, usually 200.
"""


dnsexp_dns_queries_total = Counter(
    "dnsexp_dns_queries_total",
    "The total number of DNS queries sent by this exporter since start. This counter is increased every time the dns_exporter sends out a DNS query.",
)
"""``dnsexp_dns_queries_total`` is the Counter keeping track of how many DNS queries this exporter sends out.

This metric has no labels.
"""


dnsexp_dns_responses_total = Counter(
    "dnsexp_dns_responses_total",
    "The total number of DNS query responses received since start. This counter is increased every time the dns_exporter receives a query response (before timeout).",
)
"""``dnsexp_dns_responses_total`` is the Counter keeping track of how many DNS responses this exporter received since start.

This metric has no labels.
"""


dnsexp_dns_failures_total = Counter(
    "dnsexp_dns_failures_total",
    "The total number of DNS queries considered failed. This counter is increased every time a DNS query is sent out and a valid response is not received.",
)
"""``dnsexp_dns_failures_total`` is the Counter keeping track of how many DNS queries are considered failed by this exporter since start.

A failed query is either a timeout, network issue, bad response, or failed response validation.

This metric has no labels.
"""

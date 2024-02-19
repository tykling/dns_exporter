"""The ``dns_exporter.metrics`` module contains definition of all the metrics for dns_exporter.

All metrics exposed by ``dns_exporter`` are prefixed with ``dnsexp_`` (apart from ``up``
and the built-in Python metrics).
"""
from typing import Optional

from prometheus_client.core import (
    Counter,
    CounterMetricFamily,
    GaugeMetricFamily,
    Histogram,
    Info,
)

from dns_exporter.version import __version__

########################################################
# scrape-specific metrics used by the DNSCollector (served under /query)

# the labels used in the qtime and ttl metrics
QTIME_LABELS = [
    "server",
    "ip",
    "port",
    "protocol",
    "family",
    "proxy",
    "query_name",
    "query_type",
    "transport",
    "opcode",
    "rcode",
    "flags",
    "answer",
    "authority",
    "additional",
    "nsid",
]

FAILURE_REASONS = [
    "invalid_request_module",
    "invalid_request_config",
    "invalid_request_server",
    "invalid_request_proxy",
    "invalid_request_family",
    "invalid_request_ip",
    "invalid_request_port",
    "invalid_request_path",
    "invalid_request_protocol",
    "invalid_request_query_name",
    "invalid_request_query_type",
    "invalid_request_query_class",
    "connection_error",
    "connection_refused",
    "timeout",
    "invalid_response_rcode",
    "invalid_response_flags",
    "invalid_response_answer_rrs",
    "invalid_response_authority_rrs",
    "invalid_response_additional_rrs",
    "other_failure",
]
"""FAILURE_REASONS is a list of the possible failure modes which might show up in the dnsexp_failure_reason metric."""


def get_dns_qtime_metric() -> GaugeMetricFamily:
    """``dnsexp_dns_query_time_seconds`` is the gauge used as the primary timing metric for DNS queries.

    Each DNS query duration is added to this gauge with the following labels to identify it:

        - ``server``
        - ``ip``
        - ``port``
        - ``protocol``
        - ``family``
        - ``query_name``
        - ``query_type``
        - ``transport``
        - ``opcode``
        - ``rcode``
        - ``flags``
        - ``answer``
        - ``authority``
        - ``additional``
        - ``nsid``

    In some cases the ``nsid`` label has no value and the placeholder ``no_nsid`` is used instead.
    """
    return GaugeMetricFamily(
        name="dnsexp_dns_query_time_seconds",
        documentation="DNS query time in seconds.",
        labels=QTIME_LABELS,
    )


def get_dns_success_metric(value: Optional[int] = None) -> GaugeMetricFamily:
    """``dnsexp_dns_query_success`` is a Gauge set to 1 when a DNS query is successful, or 0 otherwise.

    A DNS query is considered failed in the following cases:
        - Configuration issues preventing a DNS query
        - Network or server issues preventing a response from reaching the exporter
        - Response parsing issues
        - Response validation issues

    A DNS query is considered a success if a DNS query response is received and any configured
    validation logic passes.
    """
    return GaugeMetricFamily(
        name="dnsexp_dns_query_success",
        documentation="Was this DNS query successful or not, 1 for success or 0 for failure.",
        value=value,
    )


def get_dns_ttl_metric() -> GaugeMetricFamily:
    """``dnsexp_dns_response_rr_ttl_seconds`` is a Gauge which tracks the TTL of individual response RRs.

    This metric will often be set multiple times during a scrape, whenever a DNS query results in multiple
    RRs in the answer/authority/additional sections. For example, if a DNS query results in a response with
    2 ``ANSWER``, 0 ``AUTHORITY`` and 4 ``ADDITIONAL`` then this metric will be set 6 times (with different labels).

    This Gauge has the following labels, they are the same as ``dns_exporter.metrics.dnsexp_dns_query_time_seconds`` plus a few more:

        - ``server``
        - ``ip``
        - ``port``
        - ``protocol``
        - ``family``
        - ``query_name``
        - ``query_type``
        - ``transport``
        - ``opcode``
        - ``rcode``
        - ``flags``
        - ``answer``
        - ``authority``
        - ``additional``
        - ``nsid``
        - ``rr_section`` (answer, authority or additional)
        - ``rr_name`` (the RR name)
        - ``rr_type`` (the RR type)
        - ``rr_value`` (the first 255 chars of the RR value)
    """
    return GaugeMetricFamily(
        name="dnsexp_dns_response_rr_ttl_seconds",
        documentation="DNS response RR TTL in seconds.",
        labels=QTIME_LABELS
        + [
            "rr_section",  # answer, authority or additional
            "rr_name",
            "rr_type",
            "rr_value",
        ],
    )


def get_dns_failure_metric() -> CounterMetricFamily:
    """``dnsexp_failures_total`` is the per-scrape Counter keeping track of the reason a scrape failed.

    A scrape (or the resulting DNS query) can fail for many reasons, including configuration issues, server issues, timeout, network issues, bad response, or failed response validation.

    This metric has just one label:
        - ``reason``: The reason for the failure.
    """
    return CounterMetricFamily(
        name="dnsexp_failures_total",
        documentation="The total number of scrape failures by failure reason. This counter is increased every time a scrape is initiated and a valid response (considering validation rules) is not received.",
        labels=["reason"],
    )


########################################################
# exporter internal/persitent metrics (served under /metrics)

dnsexp_build_version = Info(
    name="dnsexp_build_version", documentation="The version of dns_exporter"
)
"""``dnsexp_build_version`` is a persistent Info metric which contains the version of ``dns_exporter``.

The version is taken from the installed Python package if possible, and from _version.py written by ``setuptools_scm`` if the package is not installed, like when running from a Git checkout.
"""
dnsexp_build_version.info({"version": __version__})

dnsexp_http_requests_total = Counter(
    name="dnsexp_http_requests_total",
    documentation="The total number of HTTP requests received by this exporter since start. This counter is increased every time any HTTP request is received by the dns_exporter.",
    labelnames=["path"],
)
"""``dnsexp_http_requests_total`` is a persistent Counter keeping track of the total number of HTTP requests received by the exporter since start.

This metric has a single label, ``path`` which is set to the request path, usually ``/query`` (for making DNS queries) or ``/metrics`` (for getting the internal exporter metrics.
"""

dnsexp_http_responses_total = Counter(
    name="dnsexp_http_responses_total",
    documentation="The total number of HTTP responses sent by this exporter since start. This counter is increased every time an HTTP response is sent from the dns_exporter.",
    labelnames=["path", "response_code"],
)
"""``dnsexp_http_responses_total`` is a persistent Counter keeping track of the total number of HTTP responses sent by the exporter since start.

This metric has two labels:
    - ``path`` is set to the request path, usually ``/query`` (for making DNS queries) or ``/metrics`` (for getting the internal exporter metrics).
    - ``response_code`` is set to the HTTP response code, usually 200.
"""

dnsexp_dns_queries_total = Counter(
    name="dnsexp_dns_queries_total",
    documentation="The total number of DNS queries sent by this exporter since start. This counter is increased every time the dns_exporter sends out a DNS query.",
)
"""``dnsexp_dns_queries_total`` is the Counter keeping track of how many DNS queries this exporter sends out.

This metric has no labels.
"""

dnsexp_dns_responsetime_seconds = Histogram(
    name="dnsexp_dns_responsetime_seconds",
    documentation="DNS query response timing histogram. This histogram is updated every time the dns_exporter receives a query response.",
    labelnames=QTIME_LABELS,
)
"""``dnsexp_dns_responsetime_seconds`` is the Histogram keeping track of how many DNS responses this exporter received since start and how long the query took.

    Each DNS query duration is observed in this histogram with the following labels to identify it:

        - ``server``
        - ``ip``
        - ``port``
        - ``protocol``
        - ``family``
        - ``query_name``
        - ``query_type``
        - ``transport``
        - ``opcode``
        - ``rcode``
        - ``flags``
        - ``answer``
        - ``authority``
        - ``additional``
        - ``nsid``

    In some cases the ``nsid`` label has no value and the placeholder ``no_nsid`` is used instead.
"""

dnsexp_scrape_failures_total = Counter(
    name="dnsexp_scrape_failures_total",
    documentation="The total number of scrapes failed by failure reason. This counter is increased every time the dns_exporter receives a scrape request which fails for some reason, including response validation logic.",
    labelnames=["reason"],
)
"""``dnsexp_scrape_failures_total`` is the Counter keeping track of how many scrape requests failed for some reason.

This metric has one label:
    - ``reason`` is set to the failure reason.
"""

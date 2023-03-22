"""A module with all the metrics stuff for dns_exporter."""
from prometheus_client import CollectorRegistry, Counter, Enum, Gauge, Histogram
from prometheus_client.utils import INF

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

QUERY_RESPONSE_TTL = Histogram(
    "dns_response_record_ttl_seconds",
    "DNS query response record TTL in seconds.",
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
        "section",  # answer, authority or additional
        "value",
    ],
    registry=dns_registry,
    buckets=(
        1.0,
        2.0,
        4.0,
        8.0,
        16.0,
        32.0,
        64.0,
        128.0,
        256.0,
        512.0,
        1024.0,
        2048.0,
        4096.0,
        8192.0,
        16384.0,
        32768.0,
        65536.0,
        131072.0,
        262144.0,
        524288.0,
        1048576.0,
        2097152.0,
        4194304.0,
        8388608.0,
        16777216.0,
        33554432.0,
        67108864.0,
        134217728.0,
        268435456.0,
        536870912.0,
        INF,
    ),
)

# now define the persistent metrics for the exporter itself

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

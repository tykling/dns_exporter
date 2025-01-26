"""dnsexporter test of internal metrics. Runs last, breaks easily."""

import logging

import pytest
import requests

from dns_exporter.version import __version__


# run this test last
@pytest.mark.order(-1)
def test_internal_metrics(dns_exporter_example_config, tmp_path, caplog):
    """Test the internal metrics and make sure aggregated counts of all unit tests are there.

    This test breaks as soon as any other test breaks, it must run last, and it cannot run alone.
    """
    caplog.clear()
    caplog.set_level(logging.DEBUG)
    r = requests.get(
        "http://127.0.0.1:25353/metrics",
    )
    # write metrics to file to help debugging failing tests
    p = tmp_path / "metrics.prom"
    with p.open("w") as f:
        f.write(r.text)
    # on with the asserts
    assert f'dnsexp_build_version_info{{version="{__version__}"}} 1.0' in r.text
    assert "Returning exporter metrics for request to /metrics" in caplog.text
    for metric in """dnsexp_http_requests_total{path="/notfound"} 1.0
dnsexp_http_requests_total{path="/query"} 90.0
dnsexp_http_requests_total{path="/config"} 2.0
dnsexp_http_requests_total{path="/"} 1.0
dnsexp_http_requests_total{path="/metrics"} 1.0
dnsexp_http_responses_total{path="/notfound",response_code="404"} 1.0
dnsexp_http_responses_total{path="/query",response_code="200"} 90.0
dnsexp_http_responses_total{path="/",response_code="200"} 1.0
dnsexp_dns_queries_total 73.0
dnsexp_dns_responsetime_seconds_bucket{additional="0",answer="6",authority="0",family="ipv4",flags="QR RA RD",ip="8.8.4.4",le="2.5",nsid="no_nsid",opcode="QUERY",port="53",protocol="udp",proxy="none",query_name="example.com",query_type="A",rcode="NOERROR",server="udp://dns.google:53",transport="UDP"}
dnsexp_scrape_failures_total{additional="none",answer="none",authority="none",family="none",flags="none",ip="none",nsid="none",opcode="none",port="none",protocol="none",proxy="none",query_name="none",query_type="none",rcode="none",reason="invalid_request_config",server="none",transport="none"} 2.0
dnsexp_scrape_failures_total{additional="none",answer="none",authority="none",family="none",flags="none",ip="none",nsid="none",opcode="none",port="none",protocol="none",proxy="none",query_name="none",query_type="none",rcode="none",reason="invalid_request_server",server="none",transport="none"} 2.0
dnsexp_scrape_failures_total{additional="none",answer="none",authority="none",family="none",flags="none",ip="none",nsid="none",opcode="none",port="none",protocol="none",proxy="none",query_name="none",query_type="none",rcode="none",reason="invalid_request_query_name",server="none",transport="none"} 1.0
dnsexp_scrape_failures_total{additional="none",answer="none",authority="none",family="none",flags="none",ip="none",nsid="none",opcode="none",port="none",protocol="none",proxy="none",query_name="none",query_type="none",rcode="none",reason="invalid_request_ip",server="none",transport="none"} 3.0
dnsexp_scrape_failures_total{additional="none",answer="none",authority="none",family="ipv4",flags="none",ip="8.8.8.8",nsid="none",opcode="none",port="443",protocol="doh",proxy="none",query_name="example.com",query_type="A",rcode="none",reason="invalid_response_statuscode",server="doh://dns.google:443/dns-query",transport="none"} 1.0
dnsexp_scrape_failures_total{additional="none",answer="none",authority="none",family="none",flags="none",ip="none",nsid="none",opcode="none",port="none",protocol="none",proxy="none",query_name="none",query_type="none",rcode="none",reason="invalid_request_module",server="none",transport="none"} 1.0
dnsexp_scrape_failures_total{additional="none",answer="none",authority="none",family="none",flags="none",ip="none",nsid="none",opcode="none",port="none",protocol="none",proxy="none",query_name="none",query_type="none",rcode="none",reason="invalid_request_family",server="none",transport="none"} 1.0
dnsexp_scrape_failures_total{additional="none",answer="none",authority="none",family="ipv4",flags="none",ip="8.8.8.8",nsid="none",opcode="none",port="443",protocol="doh",proxy="none",query_name="example.com",query_type="A",rcode="none",reason="other_failure",server="doh://dns.google:443/dns-query",transport="none"} 1.0
dnsexp_scrape_failures_total{additional="none",answer="none",authority="none",family="ipv4",flags="none",ip="91.239.100.100",nsid="none",opcode="none",port="853",protocol="dot",proxy="none",query_name="example.com",query_type="A",rcode="none",reason="certificate_error",server="dot://91.239.100.100:853",transport="none"} 1.0
dnsexp_scrape_failures_total{additional="none",answer="none",authority="none",family="ipv4",flags="none",ip="91.239.100.100",nsid="none",opcode="none",port="443",protocol="doh",proxy="none",query_name="example.com",query_type="A",rcode="none",reason="certificate_error",server="doh://91.239.100.100:443/dns-query",transport="none"} 1.0
dnsexp_scrape_failures_total{additional="none",answer="none",authority="none",family="none",flags="none",ip="none",nsid="none",opcode="none",port="none",protocol="none",proxy="none",query_name="none",query_type="none",rcode="none",reason="invalid_request_proxy",server="none",transport="none"} 2.0""".split(
        "\n"
    ):
        assert metric in r.text, f"expected metric {metric} not found in metrics: {p}"

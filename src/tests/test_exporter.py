# type: ignore
"""dns_exporter test suite extravaganza."""
import requests


def test_basic_functionality(dns_exporter_server):
    """Test basic lookup functionality."""
    print("inside test_basic_functionality...")
    r = requests.get(
        "http://127.0.0.1:15353/query",
        params={
            "query_name": "example.com",
            "target": "dns.google",
            "family": "ipv4",
        },
    )
    assert r.status_code == 200, "basic request failed with non-200 returncode"

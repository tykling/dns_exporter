# type: ignore
"""pytest fixtures file for the dns_exporter project."""

import time
from http.server import HTTPServer
from threading import Thread

import pytest

from dns_exporter.exporter import DNSExporter, main


@pytest.fixture(scope="session")
def dns_exporter_no_main_no_config():
    """Run a basic server without main() and with no config."""
    print("Running server with no config on 127.0.0.1:15353 ...")
    serve_forever = HTTPServer(("127.0.0.1", 15353), DNSExporter).serve_forever
    thread = Thread(target=serve_forever)
    thread.setDaemon(True)
    thread.start()
    time.sleep(1)
    yield
    print("Beginning teardown")


@pytest.fixture(scope="session")
def dns_exporter_example_config():
    """Run a server with main() and with the example config."""
    print("Running server with example config on 127.0.0.1:25353 ...")
    thread = Thread(
        target=main,
        args=(["-c", "dns_exporter/dns_exporter_example.yml", "-p", "25353"],),
    )
    thread.setDaemon(True)
    thread.start()
    time.sleep(1)
    yield
    print("Beginning teardown")

# type: ignore
"""pytest fixtures file for the dns_exporter project."""

import subprocess
import time

import pytest


@pytest.fixture(scope="session")
def dns_exporter_server():
    """Run a basic server with no config file."""
    print("Running server...")
    proc = subprocess.Popen(
        args=["dns_exporter"],
    )

    time.sleep(2)
    # end buildup
    port = 15353
    yield port

    # begin teardown
    print("Beginning teardown")
    print("Stopping server...")
    proc.terminate()
    print("Teardown finished")

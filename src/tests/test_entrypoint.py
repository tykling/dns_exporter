# type: ignore
import time

import pytest

import dns_exporter.entrypoint

mockargs = [
    "-c",
    "dns_exporter/dns_exporter_example.yml",
    "-d",
    "-p",
    "25353",
]


def test_listen_port_busy(dns_exporter_example_config, caplog):
    """Test calling main() on a port which is already busy."""
    with pytest.raises(SystemExit):
        dns_exporter.entrypoint.main(mockargs)
    time.sleep(2)
    assert "is in use?" in caplog.text

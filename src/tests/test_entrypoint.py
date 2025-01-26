"""Unit tests for entrypoint.py."""

import time

import pytest

import dns_exporter.entrypoint
from dns_exporter.entrypoint import main
from dns_exporter.version import __version__

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


def test_version(capsys):
    """Make sure the -v command-line option returns the version."""
    with pytest.raises(SystemExit):
        main(["-v"])
    captured = capsys.readouterr()
    assert __version__ in captured.out

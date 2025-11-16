"""Unit tests for entrypoint.py."""

import time

import pytest

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
        main(mockargs)
    time.sleep(2)
    assert "is in use?" in caplog.text


def test_version(capsys):
    """Make sure the -v command-line option returns the version."""
    with pytest.raises(SystemExit):
        main(["-v"])
    captured = capsys.readouterr()
    assert __version__ in captured.out


def test_socket_cache_max_age_option(dns_exporter_example_config, caplog):
    """Make sure the --socket-cache-age-max command-line option works."""
    with pytest.raises(SystemExit):
        main([*mockargs, "--socket-cache-age-max", "1234"])
    assert "SocketCache initialised with max. age 1234 seconds" in caplog.text


def test_socket_cache_max_idle_option(dns_exporter_example_config, caplog):
    """Make sure the --socket-cache-idle-max command-line option works."""
    with pytest.raises(SystemExit):
        main([*mockargs, "--socket-cache-idle-max", "1234"])
    assert "and max. idle 1234 seconds" in caplog.text


def test_socket_cache_cleanup_interval_option(dns_exporter_example_config, caplog):
    """Make sure the --socket-cache-cleanup-interval command-line option works."""
    with pytest.raises(SystemExit):
        main([*mockargs, "--socket-cache-cleanup-interval", "1234"])
    assert "and housekeeping interval 1234 seconds" in caplog.text

"""pytest fixtures file for the dns_exporter project."""

import subprocess
import time
from http.server import HTTPServer
from pathlib import Path
from threading import Thread

import httpx
import pytest
import yaml

from dns_exporter.entrypoint import main
from dns_exporter.exporter import DNSExporter


@pytest.fixture
def exporter():
    """Fixture to return a clean version of the DNSExporter class."""

    class CleanTestExporter(DNSExporter):
        """This is just here so tests can mess around with cls.modules without changing the global DNSExporter class."""

    CleanTestExporter.modules = None
    return CleanTestExporter


@pytest.fixture(scope="session")
def dns_exporter_no_main_no_config():
    """Run a basic server without main() and with no config."""
    print("Running server with no config on 127.0.0.1:45353 ...")
    serve_forever = HTTPServer(("127.0.0.1", 45353), DNSExporter).serve_forever
    thread = Thread(target=serve_forever)
    thread.daemon = True
    thread.start()
    time.sleep(1)
    if not thread.is_alive():
        pytest.fail("Unable to create test instance on 127.0.0.1:45353")
    yield
    print("Beginning teardown")


@pytest.fixture(scope="session")
def dns_exporter_example_config():
    """Run a server with main() and with the example config."""
    print("Running server with example config on 127.0.0.1:25353 ...")
    thread = Thread(
        target=main,
        args=(["-c", "dns_exporter/dns_exporter_example.yml", "-p", "25353", "-d"],),
    )
    thread.daemon = True
    thread.start()
    time.sleep(1)
    if not thread.is_alive():
        pytest.fail("Unable to create test instance on 127.0.0.1:25353")
    yield
    print("Beginning teardown")


@pytest.fixture(scope="session")
def dns_exporter_main_no_config_no_debug():
    """Run a server with main() and no config."""
    print("Running server with no config on 127.0.0.1:35353 ...")
    thread = Thread(
        target=main,
        args=(["-p", "35353"],),
    )
    thread.daemon = True
    thread.start()
    time.sleep(1)
    if not thread.is_alive():
        pytest.fail("Unable to create test instance on 127.0.0.1:35353")
    yield
    print("Beginning teardown")


@pytest.fixture
def dns_exporter_param_config(request):
    """Run a server in a subprocess with the config from request.param."""
    print(f"Running dns_exporter with config {request.param} on 127.0.0.1:15353 ...")
    conf = Path(__file__).parents[0] / "tests" / "prometheus" / request.param
    proc = subprocess.Popen(
        args=["dns_exporter", "-c", str(conf), "-d"],
    )
    time.sleep(1)
    if proc.poll():
        # process didn't start properly, bail out
        pytest.fail(
            f"Unable to create test instance with config {request.param} on 127.0.0.1:15353",
        )
    yield
    print(f"Stopping dns_exporter with config {request.param} on 127.0.0.1:15353 ...")
    proc.terminate()


@pytest.fixture
def dns_exporter_broken_yaml_configfile(tmp_path_factory):
    """Write a dns_exporter.yml file with invalid yaml."""
    confpath = tmp_path_factory.mktemp("conf") / "dns_exporter.yml"
    # write file to disk
    with Path.open(confpath, "w") as f:
        f.write("foo:\nbar")
    # return path to the config
    return confpath


@pytest.fixture
def dns_exporter_empty_yaml_configfile(tmp_path_factory):
    """Write a dns_exporter.yml file with no configs in it."""
    confpath = tmp_path_factory.mktemp("conf") / "dns_exporter.yml"
    # write file to disk
    with Path.open(confpath, "w") as f:
        f.write("---")
    # return path to the config
    return confpath


@pytest.fixture
def dns_exporter_invalid_yaml_configfile(tmp_path_factory):
    """Write a dns_exporter.yml file with configs with errors in it."""
    confpath = tmp_path_factory.mktemp("conf") / "dns_exporter.yml"
    # write file to disk
    with Path.open(confpath, "w") as f:
        f.write("---\n")
        f.write("modules:\n")
        f.write("  broken:\n")
        f.write("    notakey: 42\n")
    # return path to the config
    return confpath


@pytest.fixture
def prometheus_server(request, tmp_path_factory, tmpdir_factory):
    """Run a prometheus server with a config provided by the unit test in request.param."""
    # write the prometheus config with scrape configs from request.param
    targetpath = Path(__file__).parents[0] / "tests" / "prometheus" / request.param
    with Path.open(targetpath) as f:
        targets = f.read()
    targets = yaml.load(targets.encode("utf-8"), Loader=yaml.SafeLoader)
    confpath = tmp_path_factory.mktemp("prometheus") / "prometheus.yml"
    # scrape asap please
    promconf = {"global": {"scrape_interval": "1s"}}
    promconf.update(targets)
    with Path.open(confpath, "w") as f:
        f.write(yaml.dump(promconf))
    # create prometheus datadir
    prompath = tmpdir_factory.mktemp("prometheus")
    print("Running Prometheus server...")
    proc = subprocess.Popen(
        args=[
            "prometheus",
            "--config.file",
            confpath,
            "--storage.tsdb.path",
            prompath,
            "--web.listen-address",
            "127.0.0.1:9092",
        ],
    )
    if proc.poll():
        pytest.fail("Unable to start prometheus on 127.0.0.1:9091")
    print("Setup finished - prometheus is running!")

    # end buildup
    yield request.param
    # begin teardown

    print("Beginning teardown")
    print("Stopping prometheus server...")
    proc.terminate()
    proc.communicate()
    print("Teardown finished!")


@pytest.fixture
def mock_collect_zerodivisionerror(mocker):
    """Monkeypatch DNSCollector.get_dns_response() to raise ZeroDivisionError (something not explicitly handled)."""
    mocker.patch(
        "dns_exporter.collector.DNSCollector.get_dns_response",
        side_effect=ZeroDivisionError("mocked"),
    )


@pytest.fixture(scope="session")
def proxy_server():
    """Run a proxy server on localhost port 1080 using gera2ld.socks.server."""
    print("Running proxy server on 127.0.0.1:1080...")
    proc = subprocess.Popen(
        args=[
            "python3",
            "-m",
            "gera2ld.socks.server",
            "-b",
            "127.0.0.1:1080",
        ],
    )
    time.sleep(3)
    if proc.poll():
        pytest.fail("Unable to start proxy on 127.0.0.1:1080")
    print("Setup finished - proxy is running on 127.0.0.1:1080!")

    # end buildup
    yield
    # begin teardown

    print("Beginning teardown")
    print("Stopping proxy server...")
    proc.terminate()
    proc.communicate()
    print("Teardown finished!")


@pytest.fixture
def mock_dns_query_https_valuerror(mocker):
    """Monkeypatch dns.query.https to raise a ValueError like a non-2XX statuscode was received from server."""
    mocker.patch(
        "dns.query.https",
        side_effect=ValueError("mocked"),
    )


@pytest.fixture
def mock_dns_query_httpx_connecttimeout(mocker):
    """Monkeypatch dns.query.https to raise a httpx.ConnectTimeout."""
    mocker.patch(
        "dns.query.https",
        side_effect=httpx.ConnectTimeout("mocked"),
    )

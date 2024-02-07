# type: ignore
"""pytest fixtures file for the dns_exporter project."""

import subprocess
import time
from http.server import HTTPServer
from pathlib import Path
from threading import Thread

import pytest
import yaml

from dns_exporter.entrypoint import main
from dns_exporter.exporter import DNSExporter


@pytest.fixture(scope="session")
def dns_exporter_no_main_no_config():
    """Run a basic server without main() and with no config."""
    print("Running server with no config on 127.0.0.1:45353 ...")
    serve_forever = HTTPServer(("127.0.0.1", 45353), DNSExporter).serve_forever
    thread = Thread(target=serve_forever)
    thread.daemon = True
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
        args=(["-c", "dns_exporter/dns_exporter_example.yml", "-p", "25353", "-d"],),
    )
    thread.daemon = True
    thread.start()
    time.sleep(1)
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
    yield
    print("Beginning teardown")


@pytest.fixture(scope="function")
def dns_exporter_param_config(request):
    """Run a server in a subprocess with the config from request.param."""
    print(f"Running dns_exporter with config {request.param} on 127.0.0.1:15353 ...")
    conf = Path(__file__).parents[0] / "tests" / "prometheus" / request.param
    proc = subprocess.Popen(
        args=["dns_exporter", "-c", str(conf), "-d"],
    )
    time.sleep(1)
    yield
    print(f"Stopping dns_exporter with config {request.param} on 127.0.0.1:15353 ...")
    proc.terminate()


@pytest.fixture
def dns_exporter_broken_yaml_configfile(tmp_path_factory):
    """Write a dns_exporter.yml file with invalid yaml."""
    confpath = tmp_path_factory.mktemp("conf") / "dns_exporter.yml"
    # write file to disk
    with open(confpath, "w") as f:
        f.write("foo:\nbar")
    # return path to the config
    return confpath


@pytest.fixture
def dns_exporter_empty_yaml_configfile(tmp_path_factory):
    """Write a dns_exporter.yml file with no configs in it."""
    confpath = tmp_path_factory.mktemp("conf") / "dns_exporter.yml"
    # write file to disk
    with open(confpath, "w") as f:
        f.write("---")
    # return path to the config
    return confpath


@pytest.fixture
def dns_exporter_invalid_yaml_configfile(tmp_path_factory):
    """Write a dns_exporter.yml file with configs with errors in it."""
    confpath = tmp_path_factory.mktemp("conf") / "dns_exporter.yml"
    # write file to disk
    with open(confpath, "w") as f:
        f.write("---\n")
        f.write("modules:\n")
        f.write("  broken:\n")
        f.write("    notakey: 42\n")
    # return path to the config
    return confpath


@pytest.fixture(scope="function")
def prometheus_server(request, tmp_path_factory, tmpdir_factory):
    # write the prometheus config with scrape configs from request.param
    targetpath = Path(__file__).parents[0] / "tests" / "prometheus" / request.param
    with open(targetpath) as f:
        targets = f.read()
    targets = yaml.load(targets.encode("utf-8"), Loader=yaml.SafeLoader)
    confpath = tmp_path_factory.mktemp("prometheus") / "prometheus.yml"
    # scrape asap please
    promconf = {"global": {"scrape_interval": "1s"}}
    promconf.update(targets)
    with open(confpath, "w") as f:
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
            "127.0.0.1:9091",
        ],
    )
    print("Setup finished - prometheus is running!")

    # end buildup
    yield request.param
    # begin teardown

    print("Beginning teardown")
    print("Stopping prometheus server...")
    proc.terminate()
    print("Teardown finished!")

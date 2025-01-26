"""``dns_exporter.entrypoint`` contains argparse stuff and ``dns_exporter`` script entrypoint.

This module is mostly boilerplate code for command-line argument handling and logging.
"""

from __future__ import annotations

import argparse
import logging
import sys
import warnings
from http.server import ThreadingHTTPServer
from pathlib import Path

import yaml

from dns_exporter.config import ConfigDict
from dns_exporter.exporter import DNSExporter

# get logger
logger = logging.getLogger(f"dns_exporter.{__name__}")


def get_parser() -> argparse.ArgumentParser:
    """Create and return the argparse object."""
    parser = argparse.ArgumentParser(
        description=f"dns_exporter version {DNSExporter.__version__}. See ReadTheDocs for more info.",
    )

    # optional arguments
    parser.add_argument(
        "-c",
        "--config-file",
        dest="config-file",
        help="The path to the yaml config file to use. Only the root 'modules' key is read from the config file.",
        default=argparse.SUPPRESS,
    )
    parser.add_argument(
        "-d",
        "--debug",
        action="store_const",
        dest="log-level",
        const="DEBUG",
        help="Debug mode. Equal to setting --log-level=DEBUG.",
        default=argparse.SUPPRESS,
    )
    parser.add_argument(
        "-L",
        "--listen-ip",
        type=str,
        help="Listen IP. Defaults to 127.0.0.1. Set to :: to listen on all v6 IPs.",
        default="127.0.0.1",
    )
    parser.add_argument(
        "-l",
        "--log-level",
        dest="log-level",
        choices=["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"],
        help="Logging level. One of DEBUG, INFO, WARNING, ERROR, CRITICAL. Defaults to INFO.",
        default="INFO",
    )
    parser.add_argument(
        "-p",
        "--port",
        dest="port",
        type=int,
        help="The port the exporter should listen for requests on. Default: 15353",
        default=15353,
    )
    parser.add_argument(
        "-q",
        "--quiet",
        action="store_const",
        dest="log-level",
        const="WARNING",
        help="Quiet mode. No output at all if no errors are encountered. Equal to setting --log-level=WARNING.",
        default=argparse.SUPPRESS,
    )
    parser.add_argument(
        "-v",
        "--version",
        dest="version",
        action="store_true",
        help="Show version and exit.",
        default=argparse.SUPPRESS,
    )
    return parser


def parse_args(
    mockargs: list[str] | None = None,
) -> tuple[argparse.ArgumentParser, argparse.Namespace]:
    """Create an argparse monster and parse mockargs or sys.argv[1:]."""
    parser = get_parser()
    args = parser.parse_args(mockargs if mockargs else sys.argv[1:])
    return parser, args


def main(mockargs: list[str] | None = None) -> None:
    """Read config and start exporter."""
    # suppress warnings at runtime
    if not sys.warnoptions:
        warnings.simplefilter("ignore")

    # get arpparser and parse args
    parser, args = parse_args(mockargs)

    # handle version check
    if hasattr(args, "version"):
        print(f"dns_exporter version {DNSExporter.__version__}")  # noqa: T201
        sys.exit(0)

    # configure the log format and level
    console_logformat = "%(asctime)s %(levelname)s %(name)s.%(funcName)s():%(lineno)i:  %(message)s"
    level = getattr(args, "log-level")
    logging.basicConfig(
        level=level,
        format=console_logformat,
        datefmt="%Y-%m-%d %H:%M:%S %z",
    )
    logger.setLevel(level)
    # also configure the root logger
    rootlogger = logging.getLogger("")
    rootlogger.setLevel(level)
    # httpx is noisy at INFO
    if level == "INFO":
        # httpx is noisy at level info, cap to WARNING
        logging.getLogger("httpx").setLevel(logging.WARNING)
    logger.info(
        f"dns_exporter v{DNSExporter.__version__} starting up - logging at level {level}",
    )

    if hasattr(args, "config-file"):
        with Path(getattr(args, "config-file")).open() as f:
            try:
                configfile = yaml.load(f, Loader=yaml.SafeLoader)
            except Exception:
                logger.exception(
                    f"Unable to parse YAML config file {getattr(args, 'config-file')} - bailing out.",
                )
                sys.exit(1)
        if (
            not configfile
            or "modules" not in configfile
            or not isinstance(configfile["modules"], dict)
            or not configfile["modules"]
        ):
            # configfile is empty, missing "modules" key, or modules is empty or not a dict
            logger.error(
                f"Invalid config file {getattr(args, 'config-file')} - yaml was valid but no modules found",
            )
            sys.exit(1)
        logger.debug(f"Read {len(configfile['modules'])} modules from config file {getattr(args, 'config-file')}:")
        logger.debug(list(configfile["modules"].keys()))
    else:
        # there is no config file
        configfile = {"modules": {}}
        logger.debug(
            "No -c / --config-file found so a config file will not be used. No modules loaded.",
        )

    # configure DNSExporter handler and start HTTPServer
    handler = DNSExporter
    if configfile["modules"] and not handler.configure(
        modules={k: ConfigDict(**v) for k, v in configfile["modules"].items()},  # type: ignore[typeddict-item]
    ):
        logger.error(
            "An error occurred while configuring dns_exporter. Bailing out.",
        )
        sys.exit(1)
    logger.info(
        f"Ready to serve requests. Starting listener on {args.listen_ip} port {args.port}...",
    )
    try:
        ThreadingHTTPServer((args.listen_ip, args.port), handler).serve_forever()
    except OSError:
        logger.exception(
            f"Unable to start listener, maybe port {args.port} is in use? bailing out",
        )
        sys.exit(1)


if __name__ == "__main__":  # pragma: no cover
    main()

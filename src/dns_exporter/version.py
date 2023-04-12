"""``dns_exporter.version`` takes care of getting the package version from SCM or file.

The module contains no functions or methods and only a single module-level variable which is the version.
"""
import logging
from importlib.metadata import PackageNotFoundError, version

# get logger
logger = logging.getLogger(f"dns_exporter.{__name__}")

# get version number from package metadata if possible
__version__: str = "0.0.0"
"""The value of this variable is taken from the Python package registry, and if that fails from the ``_version.py`` file written by ``setuptools_scm``."""

try:
    __version__ = version("dns_exporter")
except PackageNotFoundError:
    # package is not installed, get version from file
    try:
        from _version import version as __version__  # type: ignore
    except ImportError:
        # this must be a git checkout with no _version.py file, version unknown
        pass
logger.debug(f"Detected version running: {__version__}")

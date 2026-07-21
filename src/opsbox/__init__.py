"""OpsBox - Server Operations Tools Library.

A comprehensive Python library for server operations including backup scripts,
encrypted mail functionality, and utility tools.
"""

from importlib.metadata import PackageNotFoundError, version

try:
    # Single source of truth: the version declared in pyproject.toml.
    __version__ = version("opsbox")
except PackageNotFoundError:  # pragma: no cover - e.g. running from a raw checkout
    __version__ = "0.0.0.dev0"

__author__ = "OpsBox Team"
__email__ = "opsbox@example.com"

# Import only what's needed for the encrypted_mail module
from . import exceptions, logging

__all__ = ["exceptions", "logging"]

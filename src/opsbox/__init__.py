"""OpsBox - Server Operations Tools Library.

A comprehensive Python library for server operations including backup scripts,
encrypted mail functionality, and utility tools.
"""

__version__ = "0.1.0"
__author__ = "OpsBox Team"
__email__ = "opsbox@example.com"

# Import only what's needed for the encrypted_mail module
from . import exceptions, logging

__all__ = ["exceptions", "logging"]

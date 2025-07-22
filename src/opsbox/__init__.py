"""OpsBox - Server Operations Tools Library.

A comprehensive Python library for server operations including backup scripts,
encrypted mail functionality, and utility tools.
"""

__version__ = "0.1.0"
__author__ = "OpsBox Team"
__email__ = "opsbox@example.com"

from . import backup, encrypted_mail, locking, logging, utils

__all__ = ["backup", "encrypted_mail", "locking", "logging", "utils"]

"""Backup module for OpsBox with improved architecture and error handling."""

from .config_manager import BackupConfig, ConfigManager
from .exceptions import (
    BackupEnvironmentError,
    BackupError,
    ConfigurationError,
    FolderNotFoundError,
    InvalidResticConfigError,
    MaintenanceError,
    NetworkUnreachableError,
    PasswordIsEmptyError,
    PasswordRetrievalFailedError,
    ResticBackupFailedError,
    ResticCommandFailedError,
    SnapshotIDNotFoundError,
    SSHKeyNotFoundError,
    UserDoesNotExistError,
    VerificationError,
    WrongOSForResticBackupError,
)
from .network_checker import NetworkChecker
from .password_manager import PasswordManager
from .restic_backup import BackupScript
from .restic_client import ResticClient
from .ssh_manager import SSHManager

__all__ = [
    "BackupConfig",
    "BackupEnvironmentError",
    "BackupError",
    "BackupScript",
    "ConfigManager",
    "ConfigurationError",
    "FolderNotFoundError",
    "InvalidResticConfigError",
    "MaintenanceError",
    "NetworkChecker",
    "NetworkUnreachableError",
    "PasswordIsEmptyError",
    "PasswordManager",
    "PasswordRetrievalFailedError",
    "ResticBackupFailedError",
    "ResticClient",
    "ResticCommandFailedError",
    "SSHKeyNotFoundError",
    "SSHManager",
    "SnapshotIDNotFoundError",
    "UserDoesNotExistError",
    "VerificationError",
    "WrongOSForResticBackupError",
]

__version__ = "2.0.0"

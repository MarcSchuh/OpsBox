"""Custom exceptions for the backup module."""


class BackupError(Exception):
    """Base exception for all backup-related errors."""

    def __init__(self, message: str, original_error: Exception | None = None) -> None:
        """Initialize the exception with message and optional original error."""
        super().__init__(message)
        self.original_error = original_error
        self.message = message


class ConfigurationError(BackupError):
    """Raised when there are configuration-related issues."""


class InvalidResticConfigError(ConfigurationError):
    """Raised when restic configuration is invalid."""


class BackupEnvironmentError(BackupError):
    """Raised when there are environment-related issues."""


class WrongOSForResticBackupError(BackupEnvironmentError):
    """Raised when trying to run restic backup on unsupported OS."""


class ResticEnvNotSetError(BackupEnvironmentError):
    """Raised when restic environment is not properly configured."""


class SecurityError(BackupError):
    """Raised when there are security-related issues."""


class PasswordRetrievalFailedError(SecurityError):
    """Raised when password retrieval fails."""


class PasswordIsEmptyError(SecurityError):
    """Raised when retrieved password is empty."""


class SSHKeyNotFoundError(SecurityError):
    """Raised when required SSH key is not found."""


class UserDoesNotExistError(SecurityError):
    """Raised when specified user does not exist."""


class NetworkError(BackupError):
    """Raised when there are network-related issues."""


class NetworkUnreachableError(NetworkError):
    """Raised when target network is unreachable."""


class ResticError(BackupError):
    """Base exception for restic-related errors."""


class ResticBackupFailedError(ResticError):
    """Raised when restic backup operation fails."""


class ResticCommandFailedError(ResticError):
    """Raised when any restic command fails."""


class SnapshotIDNotFoundError(ResticError):
    """Raised when snapshot ID cannot be found in restic output."""


class VerificationError(BackupError):
    """Raised when backup verification fails."""


class MaintenanceError(BackupError):
    """Raised when maintenance operations fail."""


class DiffParsingError(BackupError):
    """Raised when there are issues parsing the diff output."""


class InvalidSnapshotIDError(BackupError):
    """Raised when snapshot ID format is invalid."""

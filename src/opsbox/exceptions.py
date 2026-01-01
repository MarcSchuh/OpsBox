"""Common exceptions used across the OpsBox library."""


class EmailSettingsNotFoundError(Exception):
    """Exception raised when email settings file is not found or invalid."""


class LockAlreadyTakenError(Exception):
    """Exception raised when a lock is already taken by another process."""


class MissingEnvVariableError(Exception):
    """Exception raised when a required environment variable is missing."""


class RsyncError(Exception):
    """Exception raised when rsync operations fail."""


class EmailSearchError(Exception):
    """Exception raised when email search operations fail."""


class EmailDeleteError(Exception):
    """Exception raised when email deletion operations fail."""


class EmailConnectionError(Exception):
    """Exception raised when email connection operations fail."""

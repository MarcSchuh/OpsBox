"""Custom exceptions for the notifier module."""


class NotificationError(Exception):
    """Base exception for all notification-related errors."""

    def __init__(self, message: str, original_error: Exception | None = None) -> None:
        """Initialize the exception with message and optional original error."""
        super().__init__(message)
        self.original_error = original_error
        self.message = message


class DBusNotAvailableError(NotificationError):
    """Raised when D-Bus is not available or cannot be imported."""


class DBusNotificationError(NotificationError):
    """Raised when D-Bus notification fails."""


class UserNotFoundError(NotificationError):
    """Raised when a specified user does not exist."""


class NotificationSendError(NotificationError):
    """Raised when sending a notification fails."""


class UsernameRequiredError(NotificationError):
    """Raised when username is required but not provided."""

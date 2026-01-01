"""Desktop notification functionality for OpsBox."""

from opsbox.notifier.exceptions import (
    DBusNotAvailableError,
    DBusNotificationError,
    NotificationError,
    NotificationSendError,
    UsernameRequiredError,
    UserNotFoundError,
)
from opsbox.notifier.notifier import NotificationSender

__all__ = [
    "DBusNotAvailableError",
    "DBusNotificationError",
    "NotificationError",
    "NotificationSendError",
    "NotificationSender",
    "UserNotFoundError",
    "UsernameRequiredError",
]

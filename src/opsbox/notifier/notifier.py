"""Desktop notification functionality for OpsBox."""

import argparse
import logging
import os
import pwd
import subprocess
import sys

import dbus
import dbus.exceptions

from opsbox.logging import LoggingConfig, configure_logging
from opsbox.notifier.exceptions import (
    DBusNotAvailableError,
    DBusNotificationError,
    NotificationSendError,
    UsernameRequiredError,
    UserNotFoundError,
)


class NotificationSender:
    """Handles sending desktop notifications via D-Bus."""

    def __init__(self, logger: logging.Logger) -> None:
        """Initialize the NotificationSender.

        Args:
            logger: Logger instance for logging operations

        """
        self.logger = logger

    def send_notification(
        self,
        summary: str,
        body: str,
        username: str | None = None,
    ) -> None:
        """Send a desktop notification.

        If running as root, username must be provided. Otherwise, sends
        notification to the current user.

        Args:
            summary: Notification summary/title
            body: Notification body/message
            username: Username to send notification to (required when running as root)

        Raises:
            UsernameRequiredError: If running as root without username
            NotificationSendError: If notification sending fails
            DBusNotAvailableError: If D-Bus is not available
            DBusNotificationError: If D-Bus notification fails
            UserNotFoundError: If specified user does not exist

        """
        if os.geteuid() == 0:
            # Running as root
            if username is None:
                error_msg = "Username is required when running as root"
                self.logger.error(error_msg)
                raise UsernameRequiredError(error_msg)
            self._send_as_user(summary, body, username)
        else:
            # Running as normal user
            self._send_via_dbus(summary, body)

    def _send_via_dbus(self, summary: str, body: str) -> None:
        """Send notification via D-Bus for the current user.

        Args:
            summary: Notification summary/title
            body: Notification body/message

        Raises:
            DBusNotAvailableError: If D-Bus module is not installed
            DBusNotificationError: If D-Bus notification fails

        """
        if dbus is None:
            error_msg = "D-Bus module is not installed"
            self.logger.error(error_msg)
            raise DBusNotAvailableError(error_msg)

        try:
            session_bus = dbus.SessionBus()
            notify_object = session_bus.get_object(
                "org.freedesktop.Notifications",
                "/org/freedesktop/Notifications",
            )
            notify_interface = dbus.Interface(
                notify_object,
                "org.freedesktop.Notifications",
            )
            notify_interface.Notify("OpsBox", 0, "", summary, body, [], {}, 5000)
            self.logger.info(f"Notification sent: {summary} - {body}")
        except dbus.exceptions.DBusException as e:
            error_msg = f"Failed to send notification via D-Bus: {e}"
            self.logger.exception(error_msg)
            raise DBusNotificationError(error_msg, original_error=e) from e

    def _send_as_user(self, summary: str, body: str, username: str) -> None:
        """Send notification as a specific user (for root execution).

        Args:
            summary: Notification summary/title
            body: Notification body/message
            username: Username to send notification to

        Raises:
            UserNotFoundError: If the specified user does not exist
            NotificationSendError: If sending the notification fails

        """
        try:
            user_info = pwd.getpwnam(username)
            user_uid = user_info.pw_uid
        except KeyError as e:
            error_msg = f"User {username} does not exist"
            self.logger.exception(error_msg)
            raise UserNotFoundError(error_msg) from e

        # Get the DISPLAY variable for the user
        try:
            display = (
                subprocess.check_output(  # noqa: S603
                    ["sudo", "-u", username, "echo", "$DISPLAY"],  # noqa: S607
                    stderr=subprocess.STDOUT,
                )
                .decode()
                .strip()
            )
            if not display:
                display = ":0"  # Default value
        except subprocess.CalledProcessError:
            display = ":0"  # Default value

        # Create command
        command = [
            "sudo",
            "-u",
            username,
            "env",
            f"DISPLAY={display}",
            f"DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/{user_uid}/bus",
            "notify-send",
            summary,
            body,
        ]

        try:
            subprocess.run(command, check=True)  # noqa: S603
            self.logger.info(
                f"Notification sent to {username}: {summary} - {body}",
            )
        except subprocess.CalledProcessError as e:
            error_msg = f"Failed to send notification to {username}: {e}"
            self.logger.exception(error_msg)
            raise NotificationSendError(error_msg, original_error=e) from e


def main() -> None:
    """Execute the main entry point for the notification sender script."""
    parser = argparse.ArgumentParser(
        description="Send desktop notifications via D-Bus",
    )
    parser.add_argument(
        "message",
        type=str,
        help="Notification message to send",
    )
    parser.add_argument(
        "--username",
        type=str,
        default=None,
        help="Username to send notification to (required when running as root)",
    )
    parser.add_argument(
        "--summary",
        type=str,
        default="Notification",
        help="Notification summary/title (default: 'Notification')",
    )
    parser.add_argument(
        "--log-level",
        type=str,
        default="INFO",
        choices=["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"],
        help="Set the logging level (default: INFO)",
    )
    args = parser.parse_args()

    logging_config = LoggingConfig(
        log_name="notification_sender",
        log_filename="notifications.log",
        log_level=args.log_level,
    )
    logger = configure_logging(logging_config)

    try:
        sender = NotificationSender(logger)
        sender.send_notification(args.summary, args.message, args.username)
    except (
        UsernameRequiredError,
        DBusNotAvailableError,
        DBusNotificationError,
        UserNotFoundError,
        NotificationSendError,
    ):
        logger.exception("Notification failed")
        sys.exit(1)
    except Exception:
        logger.exception("Unexpected error during notification")
        sys.exit(2)


if __name__ == "__main__":
    main()

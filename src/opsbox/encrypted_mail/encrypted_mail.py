"""Encrypted email functionality using GPG encryption."""

import argparse
import json
import logging
import os
import subprocess
import sys
import time
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

from envelope import Envelope

from opsbox.logging import LoggingConfig, configure_logging


class EmailSettingsNotFoundError(Exception):
    """Exception raised when email settings file is not found or invalid."""


@dataclass(frozen=True)
class MailSettings:
    """Configuration settings for email operations."""

    sender: str
    recipient: str
    password_lookup_1: str
    password_lookup_2: str
    host: str
    port: int
    user: str
    security: str
    gpg_key_id: str
    default_user: str
    password: str


class EncryptedMail:
    """Handles sending encrypted emails using GPG encryption."""

    # Class constants
    MAX_ATTACHMENT_SIZE = 5 * 1024 * 1024  # 5MB
    MAX_RETRY_ATTEMPTS = 10
    RETRY_DELAY_SECONDS = 2

    def __init__(
        self,
        logger: logging.Logger,
        email_settings_path: str,
        fail_silently: bool = False,
    ) -> None:
        """Initialize the EncryptedMail instance.

        Args:
            logger: Logger instance for logging operations
            email_settings_path: Path to the email settings JSON file
            fail_silently: If True, don't raise exceptions on send failures

        """
        self.logger = logger
        self.mail_settings = self.load_email_settings(email_settings_path)
        self.fail_silently = fail_silently

    def send_encrypted_mail(
        self,
        subject: str,
        message: str,
        mail_attachment: str | None = None,
    ) -> None:
        """Send an encrypted email with optional attachment.

        Args:
            subject: Email subject line
            message: Email message body
            mail_attachment: Optional path to file attachment

        Raises:
            subprocess.CalledProcessError: If user ID lookup fails
            FileNotFoundError: If attachment file not found
            Exception: For other email sending errors

        """
        self.logger.info(
            f"Sending email to {self.mail_settings.recipient} with subject '{subject}'",
        )

        # Get user ID
        get_user_id = subprocess.run(  # noqa: S603
            ["id", "-u", self.mail_settings.default_user],  # noqa: S607
            check=False,
            capture_output=True,
            text=True,
        )
        if get_user_id.returncode != 0:
            error_msg = f"Failed to get user ID for user '{self.mail_settings.default_user}': {get_user_id.stderr.strip()}"
            self.logger.error(error_msg)
            raise subprocess.CalledProcessError(
                get_user_id.returncode,
                get_user_id.args,
                error_msg,
            )
        user_id = get_user_id.stdout.strip()
        # Normalize line endings
        message = message.replace("\\n", "\n")
        email = Envelope(
            from_=self.mail_settings.sender,
            to=self.mail_settings.recipient,
            message=message,
        )

        def return_correct_decipherers() -> set[str]:
            return {self.mail_settings.recipient}

        email._get_decipherers = return_correct_decipherers  # noqa: SLF001
        email.subject(subject, encrypted=False)

        if mail_attachment:
            email = self._handle_attachment(
                email,
                mail_attachment,
                message,
                subject,
                return_correct_decipherers,
            )

        if not self.mail_settings.password:
            dbus_session_bus_address = os.getenv("DBUS_SESSION_BUS_ADDRESS", "")
            if "unix:path" not in dbus_session_bus_address:
                dbus_session_bus_address = f"unix:path=/run/user/{user_id}/bus"

            get_password = subprocess.run(  # noqa: S603
                [  # noqa: S607
                    "sudo",
                    "-u",
                    self.mail_settings.default_user,
                    f"DBUS_SESSION_BUS_ADDRESS={dbus_session_bus_address}",
                    "secret-tool",
                    "lookup",
                    self.mail_settings.password_lookup_1,
                    self.mail_settings.password_lookup_2,
                ],
                check=False,
                capture_output=True,
                text=True,
            )
            if get_password.returncode != 0:
                error_msg = f"Failed to retrieve password with secret-tool: {get_password.stderr.strip()}"
                self.logger.error(error_msg)
                raise subprocess.CalledProcessError(
                    get_password.returncode,
                    get_password.args,
                    error_msg,
                )

            password = get_password.stdout.strip()
            if not password:
                error_msg = "Retrieved password is empty"
                self.logger.error(error_msg)
                raise ValueError(error_msg)
        else:
            password = self.mail_settings.password

        email.smtp(
            host=self.mail_settings.host,
            port=self.mail_settings.port,
            user=self.mail_settings.user,
            password=password,
            security=self.mail_settings.security,
            attempts=self.MAX_RETRY_ATTEMPTS,
        )
        email.encryption(key=self.mail_settings.gpg_key_id)
        try:
            email.send(sign=False)
            self.logger.info(
                f"Email successfully sent to {self.mail_settings.recipient}",
            )
        except Exception:
            self.logger.exception("Error sending email")
            raise

    def send_mail_with_retries(
        self,
        subject: str,
        message: str,
        mail_attachment: str | None = None,
    ) -> None:
        """Send email with retry logic.

        Args:
            subject: Email subject line
            message: Email message body
            mail_attachment: Optional path to file attachment

        Raises:
            Exception: If all retry attempts fail and fail_silently is False

        """
        for attempt in range(1, self.MAX_RETRY_ATTEMPTS + 1):
            try:
                self.send_encrypted_mail(subject, message, mail_attachment)
                self.logger.info(f"Email successfully sent on attempt {attempt}")
                break
            except Exception:
                self.logger.exception(f"Attempt {attempt} failed")
                if attempt == self.MAX_RETRY_ATTEMPTS:
                    self.logger.exception("All attempts failed. Terminating.")
                    if not self.fail_silently:
                        raise
                else:
                    time.sleep(self.RETRY_DELAY_SECONDS)
                    self.logger.info(f"Starting attempt {attempt + 1}")

    @staticmethod
    def load_email_settings(path_to_mail_settings: str) -> MailSettings:
        """Load email settings from JSON configuration file.

        Args:
            path_to_mail_settings: Path to the JSON configuration file

        Returns:
            MailSettings object with loaded configuration

        Raises:
            EMailSettingsNotFound: If path is empty or file not found
            json.JSONDecodeError: If JSON is invalid
            KeyError: If required configuration keys are missing

        """
        if not path_to_mail_settings:
            error_msg = "email_settings_path not specified in configuration."
            raise EmailSettingsNotFoundError(error_msg)

        try:
            with Path(path_to_mail_settings).open(encoding="utf-8") as file:
                config = json.loads(file.read())
        except FileNotFoundError as e:
            error_msg = f"Email settings file not found: {path_to_mail_settings}"
            raise EmailSettingsNotFoundError(error_msg) from e
        except json.JSONDecodeError as e:
            error_msg = f"Invalid JSON in email settings file: {e}"
            raise EmailSettingsNotFoundError(error_msg) from e

        try:
            mail_settings = MailSettings(
                sender=config["sender"],
                recipient=config["recipient"],
                password_lookup_1=config["password_lookup_1"],
                password_lookup_2=config["password_lookup_2"],
                host=config["host"],
                port=config["port"],
                user=config["user"],
                security=config["security"],
                gpg_key_id=config["gpg_key_id"],
                default_user=config["default_user"],
                password=config.get("password", None),
            )
        except KeyError as e:
            error_msg = f"Missing required configuration key: {e}"
            raise EmailSettingsNotFoundError(error_msg) from e

        return mail_settings

    def _handle_attachment(
        self,
        email: Envelope,
        attachment_path: str,
        message: str,
        subject: str,
        decipherer_func: Callable[[], set],
    ) -> Envelope:
        """Handle email attachment processing.

        Args:
            email: The email envelope object
            attachment_path: Path to the attachment file
            message: Original message text
            subject: Original subject
            decipherer_func: Function to set decipherers

        Returns:
            Modified email envelope

        """
        attachment_path_obj = Path(attachment_path)
        if attachment_path_obj.is_file():
            file_size = attachment_path_obj.stat().st_size
            if file_size < self.MAX_ATTACHMENT_SIZE:
                email.attach(path=attachment_path)
                self.logger.info(f"Attachment '{attachment_path}' added")
                return email
            self.logger.warning(
                f"Attachment '{attachment_path}' is too large ({file_size} bytes). Sending without attachment.",
            )
            warning_message = f"!!!WARNING!!! {attachment_path} is too large ({file_size} bytes).\n{message}"
            warning_subject = f"{subject} -- Attachment too large"
        else:
            self.logger.warning(
                f"Attachment '{attachment_path}' not found. Sending without attachment.",
            )
            warning_message = (
                f"!!!WARNING!!! Attachment {attachment_path} not found\n{message}"
            )
            warning_subject = f"{subject} -- Attachment not found"

        # Create new email with warning
        warning_email = Envelope(
            from_=self.mail_settings.sender,
            to=self.mail_settings.recipient,
            message=warning_message,
        )
        warning_email._get_decipherers = decipherer_func  # noqa: SLF001
        warning_email.subject(warning_subject, encrypted=False)
        return warning_email


def main() -> None:
    """Execute the main entry point for the encrypted mail script."""
    parser = argparse.ArgumentParser(description="Send encrypted emails using GPG")
    parser.add_argument(
        "--email-settings",
        type=str,
        required=True,
        help="Path to email settings JSON file",
    )
    parser.add_argument("--subject", type=str, required=True, help="Email subject line")
    parser.add_argument("--message", type=str, required=True, help="Email message body")
    parser.add_argument(
        "--attachment",
        type=str,
        help="Optional path to file attachment",
    )
    args = parser.parse_args()

    try:
        # Configure logging
        logging_config = LoggingConfig(log_name="encrypted_mail")
        log_handler = configure_logging(logging_config)

        encrypted_mail = EncryptedMail(log_handler, args.email_settings)
        attachment = args.attachment if args.attachment else None
        encrypted_mail.send_mail_with_retries(args.subject, args.message, attachment)

    except EmailSettingsNotFoundError:
        log_handler.exception("Configuration error")
        sys.exit(1)
    except (OSError, subprocess.SubprocessError):
        log_handler.exception("System error")
        sys.exit(1)


if __name__ == "__main__":
    main()

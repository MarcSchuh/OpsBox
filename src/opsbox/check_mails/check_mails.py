"""Email checking functionality for monitoring expected emails."""

import argparse
import email
import imaplib
import json
import logging
import sys
import tempfile
import types
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from email.header import decode_header
from pathlib import Path

import yaml

from opsbox.encrypted_mail import EncryptedMail
from opsbox.exceptions import (
    EmailConnectionError,
    EmailDeleteError,
    EmailSearchError,
)
from opsbox.locking import LockManager
from opsbox.logging import LoggingConfig, configure_logging


@dataclass
class EmailSearchConfig:
    """Configuration for a single email search."""

    subject: str
    days_in_past: int = 1
    number_of_occurrences: int = 1
    match_any: bool = False


@dataclass
class DeleteOldEmailsConfig:
    """Configuration for deleting old emails."""

    enabled: bool = False
    older_than_days: int = 30
    folder: str = "inbox"


@dataclass
class EmailCheckerConfig:
    """Configuration for EmailChecker initialization."""

    email_account: str
    password: str
    imap_server: str
    logger: logging.Logger
    imap_port: int = 993
    imap_folder: str = "inbox"


@dataclass
class CheckMailsConfig:
    """Configuration for email checking operations."""

    email_settings_path: str
    imap_folder: str
    searches: list[EmailSearchConfig] = field(default_factory=list)
    delete_old_emails: DeleteOldEmailsConfig = field(
        default_factory=DeleteOldEmailsConfig,
    )

    def __post_init__(self) -> None:
        """Validate configuration after initialization."""
        if not self.email_settings_path:
            error_msg = "email_settings_path is required"
            raise ValueError(error_msg)
        if not self.imap_folder:
            error_msg = "imap_folder is required"
            raise ValueError(error_msg)
        if not self.searches:
            error_msg = "At least one search configuration is required"
            raise ValueError(error_msg)


class EmailChecker:
    """Handles email operations such as checking for emails with specific subjects."""

    def __init__(self, config: EmailCheckerConfig) -> None:
        """Initialize the EmailChecker instance.

        Args:
            config: EmailCheckerConfig containing all initialization parameters

        """
        self.email_account = config.email_account
        self.password = config.password
        self.imap_server = config.imap_server
        self.imap_port = config.imap_port
        self.logger = config.logger
        self.imap_folder = config.imap_folder
        self.mail: imaplib.IMAP4_SSL | None = None

    def __enter__(self) -> "EmailChecker":
        """Context manager entry point."""
        self.connect()
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_val: BaseException | None,
        exc_tb: types.TracebackType | None,
    ) -> None:
        """Context manager exit point."""
        self.disconnect()

    def connect(self) -> None:
        """Connect to the IMAP server and login to the email account.

        Raises:
            EmailConnectionError: If connection fails

        """
        try:
            self.mail = imaplib.IMAP4_SSL(self.imap_server, port=self.imap_port)
            self.mail.login(self.email_account, self.password)
            self.logger.info("Connected to email server.")
        except (imaplib.IMAP4.error, OSError, ConnectionError) as e:
            error_msg = f"Failed to connect to email server: {e}"
            self.logger.exception(error_msg)
            raise EmailConnectionError(error_msg) from e

    def disconnect(self) -> None:
        """Logout from the email account and close the connection."""
        if self.mail:
            try:
                self.mail.logout()
                self.logger.info("Disconnected from email server.")
            except (imaplib.IMAP4.error, AttributeError) as e:
                self.logger.warning(f"Error during disconnect: {e}")
        self.mail = None

    def check_email_subject(
        self,
        subject: str,
        number_of_occurrences: int,
        number_of_days_in_the_past: int,
        match_any: bool = False,
    ) -> bool:
        """Check if emails with a given subject were received at least n times within the last k days.

        Args:
            subject: The subject to search for
            number_of_occurrences: The minimum number of times the email should have been received
            number_of_days_in_the_past: The number of days to look back from now
            match_any: If True, match if subject contains the search string; if False, exact match

        Returns:
            True if the condition is met, False otherwise

        Raises:
            EmailSearchError: If search operation fails

        """
        if not self.mail:
            error_msg = "Email connection not available"
            raise EmailSearchError(error_msg)

        try:
            self.mail.select(self.imap_folder, readonly=True)
            # Escape double quotes in subject
            safe_subject = subject.replace('"', '\\"')

            # Calculate the SINCE date and BEFORE date
            date_since = (
                datetime.now(UTC) - timedelta(days=number_of_days_in_the_past - 1)
            ).strftime(
                "%d-%b-%Y",
            )
            date_before = (datetime.now(UTC) + timedelta(days=1)).strftime(
                "%d-%b-%Y",
            )  # date tomorrow

            search_criterion = f'(SINCE "{date_since}" BEFORE "{date_before}" SUBJECT "{safe_subject}")'
            result, data = self.mail.search(None, search_criterion)

            if result != "OK":
                error_msg = "Failed to search emails."
                self.logger.error(error_msg)
                raise EmailSearchError(error_msg)  # noqa: TRY301

            email_ids = data[0].split() if data[0] else []
            count = self._count_mails_with_subject(email_ids, subject, match_any)
            self.logger.info(
                f"Found {count} emails with subject '{subject}' in the last {number_of_days_in_the_past} days.",
            )

            if count >= number_of_occurrences:
                self.logger.info(
                    f"Condition met: received {count} emails with the subject in the time frame.",
                )
                return True
            self.logger.warning(
                f"Condition not met: only {count} emails received; expected at least {number_of_occurrences}.",
            )
            return False  # noqa: TRY300

        except EmailSearchError:
            raise
        except (imaplib.IMAP4.error, AttributeError, IndexError) as e:
            error_msg = f"An error occurred while checking emails: {e}"
            self.logger.exception(error_msg)
            raise EmailSearchError(error_msg) from e

    def _count_mails_with_subject(  # noqa: C901
        self,
        email_ids: list[bytes],
        searched_subject: str,
        match_any: bool,
    ) -> int:
        """Count emails matching the subject criteria.

        Args:
            email_ids: List of email IDs to check
            searched_subject: The subject to search for
            match_any: If True, match if subject contains the search string; if False, exact match

        Returns:
            Number of matching emails

        """
        if not self.mail:
            error_msg = "Email connection not available"
            raise EmailSearchError(error_msg)

        count = 0
        for email_id in email_ids:
            # Fetch the email headers (don't need the body)
            result, msg_data = self.mail.fetch(email_id.decode(), "(BODY.PEEK[HEADER])")
            if result != "OK" or not msg_data or not msg_data[0]:
                self.logger.error(f"Failed to fetch email with ID {email_id.decode()}.")
                continue

            # Parse the email
            msg_body = msg_data[0][1]
            if not isinstance(msg_body, bytes):
                continue
            msg = email.message_from_bytes(msg_body)

            # Decode the email subject
            msg_subject_encoded = msg.get("Subject", "")
            if not msg_subject_encoded:
                continue

            decoded_header = decode_header(msg_subject_encoded)
            if not decoded_header:
                continue

            msg_subject, encoding = decoded_header[0]
            if isinstance(msg_subject, bytes):
                msg_subject = msg_subject.decode(encoding or "utf-8")

            # Compare the decoded subject with the provided subject
            if match_any:
                if searched_subject in msg_subject:
                    count += 1
            elif msg_subject == searched_subject:
                count += 1
        return count

    def delete_emails_older_than(self, n_days: int, folder: str = "inbox") -> None:
        """Delete all emails older than n days.

        Args:
            n_days: The number of days; emails older than this will be deleted
            folder: The IMAP folder to delete from (default: "inbox")

        Raises:
            EmailDeleteError: If deletion operation fails

        """
        if not self.mail:
            error_msg = "Email connection not available"
            raise EmailDeleteError(error_msg)

        try:
            self.mail.select(folder)
            date_cutoff = (datetime.now(UTC) - timedelta(days=n_days)).strftime(
                "%d-%b-%Y",
            )
            search_criterion = f"(BEFORE {date_cutoff})"
            result, data = self.mail.search(None, search_criterion)

            if result != "OK":
                error_msg = f"Failed to search for emails older than {n_days} days."
                self.logger.error(error_msg)
                raise EmailDeleteError(error_msg)  # noqa: TRY301

            email_ids = data[0].split() if data[0] else []
            count = len(email_ids)
            self.logger.info(f"Found {count} emails older than {n_days} days.")

            if count == 0:
                self.logger.info("No emails to delete.")
                return

            for email_id in email_ids:
                # Mark the email for deletion
                self.mail.store(email_id.decode(), "+FLAGS", "\\Deleted")

            # Permanently remove emails marked for deletion
            self.mail.expunge()
            self.logger.info(f"Deleted {count} emails older than {n_days} days.")

        except EmailDeleteError:
            raise
        except (imaplib.IMAP4.error, AttributeError, IndexError) as e:
            error_msg = f"An error occurred while deleting emails: {e}"
            self.logger.exception(error_msg)
            raise EmailDeleteError(error_msg) from e


def load_config(config_path: Path) -> CheckMailsConfig:
    """Load and validate configuration from YAML or JSON file.

    Args:
        config_path: Path to the configuration YAML or JSON file

    Returns:
        Validated CheckMailsConfig instance

    Raises:
        FileNotFoundError: If configuration file not found
        ValueError: If configuration is invalid

    """
    if not config_path.exists() or not config_path.is_file():
        error_msg = f"Configuration file not found: {config_path}"
        raise FileNotFoundError(error_msg)

    try:
        with config_path.open(encoding="utf-8") as f:
            if config_path.suffix in (".yaml", ".yml"):
                config_data = yaml.safe_load(f)
            else:
                config_data = json.load(f)
    except Exception as e:
        error_msg = f"Error loading configuration file: {e}"
        raise ValueError(error_msg) from e

    try:
        # Parse searches
        searches = [
            EmailSearchConfig(
                subject=search_data["subject"],
                days_in_past=search_data.get("days_in_past", 1),
                number_of_occurrences=search_data.get("number_of_occurrences", 1),
                match_any=search_data.get("match_any", False),
            )
            for search_data in config_data.get("searches", [])
        ]

        # Parse delete_old_emails config
        delete_config_data = config_data.get("delete_old_emails", {})
        delete_config = DeleteOldEmailsConfig(
            enabled=delete_config_data.get("enabled", False),
            older_than_days=delete_config_data.get("older_than_days", 30),
            folder=delete_config_data.get("folder", "inbox"),
        )

        return CheckMailsConfig(
            email_settings_path=config_data["email_settings_path"],
            imap_folder=config_data["imap_folder"],
            searches=searches,
            delete_old_emails=delete_config,
        )
    except KeyError as e:
        error_msg = f"Missing required configuration field: {e}"
        raise ValueError(error_msg) from e
    except Exception as e:
        error_msg = f"Configuration validation failed: {e}"
        raise ValueError(error_msg) from e


def main() -> None:
    """Execute the main entry point for the check_mails script."""
    parser = argparse.ArgumentParser(
        description="Check for expected emails in IMAP mailbox",
    )
    parser.add_argument(
        "--config",
        type=str,
        required=True,
        help="Path to configuration YAML or JSON file",
    )
    parser.add_argument(
        "--log-level",
        type=str,
        default="INFO",
        help="Logging level (default: INFO)",
    )
    args = parser.parse_args()

    logging_config = LoggingConfig(log_name="check_mails", log_level=args.log_level)
    logger = configure_logging(logging_config)

    config = load_config(Path(args.config))
    logger.info(f"Loaded configuration from {args.config}")

    email_settings = EncryptedMail.load_email_settings(Path(config.email_settings_path))
    logger.info("Loaded email settings")

    encrypted_mail = EncryptedMail(
        logger,
        Path(config.email_settings_path),
        fail_silently=True,
    )

    script_name = Path(__file__).name
    lock_file_path = Path(tempfile.gettempdir()) / f"{script_name}.lock"
    lock_manager = LockManager(
        lock_file=lock_file_path,
        logger=logger,
        encrypted_mail=encrypted_mail,
        script_name=script_name,
    )

    with (
        lock_manager,
        EmailChecker(
            EmailCheckerConfig(
                email_account=email_settings.user,
                password=email_settings.password,
                imap_server=email_settings.host,
                logger=logger,
                imap_folder=config.imap_folder,
            ),
        ) as email_checker,
    ):
        number_of_problems = 0
        failed_searches: list[str] = []

        for search_config in config.searches:
            logger.info(
                f"Checking for email: '{search_config.subject}' "
                f"(expecting {search_config.number_of_occurrences} in last {search_config.days_in_past} days)",
            )
            if not email_checker.check_email_subject(
                search_config.subject,
                search_config.number_of_occurrences,
                search_config.days_in_past,
                search_config.match_any,
            ):
                number_of_problems += 1
                failed_searches.append(search_config.subject)

        # Handle old email deletion if enabled
        if config.delete_old_emails.enabled:
            logger.info(
                f"Deleting emails older than {config.delete_old_emails.older_than_days} days "
                f"from folder '{config.delete_old_emails.folder}'",
            )
            email_checker.delete_emails_older_than(
                config.delete_old_emails.older_than_days,
                config.delete_old_emails.folder,
            )

        # Send notification if problems found
        if number_of_problems > 0:
            error_message = (
                f"Problems finding expected emails!\n\n"
                f"Failed searches ({number_of_problems}):\n"
                + "\n".join(f"  - {subject}" for subject in failed_searches)
            )
            try:
                encrypted_mail.send_mail_with_retries(
                    subject="Problems finding all searched mails!",
                    message=error_message,
                )
                logger.info("Notification email sent")
            except Exception:
                logger.exception("Failed to send notification email")

            logger.error("Check not successful!")
            sys.exit(1)
        else:
            logger.info("All email checks successful!")


if __name__ == "__main__":
    main()

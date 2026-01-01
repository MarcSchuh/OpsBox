"""Tests for the EmailChecker class."""

import imaplib
import logging
from email.message import Message
from unittest.mock import MagicMock, patch

import pytest

from opsbox.check_mails.check_mails import EmailChecker, EmailCheckerConfig
from opsbox.exceptions import (
    EmailConnectionError,
    EmailDeleteError,
    EmailSearchError,
)


class TestEmailCheckerConnection:
    """Test cases for EmailChecker connection management."""

    def test_connect_success(self) -> None:
        """Test successful connection to IMAP server."""
        logger = logging.getLogger("test")
        mock_imap = MagicMock()
        mock_imap.login.return_value = ("OK", [b"Login successful"])

        with patch(
            "opsbox.check_mails.check_mails.imaplib.IMAP4_SSL",
            return_value=mock_imap,
        ):
            config = EmailCheckerConfig(
                email_account="test@example.com",
                password="password123",
                imap_server="imap.example.com",
                logger=logger,
            )
            checker = EmailChecker(config)
            checker.connect()

            assert checker.mail is not None
            mock_imap.login.assert_called_once_with("test@example.com", "password123")

    def test_connect_with_custom_port(self) -> None:
        """Test connection with custom IMAP port."""
        logger = logging.getLogger("test")
        mock_imap = MagicMock()
        mock_imap.login.return_value = ("OK", [b"Login successful"])

        with patch(
            "opsbox.check_mails.check_mails.imaplib.IMAP4_SSL",
            return_value=mock_imap,
        ) as mock_imap_class:
            config = EmailCheckerConfig(
                email_account="test@example.com",
                password="password123",
                imap_server="imap.example.com",
                logger=logger,
                imap_port=143,
            )
            checker = EmailChecker(config)
            checker.connect()

            assert checker.mail is not None
            # Verify IMAP4_SSL was called with custom port
            mock_imap_class.assert_called_once_with("imap.example.com", port=143)

    def test_connect_failure_imap_error(self) -> None:
        """Test that EmailConnectionError is raised on IMAP connection failure."""
        logger = logging.getLogger("test")
        mock_imap = MagicMock()
        mock_imap.login.side_effect = imaplib.IMAP4.error("Authentication failed")

        with patch(
            "opsbox.check_mails.check_mails.imaplib.IMAP4_SSL",
            return_value=mock_imap,
        ):
            config = EmailCheckerConfig(
                email_account="test@example.com",
                password="wrong_password",
                imap_server="imap.example.com",
                logger=logger,
            )
            checker = EmailChecker(config)

            with pytest.raises(
                EmailConnectionError,
                match="Failed to connect to email server",
            ):
                checker.connect()

    def test_connect_failure_os_error(self) -> None:
        """Test that EmailConnectionError is raised on network connection failure."""
        logger = logging.getLogger("test")

        with patch(
            "opsbox.check_mails.check_mails.imaplib.IMAP4_SSL",
            side_effect=OSError("Connection refused"),
        ):
            config = EmailCheckerConfig(
                email_account="test@example.com",
                password="password123",
                imap_server="imap.example.com",
                logger=logger,
            )
            checker = EmailChecker(config)

            with pytest.raises(
                EmailConnectionError,
                match="Failed to connect to email server",
            ):
                checker.connect()

    def test_disconnect_success(self) -> None:
        """Test successful disconnection from IMAP server."""
        logger = logging.getLogger("test")
        mock_imap = MagicMock()
        mock_imap.logout.return_value = ("OK", [b"Logout successful"])

        with patch(
            "opsbox.check_mails.check_mails.imaplib.IMAP4_SSL",
            return_value=mock_imap,
        ):
            config = EmailCheckerConfig(
                email_account="test@example.com",
                password="password123",
                imap_server="imap.example.com",
                logger=logger,
            )
            checker = EmailChecker(config)
            checker.connect()
            checker.disconnect()

            mock_imap.logout.assert_called_once()
            assert checker.mail is None

    def test_disconnect_handles_errors_gracefully(self) -> None:
        """Test that disconnect handles errors gracefully without crashing."""
        logger = logging.getLogger("test")
        mock_imap = MagicMock()
        mock_imap.logout.side_effect = imaplib.IMAP4.error("Already logged out")

        with patch(
            "opsbox.check_mails.check_mails.imaplib.IMAP4_SSL",
            return_value=mock_imap,
        ):
            config = EmailCheckerConfig(
                email_account="test@example.com",
                password="password123",
                imap_server="imap.example.com",
                logger=logger,
            )
            checker = EmailChecker(config)
            checker.connect()
            # Should not raise an exception
            checker.disconnect()

            assert checker.mail is None

    def test_context_manager_connects_on_enter(self) -> None:
        """Test that context manager connects on enter."""
        logger = logging.getLogger("test")
        mock_imap = MagicMock()
        mock_imap.login.return_value = ("OK", [b"Login successful"])

        with patch(
            "opsbox.check_mails.check_mails.imaplib.IMAP4_SSL",
            return_value=mock_imap,
        ):
            config = EmailCheckerConfig(
                email_account="test@example.com",
                password="password123",
                imap_server="imap.example.com",
                logger=logger,
            )
            with EmailChecker(config) as checker:
                assert checker.mail is not None
                mock_imap.login.assert_called_once()

    def test_context_manager_disconnects_on_exit(self) -> None:
        """Test that context manager disconnects on exit."""
        logger = logging.getLogger("test")
        mock_imap = MagicMock()
        mock_imap.login.return_value = ("OK", [b"Login successful"])
        mock_imap.logout.return_value = ("OK", [b"Logout successful"])

        with patch(
            "opsbox.check_mails.check_mails.imaplib.IMAP4_SSL",
            return_value=mock_imap,
        ):
            config = EmailCheckerConfig(
                email_account="test@example.com",
                password="password123",
                imap_server="imap.example.com",
                logger=logger,
            )
            with EmailChecker(config):
                pass

            mock_imap.logout.assert_called_once()


class TestEmailCheckerEmailSearch:
    """Test cases for email subject checking functionality."""

    def _create_mock_email_message(self, subject: str) -> bytes:
        """Create a mock email message with the given subject."""
        msg = Message()
        msg["Subject"] = subject
        return msg.as_bytes()

    def test_check_email_subject_exact_match_found(self) -> None:
        """Test checking email subject with exact match when email is found."""
        logger = logging.getLogger("test")
        mock_imap = MagicMock()
        mock_imap.login.return_value = ("OK", [b"Login successful"])
        mock_imap.select.return_value = ("OK", [b"1"])
        mock_imap.search.return_value = ("OK", [b"1 2"])
        mock_imap.fetch.return_value = (
            "OK",
            [
                (
                    b"1 (BODY[HEADER] {100}",
                    self._create_mock_email_message("Test Subject"),
                ),
                (
                    b"2 (BODY[HEADER] {100}",
                    self._create_mock_email_message("Test Subject"),
                ),
            ],
        )

        with patch(
            "opsbox.check_mails.check_mails.imaplib.IMAP4_SSL",
            return_value=mock_imap,
        ):
            config = EmailCheckerConfig(
                email_account="test@example.com",
                password="password123",
                imap_server="imap.example.com",
                logger=logger,
            )
            checker = EmailChecker(config)
            checker.connect()

            result = checker.check_email_subject(
                subject="Test Subject",
                number_of_occurrences=2,
                number_of_days_in_the_past=1,
                match_any=False,
            )

            assert result is True
            mock_imap.select.assert_called_once_with("inbox", readonly=True)

    def test_check_email_subject_exact_match_not_found(self) -> None:
        """Test checking email subject with exact match when email is not found."""
        logger = logging.getLogger("test")
        mock_imap = MagicMock()
        mock_imap.login.return_value = ("OK", [b"Login successful"])
        mock_imap.select.return_value = ("OK", [b"1"])
        mock_imap.search.return_value = ("OK", [b""])  # No emails found

        with patch(
            "opsbox.check_mails.check_mails.imaplib.IMAP4_SSL",
            return_value=mock_imap,
        ):
            config = EmailCheckerConfig(
                email_account="test@example.com",
                password="password123",
                imap_server="imap.example.com",
                logger=logger,
            )
            checker = EmailChecker(config)
            checker.connect()

            result = checker.check_email_subject(
                subject="Test Subject",
                number_of_occurrences=1,
                number_of_days_in_the_past=1,
                match_any=False,
            )

            assert result is False

    def test_check_email_subject_match_any_partial_match(self) -> None:
        """Test checking email subject with match_any=True matches partial subjects."""
        logger = logging.getLogger("test")
        mock_imap = MagicMock()
        mock_imap.login.return_value = ("OK", [b"Login successful"])
        mock_imap.select.return_value = ("OK", [b"1"])
        mock_imap.search.return_value = ("OK", [b"1"])
        mock_imap.fetch.return_value = (
            "OK",
            [
                (
                    b"1 (BODY[HEADER] {100}",
                    self._create_mock_email_message("Errorlog found for backup.."),
                ),
            ],
        )

        with patch(
            "opsbox.check_mails.check_mails.imaplib.IMAP4_SSL",
            return_value=mock_imap,
        ):
            config = EmailCheckerConfig(
                email_account="test@example.com",
                password="password123",
                imap_server="imap.example.com",
                logger=logger,
            )
            checker = EmailChecker(config)
            checker.connect()

            result = checker.check_email_subject(
                subject="Errorlog",
                number_of_occurrences=1,
                number_of_days_in_the_past=1,
                match_any=True,
            )

            assert result is True

    def test_check_email_subject_match_any_exact_match_required(self) -> None:
        """Test checking email subject with match_any=False requires exact match."""
        logger = logging.getLogger("test")
        mock_imap = MagicMock()
        mock_imap.login.return_value = ("OK", [b"Login successful"])
        mock_imap.select.return_value = ("OK", [b"1"])
        mock_imap.search.return_value = ("OK", [b"1"])
        mock_imap.fetch.return_value = (
            "OK",
            [
                (
                    b"1 (BODY[HEADER] {100}",
                    self._create_mock_email_message("Errorlog found for backup.."),
                ),
            ],
        )

        with patch(
            "opsbox.check_mails.check_mails.imaplib.IMAP4_SSL",
            return_value=mock_imap,
        ):
            config = EmailCheckerConfig(
                email_account="test@example.com",
                password="password123",
                imap_server="imap.example.com",
                logger=logger,
            )
            checker = EmailChecker(config)
            checker.connect()

            result = checker.check_email_subject(
                subject="Errorlog",
                number_of_occurrences=1,
                number_of_days_in_the_past=1,
                match_any=False,
            )

            assert result is False  # Partial match doesn't count with match_any=False

    def test_check_email_subject_insufficient_occurrences(self) -> None:
        """Test checking email subject when occurrences are insufficient."""
        logger = logging.getLogger("test")
        mock_imap = MagicMock()
        mock_imap.login.return_value = ("OK", [b"Login successful"])
        mock_imap.select.return_value = ("OK", [b"1"])
        mock_imap.search.return_value = ("OK", [b"1"])
        mock_imap.fetch.return_value = (
            "OK",
            [
                (
                    b"1 (BODY[HEADER] {100}",
                    self._create_mock_email_message("Test Subject"),
                ),
            ],
        )

        with patch(
            "opsbox.check_mails.check_mails.imaplib.IMAP4_SSL",
            return_value=mock_imap,
        ):
            config = EmailCheckerConfig(
                email_account="test@example.com",
                password="password123",
                imap_server="imap.example.com",
                logger=logger,
            )
            checker = EmailChecker(config)
            checker.connect()

            result = checker.check_email_subject(
                subject="Test Subject",
                number_of_occurrences=2,  # Need 2, but only 1 found
                number_of_days_in_the_past=1,
                match_any=False,
            )

            assert result is False

    def test_check_email_subject_without_connection(self) -> None:
        """Test that EmailSearchError is raised when checking without connection."""
        logger = logging.getLogger("test")
        config = EmailCheckerConfig(
            email_account="test@example.com",
            password="password123",
            imap_server="imap.example.com",
            logger=logger,
        )
        checker = EmailChecker(config)
        # Don't connect

        with pytest.raises(EmailSearchError, match="Email connection not available"):
            checker.check_email_subject(
                subject="Test Subject",
                number_of_occurrences=1,
                number_of_days_in_the_past=1,
            )

    def test_check_email_subject_search_failure(self) -> None:
        """Test that EmailSearchError is raised when IMAP search fails."""
        logger = logging.getLogger("test")
        mock_imap = MagicMock()
        mock_imap.login.return_value = ("OK", [b"Login successful"])
        mock_imap.select.return_value = ("OK", [b"1"])
        mock_imap.search.return_value = ("NO", [b"Search failed"])

        with patch(
            "opsbox.check_mails.check_mails.imaplib.IMAP4_SSL",
            return_value=mock_imap,
        ):
            config = EmailCheckerConfig(
                email_account="test@example.com",
                password="password123",
                imap_server="imap.example.com",
                logger=logger,
            )
            checker = EmailChecker(config)
            checker.connect()

            with pytest.raises(EmailSearchError, match="Failed to search emails"):
                checker.check_email_subject(
                    subject="Test Subject",
                    number_of_occurrences=1,
                    number_of_days_in_the_past=1,
                )

    def test_check_email_subject_custom_folder(self) -> None:
        """Test checking email subject with custom IMAP folder."""
        logger = logging.getLogger("test")
        mock_imap = MagicMock()
        mock_imap.login.return_value = ("OK", [b"Login successful"])
        mock_imap.select.return_value = ("OK", [b"1"])
        mock_imap.search.return_value = ("OK", [b"1"])
        mock_imap.fetch.return_value = (
            "OK",
            [
                (
                    b"1 (BODY[HEADER] {100}",
                    self._create_mock_email_message("Test Subject"),
                ),
            ],
        )

        with patch(
            "opsbox.check_mails.check_mails.imaplib.IMAP4_SSL",
            return_value=mock_imap,
        ):
            config = EmailCheckerConfig(
                email_account="test@example.com",
                password="password123",
                imap_server="imap.example.com",
                logger=logger,
                imap_folder="server",
            )
            checker = EmailChecker(config)
            checker.connect()

            checker.check_email_subject(
                subject="Test Subject",
                number_of_occurrences=1,
                number_of_days_in_the_past=1,
            )

            mock_imap.select.assert_called_once_with("server", readonly=True)


class TestEmailCheckerEmailDeletion:
    """Test cases for email deletion functionality."""

    def test_delete_emails_older_than_success(self) -> None:
        """Test deleting emails older than N days successfully."""
        logger = logging.getLogger("test")
        mock_imap = MagicMock()
        mock_imap.login.return_value = ("OK", [b"Login successful"])
        mock_imap.select.return_value = ("OK", [b"1"])
        mock_imap.search.return_value = ("OK", [b"1 2 3"])
        mock_imap.store.return_value = ("OK", [b"Stored"])
        mock_imap.expunge.return_value = ("OK", [b"Expunged"])

        with patch(
            "opsbox.check_mails.check_mails.imaplib.IMAP4_SSL",
            return_value=mock_imap,
        ):
            config = EmailCheckerConfig(
                email_account="test@example.com",
                password="password123",
                imap_server="imap.example.com",
                logger=logger,
            )
            checker = EmailChecker(config)
            checker.connect()

            checker.delete_emails_older_than(n_days=30, folder="inbox")

            mock_imap.select.assert_called_once_with("inbox")
            assert mock_imap.store.call_count == 3  # Three emails marked for deletion
            mock_imap.expunge.assert_called_once()

    def test_delete_emails_older_than_no_emails_found(self) -> None:
        """Test deleting emails when no old emails are found."""
        logger = logging.getLogger("test")
        mock_imap = MagicMock()
        mock_imap.login.return_value = ("OK", [b"Login successful"])
        mock_imap.select.return_value = ("OK", [b"1"])
        mock_imap.search.return_value = ("OK", [b""])  # No emails found

        with patch(
            "opsbox.check_mails.check_mails.imaplib.IMAP4_SSL",
            return_value=mock_imap,
        ):
            config = EmailCheckerConfig(
                email_account="test@example.com",
                password="password123",
                imap_server="imap.example.com",
                logger=logger,
            )
            checker = EmailChecker(config)
            checker.connect()

            # Should not raise an exception
            checker.delete_emails_older_than(n_days=30, folder="inbox")

            mock_imap.select.assert_called_once_with("inbox")
            mock_imap.store.assert_not_called()
            mock_imap.expunge.assert_not_called()

    def test_delete_emails_older_than_without_connection(self) -> None:
        """Test that EmailDeleteError is raised when deleting without connection."""
        logger = logging.getLogger("test")
        config = EmailCheckerConfig(
            email_account="test@example.com",
            password="password123",
            imap_server="imap.example.com",
            logger=logger,
        )
        checker = EmailChecker(config)
        # Don't connect

        with pytest.raises(EmailDeleteError, match="Email connection not available"):
            checker.delete_emails_older_than(n_days=30)

    def test_delete_emails_older_than_search_failure(self) -> None:
        """Test that EmailDeleteError is raised when search for old emails fails."""
        logger = logging.getLogger("test")
        mock_imap = MagicMock()
        mock_imap.login.return_value = ("OK", [b"Login successful"])
        mock_imap.select.return_value = ("OK", [b"1"])
        mock_imap.search.return_value = ("NO", [b"Search failed"])

        with patch(
            "opsbox.check_mails.check_mails.imaplib.IMAP4_SSL",
            return_value=mock_imap,
        ):
            config = EmailCheckerConfig(
                email_account="test@example.com",
                password="password123",
                imap_server="imap.example.com",
                logger=logger,
            )
            checker = EmailChecker(config)
            checker.connect()

            with pytest.raises(
                EmailDeleteError,
                match="Failed to search for emails older than",
            ):
                checker.delete_emails_older_than(n_days=30)

    def test_delete_emails_older_than_custom_folder(self) -> None:
        """Test deleting emails from a custom folder."""
        logger = logging.getLogger("test")
        mock_imap = MagicMock()
        mock_imap.login.return_value = ("OK", [b"Login successful"])
        mock_imap.select.return_value = ("OK", [b"1"])
        mock_imap.search.return_value = ("OK", [b"1"])
        mock_imap.store.return_value = ("OK", [b"Stored"])
        mock_imap.expunge.return_value = ("OK", [b"Expunged"])

        with patch(
            "opsbox.check_mails.check_mails.imaplib.IMAP4_SSL",
            return_value=mock_imap,
        ):
            config = EmailCheckerConfig(
                email_account="test@example.com",
                password="password123",
                imap_server="imap.example.com",
                logger=logger,
            )
            checker = EmailChecker(config)
            checker.connect()

            checker.delete_emails_older_than(n_days=60, folder="archive")

            mock_imap.select.assert_called_once_with("archive")


if __name__ == "__main__":
    pytest.main([__file__])

"""Tests for the lock manager module."""

import logging
import os
import tempfile
from pathlib import Path
from unittest.mock import Mock, patch

import pytest

from opsbox.encrypted_mail import EncryptedMail
from opsbox.exceptions import EmailSettingsNotFoundError, LockAlreadyTakenError
from opsbox.locking.lock_manager import LockManager


class TestLockManager:
    """Test cases for LockManager functionality."""

    def test_init_with_all_parameters(self) -> None:
        """Test LockManager initialization with all parameters."""
        with tempfile.TemporaryDirectory() as temp_dir:
            lock_file = Path(temp_dir) / "test.lock"
            logger = Mock(spec=logging.Logger)
            encrypted_mail = Mock(spec=EncryptedMail)
            script_name = "test_script.py"

            lock_manager = LockManager(
                lock_file=lock_file,
                logger=logger,
                encrypted_mail=encrypted_mail,
                script_name=script_name,
            )

            assert lock_manager.lock_file == lock_file
            assert lock_manager.logger == logger
            assert lock_manager.encrypted_mail == encrypted_mail
            assert lock_manager.script_name == script_name

    def test_init_with_minimal_parameters(self) -> None:
        """Test LockManager initialization with only required parameters."""
        with tempfile.TemporaryDirectory() as temp_dir:
            lock_file = Path(temp_dir) / "test.lock"
            logger = Mock(spec=logging.Logger)

            lock_manager = LockManager(lock_file=lock_file, logger=logger)

            assert lock_manager.lock_file == lock_file
            assert lock_manager.logger == logger
            assert lock_manager.encrypted_mail is None
            assert lock_manager.script_name is None

    def test_init_with_none_optional_parameters(self) -> None:
        """Test LockManager initialization with None for optional parameters."""
        with tempfile.TemporaryDirectory() as temp_dir:
            lock_file = Path(temp_dir) / "test.lock"
            logger = Mock(spec=logging.Logger)

            lock_manager = LockManager(
                lock_file=lock_file,
                logger=logger,
                encrypted_mail=None,
                script_name=None,
            )

            assert lock_manager.lock_file == lock_file
            assert lock_manager.logger == logger
            assert lock_manager.encrypted_mail is None
            assert lock_manager.script_name is None

    def test_context_manager_success(self) -> None:
        """Test context manager creates and releases lock successfully."""
        with tempfile.TemporaryDirectory() as temp_dir:
            lock_file = Path(temp_dir) / "test.lock"
            logger = Mock(spec=logging.Logger)

            with LockManager(lock_file=lock_file, logger=logger) as lock_manager:
                assert lock_manager.lock_file == lock_file
                assert lock_file.exists()

            # Lock should be released after context exit
            assert not lock_file.exists()
            # Check that both log messages were called
            assert logger.info.call_count == 2
            logger.info.assert_any_call(f"Lock file {lock_file} created.")
            logger.info.assert_any_call("Lock file released.")

    def test_context_manager_with_exception(self) -> None:
        """Test context manager releases lock even when exception occurs."""
        with tempfile.TemporaryDirectory() as temp_dir:
            lock_file = Path(temp_dir) / "test.lock"
            logger = Mock(spec=logging.Logger)
            test_exception_message = "Test exception"

            with pytest.raises(ValueError, match=test_exception_message):
                with LockManager(lock_file=lock_file, logger=logger):
                    raise ValueError(test_exception_message)

            # Lock should still be released despite exception
            assert not lock_file.exists()
            # Check that both log messages were called
            assert logger.info.call_count == 2
            logger.info.assert_any_call(f"Lock file {lock_file} created.")
            logger.info.assert_any_call("Lock file released.")

    def test_create_lock_success(self) -> None:
        """Test successful lock creation when lock file doesn't exist."""
        with tempfile.TemporaryDirectory() as temp_dir:
            lock_file = Path(temp_dir) / "test.lock"
            logger = Mock(spec=logging.Logger)

            lock_manager = LockManager(lock_file=lock_file, logger=logger)
            lock_manager.create_lock()

            assert lock_file.exists()
            logger.info.assert_called_with(f"Lock file {lock_file} created.")

    def test_create_lock_already_exists(self) -> None:
        """Test lock creation fails when lock file already exists."""
        with tempfile.TemporaryDirectory() as temp_dir:
            lock_file = Path(temp_dir) / "test.lock"
            logger = Mock(spec=logging.Logger)

            # Create the lock file first
            lock_file.touch()

            lock_manager = LockManager(lock_file=lock_file, logger=logger)

            with pytest.raises(LockAlreadyTakenError) as exc_info:
                lock_manager.create_lock()

            assert str(exc_info.value) == f"Lock file {lock_file} already exists."
            logger.error.assert_called_with(
                "Lock file exists. Another instance may be running.",
            )

    def test_create_lock_already_exists_with_email_notification(self) -> None:
        """Test email notification is sent when lock is already taken."""
        with tempfile.TemporaryDirectory() as temp_dir:
            lock_file = Path(temp_dir) / "test.lock"
            logger = Mock(spec=logging.Logger)
            encrypted_mail = Mock(spec=EncryptedMail)
            script_name = "test_script.py"

            # Create the lock file first
            lock_file.touch()

            lock_manager = LockManager(
                lock_file=lock_file,
                logger=logger,
                encrypted_mail=encrypted_mail,
                script_name=script_name,
            )

            with pytest.raises(LockAlreadyTakenError):
                lock_manager.create_lock()

            encrypted_mail.send_mail_with_retries.assert_called_once_with(
                subject=f"Lock already taken by script {script_name}",
                message=f"The lock file {lock_file} already exists. Script {script_name} cannot acquire lock.",
            )

    def test_create_lock_already_exists_without_email_config(self) -> None:
        """Test no email notification when email is not configured."""
        with tempfile.TemporaryDirectory() as temp_dir:
            lock_file = Path(temp_dir) / "test.lock"
            logger = Mock(spec=logging.Logger)

            # Create the lock file first
            lock_file.touch()

            lock_manager = LockManager(lock_file=lock_file, logger=logger)

            with pytest.raises(LockAlreadyTakenError):
                lock_manager.create_lock()

            # Should not try to send email
            logger.error.assert_called_with(
                "Lock file exists. Another instance may be running.",
            )

    def test_create_lock_already_exists_without_script_name(self) -> None:
        """Test no email notification when script_name is not provided."""
        with tempfile.TemporaryDirectory() as temp_dir:
            lock_file = Path(temp_dir) / "test.lock"
            logger = Mock(spec=logging.Logger)
            encrypted_mail = Mock(spec=EncryptedMail)

            # Create the lock file first
            lock_file.touch()

            lock_manager = LockManager(
                lock_file=lock_file,
                logger=logger,
                encrypted_mail=encrypted_mail,
                script_name=None,
            )

            with pytest.raises(LockAlreadyTakenError):
                lock_manager.create_lock()

            # Should not try to send email
            encrypted_mail.send_mail_with_retries.assert_not_called()

    def test_create_lock_email_sending_failure(self) -> None:
        """Test email sending failure is handled gracefully."""
        with tempfile.TemporaryDirectory() as temp_dir:
            lock_file = Path(temp_dir) / "test.lock"
            logger = Mock(spec=logging.Logger)
            encrypted_mail = Mock(spec=EncryptedMail)
            script_name = "test_script.py"

            # Configure email to raise an exception
            encrypted_mail.send_mail_with_retries.side_effect = (
                EmailSettingsNotFoundError("Email settings not found")
            )

            # Create the lock file first
            lock_file.touch()

            lock_manager = LockManager(
                lock_file=lock_file,
                logger=logger,
                encrypted_mail=encrypted_mail,
                script_name=script_name,
            )

            with pytest.raises(LockAlreadyTakenError):
                lock_manager.create_lock()

            # Should log the email failure but still raise LockAlreadyTakenError
            logger.exception.assert_called_with(
                "Failed to send lock notification email",
            )

    def test_create_lock_email_os_error(self) -> None:
        """Test OSError from email sending is handled gracefully."""
        with tempfile.TemporaryDirectory() as temp_dir:
            lock_file = Path(temp_dir) / "test.lock"
            logger = Mock(spec=logging.Logger)
            encrypted_mail = Mock(spec=EncryptedMail)
            script_name = "test_script.py"

            # Configure email to raise OSError
            encrypted_mail.send_mail_with_retries.side_effect = OSError("Network error")

            # Create the lock file first
            lock_file.touch()

            lock_manager = LockManager(
                lock_file=lock_file,
                logger=logger,
                encrypted_mail=encrypted_mail,
                script_name=script_name,
            )

            with pytest.raises(LockAlreadyTakenError):
                lock_manager.create_lock()

            # Should log the email failure but still raise LockAlreadyTakenError
            logger.exception.assert_called_with(
                "Failed to send lock notification email",
            )

    def test_release_lock_success(self) -> None:
        """Test successful lock release when lock file exists."""
        with tempfile.TemporaryDirectory() as temp_dir:
            lock_file = Path(temp_dir) / "test.lock"
            logger = Mock(spec=logging.Logger)

            # Create the lock file first
            lock_file.touch()

            lock_manager = LockManager(lock_file=lock_file, logger=logger)
            lock_manager.release_lock()

            assert not lock_file.exists()
            logger.info.assert_called_with("Lock file released.")

    def test_release_lock_file_not_exists(self) -> None:
        """Test lock release when lock file doesn't exist."""
        with tempfile.TemporaryDirectory() as temp_dir:
            lock_file = Path(temp_dir) / "test.lock"
            logger = Mock(spec=logging.Logger)

            lock_manager = LockManager(lock_file=lock_file, logger=logger)
            lock_manager.release_lock()

            assert not lock_file.exists()
            logger.warning.assert_called_with(
                "Lock file does not exist when attempting to release.",
            )

    def test_lock_file_permissions_error(self) -> None:
        """Test behavior when lock file directory has permission issues."""
        with tempfile.TemporaryDirectory() as temp_dir:
            lock_file = Path(temp_dir) / "test.lock"
            logger = Mock(spec=logging.Logger)

            # Mock Path.touch to raise PermissionError
            with patch.object(
                Path,
                "touch",
                side_effect=PermissionError("Permission denied"),
            ):
                lock_manager = LockManager(lock_file=lock_file, logger=logger)

                with pytest.raises(PermissionError):
                    lock_manager.create_lock()

    def test_lock_file_directory_not_exists(self) -> None:
        """Test behavior when lock file directory doesn't exist."""
        lock_file = Path("/nonexistent/directory/test.lock")
        logger = Mock(spec=logging.Logger)

        lock_manager = LockManager(lock_file=lock_file, logger=logger)

        with pytest.raises(FileNotFoundError):
            lock_manager.create_lock()

    def test_lock_file_with_spaces_in_path(self) -> None:
        """Test lock file creation with spaces in the path."""
        with tempfile.TemporaryDirectory() as temp_dir:
            lock_file = Path(temp_dir) / "test lock file.lock"
            logger = Mock(spec=logging.Logger)

            lock_manager = LockManager(lock_file=lock_file, logger=logger)
            lock_manager.create_lock()

            assert lock_file.exists()
            logger.info.assert_called_with(f"Lock file {lock_file} created.")

    def test_lock_file_relative_path(self) -> None:
        """Test lock file creation with relative path."""
        with tempfile.TemporaryDirectory() as temp_dir:
            # Change to temp directory to test relative paths
            original_cwd = Path.cwd()
            try:
                os.chdir(temp_dir)
                lock_file = Path("relative_test.lock")
                logger = Mock(spec=logging.Logger)

                lock_manager = LockManager(lock_file=lock_file, logger=logger)
                lock_manager.create_lock()

                assert lock_file.exists()
                logger.info.assert_called_with(f"Lock file {lock_file} created.")
            finally:
                os.chdir(original_cwd)

    def test_concurrent_lock_attempts(self) -> None:
        """Test multiple instances trying to acquire the same lock."""
        with tempfile.TemporaryDirectory() as temp_dir:
            lock_file = Path(temp_dir) / "concurrent_test.lock"
            logger1 = Mock(spec=logging.Logger)
            logger2 = Mock(spec=logging.Logger)

            # First instance should succeed
            lock_manager1 = LockManager(lock_file=lock_file, logger=logger1)
            lock_manager1.create_lock()

            # Second instance should fail
            lock_manager2 = LockManager(lock_file=lock_file, logger=logger2)
            with pytest.raises(LockAlreadyTakenError):
                lock_manager2.create_lock()

            # Release first lock
            lock_manager1.release_lock()

            # Now second instance should succeed
            lock_manager2.create_lock()
            assert lock_file.exists()

    def test_lock_file_race_condition(self) -> None:
        """Test race condition where lock file is created between check and creation."""
        with tempfile.TemporaryDirectory() as temp_dir:
            lock_file = Path(temp_dir) / "race_test.lock"
            logger = Mock(spec=logging.Logger)

            lock_manager = LockManager(lock_file=lock_file, logger=logger)

            # Mock Path.touch to raise FileExistsError to simulate race condition
            with patch.object(
                Path,
                "touch",
                side_effect=FileExistsError("File exists"),
            ):
                with pytest.raises(FileExistsError):
                    lock_manager.create_lock()

    def test_lock_already_taken_error_message(self) -> None:
        """Test that LockAlreadyTakenError includes proper error message."""
        with tempfile.TemporaryDirectory() as temp_dir:
            lock_file = Path(temp_dir) / "error_test.lock"
            logger = Mock(spec=logging.Logger)

            # Create the lock file first
            lock_file.touch()

            lock_manager = LockManager(lock_file=lock_file, logger=logger)

            with pytest.raises(LockAlreadyTakenError) as exc_info:
                lock_manager.create_lock()

            expected_message = f"Lock file {lock_file} already exists."
            assert str(exc_info.value) == expected_message


if __name__ == "__main__":
    pytest.main([__file__])

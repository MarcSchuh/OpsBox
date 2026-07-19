"""Tests for the lock manager module."""

import fcntl
import logging
import os
import tempfile
from pathlib import Path
from unittest.mock import Mock, patch

import pytest

from opsbox.encrypted_mail import EncryptedMail
from opsbox.exceptions import EmailSettingsNotFoundError, LockAlreadyTakenError
from opsbox.locking.lock_manager import LockManager


def _hold_flock(lock_file: Path) -> int:
    """Acquire an exclusive advisory lock on ``lock_file`` and return the fd.

    Simulates another running instance holding the lock. The caller is
    responsible for closing the returned descriptor.
    """
    fd = os.open(lock_file, os.O_RDWR | os.O_CREAT, 0o644)
    fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    return fd


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
            assert lock_manager._lock_fd is None

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
                assert lock_manager._lock_fd is not None

            # The advisory lock is released (fd closed) after context exit.
            assert lock_manager._lock_fd is None
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

            lock_manager = LockManager(lock_file=lock_file, logger=logger)
            with pytest.raises(ValueError, match=test_exception_message):
                with lock_manager:
                    raise ValueError(test_exception_message)

            # Lock should still be released despite exception
            assert lock_manager._lock_fd is None
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
            assert lock_manager._lock_fd is not None
            logger.info.assert_called_with(f"Lock file {lock_file} created.")

            lock_manager.release_lock()

    def test_create_lock_writes_holder_diagnostics(self) -> None:
        """Test that PID/host diagnostics are written into the lock file."""
        with tempfile.TemporaryDirectory() as temp_dir:
            lock_file = Path(temp_dir) / "test.lock"
            logger = Mock(spec=logging.Logger)

            lock_manager = LockManager(lock_file=lock_file, logger=logger)
            lock_manager.create_lock()
            try:
                contents = lock_file.read_text()
                assert f"pid={os.getpid()}" in contents
                assert "host=" in contents
                assert "acquired=" in contents
            finally:
                lock_manager.release_lock()

    def test_create_lock_already_held(self) -> None:
        """Test lock creation fails when the lock is actively held."""
        with tempfile.TemporaryDirectory() as temp_dir:
            lock_file = Path(temp_dir) / "test.lock"
            logger = Mock(spec=logging.Logger)

            holder_fd = _hold_flock(lock_file)
            try:
                lock_manager = LockManager(lock_file=lock_file, logger=logger)

                with pytest.raises(LockAlreadyTakenError) as exc_info:
                    lock_manager.create_lock()

                assert str(exc_info.value) == f"Lock file {lock_file} is already held."
                assert lock_manager._lock_fd is None
                logger.error.assert_called_once()
            finally:
                os.close(holder_fd)

    def test_create_lock_already_held_with_email_notification(self) -> None:
        """Test email notification is sent when lock is already held."""
        with tempfile.TemporaryDirectory() as temp_dir:
            lock_file = Path(temp_dir) / "test.lock"
            logger = Mock(spec=logging.Logger)
            encrypted_mail = Mock(spec=EncryptedMail)
            script_name = "test_script.py"

            holder_fd = _hold_flock(lock_file)
            try:
                lock_manager = LockManager(
                    lock_file=lock_file,
                    logger=logger,
                    encrypted_mail=encrypted_mail,
                    script_name=script_name,
                )

                with pytest.raises(LockAlreadyTakenError):
                    lock_manager.create_lock()

                encrypted_mail.send_mail_with_retries.assert_called_once()
                call_kwargs = encrypted_mail.send_mail_with_retries.call_args.kwargs
                assert (
                    call_kwargs["subject"]
                    == f"Lock already taken by script {script_name}"
                )
                assert str(lock_file) in call_kwargs["message"]
            finally:
                os.close(holder_fd)

    def test_create_lock_already_held_without_email_config(self) -> None:
        """Test no email notification when email is not configured."""
        with tempfile.TemporaryDirectory() as temp_dir:
            lock_file = Path(temp_dir) / "test.lock"
            logger = Mock(spec=logging.Logger)

            holder_fd = _hold_flock(lock_file)
            try:
                lock_manager = LockManager(lock_file=lock_file, logger=logger)

                with pytest.raises(LockAlreadyTakenError):
                    lock_manager.create_lock()

                logger.error.assert_called_once()
            finally:
                os.close(holder_fd)

    def test_create_lock_already_held_without_script_name(self) -> None:
        """Test no email notification when script_name is not provided."""
        with tempfile.TemporaryDirectory() as temp_dir:
            lock_file = Path(temp_dir) / "test.lock"
            logger = Mock(spec=logging.Logger)
            encrypted_mail = Mock(spec=EncryptedMail)

            holder_fd = _hold_flock(lock_file)
            try:
                lock_manager = LockManager(
                    lock_file=lock_file,
                    logger=logger,
                    encrypted_mail=encrypted_mail,
                    script_name=None,
                )

                with pytest.raises(LockAlreadyTakenError):
                    lock_manager.create_lock()

                encrypted_mail.send_mail_with_retries.assert_not_called()
            finally:
                os.close(holder_fd)

    def test_create_lock_email_sending_failure(self) -> None:
        """Test email sending failure is handled gracefully."""
        with tempfile.TemporaryDirectory() as temp_dir:
            lock_file = Path(temp_dir) / "test.lock"
            logger = Mock(spec=logging.Logger)
            encrypted_mail = Mock(spec=EncryptedMail)
            script_name = "test_script.py"

            encrypted_mail.send_mail_with_retries.side_effect = (
                EmailSettingsNotFoundError("Email settings not found")
            )

            holder_fd = _hold_flock(lock_file)
            try:
                lock_manager = LockManager(
                    lock_file=lock_file,
                    logger=logger,
                    encrypted_mail=encrypted_mail,
                    script_name=script_name,
                )

                with pytest.raises(LockAlreadyTakenError):
                    lock_manager.create_lock()

                logger.exception.assert_called_with(
                    "Failed to send lock notification email",
                )
            finally:
                os.close(holder_fd)

    def test_create_lock_email_os_error(self) -> None:
        """Test OSError from email sending is handled gracefully."""
        with tempfile.TemporaryDirectory() as temp_dir:
            lock_file = Path(temp_dir) / "test.lock"
            logger = Mock(spec=logging.Logger)
            encrypted_mail = Mock(spec=EncryptedMail)
            script_name = "test_script.py"

            encrypted_mail.send_mail_with_retries.side_effect = OSError("Network error")

            holder_fd = _hold_flock(lock_file)
            try:
                lock_manager = LockManager(
                    lock_file=lock_file,
                    logger=logger,
                    encrypted_mail=encrypted_mail,
                    script_name=script_name,
                )

                with pytest.raises(LockAlreadyTakenError):
                    lock_manager.create_lock()

                logger.exception.assert_called_with(
                    "Failed to send lock notification email",
                )
            finally:
                os.close(holder_fd)

    def test_release_lock_success(self) -> None:
        """Test successful lock release when a lock is held."""
        with tempfile.TemporaryDirectory() as temp_dir:
            lock_file = Path(temp_dir) / "test.lock"
            logger = Mock(spec=logging.Logger)

            lock_manager = LockManager(lock_file=lock_file, logger=logger)
            lock_manager.create_lock()
            lock_manager.release_lock()

            assert lock_manager._lock_fd is None
            logger.info.assert_called_with("Lock file released.")

    def test_release_lock_not_held(self) -> None:
        """Test lock release when no lock is held."""
        with tempfile.TemporaryDirectory() as temp_dir:
            lock_file = Path(temp_dir) / "test.lock"
            logger = Mock(spec=logging.Logger)

            lock_manager = LockManager(lock_file=lock_file, logger=logger)
            lock_manager.release_lock()

            logger.warning.assert_called_with(
                "Lock file does not exist when attempting to release.",
            )

    def test_lock_file_permissions_error(self) -> None:
        """Test behavior when lock file cannot be opened due to permissions."""
        with tempfile.TemporaryDirectory() as temp_dir:
            lock_file = Path(temp_dir) / "test.lock"
            logger = Mock(spec=logging.Logger)

            with patch(
                "opsbox.locking.lock_manager.os.open",
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
            try:
                assert lock_file.exists()
                logger.info.assert_called_with(f"Lock file {lock_file} created.")
            finally:
                lock_manager.release_lock()

    def test_lock_file_relative_path(self) -> None:
        """Test lock file creation with relative path."""
        with tempfile.TemporaryDirectory() as temp_dir:
            original_cwd = Path.cwd()
            try:
                os.chdir(temp_dir)
                lock_file = Path("relative_test.lock")
                logger = Mock(spec=logging.Logger)

                lock_manager = LockManager(lock_file=lock_file, logger=logger)
                lock_manager.create_lock()
                assert lock_file.exists()
                logger.info.assert_called_with(f"Lock file {lock_file} created.")
                lock_manager.release_lock()
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

            # Second instance should fail while the first holds the lock
            lock_manager2 = LockManager(lock_file=lock_file, logger=logger2)
            with pytest.raises(LockAlreadyTakenError):
                lock_manager2.create_lock()

            # Release first lock
            lock_manager1.release_lock()

            # Now second instance should succeed
            lock_manager2.create_lock()
            assert lock_file.exists()
            lock_manager2.release_lock()

    def test_stale_lock_file_does_not_block(self) -> None:
        """Test that a leftover lock file with no active flock does not block."""
        with tempfile.TemporaryDirectory() as temp_dir:
            lock_file = Path(temp_dir) / "stale.lock"
            logger = Mock(spec=logging.Logger)

            # Simulate a stale lock file left behind by a crashed process:
            # the file exists but nobody holds an advisory lock on it.
            lock_file.write_text("pid=99999 host=dead acquired=2020-01-01T00:00:00")

            lock_manager = LockManager(lock_file=lock_file, logger=logger)
            lock_manager.create_lock()
            try:
                assert lock_manager._lock_fd is not None
            finally:
                lock_manager.release_lock()

    def test_lock_already_taken_error_message(self) -> None:
        """Test that LockAlreadyTakenError includes proper error message."""
        with tempfile.TemporaryDirectory() as temp_dir:
            lock_file = Path(temp_dir) / "error_test.lock"
            logger = Mock(spec=logging.Logger)

            holder_fd = _hold_flock(lock_file)
            try:
                lock_manager = LockManager(lock_file=lock_file, logger=logger)

                with pytest.raises(LockAlreadyTakenError) as exc_info:
                    lock_manager.create_lock()

                expected_message = f"Lock file {lock_file} is already held."
                assert str(exc_info.value) == expected_message
            finally:
                os.close(holder_fd)


if __name__ == "__main__":
    pytest.main([__file__])

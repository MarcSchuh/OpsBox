"""Lock management functionality for concurrent operations."""

import logging
import types
from pathlib import Path

from opsbox.encrypted_mail import EmailSettingsNotFoundError, EncryptedMail


class LockAlreadyTakenError(Exception):
    """Exception raised when a lock is already taken by another process."""


class LockManager:
    """Manages file-based locks for concurrent operations."""

    def __init__(
        self,
        lock_file: Path,
        logger: logging.Logger,
        encrypted_mail: EncryptedMail | None = None,
        script_name: str | None = None,
    ) -> None:
        """Initialize the LockManager.

        Args:
            lock_file: Path to the lock file
            logger: Logger instance for logging operations
            encrypted_mail: Optional encrypted mail instance for notifications
            script_name: Optional name of the script for notifications

        """
        self.lock_file = lock_file
        self.logger = logger
        self.encrypted_mail = encrypted_mail
        self.script_name = script_name

    def __enter__(self) -> "LockManager":
        """Context manager entry point."""
        self.create_lock()
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_val: BaseException | None,
        exc_tb: types.TracebackType | None,
    ) -> None:
        """Context manager exit point."""
        self.release_lock()

    def create_lock(self) -> None:
        """Create a lock file.

        Raises:
            LockAlreadyTakenError: If the lock file already exists

        """
        if self.lock_file.exists():
            self.logger.error("Lock file exists. Another instance may be running.")

            # Send email notification if configured
            if self.encrypted_mail and self.script_name:
                try:
                    self.encrypted_mail.send_mail_with_retries(
                        subject=f"Lock already taken by script {self.script_name}",
                        message=f"The lock file {self.lock_file} already exists. Script {self.script_name} cannot acquire lock.",
                    )
                except (EmailSettingsNotFoundError, OSError):
                    self.logger.exception("Failed to send lock notification email")

            # Raise custom exception
            error_message = f"Lock file {self.lock_file} already exists."
            raise LockAlreadyTakenError(error_message)
        self.lock_file.touch()
        self.logger.info("Lock file created.")

    def release_lock(self) -> None:
        """Release the lock file."""
        if self.lock_file.exists():
            self.lock_file.unlink()
            self.logger.info("Lock file released.")
        else:
            self.logger.warning("Lock file does not exist when attempting to release.")

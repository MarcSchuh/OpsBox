"""Lock management functionality for concurrent operations."""

import fcntl
import logging
import os
import socket
import types
from datetime import datetime
from pathlib import Path

from opsbox.encrypted_mail import EncryptedMail
from opsbox.exceptions import EmailSettingsNotFoundError, LockAlreadyTakenError

_HOLDER_INFO_READ_SIZE = 4096


class LockManager:
    """Manages advisory ``flock``-based locks for concurrent operations.

    The lock is held via an exclusive, non-blocking ``fcntl.flock`` on an open
    file descriptor for the lifetime of the manager. This is robust against
    stale locks: a lock file that merely exists (e.g. left behind by a crashed
    process) does not block a new run, because the advisory lock is released
    automatically by the kernel when the holding process dies. Diagnostic
    information (PID, host, acquisition time) is written into the lock file so
    that a genuinely concurrent run can report who currently holds the lock.
    """

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
        self._lock_fd: int | None = None

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
        """Acquire an exclusive advisory lock on the lock file.

        Raises:
            LockAlreadyTakenError: If the lock is actively held by another
                (running) process.

        """
        # Open (creating if necessary) and keep the descriptor for the whole
        # lifetime of the lock: the flock is bound to this open file description.
        fd = os.open(self.lock_file, os.O_RDWR | os.O_CREAT, 0o644)

        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError as error:
            # The lock is currently held by another live process.
            holder_info = self._read_holder_info(fd)
            os.close(fd)
            self.logger.exception(
                "Lock is held by another running instance. "
                f"Current holder: {holder_info}",
            )
            self._notify_lock_taken(holder_info)
            error_message = f"Lock file {self.lock_file} is already held."
            raise LockAlreadyTakenError(error_message) from error

        self._lock_fd = fd
        self._write_holder_info(fd)
        self.logger.info(f"Lock file {self.lock_file} created.")

    def release_lock(self) -> None:
        """Release the advisory lock and close the descriptor."""
        if self._lock_fd is None:
            self.logger.warning("Lock file does not exist when attempting to release.")
            return

        try:
            fcntl.flock(self._lock_fd, fcntl.LOCK_UN)
        finally:
            os.close(self._lock_fd)
            self._lock_fd = None
        self.logger.info("Lock file released.")

    def _write_holder_info(self, fd: int) -> None:
        """Write PID/host/timestamp diagnostics into the lock file."""
        info = (
            f"pid={os.getpid()} "
            f"host={socket.gethostname()} "
            f"acquired={datetime.now().astimezone().isoformat()}"
        )
        try:
            os.lseek(fd, 0, os.SEEK_SET)
            os.ftruncate(fd, 0)
            os.write(fd, info.encode("utf-8"))
            os.fsync(fd)
        except OSError:
            self.logger.debug("Could not write lock holder diagnostics", exc_info=True)

    def _read_holder_info(self, fd: int) -> str:
        """Read the diagnostics written by the current lock holder."""
        try:
            os.lseek(fd, 0, os.SEEK_SET)
            raw = os.read(fd, _HOLDER_INFO_READ_SIZE)
        except OSError:
            return "unknown (could not read lock file)"
        info = raw.decode("utf-8", errors="replace").strip()
        return info or "unknown (lock file empty)"

    def _notify_lock_taken(self, holder_info: str) -> None:
        """Send an email notification that the lock could not be acquired."""
        if not (self.encrypted_mail and self.script_name):
            return
        try:
            self.encrypted_mail.send_mail_with_retries(
                subject=f"Lock already taken by script {self.script_name}",
                message=(
                    f"The lock file {self.lock_file} is held by another running "
                    f"instance; script {self.script_name} cannot acquire the lock.\n\n"
                    f"Current holder: {holder_info}"
                ),
            )
        except (EmailSettingsNotFoundError, OSError):
            self.logger.exception("Failed to send lock notification email")

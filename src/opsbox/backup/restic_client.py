"""Restic client for executing restic commands with proper error handling and logging."""

import logging
import subprocess
import tempfile
from pathlib import Path

from opsbox.backup.exceptions import (
    ResticCommandFailedError,
    SnapshotIDNotFoundError,
)
from opsbox.encrypted_mail import EncryptedMail


class ResticClient:
    """Handles all restic command execution with proper error handling and logging."""

    MIN_SNAPSHOT_ID_LENGTH = 7
    SNAPSHOT_PARTS_MIN_LENGTH = 2

    def __init__(
        self,
        restic_path: str,
        backup_target: str,
        logger: logging.Logger,
        encrypted_mail: EncryptedMail,
    ) -> None:
        """Initialize the restic client with path, target, logger, and encrypted mail."""
        self.restic_path = restic_path
        self.backup_target = backup_target
        self.logger = logger
        self.encrypted_mail = encrypted_mail
        self.temp_dir = Path(tempfile.gettempdir())
        self.temp_dir.mkdir(parents=True, exist_ok=True)
        self.cache_dir = self.temp_dir / "restic_cache"
        self._restic_env: dict[str, str] | None = None

        # Create temporary log file for all commands
        with tempfile.NamedTemporaryFile(
            suffix=".log",
            prefix="restic_",
            delete=False,
        ) as temp_file:
            temp_file_path = temp_file.name
        self.log_file = Path(temp_file_path)
        self.logger.info(f"Created temporary log file: {self.log_file}")

    def set_environment(
        self,
        restic_password: str,
        ssh_auth_sock: str | None = None,
    ) -> None:
        """Set the restic environment variables."""
        self._restic_env = {
            "RESTIC_PASSWORD": restic_password,
        }
        if ssh_auth_sock:
            self._restic_env["SSH_AUTH_SOCK"] = ssh_auth_sock

    def _get_cache_dir_args(self) -> list[str]:
        """Get cache directory arguments for restic commands."""
        if self.cache_dir:
            # Ensure cache directory exists
            self.cache_dir.mkdir(parents=True, exist_ok=True)
            return ["--cache-dir", str(self.cache_dir)]
        return []

    def _get_environment(self) -> dict[str, str]:
        """Get the restic environment, ensuring it's been set."""
        if self._restic_env is None:
            error_msg = "Restic environment not set. Call set_environment() first."
            raise ValueError(error_msg)
        return self._restic_env

    def _send_error_email(
        self,
        command: list[str],
        error_msg: str,
        log_contents: str | None = None,
    ) -> None:
        """Send encrypted email with error details and log file."""
        try:
            subject = f"Restic command failed: {' '.join(command[:3])}..."
            message = f"Command: {' '.join(command)}\n\nError: {error_msg}"

            # Include log contents in message if available
            if log_contents:
                message += f"\n\nLog contents:\n{log_contents}"

            self.encrypted_mail.send_mail_with_retries(
                subject=subject,
                message=message,
                mail_attachment=str(self.log_file) if self.log_file.exists() else None,
            )
        except Exception:
            self.logger.exception("Failed to send error email")

    def _run_command(
        self,
        command: list[str],
        text: bool = True,
        timeout: int = 3600,
    ) -> subprocess.CompletedProcess[str]:
        """Execute a command with proper error handling and logging."""
        self.logger.debug(f"Running command: {' '.join(command)}")

        try:
            # Run command and capture output to log file
            with self.log_file.open("w") as f:
                result = subprocess.run(  # noqa: S603
                    command,
                    capture_output=False,
                    text=text,
                    timeout=timeout,
                    env=self._get_environment(),
                    check=False,
                    stdout=f,
                    stderr=subprocess.STDOUT,
                )

            result.stdout = self.log_file.read_text()
            # Check for non-zero exit code
            if result.returncode != 0:
                log_contents = (
                    self.log_file.read_text() if self.log_file.exists() else None
                )
                error_msg = f"Command returned non-zero exit code: {result.returncode}"
                self.logger.error(f"{error_msg} - Command: {' '.join(command)}")
                self._send_error_email(command, error_msg, log_contents)
                raise ResticCommandFailedError(error_msg)
            return result  # noqa: TRY300

        except subprocess.TimeoutExpired as e:
            log_contents = self.log_file.read_text() if self.log_file.exists() else None
            error_msg = f"Command timed out after {timeout} seconds"
            self.logger.exception(f"{error_msg}: {' '.join(command)}")
            self._send_error_email(command, error_msg, log_contents)
            raise ResticCommandFailedError(error_msg) from e
        except subprocess.SubprocessError as e:
            log_contents = self.log_file.read_text() if self.log_file.exists() else None
            error_msg = f"Command failed: {e}"
            self.logger.exception(f"{error_msg} - Command: {' '.join(command)}")
            self._send_error_email(command, error_msg, log_contents)
            raise ResticCommandFailedError(error_msg) from e

    def unlock(self) -> None:
        """Unlock the restic repository."""
        self.logger.info("Unlocking restic repository")
        cmd = [
            self.restic_path,
            "unlock",
            "-r",
            self.backup_target,
            *self._get_cache_dir_args(),
        ]
        result = self._run_command(cmd)
        if result.returncode != 0:
            self.logger.warning(
                f"Unlock command returned non-zero exit code: {result.returncode}",
            )

    def backup(
        self,
        backup_source: str,
        excluded_files: list[str],
    ) -> str:
        """Run restic backup and return the snapshot ID."""
        cmd = [
            self.restic_path,
            "backup",
            "--repo",
            self.backup_target,
            backup_source,
            "--exclude-caches",
            "--one-file-system",
            *self._get_cache_dir_args(),
        ]
        self.logger.info(f"Executing command: {' '.join(cmd)}")

        for exclude in excluded_files:
            cmd.extend(["--exclude", exclude])

        # Use _run_command which handles logging and error emailing
        self._run_command(cmd)

        # Extract snapshot ID from log file
        snapshot_id = self._extract_snapshot_id(self.log_file.read_text())
        if not snapshot_id:
            error_msg = f"Could not find snapshot ID in restic output. Please see log file: {self.log_file}"
            raise SnapshotIDNotFoundError(error_msg)

        self.logger.info(f"Backup completed successfully. Snapshot ID: {snapshot_id}")
        return snapshot_id

    def _extract_snapshot_id(self, output: str) -> str | None:
        """Extract snapshot ID from restic output."""
        lines = output.splitlines()
        for line in reversed(lines):
            if line.startswith("snapshot"):
                parts = line.split()
                if len(parts) >= self.SNAPSHOT_PARTS_MIN_LENGTH:
                    return parts[1]
        return None

    def get_snapshots(self) -> list[str]:
        """Get list of snapshot IDs."""
        cmd = [
            self.restic_path,
            "snapshots",
            "-r",
            self.backup_target,
            *self._get_cache_dir_args(),
        ]
        result = self._run_command(cmd)

        if result.returncode != 0:
            error_msg = "Failed to get snapshots"
            raise ResticCommandFailedError(error_msg)

        snapshot_ids = []
        for line in result.stdout.splitlines():
            parts = line.split()
            if (
                len(parts) > 0
                and len(parts[0]) >= self.MIN_SNAPSHOT_ID_LENGTH
                and "---------------" not in parts
                and "ID        Time                 Host" not in parts
            ):
                snapshot_ids.append(parts[0])

        return snapshot_ids

    def diff(self, snapshot1: str, snapshot2: str) -> str:
        """Get diff between two snapshots."""
        cmd = [
            self.restic_path,
            "diff",
            snapshot1,
            snapshot2,
            "-r",
            self.backup_target,
            *self._get_cache_dir_args(),
        ]

        result = self._run_command(cmd)
        if result.returncode != 0:
            error_msg = "Failed to get diff between snapshots"
            raise ResticCommandFailedError(error_msg)
        self.logger.info(f"Diff output: {result.stdout}")
        return result.stdout

    def find(self, file_pattern: str, snapshot_id: str) -> str:
        """Find files in a snapshot."""
        cmd = [
            self.restic_path,
            "find",
            file_pattern,
            "-s",
            snapshot_id,
            "--repo",
            self.backup_target,
            *self._get_cache_dir_args(),
        ]

        result = self._run_command(cmd)
        if result.returncode != 0:
            error_msg = f"Failed to find {file_pattern} in snapshot {snapshot_id}"
            raise ResticCommandFailedError(error_msg)

        return result.stdout or ""

    def forget(self, keep_last: str, keep_daily: str, keep_monthly: str) -> None:
        """Forget old snapshots according to retention policy."""
        self.logger.info("Running forget operation")
        cmd = [
            self.restic_path,
            "forget",
            "--keep-last",
            keep_last,
            "--keep-daily",
            keep_daily,
            "--keep-monthly",
            keep_monthly,
            "--repo",
            self.backup_target,
            *self._get_cache_dir_args(),
        ]

        result = self._run_command(cmd)
        if result.returncode != 0:
            error_msg = "Failed to forget old snapshots"
            raise ResticCommandFailedError(error_msg)

    def prune(self) -> None:
        """Prune the repository."""
        self.logger.info("Running prune operation")
        cmd = [
            self.restic_path,
            "prune",
            "-r",
            self.backup_target,
            *self._get_cache_dir_args(),
        ]

        result = self._run_command(cmd)
        if result.returncode != 0:
            error_msg = "Failed to prune repository"
            raise ResticCommandFailedError(error_msg)

    def cache_cleanup(self) -> None:
        """Clean up the cache."""
        self.logger.info("Running cache cleanup")
        cmd = [
            self.restic_path,
            "cache",
            "--cleanup",
            *self._get_cache_dir_args(),
        ]

        result = self._run_command(cmd)
        if result.returncode != 0:
            error_msg = "Failed to cleanup cache"
            raise ResticCommandFailedError(error_msg)

    def check(self, read_data_subset: str = "20%") -> str:
        """Check repository integrity."""
        self.logger.info("Running repository check")
        cmd = [
            self.restic_path,
            "check",
            f"--read-data-subset={read_data_subset}",
            "--repo",
            self.backup_target,
            *self._get_cache_dir_args(),
        ]

        result = self._run_command(cmd)
        if result.returncode != 0:
            error_msg = "Repository check failed"
            raise ResticCommandFailedError(error_msg)

        return result.stdout or ""

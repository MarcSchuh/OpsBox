"""Restic client for executing restic commands with proper error handling and logging."""

import logging
import subprocess
from pathlib import Path

from opsbox.backup.exceptions import (
    ResticBackupFailedError,
    ResticCommandFailedError,
    SnapshotIDNotFoundError,
)


class ResticClient:
    """Handles all restic command execution with proper error handling and logging."""

    MIN_SNAPSHOT_ID_LENGTH = 7
    SNAPSHOT_PARTS_MIN_LENGTH = 2

    def __init__(
        self,
        restic_path: str,
        backup_target: str,
        logger: logging.Logger,
    ) -> None:
        """Initialize the restic client with path, target, and logger."""
        self.restic_path = restic_path
        self.backup_target = backup_target
        self.logger = logger
        self._restic_env: dict[str, str] | None = None

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

    def _get_environment(self) -> dict[str, str]:
        """Get the restic environment, ensuring it's been set."""
        if self._restic_env is None:
            error_msg = "Restic environment not set. Call set_environment() first."
            raise ValueError(error_msg)
        return self._restic_env

    def _run_command(
        self,
        command: list[str],
        capture_output: bool = True,
        text: bool = True,
        timeout: int = 3600,
    ) -> subprocess.CompletedProcess[str]:
        """Execute a command with proper error handling and logging."""
        self.logger.debug(f"Running command: {' '.join(command)}")

        try:
            return subprocess.run(  # noqa: S603
                command,
                capture_output=capture_output,
                text=text,
                timeout=timeout,
                env=self._get_environment(),
                check=False,
            )
        except subprocess.TimeoutExpired as e:
            self.logger.exception(
                f"Command timed out after {timeout} seconds: {' '.join(command)}",
            )
            error_msg = f"Command timed out: {' '.join(command)}"
            raise ResticCommandFailedError(error_msg) from e
        except subprocess.SubprocessError as e:
            self.logger.exception(f"Command failed: {' '.join(command)}")
            error_msg = f"Command failed: {' '.join(command)}"
            raise ResticCommandFailedError(error_msg) from e

    def unlock(self) -> None:
        """Unlock the restic repository."""
        self.logger.info("Unlocking restic repository")
        cmd = [self.restic_path, "unlock", "-r", self.backup_target]
        result = self._run_command(cmd)
        if result.returncode != 0:
            self.logger.warning(
                f"Unlock command returned non-zero exit code: {result.returncode}",
            )

    def backup(
        self,
        backup_source: str,
        excluded_files: list[str],
        log_file: Path | None = None,
    ) -> str:
        """Run restic backup and return the snapshot ID."""
        self.logger.info(f"Starting backup of {backup_source}")

        cmd = [
            self.restic_path,
            "backup",
            "--repo",
            self.backup_target,
            backup_source,
            "--exclude-caches",
            "--one-file-system",
        ]

        for exclude in excluded_files:
            cmd.extend(["--exclude", exclude])

        if log_file:
            with log_file.open("w") as f:
                result = subprocess.run(  # noqa: S603
                    cmd,
                    capture_output=False,
                    text=True,
                    timeout=3600,
                    env=self._get_environment(),
                    check=False,
                    stdout=f,
                    stderr=subprocess.STDOUT,
                )
        else:
            result = self._run_command(cmd)

        if result.returncode != 0:
            error_msg = "Restic backup failed"
            if log_file and log_file.exists():
                with log_file.open() as f:
                    log_contents = f.read()
                error_msg += f"\nLog contents:\n{log_contents}"
            raise ResticBackupFailedError(error_msg)

        # Extract snapshot ID from output
        snapshot_id = self._extract_snapshot_id(result.stdout if result.stdout else "")
        if not snapshot_id:
            error_msg = "Could not find snapshot ID in restic output"
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
        cmd = [self.restic_path, "snapshots", "-r", self.backup_target]
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
        ]

        result = self._run_command(cmd)
        if result.returncode != 0:
            error_msg = "Failed to get diff between snapshots"
            raise ResticCommandFailedError(error_msg)

        return result.stdout or ""

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
        ]

        result = self._run_command(cmd)
        if result.returncode != 0:
            error_msg = "Failed to forget old snapshots"
            raise ResticCommandFailedError(error_msg)

    def prune(self) -> None:
        """Prune the repository."""
        self.logger.info("Running prune operation")
        cmd = [self.restic_path, "prune", "-r", self.backup_target]

        result = self._run_command(cmd)
        if result.returncode != 0:
            error_msg = "Failed to prune repository"
            raise ResticCommandFailedError(error_msg)

    def cache_cleanup(self) -> None:
        """Clean up the cache."""
        self.logger.info("Running cache cleanup")
        cmd = [self.restic_path, "cache", "--cleanup"]

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
        ]

        result = self._run_command(cmd)
        if result.returncode != 0:
            error_msg = "Repository check failed"
            raise ResticCommandFailedError(error_msg)

        return result.stdout or ""

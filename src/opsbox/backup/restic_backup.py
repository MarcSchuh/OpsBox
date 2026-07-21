"""Refactored backup script with improved architecture and error handling."""

import argparse
import hashlib
import json
import os
import sys
import tempfile
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import TypeVar

from opsbox.backup.config_manager import ConfigManager
from opsbox.backup.exceptions import (
    BackupError,
    ConfigurationError,
    EmptySourceError,
    InvalidResticConfigError,
    MaintenanceError,
    NetworkUnreachableError,
    ResticBackupFailedError,
    ResticRepositoryLockedError,
    SnapshotIDNotFoundError,
    SSHKeyNotFoundError,
    UserDoesNotExistError,
    VerificationError,
    WrongOSForResticBackupError,
)
from opsbox.backup.network_checker import NetworkChecker
from opsbox.backup.password_manager import PasswordManager
from opsbox.backup.restic_client import ResticClient, is_lock_error
from opsbox.backup.snapshot_id import ResticSnapshotId
from opsbox.backup.ssh_manager import SSHManager
from opsbox.encrypted_mail import EncryptedMail
from opsbox.locking import LockManager
from opsbox.logging import LoggingConfig, configure_logging

_T = TypeVar("_T")


@dataclass
class ResticDiff:
    """Represents the result of a restic diff operation.

    Attributes:
        added_files: List of added file paths
        altered_files: List of altered file paths
        deleted_files: List of deleted file paths
        snapshot_id: The snapshot ID this diff is for

    """

    added_files: list[Path]
    altered_files: list[Path]
    deleted_files: list[Path]
    snapshot_id: ResticSnapshotId


class BackupScript:
    """Refactored backup script with improved architecture and error handling."""

    MIN_SNAPSHOTS_FOR_DIFF = 2
    MAX_FILES_IN_EMAIL = 200

    def __init__(
        self,
        config_path: str,
        restic_path: str = "/snap/bin/restic",
        temp_dir: str | None = None,
        log_level: str = "INFO",
    ) -> None:
        """Initialize the backup script with proper dependency injection.

        Args:
            config_path: Path to configuration file
            restic_path: Path to restic executable
            temp_dir: Directory for temporary files (defaults to system temp dir)
            log_level: Logging level (defaults to INFO)

        Raises:
            WrongOSForResticBackupError: If not running on Linux
            ConfigurationError: If configuration cannot be loaded
            InvalidResticConfigError: If configuration is invalid

        """
        self._validate_environment()

        # Load and validate configuration
        self.config = ConfigManager.load_config(config_path)

        self.script_name = Path(__file__).name
        target_hash = self._get_target_hash(self.config.backup_target)
        self.logger = configure_logging(
            LoggingConfig(
                log_name=f"{self.script_name}.{target_hash}",
                log_level=log_level,
            ),
        )

        # Setup temporary directory
        self.temp_dir = Path(temp_dir) if temp_dir else Path(tempfile.gettempdir())
        self.temp_dir.mkdir(parents=True, exist_ok=True)

        self.lock_file_path = self.temp_dir / f"{self.script_name}.{target_hash}.lock"

        # Initialize components with dependency injection
        self._initialize_components(restic_path)

        self.logger.info("Backup script initialized successfully")

    def _validate_environment(self) -> None:
        """Validate that the script is running in a supported environment."""
        if os.name != "posix" or sys.platform != "linux":
            error_msg = "This script only runs on Linux."
            raise WrongOSForResticBackupError(error_msg)

    def _get_target_hash(self, backup_target: str) -> str:
        """Generate a stable hash from the backup target directory.

        Args:
            backup_target: The backup target path (e.g., "sftp:user@host:/path/to/repo")

        Returns:
            First 8 hexadecimal digits of the SHA256 hash of the backup target

        """
        hash_obj = hashlib.sha256(backup_target.encode("utf-8"))
        return hash_obj.hexdigest()[:8]

    def _initialize_components(self, restic_path: str) -> None:
        """Initialize all component classes with proper dependency injection."""
        # Initialize email and locking
        self.encrypted_mail = EncryptedMail(
            self.logger,
            Path(self.config.email_settings_path),
            fail_silently=True,
        )

        self.lock_manager = LockManager(
            lock_file=self.lock_file_path,
            logger=self.logger,
            encrypted_mail=self.encrypted_mail,
            script_name=self.script_name,
        )

        # Initialize specialized components
        self.password_manager = PasswordManager(self.logger)
        self.network_checker = NetworkChecker(self.logger)
        self.ssh_manager = SSHManager(self.logger)

        # Setup cache directory for restic

        self.restic_client = ResticClient(
            restic_path,
            self.config.backup_target,
            self.logger,
            command_timeout=self.config.command_timeout,
        )

    def _failure_mail_subject(self, error: BaseException) -> str:
        """Pick a failure mail subject that matches the failing stage."""
        title = self.config.backup_title
        if isinstance(error, VerificationError):
            return f"Backup {title} verification failed"
        if isinstance(error, MaintenanceError):
            return f"Backup maintenance {title} failed"
        return f"Backup {title} failed"

    def _send_failure_email(self, error: BaseException) -> None:
        """Send a single failure notification with the full session log."""
        attachment = None
        session_log = getattr(self.restic_client, "session_log", None)
        if isinstance(session_log, (str, Path)) and Path(session_log).exists():
            attachment = str(session_log)
        self.encrypted_mail.send_mail_with_retries(
            subject=self._failure_mail_subject(error),
            message=f"Backup failed: {error}",
            mail_attachment=attachment,
        )

    def run(self) -> None:
        """Execute the complete backup workflow with proper error handling."""
        with self.lock_manager:
            try:
                self.logger.info(f"Starting backup {self.config.backup_title} workflow")

                # Step 0: Ensure the source is present and not empty
                self._check_source_not_empty()

                # Step 1: Setup environment
                self._setup_environment()

                # Step 2: Check network connectivity (if required)
                if self.config.network_host:
                    self._check_network_connectivity()

                # Step 3: Setup SSH (if required)
                if self.config.ssh_key:
                    self._setup_ssh()

                # Step 4: Execute backup
                snapshot_id = self._execute_backup()

                # Step 5: Verify backup (raises VerificationError on failure)
                self._verify_backup(snapshot_id)

                # Step 6: Perform maintenance
                self._perform_maintenance()

                self.logger.info("Backup workflow completed successfully")

            except (
                NetworkUnreachableError,
                SSHKeyNotFoundError,
                UserDoesNotExistError,
            ) as e:
                # These are expected failures that should be handled gracefully
                self.logger.warning(f"Backup skipped due to: {e}")
                self.encrypted_mail.send_mail_with_retries(
                    subject=f"Backup {self.config.backup_title} skipped",
                    message=f"Backup was skipped: {e}",
                )
            except BackupError as e:
                # Single failure notification for the whole workflow
                self.logger.exception("Backup failed")
                self._send_failure_email(e)
                raise
            except Exception as e:
                # Handle unexpected errors
                self.logger.exception("Unexpected error during backup")
                self.encrypted_mail.send_mail_with_retries(
                    subject=f"Backup {self.config.backup_title} script error",
                    message=f"Unexpected error: {e}",
                )
                error_msg = f"Unexpected error: {e}"
                raise BackupError(error_msg, original_error=e) from e

    def _check_source_not_empty(self) -> None:
        """Abort the backup if the source directory is missing or (near) empty.

        Backing up an unmounted or empty source would create an almost empty
        snapshot and could cause data loss once old snapshots are pruned. This
        guard counts the entries in the source directory and raises if there are
        fewer than ``min_source_entries``.

        Raises:
            EmptySourceError: If the source is inaccessible or has too few entries

        """
        source = Path(self.config.backup_source)
        self.logger.info(
            f"Checking backup source {source} has at least "
            f"{self.config.min_source_entries} entries",
        )

        try:
            entry_count = sum(1 for _ in source.iterdir())
        except (FileNotFoundError, NotADirectoryError, PermissionError) as e:
            error_msg = (
                f"Backup source is not an accessible directory: {source} ({e}). "
                f"Aborting to avoid backing up a missing or unmounted source."
            )
            raise EmptySourceError(error_msg) from e

        if entry_count < self.config.min_source_entries:
            error_msg = (
                f"Backup source {source} contains only {entry_count} entries "
                f"(minimum required: {self.config.min_source_entries}). "
                f"Aborting to avoid backing up an empty or unmounted source."
            )
            raise EmptySourceError(error_msg)

        self.logger.info(f"Backup source check passed ({entry_count} entries)")

    def _setup_environment(self) -> None:
        """Set up the restic environment with password and SSH configuration."""
        self.logger.info("Setting up restic environment")

        # Get restic password
        # Type assertions: validation ensures password_lookup fields are provided
        # when restic_password is not provided
        password_lookup_1 = self.config.password_lookup_1 or ""
        password_lookup_2 = self.config.password_lookup_2 or ""
        restic_password = self.password_manager.get_restic_password(
            password_lookup_1,
            password_lookup_2,
            self.config.restic_password,
        )

        # Setup SSH auth sock if needed
        ssh_auth_sock = None
        if self.config.ssh_key and self.config.ssh_user:
            ssh_auth_sock = self.ssh_manager.get_ssh_auth_sock(self.config.ssh_user)

        # Configure restic client
        self.restic_client.set_environment(restic_password, ssh_auth_sock)

        self.logger.info("Restic environment setup completed")

    def _check_network_connectivity(self) -> None:
        """Check network connectivity to the backup target."""
        if self.config.network_host is None:
            return

        self.logger.info(f"Checking network connectivity to {self.config.network_host}")

        try:
            self.network_checker.check_network_connectivity_or_raise(
                self.config.network_host,
            )
        except NetworkUnreachableError as e:
            self.logger.info(f"Network check failed: {e}")
            raise

    def _setup_ssh(self) -> None:
        """Set up SSH key for backup connection."""
        if not self.config.ssh_key or not self.config.ssh_user:
            error_msg = "SSH key and user must be configured together"
            raise InvalidResticConfigError(error_msg)

        self.logger.info("Setting up SSH key")
        self.ssh_manager.ensure_ssh_key_loaded(
            self.config.ssh_key,
            self.config.ssh_user,
            self.config.ssh_key_max_retries,
        )

    def _run_with_lock_retry(
        self,
        operation: Callable[[], _T],
        description: str,
    ) -> _T:
        """Run a restic operation, recovering once from a stale repository lock.

        If the operation fails because the repository is locked (e.g. a stale
        lock left behind by a previously killed run), ``restic unlock`` is run
        to remove stale locks and the operation is retried exactly once. If it
        is still locked afterwards the error propagates so a real, concurrent
        run is not silently overridden.
        """
        try:
            return operation()
        except ResticRepositoryLockedError:
            self.logger.warning(
                f"Restic repository is locked during '{description}'; "
                "removing stale locks and retrying once.",
            )
            self.restic_client.unlock()
            try:
                return operation()
            except ResticRepositoryLockedError:
                self.logger.exception(
                    f"Restic repository still locked after unlock during "
                    f"'{description}'",
                )
                raise

    def _execute_backup(self) -> ResticSnapshotId:
        """Execute the restic backup operation and notify on success.

        Failures propagate to :meth:`run`, which sends the single failure email.
        """
        self.logger.info(f"Starting backup of {self.config.backup_source}")

        snapshot_id = self._run_with_lock_retry(
            lambda: self.restic_client.backup(
                self.config.backup_source,
                self.config.excluded_files,
            ),
            "backup",
        )

        # Send success notification with diff summary
        diff_summary = self._generate_diff_summary(snapshot_id)
        self.encrypted_mail.send_mail_with_retries(
            subject=f"Backup {self.config.backup_title} successful",
            message=(
                f"Backup completed successfully.\nSnapshot ID: {snapshot_id}\n\n"
                f"Diff Summary:\n{diff_summary}"
            ),
            mail_attachment=str(self.restic_client.session_log),
        )
        return snapshot_id

    def _parse_diff_line(self, line: str) -> dict | None:
        """Parse a single line of ``restic diff --json`` output into a message.

        Returns the decoded message dict, or None for blank lines, non-JSON
        lines (logged as a warning) and non-dict payloads.
        """
        line_stripped = line.strip()
        if not line_stripped:
            return None

        try:
            message = json.loads(line_stripped)
        except json.JSONDecodeError:
            # stdout is captured cleanly, so any non-JSON line is unexpected
            self.logger.warning(
                f"Ignoring non-JSON line in diff output: {line_stripped}",
            )
            return None

        if not isinstance(message, dict):
            return None
        return message

    def _classify_change(
        self,
        message: dict,
        *,
        added_files: list[Path],
        altered_files: list[Path],
        deleted_files: list[Path],
    ) -> None:
        """Append a ``change`` message's path to the matching change list.

        A single change carries one modifier; "+" added, "-" removed, "M"
        content modified. Metadata-only changes (e.g. "U"/"T") are intentionally
        ignored.
        """
        path_str = message.get("path")
        modifier = message.get("modifier", "")
        if not path_str:
            return

        path = Path(path_str)
        if "+" in modifier:
            added_files.append(path)
        elif "-" in modifier:
            deleted_files.append(path)
        elif "M" in modifier:
            altered_files.append(path)

    def _parse_diff_output(
        self,
        diff_output: str,
        snapshot_id: ResticSnapshotId,
    ) -> ResticDiff:
        """Parse ``restic diff --json`` output into added/altered/deleted files.

        The output is newline-delimited JSON. Each change is a message of type
        ``change`` with a ``path`` and a ``modifier`` string (e.g. "+", "-",
        "M", or combinations such as "MU").

        A well-formed ``restic diff --json`` run always ends with a
        ``statistics`` message. If that message is missing, the diff did not
        complete correctly, so the output is considered invalid and an error is
        raised (the report must succeed; a broken report means something went
        wrong with the run).

        Args:
            diff_output: The raw JSON output from the restic diff command
            snapshot_id: The snapshot ID this diff is for

        Returns:
            ResticDiff object containing added, altered, and deleted files

        Raises:
            ResticBackupFailedError: If the diff output is empty or does not
                contain the terminating ``statistics`` message

        """
        deleted_files: list[Path] = []
        altered_files: list[Path] = []
        added_files: list[Path] = []
        saw_statistics = False

        if not diff_output or not diff_output.strip():
            error_msg = "restic diff produced no output"
            self.logger.error(error_msg)
            raise ResticBackupFailedError(error_msg)

        for line in diff_output.splitlines():
            message = self._parse_diff_line(line)
            if message is None:
                continue

            message_type = message.get("message_type")
            if message_type == "statistics":
                saw_statistics = True
                continue
            if message_type != "change":
                continue

            self._classify_change(
                message,
                added_files=added_files,
                altered_files=altered_files,
                deleted_files=deleted_files,
            )

        if not saw_statistics:
            error_msg = (
                "restic diff --json did not emit a terminating 'statistics' "
                "message; the diff output is incomplete or invalid"
            )
            self.logger.error(error_msg)
            raise ResticBackupFailedError(error_msg)

        return ResticDiff(
            added_files=added_files,
            altered_files=altered_files,
            deleted_files=deleted_files,
            snapshot_id=snapshot_id,
        )

    def _extract_diff_statistics(self, diff_output: str) -> str:
        """Extract a human-readable summary from ``restic diff --json`` output.

        Looks for the ``statistics`` message emitted at the end of the diff.

        Args:
            diff_output: The raw JSON output from the restic diff command

        Returns:
            A formatted summary string, or a fallback message if unavailable

        """
        for line in diff_output.splitlines():
            line_stripped = line.strip()
            if not line_stripped:
                continue
            try:
                message = json.loads(line_stripped)
            except json.JSONDecodeError:
                continue
            if (
                not isinstance(message, dict)
                or message.get("message_type") != "statistics"
            ):
                continue

            added = message.get("added", {}) or {}
            removed = message.get("removed", {}) or {}
            changed_files = message.get("changed_files")

            summary_lines = []
            if changed_files is not None:
                summary_lines.append(f"Changed files: {changed_files}")
            summary_lines.append(
                f"Added:   files={added.get('files', 0)}, "
                f"dirs={added.get('dirs', 0)}, bytes={added.get('bytes', 0)}",
            )
            summary_lines.append(
                f"Removed: files={removed.get('files', 0)}, "
                f"dirs={removed.get('dirs', 0)}, bytes={removed.get('bytes', 0)}",
            )
            return "\n".join(summary_lines)

        return "No summary available."

    def _send_threshold_warning(
        self,
        change_type: str,
        files: list[Path],
        threshold: int,
        snapshot_id: ResticSnapshotId,
    ) -> None:
        """Send a warning email because a change-count threshold was exceeded.

        Args:
            change_type: The kind of change ("deleted", "altered" or "added")
            files: The affected files
            threshold: The configured threshold that was exceeded
            snapshot_id: The snapshot ID this change belongs to

        """
        self.logger.warning(
            f"{change_type.capitalize()} threshold exceeded: {len(files)} files "
            f"{change_type} (threshold: {threshold})",
        )
        file_list = "\n".join(str(path) for path in files[: self.MAX_FILES_IN_EMAIL])
        if len(files) > self.MAX_FILES_IN_EMAIL:
            file_list += f"\n... and {len(files) - self.MAX_FILES_IN_EMAIL} more files"
        self.encrypted_mail.send_mail_with_retries(
            subject=(
                f"Backup {self.config.backup_title} Warning: {len(files)} files "
                f"{change_type} (threshold: {threshold})"
            ),
            message=(
                f"Warning: The backup detected {len(files)} {change_type} files, "
                f"which exceeds the threshold of {threshold}.\n\n"
                f"Snapshot ID: {snapshot_id}\n\n"
                f"{change_type.capitalize()} files:\n{file_list}"
            ),
        )

    def _check_thresholds_and_send_warnings(
        self,
        diff: ResticDiff,
    ) -> None:
        """Check thresholds and send warning emails if exceeded.

        Deleted, altered and added files are each checked against their own
        independent threshold.

        Args:
            diff: ResticDiff object containing file changes and snapshot ID

        """
        threshold_checks: tuple[tuple[str, list[Path], int | None], ...] = (
            ("deleted", diff.deleted_files, self.config.deletion_threshold),
            ("altered", diff.altered_files, self.config.alteration_threshold),
            ("added", diff.added_files, self.config.addition_threshold),
        )

        for change_type, files, threshold in threshold_checks:
            if threshold is not None and len(files) > threshold:
                self._send_threshold_warning(
                    change_type,
                    files,
                    threshold,
                    diff.snapshot_id,
                )

    def _is_file_in_monitored_folder(self, file_path: Path) -> bool:
        """Check if a file is within any of the monitored folders.

        Args:
            file_path: Path to the file to check

        Returns:
            True if the file is in a monitored folder, False otherwise

        """
        if not self.config.monitored_folders:
            return False

        # Normalize the file path
        normalized_file_path = file_path.as_posix()

        for monitored_folder in self.config.monitored_folders:
            # Normalize the monitored folder path
            normalized_folder = Path(monitored_folder).as_posix()
            # Ensure folder path ends with / for proper matching
            if not normalized_folder.endswith("/"):
                normalized_folder += "/"

            # Check if file path starts with the monitored folder path
            if normalized_file_path.startswith(normalized_folder):
                return True

        return False

    def _filter_files_in_monitored_folders(
        self,
        files: list[Path],
    ) -> list[Path]:
        """Filter files to only include those in monitored folders.

        Args:
            files: List of file paths to filter

        Returns:
            List of files that are in monitored folders

        """
        return [
            file_path
            for file_path in files
            if self._is_file_in_monitored_folder(file_path)
        ]

    def _is_file_in_specific_monitored_folder(
        self,
        file_path: Path,
        monitored_folder: str,
    ) -> bool:
        """Check if a file is within a specific monitored folder.

        Args:
            file_path: Path to the file to check
            monitored_folder: Path to the monitored folder to check against

        Returns:
            True if the file is in the specified monitored folder, False otherwise

        """
        # Normalize the file path
        normalized_file_path = file_path.as_posix()

        # Normalize the monitored folder path
        normalized_folder = Path(monitored_folder).as_posix()
        # Ensure folder path ends with / for proper matching
        if not normalized_folder.endswith("/"):
            normalized_folder += "/"

        # Check if file path starts with the monitored folder path
        return normalized_file_path.startswith(normalized_folder)

    def _filter_files_for_monitored_folder(
        self,
        files: list[Path],
        monitored_folder: str,
    ) -> list[Path]:
        """Filter files to only include those in a specific monitored folder.

        Args:
            files: List of file paths to filter
            monitored_folder: Path to the monitored folder to filter for

        Returns:
            List of files that are in the specified monitored folder

        """
        return [
            file_path
            for file_path in files
            if self._is_file_in_specific_monitored_folder(file_path, monitored_folder)
        ]

    def _check_monitored_folders_and_send_alerts(
        self,
        diff: ResticDiff,
    ) -> None:
        """Check for changes in monitored folders and send email alerts.

        Sends a separate email for each monitored folder and change type (added,
        altered, deleted) containing only the files affected in that specific
        folder. Any change inside a monitored folder triggers a notification.

        Args:
            diff: ResticDiff object containing file changes and snapshot ID

        """
        if not self.config.monitored_folders:
            return

        # Every change type is reported so that any modification triggers an alert.
        change_categories: tuple[tuple[str, list[Path]], ...] = (
            ("added", diff.added_files),
            ("altered", diff.altered_files),
            ("deleted", diff.deleted_files),
        )

        for monitored_folder in self.config.monitored_folders:
            for change_type, files in change_categories:
                folder_files = self._filter_files_for_monitored_folder(
                    files,
                    monitored_folder,
                )
                if folder_files:
                    self._send_monitored_folder_alert(
                        monitored_folder,
                        change_type,
                        folder_files,
                        diff.snapshot_id,
                    )

    def _send_monitored_folder_alert(
        self,
        monitored_folder: str,
        change_type: str,
        files: list[Path],
        snapshot_id: ResticSnapshotId,
    ) -> None:
        """Send an alert email for one change type in a monitored folder.

        Args:
            monitored_folder: The monitored folder the files belong to
            change_type: The kind of change ("added", "altered" or "deleted")
            files: The affected files inside the monitored folder
            snapshot_id: The snapshot ID this change belongs to

        """
        self.logger.warning(
            f"Files {change_type} in monitored folder {monitored_folder}: "
            f"{len(files)} files",
        )
        file_list = "\n".join(str(path) for path in files[: self.MAX_FILES_IN_EMAIL])
        if len(files) > self.MAX_FILES_IN_EMAIL:
            file_list += f"\n... and {len(files) - self.MAX_FILES_IN_EMAIL} more files"
        self.encrypted_mail.send_mail_with_retries(
            subject=(
                f"Backup {self.config.backup_title} Alert: {len(files)} files "
                f"{change_type} in monitored folder: {monitored_folder}"
            ),
            message=(
                f"Alert: The backup detected {len(files)} {change_type} files "
                f"in monitored folder: {monitored_folder}\n\n"
                f"Snapshot ID: {snapshot_id}\n\n"
                f"{change_type.capitalize()} files:\n{file_list}"
            ),
        )

    def _send_file_changes_email(
        self,
        diff: ResticDiff,
    ) -> None:
        """Send separate emails for added, altered, and deleted files.

        Args:
            diff: ResticDiff object containing file changes and snapshot ID

        """
        # Send email for added files
        if diff.added_files:
            self.logger.info(
                f"Sending email for {len(diff.added_files)} added files (Snapshot: {diff.snapshot_id})",
            )
            added_list = "\n".join(
                str(path) for path in diff.added_files[: self.MAX_FILES_IN_EMAIL]
            )
            if len(diff.added_files) > self.MAX_FILES_IN_EMAIL:
                added_list += f"\n... and {len(diff.added_files) - self.MAX_FILES_IN_EMAIL} more files"
            message = (
                f"Backup detected {len(diff.added_files)} added files.\n\n"
                f"Snapshot ID: {diff.snapshot_id}\n\n"
                f"Added files:\n{added_list}"
            )
            self.encrypted_mail.send_mail_with_retries(
                subject=f"Backup {self.config.backup_title}: {len(diff.added_files)} files added (Snapshot: {diff.snapshot_id})",
                message=message,
            )

        # Send email for altered files
        if diff.altered_files:
            self.logger.info(
                f"Sending email for {len(diff.altered_files)} altered files (Snapshot: {diff.snapshot_id})",
            )
            altered_list = "\n".join(
                str(path) for path in diff.altered_files[: self.MAX_FILES_IN_EMAIL]
            )
            if len(diff.altered_files) > self.MAX_FILES_IN_EMAIL:
                altered_list += f"\n... and {len(diff.altered_files) - self.MAX_FILES_IN_EMAIL} more files"
            message = (
                f"Backup detected {len(diff.altered_files)} altered files.\n\n"
                f"Snapshot ID: {diff.snapshot_id}\n\n"
                f"Altered files:\n{altered_list}"
            )
            self.encrypted_mail.send_mail_with_retries(
                subject=f"Backup {self.config.backup_title}: {len(diff.altered_files)} files altered (Snapshot: {diff.snapshot_id})",
                message=message,
            )

        # Send email for deleted files
        if diff.deleted_files:
            self.logger.info(
                f"Sending email for {len(diff.deleted_files)} deleted files (Snapshot: {diff.snapshot_id})",
            )
            deleted_list = "\n".join(
                str(path) for path in diff.deleted_files[: self.MAX_FILES_IN_EMAIL]
            )
            if len(diff.deleted_files) > self.MAX_FILES_IN_EMAIL:
                deleted_list += f"\n... and {len(diff.deleted_files) - self.MAX_FILES_IN_EMAIL} more files"
            message = (
                f"Backup detected {len(diff.deleted_files)} deleted files.\n\n"
                f"Snapshot ID: {diff.snapshot_id}\n\n"
                f"Deleted files:\n{deleted_list}"
            )
            self.encrypted_mail.send_mail_with_retries(
                subject=f"Backup {self.config.backup_title}: {len(diff.deleted_files)} files deleted (Snapshot: {diff.snapshot_id})",
                message=message,
            )

    def _generate_diff_summary(self, snapshot_id: ResticSnapshotId) -> str:
        """Generate diff summary between current and previous snapshot."""
        try:
            snapshots = self.restic_client.get_snapshots()
            if len(snapshots) < self.MIN_SNAPSHOTS_FOR_DIFF:
                return "Not enough snapshots to generate diff summary."

            # Locate the just-created snapshot in the (time-ordered) list and
            # use the one immediately before it, instead of assuming it is the
            # last entry. This is robust against ordering surprises or a newer
            # snapshot created by a concurrent run.
            if snapshot_id not in snapshots:
                error_msg = (
                    f"Current snapshot {snapshot_id} was not found in the "
                    f"snapshot list returned by restic."
                )
                raise SnapshotIDNotFoundError(error_msg)

            current_index = snapshots.index(snapshot_id)
            if current_index == 0:
                return "No previous snapshot available to generate diff summary."
            previous_snapshot = snapshots[current_index - 1]

            diff_output = self.restic_client.diff(previous_snapshot, snapshot_id)

            # Parse diff output to extract deleted, altered, and added files
            diff = self._parse_diff_output(diff_output, snapshot_id)

            self._send_file_changes_email(diff)

            # Check thresholds and send warnings if needed
            self._check_thresholds_and_send_warnings(diff)

            # Check monitored folders and send alerts if needed
            self._check_monitored_folders_and_send_alerts(diff)

            return self._extract_diff_statistics(diff_output)

        except (ValueError, TypeError, AttributeError) as e:
            self.logger.warning(f"Failed to generate diff summary: {e}")
            return f"Failed to generate diff summary: {e}"

    def _is_file_found_in_find_output(self, find_output: str) -> bool:
        """Check whether ``restic find --json`` reported at least one match.

        ``find`` is invoked with ``-s <snapshot>``, so the output is restricted
        to the verified snapshot and any hit is within it. The output is a JSON
        array of objects with ``hits``/``matches`` fields.

        Args:
            find_output: The raw JSON output from restic find

        Returns:
            True if at least one match was found, False otherwise

        """
        if not find_output or not find_output.strip():
            return False

        try:
            results = json.loads(find_output)
        except json.JSONDecodeError:
            self.logger.exception("Failed to parse restic find --json output")
            return False

        if not isinstance(results, list):
            return False

        for entry in results:
            if not isinstance(entry, dict):
                continue
            matches = entry.get("matches") or []
            hits = entry.get("hits", len(matches))
            if hits:
                return True
        return False

    def _verify_backup(self, snapshot_id: ResticSnapshotId) -> None:
        """Verify the backup by checking if a configured file exists in the snapshot.

        Raises:
            VerificationError: If the file is missing or verification cannot run

        """
        self.logger.info(f"Verifying backup snapshot {snapshot_id}")

        try:
            find_output = self.restic_client.find(
                self.config.file_to_check,
                snapshot_id,
            )
        except Exception as e:
            self.logger.exception(
                f"Backup {self.config.backup_title} verification failed",
            )
            error_msg = f"Backup verification failed: {e}"
            raise VerificationError(error_msg, original_error=e) from e

        if self._is_file_found_in_find_output(find_output):
            self.logger.info("Backup verification successful")
            self.encrypted_mail.send_mail_with_retries(
                subject=f"Backup {self.config.backup_title} verification successful",
                message=(
                    f"Backup verification successful for snapshot {snapshot_id}. "
                    f"File {self.config.file_to_check} found."
                ),
            )
            return

        self.logger.error(
            f"Backup verification failed - file {self.config.file_to_check} not found",
        )
        error_msg = (
            f"Backup verification failed for snapshot {snapshot_id} - "
            f"file {self.config.file_to_check} not found. Maintenance skipped."
        )
        raise VerificationError(error_msg)

    def _check_repository_integrity(self) -> str:
        """Run ``restic check`` and recover once from a stale repository lock.

        ``check`` does not raise on a non-zero exit code (so integrity warnings
        can be inspected), so a repository lock surfaces as lock text in the
        output rather than as an exception. In that case stale locks are removed
        and the check is retried once.
        """
        check_output = self.restic_client.check(self.config.check_read_data_subset)
        if is_lock_error(check_output):
            self.logger.warning(
                "Restic repository is locked during 'check'; "
                "removing stale locks and retrying once.",
            )
            self.restic_client.unlock()
            check_output = self.restic_client.check(self.config.check_read_data_subset)
        return check_output

    def _perform_maintenance(self) -> None:
        """Perform maintenance: forget → check → prune (only if check is clean).

        ``forget`` only drops snapshot references and is relatively safe.
        ``prune`` permanently deletes unreferenced data, so it runs only after
        ``restic check`` reports a clean repository.
        """
        self.logger.info("Starting maintenance operations")

        try:
            # Forget old snapshots (references only; pack data remains until prune)
            self._run_with_lock_retry(
                lambda: self.restic_client.forget(
                    self.config.keep_last,
                    self.config.keep_daily,
                    self.config.keep_monthly,
                ),
                "forget",
            )

            # Clean up local cache (independent of repository integrity)
            self.restic_client.cache_cleanup()

            # Verify repository integrity before destructive cleanup
            check_output = self._check_repository_integrity()

            if "no errors were found" not in check_output:
                self.logger.warning(
                    "Repository check reported problems - skipping prune to "
                    "avoid deleting data from a potentially unhealthy repository",
                )
                self.encrypted_mail.send_mail_with_retries(
                    subject=(
                        f"Backup maintenance {self.config.backup_title} "
                        "completed with warnings"
                    ),
                    message=(
                        "Repository check reported problems. Prune was skipped "
                        "to avoid deleting data from a potentially unhealthy "
                        f"repository.\n\nCheck output:\n{check_output}"
                    ),
                )
                return

            # Repo is clean - safe to permanently remove unreferenced data
            self._run_with_lock_retry(self.restic_client.prune, "prune")

            self.logger.info("Maintenance completed successfully")
            self.encrypted_mail.send_mail_with_retries(
                subject=f"Backup maintenance {self.config.backup_title} successful",
                message="Repository maintenance completed successfully.",
            )

        except Exception as e:
            self.logger.exception("Maintenance failed")
            error_msg = f"Maintenance failed: {e}"
            raise MaintenanceError(error_msg, original_error=e) from e


def main() -> None:
    """Run the main backup script."""
    parser = argparse.ArgumentParser(
        description="Run Restic backup with improved architecture.",
    )
    parser.add_argument(
        "--config",
        required=True,
        help="Path to the configuration file",
    )
    parser.add_argument(
        "--restic-path",
        default="/snap/bin/restic",
        help="Path to restic executable",
    )
    parser.add_argument("--temp-dir", help="Directory for temporary files")
    parser.add_argument(
        "--log-level",
        default="INFO",
        choices=["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"],
        help="Set the logging level (default: INFO)",
    )

    args = parser.parse_args()

    # Setup basic logging for main function
    logger = configure_logging(
        LoggingConfig(log_name="backup_script", log_level=args.log_level),
    )

    try:
        backup_script = BackupScript(
            config_path=args.config,
            restic_path=args.restic_path,
            temp_dir=args.temp_dir,
            log_level=args.log_level,
        )
        backup_script.run()
    except (ConfigurationError, InvalidResticConfigError):
        logger.exception("Configuration error")
        sys.exit(1)
    except BackupError:
        logger.exception("Backup error")
        sys.exit(2)
    except Exception:
        logger.exception("Unexpected error")
        sys.exit(3)


if __name__ == "__main__":
    main()

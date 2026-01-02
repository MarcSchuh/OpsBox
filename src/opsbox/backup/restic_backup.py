"""Refactored backup script with improved architecture and error handling."""

import argparse
import hashlib
import os
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path

from opsbox.backup.config_manager import ConfigManager
from opsbox.backup.exceptions import (
    BackupError,
    ConfigurationError,
    DiffParsingError,
    InvalidResticConfigError,
    MaintenanceError,
    NetworkUnreachableError,
    ResticBackupFailedError,
    ResticCommandFailedError,
    SnapshotIDNotFoundError,
    SSHKeyNotFoundError,
    UserDoesNotExistError,
    WrongOSForResticBackupError,
)
from opsbox.backup.network_checker import NetworkChecker
from opsbox.backup.password_manager import PasswordManager
from opsbox.backup.restic_client import ResticClient
from opsbox.backup.snapshot_id import ResticSnapshotId
from opsbox.backup.ssh_manager import SSHManager
from opsbox.encrypted_mail import EncryptedMail
from opsbox.locking import LockManager
from opsbox.logging import LoggingConfig, configure_logging


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
    MAX_FILES_IN_EMAIL = 100

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
            self.encrypted_mail,
        )

    def run(self) -> None:
        """Execute the complete backup workflow with proper error handling."""
        with self.lock_manager:
            try:
                self.logger.info(f"Starting backup {self.config.backup_title} workflow")

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

                # Step 5: Verify backup
                if self._verify_backup(snapshot_id):
                    # Step 6: Perform maintenance
                    self._perform_maintenance()
                else:
                    self._handle_verification_failure()

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
                # Handle backup-specific errors
                self.logger.exception("Backup failed")
                self.encrypted_mail.send_mail_with_retries(
                    subject=f"Backup {self.config.backup_title} failed",
                    message=f"Backup failed: {e}",
                )
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

    def _execute_backup(self) -> ResticSnapshotId:
        """Execute the restic backup operation."""
        self.logger.info(f"Starting backup of {self.config.backup_source}")

        try:
            snapshot_id = self.restic_client.backup(
                self.config.backup_source,
                self.config.excluded_files,
            )

            # Send success notification with diff summary
            diff_summary = self._generate_diff_summary(snapshot_id)
            self.encrypted_mail.send_mail_with_retries(
                subject=f"Backup {self.config.backup_title} successful",
                message=f"Backup completed successfully.\nSnapshot ID: {snapshot_id}\n\nDiff Summary:\n{diff_summary}",
                mail_attachment=str(self.restic_client.log_file),
            )
        except (
            ResticBackupFailedError,
            SnapshotIDNotFoundError,
            ResticCommandFailedError,
        ) as e:
            # Send failure notification with log
            self.encrypted_mail.send_mail_with_retries(
                subject=f"Backup {self.config.backup_title} failed",
                message=f"Backup failed: {e}",
                mail_attachment=str(self.restic_client.log_file)
                if self.restic_client.log_file.exists()
                else None,
            )
            raise
        else:
            return snapshot_id

    def _is_section_header(self, line: str) -> bool:
        """Check if a line is a section header.

        Args:
            line: Line to check

        Returns:
            True if the line is a section header

        """
        line_lower = line.lower()
        return any(
            word in line_lower
            for word in [
                "files:",
                "dirs:",
                "others:",
                "data blobs:",
                "tree blobs:",
                "summary",
            ]
        )

    def _extract_file_path_from_plain_path(
        self,
        line: str,
    ) -> Path:
        """Extract file path from a plain path line in restic diff output.

        Parses lines in the format:
        - "M    /path/to/file.txt" (modified)
        - "-    /path/to/file.txt" (deleted)
        - "+    /path/to/file.txt" (added)

        Args:
            line: Line to parse (e.g., "M    /home/user/file.txt")

        Returns:
            File path as Path object if found, None otherwise

        """
        line_stripped = line.strip()
        if not line_stripped:
            error_msg = "Empty line in diff output"
            self.logger.error(error_msg)
            raise DiffParsingError(error_msg)

        # Check if line starts with M, -, or + followed by spaces
        if line_stripped.startswith(("M", "-", "+")):
            # Remove the prefix character and any following whitespace
            path_str = line_stripped[1:].strip()
            if path_str and path_str.startswith("/"):
                return Path(path_str)
        error_msg = f"Invalid line in diff output: {line_stripped}"
        self.logger.error(error_msg)
        raise DiffParsingError(error_msg)

    def _parse_diff_output(
        self,
        diff_output: str,
        snapshot_id: ResticSnapshotId,
    ) -> ResticDiff:
        """Parse restic diff output to extract deleted, altered, and added files.

        Args:
            diff_output: The raw output from restic diff command
            snapshot_id: The snapshot ID this diff is for

        Returns:
            ResticDiff object containing added, altered, and deleted files

        """
        deleted_files: list[Path] = []
        altered_files: list[Path] = []
        added_files: list[Path] = []

        # Handle None or empty diff output
        if not diff_output:
            error_msg = "No diff output found"
            self.logger.error(error_msg)
            raise ResticBackupFailedError(error_msg)

        for line in diff_output.splitlines():
            line_stripped = line.strip()
            if not line_stripped:
                continue

            # Extract path from lines starting with M (modified), - (deleted), or + (added)
            if line_stripped.startswith("-"):
                # Deleted file
                deleted_files.append(
                    self._extract_file_path_from_plain_path(line_stripped),
                )
            elif line_stripped.startswith("+"):
                # Modified or added file (both count as altered)
                altered_files.append(
                    self._extract_file_path_from_plain_path(line_stripped),
                )
            elif line_stripped.startswith("M"):
                # Modified or added file (both count as altered)
                added_files.append(
                    self._extract_file_path_from_plain_path(line_stripped),
                )

        return ResticDiff(
            added_files=added_files,
            altered_files=altered_files,
            deleted_files=deleted_files,
            snapshot_id=snapshot_id,
        )

    def _check_thresholds_and_send_warnings(
        self,
        diff: ResticDiff,
    ) -> None:
        """Check thresholds and send warning emails if exceeded.

        Args:
            diff: ResticDiff object containing file changes and snapshot ID

        """
        # Check deletion threshold
        if (
            self.config.deletion_threshold is not None
            and len(diff.deleted_files) > self.config.deletion_threshold
        ):
            self.logger.warning(
                f"Deletion threshold exceeded: {len(diff.deleted_files)} files deleted "
                f"(threshold: {self.config.deletion_threshold})",
            )
            deleted_list = "\n".join(
                str(path) for path in diff.deleted_files[: self.MAX_FILES_IN_EMAIL]
            )  # Limit to first N files
            if len(diff.deleted_files) > self.MAX_FILES_IN_EMAIL:
                deleted_list += f"\n... and {len(diff.deleted_files) - self.MAX_FILES_IN_EMAIL} more files"
            self.encrypted_mail.send_mail_with_retries(
                subject=f"Backup {self.config.backup_title} Warning: {len(diff.deleted_files)} files deleted (threshold: {self.config.deletion_threshold})",
                message=(
                    f"Warning: The backup detected {len(diff.deleted_files)} deleted files, "
                    f"which exceeds the threshold of {self.config.deletion_threshold}.\n\n"
                    f"Snapshot ID: {diff.snapshot_id}\n\n"
                    f"Deleted files:\n{deleted_list}"
                ),
            )

        # Check alteration threshold
        altered_and_added = diff.altered_files + diff.added_files
        if (
            self.config.alteration_threshold is not None
            and len(altered_and_added) > self.config.alteration_threshold
        ):
            self.logger.warning(
                f"Alteration threshold exceeded: {len(altered_and_added)} files altered "
                f"(threshold: {self.config.alteration_threshold})",
            )
            altered_list = "\n".join(
                str(path) for path in altered_and_added[: self.MAX_FILES_IN_EMAIL]
            )  # Limit to first N files
            if len(altered_and_added) > self.MAX_FILES_IN_EMAIL:
                altered_list += f"\n... and {len(altered_and_added) - self.MAX_FILES_IN_EMAIL} more files"
            self.encrypted_mail.send_mail_with_retries(
                subject=f"Backup {self.config.backup_title} Warning: {len(altered_and_added)} files altered (threshold: {self.config.alteration_threshold})",
                message=(
                    f"Warning: The backup detected {len(altered_and_added)} altered files, "
                    f"which exceeds the threshold of {self.config.alteration_threshold}.\n\n"
                    f"Snapshot ID: {diff.snapshot_id}\n\n"
                    f"Altered files:\n{altered_list}"
                ),
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

        Sends a separate email for each monitored folder containing only the files
        that were deleted or altered in that specific folder.

        Args:
            diff: ResticDiff object containing file changes and snapshot ID

        """
        if not self.config.monitored_folders:
            return

        # Iterate over each monitored folder and send separate emails
        for monitored_folder in self.config.monitored_folders:
            # Filter files for this specific monitored folder
            folder_deleted = self._filter_files_for_monitored_folder(
                diff.deleted_files,
                monitored_folder,
            )
            folder_altered = self._filter_files_for_monitored_folder(
                diff.altered_files,
                monitored_folder,
            )

            # Send alert for deleted files in this monitored folder
            if folder_deleted:
                self.logger.warning(
                    f"Files deleted in monitored folder {monitored_folder}: "
                    f"{len(folder_deleted)} files",
                )
                deleted_list = "\n".join(
                    str(path) for path in folder_deleted[: self.MAX_FILES_IN_EMAIL]
                )
                if len(folder_deleted) > self.MAX_FILES_IN_EMAIL:
                    deleted_list += f"\n... and {len(folder_deleted) - self.MAX_FILES_IN_EMAIL} more files"
                self.encrypted_mail.send_mail_with_retries(
                    subject=(
                        f"Backup {self.config.backup_title} Alert: {len(folder_deleted)} files deleted in "
                        f"monitored folder: {monitored_folder}"
                    ),
                    message=(
                        f"Alert: The backup detected {len(folder_deleted)} deleted files "
                        f"in monitored folder: {monitored_folder}\n\n"
                        f"Snapshot ID: {diff.snapshot_id}\n\n"
                        f"Deleted files:\n{deleted_list}"
                    ),
                )

            # Send alert for altered files in this monitored folder
            if folder_altered:
                self.logger.warning(
                    f"Files altered in monitored folder {monitored_folder}: "
                    f"{len(folder_altered)} files",
                )
                altered_list = "\n".join(
                    str(path) for path in folder_altered[: self.MAX_FILES_IN_EMAIL]
                )
                if len(folder_altered) > self.MAX_FILES_IN_EMAIL:
                    altered_list += f"\n... and {len(folder_altered) - self.MAX_FILES_IN_EMAIL} more files"
                self.encrypted_mail.send_mail_with_retries(
                    subject=(
                        f"Backup {self.config.backup_title} Alert: {len(folder_altered)} files altered in "
                        f"monitored folder: {monitored_folder}"
                    ),
                    message=(
                        f"Alert: The backup detected {len(folder_altered)} altered files "
                        f"in monitored folder: {monitored_folder}\n\n"
                        f"Snapshot ID: {diff.snapshot_id}\n\n"
                        f"Altered files:\n{altered_list}"
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

            # Get the previous snapshot (second to last)
            # Convert snapshot IDs to ResticSnapshotId for comparison
            current_snapshot = snapshots[-1]
            if current_snapshot != snapshot_id:
                error_msg = f"Here I was expecting to find the current snapshot, but I found something else. Expected: {snapshot_id}, Found: {current_snapshot}"
                raise SnapshotIDNotFoundError(error_msg)
            previous_snapshot = snapshots[-2]

            diff_output = self.restic_client.diff(previous_snapshot, snapshot_id)

            # Parse diff output to extract deleted, altered, and added files
            diff = self._parse_diff_output(diff_output, snapshot_id)

            self._send_file_changes_email(diff)

            # Check thresholds and send warnings if needed
            self._check_thresholds_and_send_warnings(diff)

            # Check monitored folders and send alerts if needed
            self._check_monitored_folders_and_send_alerts(diff)

            # Parse diff output to extract summary
            summary_lines = []
            collecting_summary = False

            for line in diff_output.splitlines():
                if any(
                    word in line
                    for word in [
                        "Files: ",
                        "Dirs: ",
                        "Others: ",
                        "Data Blobs: ",
                        "Tree Blobs: ",
                        "Added: ",
                        "Removed: ",
                    ]
                ):
                    collecting_summary = True

                if collecting_summary:
                    summary_lines.append(line)

            return (
                "\n".join(summary_lines) if summary_lines else "No summary available."
            )

        except (ValueError, TypeError, AttributeError) as e:
            self.logger.warning(f"Failed to generate diff summary: {e}")
            return f"Failed to generate diff summary: {e}"

    def _verify_backup(self, snapshot_id: ResticSnapshotId) -> bool:
        """Verify the backup by checking if specific files exist."""
        self.logger.info(f"Verifying backup snapshot {snapshot_id}")

        try:
            find_output = self.restic_client.find(
                self.config.file_to_check,
                snapshot_id,
            )

            if f"Found matching entries in snapshot {snapshot_id}" in find_output:
                self.logger.info("Backup verification successful")
                self.encrypted_mail.send_mail_with_retries(
                    subject=f"Backup {self.config.backup_title} verification successful",
                    message=f"Backup verification successful for snapshot {snapshot_id}. File {self.config.file_to_check} found.",
                )
                return True
            self.logger.error(
                f"Backup verification failed - file {self.config.file_to_check} not found",
            )
            self.encrypted_mail.send_mail_with_retries(
                subject=f"Backup {self.config.backup_title} verification failed",
                message=f"Backup verification failed for snapshot {snapshot_id} - file {self.config.file_to_check} not found",
            )
            return False  # noqa: TRY300

        except Exception as e:
            self.logger.exception(
                f"Backup {self.config.backup_title} verification failed",
            )
            self.encrypted_mail.send_mail_with_retries(
                subject=f"Backup {self.config.backup_title} verification failed",
                message=f"Backup verification failed: {e}",
            )
            return False

    def _handle_verification_failure(self) -> None:
        """Handle backup verification failure."""
        self.logger.error(
            f"Backup {self.config.backup_title} verification failed - skipping maintenance",
        )
        self.encrypted_mail.send_mail_with_retries(
            subject=f"Backup {self.config.backup_title} verification failed",
            message="Backup verification failed. Maintenance skipped.",
        )

    def _perform_maintenance(self) -> None:
        """Perform maintenance operations on the repository."""
        self.logger.info("Starting maintenance operations")

        try:
            # Forget old snapshots
            self.restic_client.forget(
                self.config.keep_last,
                self.config.keep_daily,
                self.config.keep_monthly,
            )

            # Clean up cache
            self.restic_client.cache_cleanup()

            # Prune repository
            self.restic_client.prune()

            # Check repository integrity
            check_output = self.restic_client.check()

            if "no errors were found" in check_output:
                self.logger.info("Maintenance completed successfully")
                self.encrypted_mail.send_mail_with_retries(
                    subject=f"Backup maintenance {self.config.backup_title} successful",
                    message="Repository maintenance completed successfully.",
                )
            else:
                self.logger.warning("Maintenance completed with warnings")
                self.encrypted_mail.send_mail_with_retries(
                    subject=f"Backup maintenance {self.config.backup_title} completed with warnings",
                    message=f"Repository maintenance completed with warnings:\n{check_output}",
                )

        except Exception as e:
            self.logger.exception("Maintenance failed")
            self.encrypted_mail.send_mail_with_retries(
                subject=f"Backup maintenance {self.config.backup_title} failed",
                message=f"Repository maintenance failed: {e}",
            )
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

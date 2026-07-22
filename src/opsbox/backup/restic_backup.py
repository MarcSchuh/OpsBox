"""Refactored backup script with improved architecture and error handling."""

import argparse
import hashlib
import json
import os
import sys
import tempfile
from collections.abc import Callable
from pathlib import Path
from typing import TypeVar

from opsbox.backup.backup_notifier import BackupNotifier
from opsbox.backup.config_manager import ConfigManager
from opsbox.backup.exceptions import (
    BackupError,
    ConfigurationError,
    EmptySourceError,
    InvalidResticConfigError,
    MaintenanceError,
    NetworkUnreachableError,
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
from opsbox.backup.restic_diff import ResticDiffParser
from opsbox.backup.snapshot_id import ResticSnapshotId
from opsbox.backup.ssh_manager import SSHManager
from opsbox.encrypted_mail import EncryptedMail
from opsbox.locking import LockManager
from opsbox.logging import LoggingConfig, configure_logging

_T = TypeVar("_T")


class BackupScript:
    """Refactored backup script with improved architecture and error handling.

    ``BackupScript`` orchestrates the backup workflow. Diff interpretation is
    delegated to :class:`~opsbox.backup.restic_diff.ResticDiffParser` and all
    notification emails to :class:`~opsbox.backup.backup_notifier.BackupNotifier`.
    """

    MIN_SNAPSHOTS_FOR_DIFF = 2

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

        self.restic_client = ResticClient(
            restic_path,
            self.config.backup_target,
            self.logger,
            command_timeout=self.config.command_timeout,
        )

        # Diff interpretation and notifications live in dedicated collaborators
        self.diff_parser = ResticDiffParser(self.logger)
        self.notifier = BackupNotifier(
            self.encrypted_mail,
            self.config,
            self.logger,
            self.temp_dir,
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
                self.notifier.send_skipped(e)
            except BackupError as e:
                # Single failure notification for the whole workflow
                self.logger.exception("Backup failed")
                self.notifier.send_failure(
                    e,
                    getattr(self.restic_client, "session_log", None),
                )
                raise
            except Exception as e:
                # Handle unexpected errors
                self.logger.exception("Unexpected error during backup")
                self.notifier.send_unexpected_error(e)
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
        self.notifier.send_success(
            snapshot_id,
            diff_summary,
            self.restic_client.session_log,
        )
        return snapshot_id

    def _generate_diff_summary(self, snapshot_id: ResticSnapshotId) -> str:
        """Generate diff summary between current and previous snapshot.

        Diff reporting (change emails, threshold warnings, monitored-folder
        alerts) is a *post-success* convenience: the snapshot has already been
        created and verified separately. A failure while generating the report
        (e.g. ``restic diff`` timing out, an unparseable diff, or a snapshot
        lookup problem) must therefore NOT mark the whole backup as failed.
        Such errors are caught here, logged, and turned into a summary string
        so the success path (and any change emails produced up to that point)
        is preserved instead of triggering a spurious failure notification.
        """
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
            diff = self.diff_parser.parse(diff_output, snapshot_id)

            self.notifier.send_file_changes(diff)
            self.notifier.send_threshold_warnings(diff)
            self.notifier.send_monitored_folder_alerts(diff)

            return self.diff_parser.extract_statistics(diff_output)

        except BackupError as e:
            # BackupError covers the restic-level failures that can legitimately
            # occur here (ResticCommandFailedError, ResticBackupFailedError,
            # SnapshotIDNotFoundError, ...). Reporting problems are non-fatal, so
            # they are logged instead of propagated. Programming errors
            # (TypeError/AttributeError/...) are intentionally NOT caught so they
            # surface instead of being masked as a harmless summary string.
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
            self.notifier.send_verification_success(snapshot_id)
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
        self.logger.info(
            f"Checking repository integrity with read data subset: {self.config.check_read_data_subset}",
        )
        check_output = self.restic_client.check(self.config.check_read_data_subset)
        if is_lock_error(check_output):
            self.logger.warning(
                "Restic repository is locked during 'check'; "
                "removing stale locks and retrying once.",
            )
            self.restic_client.unlock()
            check_output = self.restic_client.check(self.config.check_read_data_subset)
        self.logger.info(f"Repository integrity check output: {check_output}")
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
                self.notifier.send_maintenance_warning(check_output)
                return

            # Repo is clean - safe to permanently remove unreferenced data
            self._run_with_lock_retry(self.restic_client.prune, "prune")

            self.logger.info("Maintenance completed successfully")
            self.notifier.send_maintenance_success(check_output)

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

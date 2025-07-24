"""Refactored backup script with improved architecture and error handling."""

import argparse
import os
import sys
import tempfile
import time
from pathlib import Path

from opsbox.backup.config_manager import ConfigManager
from opsbox.backup.exceptions import (
    BackupError,
    ConfigurationError,
    InvalidResticConfigError,
    MaintenanceError,
    NetworkUnreachableError,
    ResticBackupFailedError,
    SSHKeyNotFoundError,
    UserDoesNotExistError,
    WrongOSForResticBackupError,
)
from opsbox.backup.network_checker import NetworkChecker
from opsbox.backup.password_manager import PasswordManager
from opsbox.backup.restic_client import ResticClient
from opsbox.backup.ssh_manager import SSHManager
from opsbox.encrypted_mail import EncryptedMail
from opsbox.locking import LockManager
from opsbox.logging import LoggingConfig, configure_logging


class BackupScript:
    """Refactored backup script with improved architecture and error handling."""

    MIN_SNAPSHOTS_FOR_DIFF = 2

    def __init__(
        self,
        config_path: str,
        restic_path: str = "/snap/bin/restic",
        temp_dir: str | None = None,
    ) -> None:
        """Initialize the backup script with proper dependency injection.

        Args:
            config_path: Path to configuration file
            restic_path: Path to restic executable
            temp_dir: Directory for temporary files (defaults to system temp dir)

        Raises:
            WrongOSForResticBackupError: If not running on Linux
            ConfigurationError: If configuration cannot be loaded
            InvalidResticConfigError: If configuration is invalid

        """
        self._validate_environment()

        # Load and validate configuration
        self.config = ConfigManager.load_config(config_path)

        # Setup logging
        self.script_name = Path(__file__).name
        self.logger = configure_logging(LoggingConfig(log_name=self.script_name))

        # Setup temporary directory
        self.temp_dir = Path(temp_dir) if temp_dir else Path(tempfile.gettempdir())
        self.temp_dir.mkdir(parents=True, exist_ok=True)

        # Setup lock file
        self.lock_file_path = self.temp_dir / f"{self.script_name}.lock"

        # Initialize components with dependency injection
        self._initialize_components(restic_path)

        self.logger.info("Backup script initialized successfully")

    def _validate_environment(self) -> None:
        """Validate that the script is running in a supported environment."""
        if os.name != "posix" or sys.platform != "linux":
            error_msg = "This script only runs on Linux."
            raise WrongOSForResticBackupError(error_msg)

    def _initialize_components(self, restic_path: str) -> None:
        """Initialize all component classes with proper dependency injection."""
        # Initialize email and locking
        self.encrypted_mail = EncryptedMail(
            self.logger,
            self.config.email_settings_path,
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
        )

    def run(self) -> None:
        """Execute the complete backup workflow with proper error handling."""
        with self.lock_manager:
            try:
                self.logger.info("Starting backup workflow")

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
                    subject="Backup skipped",
                    message=f"Backup was skipped: {e}",
                )
            except BackupError as e:
                # Handle backup-specific errors
                self.logger.exception("Backup failed")
                self.encrypted_mail.send_mail_with_retries(
                    subject="Backup failed",
                    message=f"Backup failed: {e}",
                )
                raise
            except Exception as e:
                # Handle unexpected errors
                self.logger.exception("Unexpected error during backup")
                self.encrypted_mail.send_mail_with_retries(
                    subject="Backup script error",
                    message=f"Unexpected error: {e}",
                )
                error_msg = f"Unexpected error: {e}"
                raise BackupError(error_msg, original_error=e) from e

    def _setup_environment(self) -> None:
        """Set up the restic environment with password and SSH configuration."""
        self.logger.info("Setting up restic environment")

        # Get restic password
        restic_password = self.password_manager.get_restic_password(
            self.config.password_lookup_1,
            self.config.password_lookup_2,
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

    def _execute_backup(self) -> str:
        """Execute the restic backup operation."""
        self.logger.info(f"Starting backup of {self.config.backup_source}")

        # Create temporary log file
        log_file = self.temp_dir / f"backup_log_{int(time.time())}.log"

        try:
            snapshot_id = self.restic_client.backup(
                self.config.backup_source,
                self.config.excluded_files,
                log_file,
            )

            # Send success notification with diff summary
            diff_summary = self._generate_diff_summary(snapshot_id)
            self.encrypted_mail.send_mail_with_retries(
                subject="Backup successful",
                message=f"Backup completed successfully.\nSnapshot ID: {snapshot_id}\n\nDiff Summary:\n{diff_summary}",
                mail_attachment=str(log_file),
            )
        except ResticBackupFailedError as e:
            # Send failure notification with log
            self.encrypted_mail.send_mail_with_retries(
                subject="Backup failed",
                message=f"Backup failed: {e}",
                mail_attachment=str(log_file) if log_file.exists() else None,
            )
            raise
        else:
            return snapshot_id

    def _generate_diff_summary(self, snapshot_id: str) -> str:
        """Generate diff summary between current and previous snapshot."""
        try:
            snapshots = self.restic_client.get_snapshots()

            if len(snapshots) < self.MIN_SNAPSHOTS_FOR_DIFF:
                return "Not enough snapshots to generate diff summary."

            # Get the previous snapshot (second to last)
            previous_snapshot = snapshots[-2]

            diff_output = self.restic_client.diff(previous_snapshot, snapshot_id)

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

    def _verify_backup(self, snapshot_id: str) -> bool:
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
                    subject="Backup verification successful",
                    message=f"Backup verification successful for snapshot {snapshot_id}",
                )
                return True
            self.logger.error("Backup verification failed - file not found")
            self.encrypted_mail.send_mail_with_retries(
                subject="Backup verification failed",
                message=f"Backup verification failed for snapshot {snapshot_id} - file not found",
            )
            return False  # noqa: TRY300

        except Exception as e:
            self.logger.exception("Backup verification failed")
            self.encrypted_mail.send_mail_with_retries(
                subject="Backup verification failed",
                message=f"Backup verification failed: {e}",
            )
            return False

    def _handle_verification_failure(self) -> None:
        """Handle backup verification failure."""
        self.logger.error("Backup verification failed - skipping maintenance")
        self.encrypted_mail.send_mail_with_retries(
            subject="Backup verification failed",
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
                    subject="Maintenance successful",
                    message="Repository maintenance completed successfully.",
                )
            else:
                self.logger.warning("Maintenance completed with warnings")
                self.encrypted_mail.send_mail_with_retries(
                    subject="Maintenance completed with warnings",
                    message=f"Repository maintenance completed with warnings:\n{check_output}",
                )

        except Exception as e:
            self.logger.exception("Maintenance failed")
            self.encrypted_mail.send_mail_with_retries(
                subject="Maintenance failed",
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

    args = parser.parse_args()

    # Setup basic logging for main function
    logger = configure_logging(LoggingConfig(log_name="backup_script"))

    try:
        backup_script = BackupScript(
            config_path=args.config,
            restic_path=args.restic_path,
            temp_dir=args.temp_dir,
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

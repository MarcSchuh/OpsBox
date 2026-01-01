"""Database backup functionality for Docker containers."""

import argparse
import json
import logging
import subprocess
import sys
import tempfile
import time
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import yaml
from dotenv import dotenv_values

from opsbox.encrypted_mail import EncryptedMail
from opsbox.locking import LockManager
from opsbox.logging import LoggingConfig, configure_logging


class DBBackup:
    """Handles database backup, cleanup, and notification."""

    def __init__(  # noqa: PLR0913
        self,
        backup_dir: Path,
        container_name: str,
        env_file: Path,
        retention_days: int,
        logger: logging.Logger,
        email_client: EncryptedMail,
        compression_level: int = 6,
        dry_run: bool = False,
    ) -> None:
        """Initialize the DBBackup instance.

        Args:
            backup_dir: Directory where backups will be stored
            container_name: Name of the Docker container
            env_file: Path to .env file containing DB credentials
            retention_days: Number of days to retain backups
            logger: Logger instance for logging operations
            email_client: EncryptedMail instance for notifications
            compression_level: Gzip compression level (1-9)
            dry_run: If True, don't make actual changes

        Raises:
            MissingEnvVariableError: If required DB environment variables are missing
            FileNotFoundError: If env_file doesn't exist
            NotADirectoryError: If backup_dir exists but is not a directory

        """
        self.backup_dir = backup_dir
        self.container_name = container_name
        self.retention_days = retention_days
        self.logger = logger
        self.email_client = email_client
        self.compression_level = compression_level
        self.dry_run = dry_run
        self.backup_file_path: Path | None = None
        self._start_time = datetime.now(UTC)
        self.metrics: dict[str, Any] = {
            "start_time": datetime.now(UTC).isoformat(),
            "success": False,
            "file_size_bytes": 0,
            "duration_seconds": 0,
        }

        # Load environment variables from .env file
        self.env_config = self._load_env_file(env_file)

        # Extract DB config from env_config
        self.db_user: str = str(self.env_config["DB_USER"])
        self.db_password: str = str(self.env_config["DB_PASSWORD"])
        self.db_name: str = str(self.env_config["DB_NAME"])

        # Ensure backup directory exists
        self._ensure_backup_dir()

        self.script_identifier = f"db_backup_{self.container_name}_{self.db_name}"

        self.logger.info(
            f"Backup configured for database '{self.db_name}' using user '{self.db_user}'.",
        )
        self.lock_file_path = (
            Path(tempfile.gettempdir()) / f"{self.script_identifier}.lock"
        )
        self.lock_manager = LockManager(
            lock_file=self.lock_file_path,
            logger=self.logger,
            encrypted_mail=self.email_client,
            script_name=self.script_identifier,
        )

        if self.dry_run:
            self.logger.info("DRY RUN MODE: No actual changes will be made")

    def _load_env_file(self, env_file: Path) -> dict[str, str | None]:
        """Load environment variables from .env file with error handling.

        Args:
            env_file: Path to the .env file

        Returns:
            Dictionary of environment variables

        Raises:
            FileNotFoundError: If env_file doesn't exist
            IOError: If loading fails

        """
        if not env_file.exists():
            error_msg = (
                f"Identifier: {self.script_identifier}\n"
                f"Environment file not found: {env_file}"
            )
            self.logger.error(error_msg)
            self.email_client.send_mail_with_retries(
                "Database Backup Configuration Error",
                error_msg,
            )
            raise FileNotFoundError(error_msg)

        try:
            env_config = dotenv_values(env_file)
            self.logger.info(f"Successfully loaded configuration from {env_file}")
            return dict(env_config)  # Convert to dict to satisfy type checker
        except OSError as e:
            error_msg = (
                f"Identifier: {self.script_identifier}\n"
                f"Failed to load environment file {env_file}: {e}"
            )
            self.logger.exception(error_msg)
            self.email_client.send_mail_with_retries(
                "Database Backup Configuration Error",
                error_msg,
            )
            raise

    def _ensure_backup_dir(self) -> None:
        """Create the backup directory if it doesn't exist.

        Raises:
            NotADirectoryError: If backup_dir exists but is not a directory
            OSError: If directory creation fails

        """
        self.logger.info(f"Ensuring backup directory exists: {self.backup_dir}")
        try:
            if not self.backup_dir.exists():
                if not self.dry_run:
                    self.backup_dir.mkdir(parents=True, exist_ok=True)
                warning_msg = (
                    f"Identifier: {self.script_identifier}\n"
                    f"Backup directory did not exist and was "
                    f"{'would be' if self.dry_run else 'was'} created: {self.backup_dir}"
                )
                self.logger.warning(warning_msg)
                self.email_client.send_mail_with_retries(
                    "Database Backup Warning",
                    warning_msg,
                )
            elif not self.backup_dir.is_dir():
                error_msg = (
                    f"Identifier: {self.script_identifier}\n"
                    f"Backup path exists but is not a directory: {self.backup_dir}"
                )
                self.logger.error(error_msg)
                self.email_client.send_mail_with_retries(
                    "Database Backup Error",
                    error_msg,
                )
                raise NotADirectoryError(error_msg)  # noqa: TRY301
        except Exception as e:
            error_msg = (
                f"Identifier: {self.script_identifier}\n"
                f"Failed to create backup directory {self.backup_dir}: {e}"
            )
            self.logger.exception(error_msg)
            self.email_client.send_mail_with_retries(
                "Database Backup Error",
                error_msg,
            )
            raise

    def _generate_backup_filename(self) -> Path:
        """Generate a timestamped backup filename.

        Returns:
            Path to the backup file

        """
        timestamp = datetime.now(UTC).strftime("%Y%m%d_%H%M%S")
        # Use the actual db_name from config in the filename
        filename = f"{self.db_name}_backup_{timestamp}.sql.gz"
        return self.backup_dir / filename

    def _test_database_connection(self) -> bool:
        """Test the database connection before attempting backup.

        Returns:
            True if connection test succeeds, False otherwise

        """
        if self.dry_run:
            self.logger.info("DRY RUN: Would test database connection")
            return True

        self.logger.info("Testing database connection...")

        test_cmd = [
            "docker",
            "exec",
            self.container_name,
            "mariadb",
            f"--user={self.db_user}",
            f"--password={self.db_password}",
            self.db_name,
            "-e",
            "SHOW TABLES;",
        ]

        try:
            subprocess.run(  # noqa: S603
                test_cmd,
                check=True,
                capture_output=True,
            )
        except subprocess.CalledProcessError as e:
            error_msg = (
                e.stderr.decode("utf-8", errors="replace").strip()
                if e.stderr
                else "No stderr output"
            )
            self.logger.exception(f"Database connection test failed: {error_msg}")
            return False
        else:
            self.logger.info("Database connection test successful")
            return True

    def _create_backup(self) -> None:
        """Execute the database dump and compression.

        Raises:
            subprocess.CalledProcessError: If the dump command fails

        """
        if self.dry_run:
            self.logger.info("DRY RUN: Would create database backup")
            self.backup_file_path = self._generate_backup_filename()
            return

        self.backup_file_path = self._generate_backup_filename()
        self.logger.info(f"Starting backup to {self.backup_file_path}...")

        # Prepare the dump command
        dump_command = (
            f'exec mariadb-dump --user="{self.db_user}" '
            f'--password="{self.db_password}" "{self.db_name}" | '
            f"gzip -{self.compression_level}"
        )

        docker_command = [
            "docker",
            "exec",
            self.container_name,
            "sh",
            "-c",
            dump_command,
        ]

        try:
            with self.backup_file_path.open("wb") as f_out:
                subprocess.run(  # noqa: S603
                    docker_command,
                    stdout=f_out,
                    stderr=subprocess.PIPE,
                    check=True,
                    text=False,
                )
            self.logger.info(f"Database dump successful: {self.backup_file_path}")

            # Record file size for metrics
            if self.backup_file_path.exists():
                self.metrics["file_size_bytes"] = self.backup_file_path.stat().st_size
        except subprocess.CalledProcessError as e:
            error_message = (
                e.stderr.decode("utf-8", errors="replace").strip()
                if e.stderr
                else "No stderr output"
            )
            self.logger.exception(f"Database dump failed. Return code: {e.returncode}")
            self.logger.exception(f"Stderr: {error_message}")
            raise

    def _verify_backup(self) -> bool:
        """Verify the backup file is valid and not corrupted.

        Returns:
            True if backup is valid, False otherwise

        """
        if self.dry_run:
            self.logger.info("DRY RUN: Would verify backup file")
            return True

        if not self.backup_file_path or not self.backup_file_path.exists():
            self.logger.error("Backup file does not exist, cannot verify")
            return False

        # Check file size
        min_backup_size_bytes = 100
        file_size = self.backup_file_path.stat().st_size
        if file_size < min_backup_size_bytes:
            self.logger.warning(f"Backup file suspiciously small: {file_size} bytes")
            return False

        # Test the gzip file integrity
        self.logger.info(
            f"Verifying backup file integrity: {self.backup_file_path}",
        )
        try:
            result = subprocess.run(  # noqa: S603
                ["gzip", "-t", str(self.backup_file_path)],  # noqa: S607
                check=False,
                capture_output=True,
            )
            if result.returncode != 0:
                error_msg = result.stderr.decode("utf-8", errors="replace").strip()
                self.logger.error(
                    f"Backup file failed gzip integrity check: {error_msg}",
                )
                return False
        except Exception:
            self.logger.exception("Error verifying backup file")
            return False
        return True

    def _cleanup_old_backups(self) -> None:
        """Remove backup files older than the retention period."""
        if self.retention_days <= 0:
            self.logger.info("Backup retention disabled (retention_days <= 0).")
            return

        if self.dry_run:
            self.logger.info(
                f"DRY RUN: Would clean up backups older than {self.retention_days} days",
            )
            return

        self.logger.info(
            f"Cleaning up backups older than {self.retention_days} days in {self.backup_dir}...",
        )
        cutoff_time = time.time() - (self.retention_days * 24 * 60 * 60)
        cleaned_count = 0
        try:
            for file_path in self.backup_dir.glob(f"{self.db_name}_backup_*.sql.gz"):
                if file_path.is_file():
                    try:
                        file_mtime = file_path.stat().st_mtime
                        if file_mtime < cutoff_time:
                            self.logger.info(
                                f"Deleting old backup: {file_path} "
                                f"(modified: {datetime.fromtimestamp(file_mtime, tz=UTC)})",
                            )
                            file_path.unlink()
                            cleaned_count += 1
                    except OSError as e:
                        self.logger.warning(
                            f"Could not process or delete file {file_path}: {e}",
                        )
            self.logger.info(
                f"Cleanup complete. Deleted {cleaned_count} old backup files.",
            )
        except Exception:
            self.logger.exception("An error occurred during cleanup")
            raise

    def _record_metrics(self) -> None:
        """Record metrics about the backup operation."""
        end_time = datetime.now(UTC)
        self.metrics["end_time"] = end_time.isoformat()
        self.metrics["duration_seconds"] = (end_time - self._start_time).total_seconds()

        # Create metrics file if needed
        metrics_file = self.backup_dir / "backup_metrics.json"

        if self.dry_run:
            self.logger.info(f"DRY RUN: Would record metrics to {metrics_file}")
            return

        try:
            self.logger.info(f"Recording backup metrics to {metrics_file}")

            # Add additional metrics
            self.metrics["database"] = self.db_name
            self.metrics["timestamp"] = end_time.isoformat()
            self.metrics["retention_days"] = self.retention_days

            # Write to metrics file
            with metrics_file.open("a") as f:
                f.write(json.dumps(self.metrics) + "\n")

            self.logger.info(
                f"Metrics recorded: duration={self.metrics['duration_seconds']:.2f}s, "
                f"size={self.metrics['file_size_bytes']} bytes",
            )
        except OSError as e:
            self.logger.warning(f"Failed to record metrics: {e}")
            # Non-critical error, don't raise

    def run(self) -> None:
        """Execute the full backup and cleanup process with error notification.

        Raises:
            ConnectionError: If database connection test fails
            ValueError: If backup verification fails
            Exception: For other backup-related errors

        """
        with self.lock_manager:
            start_time = datetime.now(UTC)
            self.logger.info(
                f"Database Backup Script started at {start_time.strftime('%Y-%m-%d %H:%M:%S')}",
            )
            subject_prefix = f"Database Backup {self.db_name}"

            try:
                # Test database connection first
                if not self._test_database_connection():
                    msg = "Database connection test failed"
                    raise ConnectionError(msg)  # noqa: TRY301

                # Create the backup
                self._create_backup()

                # Verify the backup
                if not self._verify_backup():
                    msg = "Backup verification failed"
                    raise ValueError(msg)  # noqa: TRY301

                # Clean up old backups
                self._cleanup_old_backups()

                # Record success in metrics
                self.metrics["success"] = True
                self._record_metrics()

                end_time = datetime.now(UTC)
                duration = end_time - start_time
                success_message = (
                    f"Identifier: {self.script_identifier}\n"
                    f"Backup completed successfully at {end_time.strftime('%Y-%m-%d %H:%M:%S')}.\n"
                    f"Database: {self.db_name}\n"
                    f"Backup file: {self.backup_file_path}\n"
                    f"File size: {self.metrics['file_size_bytes']} bytes\n"
                    f"Duration: {duration}"
                )
                self.logger.info(success_message)
                attachment_path = (
                    str(self.backup_file_path) if self.backup_file_path else None
                )
                self.email_client.send_mail_with_retries(
                    f"{subject_prefix} Successful",
                    success_message,
                    attachment_path,
                )

            except Exception as e:
                # Record failure in metrics
                self.metrics["success"] = False
                self.metrics["error"] = f"{type(e).__name__}: {e!s}"
                self._record_metrics()

                end_time = datetime.now(UTC)
                duration = end_time - start_time
                error_message = (
                    f"Identifier: {self.script_identifier}\n"
                    f"Backup FAILED at {end_time.strftime('%Y-%m-%d %H:%M:%S')}.\n"
                    f"Database: {self.db_name}\n"
                    f"Error Type: {type(e).__name__}\n"
                    f"Error Details: {e}\n"
                    f"Duration before failure: {duration}"
                )
                self.logger.exception(error_message)
                self.email_client.send_mail_with_retries(
                    f"{subject_prefix} FAILED",
                    error_message,
                    None,
                )
                raise


def main() -> None:
    """Execute the main entry point for the database backup script."""
    parser = argparse.ArgumentParser(
        description="Backup Database database from a Docker container.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument(
        "--config",
        type=Path,
        required=True,
        help="Path to the YAML configuration file.",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Run in dry-run mode without making any actual changes.",
    )

    args = parser.parse_args()

    logger = configure_logging(
        LoggingConfig(
            log_name="database_backup",
            log_filename="database_backup.log",
        ),
    )

    # Load configuration
    try:
        with args.config.open() as f:
            config = yaml.safe_load(f)
    except (OSError, yaml.YAMLError) as e:
        logger.critical(f"Failed to load configuration file {args.config}: {e}")
        sys.exit(1)

    # Initialize email client
    try:
        email_client = EncryptedMail(
            logger,
            Path(config.get("email_settings")),
            fail_silently=False,
        )
        logger.info("EncryptedMail client initialized.")
    except (OSError, ValueError, KeyError) as e:
        logger.critical(f"Failed to initialize EncryptedMail client: {e}")
        sys.exit(1)

    # Initialize and run the backup process
    try:
        backup_instance = DBBackup(
            backup_dir=Path(config.get("backup_dir")),
            container_name=config.get("container_name"),
            env_file=Path(config.get("env_file")),
            retention_days=config.get("retention_days", 30),
            logger=logger,
            email_client=email_client,
            compression_level=config.get("compression_level", 6),
            dry_run=args.dry_run,
        )

        if args.dry_run:
            logger.info("Running in DRY RUN mode - no actual changes will be made")

        backup_instance.run()

        if args.dry_run:
            logger.info(
                "DRY RUN completed successfully - no actual changes were made",
            )
        else:
            logger.info("Database Backup Script finished successfully.")

        sys.exit(0)
    except Exception as e:
        logger.critical(
            f"An unexpected critical error occurred: {e}",
            exc_info=True,
        )
        try:
            subject = "Database Backup FAILED - Critical Error"
            message = (
                f"Env-file: {config.get('env_file')}\n"
                f"Backup script failed critically:\n{type(e).__name__}: {e}"
            )
            email_client.send_mail_with_retries(subject, message, None)
        except Exception:
            logger.exception("Failed to send critical error notification")
        sys.exit(1)


if __name__ == "__main__":
    main()

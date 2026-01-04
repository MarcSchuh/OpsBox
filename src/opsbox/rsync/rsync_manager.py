"""Rsync backup manager with SSH support and retry logic."""

import argparse
import getpass
import hashlib
import re
import subprocess
import sys
import tempfile
import time
from dataclasses import dataclass, field
from enum import Enum
from functools import lru_cache
from pathlib import Path
from typing import Any

import yaml

from opsbox.backup.exceptions import (
    ConfigurationError,
    FolderNotFoundError,
    NetworkUnreachableError,
    SSHKeyNotFoundError,
    UserDoesNotExistError,
)
from opsbox.backup.network_checker import NetworkChecker
from opsbox.backup.ssh_manager import SSHManager
from opsbox.encrypted_mail import EncryptedMail
from opsbox.exceptions import LockAlreadyTakenError, RsyncError
from opsbox.locking import LockManager
from opsbox.logging import LoggingConfig, configure_logging


class Constants(Enum):
    """Constants used throughout the rsync manager."""

    BYTES_PER_KB = 1024.0
    SECONDS_PER_MINUTE = 60
    SECONDS_PER_HOUR = 3600


class StatType(Enum):
    """Enumeration for rsync statistic types."""

    SENT = "sent"
    RECEIVED = "received"
    TOTAL_SIZE = "total_size"


@dataclass
class RsyncStats:
    """Statistics from an rsync operation."""

    sent: int
    received: int
    total_size: int


@dataclass
class RsyncConfig:
    """Configuration for rsync operations."""

    # Required fields
    rsync_source: str
    rsync_target: str
    email_settings_path: Path

    # Optional fields with defaults
    log_file: str | None = None
    rsync_retry_max: int = 3
    rsync_retry_delay: int = 5
    ssh_key: str | None = None
    ssh_user: str | None = None
    network_host: str | None = None
    rsync_title: str = "Default rsync title"
    rsync_options: dict[str, Any] = field(default_factory=dict)
    default_user: str = field(default_factory=lambda: getpass.getuser())
    exclude_file: Path | None = None

    def __post_init__(self) -> None:
        """Validate configuration after initialization."""
        self._validate_required_fields()
        self._validate_ssh_configuration()
        self._validate_paths()

    def _validate_required_fields(self) -> None:
        """Validate that all required fields are present and non-empty."""
        # String fields
        string_fields = ["rsync_target", "rsync_source"]
        for field_name in string_fields:
            value = getattr(self, field_name)
            if not value or not str(value).strip():
                error_msg = f"Required field '{field_name}' cannot be empty"
                raise ConfigurationError(error_msg)

        # Path field
        if not self.email_settings_path or not str(self.email_settings_path).strip():
            error_msg = "Required field 'email_settings_path' cannot be empty"
            raise ConfigurationError(error_msg)

    def _validate_ssh_configuration(self) -> None:
        """Validate SSH configuration consistency."""
        if self.network_host is None and self.ssh_key is not None:
            error_msg = "If ssh_key is set, network_host must be set as well."
            raise ConfigurationError(error_msg)
        if self.ssh_key is None and self.network_host is not None:
            error_msg = "If network_host is set, ssh_key must be set as well."
            raise ConfigurationError(error_msg)
        if self.ssh_key is not None and self.ssh_user is None:
            error_msg = "If ssh_key is set, ssh_user must be set as well."
            raise ConfigurationError(error_msg)

    def _validate_paths(self) -> None:
        """Validate that file paths exist where required."""
        if not self.email_settings_path.exists():
            error_msg = f"Email settings file not found: {self.email_settings_path}"
            raise ConfigurationError(error_msg)
        if self.exclude_file is not None and not self.exclude_file.exists():
            error_msg = f"Exclude file not found: {self.exclude_file}"
            raise FolderNotFoundError(error_msg)


class RsyncManager:
    """Manages rsync backup operations with SSH support and retry logic."""

    def __init__(
        self,
        config_path: Path,
        log_level: str = "INFO",
    ) -> None:
        """Initialize the rsync manager.

        Args:
            config_path: Path to configuration YAML file
            log_level: Logging level (defaults to INFO)
            temp_dir: Directory for temporary files (defaults to system temp dir)

        Raises:
            ConfigurationError: If configuration cannot be loaded or is invalid

        """
        # Load and validate configuration
        self.config = self._load_config(config_path)

        # Setup logging
        self.script_name = Path(__file__).name
        self.logger = configure_logging(
            LoggingConfig(log_name=self.script_name, log_level=log_level),
        )

        # Setup temporary directory
        self.temp_dir = Path(tempfile.gettempdir())
        self.temp_dir.mkdir(parents=True, exist_ok=True)

        # Setup lock file - hash rsync_target to allow concurrent operations to different targets
        target_hash = hashlib.sha256(self.config.rsync_target.encode()).hexdigest()[:8]
        self.lock_file_path = self.temp_dir / f"{self.script_name}.{target_hash}.lock"

        # Setup log file path
        if self.config.log_file:
            self.log_file_path = Path(self.config.log_file)
            self.log_file_path.parent.mkdir(parents=True, exist_ok=True)
        else:
            self.log_file_path = self.temp_dir / f"{self.script_name}.{target_hash}.log"

        # Initialize components
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

        self.network_checker = NetworkChecker(self.logger)
        self.ssh_manager = SSHManager(self.logger)

        self.logger.info("Rsync manager initialized successfully")
        self.max_log_lines = 15

    @staticmethod
    def _load_config(config_path: Path) -> RsyncConfig:
        """Load and validate configuration from YAML file.

        Args:
            config_path: Path to the configuration YAML file

        Returns:
            Validated RsyncConfig instance

        Raises:
            ConfigurationError: If configuration file cannot be loaded or is invalid

        """
        try:
            with config_path.open(encoding="utf-8") as f:
                config_data = yaml.safe_load(f)
        except FileNotFoundError as e:
            error_msg = f"Configuration file not found: {config_path}"
            raise ConfigurationError(error_msg) from e
        except yaml.YAMLError as e:
            error_msg = f"Invalid configuration file format: {e}"
            raise ConfigurationError(error_msg) from e
        except Exception as e:
            error_msg = f"Error loading configuration: {e}"
            raise ConfigurationError(error_msg) from e

        try:
            # Create RsyncConfig instance with validation
            exclude_file = config_data.get("exclude_file")
            return RsyncConfig(
                rsync_source=config_data["rsync_source"],
                rsync_target=config_data["rsync_target"],
                email_settings_path=Path(config_data["email_settings_path"]),
                log_file=config_data.get("log_file"),
                rsync_retry_max=int(config_data.get("rsync_retry_max", 3)),
                rsync_retry_delay=int(config_data.get("rsync_retry_delay", 5)),
                ssh_key=config_data.get("ssh_key"),
                ssh_user=config_data.get("ssh_user"),
                network_host=config_data.get("network_host"),
                rsync_options=config_data.get("rsync_options", {}),
                default_user=config_data.get("default_user", getpass.getuser()),
                rsync_title=config_data.get("rsync_title", "Default rsync title"),
                exclude_file=Path(exclude_file) if exclude_file else None,
            )

        except KeyError as e:
            error_msg = f"Missing required configuration field: {e}"
            raise ConfigurationError(error_msg) from e
        except Exception as e:
            error_msg = f"Configuration validation failed: {e}"
            raise ConfigurationError(error_msg) from e

    def _ensure_target_dir_is_mounted(self, path: Path) -> None:
        """Ensure the target directory is mounted.

        Args:
            path: Path to the target directory

        Raises:
            ConfigurationError: If the target directory is not mounted

        """
        if not path.exists() or not path.is_dir():
            error_msg = f"Path does not exist or is not a directory: {path}"
            raise ConfigurationError(error_msg)

    def _check_server_connection(self) -> None:
        """Check server connectivity and SSH key availability.

        Raises:
            NetworkUnreachableError: If server is not reachable
            SSHKeyNotFoundError: If SSH key is not available
            UserDoesNotExistError: If SSH user does not exist

        """
        # Extract host from rsync_source (format: user@host:path)
        host: str | None
        if "@" in self.config.rsync_source:
            host = self.config.rsync_source.split("@")[1].split(":")[0]
        else:
            error_msg = (
                f"Cannot determine host from rsync_source {self.config.rsync_source}"
            )
            raise ConfigurationError(error_msg)

        # Check network connectivity
        self.network_checker.check_network_connectivity_or_raise(host)

        # Check SSH key if configured
        if self.config.ssh_key and self.config.ssh_user:
            self.ssh_manager.ensure_ssh_key_loaded(
                ssh_key=self.config.ssh_key,
                ssh_user=self.config.ssh_user,
            )

    def _build_rsync_command(self) -> list[str]:
        """Build the rsync command with all options.

        Returns:
            List of command arguments for rsync

        """
        cmd = ["/usr/bin/rsync", "-avz"]

        # Add rsync options from config
        if self.config.rsync_options.get("chown"):
            cmd.extend(["--chown", self.config.rsync_options["chown"]])

        if self.config.rsync_options.get("delete", False):
            cmd.append("--delete")

        if self.config.rsync_options.get("progress", False):
            cmd.append("--progress")

        # Add exclude file if specified
        if self.config.exclude_file is not None:
            cmd.extend(["--exclude-from", str(self.config.exclude_file)])

        # Add log file
        cmd.extend(["--log-file", str(self.log_file_path)])

        # Add source and destination
        cmd.append(self.config.rsync_source)
        cmd.append(self.config.rsync_target)

        return cmd

    @staticmethod
    def _format_bytes(bytes_value: int | None) -> str:
        """Format bytes in human-readable format.

        Args:
            bytes_value: Number of bytes to format, or None

        Returns:
            Human-readable string (e.g., "1.5 GB") or "N/A" if None

        """
        if bytes_value is None:
            return "N/A"

        value = float(bytes_value)
        for unit in ["B", "KB", "MB", "GB", "TB", "PB"]:
            if value < Constants.BYTES_PER_KB.value:
                return f"{value:.2f} {unit}"
            value /= Constants.BYTES_PER_KB.value
        return f"{value:.2f} PB"

    @staticmethod
    def _parse_number_with_dots(number_str: str) -> int:
        """Parse a number string that may contain dots as thousand separators.

        Args:
            number_str: Number string (e.g., "35.821.870" or "552313")

        Returns:
            Integer value

        """
        # Remove dots and convert to int
        cleaned = number_str.replace(".", "").replace(",", "")
        return int(cleaned)

    def _parse_rsync_log_stats(self) -> RsyncStats:
        """Parse rsync log file to extract statistics.

        Returns:
            RsyncStats object with sent, received, and total_size values

        """
        # Buffer values in local variables (use None as sentinel for "not found")
        sent: int | None = None
        received: int | None = None
        total_size: int | None = None

        if not self.log_file_path.exists():
            self.logger.warning(f"Log file not found: {self.log_file_path}")
            return RsyncStats(sent=0, received=0, total_size=0)

        try:
            with self.log_file_path.open(encoding="utf-8") as f:
                lines = f.readlines()

            lines_to_process = (
                lines[-self.max_log_lines :]
                if len(lines) >= self.max_log_lines
                else lines
            )
            for line in reversed(lines_to_process):
                # Match: sent X bytes  received Y bytes
                sent_match = re.search(r"sent\s+([\d.,]+)\s+bytes", line)
                received_match = re.search(r"received\s+([\d.,]+)\s+bytes", line)
                # Match: total size is X
                total_match = re.search(r"total size is\s+([\d.,]+)", line)

                if sent_match and sent is None:
                    sent = self._parse_number_with_dots(sent_match.group(1))
                if received_match and received is None:
                    received = self._parse_number_with_dots(received_match.group(1))
                if total_match and total_size is None:
                    total_size = self._parse_number_with_dots(total_match.group(1))

                # If we found all stats, we can break early
                if sent is not None and received is not None and total_size is not None:
                    break

        except Exception as e:
            self.logger.warning(f"Error parsing rsync log: {e}")

        # Convert None to 0 and create the object at the end
        return RsyncStats(
            sent=sent if sent is not None else 0,
            received=received if received is not None else 0,
            total_size=total_size if total_size is not None else 0,
        )

    @lru_cache(maxsize=1000)  # noqa: B019
    def _get_last_log_lines(self, num_lines: int) -> list[str]:
        """Get the last num_lines lines from the log file.

        Args:
            num_lines: Number of lines to retrieve
        Returns:
            List of last log lines

        """
        with self.log_file_path.open(encoding="utf-8") as f:
            lines = f.readlines()

        return lines[-num_lines:] if len(lines) >= num_lines else lines

    def _check_log_for_errors(self) -> bool:
        """Check the last 10 lines of the log file for errors.

        Returns:
            True if errors are found, False otherwise

        """
        if not self.log_file_path.exists():
            return False

        try:
            # Check for common error patterns
            error_patterns = [
                r"error",
                r"failed",
                r"fatal",
                r"permission denied",
                r"connection refused",
                r"timeout",
                r"no such file",
            ]

            for line in self._get_last_log_lines(self.max_log_lines):
                line_lower = line.lower()
                for pattern in error_patterns:
                    if re.search(pattern, line_lower):
                        return True

        except Exception as e:
            self.logger.warning(f"Error checking log for errors: {e}")

        return False

    def _format_duration(self, seconds: float) -> str:
        """Format duration in human-readable format.

        Args:
            seconds: Duration in seconds

        Returns:
            Human-readable duration string

        """
        if seconds < Constants.SECONDS_PER_MINUTE.value:
            return f"{seconds:.2f} seconds"
        if seconds < Constants.SECONDS_PER_HOUR.value:
            minutes = seconds / Constants.SECONDS_PER_MINUTE.value
            return f"{minutes:.2f} minutes"
        hours = seconds / Constants.SECONDS_PER_HOUR.value
        return f"{hours:.2f} hours"

    def _run_rsync_attempt(self, cmd: list[str]) -> None:
        """Run a single rsync attempt.

        Args:
            cmd: Rsync command to execute

        Returns:
            None if rsync succeeded, otherwise raises an exception

        """
        self.logger.info(f"Executing command: {' '.join(cmd)}")

        result = subprocess.run(  # noqa: S603
            cmd,
            check=False,
            capture_output=True,
            text=True,
            timeout=36000,  # 10 hour timeout
        )

        if result.returncode == 0:
            self.logger.info("Rsync completed successfully")
            return
        self.logger.error(
            f"Rsync failed with exit code {result.returncode}. "
            f"Stderr: {result.stderr[:500] if result.stderr else 'None'}",
        )
        raise RsyncError

    def _execute_rsync(self) -> None:
        """Execute rsync with retry logic and send summary email.

        Returns:
            True if rsync succeeded, False otherwise

        """
        self.logger.info("Starting rsync operation")

        cmd = self._build_rsync_command()
        start_time = time.time()

        # Retry loop
        success = False
        num_attempts = 0
        for attempt in range(1, self.config.rsync_retry_max + 1):
            self.logger.info(f"Rsync attempt {attempt}/{self.config.rsync_retry_max}")
            num_attempts = attempt

            try:
                self._run_rsync_attempt(cmd)
                success = True
                break
            except Exception:
                self.logger.exception(f"Rsync attempt {attempt} failed:")

            if attempt < self.config.rsync_retry_max:
                self.logger.info(
                    f"Retrying in {self.config.rsync_retry_delay} seconds...",
                )
                time.sleep(self.config.rsync_retry_delay)

        # Calculate execution time
        execution_time = time.time() - start_time

        # Parse log statistics
        stats = self._parse_rsync_log_stats()

        # Check for errors in last 10 lines
        has_errors = self._check_log_for_errors()

        # Build email message
        message_lines = [
            f"Rsync operation completed for script: {self.script_name}",
            "",
            "Summary:",
            f"  Number of attempts: {num_attempts}",
            f"  Execution time: {self._format_duration(execution_time)}",
            f"  Bytes sent: {self._format_bytes(stats.sent)}",
            f"  Bytes received: {self._format_bytes(stats.received)}",
            f"  Total size: {self._format_bytes(stats.total_size)}",
            "",
        ]

        if not success:
            message_lines.append(f"Status: FAILED after {num_attempts} attempts")
        else:
            message_lines.append("Status: SUCCESS")

        if has_errors:
            message_lines.append("")
            message_lines.append(
                f"WARNING: Errors detected in the last {self.max_log_lines} lines of the log file.",
            )
        message_lines.append("")
        message_lines.append("------------------")
        message_lines.append("The last log lines were:")
        message_lines.extend(self._get_last_log_lines(self.max_log_lines))

        message = "\n".join(message_lines)

        # Build subject
        subject_prefix = "Error: " if not success or has_errors else ""

        subject = f"{subject_prefix}Rsync {self.config.rsync_title} backup summary"

        # Send email
        try:
            self.encrypted_mail.send_mail_with_retries(
                subject=subject,
                message=message,
                mail_attachment=str(self.log_file_path),
            )
        except Exception as e:
            self.logger.warning(f"Failed to send summary email: {e}")

        if not success:
            error_msg = f"Rsync failed after {self.config.rsync_retry_max} attempts"
            self.logger.error(error_msg)
            raise RsyncError(error_msg)

    def run(self) -> None:
        """Execute the complete rsync workflow with proper error handling."""
        with self.lock_manager:
            try:
                self.logger.info(
                    f"Starting rsync {self.config.rsync_title} backup workflow",
                )

                # Step 1: Check if sync is mounted
                self._ensure_target_dir_is_mounted(Path(self.config.rsync_target))

                # Step 2: Check server connection
                try:
                    self._check_server_connection()
                except (
                    NetworkUnreachableError,
                    SSHKeyNotFoundError,
                    UserDoesNotExistError,
                ) as e:
                    error_msg = f"Server connection check failed: {e}"
                    self.logger.exception(error_msg)
                    self.encrypted_mail.send_mail_with_retries(
                        subject=f"Rsync {self.config.rsync_title} server connection failed",
                        message=f"Script {self.script_name} encountered a connection error: {e}",
                    )
                    raise

                # Step 3: Execute rsync with retry
                self._execute_rsync()

                self.logger.info("Rsync backup workflow completed successfully")
            except Exception as e:
                self.logger.exception("Unexpected error in rsync workflow")
                try:
                    self.encrypted_mail.send_mail_with_retries(
                        subject=f"Rsync {self.config.rsync_title} backup critical error",
                        message=f"Script {self.script_name} encountered an unexpected error: {type(e).__name__}: {e}",
                        mail_attachment=str(self.log_file_path),
                    )
                except Exception:
                    self.logger.exception("Failed to send error notification email")
                raise


def main() -> None:
    """Execute the main entry point for the rsync manager script."""
    parser = argparse.ArgumentParser(
        description="Rsync backup manager with SSH support",
    )
    parser.add_argument(
        "--config",
        type=str,
        required=True,
        help="Path to configuration YAML file",
    )
    parser.add_argument(
        "--log-level",
        type=str,
        default="INFO",
        choices=["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"],
        help="Logging level (default: INFO)",
    )
    args = parser.parse_args()

    # Setup basic logging for main function
    logger = configure_logging(
        LoggingConfig(log_name="rsync_manager", log_level=args.log_level),
    )

    try:
        rsync_manager = RsyncManager(
            config_path=Path(args.config),
            log_level=args.log_level,
        )
        rsync_manager.run()
        sys.exit(0)

    except ConfigurationError:
        logger.exception("Configuration error")
        sys.exit(1)
    except LockAlreadyTakenError:
        logger.exception("Lock error")
        sys.exit(1)
    except Exception:
        logger.exception("Unexpected error")
        sys.exit(1)


if __name__ == "__main__":
    main()

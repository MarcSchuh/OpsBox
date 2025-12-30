"""Rsync backup manager with SSH support and retry logic."""

import argparse
import os
import subprocess
import sys
import tempfile
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from opsbox.backup.exceptions import (
    ConfigurationError,
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
    rsync_options: dict[str, Any] = field(default_factory=dict)
    default_user: str = field(default_factory=lambda: os.getlogin())

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

        # Setup lock file
        self.lock_file_path = self.temp_dir / f"{self.script_name}.lock"

        # Setup log file path
        if self.config.log_file:
            self.log_file_path = Path(self.config.log_file)
            self.log_file_path.parent.mkdir(parents=True, exist_ok=True)
        else:
            self.log_file_path = self.temp_dir / f"{self.script_name}.log"

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
                default_user=config_data.get("default_user", os.getlogin()),
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
        self.logger.info(f"Checking network connectivity to {host}")
        self.network_checker.check_network_connectivity_or_raise(host)

        # Check SSH key if configured
        if self.config.ssh_key and self.config.ssh_user:
            self.logger.info("Ensuring SSH key is loaded")
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

        # Add log file
        cmd.extend(["--log-file", str(self.log_file_path)])

        # Add source and destination
        cmd.append(self.config.rsync_source)
        cmd.append(self.config.rsync_target)

        return cmd

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
        self.logger.warning(
            f"Rsync failed with exit code {result.returncode}. "
            f"Stderr: {result.stderr[:500] if result.stderr else 'None'}",
        )

    def _execute_rsync(self) -> None:
        """Execute rsync with retry logic.

        Returns:
            True if rsync succeeded, False otherwise

        """
        self.logger.info("Starting rsync operation")

        cmd = self._build_rsync_command()

        # Retry loop
        success = False
        for attempt in range(1, self.config.rsync_retry_max + 1):
            self.logger.info(f"Rsync attempt {attempt}/{self.config.rsync_retry_max}")

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

        if not success:
            error_msg = f"Rsync failed after {self.config.rsync_retry_max} attempts"
            self.logger.error(error_msg)
            self.encrypted_mail.send_mail_with_retries(
                subject=f"Rsync backup failed after {self.config.rsync_retry_max} attempts",
                message=f"Script {self.script_name} encountered an rsync error after {self.config.rsync_retry_max} attempts. See attached log.",
                mail_attachment=str(self.log_file_path),
            )
            raise RsyncError(error_msg)

    def run(self) -> None:
        """Execute the complete rsync workflow with proper error handling."""
        with self.lock_manager:
            try:
                self.logger.info("Starting rsync backup workflow")

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
                        subject="Rsync server connection failed",
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
                        subject="Rsync backup critical error",
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

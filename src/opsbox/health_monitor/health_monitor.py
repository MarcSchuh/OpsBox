"""Health monitoring functionality for checking conditions and executing remediation."""

import argparse
import hashlib
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path

import yaml

from opsbox.encrypted_mail import EncryptedMail
from opsbox.locking import LockManager
from opsbox.logging import LoggingConfig, configure_logging


@dataclass
class CheckResult:
    """Result of a health check command execution."""

    condition_passes: bool
    output: str


@dataclass
class RemediationResult:
    """Result of a remediation command execution."""

    success: bool
    stdout: str | None
    stderr: str | None


@dataclass
class HealthMonitorConfig:
    """Configuration for health monitoring operations."""

    email_settings_path: Path
    warning_title: str
    check_command: list[str]
    remediation_command: list[str] | None = None
    log_file: str | None = None
    min_output_lines: int = 1
    expected_output_contains: str | None = None
    invert_check: bool = False

    def __post_init__(self) -> None:
        """Validate configuration after initialization."""
        if not self.email_settings_path or not str(self.email_settings_path).strip():
            error_msg = "Required field 'email_settings_path' cannot be empty"
            raise ValueError(error_msg)
        if not self.warning_title or not str(self.warning_title).strip():
            error_msg = "Required field 'warning_title' cannot be empty"
            raise ValueError(error_msg)
        if not self.check_command:
            error_msg = "Required field 'check_command' cannot be empty"
            raise ValueError(error_msg)
        if not self.email_settings_path.exists():
            error_msg = f"Email settings file not found: {self.email_settings_path}"
            raise ValueError(error_msg)
        if self.min_output_lines < 0:
            error_msg = "min_output_lines must be non-negative"
            raise ValueError(error_msg)
        if self.expected_output_contains is not None and self.invert_check:
            error_msg = "expected_output_contains and invert_check cannot both be set"
            raise ValueError(error_msg)


class HealthMonitor:
    """Monitors health conditions and executes remediation when conditions fail."""

    def __init__(
        self,
        config_path: Path,
        log_level: str = "INFO",
    ) -> None:
        """Initialize the health monitor.

        Args:
            config_path: Path to configuration YAML file
            log_level: Logging level (defaults to INFO)

        Raises:
            ValueError: If configuration cannot be loaded or is invalid

        """
        # Store config path for hashing
        self.config_path = config_path

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

        # Create hash of config file path to allow parallel runs with different configs
        config_hash = hashlib.sha256(str(config_path).encode()).hexdigest()[:8]

        # Setup lock file
        self.lock_file_path = self.temp_dir / f"{self.script_name}.{config_hash}.lock"

        # Setup state file to track if we've already handled a failure
        self.state_file_path = self.temp_dir / f"{self.script_name}.{config_hash}.state"

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

        self.logger.info("Health monitor initialized successfully")

    @staticmethod
    def _load_config(config_path: Path) -> HealthMonitorConfig:
        """Load and validate configuration from YAML file.

        Args:
            config_path: Path to the configuration YAML file

        Returns:
            Validated HealthMonitorConfig instance

        Raises:
            ValueError: If configuration file cannot be loaded or is invalid

        """
        try:
            with config_path.open(encoding="utf-8") as f:
                config_data = yaml.safe_load(f)
        except FileNotFoundError as e:
            error_msg = f"Configuration file not found: {config_path}"
            raise ValueError(error_msg) from e
        except yaml.YAMLError as e:
            error_msg = f"Invalid configuration file format: {e}"
            raise ValueError(error_msg) from e
        except Exception as e:
            error_msg = f"Error loading configuration: {e}"
            raise ValueError(error_msg) from e

        try:
            return HealthMonitorConfig(
                email_settings_path=Path(config_data["email_settings_path"]),
                warning_title=config_data["warning_title"],
                check_command=config_data["check_command"],
                remediation_command=config_data.get("remediation_command"),
                log_file=config_data.get("log_file"),
                min_output_lines=int(config_data.get("min_output_lines", 1)),
                expected_output_contains=config_data.get("expected_output_contains"),
                invert_check=bool(config_data.get("invert_check", False)),
            )
        except KeyError as e:
            error_msg = f"Missing required configuration field: {e}"
            raise ValueError(error_msg) from e
        except Exception as e:
            error_msg = f"Configuration validation failed: {e}"
            raise ValueError(error_msg) from e

    def _read_state(self) -> bool:
        """Read the state file to check if we've already handled a failure.

        Returns:
            True if we've already handled a failure, False otherwise

        """
        if not self.state_file_path.exists():
            return False
        try:
            content = self.state_file_path.read_text(encoding="utf-8").strip()
        except (OSError, PermissionError) as e:
            self.logger.warning(f"Error reading state file: {e}")
            return False
        else:
            return content == "failure_handled"

    def _write_state(self, handled: bool) -> None:
        """Write the state file to track if we've handled a failure.

        Args:
            handled: True if we've handled a failure, False otherwise

        """
        try:
            if handled:
                self.state_file_path.write_text("failure_handled", encoding="utf-8")
            elif self.state_file_path.exists():
                self.state_file_path.unlink()
        except (OSError, PermissionError) as e:
            self.logger.warning(f"Error writing state file: {e}")

    def _execute_check_command(self) -> CheckResult:
        """Execute the check command and determine if condition passes.

        Returns:
            CheckResult with condition_passes (True if condition is satisfied) and output.

        """
        self.logger.info(
            f"Executing check command: {' '.join(self.config.check_command)}",
        )

        try:
            result = subprocess.run(  # noqa: S603
                self.config.check_command,
                check=False,
                capture_output=True,
                text=True,
                timeout=300,  # 5 minute timeout
            )

            output = result.stdout.strip()
            stderr = result.stderr.strip()

            # Log the output
            if output:
                self.logger.debug(f"Check command stdout: {output}")
            if stderr:
                self.logger.debug(f"Check command stderr: {stderr}")

            # Determine if condition passes
            condition_passes = False

            if self.config.invert_check:
                # Invert: condition passes if command fails
                condition_passes = result.returncode != 0
            elif self.config.expected_output_contains:
                # Check if output contains expected text
                condition_passes = self.config.expected_output_contains in output
            else:
                # Check if output has enough lines
                output_lines = [line for line in output.split("\n") if line.strip()]
                condition_passes = len(output_lines) >= self.config.min_output_lines

            if condition_passes:
                self.logger.info("Condition check passed")
            else:
                self.logger.warning("Condition check failed")

            return CheckResult(condition_passes=condition_passes, output=output)

        except subprocess.TimeoutExpired:
            error_msg = "Check command timed out after 300 seconds"
            self.logger.exception(error_msg)
            return CheckResult(condition_passes=False, output=error_msg)
        except Exception as e:
            error_msg = f"Error executing check command: {e}"
            self.logger.exception(error_msg)
            return CheckResult(condition_passes=False, output=error_msg)

    def _execute_remediation_command(self) -> RemediationResult:
        """Execute the remediation command if configured.

        Returns:
            RemediationResult with success (True if command succeeded), stdout, and stderr.

        Raises:
            subprocess.CalledProcessError: If remediation command fails
            subprocess.TimeoutExpired: If remediation command times out

        """
        if not self.config.remediation_command:
            self.logger.info("No remediation command configured, skipping")
            return RemediationResult(success=True, stdout=None, stderr=None)

        self.logger.info(
            f"Executing remediation command: {' '.join(self.config.remediation_command)}",
        )

        try:
            result = subprocess.run(  # noqa: S603
                self.config.remediation_command,
                check=True,
                capture_output=True,
                text=True,
                timeout=300,  # 5 minute timeout
            )

            stdout = result.stdout.strip() if result.stdout else None
            stderr = result.stderr.strip() if result.stderr else None

            if stdout:
                self.logger.info(f"Remediation command output: {stdout}")
            if stderr:
                self.logger.warning(f"Remediation command stderr: {stderr}")

            self.logger.info("Remediation command executed successfully")
        except subprocess.CalledProcessError as e:
            error_msg = f"Remediation command failed with exit code {e.returncode}"
            self.logger.exception(error_msg)
            stderr = e.stderr.strip() if e.stderr else None
            if stderr:
                self.logger.exception(f"Stderr: {stderr}")
            raise
        except subprocess.TimeoutExpired:
            error_msg = "Remediation command timed out after 300 seconds"
            self.logger.exception(error_msg)
            raise
        except Exception as e:
            error_msg = f"Error executing remediation command: {e}"
            self.logger.exception(error_msg)
            raise
        else:
            return RemediationResult(success=True, stdout=stdout, stderr=stderr)

    def _send_warning_email(self, check_output: str) -> None:
        """Send warning email when condition fails.

        Args:
            check_output: Output from the check command

        """
        message_lines = [
            f"Health check failed for: {self.config.warning_title}",
            "",
            "Check Command:",
            f"  {' '.join(self.config.check_command)}",
            "",
            "Check Output:",
            check_output if check_output else "(no output)",
            "",
        ]

        if self.config.remediation_command:
            message_lines.extend(
                [
                    "",
                    "Remediation Command (will be executed):",
                    f"  {' '.join(self.config.remediation_command)}",
                ],
            )

        message = "\n".join(message_lines)

        try:
            self.encrypted_mail.send_mail_with_retries(
                subject=f"Error Health Check: {self.config.warning_title}",
                message=message,
            )
            self.logger.info("Warning email sent successfully")
        except Exception:
            self.logger.exception("Failed to send warning email")

    def _send_recovery_email(self, check_output: str) -> None:
        """Send email when condition recovers from failure state.

        Args:
            check_output: Output from the check command

        """
        message_lines = [
            f"Health check recovered for: {self.config.warning_title}",
            "",
            "The condition that previously failed is now healthy again.",
            "",
            "Check Command:",
            f"  {' '.join(self.config.check_command)}",
            "",
            "Check Output:",
            check_output if check_output else "(no output)",
        ]

        message = "\n".join(message_lines)

        try:
            self.encrypted_mail.send_mail_with_retries(
                subject=f"{self.config.warning_title} - Recovered",
                message=message,
            )
            self.logger.info("Recovery email sent successfully")
        except Exception:
            self.logger.exception("Failed to send recovery email")

    def _send_remediation_success_email(
        self,
        remediation_output: str | None = None,
    ) -> None:
        """Send email when remediation command executes successfully.

        Args:
            remediation_output: Optional output from the remediation command

        """
        remediation_cmd = self.config.remediation_command or []
        message_lines = [
            f"Remediation command executed successfully for: {self.config.warning_title}",
            "",
            "Remediation Command:",
            f"  {' '.join(remediation_cmd)}",
        ]

        if remediation_output:
            message_lines.extend(
                [
                    "",
                    "Command Output:",
                    remediation_output,
                ],
            )

        message = "\n".join(message_lines)

        try:
            self.encrypted_mail.send_mail_with_retries(
                subject=f"{self.config.warning_title} - Remediation Successful",
                message=message,
            )
            self.logger.info("Remediation success email sent successfully")
        except Exception:
            self.logger.exception("Failed to send remediation success email")

    def _send_remediation_failure_email(
        self,
        error_message: str,
        remediation_stderr: str | None = None,
    ) -> None:
        """Send email when remediation command fails.

        Args:
            error_message: Error message describing the failure
            remediation_stderr: Optional stderr output from the remediation command

        """
        remediation_cmd = self.config.remediation_command or []
        message_lines = [
            f"Remediation command failed for: {self.config.warning_title}",
            "",
            "Error:",
            error_message,
            "",
            "Remediation Command:",
            f"  {' '.join(remediation_cmd)}",
        ]

        if remediation_stderr:
            message_lines.extend(
                [
                    "",
                    "Command Stderr:",
                    remediation_stderr,
                ],
            )

        message = "\n".join(message_lines)

        try:
            self.encrypted_mail.send_mail_with_retries(
                subject=f"Error: {self.config.warning_title} - Remediation Failed",
                message=message,
            )
            self.logger.info("Remediation failure email sent successfully")
        except Exception:
            self.logger.exception("Failed to send remediation failure email")

    def run(self) -> None:
        """Execute the health monitoring workflow."""
        with self.lock_manager:
            try:
                self.logger.info("Starting health check")

                # Execute check command
                check_result = self._execute_check_command()

                if check_result.condition_passes:
                    # Condition is healthy
                    was_handling_failure = self._read_state()
                    if was_handling_failure:
                        self.logger.info(
                            "Condition recovered - was previously in failure state",
                        )
                        # Send recovery email
                        self._send_recovery_email(check_result.output)
                        self._write_state(handled=False)
                    else:
                        self.logger.info("Condition is healthy")
                    return

                # Condition failed
                self.logger.warning("Condition check failed")

                # Check if we've already handled this failure
                already_handled = self._read_state()
                if already_handled:
                    self.logger.info(
                        "Failure already handled - skipping email and remediation",
                    )
                    return

                # Handle the failure: send email and execute remediation
                self.logger.info(
                    "Handling failure: sending email and executing remediation",
                )

                # Send warning email
                self._send_warning_email(check_result.output)

                # Execute remediation command
                try:
                    remediation_result = self._execute_remediation_command()
                    if remediation_result.success:
                        # Send success email
                        self._send_remediation_success_email(remediation_result.stdout)
                except subprocess.CalledProcessError as e:
                    error_msg = (
                        f"Remediation command failed with exit code {e.returncode}"
                    )
                    stderr = e.stderr.strip() if e.stderr else None
                    self.logger.exception(f"Remediation command failed: {error_msg}")
                    # Send failure email
                    self._send_remediation_failure_email(error_msg, stderr)
                    # Still mark as handled to avoid spamming
                except subprocess.TimeoutExpired:
                    error_msg = "Remediation command timed out after 300 seconds"
                    self.logger.exception(error_msg)
                    # Send failure email
                    self._send_remediation_failure_email(error_msg, None)
                    # Still mark as handled to avoid spamming
                except Exception as e:
                    error_msg = f"Error executing remediation command: {e}"
                    self.logger.exception(error_msg)
                    # Send failure email
                    self._send_remediation_failure_email(error_msg, None)
                    # Still mark as handled to avoid spamming

                # Mark that we've handled this failure
                self._write_state(handled=True)

            except Exception as e:
                self.logger.exception("Unexpected error in health monitoring workflow")
                try:
                    self.encrypted_mail.send_mail_with_retries(
                        subject=f"Critical Error: {self.config.warning_title}",
                        message=f"Health monitor encountered an unexpected error: {type(e).__name__}: {e}",
                    )
                except Exception:
                    self.logger.exception("Failed to send error notification email")
                raise


def main() -> None:
    """Execute the main entry point for the health monitor script."""
    parser = argparse.ArgumentParser(
        description="Health monitoring with condition checking and remediation",
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
        LoggingConfig(log_name="health_monitor", log_level=args.log_level),
    )

    try:
        health_monitor = HealthMonitor(
            config_path=Path(args.config),
            log_level=args.log_level,
        )
        health_monitor.run()
        sys.exit(0)

    except ValueError:
        logger.exception("Configuration error")
        sys.exit(1)
    except Exception:
        logger.exception("Unexpected error")
        sys.exit(1)


if __name__ == "__main__":
    main()

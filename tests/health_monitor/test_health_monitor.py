"""Tests for the HealthMonitor class."""

import subprocess
import tempfile
from pathlib import Path
from unittest.mock import patch

import pytest
import yaml

from opsbox.health_monitor.health_monitor import (
    CheckResult,
    HealthMonitor,
    RemediationResult,
)


class TestHealthMonitorInitialization:
    """Test cases for HealthMonitor initialization."""

    def _create_test_config_file(
        self,
        temp_dir: Path,
        email_settings_path: Path,
    ) -> Path:
        """Create a test configuration file."""
        config_file = temp_dir / "config.yaml"
        config_data = {
            "email_settings_path": str(email_settings_path),
            "warning_title": "Test Warning",
            "check_command": ["echo", "test"],
        }
        config_file.write_text(yaml.dump(config_data))
        return config_file

    def _create_test_email_settings(self, temp_dir: Path) -> Path:
        """Create a test email settings file."""
        email_settings = temp_dir / "email_settings.yaml"
        email_settings_data = {
            "sender": "test@example.com",
            "recipient": "admin@example.com",
            "password_lookup_1": "email",
            "password_lookup_2": "password",
            "host": "smtp.example.com",
            "port": 587,
            "user": "test@example.com",
            "security": "starttls",
            "gpg_key_id": "test_key_id",
            "default_user": "testuser",
            "password": None,
        }
        email_settings.write_text(yaml.dump(email_settings_data))
        return email_settings

    def test_initialization_success(self) -> None:
        """Test successful initialization."""
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)
            email_settings = self._create_test_email_settings(temp_path)
            config_file = self._create_test_config_file(temp_path, email_settings)

            monitor = HealthMonitor(config_path=config_file, log_level="INFO")

            assert monitor.config_path == config_file
            assert monitor.config.warning_title == "Test Warning"
            assert monitor.config.check_command == ["echo", "test"]
            assert monitor.logger is not None

    def test_initialization_with_missing_config_file(self) -> None:
        """Test initialization fails when config file doesn't exist."""
        with pytest.raises(ValueError, match="not found"):
            HealthMonitor(config_path=Path("/nonexistent/config.yaml"))

    def test_initialization_with_invalid_yaml(self) -> None:
        """Test initialization fails with invalid YAML."""
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)
            config_file = temp_path / "config.yaml"
            config_file.write_text("invalid: yaml: content: [unclosed")

            with pytest.raises(ValueError, match="Invalid configuration"):
                HealthMonitor(config_path=config_file)

    def test_initialization_with_missing_required_field(self) -> None:
        """Test initialization fails when required field is missing."""
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)
            config_file = temp_path / "config.yaml"
            config_data = {
                "warning_title": "Test Warning",
                # Missing email_settings_path and check_command
            }
            config_file.write_text(yaml.dump(config_data))

            with pytest.raises(
                ValueError,
                match="Missing required configuration field",
            ):
                HealthMonitor(config_path=config_file)


class TestCheckResult:
    """Test cases for CheckResult dataclass."""

    def test_check_result_creation(self) -> None:
        """Test CheckResult creation."""
        result = CheckResult(condition_passes=True, output="test output")

        assert result.condition_passes is True
        assert result.output == "test output"

    def test_check_result_failure(self) -> None:
        """Test CheckResult with failure."""
        result = CheckResult(condition_passes=False, output="error output")

        assert result.condition_passes is False
        assert result.output == "error output"


class TestRemediationResult:
    """Test cases for RemediationResult dataclass."""

    def test_remediation_result_success(self) -> None:
        """Test RemediationResult with success."""
        result = RemediationResult(success=True, stdout="output", stderr=None)

        assert result.success is True
        assert result.stdout == "output"
        assert result.stderr is None

    def test_remediation_result_failure(self) -> None:
        """Test RemediationResult with failure."""
        result = RemediationResult(success=False, stdout=None, stderr="error")

        assert result.success is False
        assert result.stdout is None
        assert result.stderr == "error"


class TestHealthMonitorStateManagement:
    """Test cases for state file management."""

    def _create_test_email_settings(self, temp_dir: Path) -> Path:
        """Create a test email settings file."""
        email_settings = temp_dir / "email_settings.yaml"
        email_settings_data = {
            "sender": "test@example.com",
            "recipient": "admin@example.com",
            "password_lookup_1": "email",
            "password_lookup_2": "password",
            "host": "smtp.example.com",
            "port": 587,
            "user": "test@example.com",
            "security": "starttls",
            "gpg_key_id": "test_key_id",
            "default_user": "testuser",
            "password": None,
        }
        email_settings.write_text(yaml.dump(email_settings_data))
        return email_settings

    def _create_test_monitor(self, temp_dir: Path) -> HealthMonitor:
        """Create a test HealthMonitor instance."""
        email_settings = self._create_test_email_settings(temp_dir)

        config_file = temp_dir / "config.yaml"
        config_data = {
            "email_settings_path": str(email_settings),
            "warning_title": "Test Warning",
            "check_command": ["echo", "test"],
        }
        config_file.write_text(yaml.dump(config_data))

        return HealthMonitor(config_path=config_file, log_level="DEBUG")

    def test_read_state_file_not_exists(self) -> None:
        """Test reading state when file doesn't exist."""
        with tempfile.TemporaryDirectory() as temp_dir:
            monitor = self._create_test_monitor(Path(temp_dir))

            result = monitor._read_state()

            assert result is False

    def test_read_state_file_exists(self) -> None:
        """Test reading state when file exists."""
        with tempfile.TemporaryDirectory() as temp_dir:
            monitor = self._create_test_monitor(Path(temp_dir))
            monitor.state_file_path.write_text("failure_handled", encoding="utf-8")

            result = monitor._read_state()

            assert result is True

    def test_write_state_handled(self) -> None:
        """Test writing state as handled."""
        with tempfile.TemporaryDirectory() as temp_dir:
            monitor = self._create_test_monitor(Path(temp_dir))

            monitor._write_state(handled=True)

            assert monitor.state_file_path.exists()
            assert (
                monitor.state_file_path.read_text(encoding="utf-8") == "failure_handled"
            )

    def test_write_state_not_handled(self) -> None:
        """Test writing state as not handled."""
        with tempfile.TemporaryDirectory() as temp_dir:
            monitor = self._create_test_monitor(Path(temp_dir))
            monitor.state_file_path.write_text("failure_handled", encoding="utf-8")

            monitor._write_state(handled=False)

            assert not monitor.state_file_path.exists()


class TestHealthMonitorCheckCommand:
    """Test cases for check command execution."""

    def _create_test_email_settings(self, temp_dir: Path) -> Path:
        """Create a test email settings file."""
        email_settings = temp_dir / "email_settings.yaml"
        email_settings_data = {
            "sender": "test@example.com",
            "recipient": "admin@example.com",
            "password_lookup_1": "email",
            "password_lookup_2": "password",
            "host": "smtp.example.com",
            "port": 587,
            "user": "test@example.com",
            "security": "starttls",
            "gpg_key_id": "test_key_id",
            "default_user": "testuser",
            "password": None,
        }
        email_settings.write_text(yaml.dump(email_settings_data))
        return email_settings

    def _create_test_monitor(self, temp_dir: Path) -> HealthMonitor:
        """Create a test HealthMonitor instance."""
        email_settings = self._create_test_email_settings(temp_dir)

        config_file = temp_dir / "config.yaml"
        config_data = {
            "email_settings_path": str(email_settings),
            "warning_title": "Test Warning",
            "check_command": ["echo", "test output"],
            "min_output_lines": 1,
        }
        config_file.write_text(yaml.dump(config_data))

        return HealthMonitor(config_path=config_file, log_level="DEBUG")

    def test_execute_check_command_success(self) -> None:
        """Test successful check command execution."""
        with tempfile.TemporaryDirectory() as temp_dir:
            monitor = self._create_test_monitor(Path(temp_dir))

            result = monitor._execute_check_command()

            assert result.condition_passes is True
            assert "test output" in result.output

    def test_execute_check_command_failure_insufficient_lines(self) -> None:
        """Test check command failure due to insufficient output lines."""
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)
            email_settings = self._create_test_email_settings(temp_path)

            config_file = temp_path / "config.yaml"
            config_data = {
                "email_settings_path": str(email_settings),
                "warning_title": "Test Warning",
                "check_command": ["echo"],  # Empty output
                "min_output_lines": 2,  # Requires 2 lines
            }
            config_file.write_text(yaml.dump(config_data))

            monitor = HealthMonitor(config_path=config_file, log_level="DEBUG")

            result = monitor._execute_check_command()

            assert result.condition_passes is False

    def test_execute_check_command_with_expected_output_contains(self) -> None:
        """Test check command with expected_output_contains."""
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)
            email_settings = self._create_test_email_settings(temp_path)

            config_file = temp_path / "config.yaml"
            config_data = {
                "email_settings_path": str(email_settings),
                "warning_title": "Test Warning",
                "check_command": ["echo", "test output"],
                "expected_output_contains": "test",
            }
            config_file.write_text(yaml.dump(config_data))

            monitor = HealthMonitor(config_path=config_file, log_level="DEBUG")

            result = monitor._execute_check_command()

            assert result.condition_passes is True

    def test_execute_check_command_with_invert_check(self) -> None:
        """Test check command with invert_check enabled."""
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)
            email_settings = self._create_test_email_settings(temp_path)

            config_file = temp_path / "config.yaml"
            config_data = {
                "email_settings_path": str(email_settings),
                "warning_title": "Test Warning",
                "check_command": ["false"],  # Command that fails
                "invert_check": True,
            }
            config_file.write_text(yaml.dump(config_data))

            monitor = HealthMonitor(config_path=config_file, log_level="DEBUG")

            result = monitor._execute_check_command()

            # With invert_check, command failure means condition passes
            assert result.condition_passes is True

    def test_execute_check_command_timeout(self) -> None:
        """Test check command timeout handling."""
        with tempfile.TemporaryDirectory() as temp_dir:
            monitor = self._create_test_monitor(Path(temp_dir))

            with patch(
                "opsbox.health_monitor.health_monitor.subprocess.run",
            ) as mock_run:
                mock_run.side_effect = subprocess.TimeoutExpired(
                    cmd=["echo"],
                    timeout=300,
                )

                result = monitor._execute_check_command()

                assert result.condition_passes is False
                assert "timed out" in result.output


class TestHealthMonitorRemediationCommand:
    """Test cases for remediation command execution."""

    def _create_test_email_settings(self, temp_dir: Path) -> Path:
        """Create a test email settings file."""
        email_settings = temp_dir / "email_settings.yaml"
        email_settings_data = {
            "sender": "test@example.com",
            "recipient": "admin@example.com",
            "password_lookup_1": "email",
            "password_lookup_2": "password",
            "host": "smtp.example.com",
            "port": 587,
            "user": "test@example.com",
            "security": "starttls",
            "gpg_key_id": "test_key_id",
            "default_user": "testuser",
            "password": None,
        }
        email_settings.write_text(yaml.dump(email_settings_data))
        return email_settings

    def _create_test_monitor(self, temp_dir: Path) -> HealthMonitor:
        """Create a test HealthMonitor instance."""
        email_settings = self._create_test_email_settings(temp_dir)

        config_file = temp_dir / "config.yaml"
        config_data = {
            "email_settings_path": str(email_settings),
            "warning_title": "Test Warning",
            "check_command": ["echo", "test"],
            "remediation_command": ["echo", "remediation"],
        }
        config_file.write_text(yaml.dump(config_data))

        return HealthMonitor(config_path=config_file, log_level="DEBUG")

    def test_execute_remediation_command_success(self) -> None:
        """Test successful remediation command execution."""
        with tempfile.TemporaryDirectory() as temp_dir:
            monitor = self._create_test_monitor(Path(temp_dir))

            result = monitor._execute_remediation_command()

            assert result.success is True
            assert result.stdout is not None
            assert "remediation" in result.stdout

    def test_execute_remediation_command_no_command(self) -> None:
        """Test remediation when no command is configured."""
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)
            email_settings = self._create_test_email_settings(temp_path)

            config_file = temp_path / "config.yaml"
            config_data = {
                "email_settings_path": str(email_settings),
                "warning_title": "Test Warning",
                "check_command": ["echo", "test"],
                # No remediation_command
            }
            config_file.write_text(yaml.dump(config_data))

            monitor = HealthMonitor(config_path=config_file, log_level="DEBUG")

            result = monitor._execute_remediation_command()

            assert result.success is True
            assert result.stdout is None
            assert result.stderr is None

    def test_execute_remediation_command_failure(self) -> None:
        """Test remediation command failure."""
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)
            email_settings = self._create_test_email_settings(temp_path)

            config_file = temp_path / "config.yaml"
            config_data = {
                "email_settings_path": str(email_settings),
                "warning_title": "Test Warning",
                "check_command": ["echo", "test"],
                "remediation_command": ["false"],  # Command that fails
            }
            config_file.write_text(yaml.dump(config_data))

            monitor = HealthMonitor(config_path=config_file, log_level="DEBUG")

            with pytest.raises(subprocess.CalledProcessError):
                monitor._execute_remediation_command()


class TestHealthMonitorEmailNotifications:
    """Test cases for email notification methods."""

    def _create_test_email_settings(self, temp_dir: Path) -> Path:
        """Create a test email settings file."""
        email_settings = temp_dir / "email_settings.yaml"
        email_settings_data = {
            "sender": "test@example.com",
            "recipient": "admin@example.com",
            "password_lookup_1": "email",
            "password_lookup_2": "password",
            "host": "smtp.example.com",
            "port": 587,
            "user": "test@example.com",
            "security": "starttls",
            "gpg_key_id": "test_key_id",
            "default_user": "testuser",
            "password": None,
        }
        email_settings.write_text(yaml.dump(email_settings_data))
        return email_settings

    def _create_test_monitor(self, temp_dir: Path) -> HealthMonitor:
        """Create a test HealthMonitor instance."""
        email_settings = self._create_test_email_settings(temp_dir)

        config_file = temp_dir / "config.yaml"
        config_data = {
            "email_settings_path": str(email_settings),
            "warning_title": "Test Warning",
            "check_command": ["echo", "test"],
        }
        config_file.write_text(yaml.dump(config_data))

        return HealthMonitor(config_path=config_file, log_level="DEBUG")

    def test_send_warning_email(self) -> None:
        """Test sending warning email."""
        with tempfile.TemporaryDirectory() as temp_dir:
            monitor = self._create_test_monitor(Path(temp_dir))

            with patch.object(
                monitor.encrypted_mail,
                "send_mail_with_retries",
            ) as mock_send:
                monitor._send_warning_email("test output")

                mock_send.assert_called_once()
                call_args = mock_send.call_args
                assert "Error Health Check" in call_args.kwargs["subject"]
                assert "test output" in call_args.kwargs["message"]

    def test_send_recovery_email(self) -> None:
        """Test sending recovery email."""
        with tempfile.TemporaryDirectory() as temp_dir:
            monitor = self._create_test_monitor(Path(temp_dir))

            with patch.object(
                monitor.encrypted_mail,
                "send_mail_with_retries",
            ) as mock_send:
                monitor._send_recovery_email("test output")

                mock_send.assert_called_once()
                call_args = mock_send.call_args
                assert "Recovered" in call_args.kwargs["subject"]
                assert "test output" in call_args.kwargs["message"]

    def test_send_remediation_success_email(self) -> None:
        """Test sending remediation success email."""
        with tempfile.TemporaryDirectory() as temp_dir:
            monitor = self._create_test_monitor(Path(temp_dir))

            with patch.object(
                monitor.encrypted_mail,
                "send_mail_with_retries",
            ) as mock_send:
                monitor._send_remediation_success_email("remediation output")

                mock_send.assert_called_once()
                call_args = mock_send.call_args
                assert "Remediation Successful" in call_args.kwargs["subject"]

    def test_send_remediation_failure_email(self) -> None:
        """Test sending remediation failure email."""
        with tempfile.TemporaryDirectory() as temp_dir:
            monitor = self._create_test_monitor(Path(temp_dir))

            with patch.object(
                monitor.encrypted_mail,
                "send_mail_with_retries",
            ) as mock_send:
                monitor._send_remediation_failure_email("error message", "stderr")

                mock_send.assert_called_once()
                call_args = mock_send.call_args
                assert "Remediation Failed" in call_args.kwargs["subject"]
                assert "error message" in call_args.kwargs["message"]


class TestHealthMonitorWorkflow:
    """Test cases for the main run workflow."""

    def _create_test_email_settings(self, temp_dir: Path) -> Path:
        """Create a test email settings file."""
        email_settings = temp_dir / "email_settings.yaml"
        email_settings_data = {
            "sender": "test@example.com",
            "recipient": "admin@example.com",
            "password_lookup_1": "email",
            "password_lookup_2": "password",
            "host": "smtp.example.com",
            "port": 587,
            "user": "test@example.com",
            "security": "starttls",
            "gpg_key_id": "test_key_id",
            "default_user": "testuser",
            "password": None,
        }
        email_settings.write_text(yaml.dump(email_settings_data))
        return email_settings

    def _create_test_monitor(self, temp_dir: Path) -> HealthMonitor:
        """Create a test HealthMonitor instance."""
        email_settings = self._create_test_email_settings(temp_dir)

        config_file = temp_dir / "config.yaml"
        config_data = {
            "email_settings_path": str(email_settings),
            "warning_title": "Test Warning",
            "check_command": ["echo", "test"],
        }
        config_file.write_text(yaml.dump(config_data))

        return HealthMonitor(config_path=config_file, log_level="DEBUG")

    def test_run_condition_passes_healthy(self) -> None:
        """Test run when condition passes and was always healthy."""
        with tempfile.TemporaryDirectory() as temp_dir:
            monitor = self._create_test_monitor(Path(temp_dir))

            with patch.object(monitor, "_execute_check_command") as mock_check:
                mock_check.return_value = CheckResult(
                    condition_passes=True,
                    output="test output",
                )

                monitor.run()

                # Should not send any emails when condition is healthy
                assert not monitor.state_file_path.exists()

    def test_run_condition_passes_recovered(self) -> None:
        """Test run when condition passes after being in failure state."""
        with tempfile.TemporaryDirectory() as temp_dir:
            monitor = self._create_test_monitor(Path(temp_dir))
            monitor.state_file_path.write_text("failure_handled", encoding="utf-8")

            with (
                patch.object(monitor, "_execute_check_command") as mock_check,
                patch.object(monitor, "_send_recovery_email") as mock_recovery,
            ):
                mock_check.return_value = CheckResult(
                    condition_passes=True,
                    output="test output",
                )

                monitor.run()

                mock_recovery.assert_called_once()
                assert not monitor.state_file_path.exists()

    def test_run_condition_fails_first_time(self) -> None:
        """Test run when condition fails for the first time."""
        with tempfile.TemporaryDirectory() as temp_dir:
            monitor = self._create_test_monitor(Path(temp_dir))

            with (
                patch.object(monitor, "_execute_check_command") as mock_check,
                patch.object(monitor, "_send_warning_email") as mock_warning,
                patch.object(
                    monitor,
                    "_execute_remediation_command",
                ) as mock_remediation,
            ):
                mock_check.return_value = CheckResult(
                    condition_passes=False,
                    output="failure output",
                )
                mock_remediation.return_value = RemediationResult(
                    success=True,
                    stdout="remediation output",
                    stderr=None,
                )

                monitor.run()

                mock_warning.assert_called_once()
                mock_remediation.assert_called_once()
                assert monitor.state_file_path.exists()

    def test_run_condition_fails_already_handled(self) -> None:
        """Test run when condition fails but was already handled."""
        with tempfile.TemporaryDirectory() as temp_dir:
            monitor = self._create_test_monitor(Path(temp_dir))
            monitor.state_file_path.write_text("failure_handled", encoding="utf-8")

            with (
                patch.object(monitor, "_execute_check_command") as mock_check,
                patch.object(monitor, "_send_warning_email") as mock_warning,
            ):
                mock_check.return_value = CheckResult(
                    condition_passes=False,
                    output="failure output",
                )

                monitor.run()

                # Should not send email again if already handled
                mock_warning.assert_not_called()

    def test_run_remediation_failure(self) -> None:
        """Test run when remediation command fails."""
        with tempfile.TemporaryDirectory() as temp_dir:
            monitor = self._create_test_monitor(Path(temp_dir))

            with (
                patch.object(monitor, "_execute_check_command") as mock_check,
                patch.object(monitor, "_send_warning_email") as mock_warning,
                patch.object(
                    monitor,
                    "_execute_remediation_command",
                ) as mock_remediation,
                patch.object(
                    monitor,
                    "_send_remediation_failure_email",
                ) as mock_failure,
            ):
                mock_check.return_value = CheckResult(
                    condition_passes=False,
                    output="failure output",
                )
                mock_remediation.side_effect = subprocess.CalledProcessError(
                    returncode=1,
                    cmd=["false"],
                    stderr="error",
                )

                monitor.run()

                mock_warning.assert_called_once()
                mock_failure.assert_called_once()
                assert monitor.state_file_path.exists()

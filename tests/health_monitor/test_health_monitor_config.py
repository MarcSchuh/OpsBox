"""Tests for HealthMonitorConfig validation."""

import tempfile
from pathlib import Path

import pytest
import yaml

from opsbox.health_monitor.health_monitor import HealthMonitorConfig


class TestHealthMonitorConfigValidation:
    """Test cases for HealthMonitorConfig validation."""

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

    def test_config_valid_with_required_fields(self) -> None:
        """Test valid config with only required fields."""
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)
            email_settings = self._create_test_email_settings(temp_path)

            config = HealthMonitorConfig(
                email_settings_path=email_settings,
                warning_title="Test Warning",
                check_command=["echo", "test"],
            )

            assert config.email_settings_path == email_settings
            assert config.warning_title == "Test Warning"
            assert config.check_command == ["echo", "test"]
            assert config.remediation_command is None
            assert config.log_file is None
            assert config.min_output_lines == 1
            assert config.expected_output_contains is None
            assert config.invert_check is False

    def test_config_valid_with_all_fields(self) -> None:
        """Test valid config with all optional fields."""
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)
            email_settings = self._create_test_email_settings(temp_path)

            config = HealthMonitorConfig(
                email_settings_path=email_settings,
                warning_title="Test Warning",
                check_command=["echo", "test"],
                remediation_command=["touch", "/tmp/test"],
                log_file="/custom/log",
                min_output_lines=2,
                expected_output_contains="test",
            )

            assert config.remediation_command == ["touch", "/tmp/test"]
            assert config.log_file == "/custom/log"
            assert config.min_output_lines == 2
            assert config.expected_output_contains == "test"

    def test_config_missing_email_settings_path(self) -> None:
        """Test raises ValueError when email_settings_path is empty string."""
        # Path("") will fail the exists() check, not the empty check
        # So we need to test with a non-existent path
        with pytest.raises(ValueError, match="not found"):
            HealthMonitorConfig(
                email_settings_path=Path("/nonexistent/path.yaml"),
                warning_title="Test Warning",
                check_command=["echo", "test"],
            )

    def test_config_missing_warning_title(self) -> None:
        """Test raises ValueError when warning_title is empty."""
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)
            email_settings = self._create_test_email_settings(temp_path)

            with pytest.raises(ValueError, match="warning_title"):
                HealthMonitorConfig(
                    email_settings_path=email_settings,
                    warning_title="",
                    check_command=["echo", "test"],
                )

    def test_config_missing_check_command(self) -> None:
        """Test raises ValueError when check_command is empty."""
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)
            email_settings = self._create_test_email_settings(temp_path)

            with pytest.raises(ValueError, match="check_command"):
                HealthMonitorConfig(
                    email_settings_path=email_settings,
                    warning_title="Test Warning",
                    check_command=[],
                )

    def test_config_email_settings_file_not_found(self) -> None:
        """Test raises ValueError when email settings file doesn't exist."""
        with pytest.raises(ValueError, match="not found"):
            HealthMonitorConfig(
                email_settings_path=Path("/nonexistent/file.yaml"),
                warning_title="Test Warning",
                check_command=["echo", "test"],
            )

    def test_config_negative_min_output_lines(self) -> None:
        """Test raises ValueError when min_output_lines is negative."""
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)
            email_settings = self._create_test_email_settings(temp_path)

            with pytest.raises(ValueError, match="min_output_lines"):
                HealthMonitorConfig(
                    email_settings_path=email_settings,
                    warning_title="Test Warning",
                    check_command=["echo", "test"],
                    min_output_lines=-1,
                )

    def test_config_conflicting_options(self) -> None:
        """Test raises ValueError when expected_output_contains and invert_check are both set."""
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)
            email_settings = self._create_test_email_settings(temp_path)

            with pytest.raises(
                ValueError,
                match="expected_output_contains and invert_check",
            ):
                HealthMonitorConfig(
                    email_settings_path=email_settings,
                    warning_title="Test Warning",
                    check_command=["echo", "test"],
                    expected_output_contains="test",
                    invert_check=True,
                )

    def test_config_valid_with_invert_check(self) -> None:
        """Test valid config with invert_check enabled."""
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)
            email_settings = self._create_test_email_settings(temp_path)

            config = HealthMonitorConfig(
                email_settings_path=email_settings,
                warning_title="Test Warning",
                check_command=["echo", "test"],
                invert_check=True,
            )

            assert config.invert_check is True
            assert config.expected_output_contains is None

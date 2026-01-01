"""Tests for the config_manager module."""

import getpass
import json
import tempfile
from pathlib import Path

import pytest

from opsbox.backup.config_manager import BackupConfig, ConfigManager
from opsbox.backup.exceptions import ConfigurationError, InvalidResticConfigError


class TestConfigManager:
    """Test cases for ConfigManager functionality."""

    def test_load_config_from_yaml_success(self) -> None:
        """Test loading valid YAML configuration successfully."""
        with tempfile.TemporaryDirectory() as temp_dir:
            config_file = Path(temp_dir) / "config.yaml"
            email_settings = Path(temp_dir) / "email.json"
            backup_source = Path(temp_dir) / "source"
            backup_source.mkdir()
            email_settings.touch()

            config_data = {
                "backup_source": str(backup_source),
                "excluded_files": ["*.tmp", "*.log"],
                "backup_target": "sftp:user@host:/path/to/repo",
                "password_lookup_1": "service",
                "password_lookup_2": "username",
                "email_settings_path": str(email_settings),
                "file_to_check": "important_file.txt",
            }

            config_file.write_text(
                f"backup_source: {config_data['backup_source']}\n"
                f"excluded_files:\n  - '{config_data['excluded_files'][0]}'\n  - '{config_data['excluded_files'][1]}'\n"
                f"backup_target: {config_data['backup_target']}\n"
                f"password_lookup_1: {config_data['password_lookup_1']}\n"
                f"password_lookup_2: {config_data['password_lookup_2']}\n"
                f"email_settings_path: {config_data['email_settings_path']}\n"
                f"file_to_check: {config_data['file_to_check']}\n",
            )

            config = ConfigManager.load_config(str(config_file))

            assert config.backup_source == str(backup_source)
            assert config.excluded_files == config_data["excluded_files"]
            assert config.backup_target == config_data["backup_target"]
            assert config.password_lookup_1 == config_data["password_lookup_1"]
            assert config.password_lookup_2 == config_data["password_lookup_2"]

    def test_load_config_from_json_success(self) -> None:
        """Test loading valid JSON configuration successfully."""
        with tempfile.TemporaryDirectory() as temp_dir:
            config_file = Path(temp_dir) / "config.json"
            email_settings = Path(temp_dir) / "email.json"
            backup_source = Path(temp_dir) / "source"
            backup_source.mkdir()
            email_settings.touch()

            config_data = {
                "backup_source": str(backup_source),
                "excluded_files": ["*.tmp", "*.log"],
                "backup_target": "sftp:user@host:/path/to/repo",
                "password_lookup_1": "service",
                "password_lookup_2": "username",
                "email_settings_path": str(email_settings),
                "file_to_check": "important_file.txt",
            }

            config_file.write_text(json.dumps(config_data))

            config = ConfigManager.load_config(str(config_file))

            assert config.backup_source == str(backup_source)
            assert config.excluded_files == config_data["excluded_files"]
            assert config.backup_target == config_data["backup_target"]

    def test_load_config_file_not_found(self) -> None:
        """Test that ConfigurationError is raised when config file is not found."""
        with pytest.raises(ConfigurationError, match="Configuration file not found"):
            ConfigManager.load_config("/nonexistent/config.yaml")

    def test_load_config_invalid_yaml_format(self) -> None:
        """Test that ConfigurationError is raised for invalid YAML format."""
        with tempfile.TemporaryDirectory() as temp_dir:
            config_file = Path(temp_dir) / "config.yaml"
            config_file.write_text("invalid: yaml: content: [unclosed")

            with pytest.raises(
                ConfigurationError,
                match="Invalid configuration file format",
            ):
                ConfigManager.load_config(str(config_file))

    def test_load_config_invalid_json_format(self) -> None:
        """Test that ConfigurationError is raised for invalid JSON format."""
        with tempfile.TemporaryDirectory() as temp_dir:
            config_file = Path(temp_dir) / "config.json"
            config_file.write_text('{"invalid": json}')

            with pytest.raises(
                ConfigurationError,
                match="Invalid configuration file format",
            ):
                ConfigManager.load_config(str(config_file))

    def test_load_config_missing_required_field(self) -> None:
        """Test that InvalidResticConfigError is raised for missing required fields."""
        with tempfile.TemporaryDirectory() as temp_dir:
            config_file = Path(temp_dir) / "config.yaml"
            email_settings = Path(temp_dir) / "email.json"
            backup_source = Path(temp_dir) / "source"
            backup_source.mkdir()
            email_settings.touch()

            # Missing backup_target
            config_file.write_text(
                f"backup_source: {backup_source}\n"
                f"excluded_files: []\n"
                f"password_lookup_1: service\n"
                f"password_lookup_2: username\n"
                f"email_settings_path: {email_settings}\n"
                f"file_to_check: file.txt\n",
            )

            with pytest.raises(
                InvalidResticConfigError,
                match="Missing required configuration field",
            ):
                ConfigManager.load_config(str(config_file))


class TestBackupConfig:
    """Test cases for BackupConfig validation."""

    def test_backup_config_valid_with_password_lookups(self) -> None:
        """Test that config with password lookups validates successfully."""
        with tempfile.TemporaryDirectory() as temp_dir:
            email_settings = Path(temp_dir) / "email.json"
            backup_source = Path(temp_dir) / "source"
            backup_source.mkdir()
            email_settings.touch()

            config = BackupConfig(
                backup_source=str(backup_source),
                excluded_files=["*.tmp"],
                backup_target="sftp:user@host:/repo",
                password_lookup_1="service",
                password_lookup_2="username",
                email_settings_path=str(email_settings),
                file_to_check="file.txt",
            )

            assert config.password_lookup_1 == "service"
            assert config.password_lookup_2 == "username"
            assert config.restic_password is None

    def test_backup_config_valid_with_direct_password(self) -> None:
        """Test that config with direct password validates successfully."""
        with tempfile.TemporaryDirectory() as temp_dir:
            email_settings = Path(temp_dir) / "email.json"
            backup_source = Path(temp_dir) / "source"
            backup_source.mkdir()
            email_settings.touch()

            config = BackupConfig(
                backup_source=str(backup_source),
                excluded_files=["*.tmp"],
                backup_target="sftp:user@host:/repo",
                email_settings_path=str(email_settings),
                file_to_check="file.txt",
                restic_password="direct_password_123",
            )

            assert config.restic_password == "direct_password_123"
            assert config.password_lookup_1 is None
            assert config.password_lookup_2 is None

    def test_backup_config_missing_required_field(self) -> None:
        """Test that InvalidResticConfigError is raised for missing required fields."""
        with tempfile.TemporaryDirectory() as temp_dir:
            email_settings = Path(temp_dir) / "email.json"
            backup_source = Path(temp_dir) / "source"
            backup_source.mkdir()
            email_settings.touch()

            with pytest.raises(InvalidResticConfigError, match="Required field"):
                BackupConfig(
                    backup_source=str(backup_source),
                    excluded_files=["*.tmp"],
                    backup_target="",  # Empty required field
                    password_lookup_1="service",
                    password_lookup_2="username",
                    email_settings_path=str(email_settings),
                    file_to_check="file.txt",
                )

    def test_backup_config_empty_required_field(self) -> None:
        """Test that InvalidResticConfigError is raised for empty required fields."""
        with tempfile.TemporaryDirectory() as temp_dir:
            email_settings = Path(temp_dir) / "email.json"
            backup_source = Path(temp_dir) / "source"
            backup_source.mkdir()
            email_settings.touch()

            with pytest.raises(InvalidResticConfigError, match="Required field"):
                BackupConfig(
                    backup_source="",  # Empty
                    excluded_files=["*.tmp"],
                    backup_target="sftp:user@host:/repo",
                    password_lookup_1="service",
                    password_lookup_2="username",
                    email_settings_path=str(email_settings),
                    file_to_check="file.txt",
                )

    def test_backup_config_password_configuration_logic(self) -> None:
        """Test password configuration validation logic."""
        with tempfile.TemporaryDirectory() as temp_dir:
            email_settings = Path(temp_dir) / "email.json"
            backup_source = Path(temp_dir) / "source"
            backup_source.mkdir()
            email_settings.touch()

            # Test: Neither password nor lookups provided
            # Note: The error occurs in _validate_required_fields first, before _validate_password_configuration
            with pytest.raises(
                InvalidResticConfigError,
                match="Required field 'password_lookup_1' cannot be empty",
            ):
                BackupConfig(
                    backup_source=str(backup_source),
                    excluded_files=["*.tmp"],
                    backup_target="sftp:user@host:/repo",
                    email_settings_path=str(email_settings),
                    file_to_check="file.txt",
                    password_lookup_1=None,
                    password_lookup_2=None,
                    restic_password=None,
                )

            # Test: Both password and lookups provided (should fail)
            with pytest.raises(InvalidResticConfigError, match="Cannot provide both"):
                BackupConfig(
                    backup_source=str(backup_source),
                    excluded_files=["*.tmp"],
                    backup_target="sftp:user@host:/repo",
                    email_settings_path=str(email_settings),
                    file_to_check="file.txt",
                    password_lookup_1="service",
                    password_lookup_2="username",
                    restic_password="password",
                )

    def test_backup_config_ssh_configuration_consistency(self) -> None:
        """Test SSH configuration consistency validation."""
        with tempfile.TemporaryDirectory() as temp_dir:
            email_settings = Path(temp_dir) / "email.json"
            backup_source = Path(temp_dir) / "source"
            backup_source.mkdir()
            email_settings.touch()

            # Test: ssh_key without network_host
            with pytest.raises(
                InvalidResticConfigError,
                match="If ssh_key is set, network_host must be set",
            ):
                BackupConfig(
                    backup_source=str(backup_source),
                    excluded_files=["*.tmp"],
                    backup_target="sftp:user@host:/repo",
                    password_lookup_1="service",
                    password_lookup_2="username",
                    email_settings_path=str(email_settings),
                    file_to_check="file.txt",
                    ssh_key="/path/to/key",
                    network_host=None,
                )

            # Test: network_host without ssh_key
            with pytest.raises(
                InvalidResticConfigError,
                match="If network_host is set, ssh_key must be set",
            ):
                BackupConfig(
                    backup_source=str(backup_source),
                    excluded_files=["*.tmp"],
                    backup_target="sftp:user@host:/repo",
                    password_lookup_1="service",
                    password_lookup_2="username",
                    email_settings_path=str(email_settings),
                    file_to_check="file.txt",
                    network_host="example.com",
                    ssh_key=None,
                )

    def test_backup_config_ssh_user_required_with_ssh_key(self) -> None:
        """Test that ssh_user is required when ssh_key is set."""
        with tempfile.TemporaryDirectory() as temp_dir:
            email_settings = Path(temp_dir) / "email.json"
            backup_source = Path(temp_dir) / "source"
            backup_source.mkdir()
            email_settings.touch()

            with pytest.raises(
                InvalidResticConfigError,
                match="If ssh_key is set, ssh_user must be set",
            ):
                BackupConfig(
                    backup_source=str(backup_source),
                    excluded_files=["*.tmp"],
                    backup_target="sftp:user@host:/repo",
                    password_lookup_1="service",
                    password_lookup_2="username",
                    email_settings_path=str(email_settings),
                    file_to_check="file.txt",
                    ssh_key="/path/to/key",
                    network_host="example.com",
                    ssh_user=None,
                )

    def test_backup_config_path_validation(self) -> None:
        """Test that path validation works correctly."""
        with tempfile.TemporaryDirectory() as temp_dir:
            backup_source = Path(temp_dir) / "source"
            backup_source.mkdir()

            # Test: email_settings_path doesn't exist
            with pytest.raises(
                InvalidResticConfigError,
                match="Email settings file not found",
            ):
                BackupConfig(
                    backup_source=str(backup_source),
                    excluded_files=["*.tmp"],
                    backup_target="sftp:user@host:/repo",
                    password_lookup_1="service",
                    password_lookup_2="username",
                    email_settings_path="/nonexistent/email.json",
                    file_to_check="file.txt",
                )

            # Test: backup_source doesn't exist
            email_settings = Path(temp_dir) / "email.json"
            email_settings.touch()

            with pytest.raises(
                InvalidResticConfigError,
                match="Backup source path does not exist",
            ):
                BackupConfig(
                    backup_source="/nonexistent/source",
                    excluded_files=["*.tmp"],
                    backup_target="sftp:user@host:/repo",
                    password_lookup_1="service",
                    password_lookup_2="username",
                    email_settings_path=str(email_settings),
                    file_to_check="file.txt",
                )

    def test_backup_config_retention_policy_validation(self) -> None:
        """Test that retention policy values are validated as numeric."""
        with tempfile.TemporaryDirectory() as temp_dir:
            email_settings = Path(temp_dir) / "email.json"
            backup_source = Path(temp_dir) / "source"
            backup_source.mkdir()
            email_settings.touch()

            # Test: Invalid retention policy (non-numeric)
            with pytest.raises(
                InvalidResticConfigError,
                match="Invalid retention policy value",
            ):
                BackupConfig(
                    backup_source=str(backup_source),
                    excluded_files=["*.tmp"],
                    backup_target="sftp:user@host:/repo",
                    password_lookup_1="service",
                    password_lookup_2="username",
                    email_settings_path=str(email_settings),
                    file_to_check="file.txt",
                    keep_last="invalid",
                )

    def test_backup_config_default_values(self) -> None:
        """Test that default values are set correctly."""
        with tempfile.TemporaryDirectory() as temp_dir:
            email_settings = Path(temp_dir) / "email.json"
            backup_source = Path(temp_dir) / "source"
            backup_source.mkdir()
            email_settings.touch()

            config = BackupConfig(
                backup_source=str(backup_source),
                excluded_files=["*.tmp"],
                backup_target="sftp:user@host:/repo",
                password_lookup_1="service",
                password_lookup_2="username",
                email_settings_path=str(email_settings),
                file_to_check="file.txt",
            )

            assert config.keep_last == "10"
            assert config.keep_daily == "21"
            assert config.keep_monthly == "5"
            assert config.ssh_key_max_retries == 12
            assert config.detailed_report is True
            assert config.default_user == getpass.getuser()

    def test_get_default_config(self) -> None:
        """Test that get_default_config returns a template configuration."""
        default_config = ConfigManager.get_default_config()

        assert "backup_source" in default_config
        assert "excluded_files" in default_config
        assert "backup_target" in default_config
        assert "email_settings_path" in default_config
        assert isinstance(default_config["excluded_files"], list)


if __name__ == "__main__":
    pytest.main([__file__])

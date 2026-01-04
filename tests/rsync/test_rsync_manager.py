"""Tests for the RsyncManager class and related functionality."""

import tempfile
from pathlib import Path
from unittest.mock import MagicMock, Mock, patch

import pytest
import yaml

from opsbox.backup.exceptions import (
    ConfigurationError,
    FolderNotFoundError,
    NetworkUnreachableError,
    SSHKeyNotFoundError,
)
from opsbox.exceptions import LockAlreadyTakenError, RsyncError
from opsbox.rsync import (
    RsyncConfig,
    RsyncManager,
)
from opsbox.rsync.rsync_manager import main


class TestRsyncConfigValidation:
    """Test cases for RsyncConfig validation."""

    def _create_test_email_settings(self, temp_dir: Path) -> Path:
        """Create a test email settings file."""
        email_settings = temp_dir / "email_settings.yaml"
        email_settings.write_text("test: settings")
        return email_settings

    def test_config_valid_with_required_fields(self) -> None:
        """Test valid config with only required fields."""
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)
            email_settings = self._create_test_email_settings(temp_path)

            config = RsyncConfig(
                rsync_source="user@host:/source",
                rsync_target="/target",
                email_settings_path=email_settings,
            )

            assert config.rsync_source == "user@host:/source"
            assert config.rsync_target == "/target"
            assert config.email_settings_path == email_settings
            assert config.rsync_retry_max == 3  # default
            assert config.rsync_retry_delay == 5  # default

    def test_config_valid_with_all_fields(self) -> None:
        """Test valid config with all optional fields."""
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)
            email_settings = self._create_test_email_settings(temp_path)

            config = RsyncConfig(
                rsync_source="user@host:/source",
                rsync_target="/target",
                email_settings_path=email_settings,
                log_file="/custom/log",
                rsync_retry_max=5,
                rsync_retry_delay=10,
                ssh_key="SHA256:test",
                ssh_user="testuser",
                network_host="host.example.com",
                rsync_options={"delete": True, "progress": True},
            )

            assert config.log_file == "/custom/log"
            assert config.rsync_retry_max == 5
            assert config.rsync_retry_delay == 10
            assert config.ssh_key == "SHA256:test"
            assert config.ssh_user == "testuser"
            assert config.network_host == "host.example.com"
            assert config.rsync_options["delete"] is True

    def test_config_missing_rsync_source(self) -> None:
        """Test raises ConfigurationError when rsync_source is empty."""
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)
            email_settings = self._create_test_email_settings(temp_path)

            with pytest.raises(ConfigurationError) as exc_info:
                RsyncConfig(
                    rsync_source="",
                    rsync_target="/target",
                    email_settings_path=email_settings,
                )

            assert "rsync_source" in str(exc_info.value)

    def test_config_missing_rsync_target(self) -> None:
        """Test raises ConfigurationError when rsync_target is empty."""
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)
            email_settings = self._create_test_email_settings(temp_path)

            with pytest.raises(ConfigurationError) as exc_info:
                RsyncConfig(
                    rsync_source="user@host:/source",
                    rsync_target="",
                    email_settings_path=email_settings,
                )

            assert "rsync_target" in str(exc_info.value)

    def test_config_missing_email_settings_path(self) -> None:
        """Test raises ConfigurationError when email_settings_path validation fails."""
        with pytest.raises(ConfigurationError) as exc_info:
            # Path validation happens in _validate_paths, not _validate_required_fields
            # So we need to pass a path that doesn't exist
            RsyncConfig(
                rsync_source="user@host:/source",
                rsync_target="/target",
                email_settings_path=Path("/nonexistent/path/to/email/settings.yaml"),
            )

        assert "Email settings file not found" in str(exc_info.value)

    def test_config_ssh_key_without_network_host(self) -> None:
        """Test raises ConfigurationError when ssh_key set without network_host."""
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)
            email_settings = self._create_test_email_settings(temp_path)

            with pytest.raises(ConfigurationError) as exc_info:
                RsyncConfig(
                    rsync_source="user@host:/source",
                    rsync_target="/target",
                    email_settings_path=email_settings,
                    ssh_key="SHA256:test",
                )

            assert "network_host must be set" in str(exc_info.value)

    def test_config_network_host_without_ssh_key(self) -> None:
        """Test raises ConfigurationError when network_host set without ssh_key."""
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)
            email_settings = self._create_test_email_settings(temp_path)

            with pytest.raises(ConfigurationError) as exc_info:
                RsyncConfig(
                    rsync_source="user@host:/source",
                    rsync_target="/target",
                    email_settings_path=email_settings,
                    network_host="host.example.com",
                )

            assert "ssh_key must be set" in str(exc_info.value)

    def test_config_ssh_key_without_ssh_user(self) -> None:
        """Test raises ConfigurationError when ssh_key set without ssh_user."""
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)
            email_settings = self._create_test_email_settings(temp_path)

            with pytest.raises(ConfigurationError) as exc_info:
                RsyncConfig(
                    rsync_source="user@host:/source",
                    rsync_target="/target",
                    email_settings_path=email_settings,
                    ssh_key="SHA256:test",
                    network_host="host.example.com",
                )

            assert "ssh_user must be set" in str(exc_info.value)

    def test_config_email_settings_path_not_exists(self) -> None:
        """Test raises ConfigurationError when email_settings_path doesn't exist."""
        with pytest.raises(ConfigurationError) as exc_info:
            RsyncConfig(
                rsync_source="user@host:/source",
                rsync_target="/target",
                email_settings_path=Path("/nonexistent/path"),
            )

        assert "Email settings file not found" in str(exc_info.value)

    def test_config_exclude_file_not_exists(self) -> None:
        """Test raises FolderNotFoundError when exclude_file doesn't exist."""
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)
            email_settings = self._create_test_email_settings(temp_path)

            with pytest.raises(FolderNotFoundError):
                RsyncConfig(
                    rsync_source="user@host:/source",
                    rsync_target="/target",
                    email_settings_path=email_settings,
                    exclude_file=Path("/nonexistent/exclude.txt"),
                )

    def test_config_exclude_file_optional(self) -> None:
        """Test that exclude_file is optional and None is valid."""
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)
            email_settings = self._create_test_email_settings(temp_path)

            config = RsyncConfig(
                rsync_source="user@host:/source",
                rsync_target="/target",
                email_settings_path=email_settings,
                exclude_file=None,
            )

            assert config.exclude_file is None

    def test_config_exclude_file_valid(self) -> None:
        """Test that exclude_file is accepted when file exists."""
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)
            email_settings = self._create_test_email_settings(temp_path)
            exclude_file = temp_path / "exclude.txt"
            exclude_file.write_text("*.tmp\n*.log\n")

            config = RsyncConfig(
                rsync_source="user@host:/source",
                rsync_target="/target",
                email_settings_path=email_settings,
                exclude_file=exclude_file,
            )

            assert config.exclude_file == exclude_file


class TestRsyncManagerInitialization:
    """Test cases for RsyncManager initialization."""

    def _create_test_config_file(
        self,
        temp_dir: Path,
        email_settings: Path,
        config_data: dict | None = None,
    ) -> Path:
        """Create a test configuration YAML file."""
        if config_data is None:
            config_data = {
                "rsync_source": "user@host:/source",
                "rsync_target": str(temp_dir / "target"),
                "email_settings_path": str(email_settings),
            }

        config_file = temp_dir / "config.yaml"
        config_file.write_text(yaml.dump(config_data))
        return config_file

    def _create_test_email_settings(self, temp_dir: Path) -> Path:
        """Create a test email settings file."""
        email_settings = temp_dir / "email_settings.yaml"
        email_settings.write_text("test: settings")
        return email_settings

    @patch("opsbox.rsync.rsync_manager.configure_logging")
    @patch("opsbox.rsync.rsync_manager.EncryptedMail")
    @patch("opsbox.rsync.rsync_manager.LockManager")
    @patch("opsbox.rsync.rsync_manager.NetworkChecker")
    @patch("opsbox.rsync.rsync_manager.SSHManager")
    def test_initialization_success(
        self,
        mock_ssh_manager: MagicMock,
        mock_network_checker: MagicMock,
        mock_lock_manager: MagicMock,
        mock_encrypted_mail: MagicMock,
        mock_configure_logging: MagicMock,
    ) -> None:
        """Test initializes successfully with valid config."""
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)
            email_settings = self._create_test_email_settings(temp_path)
            config_file = self._create_test_config_file(temp_path, email_settings)

            # Create target directory
            target_dir = temp_path / "target"
            target_dir.mkdir()

            mock_logger = Mock()
            mock_configure_logging.return_value = mock_logger

            manager = RsyncManager(config_path=config_file, log_level="INFO")

            assert manager.config.rsync_source == "user@host:/source"
            assert manager.config.rsync_target == str(target_dir)
            mock_configure_logging.assert_called_once()

    @patch("opsbox.rsync.rsync_manager.configure_logging")
    @patch("opsbox.rsync.rsync_manager.EncryptedMail")
    @patch("opsbox.rsync.rsync_manager.LockManager")
    @patch("opsbox.rsync.rsync_manager.NetworkChecker")
    @patch("opsbox.rsync.rsync_manager.SSHManager")
    def test_initialization_with_custom_log_file(
        self,
        mock_ssh_manager: MagicMock,
        mock_network_checker: MagicMock,
        mock_lock_manager: MagicMock,
        mock_encrypted_mail: MagicMock,
        mock_configure_logging: MagicMock,
    ) -> None:
        """Test uses custom log file path when provided."""
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)
            email_settings = self._create_test_email_settings(temp_path)
            log_file = temp_path / "custom.log"
            log_file.parent.mkdir(parents=True, exist_ok=True)

            config_data = {
                "rsync_source": "user@host:/source",
                "rsync_target": str(temp_path / "target"),
                "email_settings_path": str(email_settings),
                "log_file": str(log_file),
            }
            config_file = self._create_test_config_file(
                temp_path,
                email_settings,
                config_data,
            )

            target_dir = temp_path / "target"
            target_dir.mkdir()

            mock_logger = Mock()
            mock_configure_logging.return_value = mock_logger

            manager = RsyncManager(config_path=config_file, log_level="INFO")

            assert manager.log_file_path == log_file

    @patch("opsbox.rsync.rsync_manager.configure_logging")
    @patch("opsbox.rsync.rsync_manager.EncryptedMail")
    @patch("opsbox.rsync.rsync_manager.LockManager")
    @patch("opsbox.rsync.rsync_manager.NetworkChecker")
    @patch("opsbox.rsync.rsync_manager.SSHManager")
    def test_initialization_with_default_log_file(
        self,
        mock_ssh_manager: MagicMock,
        mock_network_checker: MagicMock,
        mock_lock_manager: MagicMock,
        mock_encrypted_mail: MagicMock,
        mock_configure_logging: MagicMock,
    ) -> None:
        """Test uses default log file path when not provided."""
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)
            email_settings = self._create_test_email_settings(temp_path)
            config_file = self._create_test_config_file(temp_path, email_settings)

            target_dir = temp_path / "target"
            target_dir.mkdir()

            mock_logger = Mock()
            mock_configure_logging.return_value = mock_logger

            manager = RsyncManager(config_path=config_file, log_level="INFO")

            assert manager.log_file_path.name.endswith(".log")

    def test_initialization_config_file_not_found(self) -> None:
        """Test raises ConfigurationError when config file not found."""
        with pytest.raises(ConfigurationError) as exc_info:
            RsyncManager(config_path=Path("/nonexistent/config.yaml"))

        assert "Configuration file not found" in str(exc_info.value)

    def test_initialization_invalid_yaml(self) -> None:
        """Test raises ConfigurationError when YAML is invalid."""
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)
            config_file = temp_path / "config.yaml"
            config_file.write_text("invalid: yaml: content: [unclosed")

            with pytest.raises(ConfigurationError) as exc_info:
                RsyncManager(config_path=config_file)

            assert "Invalid configuration file format" in str(exc_info.value)

    def test_initialization_missing_required_field(self) -> None:
        """Test raises ConfigurationError when required field missing."""
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)
            email_settings = self._create_test_email_settings(temp_path)

            config_data = {
                "rsync_target": str(temp_path / "target"),
                "email_settings_path": str(email_settings),
                # Missing rsync_source
            }
            config_file = self._create_test_config_file(
                temp_path,
                email_settings,
                config_data,
            )

            with pytest.raises(ConfigurationError) as exc_info:
                RsyncManager(config_path=config_file)

            assert "Missing required configuration field" in str(exc_info.value)

    @patch("opsbox.rsync.rsync_manager.configure_logging")
    @patch("opsbox.rsync.rsync_manager.EncryptedMail")
    @patch("opsbox.rsync.rsync_manager.LockManager")
    @patch("opsbox.rsync.rsync_manager.NetworkChecker")
    @patch("opsbox.rsync.rsync_manager.SSHManager")
    def test_initialization_with_exclude_file(
        self,
        mock_ssh_manager: MagicMock,
        mock_network_checker: MagicMock,
        mock_lock_manager: MagicMock,
        mock_encrypted_mail: MagicMock,
        mock_configure_logging: MagicMock,
    ) -> None:
        """Test initializes successfully with exclude_file in config."""
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)
            email_settings = self._create_test_email_settings(temp_path)
            exclude_file = temp_path / "exclude.txt"
            exclude_file.write_text("*.tmp\n*.log\n")

            config_data = {
                "rsync_source": "user@host:/source",
                "rsync_target": str(temp_path / "target"),
                "email_settings_path": str(email_settings),
                "exclude_file": str(exclude_file),
            }
            config_file = self._create_test_config_file(
                temp_path,
                email_settings,
                config_data,
            )

            target_dir = temp_path / "target"
            target_dir.mkdir()

            mock_logger = Mock()
            mock_configure_logging.return_value = mock_logger

            manager = RsyncManager(config_path=config_file, log_level="INFO")

            assert manager.config.exclude_file == exclude_file

    @patch("opsbox.rsync.rsync_manager.configure_logging")
    @patch("opsbox.rsync.rsync_manager.EncryptedMail")
    @patch("opsbox.rsync.rsync_manager.LockManager")
    @patch("opsbox.rsync.rsync_manager.NetworkChecker")
    @patch("opsbox.rsync.rsync_manager.SSHManager")
    def test_initialization_with_exclude_file_not_exists(
        self,
        mock_ssh_manager: MagicMock,
        mock_network_checker: MagicMock,
        mock_lock_manager: MagicMock,
        mock_encrypted_mail: MagicMock,
        mock_configure_logging: MagicMock,
    ) -> None:
        """Test raises FolderNotFoundError when exclude_file in config doesn't exist."""
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)
            email_settings = self._create_test_email_settings(temp_path)

            config_data = {
                "rsync_source": "user@host:/source",
                "rsync_target": str(temp_path / "target"),
                "email_settings_path": str(email_settings),
                "exclude_file": "/nonexistent/exclude.txt",
            }
            config_file = self._create_test_config_file(
                temp_path,
                email_settings,
                config_data,
            )

            target_dir = temp_path / "target"
            target_dir.mkdir()

            mock_logger = Mock()
            mock_configure_logging.return_value = mock_logger

            with pytest.raises(ConfigurationError) as exc_info:
                RsyncManager(config_path=config_file, log_level="INFO")

            assert "Exclude file not found" in str(exc_info.value)


class TestRsyncCommandBuilding:
    """Test cases for rsync command building."""

    def _create_test_manager(
        self,
        temp_dir: Path,
        config_data: dict | None = None,
    ) -> RsyncManager:
        """Create a test RsyncManager instance."""
        email_settings = temp_dir / "email_settings.yaml"
        email_settings.write_text("test: settings")

        if config_data is None:
            config_data = {
                "rsync_source": "user@host:/source",
                "rsync_target": str(temp_dir / "target"),
                "email_settings_path": str(email_settings),
            }

        config_file = temp_dir / "config.yaml"
        config_file.write_text(yaml.dump(config_data))

        target_dir = temp_dir / "target"
        target_dir.mkdir()

        with (
            patch("opsbox.rsync.rsync_manager.configure_logging") as mock_logging,
            patch(
                "opsbox.rsync.rsync_manager.EncryptedMail",
            ),
            patch("opsbox.rsync.rsync_manager.LockManager"),
            patch(
                "opsbox.rsync.rsync_manager.NetworkChecker",
            ),
            patch("opsbox.rsync.rsync_manager.SSHManager"),
        ):
            mock_logging.return_value = Mock()
            return RsyncManager(config_path=config_file, log_level="INFO")

    def test_build_rsync_command_basic(self) -> None:
        """Test builds basic rsync command correctly."""
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)
            manager = self._create_test_manager(temp_path)

            cmd = manager._build_rsync_command()

            assert cmd[0] == "/usr/bin/rsync"
            assert "-avz" in cmd
            assert "--log-file" in cmd
            assert manager.config.rsync_source in cmd
            assert manager.config.rsync_target in cmd

    def test_build_rsync_command_with_chown(self) -> None:
        """Test includes chown option when configured."""
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)
            config_data = {
                "rsync_source": "user@host:/source",
                "rsync_target": str(temp_path / "target"),
                "email_settings_path": str(temp_path / "email_settings.yaml"),
                "rsync_options": {"chown": "user:group"},
            }
            manager = self._create_test_manager(temp_path, config_data)

            cmd = manager._build_rsync_command()

            assert "--chown" in cmd
            assert "user:group" in cmd

    def test_build_rsync_command_with_delete(self) -> None:
        """Test includes delete option when configured."""
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)
            config_data = {
                "rsync_source": "user@host:/source",
                "rsync_target": str(temp_path / "target"),
                "email_settings_path": str(temp_path / "email_settings.yaml"),
                "rsync_options": {"delete": True},
            }
            manager = self._create_test_manager(temp_path, config_data)

            cmd = manager._build_rsync_command()

            assert "--delete" in cmd

    def test_build_rsync_command_with_progress(self) -> None:
        """Test includes progress option when configured."""
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)
            config_data = {
                "rsync_source": "user@host:/source",
                "rsync_target": str(temp_path / "target"),
                "email_settings_path": str(temp_path / "email_settings.yaml"),
                "rsync_options": {"progress": True},
            }
            manager = self._create_test_manager(temp_path, config_data)

            cmd = manager._build_rsync_command()

            assert "--progress" in cmd

    def test_build_rsync_command_with_log_file(self) -> None:
        """Test includes log file in command."""
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)
            manager = self._create_test_manager(temp_path)

            cmd = manager._build_rsync_command()

            log_file_index = cmd.index("--log-file")
            assert cmd[log_file_index + 1] == str(manager.log_file_path)

    def test_build_rsync_command_with_exclude_file(self) -> None:
        """Test includes exclude-from option when exclude_file is configured."""
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)
            exclude_file = temp_path / "exclude.txt"
            exclude_file.write_text("*.tmp\n*.log\n")

            config_data = {
                "rsync_source": "user@host:/source",
                "rsync_target": str(temp_path / "target"),
                "email_settings_path": str(temp_path / "email_settings.yaml"),
                "exclude_file": str(exclude_file),
            }
            manager = self._create_test_manager(temp_path, config_data)

            cmd = manager._build_rsync_command()

            assert "--exclude-from" in cmd
            exclude_index = cmd.index("--exclude-from")
            assert cmd[exclude_index + 1] == str(exclude_file)

    def test_build_rsync_command_without_exclude_file(self) -> None:
        """Test does not include exclude-from option when exclude_file is not configured."""
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)
            manager = self._create_test_manager(temp_path)

            cmd = manager._build_rsync_command()

            assert "--exclude-from" not in cmd

    def test_build_rsync_command_with_exclude_file_and_other_options(self) -> None:
        """Test exclude-from works correctly with other rsync options."""
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)
            exclude_file = temp_path / "exclude.txt"
            exclude_file.write_text("*.tmp\n*.log\n")

            config_data = {
                "rsync_source": "user@host:/source",
                "rsync_target": str(temp_path / "target"),
                "email_settings_path": str(temp_path / "email_settings.yaml"),
                "exclude_file": str(exclude_file),
                "rsync_options": {
                    "chown": "user:group",
                    "delete": True,
                    "progress": True,
                },
            }
            manager = self._create_test_manager(temp_path, config_data)

            cmd = manager._build_rsync_command()

            # Verify all options are present
            assert "--exclude-from" in cmd
            assert "--chown" in cmd
            assert "--delete" in cmd
            assert "--progress" in cmd
            # Verify exclude-from comes before log-file (as per implementation)
            exclude_index = cmd.index("--exclude-from")
            log_file_index = cmd.index("--log-file")
            assert exclude_index < log_file_index


class TestRsyncUtilityFunctions:
    """Test cases for utility functions."""

    def test_format_bytes_bytes(self) -> None:
        """Test formats bytes correctly."""
        result = RsyncManager._format_bytes(512)
        assert result == "512.00 B"

    def test_format_bytes_kb(self) -> None:
        """Test formats kilobytes correctly."""
        result = RsyncManager._format_bytes(2048)
        assert result == "2.00 KB"

    def test_format_bytes_mb(self) -> None:
        """Test formats megabytes correctly."""
        result = RsyncManager._format_bytes(2 * 1024 * 1024)
        assert result == "2.00 MB"

    def test_format_bytes_gb(self) -> None:
        """Test formats gigabytes correctly."""
        result = RsyncManager._format_bytes(2 * 1024 * 1024 * 1024)
        assert result == "2.00 GB"

    def test_format_bytes_none(self) -> None:
        """Test returns 'N/A' for None input."""
        result = RsyncManager._format_bytes(None)
        assert result == "N/A"

    def test_format_duration_seconds(self) -> None:
        """Test formats seconds correctly."""
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)
            manager = self._create_test_manager_for_utils(temp_path)
            result = manager._format_duration(30.5)
            assert result == "30.50 seconds"

    def test_format_duration_minutes(self) -> None:
        """Test formats minutes correctly."""
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)
            manager = self._create_test_manager_for_utils(temp_path)
            result = manager._format_duration(90.0)
            assert result == "1.50 minutes"

    def test_format_duration_hours(self) -> None:
        """Test formats hours correctly."""
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)
            manager = self._create_test_manager_for_utils(temp_path)
            result = manager._format_duration(7200.0)
            assert result == "2.00 hours"

    def test_parse_number_with_dots(self) -> None:
        """Test parses numbers with dot separators."""
        result = RsyncManager._parse_number_with_dots("35.821.870")
        assert result == 35821870

        result = RsyncManager._parse_number_with_dots("552313")
        assert result == 552313

        result = RsyncManager._parse_number_with_dots("1,234,567")
        assert result == 1234567

    def _create_test_manager_for_utils(
        self,
        temp_dir: Path,
    ) -> RsyncManager:  # type: ignore[valid-type]
        """Create a test manager for utility function tests."""
        email_settings = temp_dir / "email_settings.yaml"
        email_settings.write_text("test: settings")

        config_data = {
            "rsync_source": "user@host:/source",
            "rsync_target": str(temp_dir / "target"),
            "email_settings_path": str(email_settings),
        }
        config_file = temp_dir / "config.yaml"
        config_file.write_text(yaml.dump(config_data))

        target_dir = temp_dir / "target"
        target_dir.mkdir()

        with (
            patch("opsbox.rsync.rsync_manager.configure_logging") as mock_logging,
            patch(
                "opsbox.rsync.rsync_manager.EncryptedMail",
            ),
            patch("opsbox.rsync.rsync_manager.LockManager"),
            patch(
                "opsbox.rsync.rsync_manager.NetworkChecker",
            ),
            patch("opsbox.rsync.rsync_manager.SSHManager"),
        ):
            mock_logging.return_value = Mock()
            return RsyncManager(config_path=config_file, log_level="INFO")


class TestRsyncLogParsing:
    """Test cases for rsync log parsing."""

    def _create_test_manager(
        self,
        temp_dir: Path,
    ) -> RsyncManager:  # type: ignore[valid-type]
        """Create a test RsyncManager instance."""
        email_settings = temp_dir / "email_settings.yaml"
        email_settings.write_text("test: settings")

        config_data = {
            "rsync_source": "user@host:/source",
            "rsync_target": str(temp_dir / "target"),
            "email_settings_path": str(email_settings),
        }
        config_file = temp_dir / "config.yaml"
        config_file.write_text(yaml.dump(config_data))

        target_dir = temp_dir / "target"
        target_dir.mkdir()

        with (
            patch("opsbox.rsync.rsync_manager.configure_logging") as mock_logging,
            patch(
                "opsbox.rsync.rsync_manager.EncryptedMail",
            ),
            patch("opsbox.rsync.rsync_manager.LockManager"),
            patch(
                "opsbox.rsync.rsync_manager.NetworkChecker",
            ),
            patch("opsbox.rsync.rsync_manager.SSHManager"),
        ):
            mock_logging.return_value = Mock()
            return RsyncManager(config_path=config_file, log_level="INFO")

    def test_parse_rsync_log_stats_success(self) -> None:
        """Test parses statistics from log file correctly."""
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)
            manager = self._create_test_manager(temp_path)

            # Create log file with statistics
            log_content = """
            some log lines
            sent 1,234,567 bytes  received 987,654 bytes
            total size is 2,222,221
            """
            manager.log_file_path.write_text(log_content)

            stats = manager._parse_rsync_log_stats()

            assert stats.sent == 1234567
            assert stats.received == 987654
            assert stats.total_size == 2222221

    def test_parse_rsync_log_stats_missing_file(self) -> None:
        """Test returns zero stats when log file missing."""
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)
            manager = self._create_test_manager(temp_path)

            # Ensure log file doesn't exist
            if manager.log_file_path.exists():
                manager.log_file_path.unlink()

            stats = manager._parse_rsync_log_stats()

            assert stats.sent == 0
            assert stats.received == 0
            assert stats.total_size == 0

    def test_parse_rsync_log_stats_partial_data(self) -> None:
        """Test handles partial statistics in log."""
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)
            manager = self._create_test_manager(temp_path)

            # Create log file with only sent bytes
            log_content = "sent 1,234,567 bytes"
            manager.log_file_path.write_text(log_content)

            stats = manager._parse_rsync_log_stats()

            assert stats.sent == 1234567
            assert stats.received == 0
            assert stats.total_size == 0

    def test_parse_rsync_log_stats_with_dots(self) -> None:
        """Test parses numbers with dot separators correctly."""
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)
            manager = self._create_test_manager(temp_path)

            # Create log file with dot-separated numbers
            log_content = "sent 35.821.870 bytes  received 552.313 bytes"
            manager.log_file_path.write_text(log_content)

            stats = manager._parse_rsync_log_stats()

            assert stats.sent == 35821870
            assert stats.received == 552313

    def test_check_log_for_errors_found(self) -> None:
        """Test detects errors in log file."""
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)
            manager = self._create_test_manager(temp_path)

            # Create log file with error
            log_content = "some log lines\nrsync: error: connection refused\nmore lines"
            manager.log_file_path.write_text(log_content)

            has_errors = manager._check_log_for_errors()

            assert has_errors is True

    def test_check_log_for_errors_not_found(self) -> None:
        """Test returns False when no errors found."""
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)
            manager = self._create_test_manager(temp_path)

            # Create log file without errors
            log_content = "some log lines\nrsync completed successfully\nmore lines"
            manager.log_file_path.write_text(log_content)

            has_errors = manager._check_log_for_errors()

            assert has_errors is False

    def test_check_log_for_errors_missing_file(self) -> None:
        """Test returns False when log file missing."""
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)
            manager = self._create_test_manager(temp_path)

            has_errors = manager._check_log_for_errors()

            assert has_errors is False


class TestRsyncManagerWorkflow:
    """Test cases for rsync workflow execution."""

    def _create_test_manager(
        self,
        temp_dir: Path,
        config_data: dict | None = None,
    ) -> RsyncManager:
        """Create a test RsyncManager instance."""
        email_settings = temp_dir / "email_settings.yaml"
        email_settings.write_text("test: settings")

        if config_data is None:
            config_data = {
                "rsync_source": "user@host:/source",
                "rsync_target": str(temp_dir / "target"),
                "email_settings_path": str(email_settings),
            }

        config_file = temp_dir / "config.yaml"
        config_file.write_text(yaml.dump(config_data))

        target_dir = temp_dir / "target"
        target_dir.mkdir()

        with (
            patch("opsbox.rsync.rsync_manager.configure_logging") as mock_logging,
            patch(
                "opsbox.rsync.rsync_manager.EncryptedMail",
            ) as mock_mail,
            patch(
                "opsbox.rsync.rsync_manager.LockManager",
            ) as mock_lock,
            patch(
                "opsbox.rsync.rsync_manager.NetworkChecker",
            ) as mock_network,
            patch(
                "opsbox.rsync.rsync_manager.SSHManager",
            ) as mock_ssh,
        ):
            mock_logger = Mock()
            mock_logging.return_value = mock_logger

            mock_mail_instance = Mock()
            mock_mail.return_value = mock_mail_instance

            mock_lock_instance = MagicMock()
            mock_lock_instance.__enter__ = Mock(return_value=mock_lock_instance)
            mock_lock_instance.__exit__ = Mock(return_value=None)
            mock_lock.return_value = mock_lock_instance

            mock_network_instance = Mock()
            mock_network.return_value = mock_network_instance

            mock_ssh_instance = Mock()
            mock_ssh.return_value = mock_ssh_instance

            manager = RsyncManager(config_path=config_file, log_level="INFO")
            manager.encrypted_mail = mock_mail_instance
            manager.lock_manager = mock_lock_instance
            manager.network_checker = mock_network_instance
            manager.ssh_manager = mock_ssh_instance

            return manager

    @patch("opsbox.rsync.rsync_manager.subprocess.run")
    @patch("opsbox.rsync.rsync_manager.time.time")
    def test_run_success_complete_workflow(
        self,
        mock_time: MagicMock,
        mock_subprocess: MagicMock,
    ) -> None:
        """Test complete workflow executes successfully."""
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)
            manager = self._create_test_manager(temp_path)

            # Setup mocks
            mock_time.side_effect = [0, 100]  # Start and end time
            mock_result = Mock()
            mock_result.returncode = 0
            mock_subprocess.return_value = mock_result

            # Create log file with stats
            log_content = "sent 1,234 bytes  received 567 bytes\ntotal size is 1,801"
            manager.log_file_path.write_text(log_content)

            manager.run()

            # Verify rsync was called
            mock_subprocess.assert_called()
            # Verify email was sent
            manager.encrypted_mail.send_mail_with_retries.assert_called()  # type: ignore[attr-defined]

    def test_run_target_dir_not_mounted(self) -> None:
        """Test raises ConfigurationError when target dir not mounted."""
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)
            manager = self._create_test_manager(temp_path)

            # Remove target directory to simulate not mounted
            target_path = Path(manager.config.rsync_target)
            if target_path.exists():
                target_path.rmdir()

            with pytest.raises(ConfigurationError) as exc_info:
                manager.run()

            assert "Path does not exist" in str(exc_info.value)

    @patch("opsbox.rsync.rsync_manager.subprocess.run")
    def test_run_network_unreachable(
        self,
        mock_subprocess: MagicMock,
    ) -> None:
        """Test handles NetworkUnreachableError and sends email."""
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)
            manager = self._create_test_manager(temp_path)

            # Setup network checker to raise error
            manager.network_checker.check_network_connectivity_or_raise.side_effect = (  # type: ignore[attr-defined]
                NetworkUnreachableError("Host unreachable")
            )

            with pytest.raises(NetworkUnreachableError):
                manager.run()

            # Verify error email was sent (may be called multiple times)
            assert manager.encrypted_mail.send_mail_with_retries.call_count >= 1  # type: ignore[attr-defined]
            # Check if any call has the connection failed subject
            calls = manager.encrypted_mail.send_mail_with_retries.call_args_list  # type: ignore[attr-defined]
            subjects = [call.kwargs.get("subject", "") for call in calls]
            assert any("server connection failed" in subj.lower() for subj in subjects)

    @patch("opsbox.rsync.rsync_manager.subprocess.run")
    def test_run_ssh_key_not_found(
        self,
        mock_subprocess: MagicMock,
    ) -> None:
        """Test handles SSHKeyNotFoundError and sends email."""
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)
            # Create config with SSH settings so SSH check is performed
            email_settings = temp_path / "email_settings.yaml"
            email_settings.write_text("test: settings")
            config_data = {
                "rsync_source": "user@host:/source",
                "rsync_target": str(temp_path / "target"),
                "email_settings_path": str(email_settings),
                "ssh_key": "SHA256:test",
                "ssh_user": "testuser",
                "network_host": "host.example.com",
            }
            manager = self._create_test_manager(temp_path, config_data)

            # Setup network checker to succeed, but SSH manager to fail
            manager.network_checker.check_network_connectivity_or_raise.return_value = (  # type: ignore[attr-defined]
                None
            )
            manager.ssh_manager.ensure_ssh_key_loaded.side_effect = SSHKeyNotFoundError(  # type: ignore[attr-defined]
                "SSH key not found",
            )

            with pytest.raises(SSHKeyNotFoundError):
                manager.run()

            # Verify error email was sent (may be called multiple times)
            assert manager.encrypted_mail.send_mail_with_retries.call_count >= 1  # type: ignore[attr-defined]
            # Check if any call has the connection failed subject
            calls = manager.encrypted_mail.send_mail_with_retries.call_args_list  # type: ignore[attr-defined]
            subjects = [call.kwargs.get("subject", "") for call in calls]
            assert any("server connection failed" in subj.lower() for subj in subjects)

    @patch("opsbox.rsync.rsync_manager.subprocess.run")
    @patch("opsbox.rsync.rsync_manager.time.sleep")
    @patch("opsbox.rsync.rsync_manager.time.time")
    def test_run_rsync_fails_all_retries(
        self,
        mock_time: MagicMock,
        mock_sleep: MagicMock,
        mock_subprocess: MagicMock,
    ) -> None:
        """Test raises RsyncError after all retries fail."""
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)
            config_data = {
                "rsync_source": "user@host:/source",
                "rsync_target": str(temp_path / "target"),
                "email_settings_path": str(temp_path / "email_settings.yaml"),
                "rsync_retry_max": 2,
            }
            manager = self._create_test_manager(temp_path, config_data)

            # Setup mocks
            mock_time.side_effect = [0, 100]
            mock_result = Mock()
            mock_result.returncode = 1  # Failure
            mock_subprocess.return_value = mock_result

            manager.log_file_path.write_text("log content")

            with pytest.raises(RsyncError):
                manager._execute_rsync()

            # Verify retries were attempted
            assert mock_subprocess.call_count == 2  # type: ignore[attr-defined]

    @patch("opsbox.rsync.rsync_manager.subprocess.run")
    @patch("opsbox.rsync.rsync_manager.time.sleep")
    @patch("opsbox.rsync.rsync_manager.time.time")
    def test_run_rsync_succeeds_on_retry(
        self,
        mock_time: MagicMock,
        mock_sleep: MagicMock,
        mock_subprocess: MagicMock,
    ) -> None:
        """Test succeeds on retry after initial failure."""
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)
            config_data = {
                "rsync_source": "user@host:/source",
                "rsync_target": str(temp_path / "target"),
                "email_settings_path": str(temp_path / "email_settings.yaml"),
                "rsync_retry_max": 3,
            }
            manager = self._create_test_manager(temp_path, config_data)

            # Setup mocks - first call fails, second succeeds
            mock_time.side_effect = [0, 100]
            mock_result_fail = Mock()
            mock_result_fail.returncode = 1
            mock_result_success = Mock()
            mock_result_success.returncode = 0
            mock_subprocess.side_effect = [mock_result_fail, mock_result_success]

            log_content = "sent 1,234 bytes  received 567 bytes\ntotal size is 1,801"
            manager.log_file_path.write_text(log_content)

            # Should not raise exception
            manager._execute_rsync()

            # Verify retry was attempted
            assert mock_subprocess.call_count == 2  # type: ignore[attr-defined]


class TestRsyncManagerCLI:
    """Test cases for CLI interface."""

    def _create_test_config_file(self, temp_dir: Path, email_settings: Path) -> Path:
        """Create a test configuration file."""
        config_data = {
            "rsync_source": "user@host:/source",
            "rsync_target": str(temp_dir / "target"),
            "email_settings_path": str(email_settings),
        }
        config_file = temp_dir / "config.yaml"
        config_file.write_text(yaml.dump(config_data))
        return config_file

    def _create_test_email_settings(self, temp_dir: Path) -> Path:
        """Create a test email settings file."""
        email_settings = temp_dir / "email_settings.yaml"
        email_settings.write_text("test: settings")
        return email_settings

    @patch(
        "opsbox.rsync.rsync_manager.sys.argv",
        ["rsync-manager", "--config", "config.yaml"],
    )
    @patch("opsbox.rsync.rsync_manager.RsyncManager")
    @patch("opsbox.rsync.rsync_manager.configure_logging")
    def test_main_success(
        self,
        mock_configure_logging: MagicMock,
        mock_rsync_manager: MagicMock,
    ) -> None:
        """Test CLI executes successfully."""
        mock_logger = Mock()
        mock_configure_logging.return_value = mock_logger

        mock_manager_instance = Mock()
        mock_rsync_manager.return_value = mock_manager_instance

        with patch("opsbox.rsync.rsync_manager.sys.exit") as mock_exit:
            main()
            mock_exit.assert_called_once_with(0)

    @patch(
        "opsbox.rsync.rsync_manager.sys.argv",
        ["rsync-manager", "--config", "nonexistent.yaml"],
    )
    @patch("opsbox.rsync.rsync_manager.configure_logging")
    def test_main_config_error(
        self,
        mock_configure_logging: MagicMock,
    ) -> None:
        """Test CLI exits with code 1 on ConfigurationError."""
        mock_logger = Mock()
        mock_configure_logging.return_value = mock_logger

        with (
            patch("opsbox.rsync.rsync_manager.sys.exit") as mock_exit,
            patch(
                "opsbox.rsync.rsync_manager.RsyncManager",
            ) as mock_manager,
        ):
            mock_manager.side_effect = ConfigurationError("Config error")

            main()
            mock_exit.assert_called_once_with(1)

    @patch(
        "opsbox.rsync.rsync_manager.sys.argv",
        ["rsync-manager", "--config", "config.yaml"],
    )
    @patch("opsbox.rsync.rsync_manager.configure_logging")
    def test_main_lock_error(
        self,
        mock_configure_logging: MagicMock,
    ) -> None:
        """Test CLI exits with code 1 on LockAlreadyTakenError."""
        mock_logger = Mock()
        mock_configure_logging.return_value = mock_logger

        with (
            patch("opsbox.rsync.rsync_manager.sys.exit") as mock_exit,
            patch(
                "opsbox.rsync.rsync_manager.RsyncManager",
            ) as mock_manager,
        ):
            mock_manager_instance = Mock()
            mock_manager_instance.run.side_effect = LockAlreadyTakenError("Lock taken")
            mock_manager.return_value = mock_manager_instance

            main()
            mock_exit.assert_called_once_with(1)

    @patch(
        "opsbox.rsync.rsync_manager.sys.argv",
        ["rsync-manager", "--config", "config.yaml", "--log-level", "DEBUG"],
    )
    @patch("opsbox.rsync.rsync_manager.RsyncManager")
    @patch("opsbox.rsync.rsync_manager.configure_logging")
    def test_main_custom_log_level(
        self,
        mock_configure_logging: MagicMock,
        mock_rsync_manager: MagicMock,
    ) -> None:
        """Test CLI uses custom log level."""
        mock_logger = Mock()
        mock_configure_logging.return_value = mock_logger

        mock_manager_instance = Mock()
        mock_rsync_manager.return_value = mock_manager_instance

        with patch("opsbox.rsync.rsync_manager.sys.exit"):
            main()

            # Verify log level was passed
            mock_rsync_manager.assert_called_once()
            call_args = mock_rsync_manager.call_args
            assert call_args.kwargs["log_level"] == "DEBUG"

"""Tests for the restic_backup module."""

import json
import tempfile
from collections.abc import Generator
from pathlib import Path
from unittest.mock import Mock, patch

import pytest

from opsbox.backup.exceptions import (
    ConfigurationError,
    NetworkUnreachableError,
    ResticBackupFailedError,
    SSHKeyNotFoundError,
    WrongOSForResticBackupError,
)
from opsbox.backup.restic_backup import BackupScript


class TestBackupScript:
    """Test cases for BackupScript functionality."""

    @pytest.fixture
    def temp_config(self) -> Generator[tuple[Path, Path, Path], None, None]:
        """Create temporary configuration files for testing."""
        with tempfile.TemporaryDirectory() as temp_dir:
            config_file = Path(temp_dir) / "config.yaml"
            email_settings = Path(temp_dir) / "email.json"
            backup_source = Path(temp_dir) / "source"
            backup_source.mkdir()
            email_settings.write_text(json.dumps({"sender": "test@example.com"}))

            config_data = {
                "backup_source": str(backup_source),
                "excluded_files": ["*.tmp"],
                "backup_target": "sftp:user@host:/repo",
                "password_lookup_1": "service",
                "password_lookup_2": "username",
                "email_settings_path": str(email_settings),
                "file_to_check": "important_file.txt",
            }

            config_file.write_text(
                f"backup_source: {config_data['backup_source']}\n"
                f"excluded_files:\n  - '{config_data['excluded_files'][0]}'\n"
                f"backup_target: {config_data['backup_target']}\n"
                f"password_lookup_1: {config_data['password_lookup_1']}\n"
                f"password_lookup_2: {config_data['password_lookup_2']}\n"
                f"email_settings_path: {config_data['email_settings_path']}\n"
                f"file_to_check: {config_data['file_to_check']}\n",
            )

            yield config_file, email_settings, backup_source

    @pytest.fixture
    def mock_lock_manager(self) -> Mock:
        """Create a mock LockManager that acts as a context manager."""
        lock_manager = Mock()
        lock_manager.__enter__ = Mock(return_value=lock_manager)
        lock_manager.__exit__ = Mock(return_value=False)
        return lock_manager

    def test_backup_script_init_success(self, temp_config, mock_lock_manager) -> None:
        """Test that BackupScript initializes successfully with valid configuration."""
        config_file, _email_settings, _backup_source = temp_config

        with (
            patch(
                "opsbox.backup.restic_backup.LockManager",
                return_value=mock_lock_manager,
            ),
            patch("opsbox.backup.restic_backup.EncryptedMail"),
            patch("opsbox.backup.restic_backup.PasswordManager"),
            patch("opsbox.backup.restic_backup.NetworkChecker"),
            patch("opsbox.backup.restic_backup.SSHManager"),
            patch("opsbox.backup.restic_backup.ResticClient"),
        ):
            backup_script = BackupScript(str(config_file))

            assert backup_script.config is not None
            assert backup_script.logger is not None

    def test_backup_script_init_wrong_os(self, temp_config) -> None:
        """Test that WrongOSForResticBackupError is raised on non-Linux OS."""
        config_file, _, _ = temp_config

        with (
            patch("os.name", "nt"),  # Windows
            patch("sys.platform", "win32"),
        ):
            with pytest.raises(
                WrongOSForResticBackupError,
                match="This script only runs on Linux",
            ):
                BackupScript(str(config_file))

    def test_backup_script_init_invalid_config(self) -> None:
        """Test that ConfigurationError is raised for invalid config file."""
        with pytest.raises(ConfigurationError):
            BackupScript("/nonexistent/config.yaml")

    def test_run_complete_backup_workflow_success(
        self,
        temp_config,
        mock_lock_manager,
    ) -> None:
        """Test that complete backup workflow executes successfully."""
        config_file, _, _ = temp_config

        mock_restic_client = Mock()
        mock_restic_client.backup.return_value = "abc123def"
        # The code expects snapshots[-2] to be the current snapshot, so we need at least 3 snapshots
        # with the current one at index -2
        mock_restic_client.get_snapshots.return_value = ["snap1", "abc123def", "snap3"]
        mock_restic_client.diff.return_value = "Files: 10\nDirs: 5"
        mock_restic_client.find.return_value = (
            "Found matching entries in snapshot abc123def"
        )
        mock_restic_client.check.return_value = "no errors were found"
        mock_restic_client.log_file = Path("/tmp/restic.log")

        mock_encrypted_mail = Mock()

        with (
            patch(
                "opsbox.backup.restic_backup.LockManager",
                return_value=mock_lock_manager,
            ),
            patch(
                "opsbox.backup.restic_backup.EncryptedMail",
                return_value=mock_encrypted_mail,
            ),
            patch("opsbox.backup.restic_backup.PasswordManager") as mock_pm_class,
            patch("opsbox.backup.restic_backup.NetworkChecker"),
            patch("opsbox.backup.restic_backup.SSHManager"),
            patch(
                "opsbox.backup.restic_backup.ResticClient",
                return_value=mock_restic_client,
            ),
        ):
            mock_password_manager = Mock()
            mock_password_manager.get_restic_password.return_value = "test_password"
            mock_pm_class.return_value = mock_password_manager

            backup_script = BackupScript(str(config_file))
            backup_script.run()

            # Verify backup was executed
            mock_restic_client.backup.assert_called_once()
            # Verify verification was performed
            mock_restic_client.find.assert_called_once()
            # Verify maintenance was performed
            mock_restic_client.forget.assert_called_once()
            mock_restic_client.prune.assert_called_once()
            mock_restic_client.check.assert_called_once()

    def test_run_backup_with_network_check(
        self,
        temp_config,
        mock_lock_manager,
    ) -> None:
        """Test that network check is performed when network_host is configured."""
        config_file, email_settings, backup_source = temp_config

        # Add network_host to config
        config_data = {
            "backup_source": str(backup_source),
            "excluded_files": ["*.tmp"],
            "backup_target": "sftp:user@host:/repo",
            "password_lookup_1": "service",
            "password_lookup_2": "username",
            "email_settings_path": str(email_settings),
            "file_to_check": "important_file.txt",
            "network_host": "example.com",
            "ssh_key": "/path/to/key",
            "ssh_user": "backup_user",
        }

        excluded_file = config_data["excluded_files"][0]
        config_file.write_text(
            f"backup_source: {config_data['backup_source']}\n"
            f"excluded_files:\n  - '{excluded_file}'\n"
            f"backup_target: {config_data['backup_target']}\n"
            f"password_lookup_1: {config_data['password_lookup_1']}\n"
            f"password_lookup_2: {config_data['password_lookup_2']}\n"
            f"email_settings_path: {config_data['email_settings_path']}\n"
            f"file_to_check: {config_data['file_to_check']}\n"
            f"network_host: {config_data['network_host']}\n"
            f"ssh_key: {config_data['ssh_key']}\n"
            f"ssh_user: {config_data['ssh_user']}\n",
        )

        mock_restic_client = Mock()
        mock_restic_client.backup.return_value = "abc123def"
        mock_restic_client.get_snapshots.return_value = ["snap1", "abc123def", "snap3"]
        mock_restic_client.find.return_value = (
            "Found matching entries in snapshot abc123def"
        )
        mock_restic_client.check.return_value = "no errors were found"
        mock_restic_client.log_file = Path("/tmp/restic.log")

        mock_network_checker = Mock()
        mock_network_checker.check_network_connectivity_or_raise.return_value = None

        with (
            patch(
                "opsbox.backup.restic_backup.LockManager",
                return_value=mock_lock_manager,
            ),
            patch("opsbox.backup.restic_backup.EncryptedMail"),
            patch("opsbox.backup.restic_backup.PasswordManager") as mock_pm_class,
            patch(
                "opsbox.backup.restic_backup.NetworkChecker",
                return_value=mock_network_checker,
            ),
            patch("opsbox.backup.restic_backup.SSHManager"),
            patch(
                "opsbox.backup.restic_backup.ResticClient",
                return_value=mock_restic_client,
            ),
        ):
            mock_password_manager = Mock()
            mock_password_manager.get_restic_password.return_value = "test_password"
            mock_pm_class.return_value = mock_password_manager

            backup_script = BackupScript(str(config_file))
            backup_script.run()

            # Verify network check was performed
            mock_network_checker.check_network_connectivity_or_raise.assert_called_once()

    def test_run_backup_with_ssh_setup(self, temp_config, mock_lock_manager) -> None:
        """Test that SSH setup is performed when ssh_key is configured."""
        config_file, email_settings, backup_source = temp_config

        # Add SSH config
        config_data = {
            "backup_source": str(backup_source),
            "excluded_files": ["*.tmp"],
            "backup_target": "sftp:user@host:/repo",
            "password_lookup_1": "service",
            "password_lookup_2": "username",
            "email_settings_path": str(email_settings),
            "file_to_check": "important_file.txt",
            "network_host": "example.com",
            "ssh_key": "/path/to/key",
            "ssh_user": "backup_user",
        }

        excluded_file = config_data["excluded_files"][0]
        config_file.write_text(
            f"backup_source: {config_data['backup_source']}\n"
            f"excluded_files:\n  - '{excluded_file}'\n"
            f"backup_target: {config_data['backup_target']}\n"
            f"password_lookup_1: {config_data['password_lookup_1']}\n"
            f"password_lookup_2: {config_data['password_lookup_2']}\n"
            f"email_settings_path: {config_data['email_settings_path']}\n"
            f"file_to_check: {config_data['file_to_check']}\n"
            f"network_host: {config_data['network_host']}\n"
            f"ssh_key: {config_data['ssh_key']}\n"
            f"ssh_user: {config_data['ssh_user']}\n",
        )

        mock_restic_client = Mock()
        mock_restic_client.backup.return_value = "abc123def"
        mock_restic_client.get_snapshots.return_value = ["snap1", "abc123def", "snap3"]
        mock_restic_client.find.return_value = (
            "Found matching entries in snapshot abc123def"
        )
        mock_restic_client.check.return_value = "no errors were found"
        mock_restic_client.log_file = Path("/tmp/restic.log")

        mock_ssh_manager = Mock()
        mock_ssh_manager.get_ssh_auth_sock.return_value = "/path/to/sock"
        mock_ssh_manager.ensure_ssh_key_loaded.return_value = None

        with (
            patch(
                "opsbox.backup.restic_backup.LockManager",
                return_value=mock_lock_manager,
            ),
            patch("opsbox.backup.restic_backup.EncryptedMail"),
            patch("opsbox.backup.restic_backup.PasswordManager") as mock_pm_class,
            patch("opsbox.backup.restic_backup.NetworkChecker"),
            patch(
                "opsbox.backup.restic_backup.SSHManager",
                return_value=mock_ssh_manager,
            ),
            patch(
                "opsbox.backup.restic_backup.ResticClient",
                return_value=mock_restic_client,
            ),
        ):
            mock_password_manager = Mock()
            mock_password_manager.get_restic_password.return_value = "test_password"
            mock_pm_class.return_value = mock_password_manager

            backup_script = BackupScript(str(config_file))
            backup_script.run()

            # Verify SSH setup was performed
            mock_ssh_manager.ensure_ssh_key_loaded.assert_called_once()

    def test_run_backup_network_unreachable(
        self,
        temp_config,
        mock_lock_manager,
    ) -> None:
        """Test that network unreachable is handled gracefully (sends email, skips backup)."""
        config_file, email_settings, backup_source = temp_config

        # Add network_host to config (ssh_key is required when network_host is set)
        config_data = {
            "backup_source": str(backup_source),
            "excluded_files": ["*.tmp"],
            "backup_target": "sftp:user@host:/repo",
            "password_lookup_1": "service",
            "password_lookup_2": "username",
            "email_settings_path": str(email_settings),
            "file_to_check": "important_file.txt",
            "network_host": "example.com",
            "ssh_key": "/path/to/key",
            "ssh_user": "backup_user",
        }

        excluded_file = config_data["excluded_files"][0]
        config_file.write_text(
            f"backup_source: {config_data['backup_source']}\n"
            f"excluded_files:\n  - '{excluded_file}'\n"
            f"backup_target: {config_data['backup_target']}\n"
            f"password_lookup_1: {config_data['password_lookup_1']}\n"
            f"password_lookup_2: {config_data['password_lookup_2']}\n"
            f"email_settings_path: {config_data['email_settings_path']}\n"
            f"file_to_check: {config_data['file_to_check']}\n"
            f"network_host: {config_data['network_host']}\n"
            f"ssh_key: {config_data['ssh_key']}\n"
            f"ssh_user: {config_data['ssh_user']}\n",
        )

        mock_encrypted_mail = Mock()
        mock_network_checker = Mock()
        mock_network_checker.check_network_connectivity_or_raise.side_effect = (
            NetworkUnreachableError("Host unreachable")
        )

        with (
            patch(
                "opsbox.backup.restic_backup.LockManager",
                return_value=mock_lock_manager,
            ),
            patch(
                "opsbox.backup.restic_backup.EncryptedMail",
                return_value=mock_encrypted_mail,
            ),
            patch("opsbox.backup.restic_backup.PasswordManager"),
            patch(
                "opsbox.backup.restic_backup.NetworkChecker",
                return_value=mock_network_checker,
            ),
            patch("opsbox.backup.restic_backup.SSHManager"),
            patch("opsbox.backup.restic_backup.ResticClient"),
        ):
            backup_script = BackupScript(str(config_file))
            backup_script.run()

            # Verify email was sent about skipped backup
            mock_encrypted_mail.send_mail_with_retries.assert_called()
            call_args = mock_encrypted_mail.send_mail_with_retries.call_args
            assert "Backup skipped" in call_args[1]["subject"]

    def test_run_backup_ssh_key_not_found(self, temp_config, mock_lock_manager) -> None:
        """Test that SSH key not found is handled gracefully (sends email, skips backup)."""
        config_file, email_settings, backup_source = temp_config

        # Add SSH config
        config_data = {
            "backup_source": str(backup_source),
            "excluded_files": ["*.tmp"],
            "backup_target": "sftp:user@host:/repo",
            "password_lookup_1": "service",
            "password_lookup_2": "username",
            "email_settings_path": str(email_settings),
            "file_to_check": "important_file.txt",
            "network_host": "example.com",
            "ssh_key": "/path/to/key",
            "ssh_user": "backup_user",
        }

        excluded_file = config_data["excluded_files"][0]
        config_file.write_text(
            f"backup_source: {config_data['backup_source']}\n"
            f"excluded_files:\n  - '{excluded_file}'\n"
            f"backup_target: {config_data['backup_target']}\n"
            f"password_lookup_1: {config_data['password_lookup_1']}\n"
            f"password_lookup_2: {config_data['password_lookup_2']}\n"
            f"email_settings_path: {config_data['email_settings_path']}\n"
            f"file_to_check: {config_data['file_to_check']}\n"
            f"network_host: {config_data['network_host']}\n"
            f"ssh_key: {config_data['ssh_key']}\n"
            f"ssh_user: {config_data['ssh_user']}\n",
        )

        mock_encrypted_mail = Mock()
        mock_ssh_manager = Mock()
        mock_ssh_manager.get_ssh_auth_sock.return_value = "/path/to/sock"
        mock_ssh_manager.ensure_ssh_key_loaded.side_effect = SSHKeyNotFoundError(
            "Key not found",
        )

        with (
            patch(
                "opsbox.backup.restic_backup.LockManager",
                return_value=mock_lock_manager,
            ),
            patch(
                "opsbox.backup.restic_backup.EncryptedMail",
                return_value=mock_encrypted_mail,
            ),
            patch("opsbox.backup.restic_backup.PasswordManager"),
            patch("opsbox.backup.restic_backup.NetworkChecker"),
            patch(
                "opsbox.backup.restic_backup.SSHManager",
                return_value=mock_ssh_manager,
            ),
            patch("opsbox.backup.restic_backup.ResticClient"),
        ):
            backup_script = BackupScript(str(config_file))
            backup_script.run()

            # Verify email was sent about skipped backup
            mock_encrypted_mail.send_mail_with_retries.assert_called()
            call_args = mock_encrypted_mail.send_mail_with_retries.call_args
            assert "Backup skipped" in call_args[1]["subject"]

    def test_run_backup_verification_success(
        self,
        temp_config,
        mock_lock_manager,
    ) -> None:
        """Test that backup verification succeeds when file is found."""
        config_file, _, _ = temp_config

        mock_restic_client = Mock()
        mock_restic_client.backup.return_value = "abc123def"
        mock_restic_client.get_snapshots.return_value = ["snap1", "abc123def", "snap3"]
        mock_restic_client.diff.return_value = "Files: 10"
        mock_restic_client.find.return_value = (
            "Found matching entries in snapshot abc123def"
        )
        mock_restic_client.check.return_value = "no errors were found"
        mock_restic_client.log_file = Path("/tmp/restic.log")

        mock_encrypted_mail = Mock()

        with (
            patch(
                "opsbox.backup.restic_backup.LockManager",
                return_value=mock_lock_manager,
            ),
            patch(
                "opsbox.backup.restic_backup.EncryptedMail",
                return_value=mock_encrypted_mail,
            ),
            patch("opsbox.backup.restic_backup.PasswordManager") as mock_pm_class,
            patch("opsbox.backup.restic_backup.NetworkChecker"),
            patch("opsbox.backup.restic_backup.SSHManager"),
            patch(
                "opsbox.backup.restic_backup.ResticClient",
                return_value=mock_restic_client,
            ),
        ):
            mock_password_manager = Mock()
            mock_password_manager.get_restic_password.return_value = "test_password"
            mock_pm_class.return_value = mock_password_manager

            backup_script = BackupScript(str(config_file))
            backup_script.run()

            # Verify verification email was sent
            mock_encrypted_mail.send_mail_with_retries.assert_called()
            # Verify maintenance was performed (only if verification succeeds)
            mock_restic_client.forget.assert_called_once()

    def test_run_backup_verification_failure(
        self,
        temp_config,
        mock_lock_manager,
    ) -> None:
        """Test that verification failure is handled (sends email, skips maintenance)."""
        config_file, _, _ = temp_config

        mock_restic_client = Mock()
        mock_restic_client.backup.return_value = "abc123def"
        mock_restic_client.get_snapshots.return_value = ["snap1", "abc123def", "snap3"]
        mock_restic_client.diff.return_value = "Files: 10"
        mock_restic_client.find.return_value = "No matching entries found"
        mock_restic_client.log_file = Path("/tmp/restic.log")

        mock_encrypted_mail = Mock()

        with (
            patch(
                "opsbox.backup.restic_backup.LockManager",
                return_value=mock_lock_manager,
            ),
            patch(
                "opsbox.backup.restic_backup.EncryptedMail",
                return_value=mock_encrypted_mail,
            ),
            patch("opsbox.backup.restic_backup.PasswordManager") as mock_pm_class,
            patch("opsbox.backup.restic_backup.NetworkChecker"),
            patch("opsbox.backup.restic_backup.SSHManager"),
            patch(
                "opsbox.backup.restic_backup.ResticClient",
                return_value=mock_restic_client,
            ),
        ):
            mock_password_manager = Mock()
            mock_password_manager.get_restic_password.return_value = "test_password"
            mock_pm_class.return_value = mock_password_manager

            backup_script = BackupScript(str(config_file))
            backup_script.run()

            # Verify verification failure email was sent
            mock_encrypted_mail.send_mail_with_retries.assert_called()
            # Verify maintenance was NOT performed (verification failed)
            mock_restic_client.forget.assert_not_called()
            mock_restic_client.prune.assert_not_called()

    def test_run_backup_maintenance_success(
        self,
        temp_config,
        mock_lock_manager,
    ) -> None:
        """Test that maintenance operations are performed successfully."""
        config_file, _, _ = temp_config

        mock_restic_client = Mock()
        mock_restic_client.backup.return_value = "abc123def"
        mock_restic_client.get_snapshots.return_value = ["snap1", "abc123def", "snap3"]
        mock_restic_client.diff.return_value = "Files: 10"
        mock_restic_client.find.return_value = (
            "Found matching entries in snapshot abc123def"
        )
        mock_restic_client.check.return_value = "no errors were found"
        mock_restic_client.log_file = Path("/tmp/restic.log")

        mock_encrypted_mail = Mock()

        with (
            patch(
                "opsbox.backup.restic_backup.LockManager",
                return_value=mock_lock_manager,
            ),
            patch(
                "opsbox.backup.restic_backup.EncryptedMail",
                return_value=mock_encrypted_mail,
            ),
            patch("opsbox.backup.restic_backup.PasswordManager") as mock_pm_class,
            patch("opsbox.backup.restic_backup.NetworkChecker"),
            patch("opsbox.backup.restic_backup.SSHManager"),
            patch(
                "opsbox.backup.restic_backup.ResticClient",
                return_value=mock_restic_client,
            ),
        ):
            mock_password_manager = Mock()
            mock_password_manager.get_restic_password.return_value = "test_password"
            mock_pm_class.return_value = mock_password_manager

            backup_script = BackupScript(str(config_file))
            backup_script.run()

            # Verify all maintenance operations were performed
            mock_restic_client.forget.assert_called_once()
            mock_restic_client.cache_cleanup.assert_called_once()
            mock_restic_client.prune.assert_called_once()
            mock_restic_client.check.assert_called_once()

    def test_generate_diff_summary_success(
        self,
        temp_config,
        mock_lock_manager,
    ) -> None:
        """Test that diff summary is generated successfully between snapshots."""
        config_file, _, _ = temp_config

        mock_restic_client = Mock()
        mock_restic_client.backup.return_value = "snapshot3"
        # Code expects snapshots[-2] to be current snapshot, snapshots[-3] to be previous
        mock_restic_client.get_snapshots.return_value = [
            "snapshot1",
            "snapshot3",
            "snapshot2",
        ]
        mock_restic_client.diff.return_value = (
            "Files: 10\nDirs: 5\nAdded: 3\nRemoved: 2"
        )
        mock_restic_client.find.return_value = (
            "Found matching entries in snapshot snapshot3"
        )
        mock_restic_client.check.return_value = "no errors were found"
        mock_restic_client.log_file = Path("/tmp/restic.log")

        with (
            patch(
                "opsbox.backup.restic_backup.LockManager",
                return_value=mock_lock_manager,
            ),
            patch("opsbox.backup.restic_backup.EncryptedMail"),
            patch("opsbox.backup.restic_backup.PasswordManager") as mock_pm_class,
            patch("opsbox.backup.restic_backup.NetworkChecker"),
            patch("opsbox.backup.restic_backup.SSHManager"),
            patch(
                "opsbox.backup.restic_backup.ResticClient",
                return_value=mock_restic_client,
            ),
        ):
            mock_password_manager = Mock()
            mock_password_manager.get_restic_password.return_value = "test_password"
            mock_pm_class.return_value = mock_password_manager

            backup_script = BackupScript(str(config_file))
            backup_script.run()

            # Verify diff was called
            mock_restic_client.diff.assert_called_once()

    def test_generate_diff_summary_insufficient_snapshots(
        self,
        temp_config,
        mock_lock_manager,
    ) -> None:
        """Test that diff summary handles insufficient snapshots gracefully."""
        config_file, _, _ = temp_config

        mock_restic_client = Mock()
        mock_restic_client.backup.return_value = "snapshot1"
        mock_restic_client.get_snapshots.return_value = [
            "snapshot1",
        ]  # Only one snapshot
        mock_restic_client.find.return_value = (
            "Found matching entries in snapshot snapshot1"
        )
        mock_restic_client.check.return_value = "no errors were found"
        mock_restic_client.log_file = Path("/tmp/restic.log")

        with (
            patch(
                "opsbox.backup.restic_backup.LockManager",
                return_value=mock_lock_manager,
            ),
            patch("opsbox.backup.restic_backup.EncryptedMail"),
            patch("opsbox.backup.restic_backup.PasswordManager") as mock_pm_class,
            patch("opsbox.backup.restic_backup.NetworkChecker"),
            patch("opsbox.backup.restic_backup.SSHManager"),
            patch(
                "opsbox.backup.restic_backup.ResticClient",
                return_value=mock_restic_client,
            ),
        ):
            mock_password_manager = Mock()
            mock_password_manager.get_restic_password.return_value = "test_password"
            mock_pm_class.return_value = mock_password_manager

            backup_script = BackupScript(str(config_file))
            backup_script.run()

            # Verify diff was not called (insufficient snapshots)
            mock_restic_client.diff.assert_not_called()

    def test_check_thresholds_and_send_warnings_deletion(
        self,
        temp_config,
        mock_lock_manager,
    ) -> None:
        """Test that warning email is sent when deletion threshold is exceeded."""
        config_file, _, _ = temp_config

        # Update config with deletion threshold
        config_file, email_settings, backup_source = temp_config
        config_data: dict[str, str | int | list[str]] = {
            "backup_source": str(backup_source),
            "excluded_files": ["*.tmp"],
            "backup_target": "sftp:user@host:/repo",
            "password_lookup_1": "service",
            "password_lookup_2": "username",
            "email_settings_path": str(email_settings),
            "file_to_check": "important_file.txt",
            "deletion_threshold": 5,
        }

        excluded_file = config_data["excluded_files"][0]  # type: ignore[index]
        config_file.write_text(
            f"backup_source: {config_data['backup_source']}\n"
            f"excluded_files:\n  - '{excluded_file}'\n"
            f"backup_target: {config_data['backup_target']}\n"
            f"password_lookup_1: {config_data['password_lookup_1']}\n"
            f"password_lookup_2: {config_data['password_lookup_2']}\n"
            f"email_settings_path: {config_data['email_settings_path']}\n"
            f"file_to_check: {config_data['file_to_check']}\n"
            f"deletion_threshold: {config_data['deletion_threshold']}\n",
        )

        mock_restic_client = Mock()
        mock_restic_client.backup.return_value = "snapshot3"
        # Code expects snapshots[-2] to be current snapshot, snapshots[-3] to be previous
        mock_restic_client.get_snapshots.return_value = [
            "snapshot1",
            "snapshot3",
            "snapshot2",
        ]
        # Create diff output with 10 deleted files (exceeds threshold of 5)
        diff_output = "\n".join([f"-    /path/to/file{i}.txt" for i in range(10)])
        mock_restic_client.diff.return_value = diff_output
        mock_restic_client.find.return_value = (
            "Found matching entries in snapshot snapshot3"
        )
        mock_restic_client.check.return_value = "no errors were found"
        mock_restic_client.log_file = Path("/tmp/restic.log")

        mock_encrypted_mail = Mock()

        with (
            patch(
                "opsbox.backup.restic_backup.LockManager",
                return_value=mock_lock_manager,
            ),
            patch(
                "opsbox.backup.restic_backup.EncryptedMail",
                return_value=mock_encrypted_mail,
            ),
            patch("opsbox.backup.restic_backup.PasswordManager") as mock_pm_class,
            patch("opsbox.backup.restic_backup.NetworkChecker"),
            patch("opsbox.backup.restic_backup.SSHManager"),
            patch(
                "opsbox.backup.restic_backup.ResticClient",
                return_value=mock_restic_client,
            ),
        ):
            mock_password_manager = Mock()
            mock_password_manager.get_restic_password.return_value = "test_password"
            mock_pm_class.return_value = mock_password_manager

            backup_script = BackupScript(str(config_file))
            backup_script.run()

            # Verify warning email was sent
            mock_encrypted_mail.send_mail_with_retries.assert_called()
            # Check that at least one call contains deletion threshold warning
            calls = [
                str(call)
                for call in mock_encrypted_mail.send_mail_with_retries.call_args_list
            ]
            assert any(
                "deletion threshold" in call.lower() or "files deleted" in call.lower()
                for call in calls
            )

    def test_check_thresholds_and_send_warnings_alteration(
        self,
        temp_config,
        mock_lock_manager,
    ) -> None:
        """Test that warning email is sent when alteration threshold is exceeded."""
        config_file, _, _ = temp_config

        # Update config with alteration threshold
        config_file, email_settings, backup_source = temp_config
        config_data: dict[str, str | int | list[str]] = {
            "backup_source": str(backup_source),
            "excluded_files": ["*.tmp"],
            "backup_target": "sftp:user@host:/repo",
            "password_lookup_1": "service",
            "password_lookup_2": "username",
            "email_settings_path": str(email_settings),
            "file_to_check": "important_file.txt",
            "alteration_threshold": 5,
        }

        excluded_file = config_data["excluded_files"][0]  # type: ignore[index]
        config_file.write_text(
            f"backup_source: {config_data['backup_source']}\n"
            f"excluded_files:\n  - '{excluded_file}'\n"
            f"backup_target: {config_data['backup_target']}\n"
            f"password_lookup_1: {config_data['password_lookup_1']}\n"
            f"password_lookup_2: {config_data['password_lookup_2']}\n"
            f"email_settings_path: {config_data['email_settings_path']}\n"
            f"file_to_check: {config_data['file_to_check']}\n"
            f"alteration_threshold: {config_data['alteration_threshold']}\n",
        )

        mock_restic_client = Mock()
        mock_restic_client.backup.return_value = "snapshot3"
        # Code expects snapshots[-2] to be current snapshot, snapshots[-3] to be previous
        mock_restic_client.get_snapshots.return_value = [
            "snapshot1",
            "snapshot3",
            "snapshot2",
        ]
        # Create diff output with 10 modified files (exceeds threshold of 5)
        diff_output = "\n".join([f"M    /path/to/file{i}.txt" for i in range(10)])
        mock_restic_client.diff.return_value = diff_output
        mock_restic_client.find.return_value = (
            "Found matching entries in snapshot snapshot3"
        )
        mock_restic_client.check.return_value = "no errors were found"
        mock_restic_client.log_file = Path("/tmp/restic.log")

        mock_encrypted_mail = Mock()

        with (
            patch(
                "opsbox.backup.restic_backup.LockManager",
                return_value=mock_lock_manager,
            ),
            patch(
                "opsbox.backup.restic_backup.EncryptedMail",
                return_value=mock_encrypted_mail,
            ),
            patch("opsbox.backup.restic_backup.PasswordManager") as mock_pm_class,
            patch("opsbox.backup.restic_backup.NetworkChecker"),
            patch("opsbox.backup.restic_backup.SSHManager"),
            patch(
                "opsbox.backup.restic_backup.ResticClient",
                return_value=mock_restic_client,
            ),
        ):
            mock_password_manager = Mock()
            mock_password_manager.get_restic_password.return_value = "test_password"
            mock_pm_class.return_value = mock_password_manager

            backup_script = BackupScript(str(config_file))
            backup_script.run()

            # Verify warning email was sent
            mock_encrypted_mail.send_mail_with_retries.assert_called()
            # Check that at least one call contains alteration threshold warning
            calls = [
                str(call)
                for call in mock_encrypted_mail.send_mail_with_retries.call_args_list
            ]
            assert any(
                "alteration threshold" in call.lower()
                or "files altered" in call.lower()
                for call in calls
            )

    def test_check_monitored_folders_and_send_alerts(
        self,
        temp_config,
        mock_lock_manager,
    ) -> None:
        """Test that alerts are sent for changes in monitored folders."""
        config_file, _, _ = temp_config

        # Update config with monitored folders
        config_file, email_settings, backup_source = temp_config
        config_data = {
            "backup_source": str(backup_source),
            "excluded_files": ["*.tmp"],
            "backup_target": "sftp:user@host:/repo",
            "password_lookup_1": "service",
            "password_lookup_2": "username",
            "email_settings_path": str(email_settings),
            "file_to_check": "important_file.txt",
            "monitored_folders": ["/important/folder"],
        }

        excluded_file = config_data["excluded_files"][0]
        config_file.write_text(
            f"backup_source: {config_data['backup_source']}\n"
            f"excluded_files:\n  - '{excluded_file}'\n"
            f"backup_target: {config_data['backup_target']}\n"
            f"password_lookup_1: {config_data['password_lookup_1']}\n"
            f"password_lookup_2: {config_data['password_lookup_2']}\n"
            f"email_settings_path: {config_data['email_settings_path']}\n"
            f"file_to_check: {config_data['file_to_check']}\n"
            f"monitored_folders:\n  - {config_data['monitored_folders'][0]}\n",
        )

        mock_restic_client = Mock()
        mock_restic_client.backup.return_value = "snapshot3"
        # Code expects snapshots[-2] to be current snapshot, snapshots[-3] to be previous
        mock_restic_client.get_snapshots.return_value = [
            "snapshot1",
            "snapshot3",
            "snapshot2",
        ]
        # Create diff output with files in monitored folder
        diff_output = (
            "-    /important/folder/file1.txt\nM    /important/folder/file2.txt"
        )
        mock_restic_client.diff.return_value = diff_output
        mock_restic_client.find.return_value = (
            "Found matching entries in snapshot snapshot3"
        )
        mock_restic_client.check.return_value = "no errors were found"
        mock_restic_client.log_file = Path("/tmp/restic.log")

        mock_encrypted_mail = Mock()

        with (
            patch(
                "opsbox.backup.restic_backup.LockManager",
                return_value=mock_lock_manager,
            ),
            patch(
                "opsbox.backup.restic_backup.EncryptedMail",
                return_value=mock_encrypted_mail,
            ),
            patch("opsbox.backup.restic_backup.PasswordManager") as mock_pm_class,
            patch("opsbox.backup.restic_backup.NetworkChecker"),
            patch("opsbox.backup.restic_backup.SSHManager"),
            patch(
                "opsbox.backup.restic_backup.ResticClient",
                return_value=mock_restic_client,
            ),
        ):
            mock_password_manager = Mock()
            mock_password_manager.get_restic_password.return_value = "test_password"
            mock_pm_class.return_value = mock_password_manager

            backup_script = BackupScript(str(config_file))
            backup_script.run()

            # Verify alert emails were sent for monitored folder changes
            mock_encrypted_mail.send_mail_with_retries.assert_called()
            # Check that at least one call contains monitored folder alert
            calls = [
                str(call)
                for call in mock_encrypted_mail.send_mail_with_retries.call_args_list
            ]
            assert any("monitored folder" in call.lower() for call in calls)

    def test_run_backup_failure_sends_email(
        self,
        temp_config,
        mock_lock_manager,
    ) -> None:
        """Test that backup failure sends error email with log attachment."""
        config_file, _, _ = temp_config

        mock_restic_client = Mock()
        mock_restic_client.backup.side_effect = ResticBackupFailedError("Backup failed")
        mock_restic_client.log_file = Path("/tmp/restic.log")
        mock_restic_client.log_file.touch()

        mock_encrypted_mail = Mock()

        with (
            patch(
                "opsbox.backup.restic_backup.LockManager",
                return_value=mock_lock_manager,
            ),
            patch(
                "opsbox.backup.restic_backup.EncryptedMail",
                return_value=mock_encrypted_mail,
            ),
            patch("opsbox.backup.restic_backup.PasswordManager") as mock_pm_class,
            patch("opsbox.backup.restic_backup.NetworkChecker"),
            patch("opsbox.backup.restic_backup.SSHManager"),
            patch(
                "opsbox.backup.restic_backup.ResticClient",
                return_value=mock_restic_client,
            ),
        ):
            mock_password_manager = Mock()
            mock_password_manager.get_restic_password.return_value = "test_password"
            mock_pm_class.return_value = mock_password_manager

            backup_script = BackupScript(str(config_file))

            with pytest.raises(ResticBackupFailedError):
                backup_script.run()

            # Verify error email was sent with log attachment
            mock_encrypted_mail.send_mail_with_retries.assert_called()
            # Check all calls to find the backup failure email
            calls = mock_encrypted_mail.send_mail_with_retries.call_args_list
            backup_failure_call = None
            for call in calls:
                kwargs = (
                    call.kwargs
                    if hasattr(call, "kwargs")
                    else call[1]
                    if len(call) > 1
                    else {}
                )
                if "Backup failed" in str(kwargs.get("subject", "")):
                    backup_failure_call = call
                    break

            assert backup_failure_call is not None, "Backup failure email was not sent"
            kwargs = (
                backup_failure_call.kwargs
                if hasattr(backup_failure_call, "kwargs")
                else backup_failure_call[1]
            )
            assert kwargs.get("mail_attachment") == str(mock_restic_client.log_file)


if __name__ == "__main__":
    pytest.main([__file__])

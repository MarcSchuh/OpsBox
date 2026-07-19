"""Tests for the restic_backup module."""

import json
import tempfile
from collections.abc import Generator
from pathlib import Path
from unittest.mock import Mock, patch

import pytest

from opsbox.backup.exceptions import (
    ConfigurationError,
    EmptySourceError,
    NetworkUnreachableError,
    ResticBackupFailedError,
    ResticRepositoryLockedError,
    SSHKeyNotFoundError,
    VerificationError,
    WrongOSForResticBackupError,
)
from opsbox.backup.restic_backup import BackupScript
from opsbox.backup.snapshot_id import ResticSnapshotId


def make_diff_ndjson(
    entries: list[tuple[str, str]] | None = None,
    *,
    changed_files: int = 0,
) -> str:
    """Build 'restic diff --json' ndjson output from (modifier, path) tuples.

    A terminating ``statistics`` message is always appended, mirroring real
    ``restic diff --json`` output (which the parser now requires).
    """
    entries = entries or []
    lines = [
        json.dumps({"message_type": "change", "path": path, "modifier": modifier})
        for modifier, path in entries
    ]
    empty_stat = {
        "files": 0,
        "dirs": 0,
        "others": 0,
        "data_blobs": 0,
        "tree_blobs": 0,
        "bytes": 0,
    }
    lines.append(
        json.dumps(
            {
                "message_type": "statistics",
                "source_snapshot": "aaaaaaaa",
                "target_snapshot": "bbbbbbbb",
                "changed_files": changed_files,
                "added": empty_stat,
                "removed": empty_stat,
            },
        ),
    )
    return "\n".join(lines)


def make_find_json(*, found: bool = True) -> str:
    """Build 'restic find --json' output; found=False yields no matches."""
    if not found:
        return json.dumps([])
    return json.dumps(
        [
            {
                "hits": 1,
                "snapshot": "0" * 64,
                "matches": [{"path": "/important_file.txt", "type": "file"}],
            },
        ],
    )


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
            # Add an entry so the non-empty source guard passes by default
            (backup_source / "dummy.txt").write_text("data")
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
        snapshot_id = ResticSnapshotId("c9d0e1f2")
        mock_restic_client.backup.return_value = snapshot_id
        # The code expects snapshots[-2] to be the current snapshot, so we need at least 3 snapshots
        # with the current one at index -2
        mock_restic_client.get_snapshots.return_value = [
            ResticSnapshotId("e5f6a7b8"),
            ResticSnapshotId("a1b2c3d4"),
            ResticSnapshotId("c9d0e1f2"),
        ]
        mock_restic_client.diff.return_value = make_diff_ndjson()
        mock_restic_client.find.return_value = make_find_json()
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
        snapshot_id = ResticSnapshotId("c9d0e1f2")
        mock_restic_client.backup.return_value = snapshot_id
        mock_restic_client.get_snapshots.return_value = [
            ResticSnapshotId("e5f6a7b8"),
            ResticSnapshotId("a1b2c3d4"),
            ResticSnapshotId("c9d0e1f2"),
        ]
        mock_restic_client.find.return_value = make_find_json()
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
        snapshot_id = ResticSnapshotId("c9d0e1f2")
        mock_restic_client.backup.return_value = snapshot_id
        mock_restic_client.get_snapshots.return_value = [
            ResticSnapshotId("e5f6a7b8"),
            ResticSnapshotId("a1b2c3d4"),
            ResticSnapshotId("c9d0e1f2"),
        ]
        mock_restic_client.find.return_value = make_find_json()
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
            assert "skipped" in call_args[1]["subject"]

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
            assert "skipped" in call_args[1]["subject"]

    def test_run_backup_verification_success(
        self,
        temp_config,
        mock_lock_manager,
    ) -> None:
        """Test that backup verification succeeds when file is found."""
        config_file, _, _ = temp_config

        mock_restic_client = Mock()
        snapshot_id = ResticSnapshotId("87654321")
        mock_restic_client.backup.return_value = snapshot_id
        mock_restic_client.get_snapshots.return_value = [
            ResticSnapshotId("12345678"),
            ResticSnapshotId("a1b2c3d4"),
            ResticSnapshotId("87654321"),
        ]
        mock_restic_client.diff.return_value = make_diff_ndjson()
        mock_restic_client.find.return_value = make_find_json()
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
        """Test that verification failure raises, emails once, and skips maintenance."""
        config_file, _, _ = temp_config

        mock_restic_client = Mock()
        mock_restic_client.backup.return_value = ResticSnapshotId("a1b2c3d6")
        mock_restic_client.get_snapshots.return_value = [
            ResticSnapshotId("a1b2c3d5"),
            ResticSnapshotId("abc123de"),
            ResticSnapshotId("a1b2c3d6"),
        ]
        mock_restic_client.diff.return_value = make_diff_ndjson()
        mock_restic_client.find.return_value = make_find_json(found=False)
        mock_restic_client.session_log = Path("/tmp/restic_session.log")
        mock_restic_client.session_log.touch()

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
            with pytest.raises(VerificationError):
                backup_script.run()

            failure_subjects = [
                call.kwargs.get("subject", "")
                for call in mock_encrypted_mail.send_mail_with_retries.call_args_list
            ]
            assert sum("verification failed" in s for s in failure_subjects) == 1
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
        snapshot_id = ResticSnapshotId("87654321")
        mock_restic_client.backup.return_value = snapshot_id
        mock_restic_client.get_snapshots.return_value = [
            ResticSnapshotId("12345678"),
            ResticSnapshotId("a1b2c3d4"),
            ResticSnapshotId("87654321"),
        ]
        mock_restic_client.diff.return_value = make_diff_ndjson()
        mock_restic_client.find.return_value = make_find_json()
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
            mock_restic_client.check.assert_called_once()
            mock_restic_client.prune.assert_called_once()
            # Prune must run only after a successful repository check
            maintenance_names = [
                call[0]
                for call in mock_restic_client.method_calls
                if call[0] in {"forget", "cache_cleanup", "check", "prune"}
            ]
            assert maintenance_names == [
                "forget",
                "cache_cleanup",
                "check",
                "prune",
            ]

    def test_run_backup_maintenance_skips_prune_when_check_fails(
        self,
        temp_config,
        mock_lock_manager,
    ) -> None:
        """Test that prune is skipped when repository check reports problems."""
        config_file, _, _ = temp_config

        mock_restic_client = Mock()
        snapshot_id = ResticSnapshotId("87654321")
        mock_restic_client.backup.return_value = snapshot_id
        mock_restic_client.get_snapshots.return_value = [
            ResticSnapshotId("12345678"),
            ResticSnapshotId("a1b2c3d4"),
            ResticSnapshotId("87654321"),
        ]
        mock_restic_client.diff.return_value = make_diff_ndjson()
        mock_restic_client.find.return_value = make_find_json()
        mock_restic_client.check.return_value = "error: pack is damaged"
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

            mock_restic_client.forget.assert_called_once()
            mock_restic_client.cache_cleanup.assert_called_once()
            mock_restic_client.check.assert_called_once()
            mock_restic_client.prune.assert_not_called()

            warning_subjects = [
                call.kwargs.get("subject", "")
                for call in mock_encrypted_mail.send_mail_with_retries.call_args_list
            ]
            assert any(
                "completed with warnings" in subject for subject in warning_subjects
            )

    def test_generate_diff_summary_success(
        self,
        temp_config,
        mock_lock_manager,
    ) -> None:
        """Test that diff summary is generated successfully between snapshots."""
        config_file, _, _ = temp_config

        mock_restic_client = Mock()

        snapshot_id = ResticSnapshotId("87654321")
        mock_restic_client.backup.return_value = snapshot_id
        # Code expects snapshots[-2] to be current snapshot, snapshots[-3] to be previous
        mock_restic_client.get_snapshots.return_value = [
            ResticSnapshotId("12345678"),
            ResticSnapshotId("a1b2c3d4"),
            ResticSnapshotId("87654321"),
        ]
        mock_restic_client.diff.return_value = make_diff_ndjson(changed_files=10)
        mock_restic_client.find.return_value = make_find_json()
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

        snapshot_id = ResticSnapshotId("a1b2c3d4")
        mock_restic_client.backup.return_value = snapshot_id
        mock_restic_client.get_snapshots.return_value = [
            ResticSnapshotId("a1b2c3d4"),
        ]  # Only one snapshot
        mock_restic_client.find.return_value = make_find_json()
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
        snapshot_id = ResticSnapshotId("a1b2c3d6")
        mock_restic_client.backup.return_value = snapshot_id
        # Code expects snapshots[-2] to be current snapshot, snapshots[-3] to be previous
        mock_restic_client.get_snapshots.return_value = [
            ResticSnapshotId("a1b2c3d5"),
            ResticSnapshotId("a1b2c3d4"),
            ResticSnapshotId("a1b2c3d6"),
        ]
        # Create diff output with 10 deleted files (exceeds threshold of 5)
        diff_output = make_diff_ndjson(
            [("-", f"/path/to/file{i}.txt") for i in range(10)],
        )
        mock_restic_client.diff.return_value = diff_output
        mock_restic_client.find.return_value = make_find_json()
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

        snapshot_id = ResticSnapshotId("87654321")
        mock_restic_client.backup.return_value = snapshot_id
        # Code expects snapshots[-2] to be current snapshot, snapshots[-3] to be previous
        mock_restic_client.get_snapshots.return_value = [
            ResticSnapshotId("12345678"),
            ResticSnapshotId("a1b2c3d4"),
            ResticSnapshotId("87654321"),
        ]
        # Create diff output with 10 modified files (exceeds threshold of 5)
        diff_output = make_diff_ndjson(
            [("M", f"/path/to/file{i}.txt") for i in range(10)],
        )
        mock_restic_client.diff.return_value = diff_output
        mock_restic_client.find.return_value = make_find_json()
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

        snapshot_id = ResticSnapshotId("87654321")
        mock_restic_client.backup.return_value = snapshot_id
        # Code expects snapshots[-2] to be current snapshot, snapshots[-3] to be previous
        mock_restic_client.get_snapshots.return_value = [
            ResticSnapshotId("12345678"),
            ResticSnapshotId("a1b2c3d4"),
            ResticSnapshotId("87654321"),
        ]
        # Create diff output with files in monitored folder
        diff_output = make_diff_ndjson(
            [
                ("-", "/important/folder/file1.txt"),
                ("M", "/important/folder/file2.txt"),
            ],
        )
        mock_restic_client.diff.return_value = diff_output
        mock_restic_client.find.return_value = make_find_json()
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

    def test_monitored_folder_alerts_cover_all_change_types(
        self,
        temp_config,
        mock_lock_manager,
    ) -> None:
        """Test that added, altered and deleted files in a monitored folder all alert."""
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
        snapshot_id = ResticSnapshotId("87654321")
        mock_restic_client.backup.return_value = snapshot_id
        mock_restic_client.get_snapshots.return_value = [
            ResticSnapshotId("12345678"),
            ResticSnapshotId("a1b2c3d4"),
            ResticSnapshotId("87654321"),
        ]
        # One added (+), one modified (M) and one deleted (-) file in the folder
        mock_restic_client.diff.return_value = make_diff_ndjson(
            [
                ("+", "/important/folder/new.txt"),
                ("M", "/important/folder/changed.txt"),
                ("-", "/important/folder/gone.txt"),
            ],
        )
        mock_restic_client.find.return_value = make_find_json()
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

            calls = [
                str(call)
                for call in mock_encrypted_mail.send_mail_with_retries.call_args_list
            ]
            monitored_calls = [
                call for call in calls if "monitored folder" in call.lower()
            ]
            # Every change type must produce a monitored-folder alert
            assert any("added in monitored folder" in call for call in monitored_calls)
            assert any(
                "altered in monitored folder" in call for call in monitored_calls
            )
            assert any(
                "deleted in monitored folder" in call for call in monitored_calls
            )

    def test_run_aborts_on_empty_source(
        self,
        temp_config,
        mock_lock_manager,
    ) -> None:
        """Test that the backup is aborted when the source directory is empty."""
        config_file, _, backup_source = temp_config

        # Remove the fixture's entry so the source becomes empty
        for entry in backup_source.iterdir():
            entry.unlink()

        mock_restic_client = Mock()
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

            with pytest.raises(EmptySourceError):
                backup_script.run()

            # Backup must not be attempted for an empty source
            mock_restic_client.backup.assert_not_called()

    def test_run_addition_threshold_warning(
        self,
        temp_config,
        mock_lock_manager,
    ) -> None:
        """Test that a warning email is sent when the addition threshold is exceeded."""
        config_file, email_settings, backup_source = temp_config
        config_data: dict[str, str | int | list[str]] = {
            "backup_source": str(backup_source),
            "excluded_files": ["*.tmp"],
            "backup_target": "sftp:user@host:/repo",
            "password_lookup_1": "service",
            "password_lookup_2": "username",
            "email_settings_path": str(email_settings),
            "file_to_check": "important_file.txt",
            "addition_threshold": 5,
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
            f"addition_threshold: {config_data['addition_threshold']}\n",
        )

        mock_restic_client = Mock()
        snapshot_id = ResticSnapshotId("87654321")
        mock_restic_client.backup.return_value = snapshot_id
        mock_restic_client.get_snapshots.return_value = [
            ResticSnapshotId("12345678"),
            ResticSnapshotId("a1b2c3d4"),
            ResticSnapshotId("87654321"),
        ]
        # 10 added files exceeds the addition threshold of 5
        diff_output = make_diff_ndjson(
            [("+", f"/path/to/file{i}.txt") for i in range(10)],
        )
        mock_restic_client.diff.return_value = diff_output
        mock_restic_client.find.return_value = make_find_json()
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

            calls = [
                str(call)
                for call in mock_encrypted_mail.send_mail_with_retries.call_args_list
            ]
            assert any("files added (threshold" in call for call in calls)

    def test_check_read_data_subset_passed_to_check(
        self,
        temp_config,
        mock_lock_manager,
    ) -> None:
        """Test that the configured check_read_data_subset is passed to restic check."""
        config_file, email_settings, backup_source = temp_config
        config_data: dict[str, str | list[str]] = {
            "backup_source": str(backup_source),
            "excluded_files": ["*.tmp"],
            "backup_target": "sftp:user@host:/repo",
            "password_lookup_1": "service",
            "password_lookup_2": "username",
            "email_settings_path": str(email_settings),
            "file_to_check": "important_file.txt",
            "check_read_data_subset": "100%",
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
            f"check_read_data_subset: '{config_data['check_read_data_subset']}'\n",
        )

        mock_restic_client = Mock()
        snapshot_id = ResticSnapshotId("87654321")
        mock_restic_client.backup.return_value = snapshot_id
        mock_restic_client.get_snapshots.return_value = [
            ResticSnapshotId("12345678"),
            ResticSnapshotId("a1b2c3d4"),
            ResticSnapshotId("87654321"),
        ]
        mock_restic_client.diff.return_value = make_diff_ndjson()
        mock_restic_client.find.return_value = make_find_json()
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

            mock_restic_client.check.assert_called_once_with("100%")

    def test_run_backup_failure_sends_email(
        self,
        temp_config,
        mock_lock_manager,
    ) -> None:
        """Test that backup failure sends error email with log attachment."""
        config_file, _, _ = temp_config

        mock_restic_client = Mock()
        mock_restic_client.backup.side_effect = ResticBackupFailedError("Backup failed")
        mock_restic_client.session_log = Path("/tmp/restic_session.log")
        mock_restic_client.session_log.touch()

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

            # Verify error email was sent with full session log attachment
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
                if "failed" in str(kwargs.get("subject", "")).lower():
                    backup_failure_call = call
                    break

            assert backup_failure_call is not None, "Backup failure email was not sent"
            kwargs = (
                backup_failure_call.kwargs
                if hasattr(backup_failure_call, "kwargs")
                else backup_failure_call[1]
            )
            assert kwargs.get("mail_attachment") == str(mock_restic_client.session_log)

    def test_backup_retries_once_after_repository_lock(
        self,
        temp_config,
        mock_lock_manager,
    ) -> None:
        """Test that a stale repository lock triggers unlock and a single retry."""
        config_file, _, _ = temp_config

        mock_restic_client = Mock()
        snapshot_id = ResticSnapshotId("c9d0e1f2")
        # First backup attempt hits a repository lock, the retry succeeds.
        mock_restic_client.backup.side_effect = [
            ResticRepositoryLockedError("repository is already locked"),
            snapshot_id,
        ]
        mock_restic_client.get_snapshots.return_value = [
            ResticSnapshotId("e5f6a7b8"),
            ResticSnapshotId("a1b2c3d4"),
            ResticSnapshotId("c9d0e1f2"),
        ]
        mock_restic_client.diff.return_value = make_diff_ndjson()
        mock_restic_client.find.return_value = make_find_json()
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

            assert mock_restic_client.backup.call_count == 2
            mock_restic_client.unlock.assert_called_once()

    def test_backup_fails_when_still_locked_after_unlock(
        self,
        temp_config,
        mock_lock_manager,
    ) -> None:
        """Test that a persistent repository lock fails after a single retry."""
        config_file, _, _ = temp_config

        mock_restic_client = Mock()
        mock_restic_client.backup.side_effect = ResticRepositoryLockedError(
            "repository is already locked",
        )
        mock_restic_client.log_file = Path("/tmp/restic.log")
        mock_restic_client.log_file.touch()

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

            with pytest.raises(ResticRepositoryLockedError):
                backup_script.run()

            # Original attempt plus exactly one retry.
            assert mock_restic_client.backup.call_count == 2
            mock_restic_client.unlock.assert_called_once()

    def test_check_retries_once_after_repository_lock(
        self,
        temp_config,
        mock_lock_manager,
    ) -> None:
        """Test that a locked repository during check unlocks and retries once."""
        config_file, _, _ = temp_config

        mock_restic_client = Mock()
        snapshot_id = ResticSnapshotId("c9d0e1f2")
        mock_restic_client.backup.return_value = snapshot_id
        mock_restic_client.get_snapshots.return_value = [
            ResticSnapshotId("e5f6a7b8"),
            ResticSnapshotId("a1b2c3d4"),
            ResticSnapshotId("c9d0e1f2"),
        ]
        mock_restic_client.diff.return_value = make_diff_ndjson()
        mock_restic_client.find.return_value = make_find_json()
        # check() does not raise; the lock surfaces as text in the output.
        mock_restic_client.check.side_effect = [
            "unable to create lock in backend: repository is already locked",
            "no errors were found",
        ]
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

            assert mock_restic_client.check.call_count == 2
            mock_restic_client.unlock.assert_called_once()


if __name__ == "__main__":
    pytest.main([__file__])

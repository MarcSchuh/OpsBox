"""Tests for the restic_client module."""

import logging
import subprocess
import tempfile
from pathlib import Path
from unittest.mock import Mock, patch

import pytest

from opsbox.backup.exceptions import ResticCommandFailedError, SnapshotIDNotFoundError
from opsbox.backup.restic_client import ResticClient
from opsbox.backup.snapshot_id import ResticSnapshotId
from opsbox.encrypted_mail import EncryptedMail


class TestResticClient:
    """Test cases for ResticClient functionality."""

    @pytest.fixture
    def logger(self) -> Mock:
        """Create a mock logger for testing."""
        return Mock(spec=logging.Logger)

    @pytest.fixture
    def encrypted_mail(self) -> Mock:
        """Create a mock EncryptedMail for testing."""
        return Mock(spec=EncryptedMail)

    @pytest.fixture
    def restic_client(self, logger, encrypted_mail) -> ResticClient:
        """Create a ResticClient instance for testing."""
        return ResticClient(
            restic_path="/snap/bin/restic",
            backup_target="sftp:user@host:/repo",
            logger=logger,
            encrypted_mail=encrypted_mail,
        )

    def test_set_environment_with_password(self, restic_client) -> None:
        """Test that RESTIC_PASSWORD environment variable is set."""
        restic_client.set_environment("test_password_123")

        env = restic_client._get_environment()
        assert env["RESTIC_PASSWORD"] == "test_password_123"
        assert "SSH_AUTH_SOCK" not in env

    def test_set_environment_with_ssh_auth_sock(self, restic_client) -> None:
        """Test that SSH_AUTH_SOCK is set when provided."""
        restic_client.set_environment(
            "test_password_123",
            ssh_auth_sock="/path/to/sock",
        )

        env = restic_client._get_environment()
        assert env["RESTIC_PASSWORD"] == "test_password_123"
        assert env["SSH_AUTH_SOCK"] == "/path/to/sock"

    def test_set_environment_not_set_raises_error(self, restic_client) -> None:
        """Test that _get_environment raises ValueError when environment is not set."""
        with pytest.raises(ValueError, match="Restic environment not set"):
            restic_client._get_environment()

    def test_backup_success(self, restic_client) -> None:
        """Test that backup executes successfully and returns snapshot ID."""
        restic_client.set_environment("test_password")

        mock_result = Mock()
        mock_result.returncode = 0

        with tempfile.TemporaryDirectory() as temp_dir:
            log_file = Path(temp_dir) / "restic.log"
            log_file.write_text("backup output\nsnapshot a1b2c3d4 created\n")

            with patch.object(restic_client, "log_file", log_file):
                with patch.object(
                    restic_client,
                    "_run_command",
                    return_value=mock_result,
                ):
                    snapshot_id = restic_client.backup("/backup/source", ["*.tmp"])

                    assert isinstance(snapshot_id, ResticSnapshotId)
                    assert snapshot_id == "a1b2c3d4"
                    restic_client.logger.info.assert_called()

    def test_backup_failure(self, restic_client) -> None:
        """Test that ResticCommandFailedError is raised on backup failure."""
        restic_client.set_environment("test_password")

        with patch.object(
            restic_client,
            "_run_command",
            side_effect=ResticCommandFailedError("Backup failed"),
        ):
            with pytest.raises(ResticCommandFailedError, match="Backup failed"):
                restic_client.backup("/backup/source", ["*.tmp"])

    def test_backup_snapshot_id_not_found(self, restic_client) -> None:
        """Test that SnapshotIDNotFoundError is raised when snapshot ID cannot be extracted."""
        restic_client.set_environment("test_password")

        mock_result = Mock()
        mock_result.returncode = 0

        with tempfile.TemporaryDirectory() as temp_dir:
            log_file = Path(temp_dir) / "restic.log"
            log_file.write_text("backup output without snapshot ID\n")

            with patch.object(restic_client, "log_file", log_file):
                with patch.object(
                    restic_client,
                    "_run_command",
                    return_value=mock_result,
                ):
                    with pytest.raises(
                        SnapshotIDNotFoundError,
                        match="Could not find snapshot ID",
                    ):
                        restic_client.backup("/backup/source", ["*.tmp"])

    def test_get_snapshots_success(self, restic_client) -> None:
        """Test that get_snapshots returns list of snapshot IDs."""
        restic_client.set_environment("test_password")

        mock_result = Mock()
        mock_result.returncode = 0
        mock_result.stdout = (
            "ID        Time                 Host        Tags        Paths\n"
            "------------------------------------------------------------------------------\n"
            "a1b2c3d4 2024-01-01 12:00:00  host   /path/to/backup\n"
            "e5f6a7b8 2024-01-02 12:00:00  host   /path/to/backup\n"
            "c9d0e1f2 2024-01-03 12:00:00  host   /path/to/backup\n"
            "------------------------------------------------------------------------------\n"
            "3 snapshots"
        )

        with patch.object(restic_client, "_run_command", return_value=mock_result):
            snapshots = restic_client.get_snapshots()

            assert len(snapshots) == 3
            assert all(isinstance(s, ResticSnapshotId) for s in snapshots)
            assert ResticSnapshotId("a1b2c3d4") in snapshots
            assert ResticSnapshotId("e5f6a7b8") in snapshots
            assert ResticSnapshotId("c9d0e1f2") in snapshots
            # Also test string comparison
            assert "a1b2c3d4" in [str(s) for s in snapshots]
            assert "e5f6a7b8" in [str(s) for s in snapshots]
            assert "c9d0e1f2" in [str(s) for s in snapshots]

    def test_get_snapshots_failure(self, restic_client) -> None:
        """Test that ResticCommandFailedError is raised on get_snapshots failure."""
        restic_client.set_environment("test_password")

        with patch.object(
            restic_client,
            "_run_command",
            side_effect=ResticCommandFailedError("Command failed"),
        ):
            with pytest.raises(ResticCommandFailedError, match="Command failed"):
                restic_client.get_snapshots()

    def test_diff_success(self, restic_client) -> None:
        """Test that diff returns output between snapshots."""
        restic_client.set_environment("test_password")

        mock_result = Mock()
        mock_result.returncode = 0
        mock_result.stdout = "diff output between snapshots"

        with patch.object(restic_client, "_run_command", return_value=mock_result):
            diff_output = restic_client.diff(
                ResticSnapshotId("a1b2c3d4"),
                ResticSnapshotId("e5f6a7b8"),
            )

            assert diff_output == "diff output between snapshots"
            restic_client.logger.info.assert_called()

    def test_diff_failure(self, restic_client) -> None:
        """Test that ResticCommandFailedError is raised on diff failure."""
        restic_client.set_environment("test_password")

        with patch.object(
            restic_client,
            "_run_command",
            side_effect=ResticCommandFailedError("Diff failed"),
        ):
            with pytest.raises(ResticCommandFailedError, match="Diff failed"):
                restic_client.diff(
                    ResticSnapshotId("a1b2c3d4"),
                    ResticSnapshotId("e5f6a7b8"),
                )

    def test_find_success(self, restic_client) -> None:
        """Test that find returns output when searching for files in snapshot."""
        restic_client.set_environment("test_password")

        mock_result = Mock()
        mock_result.returncode = 0
        mock_result.stdout = "Found matching entries in snapshot a1b2c3d4"

        with patch.object(restic_client, "_run_command", return_value=mock_result):
            find_output = restic_client.find("file.txt", ResticSnapshotId("a1b2c3d4"))

            assert "Found matching entries" in find_output

    def test_find_failure(self, restic_client) -> None:
        """Test that ResticCommandFailedError is raised on find failure."""
        restic_client.set_environment("test_password")

        with patch.object(
            restic_client,
            "_run_command",
            side_effect=ResticCommandFailedError("Find failed"),
        ):
            with pytest.raises(ResticCommandFailedError, match="Find failed"):
                restic_client.find("file.txt", ResticSnapshotId("a1b2c3d4"))

    def test_forget_success(self, restic_client) -> None:
        """Test that forget executes successfully."""
        restic_client.set_environment("test_password")

        mock_result = Mock()
        mock_result.returncode = 0

        with patch.object(restic_client, "_run_command", return_value=mock_result):
            restic_client.forget("10", "21", "5")

            restic_client.logger.info.assert_called()
            restic_client._run_command.assert_called_once()

    def test_forget_failure(self, restic_client) -> None:
        """Test that ResticCommandFailedError is raised on forget failure."""
        restic_client.set_environment("test_password")

        with patch.object(
            restic_client,
            "_run_command",
            side_effect=ResticCommandFailedError("Forget failed"),
        ):
            with pytest.raises(ResticCommandFailedError, match="Forget failed"):
                restic_client.forget("10", "21", "5")

    def test_prune_success(self, restic_client) -> None:
        """Test that prune executes successfully."""
        restic_client.set_environment("test_password")

        mock_result = Mock()
        mock_result.returncode = 0

        with patch.object(restic_client, "_run_command", return_value=mock_result):
            restic_client.prune()

            restic_client.logger.info.assert_called()
            restic_client._run_command.assert_called_once()

    def test_prune_failure(self, restic_client) -> None:
        """Test that ResticCommandFailedError is raised on prune failure."""
        restic_client.set_environment("test_password")

        with patch.object(
            restic_client,
            "_run_command",
            side_effect=ResticCommandFailedError("Prune failed"),
        ):
            with pytest.raises(ResticCommandFailedError, match="Prune failed"):
                restic_client.prune()

    def test_cache_cleanup_success(self, restic_client) -> None:
        """Test that cache_cleanup executes successfully."""
        restic_client.set_environment("test_password")

        mock_result = Mock()
        mock_result.returncode = 0

        with patch.object(restic_client, "_run_command", return_value=mock_result):
            restic_client.cache_cleanup()

            restic_client.logger.info.assert_called()
            restic_client._run_command.assert_called_once()

    def test_cache_cleanup_failure(self, restic_client) -> None:
        """Test that ResticCommandFailedError is raised on cache_cleanup failure."""
        restic_client.set_environment("test_password")

        with patch.object(
            restic_client,
            "_run_command",
            side_effect=ResticCommandFailedError("Cleanup failed"),
        ):
            with pytest.raises(ResticCommandFailedError, match="Cleanup failed"):
                restic_client.cache_cleanup()

    def test_check_success(self, restic_client) -> None:
        """Test that check executes successfully and returns output."""
        restic_client.set_environment("test_password")

        mock_result = Mock()
        mock_result.returncode = 0
        mock_result.stdout = "no errors were found"

        with patch.object(restic_client, "_run_command", return_value=mock_result):
            check_output = restic_client.check()

            assert check_output == "no errors were found"
            restic_client.logger.info.assert_called()

    def test_check_failure(self, restic_client) -> None:
        """Test that ResticCommandFailedError is raised on check failure."""
        restic_client.set_environment("test_password")

        with patch.object(
            restic_client,
            "_run_command",
            side_effect=ResticCommandFailedError("Check failed"),
        ):
            with pytest.raises(ResticCommandFailedError, match="Check failed"):
                restic_client.check()

    def test_unlock_success(self, restic_client) -> None:
        """Test that unlock executes successfully (handles non-zero exit gracefully)."""
        restic_client.set_environment("test_password")

        mock_result = Mock()
        mock_result.returncode = 0

        with patch.object(restic_client, "_run_command", return_value=mock_result):
            restic_client.unlock()

            restic_client.logger.info.assert_called()

    def test_unlock_non_zero_exit(self, restic_client) -> None:
        """Test that unlock handles non-zero exit code gracefully."""
        restic_client.set_environment("test_password")

        mock_result = Mock()
        mock_result.returncode = 1

        with patch.object(restic_client, "_run_command", return_value=mock_result):
            restic_client.unlock()

            restic_client.logger.warning.assert_called()

    def test_extract_snapshot_id_success(self, restic_client) -> None:
        """Test that snapshot ID is extracted correctly from output."""
        output = "backup output\nsnapshot a1b2c3d4 created\nmore output"
        snapshot_id = restic_client._extract_snapshot_id(output)

        assert snapshot_id == "a1b2c3d4"

    def test_extract_snapshot_id_not_found(self, restic_client) -> None:
        """Test that SnapshotIDNotFoundError is raised when snapshot ID cannot be extracted."""
        output = "backup output without snapshot ID"

        with pytest.raises(SnapshotIDNotFoundError, match="Could not find snapshot ID"):
            restic_client._extract_snapshot_id(output)

    def test_run_command_timeout(self, restic_client) -> None:
        """Test that ResticCommandFailedError is raised on command timeout."""
        restic_client.set_environment("test_password")

        with tempfile.TemporaryDirectory() as temp_dir:
            log_file = Path(temp_dir) / "restic.log"
            log_file.touch()

            with patch.object(restic_client, "log_file", log_file):
                with patch(
                    "subprocess.run",
                    side_effect=subprocess.TimeoutExpired("restic", 3600),
                ):
                    with pytest.raises(
                        ResticCommandFailedError,
                        match="Command timed out",
                    ):
                        restic_client._run_command(["restic", "backup"])

    def test_run_command_subprocess_error(self, restic_client) -> None:
        """Test that ResticCommandFailedError is raised on subprocess error."""
        restic_client.set_environment("test_password")

        with tempfile.TemporaryDirectory() as temp_dir:
            log_file = Path(temp_dir) / "restic.log"
            log_file.touch()

            with patch.object(restic_client, "log_file", log_file):
                with patch(
                    "subprocess.run",
                    side_effect=subprocess.SubprocessError("Command failed"),
                ):
                    with pytest.raises(
                        ResticCommandFailedError,
                        match="Command failed",
                    ):
                        restic_client._run_command(["restic", "backup"])

    def test_send_error_email_on_failure(self, restic_client) -> None:
        """Test that error email is sent when command fails."""
        restic_client.set_environment("test_password")

        with tempfile.TemporaryDirectory() as temp_dir:
            log_file = Path(temp_dir) / "restic.log"
            log_file.write_text("error log content")

            mock_result = Mock()
            mock_result.returncode = 1

            with patch.object(restic_client, "log_file", log_file):
                with patch("subprocess.run", return_value=mock_result):
                    with pytest.raises(ResticCommandFailedError):
                        restic_client._run_command(["restic", "backup"])

                    # Verify error email was sent
                    restic_client.encrypted_mail.send_mail_with_retries.assert_called()


if __name__ == "__main__":
    pytest.main([__file__])

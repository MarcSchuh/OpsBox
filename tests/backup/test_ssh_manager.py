"""Tests for the ssh_manager module."""

import logging
import os
import subprocess
from unittest.mock import Mock, patch

import pytest

from opsbox.backup.exceptions import SSHKeyNotFoundError, UserDoesNotExistError
from opsbox.backup.ssh_manager import SSHManager


class TestSSHManager:
    """Test cases for SSHManager functionality."""

    @pytest.fixture
    def logger(self) -> Mock:
        """Create a mock logger for testing."""
        return Mock(spec=logging.Logger)

    @pytest.fixture
    def ssh_manager(self, logger) -> SSHManager:
        """Create a SSHManager instance for testing."""
        return SSHManager(logger)

    def test_get_ssh_auth_sock_success(self, ssh_manager) -> None:
        """Test that SSH auth socket is returned for existing user."""
        mock_user_info = Mock()
        mock_user_info.pw_uid = 1000

        with patch("pwd.getpwnam", return_value=mock_user_info):
            with patch.dict(os.environ, {}, clear=False):
                auth_sock = ssh_manager.get_ssh_auth_sock("testuser")

                assert auth_sock == "/run/user/1000/keyring/ssh"

    def test_get_ssh_auth_sock_with_env_var(self, ssh_manager) -> None:
        """Test that existing SSH_AUTH_SOCK environment variable is used."""
        mock_user_info = Mock()
        mock_user_info.pw_uid = 1000

        with patch("pwd.getpwnam", return_value=mock_user_info):
            with patch.dict(
                os.environ,
                {"SSH_AUTH_SOCK": "/custom/path/sock"},
                clear=False,
            ):
                auth_sock = ssh_manager.get_ssh_auth_sock("testuser")

                assert auth_sock == "/custom/path/sock"

    def test_get_ssh_auth_sock_user_not_found(self, ssh_manager) -> None:
        """Test that UserDoesNotExistError is raised for non-existent user."""
        with patch("pwd.getpwnam", side_effect=KeyError("User not found")):
            with pytest.raises(
                UserDoesNotExistError,
                match="User nonexistent does not exist",
            ):
                ssh_manager.get_ssh_auth_sock("nonexistent")

    def test_ensure_ssh_key_loaded_already_loaded(self, ssh_manager) -> None:
        """Test that ensure_ssh_key_loaded returns immediately when key is already loaded."""
        mock_user_info = Mock()
        mock_user_info.pw_uid = 1000

        mock_result = Mock()
        mock_result.returncode = 0
        mock_result.stdout = "2048 SHA256:key_fingerprint test@example.com (RSA)"

        with patch("pwd.getpwnam", return_value=mock_user_info):
            with patch.dict(os.environ, {}, clear=False):
                with patch("subprocess.run", return_value=mock_result):
                    # Key is already loaded
                    ssh_manager.ensure_ssh_key_loaded(
                        "SHA256:key_fingerprint",
                        "testuser",
                        max_retries=1,
                    )

                    ssh_manager.logger.info.assert_called()

    def test_ensure_ssh_key_loaded_success_after_retry(self, ssh_manager) -> None:
        """Test that ensure_ssh_key_loaded succeeds after retry."""
        mock_user_info = Mock()
        mock_user_info.pw_uid = 1000

        # First call: key not found, second call: key found
        mock_results = [
            Mock(
                returncode=0,
                stdout="2048 SHA256:other_key test@example.com (RSA)",
            ),  # Key not found
            Mock(
                returncode=0,
                stdout="2048 SHA256:key_fingerprint test@example.com (RSA)",
            ),  # Key found
        ]

        with patch("pwd.getpwnam", return_value=mock_user_info):
            with patch.dict(os.environ, {}, clear=False):
                with patch("subprocess.run", side_effect=mock_results):
                    with patch("time.sleep"):  # Skip actual sleep in tests
                        ssh_manager.ensure_ssh_key_loaded(
                            "SHA256:key_fingerprint",
                            "testuser",
                            max_retries=2,
                            retry_delay=0,
                        )

                        ssh_manager.logger.info.assert_called()

    def test_ensure_ssh_key_loaded_failure_after_max_retries(self, ssh_manager) -> None:
        """Test that SSHKeyNotFoundError is raised after max retries."""
        mock_user_info = Mock()
        mock_user_info.pw_uid = 1000

        mock_result = Mock()
        mock_result.returncode = 0
        mock_result.stdout = (
            "2048 SHA256:other_key test@example.com (RSA)"  # Different key
        )

        with patch("pwd.getpwnam", return_value=mock_user_info):
            with patch.dict(os.environ, {}, clear=False):
                with patch("subprocess.run", return_value=mock_result):
                    with patch("time.sleep"):  # Skip actual sleep in tests
                        with pytest.raises(
                            SSHKeyNotFoundError,
                            match="Failed to get correct SSH key after",
                        ):
                            ssh_manager.ensure_ssh_key_loaded(
                                "SHA256:key_fingerprint",
                                "testuser",
                                max_retries=2,
                                retry_delay=0,
                            )

    def test_ensure_ssh_key_loaded_ssh_add_timeout(self, ssh_manager) -> None:
        """Test that ensure_ssh_key_loaded handles ssh-add timeout gracefully."""
        mock_user_info = Mock()
        mock_user_info.pw_uid = 1000

        with patch("pwd.getpwnam", return_value=mock_user_info):
            with patch.dict(os.environ, {}, clear=False):
                with patch(
                    "subprocess.run",
                    side_effect=subprocess.TimeoutExpired("ssh-add", 30),
                ):
                    with patch("time.sleep"):  # Skip actual sleep in tests
                        with pytest.raises(
                            SSHKeyNotFoundError,
                            match="Failed to get correct SSH key after",
                        ):
                            ssh_manager.ensure_ssh_key_loaded(
                                "SHA256:key_fingerprint",
                                "testuser",
                                max_retries=1,
                                retry_delay=0,
                            )

    def test_ensure_ssh_key_loaded_ssh_add_error(self, ssh_manager) -> None:
        """Test that ensure_ssh_key_loaded handles ssh-add errors gracefully."""
        mock_user_info = Mock()
        mock_user_info.pw_uid = 1000

        with patch("pwd.getpwnam", return_value=mock_user_info):
            with patch.dict(os.environ, {}, clear=False):
                with patch(
                    "subprocess.run",
                    side_effect=subprocess.SubprocessError("Command failed"),
                ):
                    with patch("time.sleep"):  # Skip actual sleep in tests
                        with pytest.raises(
                            SSHKeyNotFoundError,
                            match="Failed to get correct SSH key after",
                        ):
                            ssh_manager.ensure_ssh_key_loaded(
                                "SHA256:key_fingerprint",
                                "testuser",
                                max_retries=1,
                                retry_delay=0,
                            )

    def test_is_key_loaded_success(self, ssh_manager) -> None:
        """Test that _is_key_loaded returns True when key is found."""
        mock_result = Mock()
        mock_result.returncode = 0
        mock_result.stdout = "2048 SHA256:key_fingerprint test@example.com (RSA)"

        with patch("subprocess.run", return_value=mock_result):
            result = ssh_manager._is_key_loaded("SHA256:key_fingerprint", {})

            assert result is True

    def test_is_key_loaded_not_found(self, ssh_manager) -> None:
        """Test that _is_key_loaded returns False when key is not found."""
        mock_result = Mock()
        mock_result.returncode = 0
        mock_result.stdout = "2048 SHA256:other_key test@example.com (RSA)"

        with patch("subprocess.run", return_value=mock_result):
            result = ssh_manager._is_key_loaded("SHA256:key_fingerprint", {})

            assert result is False

    def test_is_key_loaded_non_zero_exit(self, ssh_manager) -> None:
        """Test that _is_key_loaded returns False when ssh-add returns non-zero exit code."""
        mock_result = Mock()
        mock_result.returncode = 1
        mock_result.stdout = ""

        with patch("subprocess.run", return_value=mock_result):
            result = ssh_manager._is_key_loaded("SHA256:key_fingerprint", {})

            assert result is False


if __name__ == "__main__":
    pytest.main([__file__])

"""Tests for the password_manager module."""

import logging
import subprocess
from unittest.mock import Mock, patch

import pytest

from opsbox.backup.exceptions import PasswordIsEmptyError, PasswordRetrievalFailedError
from opsbox.backup.password_manager import PasswordManager


class TestPasswordManager:
    """Test cases for PasswordManager functionality."""

    @pytest.fixture
    def logger(self) -> Mock:
        """Create a mock logger for testing."""
        return Mock(spec=logging.Logger)

    @pytest.fixture
    def password_manager(self, logger) -> PasswordManager:
        """Create a PasswordManager instance for testing."""
        return PasswordManager(logger)

    def test_get_restic_password_with_direct_password(self, password_manager) -> None:
        """Test that password is returned when provided directly."""
        password = password_manager.get_restic_password(
            password_lookup_1="service",
            password_lookup_2="username",
            restic_password="direct_password_123",
        )

        assert password == "direct_password_123"
        password_manager.logger.debug.assert_called()

    def test_get_restic_password_from_secret_tool(self, password_manager) -> None:
        """Test that password is retrieved from secret-tool successfully."""
        mock_result = Mock()
        mock_result.returncode = 0
        mock_result.stdout = "retrieved_password_123\n"

        with patch("subprocess.run", return_value=mock_result):
            password = password_manager.get_restic_password(
                password_lookup_1="service",
                password_lookup_2="username",
                restic_password=None,
            )

            assert password == "retrieved_password_123"
            password_manager.logger.debug.assert_called()

    def test_get_restic_password_empty_direct_password(self, password_manager) -> None:
        """Test that PasswordIsEmptyError is raised for empty direct password."""
        with pytest.raises(
            PasswordIsEmptyError,
            match="Provided restic password is empty",
        ):
            password_manager.get_restic_password(
                password_lookup_1="service",
                password_lookup_2="username",
                restic_password="   ",  # Whitespace only
            )

    def test_get_restic_password_empty_from_secret_tool(self, password_manager) -> None:
        """Test that PasswordIsEmptyError is raised for empty retrieved password."""
        mock_result = Mock()
        mock_result.returncode = 0
        mock_result.stdout = "   \n"  # Whitespace only

        with patch("subprocess.run", return_value=mock_result):
            with pytest.raises(
                PasswordIsEmptyError,
                match="Retrieved password is empty",
            ):
                password_manager.get_restic_password(
                    password_lookup_1="service",
                    password_lookup_2="username",
                    restic_password=None,
                )

    def test_get_restic_password_secret_tool_not_found(self, password_manager) -> None:
        """Test that PasswordRetrievalFailedError is raised when secret-tool is not found."""
        with patch(
            "subprocess.run",
            side_effect=FileNotFoundError("secret-tool not found"),
        ):
            with pytest.raises(
                PasswordRetrievalFailedError,
                match="secret-tool command not found",
            ):
                password_manager.get_restic_password(
                    password_lookup_1="service",
                    password_lookup_2="username",
                    restic_password=None,
                )

    def test_get_restic_password_secret_tool_timeout(self, password_manager) -> None:
        """Test that PasswordRetrievalFailedError is raised when secret-tool times out."""
        with patch(
            "subprocess.run",
            side_effect=subprocess.TimeoutExpired("secret-tool", 30),
        ):
            with pytest.raises(
                PasswordRetrievalFailedError,
                match="secret-tool command timed out",
            ):
                password_manager.get_restic_password(
                    password_lookup_1="service",
                    password_lookup_2="username",
                    restic_password=None,
                )

    def test_get_restic_password_secret_tool_failure(self, password_manager) -> None:
        """Test that PasswordRetrievalFailedError is raised when secret-tool command fails."""
        mock_result = Mock()
        mock_result.returncode = 1
        mock_result.stderr = "No matching secret found"

        with patch(
            "subprocess.run",
            side_effect=subprocess.CalledProcessError(
                1,
                "secret-tool",
                stderr="No matching secret found",
            ),
        ):
            with pytest.raises(
                PasswordRetrievalFailedError,
                match="secret-tool command failed",
            ):
                password_manager.get_restic_password(
                    password_lookup_1="service",
                    password_lookup_2="username",
                    restic_password=None,
                )

    def test_get_restic_password_secret_tool_non_zero_exit(
        self,
        password_manager,
    ) -> None:
        """Test that PasswordRetrievalFailedError is raised when secret-tool returns non-zero exit code."""
        mock_result = Mock()
        mock_result.returncode = 1
        mock_result.stderr = "Error message"

        with patch("subprocess.run", return_value=mock_result):
            with pytest.raises(
                PasswordRetrievalFailedError,
                match="secret-tool returned non-zero exit code",
            ):
                password_manager.get_restic_password(
                    password_lookup_1="service",
                    password_lookup_2="username",
                    restic_password=None,
                )

    def test_validate_password_strength_valid(self, password_manager) -> None:
        """Test that validate_password_strength returns True for valid password length."""
        assert password_manager.validate_password_strength("valid_password_123") is True
        assert (
            password_manager.validate_password_strength("12345678") is True
        )  # Exactly minimum length

    def test_validate_password_strength_too_short(self, password_manager) -> None:
        """Test that validate_password_strength returns False for password shorter than minimum."""
        assert password_manager.validate_password_strength("short") is False
        assert password_manager.validate_password_strength("") is False
        password_manager.logger.warning.assert_called()

    def test_validate_password_strength_none(self, password_manager) -> None:
        """Test that validate_password_strength returns False for None password."""
        assert password_manager.validate_password_strength(None) is False  # type: ignore[arg-type]

    def test_get_restic_password_strips_whitespace(self, password_manager) -> None:
        """Test that retrieved password has whitespace stripped."""
        mock_result = Mock()
        mock_result.returncode = 0
        mock_result.stdout = "  password_with_whitespace  \n"

        with patch("subprocess.run", return_value=mock_result):
            password = password_manager.get_restic_password(
                password_lookup_1="service",
                password_lookup_2="username",
                restic_password=None,
            )

            assert password == "password_with_whitespace"


if __name__ == "__main__":
    pytest.main([__file__])

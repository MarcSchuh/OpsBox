"""Secure password management for backup operations."""

import logging
import subprocess

from opsbox.backup.exceptions import PasswordIsEmptyError, PasswordRetrievalFailedError


class PasswordManager:
    """Handles secure password retrieval and management."""

    MIN_PASSWORD_LENGTH = 8

    def __init__(self, logger: logging.Logger) -> None:
        """Initialize the password manager with a logger."""
        self.logger = logger

    def get_restic_password(
        self,
        password_lookup_1: str,
        password_lookup_2: str,
        restic_password: str | None = None,
    ) -> str:
        """Retrieve the restic password securely.

        Args:
            password_lookup_1: First lookup parameter for secret-tool
            password_lookup_2: Second lookup parameter for secret-tool
            restic_password: Direct password (if provided, overrides secret-tool lookup)

        Returns:
            The restic password

        Raises:
            PasswordRetrievalFailedError: If password retrieval fails
            PasswordIsEmptyError: If retrieved password is empty

        """
        # If password is provided directly, use it
        if restic_password:
            if not restic_password.strip():
                error_msg = "Provided restic password is empty"
                self.logger.error(error_msg)
                raise PasswordIsEmptyError(error_msg)
            self.logger.debug("Using provided restic password")
            return restic_password

        # Otherwise, retrieve from secret-tool
        self.logger.debug("Retrieving password from secret-tool")
        password = self._retrieve_from_secret_tool(password_lookup_1, password_lookup_2)

        if not password.strip():
            error_msg = "Retrieved password is empty"
            self.logger.error(error_msg)
            raise PasswordIsEmptyError(error_msg)

        self.logger.debug("Password retrieved successfully from secret-tool")
        return password

    def _retrieve_from_secret_tool(self, lookup_1: str, lookup_2: str) -> str:
        """Retrieve password from secret-tool.

        Args:
            lookup_1: First lookup parameter
            lookup_2: Second lookup parameter

        Returns:
            The retrieved password

        Raises:
            PasswordRetrievalFailedError: If secret-tool command fails

        """
        try:
            cmd = [
                "secret-tool",
                "lookup",
                lookup_1,
                lookup_2,
            ]

            result = subprocess.run(  # noqa: S603
                cmd,
                capture_output=True,
                text=True,
                timeout=30,  # 30 second timeout
                check=True,
            )

            if result.returncode != 0:
                error_msg = (
                    f"secret-tool returned non-zero exit code: {result.stderr.strip()}"
                )
                self.logger.error(error_msg)
                raise PasswordRetrievalFailedError(error_msg)  # noqa: TRY301

            return result.stdout.strip()

        except subprocess.TimeoutExpired as e:
            error_msg = "secret-tool command timed out"
            self.logger.exception(error_msg)
            raise PasswordRetrievalFailedError(error_msg) from e
        except subprocess.CalledProcessError as e:
            error_msg = f"secret-tool command failed: {e.stderr.strip() if e.stderr else str(e)}"
            self.logger.exception(error_msg)
            raise PasswordRetrievalFailedError(error_msg) from e
        except FileNotFoundError as e:
            error_msg = "secret-tool command not found. Please install libsecret-tools."
            self.logger.exception(error_msg)
            raise PasswordRetrievalFailedError(error_msg) from e
        except Exception as e:
            error_msg = f"Unexpected error retrieving password: {e}"
            self.logger.exception(error_msg)
            raise PasswordRetrievalFailedError(error_msg) from e

    def validate_password_strength(self, password: str) -> bool:
        """Validate password strength (basic validation).

        Args:
            password: Password to validate

        Returns:
            True if password meets basic strength requirements

        """
        if not password:
            return False

        # Basic validation - password should be at least MIN_PASSWORD_LENGTH characters
        if len(password) < self.MIN_PASSWORD_LENGTH:
            self.logger.warning(
                f"Password is shorter than recommended minimum length ({self.MIN_PASSWORD_LENGTH} characters)",
            )
            return False

        return True

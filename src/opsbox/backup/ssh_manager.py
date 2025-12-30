"""SSH key management for backup operations."""

import logging
import os
import pwd
import subprocess
import time

from opsbox.backup.exceptions import SSHKeyNotFoundError, UserDoesNotExistError


class SSHManager:
    """Manages SSH key operations for backup connections."""

    def __init__(self, logger: logging.Logger) -> None:
        """Initialize the SSH manager with a logger."""
        self.logger = logger

    def get_ssh_auth_sock(self, ssh_user: str) -> str:
        """Get the SSH auth socket for the specified user."""
        try:
            user_info = pwd.getpwnam(ssh_user)
            return os.getenv(
                "SSH_AUTH_SOCK",
                f"/run/user/{user_info.pw_uid}/keyring/ssh",
            )
        except KeyError as e:
            self.logger.exception(f"User {ssh_user} does not exist.")
            error_msg = f"User {ssh_user} does not exist."
            raise UserDoesNotExistError(error_msg) from e

    def ensure_ssh_key_loaded(
        self,
        ssh_key: str,
        ssh_user: str,
        max_retries: int = 12,
        retry_delay: int = 10,
    ) -> None:
        """Ensure the correct SSH key is loaded into the SSH agent.

        Args:
            ssh_key: The SSH key fingerprint to look for
            ssh_user: The user whose SSH agent to check
            max_retries: Maximum number of retry attempts
            retry_delay: Delay between retries in seconds

        Raises:
            SSHKeyNotFoundError: If the required SSH key is not found after max_retries

        """
        self.logger.info("Ensuring SSH key is loaded.")

        # Set up environment with correct SSH auth sock
        env = os.environ.copy()
        env["SSH_AUTH_SOCK"] = self.get_ssh_auth_sock(ssh_user)

        # Check if the key is already loaded
        if self._is_key_loaded(ssh_key, env):
            self.logger.info("SSH key is already loaded.")
            return

        # Retry loop for key loading
        for attempt in range(1, max_retries + 1):
            self.logger.info(f"SSH key not found, attempt {attempt}/{max_retries}")

            # Check again after waiting
            time.sleep(retry_delay)

            if self._is_key_loaded(ssh_key, env):
                self.logger.info("SSH key is now loaded.")
                return

        # If we get here, the key was never found
        error_message = f"Failed to get correct SSH key after {max_retries} attempts"
        self.logger.error(error_message)
        raise SSHKeyNotFoundError(error_message)

    def _is_key_loaded(self, ssh_key: str, env: dict) -> bool:
        """Check if the specified SSH key is loaded in the agent."""
        try:
            result = subprocess.run(
                ["ssh-add", "-l"],  # noqa: S607
                check=False,
                capture_output=True,
                text=True,
                env=env,
                timeout=30,
            )

            return result.returncode == 0 and ssh_key in result.stdout  # noqa: TRY300

        except subprocess.TimeoutExpired:
            self.logger.warning("SSH agent list command timed out")
        except subprocess.SubprocessError as e:
            self.logger.warning(f"SSH agent list command failed: {e}")

        return False

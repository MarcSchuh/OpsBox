"""Network connectivity checking for backup operations."""

import logging
import subprocess

from opsbox.backup.exceptions import NetworkUnreachableError


class NetworkChecker:
    """Handles network connectivity checks for backup operations."""

    def __init__(self, logger: logging.Logger) -> None:
        """Initialize the network checker with a logger."""
        self.logger = logger

    def check_network_connectivity(
        self,
        host: str,
        ping_count: int = 3,
        timeout: int = 30,
    ) -> bool:
        """Check if the specified host is reachable via ping.

        Args:
            host: The host to ping
            ping_count: Number of ping attempts
            timeout: Timeout in seconds for the entire ping operation

        Returns:
            True if host is reachable, False otherwise

        """
        self.logger.info(f"Checking network connectivity to {host}")

        try:
            cmd = ["ping", "-c", str(ping_count), host]
            result = subprocess.run(  # noqa: S603
                cmd,
                check=False,
                capture_output=True,
                text=True,
                timeout=timeout,
            )

            if result.returncode == 0 and "0% packet loss" in result.stdout:
                self.logger.info(f"Successfully reached {host}")
                return True
            self.logger.info(f"Cannot reach {host}")
            return False  # noqa: TRY300

        except subprocess.TimeoutExpired:
            self.logger.warning(f"Ping to {host} timed out after {timeout} seconds")
            return False
        except subprocess.SubprocessError as e:
            self.logger.warning(f"Ping to {host} failed: {e}")
            return False

    def check_network_connectivity_or_raise(
        self,
        host: str,
        ping_count: int = 3,
        timeout: int = 30,
    ) -> None:
        """Check network connectivity and raise an exception if unreachable.

        Args:
            host: The host to ping
            ping_count: Number of ping attempts
            timeout: Timeout in seconds for the entire ping operation

        Raises:
            NetworkUnreachableError: If the host is not reachable

        """
        if not self.check_network_connectivity(host, ping_count, timeout):
            error_msg = f"Host {host} is not reachable"
            raise NetworkUnreachableError(error_msg)

    def check_multiple_hosts(
        self,
        hosts: list[str],
        ping_count: int = 3,
        timeout: int = 30,
    ) -> dict[str, bool]:
        """Check connectivity to multiple hosts.

        Args:
            hosts: List of hosts to check
            ping_count: Number of ping attempts per host
            timeout: Timeout in seconds for each ping operation

        Returns:
            Dictionary mapping host names to connectivity status

        """
        results = {}
        for host in hosts:
            results[host] = self.check_network_connectivity(host, ping_count, timeout)
        return results

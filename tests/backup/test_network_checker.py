"""Tests for the network_checker module."""

import logging
import subprocess
from unittest.mock import Mock, patch

import pytest

from opsbox.backup.exceptions import NetworkUnreachableError
from opsbox.backup.network_checker import NetworkChecker


class TestNetworkChecker:
    """Test cases for NetworkChecker functionality."""

    @pytest.fixture
    def logger(self) -> Mock:
        """Create a mock logger for testing."""
        return Mock(spec=logging.Logger)

    @pytest.fixture
    def network_checker(self, logger) -> NetworkChecker:
        """Create a NetworkChecker instance for testing."""
        return NetworkChecker(logger)

    def test_check_network_connectivity_success(self, network_checker) -> None:
        """Test that network connectivity check returns True when host is reachable."""
        mock_result = Mock()
        mock_result.returncode = 0
        mock_result.stdout = "3 packets transmitted, 3 received, 0% packet loss"

        with patch("subprocess.run", return_value=mock_result):
            result = network_checker.check_network_connectivity("example.com")

            assert result is True
            network_checker.logger.info.assert_called()

    def test_check_network_connectivity_failure(self, network_checker) -> None:
        """Test that network connectivity check returns False when host is unreachable."""
        mock_result = Mock()
        mock_result.returncode = 1
        mock_result.stdout = "3 packets transmitted, 0 received, 100% packet loss"

        with patch("subprocess.run", return_value=mock_result):
            result = network_checker.check_network_connectivity("example.com")

            assert result is False
            network_checker.logger.info.assert_called()

    def test_check_network_connectivity_timeout(self, network_checker) -> None:
        """Test that network connectivity check handles timeout gracefully."""
        with patch("subprocess.run", side_effect=subprocess.TimeoutExpired("ping", 30)):
            result = network_checker.check_network_connectivity(
                "example.com",
                timeout=30,
            )

            assert result is False
            network_checker.logger.warning.assert_called()

    def test_check_network_connectivity_subprocess_error(self, network_checker) -> None:
        """Test that network connectivity check handles subprocess errors gracefully."""
        with patch(
            "subprocess.run",
            side_effect=subprocess.SubprocessError("Command failed"),
        ):
            result = network_checker.check_network_connectivity("example.com")

            assert result is False
            network_checker.logger.warning.assert_called()

    def test_check_network_connectivity_or_raise_success(self, network_checker) -> None:
        """Test that check_network_connectivity_or_raise does not raise when host is reachable."""
        mock_result = Mock()
        mock_result.returncode = 0
        mock_result.stdout = "3 packets transmitted, 3 received, 0% packet loss"

        with patch("subprocess.run", return_value=mock_result):
            # Should not raise
            network_checker.check_network_connectivity_or_raise("example.com")

    def test_check_network_connectivity_or_raise_failure(self, network_checker) -> None:
        """Test that check_network_connectivity_or_raise raises NetworkUnreachableError when host is unreachable."""
        mock_result = Mock()
        mock_result.returncode = 1
        mock_result.stdout = "3 packets transmitted, 0 received, 100% packet loss"

        with patch("subprocess.run", return_value=mock_result):
            with pytest.raises(
                NetworkUnreachableError,
                match=r"Host example\.com is not reachable",
            ):
                network_checker.check_network_connectivity_or_raise("example.com")

    def test_check_multiple_hosts(self, network_checker) -> None:
        """Test that check_multiple_hosts checks multiple hosts and returns status for each."""
        hosts = ["host1.com", "host2.com", "host3.com"]

        mock_results = [
            Mock(
                returncode=0,
                stdout="3 packets transmitted, 3 received, 0% packet loss",
            ),  # host1: reachable
            Mock(
                returncode=1,
                stdout="3 packets transmitted, 0 received, 100% packet loss",
            ),  # host2: unreachable
            Mock(
                returncode=0,
                stdout="3 packets transmitted, 3 received, 0% packet loss",
            ),  # host3: reachable
        ]

        with patch("subprocess.run", side_effect=mock_results):
            results = network_checker.check_multiple_hosts(hosts)

            assert results["host1.com"] is True
            assert results["host2.com"] is False
            assert results["host3.com"] is True
            assert len(results) == 3

    def test_check_network_connectivity_custom_parameters(
        self,
        network_checker,
    ) -> None:
        """Test that network connectivity check uses custom ping_count and timeout parameters."""
        mock_result = Mock()
        mock_result.returncode = 0
        mock_result.stdout = "5 packets transmitted, 5 received, 0% packet loss"

        with patch("subprocess.run", return_value=mock_result) as mock_run:
            network_checker.check_network_connectivity(
                "example.com",
                ping_count=5,
                timeout=60,
            )

            # Verify subprocess.run was called with correct parameters
            mock_run.assert_called_once()
            call_args = mock_run.call_args
            assert call_args[0][0] == ["ping", "-c", "5", "example.com"]
            assert call_args[1]["timeout"] == 60


if __name__ == "__main__":
    pytest.main([__file__])

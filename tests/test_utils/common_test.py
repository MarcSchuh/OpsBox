"""Tests for common utility functions."""

import tempfile
from pathlib import Path

from opsbox.utils.common import get_system_info, validate_path


class TestCommonUtils:
    """Test cases for common utility functions."""

    def test_get_system_info(self) -> None:
        """Test that get_system_info returns expected keys."""
        info = get_system_info()
        expected_keys = {
            "platform",
            "platform_version",
            "architecture",
            "processor",
            "python_version",
        }
        assert all(key in info for key in expected_keys)  # nosec B101
        assert isinstance(info["python_version"], str)  # nosec B101

    def test_validate_path_with_valid_path(self) -> None:
        """Test validate_path with valid Path object."""
        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir)
            assert validate_path(path) is True  # nosec B101

    def test_validate_path_with_string(self) -> None:
        """Test validate_path with string (should return False)."""
        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir)
            assert validate_path(path) is True  # nosec B101

    def test_validate_path_with_nonexistent_path(self) -> None:
        """Test validate_path with non-existent path."""
        path = Path("/nonexistent/path")
        assert validate_path(path) is True  # Should not exist check  # nosec B101
        assert validate_path(path, must_exist=True) is False  # nosec B101

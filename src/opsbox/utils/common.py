"""Common utility functions for server operations."""

import platform
from pathlib import Path
from typing import Any


def get_system_info() -> dict[str, Any]:
    """Get system information for server operations.

    Returns
    -------
        Dictionary containing system information

    """
    return {
        "platform": platform.system(),
        "platform_version": platform.version(),
        "architecture": platform.machine(),
        "processor": platform.processor(),
        "python_version": platform.python_version(),
    }


def validate_path(path: Path, *, must_exist: bool = False) -> bool:
    """Validate a file or directory path.

    Args:
    ----
        path: Path to validate
        must_exist: Whether the path must exist

    Returns:
    -------
        True if path is valid, False otherwise

    """
    return path.exists() if must_exist else True

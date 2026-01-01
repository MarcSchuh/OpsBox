"""Common utility functions for server operations."""

import platform
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

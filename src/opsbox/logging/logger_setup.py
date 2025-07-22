"""Logging configuration and setup utilities for OpsBox.

This module provides comprehensive logging configuration capabilities including
file rotation, console output, and customizable log levels.
"""

import logging
import logging.config
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any


class LoggerConfigError(Exception):
    """Custom exception for logger configuration errors."""


@dataclass
class LoggingConfig:
    """Configuration for logging setup."""

    log_name: str
    log_filename: str | None = None
    log_level: str = "INFO"
    log_dir: Path | None = None
    max_bytes: int = 5 * 1024 * 1024  # 5 MB
    backup_count: int = 3
    enable_console: bool = True
    enable_file: bool = True


def validate_log_level(log_level: str) -> int:
    """Validate and return the numeric log level."""
    numeric_level = getattr(logging, log_level.upper(), None)
    if not isinstance(numeric_level, int):
        error_msg = f"Invalid log level: {log_level}"
        raise LoggerConfigError(error_msg)
    return numeric_level


def get_default_log_dir() -> Path:
    """Get the default log directory based on environment."""
    # In Docker, prefer /var/log, otherwise use user's home directory
    var_log_path = Path("/var/log")
    if var_log_path.exists() and os.access("/var/log", os.W_OK):
        return Path("/var/log/opsbox")
    return Path.home() / ".local" / "log" / "opsbox"


def create_logging_config(config: LoggingConfig) -> dict[str, Any]:
    """Create logging configuration dictionary."""
    # Validate log level
    numeric_level = validate_log_level(config.log_level)

    # Determine log directory and filename
    log_dir = get_default_log_dir() if config.log_dir is None else config.log_dir

    if not config.log_filename:
        log_filename = f"{config.log_name}.log"
    else:
        log_filename = config.log_filename

    # Ensure log directory exists
    try:
        log_dir.mkdir(parents=True, exist_ok=True)
    except (PermissionError, OSError) as e:
        error_msg = f"Failed to create log directory {log_dir}: {e}"
        raise LoggerConfigError(error_msg) from e

    log_file = log_dir / log_filename

    # Create formatters
    formatters = {
        "standard": {
            "format": "%(asctime)s %(levelname)s %(name)s: %(message)s",
            "datefmt": "%Y-%m-%d %H:%M:%S",
        },
        "detailed": {
            "format": "%(asctime)s %(levelname)s %(name)s:%(lineno)d: %(message)s",
            "datefmt": "%Y-%m-%d %H:%M:%S",
        },
    }

    # Create handlers
    handlers = {}

    if config.enable_file:
        handlers["file_handler"] = {
            "level": numeric_level,
            "class": "logging.handlers.RotatingFileHandler",
            "filename": str(log_file),
            "maxBytes": config.max_bytes,
            "backupCount": config.backup_count,
            "formatter": "detailed",
            "encoding": "utf8",
        }

    if config.enable_console:
        handlers["console_handler"] = {
            "level": numeric_level,
            "class": "logging.StreamHandler",
            "formatter": "standard",
        }

    # Create loggers configuration
    loggers = {
        config.log_name: {
            "handlers": list(handlers.keys()),
            "level": numeric_level,
            "propagate": False,
        },
    }

    # Add root logger to catch unhandled messages
    if config.log_name != "root":
        loggers["root"] = {
            "handlers": list(handlers.keys()),
            "level": numeric_level,
            "propagate": False,
        }

    return {
        "version": 1,
        "disable_existing_loggers": False,
        "formatters": formatters,
        "handlers": handlers,
        "loggers": loggers,
        "root": {
            "handlers": list(handlers.keys()),
            "level": numeric_level,
        }
        if config.log_name == "root"
        else None,
    }


def configure_logging(config: LoggingConfig) -> logging.Logger:
    """Configure logging for the application.

    Args:
        config: Logging configuration object

    Returns:
        Configured logger instance

    Raises:
        LoggerConfigError: If configuration fails

    """
    try:
        logging_config = create_logging_config(config)

        # Apply logging configuration
        logging.config.dictConfig(logging_config)
        logger = logging.getLogger(config.log_name)

        # Log successful configuration
        logger.info(
            f"Logging configured successfully for '{config.log_name}' at level {config.log_level}",
        )

    except (LoggerConfigError, ValueError, KeyError):
        # Fallback to basic console logging if configuration fails
        logging.basicConfig(
            level=validate_log_level(config.log_level),
            format="%(asctime)s %(levelname)s %(name)s: %(message)s",
        )
        logger = logging.getLogger(config.log_name)
        logger.exception("Failed to configure logging. Using fallback configuration.")

    return logger


def get_logger(name: str) -> logging.Logger:
    """Get a logger instance. If not configured, uses basic configuration.

    Args:
        name: Name of the logger

    Returns:
        Logger instance

    """
    logger = logging.getLogger(name)

    # If no handlers are configured, set up basic configuration
    parent_logger = logger.parent
    if not logger.handlers and (parent_logger is None or not parent_logger.handlers):
        logging.basicConfig(
            level=logging.INFO,
            format="%(asctime)s %(levelname)s %(name)s: %(message)s",
        )

    return logger


# Convenience function for quick setup
def setup_logging(
    app_name: str = "opsbox",
    level: str = "INFO",
    log_to_file: bool = True,
    log_to_console: bool = True,
) -> logging.Logger:
    """Quick setup function for common logging configuration.

    Args:
        app_name: Application name for the logger
        level: Logging level
        log_to_file: Whether to log to file
        log_to_console: Whether to log to console

    Returns:
        Configured logger

    """
    config = LoggingConfig(
        log_name=app_name,
        log_level=level,
        enable_file=log_to_file,
        enable_console=log_to_console,
    )
    return configure_logging(config)

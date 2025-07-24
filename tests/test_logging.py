"""Tests for the logging module."""

import logging
import tempfile
from pathlib import Path
from unittest.mock import patch

import pytest

from opsbox.logging.logger_setup import (
    LoggerConfigError,
    LoggingConfig,
    configure_logging,
    create_logging_config,
    get_default_log_dir,
    get_logger,
    setup_logging,
    validate_log_level,
)


class TestLoggerSetup:
    """Test cases for logger setup functionality."""

    def test_validate_log_level_valid(self) -> None:
        """Test that valid log levels are accepted."""
        assert validate_log_level("DEBUG") == logging.DEBUG
        assert validate_log_level("INFO") == logging.INFO
        assert validate_log_level("WARNING") == logging.WARNING
        assert validate_log_level("ERROR") == logging.ERROR
        assert validate_log_level("CRITICAL") == logging.CRITICAL

    def test_validate_log_level_invalid(self) -> None:
        """Test that invalid log levels raise an exception."""
        with pytest.raises(LoggerConfigError):
            validate_log_level("INVALID_LEVEL")

    def test_get_default_log_dir_docker(self) -> None:
        """Test log directory selection in Docker environment."""
        with (
            patch("pathlib.Path.exists", return_value=True),
            patch("os.access", return_value=True),
        ):
            log_dir = get_default_log_dir()
            assert log_dir == Path("/var/log/opsbox")

    def test_get_default_log_dir_local(self) -> None:
        """Test log directory selection in local environment."""
        with patch("pathlib.Path.exists", return_value=False):
            log_dir = get_default_log_dir()
            assert log_dir == Path.home() / ".local" / "log" / "opsbox"

    def test_logging_config_dataclass(self) -> None:
        """Test LoggingConfig dataclass creation and defaults."""
        config = LoggingConfig(log_name="test_logger")

        assert config.log_name == "test_logger"
        assert config.log_filename is None
        assert config.log_level == "INFO"
        assert config.log_dir is None
        assert config.max_bytes == 5 * 1024 * 1024
        expected_backup_count = 3
        assert config.backup_count == expected_backup_count
        assert config.enable_console is True
        assert config.enable_file is True

    def test_logging_config_custom_values(self) -> None:
        """Test LoggingConfig with custom values."""
        custom_max_bytes = 1024
        custom_backup_count = 5
        config = LoggingConfig(
            log_name="custom_logger",
            log_filename="custom.log",
            log_level="DEBUG",
            log_dir=Path("/custom/path"),
            max_bytes=custom_max_bytes,
            backup_count=custom_backup_count,
            enable_console=False,
            enable_file=False,
        )

        assert config.log_name == "custom_logger"
        assert config.log_filename == "custom.log"
        assert config.log_level == "DEBUG"
        assert config.log_dir == Path("/custom/path")
        assert config.max_bytes == custom_max_bytes
        assert config.backup_count == custom_backup_count
        assert config.enable_console is False
        assert config.enable_file is False

    def test_create_logging_config_basic(self) -> None:
        """Test basic logging configuration creation."""
        config = LoggingConfig(log_name="test_logger")
        logging_config = create_logging_config(config)

        assert logging_config["version"] == 1
        assert logging_config["disable_existing_loggers"] is False
        assert "formatters" in logging_config
        assert "handlers" in logging_config
        assert "loggers" in logging_config
        assert "test_logger" in logging_config["loggers"]
        assert "root" in logging_config["loggers"]

    def test_create_logging_config_file_only(self) -> None:
        """Test logging configuration with file handler only."""
        config = LoggingConfig(
            log_name="file_logger",
            enable_console=False,
            enable_file=True,
        )
        logging_config = create_logging_config(config)

        handlers = logging_config["handlers"]
        assert "file_handler" in handlers
        assert "console_handler" not in handlers
        assert (
            handlers["file_handler"]["class"] == "logging.handlers.RotatingFileHandler"
        )

    def test_create_logging_config_console_only(self) -> None:
        """Test logging configuration with console handler only."""
        config = LoggingConfig(
            log_name="console_logger",
            enable_console=True,
            enable_file=False,
        )
        logging_config = create_logging_config(config)

        handlers = logging_config["handlers"]
        assert "console_handler" in handlers
        assert "file_handler" not in handlers
        assert handlers["console_handler"]["class"] == "logging.StreamHandler"

    def test_configure_logging_basic(self) -> None:
        """Test basic logging configuration."""
        with tempfile.TemporaryDirectory() as temp_dir:
            config = LoggingConfig(
                log_name="test_logger",
                log_dir=Path(temp_dir),
                enable_file=False,
            )
            logger = configure_logging(config)

            assert logger.name == "test_logger"
            assert logger.level == logging.INFO

    def test_configure_logging_with_file(self) -> None:
        """Test logging configuration with file output."""
        with tempfile.TemporaryDirectory() as temp_dir:
            config = LoggingConfig(
                log_name="test_file_logger",
                log_dir=Path(temp_dir),
                enable_console=False,
            )
            configure_logging(config)

            # Check if log file was created
            log_files = list(Path(temp_dir).glob("*.log"))
            assert len(log_files) == 1
            assert log_files[0].name == "test_file_logger.log"

    def test_configure_logging_with_custom_filename(self) -> None:
        """Test logging configuration with custom filename."""
        with tempfile.TemporaryDirectory() as temp_dir:
            config = LoggingConfig(
                log_name="custom_filename",
                log_filename="my_custom.log",
                log_dir=Path(temp_dir),
                enable_console=False,
            )
            configure_logging(config)

            log_files = list(Path(temp_dir).glob("*.log"))
            assert len(log_files) == 1
            assert log_files[0].name == "my_custom.log"

    def test_configure_logging_error_handling(self) -> None:
        """Test error handling when log directory creation fails."""
        config = LoggingConfig(
            log_name="error_test",
            log_dir=Path("/invalid/path"),
            enable_file=False,
        )

        with patch(
            "pathlib.Path.mkdir",
            side_effect=PermissionError("Permission denied"),
        ):
            logger = configure_logging(config)

            # Should fall back to basic configuration
            assert logger.name == "error_test"

    def test_get_logger_fallback(self) -> None:
        """Test get_logger with fallback configuration."""
        logger = get_logger("fallback_test")
        assert logger.name == "fallback_test"

    def test_setup_logging_convenience(self) -> None:
        """Test the convenience setup_logging function."""
        logger = setup_logging(
            app_name="convenience_test",
            level="DEBUG",
            log_to_file=False,
        )

        assert logger.name == "convenience_test"
        assert logger.level == logging.DEBUG

    def test_setup_logging_defaults(self) -> None:
        """Test setup_logging with default parameters."""
        logger = setup_logging()

        assert logger.name == "opsbox"
        assert logger.level == logging.INFO

    def test_logging_configuration_persistence(self) -> None:
        """Test that logging configuration persists across logger instances."""
        config = LoggingConfig(log_name="persistent_logger")
        logger1 = configure_logging(config)
        logger2 = configure_logging(config)

        # Both should be the same logger instance
        assert logger1 is logger2

    def test_logging_levels(self) -> None:
        """Test different logging levels."""
        levels = ["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"]

        for level in levels:
            config = LoggingConfig(
                log_name=f"{level.lower()}_logger",
                log_level=level,
            )
            logger = configure_logging(config)
            expected_level = getattr(logging, level)
            assert logger.level == expected_level

    def test_logging_formatters(self) -> None:
        """Test that formatters are properly configured."""
        config = LoggingConfig(log_name="formatter_test")
        logging_config = create_logging_config(config)

        formatters = logging_config["formatters"]
        assert "standard" in formatters
        assert "detailed" in formatters

        # Check format strings
        standard_format = formatters["standard"]["format"]
        detailed_format = formatters["detailed"]["format"]

        assert "%(asctime)s" in standard_format
        assert "%(levelname)s" in standard_format
        assert "%(name)s" in standard_format
        assert "%(message)s" in standard_format

        assert "%(lineno)d" in detailed_format  # Detailed format includes line numbers


if __name__ == "__main__":
    pytest.main([__file__])

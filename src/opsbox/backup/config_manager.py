"""Configuration management for backup operations."""

import json
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from opsbox.backup.exceptions import ConfigurationError, InvalidResticConfigError


@dataclass
class BackupConfig:
    """Configuration for backup operations."""

    # Required fields
    backup_source: str
    excluded_files: list[str]
    backup_target: str
    password_lookup_1: str
    password_lookup_2: str
    email_settings_path: str
    file_to_check: str

    # Optional fields with defaults
    default_user: str = field(default_factory=lambda: os.getlogin())
    keep_last: str = "10"
    keep_daily: str = "21"
    keep_monthly: str = "5"
    ssh_key_max_retries: int = 12
    detailed_report: bool = True

    # Network and SSH fields
    network_host: str | None = None
    ssh_key: str | None = None
    ssh_user: str | None = None
    restic_password: str | None = None
    user_id: int | None = None

    def __post_init__(self) -> None:
        """Validate configuration after initialization."""
        self._validate_required_fields()
        self._validate_ssh_configuration()
        self._validate_paths()
        self._validate_retention_policy()

    def _validate_required_fields(self) -> None:
        """Validate that all required fields are present and non-empty."""
        required_fields = [
            "backup_source",
            "backup_target",
            "password_lookup_1",
            "password_lookup_2",
            "email_settings_path",
            "file_to_check",
        ]

        for field_name in required_fields:
            value = getattr(self, field_name)
            if not value or not str(value).strip():
                error_msg = f"Required field '{field_name}' cannot be empty"
                raise InvalidResticConfigError(error_msg)

    def _validate_ssh_configuration(self) -> None:
        """Validate SSH configuration consistency."""
        if self.network_host is None and self.ssh_key is not None:
            error_msg = "If ssh_key is set, network_host must be set as well."
            raise InvalidResticConfigError(error_msg)
        if self.ssh_key is None and self.network_host is not None:
            error_msg = "If network_host is set, ssh_key must be set as well."
            raise InvalidResticConfigError(error_msg)
        if self.ssh_key is not None and self.ssh_user is None:
            error_msg = "If ssh_key is set, ssh_user must be set as well."
            raise InvalidResticConfigError(error_msg)

    def _validate_paths(self) -> None:
        """Validate that file paths exist where required."""
        if not Path(self.email_settings_path).exists():
            error_msg = f"Email settings file not found: {self.email_settings_path}"
            raise InvalidResticConfigError(error_msg)

        if not Path(self.backup_source).exists():
            error_msg = f"Backup source path does not exist: {self.backup_source}"
            raise InvalidResticConfigError(error_msg)

    def _validate_retention_policy(self) -> None:
        """Validate retention policy values."""
        try:
            int(self.keep_last)
            int(self.keep_daily)
            int(self.keep_monthly)
        except ValueError as e:
            error_msg = f"Invalid retention policy value: {e}"
            raise InvalidResticConfigError(error_msg) from e


class ConfigManager:
    """Manages configuration loading and validation."""

    def __init__(self) -> None:
        """Initialize the config manager."""

    @staticmethod
    def load_config(config_path: str) -> BackupConfig:
        """Load and validate configuration from JSON file.

        Args:
            config_path: Path to the configuration JSON file

        Returns:
            Validated BackupConfig instance

        Raises:
            ConfigurationError: If configuration file cannot be loaded
            InvalidResticConfigError: If configuration is invalid

        """
        try:
            with Path(config_path).open(encoding="utf-8") as f:
                config_data = json.load(f)
        except FileNotFoundError as e:
            error_msg = f"Configuration file not found: {config_path}"
            raise ConfigurationError(error_msg) from e
        except json.JSONDecodeError as e:
            error_msg = f"Invalid JSON in configuration file: {e}"
            raise ConfigurationError(error_msg) from e
        except Exception as e:
            error_msg = f"Error loading configuration: {e}"
            raise ConfigurationError(error_msg) from e

        try:
            # Create BackupConfig instance with validation
            return BackupConfig(
                backup_source=config_data["backup_source"],
                excluded_files=config_data["excluded_files"],
                backup_target=config_data["backup_target"],
                password_lookup_1=config_data["password_lookup_1"],
                password_lookup_2=config_data["password_lookup_2"],
                email_settings_path=config_data["email_settings_path"],
                file_to_check=config_data["file_to_check"],
                ssh_key=config_data.get("ssh_key"),
                ssh_user=config_data.get("ssh_user"),
                network_host=config_data.get("network_host"),
                default_user=config_data.get("default_user", os.getlogin()),
                keep_last=config_data.get("keep_last", "10"),
                keep_daily=config_data.get("keep_daily", "21"),
                keep_monthly=config_data.get("keep_monthly", "5"),
                ssh_key_max_retries=int(config_data.get("ssh_key_max_retries", 12)),
                restic_password=config_data.get("restic_password"),
                user_id=config_data.get("user_id", os.getuid()),
                detailed_report=config_data.get("detailed_report", True),
            )

        except KeyError as e:
            error_msg = f"Missing required configuration field: {e}"
            raise InvalidResticConfigError(error_msg) from e
        except Exception as e:
            error_msg = f"Configuration validation failed: {e}"
            raise InvalidResticConfigError(error_msg) from e

    @staticmethod
    def validate_config(config: BackupConfig) -> None:
        """Validate a configuration object.

        Args:
            config: BackupConfig instance to validate

        Raises:
            InvalidResticConfigError: If configuration is invalid

        """
        # This is handled by __post_init__ in BackupConfig, but we can add additional validation here

    @staticmethod
    def get_default_config() -> dict[str, Any]:
        """Get a template configuration dictionary."""
        return {
            "backup_source": "/path/to/backup/source",
            "excluded_files": ["*.tmp", "*.log"],
            "backup_target": "sftp:user@host:/path/to/repo",
            "password_lookup_1": "label",
            "password_lookup_2": "attribute",
            "email_settings_path": "/path/to/email/settings.json",
            "file_to_check": "important_file.txt",
            "default_user": "backup_user",
            "keep_last": "10",
            "keep_daily": "21",
            "keep_monthly": "5",
            "ssh_key_max_retries": 12,
            "detailed_report": True,
            "network_host": None,
            "ssh_key": None,
            "ssh_user": None,
            "restic_password": None,
            "user_id": None,
        }

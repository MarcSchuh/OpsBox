"""Tests for the check_mails configuration management."""

import json
import tempfile
from pathlib import Path

import pytest

from opsbox.check_mails.check_mails import (
    CheckMailsConfig,
    EmailSearchConfig,
    load_config,
)


class TestCheckMailsConfig:
    """Test cases for CheckMailsConfig validation."""

    def test_check_mails_config_valid_with_all_fields(self) -> None:
        """Test that config with all required fields validates successfully."""
        config = CheckMailsConfig(
            email_settings_path="/path/to/email.json",
            imap_folder="inbox",
            searches=[
                EmailSearchConfig(
                    subject="Test Subject",
                    days_in_past=1,
                    number_of_occurrences=1,
                    match_any=False,
                ),
            ],
        )

        assert config.email_settings_path == "/path/to/email.json"
        assert config.imap_folder == "inbox"
        assert len(config.searches) == 1
        assert config.searches[0].subject == "Test Subject"

    def test_check_mails_config_valid_with_defaults(self) -> None:
        """Test that config with default values works correctly."""
        config = CheckMailsConfig(
            email_settings_path="/path/to/email.json",
            imap_folder="server",
            searches=[
                EmailSearchConfig(subject="Test Subject"),
            ],
        )

        assert config.email_settings_path == "/path/to/email.json"
        assert config.imap_folder == "server"
        assert config.delete_old_emails.enabled is False
        assert config.delete_old_emails.older_than_days == 30
        assert config.searches[0].days_in_past == 1
        assert config.searches[0].number_of_occurrences == 1
        assert config.searches[0].match_any is False

    def test_check_mails_config_missing_email_settings_path(self) -> None:
        """Test that ValueError is raised when email_settings_path is missing."""
        with pytest.raises(ValueError, match="email_settings_path is required"):
            CheckMailsConfig(
                email_settings_path="",
                imap_folder="inbox",
                searches=[
                    EmailSearchConfig(subject="Test Subject"),
                ],
            )

    def test_check_mails_config_missing_imap_folder(self) -> None:
        """Test that ValueError is raised when imap_folder is missing."""
        with pytest.raises(ValueError, match="imap_folder is required"):
            CheckMailsConfig(
                email_settings_path="/path/to/email.json",
                imap_folder="",
                searches=[
                    EmailSearchConfig(subject="Test Subject"),
                ],
            )

    def test_check_mails_config_empty_searches(self) -> None:
        """Test that ValueError is raised when searches list is empty."""
        with pytest.raises(
            ValueError,
            match="At least one search configuration is required",
        ):
            CheckMailsConfig(
                email_settings_path="/path/to/email.json",
                imap_folder="inbox",
                searches=[],
            )


class TestConfigLoader:
    """Test cases for configuration loading from files."""

    def test_load_config_from_yaml_success(self) -> None:
        """Test loading valid YAML configuration successfully."""
        with tempfile.TemporaryDirectory() as temp_dir:
            config_file = Path(temp_dir) / "config.yaml"

            search_data = {
                "subject": "Errorlog found for backup..",
                "days_in_past": 1,
                "number_of_occurrences": 1,
                "match_any": False,
            }
            config_data = {
                "email_settings_path": "/path/to/email.json",
                "imap_folder": "server",
                "searches": [search_data],
            }

            config_file.write_text(
                f"email_settings_path: {config_data['email_settings_path']}\n"
                f"imap_folder: {config_data['imap_folder']}\n"
                f"searches:\n"
                f"  - subject: '{search_data['subject']}'\n"
                f"    days_in_past: {search_data['days_in_past']}\n"
                f"    number_of_occurrences: {search_data['number_of_occurrences']}\n"
                f"    match_any: {search_data['match_any']}\n",
            )

            config = load_config(config_file)

            assert config.email_settings_path == config_data["email_settings_path"]
            assert config.imap_folder == config_data["imap_folder"]
            assert len(config.searches) == 1
            assert config.searches[0].subject == search_data["subject"]
            assert config.searches[0].days_in_past == search_data["days_in_past"]
            assert (
                config.searches[0].number_of_occurrences
                == search_data["number_of_occurrences"]
            )
            assert config.searches[0].match_any == search_data["match_any"]

    def test_load_config_from_json_success(self) -> None:
        """Test loading valid JSON configuration successfully."""
        with tempfile.TemporaryDirectory() as temp_dir:
            config_file = Path(temp_dir) / "config.json"

            search_data = {
                "subject": "Test Subject",
                "days_in_past": 2,
                "number_of_occurrences": 3,
                "match_any": True,
            }
            config_data = {
                "email_settings_path": "/path/to/email.json",
                "imap_folder": "inbox",
                "searches": [search_data],
            }

            config_file.write_text(json.dumps(config_data))

            config = load_config(config_file)

            assert config.email_settings_path == config_data["email_settings_path"]
            assert config.imap_folder == config_data["imap_folder"]
            assert len(config.searches) == 1
            assert config.searches[0].subject == search_data["subject"]
            assert config.searches[0].days_in_past == search_data["days_in_past"]
            assert (
                config.searches[0].number_of_occurrences
                == search_data["number_of_occurrences"]
            )
            assert config.searches[0].match_any == search_data["match_any"]

    def test_load_config_file_not_found(self) -> None:
        """Test that FileNotFoundError is raised when config file is not found."""
        with pytest.raises(FileNotFoundError, match="Configuration file not found"):
            load_config(Path("/nonexistent/config.yaml"))

    def test_load_config_invalid_yaml_format(self) -> None:
        """Test that ValueError is raised for invalid YAML format."""
        with tempfile.TemporaryDirectory() as temp_dir:
            config_file = Path(temp_dir) / "config.yaml"
            config_file.write_text("invalid: yaml: content: [unclosed")

            with pytest.raises(ValueError, match="Error loading configuration file"):
                load_config(config_file)

    def test_load_config_invalid_json_format(self) -> None:
        """Test that ValueError is raised for invalid JSON format."""
        with tempfile.TemporaryDirectory() as temp_dir:
            config_file = Path(temp_dir) / "config.json"
            config_file.write_text('{"invalid": json}')

            with pytest.raises(ValueError, match="Error loading configuration file"):
                load_config(config_file)

    def test_load_config_missing_required_field(self) -> None:
        """Test that ValueError is raised for missing required fields."""
        with tempfile.TemporaryDirectory() as temp_dir:
            config_file = Path(temp_dir) / "config.yaml"
            # Missing email_settings_path
            config_file.write_text(
                "imap_folder: inbox\nsearches:\n  - subject: 'Test Subject'\n",
            )

            with pytest.raises(
                ValueError,
                match="Missing required configuration field",
            ):
                load_config(config_file)

    def test_load_config_searches_with_defaults(self) -> None:
        """Test that searches use default values when not specified."""
        with tempfile.TemporaryDirectory() as temp_dir:
            config_file = Path(temp_dir) / "config.yaml"

            config_file.write_text(
                "email_settings_path: /path/to/email.json\n"
                "imap_folder: inbox\n"
                "searches:\n"
                "  - subject: 'Test Subject'\n",
            )

            config = load_config(config_file)

            assert len(config.searches) == 1
            assert config.searches[0].subject == "Test Subject"
            assert config.searches[0].days_in_past == 1  # default
            assert config.searches[0].number_of_occurrences == 1  # default
            assert config.searches[0].match_any is False  # default

    def test_load_config_multiple_searches(self) -> None:
        """Test loading configuration with multiple searches."""
        with tempfile.TemporaryDirectory() as temp_dir:
            config_file = Path(temp_dir) / "config.yaml"

            config_file.write_text(
                "email_settings_path: /path/to/email.json\n"
                "imap_folder: inbox\n"
                "searches:\n"
                "  - subject: 'First Subject'\n"
                "    days_in_past: 1\n"
                "  - subject: 'Second Subject'\n"
                "    days_in_past: 2\n"
                "    number_of_occurrences: 3\n",
            )

            config = load_config(config_file)

            assert len(config.searches) == 2
            assert config.searches[0].subject == "First Subject"
            assert config.searches[0].days_in_past == 1
            assert config.searches[1].subject == "Second Subject"
            assert config.searches[1].days_in_past == 2
            assert config.searches[1].number_of_occurrences == 3

    def test_load_config_delete_old_emails_enabled(self) -> None:
        """Test loading configuration with delete_old_emails enabled."""
        with tempfile.TemporaryDirectory() as temp_dir:
            config_file = Path(temp_dir) / "config.yaml"

            config_file.write_text(
                "email_settings_path: /path/to/email.json\n"
                "imap_folder: inbox\n"
                "searches:\n"
                "  - subject: 'Test Subject'\n"
                "delete_old_emails:\n"
                "  enabled: true\n"
                "  older_than_days: 60\n"
                "  folder: archive\n",
            )

            config = load_config(config_file)

            assert config.delete_old_emails.enabled is True
            assert config.delete_old_emails.older_than_days == 60
            assert config.delete_old_emails.folder == "archive"

    def test_load_config_delete_old_emails_defaults(self) -> None:
        """Test that delete_old_emails uses default values when not specified."""
        with tempfile.TemporaryDirectory() as temp_dir:
            config_file = Path(temp_dir) / "config.yaml"

            config_file.write_text(
                "email_settings_path: /path/to/email.json\n"
                "imap_folder: inbox\n"
                "searches:\n"
                "  - subject: 'Test Subject'\n",
            )

            config = load_config(config_file)

            assert config.delete_old_emails.enabled is False  # default
            assert config.delete_old_emails.older_than_days == 30  # default
            assert config.delete_old_emails.folder == "inbox"  # default


if __name__ == "__main__":
    pytest.main([__file__])

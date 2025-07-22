"""Tests for the encrypted mail module."""

import json
import logging
import subprocess
import tempfile
from pathlib import Path
from unittest.mock import Mock, patch

import pytest

from opsbox.encrypted_mail.encrypted_mail import (
    EncryptedMail,
    MailSettings,
    main,
)
from opsbox.exceptions import EmailSettingsNotFoundError


class TestMailSettings:
    """Test cases for MailSettings dataclass."""

    def test_mail_settings_creation(self) -> None:
        """Test MailSettings dataclass creation with all required fields."""
        settings = MailSettings(
            sender="test@example.com",
            recipient="recipient@example.com",
            password_lookup_1="service",
            password_lookup_2="username",
            host="smtp.example.com",
            port=587,
            user="testuser",
            security="starttls",
            gpg_key_id="test-key-id",
            default_user="testuser",
            password="testpassword",
        )

        assert settings.sender == "test@example.com"
        assert settings.recipient == "recipient@example.com"
        assert settings.password_lookup_1 == "service"
        assert settings.password_lookup_2 == "username"
        assert settings.host == "smtp.example.com"
        assert settings.port == 587
        assert settings.user == "testuser"
        assert settings.security == "starttls"
        assert settings.gpg_key_id == "test-key-id"
        assert settings.default_user == "testuser"
        assert settings.password == "testpassword"

    def test_mail_settings_immutable(self) -> None:
        """Test that MailSettings is immutable."""
        settings = MailSettings(
            sender="test@example.com",
            recipient="recipient@example.com",
            password_lookup_1="service",
            password_lookup_2="username",
            host="smtp.example.com",
            port=587,
            user="testuser",
            security="starttls",
            gpg_key_id="test-key-id",
            default_user="testuser",
            password="testpassword",
        )

        with pytest.raises(
            Exception,
            match="cannot assign to field",
        ):  # dataclass frozen=True raises FrozenInstanceError
            settings.sender = "new@example.com"


class TestLoadEmailSettings:
    """Test cases for load_email_settings static method."""

    def test_load_email_settings_valid_config(self) -> None:
        """Test loading valid email settings from JSON."""
        config_data = {
            "sender": "test@example.com",
            "recipient": "recipient@example.com",
            "password_lookup_1": "service",
            "password_lookup_2": "username",
            "host": "smtp.example.com",
            "port": 587,
            "user": "testuser",
            "security": "starttls",
            "gpg_key_id": "test-key-id",
            "default_user": "testuser",
            "password": "testpassword",
        }

        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump(config_data, f)
            temp_path = f.name

        try:
            settings = EncryptedMail.load_email_settings(temp_path)
            assert isinstance(settings, MailSettings)
            assert settings.sender == "test@example.com"
            assert settings.recipient == "recipient@example.com"
            assert settings.host == "smtp.example.com"
            assert settings.port == 587
            assert settings.password == "testpassword"
        finally:
            Path(temp_path).unlink()

    def test_load_email_settings_without_password(self) -> None:
        """Test loading email settings without password field."""
        config_data = {
            "sender": "test@example.com",
            "recipient": "recipient@example.com",
            "password_lookup_1": "service",
            "password_lookup_2": "username",
            "host": "smtp.example.com",
            "port": 587,
            "user": "testuser",
            "security": "starttls",
            "gpg_key_id": "test-key-id",
            "default_user": "testuser",
        }

        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump(config_data, f)
            temp_path = f.name

        try:
            settings = EncryptedMail.load_email_settings(temp_path)
            assert settings.password is None
        finally:
            Path(temp_path).unlink()

    def test_load_email_settings_empty_path(self) -> None:
        """Test loading email settings with empty path."""
        with pytest.raises(
            EmailSettingsNotFoundError,
            match="email_settings_path not specified",
        ):
            EncryptedMail.load_email_settings("")

    def test_load_email_settings_none_path(self) -> None:
        """Test loading email settings with None path."""
        with pytest.raises(
            EmailSettingsNotFoundError,
            match="email_settings_path not specified",
        ):
            EncryptedMail.load_email_settings(None)  # type: ignore[arg-type]

    def test_load_email_settings_file_not_found(self) -> None:
        """Test loading email settings from non-existent file."""
        with pytest.raises(
            EmailSettingsNotFoundError,
            match="Email settings file not found",
        ):
            EncryptedMail.load_email_settings("/nonexistent/path/settings.json")

    def test_load_email_settings_invalid_json(self) -> None:
        """Test loading email settings with invalid JSON."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            f.write('{"invalid": json content}')
            temp_path = f.name

        try:
            with pytest.raises(EmailSettingsNotFoundError, match="Invalid JSON"):
                EncryptedMail.load_email_settings(temp_path)
        finally:
            Path(temp_path).unlink()

    def test_load_email_settings_missing_required_key(self) -> None:
        """Test loading email settings with missing required key."""
        config_data = {
            "sender": "test@example.com",
            "recipient": "recipient@example.com",
            # Missing password_lookup_1
            "password_lookup_2": "username",
            "host": "smtp.example.com",
            "port": 587,
            "user": "testuser",
            "security": "starttls",
            "gpg_key_id": "test-key-id",
            "default_user": "testuser",
        }

        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump(config_data, f)
            temp_path = f.name

        try:
            with pytest.raises(
                EmailSettingsNotFoundError,
                match="Missing required configuration key",
            ):
                EncryptedMail.load_email_settings(temp_path)
        finally:
            Path(temp_path).unlink()

    def test_load_email_settings_invalid_port_type(self) -> None:
        """Test loading email settings with invalid port type."""
        config_data = {
            "sender": "test@example.com",
            "recipient": "recipient@example.com",
            "password_lookup_1": "service",
            "password_lookup_2": "username",
            "host": "smtp.example.com",
            "port": "587",  # String instead of int
            "user": "testuser",
            "security": "starttls",
            "gpg_key_id": "test-key-id",
            "default_user": "testuser",
        }

        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump(config_data, f)
            temp_path = f.name

        try:
            # This should work as JSON loads strings, but the dataclass will handle type conversion
            settings = EncryptedMail.load_email_settings(temp_path)
            assert settings.port == "587"  # Will be string from JSON
        finally:
            Path(temp_path).unlink()


class TestEncryptedMailInitialization:
    """Test cases for EncryptedMail initialization."""

    def test_encrypted_mail_initialization(self) -> None:
        """Test EncryptedMail initialization with valid parameters."""
        logger = Mock(spec=logging.Logger)
        config_data = {
            "sender": "test@example.com",
            "recipient": "recipient@example.com",
            "password_lookup_1": "service",
            "password_lookup_2": "username",
            "host": "smtp.example.com",
            "port": 587,
            "user": "testuser",
            "security": "starttls",
            "gpg_key_id": "test-key-id",
            "default_user": "testuser",
            "password": "testpassword",
        }

        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump(config_data, f)
            temp_path = f.name

        try:
            encrypted_mail = EncryptedMail(logger, temp_path)
            assert encrypted_mail.logger == logger
            assert encrypted_mail.mail_settings.sender == "test@example.com"
            assert encrypted_mail.fail_silently is False
        finally:
            Path(temp_path).unlink()

    def test_encrypted_mail_initialization_fail_silently(self) -> None:
        """Test EncryptedMail initialization with fail_silently=True."""
        logger = Mock(spec=logging.Logger)
        config_data = {
            "sender": "test@example.com",
            "recipient": "recipient@example.com",
            "password_lookup_1": "service",
            "password_lookup_2": "username",
            "host": "smtp.example.com",
            "port": 587,
            "user": "testuser",
            "security": "starttls",
            "gpg_key_id": "test-key-id",
            "default_user": "testuser",
            "password": "testpassword",
        }

        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump(config_data, f)
            temp_path = f.name

        try:
            encrypted_mail = EncryptedMail(logger, temp_path, fail_silently=True)
            assert encrypted_mail.fail_silently is True
        finally:
            Path(temp_path).unlink()

    def test_encrypted_mail_initialization_invalid_settings(self) -> None:
        """Test EncryptedMail initialization with invalid settings path."""
        logger = Mock(spec=logging.Logger)

        with pytest.raises(EmailSettingsNotFoundError):
            EncryptedMail(logger, "/nonexistent/path/settings.json")


class TestEncryptedMailSendEmail:
    """Test cases for send_encrypted_mail method."""

    @pytest.fixture
    def mock_mail_settings(self) -> MailSettings:
        """Create mock mail settings for testing."""
        return MailSettings(
            sender="test@example.com",
            recipient="recipient@example.com",
            password_lookup_1="service",
            password_lookup_2="username",
            host="smtp.example.com",
            port=587,
            user="testuser",
            security="starttls",
            gpg_key_id="test-key-id",
            default_user="testuser",
            password="testpassword",
        )

    @pytest.fixture
    def encrypted_mail(self, mock_mail_settings) -> EncryptedMail:
        """Create EncryptedMail instance with mocked settings."""
        logger = Mock(spec=logging.Logger)
        encrypted_mail = EncryptedMail.__new__(EncryptedMail)
        encrypted_mail.logger = logger
        encrypted_mail.mail_settings = mock_mail_settings
        encrypted_mail.fail_silently = False
        return encrypted_mail

    @patch("subprocess.run")
    @patch("opsbox.encrypted_mail.encrypted_mail.Envelope")
    def test_send_encrypted_mail_success(
        self,
        mock_envelope_class,
        mock_subprocess_run,
        encrypted_mail,
    ) -> None:
        """Test successful email sending."""
        # Mock subprocess for user ID lookup
        mock_subprocess_run.return_value.returncode = 0
        mock_subprocess_run.return_value.stdout = "1000\n"

        # Mock Envelope completely
        mock_envelope = Mock()
        mock_envelope_class.return_value = mock_envelope

        encrypted_mail.send_encrypted_mail("Test Subject", "Test Message")

        # Verify subprocess was called for user ID lookup
        mock_subprocess_run.assert_called_once()
        assert mock_subprocess_run.call_args[0][0] == ["id", "-u", "testuser"]

        # Verify Envelope was created with correct parameters
        mock_envelope_class.assert_called_once_with(
            from_="test@example.com",
            to="recipient@example.com",
            message="Test Message",
        )

        # Verify email configuration
        mock_envelope.subject.assert_called_once_with("Test Subject", encrypted=False)
        mock_envelope.smtp.assert_called_once()
        mock_envelope.encryption.assert_called_once_with(key="test-key-id")
        mock_envelope.send.assert_called_once_with(sign=False)

    @patch("subprocess.run")
    @patch("opsbox.encrypted_mail.encrypted_mail.Envelope")
    def test_send_encrypted_mail_with_password_lookup(
        self,
        mock_envelope_class,
        mock_subprocess_run,
        encrypted_mail,
    ) -> None:
        """Test email sending with password lookup via secret-tool."""
        # Create new settings without password to trigger lookup
        encrypted_mail.mail_settings = MailSettings(
            sender="test@example.com",
            recipient="recipient@example.com",
            password_lookup_1="service",
            password_lookup_2="username",
            host="smtp.example.com",
            port=587,
            user="testuser",
            security="starttls",
            gpg_key_id="test-key-id",
            default_user="testuser",
            password=None,
        )

        # Mock subprocess calls
        def mock_subprocess_side_effect(*args: list, **kwargs) -> Mock:
            mock_result = Mock()
            if args[0] == ["id", "-u", "testuser"]:
                mock_result.returncode = 0
                mock_result.stdout = "1000\n"
            elif "secret-tool" in args[0]:
                mock_result.returncode = 0
                mock_result.stdout = "retrieved_password\n"
            return mock_result

        mock_subprocess_run.side_effect = mock_subprocess_side_effect

        # Mock Envelope completely
        mock_envelope = Mock()
        mock_envelope_class.return_value = mock_envelope

        with patch("os.getenv", return_value=""):
            encrypted_mail.send_encrypted_mail("Test Subject", "Test Message")

        # Verify secret-tool was called
        secret_tool_calls = [
            call
            for call in mock_subprocess_run.call_args_list
            if "secret-tool" in call[0][0]
        ]
        assert len(secret_tool_calls) == 1

    @patch("subprocess.run")
    def test_send_encrypted_mail_user_id_lookup_failure(
        self,
        mock_subprocess_run,
        encrypted_mail,
    ) -> None:
        """Test email sending with user ID lookup failure."""
        # Mock subprocess failure
        mock_subprocess_run.return_value.returncode = 1
        mock_subprocess_run.return_value.stderr = "User not found"

        with pytest.raises(subprocess.CalledProcessError):
            encrypted_mail.send_encrypted_mail("Test Subject", "Test Message")

        encrypted_mail.logger.error.assert_called_once()

    @patch("subprocess.run")
    @patch("opsbox.encrypted_mail.encrypted_mail.Envelope")
    def test_send_encrypted_mail_password_lookup_failure(
        self,
        mock_envelope_class,
        mock_subprocess_run,
        encrypted_mail,
    ) -> None:
        """Test email sending with password lookup failure."""
        # Create new settings without password
        encrypted_mail.mail_settings = MailSettings(
            sender="test@example.com",
            recipient="recipient@example.com",
            password_lookup_1="service",
            password_lookup_2="username",
            host="smtp.example.com",
            port=587,
            user="testuser",
            security="starttls",
            gpg_key_id="test-key-id",
            default_user="testuser",
            password=None,
        )

        # Mock subprocess calls
        def mock_subprocess_side_effect(*args: list, **kwargs) -> Mock:
            mock_result = Mock()
            if args[0] == ["id", "-u", "testuser"]:
                mock_result.returncode = 0
                mock_result.stdout = "1000\n"
            elif "secret-tool" in args[0]:
                mock_result.returncode = 1
                mock_result.stderr = "Password not found"
            return mock_result

        mock_subprocess_run.side_effect = mock_subprocess_side_effect

        # Mock Envelope completely
        mock_envelope = Mock()
        mock_envelope_class.return_value = mock_envelope

        with (
            patch("os.getenv", return_value=""),
            pytest.raises(subprocess.CalledProcessError),
        ):
            encrypted_mail.send_encrypted_mail("Test Subject", "Test Message")

    @patch("subprocess.run")
    @patch("opsbox.encrypted_mail.encrypted_mail.Envelope")
    def test_send_encrypted_mail_empty_password(
        self,
        mock_envelope_class,
        mock_subprocess_run,
        encrypted_mail,
    ) -> None:
        """Test email sending with empty password retrieval."""
        # Create new settings without password
        encrypted_mail.mail_settings = MailSettings(
            sender="test@example.com",
            recipient="recipient@example.com",
            password_lookup_1="service",
            password_lookup_2="username",
            host="smtp.example.com",
            port=587,
            user="testuser",
            security="starttls",
            gpg_key_id="test-key-id",
            default_user="testuser",
            password=None,
        )

        # Mock subprocess calls
        def mock_subprocess_side_effect(*args: list, **kwargs) -> Mock:
            mock_result = Mock()
            if args[0] == ["id", "-u", "testuser"]:
                mock_result.returncode = 0
                mock_result.stdout = "1000\n"
            elif "secret-tool" in args[0]:
                mock_result.returncode = 0
                mock_result.stdout = "\n"  # Empty password
            return mock_result

        mock_subprocess_run.side_effect = mock_subprocess_side_effect

        # Mock Envelope completely
        mock_envelope = Mock()
        mock_envelope_class.return_value = mock_envelope

        with (
            patch("os.getenv", return_value=""),
            pytest.raises(ValueError, match="Retrieved password is empty"),
        ):
            encrypted_mail.send_encrypted_mail("Test Subject", "Test Message")

    @patch("subprocess.run")
    @patch("opsbox.encrypted_mail.encrypted_mail.Envelope")
    def test_send_encrypted_mail_message_normalization(
        self,
        mock_envelope_class,
        mock_subprocess_run,
        encrypted_mail,
    ) -> None:
        r"""Test message normalization (\\n to \n conversion)."""
        # Mock subprocess for user ID lookup
        mock_subprocess_run.return_value.returncode = 0
        mock_subprocess_run.return_value.stdout = "1000\n"

        # Mock Envelope completely
        mock_envelope = Mock()
        mock_envelope_class.return_value = mock_envelope

        encrypted_mail.send_encrypted_mail("Test Subject", "Line1\\nLine2\\nLine3")

        # Verify message was normalized
        mock_envelope_class.assert_called_once_with(
            from_="test@example.com",
            to="recipient@example.com",
            message="Line1\nLine2\nLine3",
        )

    @patch("subprocess.run")
    @patch("opsbox.encrypted_mail.encrypted_mail.Envelope")
    def test_send_encrypted_mail_envelope_send_failure(
        self,
        mock_envelope_class,
        mock_subprocess_run,
        encrypted_mail,
    ) -> None:
        """Test email sending with Envelope.send() failure."""
        # Mock subprocess for user ID lookup
        mock_subprocess_run.return_value.returncode = 0
        mock_subprocess_run.return_value.stdout = "1000\n"

        # Mock Envelope with send failure
        mock_envelope = Mock()
        mock_envelope.send.side_effect = Exception("SMTP error")
        mock_envelope_class.return_value = mock_envelope

        with pytest.raises(Exception, match="SMTP error"):
            encrypted_mail.send_encrypted_mail("Test Subject", "Test Message")

        encrypted_mail.logger.exception.assert_called_once_with("Error sending email")


class TestEncryptedMailAttachmentHandling:
    """Test cases for attachment handling."""

    @pytest.fixture
    def mock_mail_settings(self) -> MailSettings:
        """Create mock mail settings for testing."""
        return MailSettings(
            sender="test@example.com",
            recipient="recipient@example.com",
            password_lookup_1="service",
            password_lookup_2="username",
            host="smtp.example.com",
            port=587,
            user="testuser",
            security="starttls",
            gpg_key_id="test-key-id",
            default_user="testuser",
            password="testpassword",
        )

    @pytest.fixture
    def encrypted_mail(self, mock_mail_settings) -> EncryptedMail:
        """Create EncryptedMail instance with mocked settings."""
        logger = Mock(spec=logging.Logger)
        encrypted_mail = EncryptedMail.__new__(EncryptedMail)
        encrypted_mail.logger = logger
        encrypted_mail.mail_settings = mock_mail_settings
        encrypted_mail.fail_silently = False
        return encrypted_mail

    @patch("opsbox.encrypted_mail.encrypted_mail.Path")
    @patch("subprocess.run")
    @patch("opsbox.encrypted_mail.encrypted_mail.Envelope")
    def test_handle_attachment_valid_file(
        self,
        mock_envelope_class,
        mock_subprocess_run,
        mock_path,
        encrypted_mail,
    ) -> None:
        """Test handling valid attachment within size limit."""
        # Mock subprocess for user ID lookup
        mock_subprocess_run.return_value.returncode = 0
        mock_subprocess_run.return_value.stdout = "1000\n"

        # Mock Path operations
        mock_path_obj = Mock()
        mock_path_obj.is_file.return_value = True
        mock_path_obj.stat.return_value.st_size = 1024  # 1KB
        mock_path.return_value = mock_path_obj

        # Mock Envelope
        mock_envelope = Mock()
        mock_envelope_class.return_value = mock_envelope

        # Test through the public send_encrypted_mail method
        encrypted_mail.send_encrypted_mail("Test Subject", "Test Message", "test.txt")

        # Verify attachment was added
        mock_envelope.attach.assert_called_once_with(path="test.txt")
        # The logger.info call for attachment is inside the _handle_attachment method
        # which is called during send_encrypted_mail, so we verify it was called
        assert any(
            "Attachment 'test.txt' added" in str(call)
            for call in encrypted_mail.logger.info.call_args_list
        )

    @patch("opsbox.encrypted_mail.encrypted_mail.Path")
    @patch("subprocess.run")
    @patch("opsbox.encrypted_mail.encrypted_mail.Envelope")
    def test_handle_attachment_file_too_large(
        self,
        mock_envelope_class,
        mock_subprocess_run,
        mock_path,
        encrypted_mail,
    ) -> None:
        """Test handling attachment that exceeds size limit."""
        # Mock subprocess for user ID lookup
        mock_subprocess_run.return_value.returncode = 0
        mock_subprocess_run.return_value.stdout = "1000\n"

        # Mock Path operations
        mock_path_obj = Mock()
        mock_path_obj.is_file.return_value = True
        mock_path_obj.stat.return_value.st_size = 10 * 1024 * 1024  # 10MB
        mock_path.return_value = mock_path_obj

        # Mock Envelope
        mock_warning_email = Mock()
        mock_envelope_class.return_value = mock_warning_email

        # Test through the public send_encrypted_mail method
        encrypted_mail.send_encrypted_mail("Test Subject", "Test Message", "large.txt")

        # Verify warning was logged
        encrypted_mail.logger.warning.assert_called()
        assert any(
            "too large" in call.args[0]
            for call in encrypted_mail.logger.warning.call_args_list
        )

        # Verify new warning email was created
        mock_envelope_class.assert_called_with(
            from_="test@example.com",
            to="recipient@example.com",
            message="!!!WARNING!!! large.txt is too large (10485760 bytes).\nTest Message",
        )

    @patch("opsbox.encrypted_mail.encrypted_mail.Path")
    @patch("subprocess.run")
    @patch("opsbox.encrypted_mail.encrypted_mail.Envelope")
    def test_handle_attachment_file_not_found(
        self,
        mock_envelope_class,
        mock_subprocess_run,
        mock_path,
        encrypted_mail,
    ) -> None:
        """Test handling non-existent attachment file."""
        # Mock subprocess for user ID lookup
        mock_subprocess_run.return_value.returncode = 0
        mock_subprocess_run.return_value.stdout = "1000\n"

        # Mock Path operations
        mock_path_obj = Mock()
        mock_path_obj.is_file.return_value = False
        mock_path.return_value = mock_path_obj

        # Mock Envelope
        mock_warning_email = Mock()
        mock_envelope_class.return_value = mock_warning_email

        # Test through the public send_encrypted_mail method
        encrypted_mail.send_encrypted_mail(
            "Test Subject",
            "Test Message",
            "nonexistent.txt",
        )

        # Verify warning was logged
        encrypted_mail.logger.warning.assert_called()
        assert any(
            "not found" in call.args[0]
            for call in encrypted_mail.logger.warning.call_args_list
        )

        # Verify new warning email was created
        mock_envelope_class.assert_called_with(
            from_="test@example.com",
            to="recipient@example.com",
            message="!!!WARNING!!! Attachment nonexistent.txt not found\nTest Message",
        )


class TestEncryptedMailRetryMechanism:
    """Test cases for retry mechanism."""

    @pytest.fixture
    def mock_mail_settings(self) -> MailSettings:
        """Create mock mail settings for testing."""
        return MailSettings(
            sender="test@example.com",
            recipient="recipient@example.com",
            password_lookup_1="service",
            password_lookup_2="username",
            host="smtp.example.com",
            port=587,
            user="testuser",
            security="starttls",
            gpg_key_id="test-key-id",
            default_user="testuser",
            password="testpassword",
        )

    @pytest.fixture
    def encrypted_mail(self, mock_mail_settings) -> EncryptedMail:
        """Create EncryptedMail instance with mocked settings."""
        logger = Mock(spec=logging.Logger)
        encrypted_mail = EncryptedMail.__new__(EncryptedMail)
        encrypted_mail.logger = logger
        encrypted_mail.mail_settings = mock_mail_settings
        encrypted_mail.fail_silently = False
        return encrypted_mail

    @patch("time.sleep")
    def test_send_mail_with_retries_success_first_attempt(
        self,
        mock_sleep,
        encrypted_mail,
    ) -> None:
        """Test successful email sending on first attempt."""
        with patch.object(encrypted_mail, "send_encrypted_mail") as mock_send:
            encrypted_mail.send_mail_with_retries("Test Subject", "Test Message")

            mock_send.assert_called_once_with("Test Subject", "Test Message", None)
            encrypted_mail.logger.info.assert_called_once_with(
                "Email successfully sent on attempt 1",
            )
            mock_sleep.assert_not_called()

    @patch("time.sleep")
    def test_send_mail_with_retries_success_after_failures(
        self,
        mock_sleep,
        encrypted_mail,
    ) -> None:
        """Test successful email sending after some failures."""
        with patch.object(encrypted_mail, "send_encrypted_mail") as mock_send:
            # Fail first two attempts, succeed on third
            mock_send.side_effect = [Exception("Error"), Exception("Error"), None]

            encrypted_mail.send_mail_with_retries("Test Subject", "Test Message")

            assert mock_send.call_count == 3
            encrypted_mail.logger.info.assert_called_with(
                "Email successfully sent on attempt 3",
            )
            assert mock_sleep.call_count == 2  # Sleep between retries

    @patch("time.sleep")
    def test_send_mail_with_retries_all_failures_fail_silently_false(
        self,
        mock_sleep,
        encrypted_mail,
    ) -> None:
        """Test all retry attempts fail with fail_silently=False."""
        with patch.object(encrypted_mail, "send_encrypted_mail") as mock_send:
            mock_send.side_effect = Exception("Error")

            with pytest.raises(Exception, match="Error"):
                encrypted_mail.send_mail_with_retries("Test Subject", "Test Message")

            assert mock_send.call_count == 10  # MAX_RETRY_ATTEMPTS
            encrypted_mail.logger.exception.assert_called_with(
                "All attempts failed. Terminating.",
            )

    @patch("time.sleep")
    def test_send_mail_with_retries_all_failures_fail_silently_true(
        self,
        mock_sleep,
        encrypted_mail,
    ) -> None:
        """Test all retry attempts fail with fail_silently=True."""
        encrypted_mail.fail_silently = True

        with patch.object(encrypted_mail, "send_encrypted_mail") as mock_send:
            mock_send.side_effect = Exception("Error")

            # Should not raise exception
            encrypted_mail.send_mail_with_retries("Test Subject", "Test Message")

            assert mock_send.call_count == 10  # MAX_RETRY_ATTEMPTS
            encrypted_mail.logger.exception.assert_called_with(
                "All attempts failed. Terminating.",
            )

    @patch("time.sleep")
    def test_send_mail_with_retries_proper_delay(
        self,
        mock_sleep,
        encrypted_mail,
    ) -> None:
        """Test that proper delay is used between retry attempts."""
        with patch.object(encrypted_mail, "send_encrypted_mail") as mock_send:
            mock_send.side_effect = [Exception("Error"), None]

            encrypted_mail.send_mail_with_retries("Test Subject", "Test Message")

            mock_sleep.assert_called_once_with(2)  # RETRY_DELAY_SECONDS


class TestMainFunction:
    """Test cases for main function."""

    @patch("opsbox.encrypted_mail.encrypted_mail.configure_logging")
    @patch("opsbox.encrypted_mail.encrypted_mail.EncryptedMail")
    def test_main_success(
        self,
        mock_encrypted_mail_class,
        mock_configure_logging,
    ) -> None:
        """Test successful main function execution."""
        # Mock logging
        mock_log_handler = Mock(spec=logging.Logger)
        mock_configure_logging.return_value = mock_log_handler

        # Mock EncryptedMail
        mock_encrypted_mail = Mock()
        mock_encrypted_mail_class.return_value = mock_encrypted_mail

        # Create temporary settings file
        config_data = {
            "sender": "test@example.com",
            "recipient": "recipient@example.com",
            "password_lookup_1": "service",
            "password_lookup_2": "username",
            "host": "smtp.example.com",
            "port": 587,
            "user": "testuser",
            "security": "starttls",
            "gpg_key_id": "test-key-id",
            "default_user": "testuser",
            "password": "testpassword",
        }

        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump(config_data, f)
            temp_path = f.name

        try:
            with patch(
                "sys.argv",
                [
                    "encrypted_mail.py",
                    "--email-settings",
                    temp_path,
                    "--subject",
                    "Test Subject",
                    "--message",
                    "Test Message",
                ],
            ):
                main()

            mock_encrypted_mail.send_mail_with_retries.assert_called_once_with(
                "Test Subject",
                "Test Message",
                None,
            )
        finally:
            Path(temp_path).unlink()

    @patch("opsbox.encrypted_mail.encrypted_mail.configure_logging")
    def test_main_with_attachment(self, mock_configure_logging) -> None:
        """Test main function with attachment."""
        # Mock logging
        mock_log_handler = Mock(spec=logging.Logger)
        mock_configure_logging.return_value = mock_log_handler

        # Create temporary settings file
        config_data = {
            "sender": "test@example.com",
            "recipient": "recipient@example.com",
            "password_lookup_1": "service",
            "password_lookup_2": "username",
            "host": "smtp.example.com",
            "port": 587,
            "user": "testuser",
            "security": "starttls",
            "gpg_key_id": "test-key-id",
            "default_user": "testuser",
            "password": "testpassword",
        }

        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump(config_data, f)
            temp_path = f.name

        try:
            with patch(
                "sys.argv",
                [
                    "encrypted_mail.py",
                    "--email-settings",
                    temp_path,
                    "--subject",
                    "Test Subject",
                    "--message",
                    "Test Message",
                    "--attachment",
                    "test.txt",
                ],
            ):
                with patch(
                    "opsbox.encrypted_mail.encrypted_mail.EncryptedMail",
                ) as mock_encrypted_mail_class:
                    mock_encrypted_mail = Mock()
                    mock_encrypted_mail_class.return_value = mock_encrypted_mail
                    main()

                    mock_encrypted_mail.send_mail_with_retries.assert_called_once_with(
                        "Test Subject",
                        "Test Message",
                        "test.txt",
                    )
        finally:
            Path(temp_path).unlink()

    @patch("opsbox.encrypted_mail.encrypted_mail.configure_logging")
    def test_main_missing_required_argument(self, mock_configure_logging) -> None:
        """Test main function with missing required argument."""
        # Mock logging
        mock_log_handler = Mock(spec=logging.Logger)
        mock_configure_logging.return_value = mock_log_handler

        with patch("sys.argv", ["encrypted_mail.py"]):
            with pytest.raises(SystemExit):
                main()

    @patch("opsbox.encrypted_mail.encrypted_mail.configure_logging")
    def test_main_email_settings_error(self, mock_configure_logging) -> None:
        """Test main function with email settings error."""
        # Mock logging
        mock_log_handler = Mock(spec=logging.Logger)
        mock_configure_logging.return_value = mock_log_handler

        with patch(
            "sys.argv",
            [
                "encrypted_mail.py",
                "--email-settings",
                "/nonexistent/path/settings.json",
                "--subject",
                "Test Subject",
                "--message",
                "Test Message",
            ],
        ):
            with patch("sys.exit") as mock_exit:
                main()
                mock_exit.assert_called_once_with(1)
                mock_log_handler.exception.assert_called_once_with(
                    "Configuration error",
                )

    @patch("opsbox.encrypted_mail.encrypted_mail.configure_logging")
    def test_main_system_error(self, mock_configure_logging) -> None:
        """Test main function with system error."""
        # Mock logging
        mock_log_handler = Mock(spec=logging.Logger)
        mock_configure_logging.return_value = mock_log_handler

        # Create temporary settings file
        config_data = {
            "sender": "test@example.com",
            "recipient": "recipient@example.com",
            "password_lookup_1": "service",
            "password_lookup_2": "username",
            "host": "smtp.example.com",
            "port": 587,
            "user": "testuser",
            "security": "starttls",
            "gpg_key_id": "test-key-id",
            "default_user": "testuser",
            "password": "testpassword",
        }

        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump(config_data, f)
            temp_path = f.name

        try:
            with patch(
                "sys.argv",
                [
                    "encrypted_mail.py",
                    "--email-settings",
                    temp_path,
                    "--subject",
                    "Test Subject",
                    "--message",
                    "Test Message",
                ],
            ):
                with patch(
                    "opsbox.encrypted_mail.encrypted_mail.EncryptedMail",
                ) as mock_encrypted_mail_class:
                    mock_encrypted_mail = Mock()
                    mock_encrypted_mail.send_mail_with_retries.side_effect = OSError(
                        "System error",
                    )
                    mock_encrypted_mail_class.return_value = mock_encrypted_mail

                    with patch("sys.exit") as mock_exit:
                        main()
                        mock_exit.assert_called_once_with(1)
                        mock_log_handler.exception.assert_called_once_with(
                            "System error",
                        )
        finally:
            Path(temp_path).unlink()


class TestEncryptedMailConstants:
    """Test cases for EncryptedMail class constants."""

    def test_encrypted_mail_constants(self) -> None:
        """Test that EncryptedMail constants have expected values."""
        assert EncryptedMail.MAX_ATTACHMENT_SIZE == 5 * 1024 * 1024  # 5MB
        assert EncryptedMail.MAX_RETRY_ATTEMPTS == 10
        assert EncryptedMail.RETRY_DELAY_SECONDS == 2

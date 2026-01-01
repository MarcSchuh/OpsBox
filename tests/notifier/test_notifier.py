"""Tests for the NotificationSender class and CLI interface."""

import logging
import subprocess
from unittest.mock import MagicMock, Mock, patch

import pytest

from opsbox.notifier.exceptions import (
    DBusNotAvailableError,
    DBusNotificationError,
    NotificationSendError,
    UsernameRequiredError,
    UserNotFoundError,
)
from opsbox.notifier.notifier import NotificationSender, main


class TestNotificationSenderInitialization:
    """Test cases for NotificationSender initialization."""

    def test_initialization_with_logger(self) -> None:
        """Test NotificationSender initializes successfully with logger."""
        logger = Mock(spec=logging.Logger)
        sender = NotificationSender(logger)
        assert sender.logger == logger


class TestNotificationSenderAsNormalUser:
    """Test cases for NotificationSender when running as normal user."""

    @patch("opsbox.notifier.notifier.os.geteuid", return_value=1000)
    @patch("opsbox.notifier.notifier.dbus")
    def test_send_notification_success(
        self,
        mock_dbus: MagicMock,
        mock_geteuid: MagicMock,
    ) -> None:
        """Test notification sent successfully as normal user."""
        logger = Mock(spec=logging.Logger)
        sender = NotificationSender(logger)

        # Setup D-Bus mocks
        mock_session_bus = MagicMock()
        mock_notify_object = MagicMock()
        mock_notify_interface = MagicMock()
        mock_dbus.SessionBus.return_value = mock_session_bus
        mock_session_bus.get_object.return_value = mock_notify_object
        mock_dbus.Interface.return_value = mock_notify_interface

        sender.send_notification("Test Summary", "Test Body")

        # Verify notification was sent via D-Bus
        mock_dbus.SessionBus.assert_called_once()
        mock_session_bus.get_object.assert_called_once_with(
            "org.freedesktop.Notifications",
            "/org/freedesktop/Notifications",
        )
        mock_dbus.Interface.assert_called_once_with(
            mock_notify_object,
            "org.freedesktop.Notifications",
        )
        mock_notify_interface.Notify.assert_called_once_with(
            "OpsBox",
            0,
            "",
            "Test Summary",
            "Test Body",
            [],
            {},
            5000,
        )
        logger.info.assert_called_once_with(
            "Notification sent: Test Summary - Test Body",
        )

    @patch("opsbox.notifier.notifier.os.geteuid", return_value=1000)
    def test_send_notification_with_dbus_unavailable(
        self,
        mock_geteuid: MagicMock,
    ) -> None:
        """Test raises DBusNotAvailableError when D-Bus is not available."""
        logger = Mock(spec=logging.Logger)
        sender = NotificationSender(logger)

        with patch("opsbox.notifier.notifier.dbus", None):
            with pytest.raises(DBusNotAvailableError) as exc_info:
                sender.send_notification("Test Summary", "Test Body")

            assert "D-Bus module is not installed" in str(exc_info.value)
            logger.error.assert_called_once_with("D-Bus module is not installed")

    @patch("opsbox.notifier.notifier.os.geteuid", return_value=1000)
    @patch("opsbox.notifier.notifier.dbus")
    def test_send_notification_with_dbus_error(
        self,
        mock_dbus: MagicMock,
        mock_geteuid: MagicMock,
    ) -> None:
        """Test raises DBusNotificationError when D-Bus operation fails."""
        logger = Mock(spec=logging.Logger)
        sender = NotificationSender(logger)

        # Create a proper exception class that will be caught
        class MockDBusError(Exception):
            pass

        # Setup D-Bus to raise exception during Notify call
        mock_dbus_exception = MockDBusError("Connection failed")
        # Make the exception accessible via dbus.exceptions
        mock_dbus.exceptions.DBusException = MockDBusError
        mock_session_bus = MagicMock()
        mock_notify_object = MagicMock()
        mock_notify_interface = MagicMock()
        mock_dbus.SessionBus.return_value = mock_session_bus
        mock_session_bus.get_object.return_value = mock_notify_object
        mock_dbus.Interface.return_value = mock_notify_interface
        mock_notify_interface.Notify.side_effect = mock_dbus_exception

        with pytest.raises(DBusNotificationError) as exc_info:
            sender.send_notification("Test Summary", "Test Body")

        assert "Failed to send notification via D-Bus" in str(exc_info.value)
        assert exc_info.value.original_error == mock_dbus_exception
        logger.exception.assert_called_once()

    @patch("opsbox.notifier.notifier.os.geteuid", return_value=1000)
    @patch("opsbox.notifier.notifier.dbus")
    def test_send_notification_username_ignored(
        self,
        mock_dbus: MagicMock,
        mock_geteuid: MagicMock,
    ) -> None:
        """Test username parameter is ignored when running as normal user."""
        logger = Mock(spec=logging.Logger)
        sender = NotificationSender(logger)

        # Setup D-Bus mocks
        mock_session_bus = MagicMock()
        mock_notify_object = MagicMock()
        mock_notify_interface = MagicMock()
        mock_dbus.SessionBus.return_value = mock_session_bus
        mock_session_bus.get_object.return_value = mock_notify_object
        mock_dbus.Interface.return_value = mock_notify_interface

        # Username provided but should be ignored
        sender.send_notification("Test Summary", "Test Body", username="someuser")

        # Verify notification was sent via D-Bus (not as user)
        mock_dbus.SessionBus.assert_called_once()
        mock_notify_interface.Notify.assert_called_once()


class TestNotificationSenderAsRoot:
    """Test cases for NotificationSender when running as root."""

    @patch("opsbox.notifier.notifier.os.geteuid", return_value=0)
    @patch("opsbox.notifier.notifier.subprocess.run")
    @patch("opsbox.notifier.notifier.subprocess.check_output")
    @patch("opsbox.notifier.notifier.pwd.getpwnam")
    def test_send_notification_success_with_username(
        self,
        mock_getpwnam: MagicMock,
        mock_check_output: MagicMock,
        mock_run: MagicMock,
        mock_geteuid: MagicMock,
    ) -> None:
        """Test notification sent successfully to specified user when running as root."""
        logger = Mock(spec=logging.Logger)
        sender = NotificationSender(logger)

        # Setup user lookup
        mock_user_info = Mock()
        mock_user_info.pw_uid = 1000
        mock_getpwnam.return_value = mock_user_info

        # Setup DISPLAY retrieval
        mock_check_output.return_value = b":1.0"

        # Setup successful notification command
        mock_run.return_value = Mock(returncode=0)

        sender.send_notification("Test Summary", "Test Body", username="testuser")

        # Verify user lookup
        mock_getpwnam.assert_called_once_with("testuser")

        # Verify notification command was constructed and executed correctly
        mock_run.assert_called_once()
        call_args = mock_run.call_args[0][0]
        assert call_args[0] == "sudo"
        assert call_args[1] == "-u"
        assert call_args[2] == "testuser"
        assert "notify-send" in call_args
        assert "Test Summary" in call_args
        assert "Test Body" in call_args

        logger.info.assert_called_once_with(
            "Notification sent to testuser: Test Summary - Test Body",
        )

    @patch("opsbox.notifier.notifier.os.geteuid", return_value=0)
    def test_send_notification_requires_username(
        self,
        mock_geteuid: MagicMock,
    ) -> None:
        """Test raises UsernameRequiredError when username is missing when running as root."""
        logger = Mock(spec=logging.Logger)
        sender = NotificationSender(logger)

        with pytest.raises(UsernameRequiredError) as exc_info:
            sender.send_notification("Test Summary", "Test Body")

        assert "Username is required when running as root" in str(exc_info.value)
        logger.error.assert_called_once_with(
            "Username is required when running as root",
        )

    @patch("opsbox.notifier.notifier.os.geteuid", return_value=0)
    @patch("opsbox.notifier.notifier.pwd.getpwnam")
    def test_send_notification_user_not_found(
        self,
        mock_getpwnam: MagicMock,
        mock_geteuid: MagicMock,
    ) -> None:
        """Test raises UserNotFoundError when specified user does not exist."""
        logger = Mock(spec=logging.Logger)
        sender = NotificationSender(logger)

        # Setup user lookup to fail
        mock_getpwnam.side_effect = KeyError("User not found")

        with pytest.raises(UserNotFoundError) as exc_info:
            sender.send_notification(
                "Test Summary",
                "Test Body",
                username="nonexistent",
            )

        assert "User nonexistent does not exist" in str(exc_info.value)
        logger.exception.assert_called_once()

    @patch("opsbox.notifier.notifier.os.geteuid", return_value=0)
    @patch("opsbox.notifier.notifier.subprocess.run")
    @patch("opsbox.notifier.notifier.subprocess.check_output")
    @patch("opsbox.notifier.notifier.pwd.getpwnam")
    def test_send_notification_command_failure(
        self,
        mock_getpwnam: MagicMock,
        mock_check_output: MagicMock,
        mock_run: MagicMock,
        mock_geteuid: MagicMock,
    ) -> None:
        """Test raises NotificationSendError when notification command fails."""
        logger = Mock(spec=logging.Logger)
        sender = NotificationSender(logger)

        # Setup user lookup
        mock_user_info = Mock()
        mock_user_info.pw_uid = 1000
        mock_getpwnam.return_value = mock_user_info

        # Setup DISPLAY retrieval
        mock_check_output.return_value = b":1.0"

        # Setup notification command to fail
        mock_error = subprocess.CalledProcessError(1, "notify-send")
        mock_run.side_effect = mock_error

        with pytest.raises(NotificationSendError) as exc_info:
            sender.send_notification("Test Summary", "Test Body", username="testuser")

        assert "Failed to send notification to testuser" in str(exc_info.value)
        assert exc_info.value.original_error == mock_error
        logger.exception.assert_called_once()

    @patch("opsbox.notifier.notifier.os.geteuid", return_value=0)
    @patch("opsbox.notifier.notifier.subprocess.run")
    @patch("opsbox.notifier.notifier.subprocess.check_output")
    @patch("opsbox.notifier.notifier.pwd.getpwnam")
    def test_send_notification_handles_missing_display(
        self,
        mock_getpwnam: MagicMock,
        mock_check_output: MagicMock,
        mock_run: MagicMock,
        mock_geteuid: MagicMock,
    ) -> None:
        """Test handles missing DISPLAY variable gracefully by defaulting to :0."""
        logger = Mock(spec=logging.Logger)
        sender = NotificationSender(logger)

        # Setup user lookup
        mock_user_info = Mock()
        mock_user_info.pw_uid = 1000
        mock_getpwnam.return_value = mock_user_info

        # Setup DISPLAY retrieval to fail (empty or error)
        mock_check_output.side_effect = subprocess.CalledProcessError(1, "echo")

        # Setup successful notification command
        mock_run.return_value = Mock(returncode=0)

        sender.send_notification("Test Summary", "Test Body", username="testuser")

        # Verify notification command uses default DISPLAY
        mock_run.assert_called_once()
        call_args = mock_run.call_args[0][0]
        assert "DISPLAY=:0" in call_args

    @patch("opsbox.notifier.notifier.os.geteuid", return_value=0)
    @patch("opsbox.notifier.notifier.subprocess.run")
    @patch("opsbox.notifier.notifier.subprocess.check_output")
    @patch("opsbox.notifier.notifier.pwd.getpwnam")
    def test_send_notification_handles_empty_display(
        self,
        mock_getpwnam: MagicMock,
        mock_check_output: MagicMock,
        mock_run: MagicMock,
        mock_geteuid: MagicMock,
    ) -> None:
        """Test handles empty DISPLAY variable by defaulting to :0."""
        logger = Mock(spec=logging.Logger)
        sender = NotificationSender(logger)

        # Setup user lookup
        mock_user_info = Mock()
        mock_user_info.pw_uid = 1000
        mock_getpwnam.return_value = mock_user_info

        # Setup DISPLAY retrieval to return empty string
        mock_check_output.return_value = b""

        # Setup successful notification command
        mock_run.return_value = Mock(returncode=0)

        sender.send_notification("Test Summary", "Test Body", username="testuser")

        # Verify notification command uses default DISPLAY
        mock_run.assert_called_once()
        call_args = mock_run.call_args[0][0]
        assert "DISPLAY=:0" in call_args


class TestNotificationSenderEdgeCases:
    """Test cases for edge cases and special scenarios."""

    @patch("opsbox.notifier.notifier.os.geteuid", return_value=1000)
    @patch("opsbox.notifier.notifier.dbus")
    def test_send_notification_empty_summary(
        self,
        mock_dbus: MagicMock,
        mock_geteuid: MagicMock,
    ) -> None:
        """Test handles empty summary string."""
        logger = Mock(spec=logging.Logger)
        sender = NotificationSender(logger)

        # Setup D-Bus mocks
        mock_session_bus = MagicMock()
        mock_notify_object = MagicMock()
        mock_notify_interface = MagicMock()
        mock_dbus.SessionBus.return_value = mock_session_bus
        mock_session_bus.get_object.return_value = mock_notify_object
        mock_dbus.Interface.return_value = mock_notify_interface

        sender.send_notification("", "Test Body")

        # Verify notification was sent with empty summary
        mock_notify_interface.Notify.assert_called_once_with(
            "OpsBox",
            0,
            "",
            "",
            "Test Body",
            [],
            {},
            5000,
        )

    @patch("opsbox.notifier.notifier.os.geteuid", return_value=1000)
    @patch("opsbox.notifier.notifier.dbus")
    def test_send_notification_empty_body(
        self,
        mock_dbus: MagicMock,
        mock_geteuid: MagicMock,
    ) -> None:
        """Test handles empty body string."""
        logger = Mock(spec=logging.Logger)
        sender = NotificationSender(logger)

        # Setup D-Bus mocks
        mock_session_bus = MagicMock()
        mock_notify_object = MagicMock()
        mock_notify_interface = MagicMock()
        mock_dbus.SessionBus.return_value = mock_session_bus
        mock_session_bus.get_object.return_value = mock_notify_object
        mock_dbus.Interface.return_value = mock_notify_interface

        sender.send_notification("Test Summary", "")

        # Verify notification was sent with empty body
        mock_notify_interface.Notify.assert_called_once_with(
            "OpsBox",
            0,
            "",
            "Test Summary",
            "",
            [],
            {},
            5000,
        )

    @patch("opsbox.notifier.notifier.os.geteuid", return_value=1000)
    @patch("opsbox.notifier.notifier.dbus")
    def test_send_notification_long_message(
        self,
        mock_dbus: MagicMock,
        mock_geteuid: MagicMock,
    ) -> None:
        """Test handles long notification messages."""
        logger = Mock(spec=logging.Logger)
        sender = NotificationSender(logger)

        # Setup D-Bus mocks
        mock_session_bus = MagicMock()
        mock_notify_object = MagicMock()
        mock_notify_interface = MagicMock()
        mock_dbus.SessionBus.return_value = mock_session_bus
        mock_session_bus.get_object.return_value = mock_notify_object
        mock_dbus.Interface.return_value = mock_notify_interface

        long_message = "A" * 1000
        sender.send_notification("Test Summary", long_message)

        # Verify notification was sent with long message
        mock_notify_interface.Notify.assert_called_once()
        call_args = mock_notify_interface.Notify.call_args[0]
        assert call_args[4] == long_message

    @patch("opsbox.notifier.notifier.os.geteuid", return_value=1000)
    @patch("opsbox.notifier.notifier.dbus")
    def test_send_notification_special_characters(
        self,
        mock_dbus: MagicMock,
        mock_geteuid: MagicMock,
    ) -> None:
        """Test handles special characters in notification message."""
        logger = Mock(spec=logging.Logger)
        sender = NotificationSender(logger)

        # Setup D-Bus mocks
        mock_session_bus = MagicMock()
        mock_notify_object = MagicMock()
        mock_notify_interface = MagicMock()
        mock_dbus.SessionBus.return_value = mock_session_bus
        mock_session_bus.get_object.return_value = mock_notify_object
        mock_dbus.Interface.return_value = mock_notify_interface

        special_message = "Test with special chars: <>&\"'"
        sender.send_notification("Summary: <>&\"'", special_message)

        # Verify notification was sent with special characters
        mock_notify_interface.Notify.assert_called_once()
        call_args = mock_notify_interface.Notify.call_args[0]
        assert call_args[3] == "Summary: <>&\"'"
        assert call_args[4] == special_message


class TestNotificationSenderCLI:
    """Test cases for the CLI interface (main function)."""

    @patch("opsbox.notifier.notifier.sys.argv", ["notifier", "Test message"])
    @patch("opsbox.notifier.notifier.os.geteuid", return_value=1000)
    @patch("opsbox.notifier.notifier.dbus")
    @patch("opsbox.notifier.notifier.configure_logging")
    def test_main_success_normal_user(
        self,
        mock_configure_logging: MagicMock,
        mock_dbus: MagicMock,
        mock_geteuid: MagicMock,
    ) -> None:
        """Test CLI sends notification successfully as normal user."""
        # Setup logging
        mock_logger = Mock(spec=logging.Logger)
        mock_configure_logging.return_value = mock_logger

        # Setup D-Bus mocks
        mock_session_bus = MagicMock()
        mock_notify_object = MagicMock()
        mock_notify_interface = MagicMock()
        mock_dbus.SessionBus.return_value = mock_session_bus
        mock_session_bus.get_object.return_value = mock_notify_object
        mock_dbus.Interface.return_value = mock_notify_interface

        with patch("opsbox.notifier.notifier.sys.exit") as mock_exit:
            main()
            # Should not exit with error
            mock_exit.assert_not_called()

        # Verify notification was sent
        mock_notify_interface.Notify.assert_called_once()

    @patch(
        "opsbox.notifier.notifier.sys.argv",
        ["notifier", "Test message", "--username", "testuser"],
    )
    @patch("opsbox.notifier.notifier.os.geteuid", return_value=0)
    @patch("opsbox.notifier.notifier.subprocess.run")
    @patch("opsbox.notifier.notifier.subprocess.check_output")
    @patch("opsbox.notifier.notifier.pwd.getpwnam")
    @patch("opsbox.notifier.notifier.configure_logging")
    def test_main_success_root_with_username(
        self,
        mock_configure_logging: MagicMock,
        mock_getpwnam: MagicMock,
        mock_check_output: MagicMock,
        mock_run: MagicMock,
        mock_geteuid: MagicMock,
    ) -> None:
        """Test CLI sends notification successfully as root with username."""
        # Setup logging
        mock_logger = Mock(spec=logging.Logger)
        mock_configure_logging.return_value = mock_logger

        # Setup user lookup
        mock_user_info = Mock()
        mock_user_info.pw_uid = 1000
        mock_getpwnam.return_value = mock_user_info

        # Setup DISPLAY retrieval
        mock_check_output.return_value = b":1.0"

        # Setup successful notification command
        mock_run.return_value = Mock(returncode=0)

        with patch("opsbox.notifier.notifier.sys.exit") as mock_exit:
            main()
            # Should not exit with error
            mock_exit.assert_not_called()

        # Verify notification command was executed
        mock_run.assert_called_once()

    @patch(
        "opsbox.notifier.notifier.sys.argv",
        ["notifier", "Test message"],
    )
    @patch("opsbox.notifier.notifier.os.geteuid", return_value=0)
    @patch("opsbox.notifier.notifier.configure_logging")
    def test_main_missing_username_as_root(
        self,
        mock_configure_logging: MagicMock,
        mock_geteuid: MagicMock,
    ) -> None:
        """Test CLI exits with code 1 when username missing as root."""
        # Setup logging
        mock_logger = Mock(spec=logging.Logger)
        mock_configure_logging.return_value = mock_logger

        with patch("opsbox.notifier.notifier.sys.exit") as mock_exit:
            main()
            # Should exit with code 1
            mock_exit.assert_called_once_with(1)

        # Verify error was logged
        mock_logger.exception.assert_called_once_with("Notification failed")

    @patch(
        "opsbox.notifier.notifier.sys.argv",
        ["notifier", "Test message", "--username", "nonexistent"],
    )
    @patch("opsbox.notifier.notifier.os.geteuid", return_value=0)
    @patch("opsbox.notifier.notifier.pwd.getpwnam")
    @patch("opsbox.notifier.notifier.configure_logging")
    def test_main_user_not_found(
        self,
        mock_configure_logging: MagicMock,
        mock_getpwnam: MagicMock,
        mock_geteuid: MagicMock,
    ) -> None:
        """Test CLI exits with code 1 when user not found."""
        # Setup logging
        mock_logger = Mock(spec=logging.Logger)
        mock_configure_logging.return_value = mock_logger

        # Setup user lookup to fail
        mock_getpwnam.side_effect = KeyError("User not found")

        with patch("opsbox.notifier.notifier.sys.exit") as mock_exit:
            main()
            # Should exit with code 1
            mock_exit.assert_called_once_with(1)

        # Verify error was logged (may be called multiple times due to exception chaining)
        assert mock_logger.exception.call_count >= 1
        # Verify the final error message was logged
        assert any(
            "Notification failed" in str(call)
            for call in mock_logger.exception.call_args_list
        )

    @patch("opsbox.notifier.notifier.sys.argv", ["notifier", "Test message"])
    @patch("opsbox.notifier.notifier.os.geteuid", return_value=1000)
    @patch("opsbox.notifier.notifier.dbus")
    @patch("opsbox.notifier.notifier.configure_logging")
    def test_main_dbus_error(
        self,
        mock_configure_logging: MagicMock,
        mock_dbus: MagicMock,
        mock_geteuid: MagicMock,
    ) -> None:
        """Test CLI exits with code 1 on D-Bus errors."""
        # Setup logging
        mock_logger = Mock(spec=logging.Logger)
        mock_configure_logging.return_value = mock_logger

        # Create a proper exception class that will be caught
        class MockDBusError(Exception):
            pass

        # Setup D-Bus to raise exception during Notify call
        mock_dbus_exception = MockDBusError("Connection failed")
        # Make the exception accessible via dbus.exceptions
        mock_dbus.exceptions.DBusException = MockDBusError
        mock_session_bus = MagicMock()
        mock_notify_object = MagicMock()
        mock_notify_interface = MagicMock()
        mock_dbus.SessionBus.return_value = mock_session_bus
        mock_session_bus.get_object.return_value = mock_notify_object
        mock_dbus.Interface.return_value = mock_notify_interface
        mock_notify_interface.Notify.side_effect = mock_dbus_exception

        with patch("opsbox.notifier.notifier.sys.exit") as mock_exit:
            main()
            # Should exit with code 1
            mock_exit.assert_called_once_with(1)

        # Verify error was logged (may be called multiple times due to exception chaining)
        assert mock_logger.exception.call_count >= 1
        # Verify the final error message was logged
        assert any(
            "Notification failed" in str(call)
            for call in mock_logger.exception.call_args_list
        )

    @patch("opsbox.notifier.notifier.sys.argv", ["notifier", "Test message"])
    @patch("opsbox.notifier.notifier.os.geteuid", return_value=1000)
    @patch("opsbox.notifier.notifier.dbus")
    @patch("opsbox.notifier.notifier.configure_logging")
    def test_main_unexpected_error(
        self,
        mock_configure_logging: MagicMock,
        mock_dbus: MagicMock,
        mock_geteuid: MagicMock,
    ) -> None:
        """Test CLI exits with code 2 on unexpected errors."""
        # Setup logging
        mock_logger = Mock(spec=logging.Logger)
        mock_configure_logging.return_value = mock_logger

        # Setup D-Bus to raise unexpected exception
        mock_dbus.SessionBus.side_effect = ValueError("Unexpected error")

        with patch("opsbox.notifier.notifier.sys.exit") as mock_exit:
            main()
            # Should exit with code 2 for unexpected errors
            mock_exit.assert_called_once_with(2)

        # Verify error was logged
        mock_logger.exception.assert_called_once_with(
            "Unexpected error during notification",
        )

    @patch(
        "opsbox.notifier.notifier.sys.argv",
        ["notifier", "Test message", "--summary", "Custom Summary"],
    )
    @patch("opsbox.notifier.notifier.os.geteuid", return_value=1000)
    @patch("opsbox.notifier.notifier.dbus")
    @patch("opsbox.notifier.notifier.configure_logging")
    def test_main_custom_summary(
        self,
        mock_configure_logging: MagicMock,
        mock_dbus: MagicMock,
        mock_geteuid: MagicMock,
    ) -> None:
        """Test CLI uses custom summary when provided."""
        # Setup logging
        mock_logger = Mock(spec=logging.Logger)
        mock_configure_logging.return_value = mock_logger

        # Setup D-Bus mocks
        mock_session_bus = MagicMock()
        mock_notify_object = MagicMock()
        mock_notify_interface = MagicMock()
        mock_dbus.SessionBus.return_value = mock_session_bus
        mock_session_bus.get_object.return_value = mock_notify_object
        mock_dbus.Interface.return_value = mock_notify_interface

        with patch("opsbox.notifier.notifier.sys.exit"):
            main()

        # Verify notification was sent with custom summary
        mock_notify_interface.Notify.assert_called_once()
        call_args = mock_notify_interface.Notify.call_args[0]
        assert call_args[3] == "Custom Summary"
        assert call_args[4] == "Test message"

    @patch("opsbox.notifier.notifier.sys.argv", ["notifier", "Test message"])
    @patch("opsbox.notifier.notifier.os.geteuid", return_value=1000)
    @patch("opsbox.notifier.notifier.dbus")
    @patch("opsbox.notifier.notifier.configure_logging")
    def test_main_default_summary(
        self,
        mock_configure_logging: MagicMock,
        mock_dbus: MagicMock,
        mock_geteuid: MagicMock,
    ) -> None:
        """Test CLI uses default summary when not provided."""
        # Setup logging
        mock_logger = Mock(spec=logging.Logger)
        mock_configure_logging.return_value = mock_logger

        # Setup D-Bus mocks
        mock_session_bus = MagicMock()
        mock_notify_object = MagicMock()
        mock_notify_interface = MagicMock()
        mock_dbus.SessionBus.return_value = mock_session_bus
        mock_session_bus.get_object.return_value = mock_notify_object
        mock_dbus.Interface.return_value = mock_notify_interface

        with patch("opsbox.notifier.notifier.sys.exit"):
            main()

        # Verify notification was sent with default summary
        mock_notify_interface.Notify.assert_called_once()
        call_args = mock_notify_interface.Notify.call_args[0]
        assert call_args[3] == "Notification"
        assert call_args[4] == "Test message"

    @patch(
        "opsbox.notifier.notifier.sys.argv",
        ["notifier", "Test message", "--log-level", "DEBUG"],
    )
    @patch("opsbox.notifier.notifier.os.geteuid", return_value=1000)
    @patch("opsbox.notifier.notifier.dbus")
    @patch("opsbox.notifier.notifier.configure_logging")
    def test_main_log_level_configuration(
        self,
        mock_configure_logging: MagicMock,
        mock_dbus: MagicMock,
        mock_geteuid: MagicMock,
    ) -> None:
        """Test CLI configures logging level correctly."""
        # Setup logging
        mock_logger = Mock(spec=logging.Logger)
        mock_configure_logging.return_value = mock_logger

        # Setup D-Bus mocks
        mock_session_bus = MagicMock()
        mock_notify_object = MagicMock()
        mock_notify_interface = MagicMock()
        mock_dbus.SessionBus.return_value = mock_session_bus
        mock_session_bus.get_object.return_value = mock_notify_object
        mock_dbus.Interface.return_value = mock_notify_interface

        with patch("opsbox.notifier.notifier.sys.exit"):
            main()

        # Verify logging was configured with correct level
        mock_configure_logging.assert_called_once()
        call_args = mock_configure_logging.call_args[0][0]
        assert call_args.log_level == "DEBUG"
        assert call_args.log_name == "notification_sender"
        assert call_args.log_filename == "notifications.log"

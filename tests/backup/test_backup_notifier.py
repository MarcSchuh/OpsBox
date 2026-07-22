"""Tests for BackupNotifier email/reporting behavior."""

from pathlib import Path
from types import SimpleNamespace
from typing import Any, cast
from unittest.mock import Mock

import pytest

from opsbox.backup.backup_notifier import BackupNotifier
from opsbox.backup.config_manager import BackupConfig
from opsbox.backup.exceptions import (
    BackupError,
    MaintenanceError,
    ResticBackupFailedError,
    VerificationError,
)
from opsbox.backup.restic_diff import ResticDiff
from opsbox.backup.snapshot_id import ResticSnapshotId

SNAPSHOT = ResticSnapshotId("c9d0e1f2")


def make_config(**overrides: object) -> BackupConfig:
    """Build a config stand-in exposing only the fields BackupNotifier reads.

    A ``SimpleNamespace`` is used as a lightweight double (a real BackupConfig
    would validate paths on construction) and cast to BackupConfig for typing.
    """
    defaults: dict[str, object] = {
        "backup_title": "MyBackup",
        "backup_target": "sftp:user@host:/repo",
        "file_to_check": "important_file.txt",
        "deletion_threshold": None,
        "alteration_threshold": None,
        "addition_threshold": None,
        "monitored_folders": [],
    }
    defaults.update(overrides)
    return cast("BackupConfig", SimpleNamespace(**defaults))


@pytest.fixture
def mail() -> Mock:
    """Return a mock EncryptedMail."""
    return Mock()


def make_notifier(
    mail: Mock,
    temp_dir: Path,
    **config_overrides: object,
) -> BackupNotifier:
    """Build a BackupNotifier with a mock mailer and stand-in config."""
    return BackupNotifier(
        mail,
        make_config(**config_overrides),
        Mock(),  # logger
        temp_dir,
    )


def subjects(mail: Mock) -> list[str]:
    """Return all subjects passed to send_mail_with_retries."""
    return [
        call.kwargs.get("subject", "")
        for call in mail.send_mail_with_retries.call_args_list
    ]


def only_call(mail: Mock) -> dict[str, Any]:
    """Return the kwargs of the single send_mail_with_retries call."""
    mail.send_mail_with_retries.assert_called_once()
    return cast("dict[str, Any]", mail.send_mail_with_retries.call_args.kwargs)


class TestPrepareLogAttachment:
    """Tests for BackupNotifier.prepare_log_attachment."""

    def test_none_and_non_path_return_none(self, mail: Mock, tmp_path: Path) -> None:
        """None or a non str/Path value yields no attachment."""
        notifier = make_notifier(mail, tmp_path)
        assert notifier.prepare_log_attachment(None) is None
        assert notifier.prepare_log_attachment(123) is None  # type: ignore[arg-type]

    def test_missing_file_returns_none(self, mail: Mock, tmp_path: Path) -> None:
        """A path that does not exist yields no attachment."""
        notifier = make_notifier(mail, tmp_path)
        assert notifier.prepare_log_attachment(tmp_path / "nope.log") is None

    def test_small_file_returned_unchanged(self, mail: Mock, tmp_path: Path) -> None:
        """A log within the budget is attached as-is."""
        notifier = make_notifier(mail, tmp_path)
        log = tmp_path / "small.log"
        log.write_text("small\n")
        assert notifier.prepare_log_attachment(log) == str(log)

    def test_large_file_is_truncated(self, mail: Mock, tmp_path: Path) -> None:
        """An oversized log becomes a head+tail excerpt below the budget."""
        notifier = make_notifier(mail, tmp_path)
        log = tmp_path / "restic_session_big.log"
        log.write_bytes(b"HEAD_MARKER\n" + b"x" * (5 * 1024 * 1024) + b"\nTAIL_MARKER")

        result = notifier.prepare_log_attachment(log)

        assert result is not None
        out = Path(result)
        assert out != log
        content = out.read_bytes()
        assert len(content) <= notifier.MAX_LOG_ATTACHMENT_BYTES
        text = content.decode("utf-8", errors="replace")
        assert "TRUNCATED LOG" in text
        assert "bytes omitted" in text
        assert b"HEAD_MARKER" in content
        assert b"TAIL_MARKER" in content
        assert "sftp:user@host:/repo" in text


class TestStatusEmails:
    """Tests for the workflow-status notifications."""

    def test_send_success_includes_summary_and_attachment(
        self,
        mail: Mock,
        tmp_path: Path,
    ) -> None:
        """Success email carries snapshot, summary and the (small) log."""
        notifier = make_notifier(mail, tmp_path)
        log = tmp_path / "session.log"
        log.write_text("ok\n")

        notifier.send_success(SNAPSHOT, "Changed files: 3", log)

        kwargs = only_call(mail)
        assert kwargs["subject"] == "Backup MyBackup successful"
        assert "Snapshot ID: c9d0e1f2" in kwargs["message"]
        assert "Changed files: 3" in kwargs["message"]
        assert kwargs["mail_attachment"] == str(log)

    @pytest.mark.parametrize(
        ("error", "expected_subject"),
        [
            (VerificationError("x"), "Backup MyBackup verification failed"),
            (MaintenanceError("x"), "Backup maintenance MyBackup failed"),
            (ResticBackupFailedError("x"), "Backup MyBackup failed"),
            (BackupError("x"), "Backup MyBackup failed"),
        ],
    )
    def test_failure_subject_matches_stage(
        self,
        mail: Mock,
        tmp_path: Path,
        error: BackupError,
        expected_subject: str,
    ) -> None:
        """The failure subject reflects the failing stage."""
        notifier = make_notifier(mail, tmp_path)
        notifier.send_failure(error, None)
        assert only_call(mail)["subject"] == expected_subject

    def test_send_skipped(self, mail: Mock, tmp_path: Path) -> None:
        """Skipped email uses the skipped subject."""
        notifier = make_notifier(mail, tmp_path)
        notifier.send_skipped(RuntimeError("net down"))
        kwargs = only_call(mail)
        assert kwargs["subject"] == "Backup MyBackup skipped"
        assert "net down" in kwargs["message"]

    def test_send_unexpected_error(self, mail: Mock, tmp_path: Path) -> None:
        """Unexpected-error email uses the script-error subject."""
        notifier = make_notifier(mail, tmp_path)
        notifier.send_unexpected_error(RuntimeError("boom"))
        kwargs = only_call(mail)
        assert kwargs["subject"] == "Backup MyBackup script error"
        assert "boom" in kwargs["message"]

    def test_send_verification_success(self, mail: Mock, tmp_path: Path) -> None:
        """Verification-success email references snapshot and checked file."""
        notifier = make_notifier(mail, tmp_path)
        notifier.send_verification_success(SNAPSHOT)
        kwargs = only_call(mail)
        assert kwargs["subject"] == "Backup MyBackup verification successful"
        assert "c9d0e1f2" in kwargs["message"]
        assert "important_file.txt" in kwargs["message"]

    def test_send_maintenance_success(self, mail: Mock, tmp_path: Path) -> None:
        """Maintenance-success email includes the check output."""
        notifier = make_notifier(mail, tmp_path)
        notifier.send_maintenance_success("no errors were found")
        kwargs = only_call(mail)
        assert kwargs["subject"] == "Backup maintenance MyBackup successful"
        assert "no errors were found" in kwargs["message"]

    def test_send_maintenance_warning(self, mail: Mock, tmp_path: Path) -> None:
        """Maintenance-warning email mentions the skipped prune."""
        notifier = make_notifier(mail, tmp_path)
        notifier.send_maintenance_warning("pack is damaged")
        kwargs = only_call(mail)
        assert (
            kwargs["subject"] == "Backup maintenance MyBackup completed with warnings"
        )
        assert "Prune was skipped" in kwargs["message"]
        assert "pack is damaged" in kwargs["message"]


def make_diff(
    *,
    added: list[str] | None = None,
    altered: list[str] | None = None,
    deleted: list[str] | None = None,
) -> ResticDiff:
    """Build a ResticDiff from lists of path strings."""
    return ResticDiff(
        added_files=[Path(p) for p in (added or [])],
        altered_files=[Path(p) for p in (altered or [])],
        deleted_files=[Path(p) for p in (deleted or [])],
        snapshot_id=SNAPSHOT,
    )


class TestFileChangeEmails:
    """Tests for send_file_changes."""

    def test_sends_one_email_per_non_empty_category(
        self,
        mail: Mock,
        tmp_path: Path,
    ) -> None:
        """Only non-empty change categories produce an email."""
        notifier = make_notifier(mail, tmp_path)
        diff = make_diff(added=["/a/new.txt"], deleted=["/a/gone.txt"])

        notifier.send_file_changes(diff)

        subs = subjects(mail)
        assert any("1 files added (Snapshot: c9d0e1f2)" in s for s in subs)
        assert any("1 files deleted (Snapshot: c9d0e1f2)" in s for s in subs)
        # No altered files -> no altered email
        assert not any("altered" in s for s in subs)

    def test_nothing_sent_when_no_changes(self, mail: Mock, tmp_path: Path) -> None:
        """An empty diff sends no file-change emails."""
        notifier = make_notifier(mail, tmp_path)
        notifier.send_file_changes(make_diff())
        mail.send_mail_with_retries.assert_not_called()

    def test_file_list_is_capped(self, mail: Mock, tmp_path: Path) -> None:
        """The listing is capped and reports how many files were omitted."""
        notifier = make_notifier(mail, tmp_path)
        cap = notifier.MAX_FILES_IN_EMAIL
        files = [f"/a/file{i}.txt" for i in range(cap + 2)]
        notifier.send_file_changes(make_diff(added=files))

        message = mail.send_mail_with_retries.call_args.kwargs["message"]
        assert "... and 2 more files" in message
        # Only the first `cap` files are listed verbatim.
        assert f"/a/file{cap - 1}.txt" in message
        assert f"/a/file{cap}.txt" not in message.split("... and")[0]


class TestThresholdWarnings:
    """Tests for send_threshold_warnings."""

    def test_no_warning_when_threshold_unset(self, mail: Mock, tmp_path: Path) -> None:
        """A None threshold never warns, regardless of the change count."""
        notifier = make_notifier(mail, tmp_path, deletion_threshold=None)
        notifier.send_threshold_warnings(make_diff(deleted=["/a", "/b", "/c"]))
        mail.send_mail_with_retries.assert_not_called()

    def test_no_warning_at_or_below_threshold(
        self,
        mail: Mock,
        tmp_path: Path,
    ) -> None:
        """Exactly `threshold` changes do not warn (strictly greater required)."""
        notifier = make_notifier(mail, tmp_path, deletion_threshold=3)
        notifier.send_threshold_warnings(make_diff(deleted=["/a", "/b", "/c"]))
        mail.send_mail_with_retries.assert_not_called()

    def test_warns_above_threshold_per_type(
        self,
        mail: Mock,
        tmp_path: Path,
    ) -> None:
        """Each change type warns independently when its threshold is exceeded."""
        notifier = make_notifier(
            mail,
            tmp_path,
            deletion_threshold=1,
            addition_threshold=1,
            alteration_threshold=10,
        )
        diff = make_diff(
            added=["/a", "/b"],
            altered=["/c", "/d"],
            deleted=["/e", "/f"],
        )
        notifier.send_threshold_warnings(diff)

        subs = subjects(mail)
        assert any("2 files deleted (threshold: 1)" in s for s in subs)
        assert any("2 files added (threshold: 1)" in s for s in subs)
        # alteration threshold (10) not exceeded by 2 altered files
        assert not any("altered (threshold" in s for s in subs)


class TestMonitoredFolderAlerts:
    """Tests for send_monitored_folder_alerts."""

    def test_no_alerts_without_monitored_folders(
        self,
        mail: Mock,
        tmp_path: Path,
    ) -> None:
        """No monitored folders configured means no alerts."""
        notifier = make_notifier(mail, tmp_path, monitored_folders=[])
        notifier.send_monitored_folder_alerts(make_diff(added=["/any/file.txt"]))
        mail.send_mail_with_retries.assert_not_called()

    def test_alerts_for_each_change_type_in_folder(
        self,
        mail: Mock,
        tmp_path: Path,
    ) -> None:
        """Added, altered and deleted files inside the folder each alert."""
        notifier = make_notifier(
            mail,
            tmp_path,
            monitored_folders=["/important/folder"],
        )
        diff = make_diff(
            added=["/important/folder/new.txt"],
            altered=["/important/folder/changed.txt"],
            deleted=["/important/folder/gone.txt"],
        )
        notifier.send_monitored_folder_alerts(diff)

        subs = subjects(mail)
        assert any("added in monitored folder: /important/folder" in s for s in subs)
        assert any("altered in monitored folder: /important/folder" in s for s in subs)
        assert any("deleted in monitored folder: /important/folder" in s for s in subs)

    def test_files_outside_folder_do_not_alert(
        self,
        mail: Mock,
        tmp_path: Path,
    ) -> None:
        """A prefix that is not a full path segment must not match."""
        notifier = make_notifier(mail, tmp_path, monitored_folders=["/a/b"])
        # "/a/bc/..." shares the textual prefix "/a/b" but is a different folder.
        notifier.send_monitored_folder_alerts(make_diff(added=["/a/bc/file.txt"]))
        mail.send_mail_with_retries.assert_not_called()

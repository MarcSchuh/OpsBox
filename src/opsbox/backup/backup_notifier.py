"""Notification/reporting concerns for the restic backup workflow.

``BackupNotifier`` owns every email the backup workflow sends (success,
failure, skipped, verification, maintenance, threshold warnings,
monitored-folder alerts and per-change-type file listings) as well as the
truncation of oversized session logs so they fit the mail attachment limit.
Keeping this separate from ``BackupScript`` leaves the latter as a slim
orchestrator.
"""

import logging
import os
from pathlib import Path

from opsbox.backup.config_manager import BackupConfig
from opsbox.backup.exceptions import MaintenanceError, VerificationError
from opsbox.backup.restic_diff import ResticDiff
from opsbox.backup.snapshot_id import ResticSnapshotId
from opsbox.encrypted_mail import EncryptedMail


class BackupNotifier:
    """Build and send all backup notification emails."""

    MAX_FILES_IN_EMAIL = 200

    # Session logs are attached to notification emails. EncryptedMail drops any
    # attachment at/above its 5 MB limit, so an oversized log (e.g. a restic
    # diff of thousands of files written verbatim) would leave the mail without
    # any log at all. Such logs are truncated to this budget (kept below the
    # 5 MB limit for encoding/encryption overhead), preserving the head and tail
    # plus a header explaining how to obtain the full log on the host.
    MAX_LOG_ATTACHMENT_BYTES = 4 * 1024 * 1024
    LOG_ATTACHMENT_HEAD_BYTES = 1 * 1024 * 1024
    LOG_ATTACHMENT_TAIL_BYTES = 2 * 1024 * 1024

    def __init__(
        self,
        encrypted_mail: EncryptedMail,
        config: BackupConfig,
        logger: logging.Logger,
        temp_dir: Path,
    ) -> None:
        """Initialize the notifier with its collaborators.

        Args:
            encrypted_mail: Mail transport used to send notifications.
            config: Backup configuration (title, target, thresholds, folders).
            logger: Logger for diagnostic messages.
            temp_dir: Directory used to write truncated log excerpts.

        """
        self.encrypted_mail = encrypted_mail
        self.config = config
        self.logger = logger
        self.temp_dir = temp_dir

    # ------------------------------------------------------------------ #
    # Log attachment handling
    # ------------------------------------------------------------------ #
    def prepare_log_attachment(self, log_path: str | Path | None) -> str | None:
        """Return a session-log attachment path that fits the mail size limit.

        The full restic session log can grow large: a diff of thousands of files
        is written verbatim. ``EncryptedMail`` silently drops attachments that
        exceed its size limit, which would leave failure/success mails without
        any log at all. To avoid that, an oversized log is truncated to a
        head+tail excerpt with a header explaining that it was cut and how to
        obtain the full log (and rebuild the diff) on the host. Logs within the
        budget are returned unchanged.
        """
        if not isinstance(log_path, (str, Path)):
            return None
        path = Path(log_path)
        if not path.is_file():
            return None

        original_size = path.stat().st_size
        if original_size <= self.MAX_LOG_ATTACHMENT_BYTES:
            return str(path)

        head_bytes = self.LOG_ATTACHMENT_HEAD_BYTES
        tail_bytes = self.LOG_ATTACHMENT_TAIL_BYTES
        omitted = original_size - head_bytes - tail_bytes

        with path.open("rb") as f:
            head = f.read(head_bytes)
            f.seek(-tail_bytes, os.SEEK_END)
            tail = f.read()

        repo = self.config.backup_target
        header = (
            "================= TRUNCATED LOG =================\n"
            "This session log was truncated for email delivery.\n"
            f"Original size: {original_size} bytes "
            f"(attachment budget: {self.MAX_LOG_ATTACHMENT_BYTES} bytes).\n"
            f"Showing the first {head_bytes} and last {tail_bytes} bytes; "
            f"{omitted} bytes in the middle were omitted.\n\n"
            "To read the FULL log on the backup host, find the restic session\n"
            "log in the system temp directory (prefixed 'restic_session_'):\n"
            "    ls -t /tmp/restic_session_*.log | head -1\n\n"
            "To rebuild a diff yourself (with repository access):\n"
            f"    restic -r {repo} snapshots\n"
            f"    restic -r {repo} diff <OLDER_SNAPSHOT_ID> <NEWER_SNAPSHOT_ID>\n"
            "=================================================\n\n"
        ).encode()
        separator = f"\n\n... [{omitted} bytes omitted] ...\n\n".encode()

        truncated_path = self.temp_dir / f"{path.stem}.truncated.log"
        with truncated_path.open("wb") as out:
            out.write(header)
            out.write(head)
            out.write(separator)
            out.write(tail)

        self.logger.warning(
            f"Session log {path} ({original_size} bytes) exceeds the mail "
            f"attachment budget ({self.MAX_LOG_ATTACHMENT_BYTES} bytes); "
            f"attaching a truncated excerpt instead ({truncated_path}).",
        )
        return str(truncated_path)

    def _format_file_list(self, files: list[Path]) -> str:
        """Format a capped, newline-separated list of file paths for an email.

        At most ``MAX_FILES_IN_EMAIL`` paths are listed; if more files are
        present a trailing "... and N more files" line is appended.
        """
        file_list = "\n".join(str(path) for path in files[: self.MAX_FILES_IN_EMAIL])
        if len(files) > self.MAX_FILES_IN_EMAIL:
            file_list += f"\n... and {len(files) - self.MAX_FILES_IN_EMAIL} more files"
        return file_list

    # ------------------------------------------------------------------ #
    # Workflow status emails
    # ------------------------------------------------------------------ #
    def send_success(
        self,
        snapshot_id: ResticSnapshotId,
        diff_summary: str,
        session_log: str | Path | None,
    ) -> None:
        """Send the backup-success notification with a diff summary."""
        self.encrypted_mail.send_mail_with_retries(
            subject=f"Backup {self.config.backup_title} successful",
            message=(
                f"Backup completed successfully.\nSnapshot ID: {snapshot_id}\n\n"
                f"Diff Summary:\n{diff_summary}"
            ),
            mail_attachment=self.prepare_log_attachment(session_log),
        )

    def _failure_subject(self, error: BaseException) -> str:
        """Pick a failure mail subject that matches the failing stage."""
        title = self.config.backup_title
        if isinstance(error, VerificationError):
            return f"Backup {title} verification failed"
        if isinstance(error, MaintenanceError):
            return f"Backup maintenance {title} failed"
        return f"Backup {title} failed"

    def send_failure(
        self,
        error: BaseException,
        session_log: str | Path | None,
    ) -> None:
        """Send a single failure notification with the (bounded) session log."""
        self.encrypted_mail.send_mail_with_retries(
            subject=self._failure_subject(error),
            message=f"Backup failed: {error}",
            mail_attachment=self.prepare_log_attachment(session_log),
        )

    def send_skipped(self, error: BaseException) -> None:
        """Send a notification that the backup was skipped (expected failure)."""
        self.encrypted_mail.send_mail_with_retries(
            subject=f"Backup {self.config.backup_title} skipped",
            message=f"Backup was skipped: {error}",
        )

    def send_unexpected_error(self, error: BaseException) -> None:
        """Send a notification about an unexpected (unclassified) error."""
        self.encrypted_mail.send_mail_with_retries(
            subject=f"Backup {self.config.backup_title} script error",
            message=f"Unexpected error: {error}",
        )

    def send_verification_success(self, snapshot_id: ResticSnapshotId) -> None:
        """Send the backup-verification-success notification."""
        self.encrypted_mail.send_mail_with_retries(
            subject=f"Backup {self.config.backup_title} verification successful",
            message=(
                f"Backup verification successful for snapshot {snapshot_id}. "
                f"File {self.config.file_to_check} found."
            ),
        )

    def send_maintenance_success(self, check_output: str) -> None:
        """Send the maintenance-success notification."""
        self.encrypted_mail.send_mail_with_retries(
            subject=f"Backup maintenance {self.config.backup_title} successful",
            message=(
                f"Repository maintenance completed successfully.\n\n"
                f"Check output:\n{check_output}"
            ),
        )

    def send_maintenance_warning(self, check_output: str) -> None:
        """Send the maintenance-completed-with-warnings notification."""
        self.encrypted_mail.send_mail_with_retries(
            subject=(
                f"Backup maintenance {self.config.backup_title} completed with warnings"
            ),
            message=(
                "Repository check reported problems. Prune was skipped "
                "to avoid deleting data from a potentially unhealthy "
                f"repository.\n\nCheck output:\n{check_output}"
            ),
        )

    # ------------------------------------------------------------------ #
    # Diff-based reporting
    # ------------------------------------------------------------------ #
    def send_file_changes(self, diff: ResticDiff) -> None:
        """Send separate emails for added, altered, and deleted files.

        Args:
            diff: ResticDiff object containing file changes and snapshot ID

        """
        change_categories: tuple[tuple[str, list[Path]], ...] = (
            ("added", diff.added_files),
            ("altered", diff.altered_files),
            ("deleted", diff.deleted_files),
        )
        for change_type, files in change_categories:
            if not files:
                continue
            self.logger.info(
                f"Sending email for {len(files)} {change_type} files "
                f"(Snapshot: {diff.snapshot_id})",
            )
            file_list = self._format_file_list(files)
            self.encrypted_mail.send_mail_with_retries(
                subject=(
                    f"Backup {self.config.backup_title}: {len(files)} files "
                    f"{change_type} (Snapshot: {diff.snapshot_id})"
                ),
                message=(
                    f"Backup detected {len(files)} {change_type} files.\n\n"
                    f"Snapshot ID: {diff.snapshot_id}\n\n"
                    f"{change_type.capitalize()} files:\n{file_list}"
                ),
            )

    def send_threshold_warnings(self, diff: ResticDiff) -> None:
        """Check thresholds and send warning emails if exceeded.

        Deleted, altered and added files are each checked against their own
        independent threshold.

        Args:
            diff: ResticDiff object containing file changes and snapshot ID

        """
        threshold_checks: tuple[tuple[str, list[Path], int | None], ...] = (
            ("deleted", diff.deleted_files, self.config.deletion_threshold),
            ("altered", diff.altered_files, self.config.alteration_threshold),
            ("added", diff.added_files, self.config.addition_threshold),
        )

        for change_type, files, threshold in threshold_checks:
            if threshold is not None and len(files) > threshold:
                self._send_threshold_warning(
                    change_type,
                    files,
                    threshold,
                    diff.snapshot_id,
                )

    def _send_threshold_warning(
        self,
        change_type: str,
        files: list[Path],
        threshold: int,
        snapshot_id: ResticSnapshotId,
    ) -> None:
        """Send a warning email because a change-count threshold was exceeded.

        Args:
            change_type: The kind of change ("deleted", "altered" or "added")
            files: The affected files
            threshold: The configured threshold that was exceeded
            snapshot_id: The snapshot ID this change belongs to

        """
        self.logger.warning(
            f"{change_type.capitalize()} threshold exceeded: {len(files)} files "
            f"{change_type} (threshold: {threshold})",
        )
        file_list = self._format_file_list(files)
        self.encrypted_mail.send_mail_with_retries(
            subject=(
                f"Backup {self.config.backup_title} Warning: {len(files)} files "
                f"{change_type} (threshold: {threshold})"
            ),
            message=(
                f"Warning: The backup detected {len(files)} {change_type} files, "
                f"which exceeds the threshold of {threshold}.\n\n"
                f"Snapshot ID: {snapshot_id}\n\n"
                f"{change_type.capitalize()} files:\n{file_list}"
            ),
        )

    def send_monitored_folder_alerts(self, diff: ResticDiff) -> None:
        """Check for changes in monitored folders and send email alerts.

        Sends a separate email for each monitored folder and change type (added,
        altered, deleted) containing only the files affected in that specific
        folder. Any change inside a monitored folder triggers a notification.

        Args:
            diff: ResticDiff object containing file changes and snapshot ID

        """
        if not self.config.monitored_folders:
            return

        # Every change type is reported so that any modification triggers an alert.
        change_categories: tuple[tuple[str, list[Path]], ...] = (
            ("added", diff.added_files),
            ("altered", diff.altered_files),
            ("deleted", diff.deleted_files),
        )

        for monitored_folder in self.config.monitored_folders:
            for change_type, files in change_categories:
                folder_files = [
                    file_path
                    for file_path in files
                    if self._path_in_folder(file_path, monitored_folder)
                ]
                if folder_files:
                    self._send_monitored_folder_alert(
                        monitored_folder,
                        change_type,
                        folder_files,
                        diff.snapshot_id,
                    )

    @staticmethod
    def _path_in_folder(file_path: Path, folder: str) -> bool:
        """Return True if ``file_path`` lies within ``folder``.

        Both paths are normalized and the folder is treated as a prefix ending
        in a path separator so that e.g. ``/a/bc`` does not match ``/a/b``.
        """
        normalized_file_path = file_path.as_posix()
        normalized_folder = Path(folder).as_posix()
        if not normalized_folder.endswith("/"):
            normalized_folder += "/"
        return normalized_file_path.startswith(normalized_folder)

    def _send_monitored_folder_alert(
        self,
        monitored_folder: str,
        change_type: str,
        files: list[Path],
        snapshot_id: ResticSnapshotId,
    ) -> None:
        """Send an alert email for one change type in a monitored folder.

        Args:
            monitored_folder: The monitored folder the files belong to
            change_type: The kind of change ("added", "altered" or "deleted")
            files: The affected files inside the monitored folder
            snapshot_id: The snapshot ID this change belongs to

        """
        self.logger.warning(
            f"Files {change_type} in monitored folder {monitored_folder}: "
            f"{len(files)} files",
        )
        file_list = self._format_file_list(files)
        self.encrypted_mail.send_mail_with_retries(
            subject=(
                f"Backup {self.config.backup_title} Alert: {len(files)} files "
                f"{change_type} in monitored folder: {monitored_folder}"
            ),
            message=(
                f"Alert: The backup detected {len(files)} {change_type} files "
                f"in monitored folder: {monitored_folder}\n\n"
                f"Snapshot ID: {snapshot_id}\n\n"
                f"{change_type.capitalize()} files:\n{file_list}"
            ),
        )

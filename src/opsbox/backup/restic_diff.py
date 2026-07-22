"""Parsing of ``restic diff --json`` output into structured change data."""

import json
import logging
from dataclasses import dataclass
from pathlib import Path

from opsbox.backup.exceptions import ResticBackupFailedError
from opsbox.backup.snapshot_id import ResticSnapshotId


@dataclass
class ResticDiff:
    """Represents the result of a restic diff operation.

    Attributes:
        added_files: List of added file paths
        altered_files: List of altered file paths
        deleted_files: List of deleted file paths
        snapshot_id: The snapshot ID this diff is for

    """

    added_files: list[Path]
    altered_files: list[Path]
    deleted_files: list[Path]
    snapshot_id: ResticSnapshotId


class ResticDiffParser:
    """Parse ``restic diff --json`` output into :class:`ResticDiff` objects.

    This isolates the interpretation of restic's newline-delimited JSON diff
    format from the backup workflow orchestration.
    """

    def __init__(self, logger: logging.Logger) -> None:
        """Initialize the parser with a logger for diagnostic messages."""
        self.logger = logger

    def parse(
        self,
        diff_output: str,
        snapshot_id: ResticSnapshotId,
    ) -> ResticDiff:
        """Parse ``restic diff --json`` output into added/altered/deleted files.

        The output is newline-delimited JSON. Each change is a message of type
        ``change`` with a ``path`` and a ``modifier`` string (e.g. "+", "-",
        "M", or combinations such as "MU").

        A well-formed ``restic diff --json`` run always ends with a
        ``statistics`` message. If that message is missing, the diff did not
        complete correctly, so the output is considered invalid and an error is
        raised (the report must succeed; a broken report means something went
        wrong with the run).

        Args:
            diff_output: The raw JSON output from the restic diff command
            snapshot_id: The snapshot ID this diff is for

        Returns:
            ResticDiff object containing added, altered, and deleted files

        Raises:
            ResticBackupFailedError: If the diff output is empty or does not
                contain the terminating ``statistics`` message

        """
        deleted_files: list[Path] = []
        altered_files: list[Path] = []
        added_files: list[Path] = []
        saw_statistics = False

        if not diff_output or not diff_output.strip():
            error_msg = "restic diff produced no output"
            self.logger.error(error_msg)
            raise ResticBackupFailedError(error_msg)

        for line in diff_output.splitlines():
            message = self._parse_diff_line(line)
            if message is None:
                continue

            message_type = message.get("message_type")
            if message_type == "statistics":
                saw_statistics = True
                continue
            if message_type != "change":
                continue

            self._classify_change(
                message,
                added_files=added_files,
                altered_files=altered_files,
                deleted_files=deleted_files,
            )

        if not saw_statistics:
            error_msg = (
                "restic diff --json did not emit a terminating 'statistics' "
                "message; the diff output is incomplete or invalid"
            )
            self.logger.error(error_msg)
            raise ResticBackupFailedError(error_msg)

        return ResticDiff(
            added_files=added_files,
            altered_files=altered_files,
            deleted_files=deleted_files,
            snapshot_id=snapshot_id,
        )

    def _parse_diff_line(self, line: str) -> dict | None:
        """Parse a single line of ``restic diff --json`` output into a message.

        Returns the decoded message dict, or None for blank lines, non-JSON
        lines (logged as a warning) and non-dict payloads.
        """
        line_stripped = line.strip()
        if not line_stripped:
            return None

        try:
            message = json.loads(line_stripped)
        except json.JSONDecodeError:
            # stdout is captured cleanly, so any non-JSON line is unexpected
            self.logger.warning(
                f"Ignoring non-JSON line in diff output: {line_stripped}",
            )
            return None

        if not isinstance(message, dict):
            return None
        return message

    def _classify_change(
        self,
        message: dict,
        *,
        added_files: list[Path],
        altered_files: list[Path],
        deleted_files: list[Path],
    ) -> None:
        """Append a ``change`` message's path to the matching change list.

        A single change carries one modifier; "+" added, "-" removed, "M"
        content modified. Metadata-only changes (e.g. "U"/"T") are intentionally
        ignored.
        """
        path_str = message.get("path")
        modifier = message.get("modifier", "")
        if not path_str:
            return

        path = Path(path_str)
        if "+" in modifier:
            added_files.append(path)
        elif "-" in modifier:
            deleted_files.append(path)
        elif "M" in modifier:
            altered_files.append(path)

    def extract_statistics(self, diff_output: str) -> str:
        """Extract a human-readable summary from ``restic diff --json`` output.

        Looks for the ``statistics`` message emitted at the end of the diff.

        Args:
            diff_output: The raw JSON output from the restic diff command

        Returns:
            A formatted summary string, or a fallback message if unavailable

        """
        for line in diff_output.splitlines():
            line_stripped = line.strip()
            if not line_stripped:
                continue
            try:
                message = json.loads(line_stripped)
            except json.JSONDecodeError:
                continue
            if (
                not isinstance(message, dict)
                or message.get("message_type") != "statistics"
            ):
                continue

            added = message.get("added", {}) or {}
            removed = message.get("removed", {}) or {}
            changed_files = message.get("changed_files")

            summary_lines = []
            if changed_files is not None:
                summary_lines.append(f"Changed files: {changed_files}")
            summary_lines.append(
                f"Added:   files={added.get('files', 0)}, "
                f"dirs={added.get('dirs', 0)}, bytes={added.get('bytes', 0)}",
            )
            summary_lines.append(
                f"Removed: files={removed.get('files', 0)}, "
                f"dirs={removed.get('dirs', 0)}, bytes={removed.get('bytes', 0)}",
            )
            return "\n".join(summary_lines)

        return "No summary available."

"""Tests for the ResticDiffParser and ResticDiff types."""

import json
import logging
from pathlib import Path

import pytest

from opsbox.backup.exceptions import ResticBackupFailedError
from opsbox.backup.restic_diff import ResticDiff, ResticDiffParser
from opsbox.backup.snapshot_id import ResticSnapshotId

SNAPSHOT = ResticSnapshotId("c9d0e1f2")


def make_diff_ndjson(
    entries: list[tuple[str, str]] | None = None,
    *,
    changed_files: int = 0,
    with_statistics: bool = True,
    added: dict | None = None,
    removed: dict | None = None,
) -> str:
    """Build 'restic diff --json' ndjson output from (modifier, path) tuples."""
    entries = entries or []
    lines = [
        json.dumps({"message_type": "change", "path": path, "modifier": modifier})
        for modifier, path in entries
    ]
    if with_statistics:
        empty_stat = {"files": 0, "dirs": 0, "bytes": 0}
        lines.append(
            json.dumps(
                {
                    "message_type": "statistics",
                    "changed_files": changed_files,
                    "added": added or empty_stat,
                    "removed": removed or empty_stat,
                },
            ),
        )
    return "\n".join(lines)


@pytest.fixture
def parser() -> ResticDiffParser:
    """Return a ResticDiffParser wired to a throwaway logger."""
    return ResticDiffParser(logging.getLogger("test_restic_diff"))


class TestResticDiffParserParse:
    """Tests for ResticDiffParser.parse."""

    def test_classifies_added_altered_deleted(self, parser: ResticDiffParser) -> None:
        """+, M and - modifiers land in the matching change lists."""
        diff_output = make_diff_ndjson(
            [
                ("+", "/data/new.txt"),
                ("M", "/data/changed.txt"),
                ("-", "/data/gone.txt"),
            ],
        )

        result = parser.parse(diff_output, SNAPSHOT)

        assert result.added_files == [Path("/data/new.txt")]
        assert result.altered_files == [Path("/data/changed.txt")]
        assert result.deleted_files == [Path("/data/gone.txt")]
        assert result.snapshot_id == SNAPSHOT

    def test_combined_modifier_prefers_add_then_delete_then_modify(
        self,
        parser: ResticDiffParser,
    ) -> None:
        """A combined modifier such as 'MU' is treated as a content change."""
        diff_output = make_diff_ndjson([("MU", "/data/meta_and_content.txt")])

        result = parser.parse(diff_output, SNAPSHOT)

        assert result.altered_files == [Path("/data/meta_and_content.txt")]
        assert result.added_files == []
        assert result.deleted_files == []

    def test_metadata_only_change_is_ignored(self, parser: ResticDiffParser) -> None:
        """A metadata-only change (e.g. 'U') is not classified as a file change."""
        diff_output = make_diff_ndjson([("U", "/data/touched.txt")])

        result = parser.parse(diff_output, SNAPSHOT)

        assert result.added_files == []
        assert result.altered_files == []
        assert result.deleted_files == []

    def test_change_without_path_is_ignored(self, parser: ResticDiffParser) -> None:
        """A change message lacking a path is skipped."""
        line = json.dumps({"message_type": "change", "modifier": "+"})
        stats = json.dumps(
            {
                "message_type": "statistics",
                "added": {},
                "removed": {},
            },
        )
        result = parser.parse(f"{line}\n{stats}", SNAPSHOT)

        assert result.added_files == []

    def test_non_json_and_blank_lines_are_ignored(
        self,
        parser: ResticDiffParser,
    ) -> None:
        """Blank lines and non-JSON noise do not break parsing."""
        diff_output = "\nnot-json-at-all\n" + make_diff_ndjson([("+", "/data/new.txt")])

        result = parser.parse(diff_output, SNAPSHOT)

        assert result.added_files == [Path("/data/new.txt")]

    def test_empty_output_raises(self, parser: ResticDiffParser) -> None:
        """Empty diff output is treated as a failed diff."""
        with pytest.raises(ResticBackupFailedError, match="no output"):
            parser.parse("   \n  ", SNAPSHOT)

    def test_missing_statistics_raises(self, parser: ResticDiffParser) -> None:
        """Output without a terminating statistics message is invalid."""
        diff_output = make_diff_ndjson(
            [("+", "/data/new.txt")],
            with_statistics=False,
        )

        with pytest.raises(ResticBackupFailedError, match="statistics"):
            parser.parse(diff_output, SNAPSHOT)


class TestResticDiffParserStatistics:
    """Tests for ResticDiffParser.extract_statistics."""

    def test_extracts_summary(self, parser: ResticDiffParser) -> None:
        """The statistics message is rendered into a human-readable summary."""
        diff_output = make_diff_ndjson(
            changed_files=7,
            added={"files": 3, "dirs": 1, "bytes": 1024},
            removed={"files": 2, "dirs": 0, "bytes": 512},
        )

        summary = parser.extract_statistics(diff_output)

        assert "Changed files: 7" in summary
        assert "Added:   files=3, dirs=1, bytes=1024" in summary
        assert "Removed: files=2, dirs=0, bytes=512" in summary

    def test_returns_fallback_when_no_statistics(
        self,
        parser: ResticDiffParser,
    ) -> None:
        """Without a statistics message a fallback string is returned."""
        assert parser.extract_statistics("") == "No summary available."
        assert parser.extract_statistics("not-json\n") == "No summary available."


def test_restic_diff_is_a_plain_dataclass() -> None:
    """ResticDiff stores the four change attributes as given."""
    diff = ResticDiff(
        added_files=[Path("/a")],
        altered_files=[Path("/b")],
        deleted_files=[Path("/c")],
        snapshot_id=SNAPSHOT,
    )
    assert diff.added_files == [Path("/a")]
    assert diff.altered_files == [Path("/b")]
    assert diff.deleted_files == [Path("/c")]
    assert diff.snapshot_id == SNAPSHOT

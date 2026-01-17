"""Business logic tests for the KVM snapshot manager."""

from __future__ import annotations

import contextlib
import logging
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import Iterable
    from pathlib import Path
    from typing import Self

import pytest

from opsbox.KVMSnapshotManager.kvm_snapshot_manager import (
    BackingFileNotFoundError,
    DomblklistTooManyLinesError,
    HeadSnapshotParseError,
    KVMSnapshotManager,
    KVMStillRunningError,
    NoHeadSnapshotFoundError,
    SnapshotNotFoundError,
    lock_path_for_base_image,
    main,
)


class StubCommandManager(KVMSnapshotManager):
    """Test helper to provide fixed command output."""

    def __init__(
        self,
        log_handler: logging.Logger,
        domain: str,
        base_image: str,
        command_output: list[str],
    ) -> None:
        """Initialize with fixed command output."""
        self._command_output = command_output
        super().__init__(log_handler=log_handler, domain=domain, base_image=base_image)

    def _run_command(self, command: list[str]) -> list[str]:
        return self._command_output


class StubDomblklistManager(KVMSnapshotManager):
    """Test helper to provide domblklist output."""

    def __init__(
        self,
        log_handler: logging.Logger,
        domain: str,
        base_image: str,
        domblklist_output: list[str],
    ) -> None:
        """Initialize with fixed domblklist output."""
        self._domblklist_output = domblklist_output
        super().__init__(log_handler=log_handler, domain=domain, base_image=base_image)

    def _run_domblklist(self) -> list[str]:
        return self._domblklist_output


class StubBackingFileManager(KVMSnapshotManager):
    """Test helper to provide backing file mappings."""

    def __init__(
        self,
        log_handler: logging.Logger,
        domain: str,
        base_image: str,
        backing_map: dict[Path, Path],
    ) -> None:
        """Initialize with backing file mappings."""
        self._backing_map = backing_map
        super().__init__(log_handler=log_handler, domain=domain, base_image=base_image)

    def _extract_backing_file(self, path_to_snapshot: Path) -> Path:
        if path_to_snapshot == self.base_image_path:
            raise BackingFileNotFoundError(path_to_snapshot)
        if path_to_snapshot in self._backing_map:
            return self._backing_map[path_to_snapshot]
        raise BackingFileNotFoundError(path_to_snapshot)


class DummyLockManager:
    """No-op lock manager for main() tests."""

    def __init__(self, *_: object, **__: object) -> None:
        """Initialize a no-op context manager."""
        self._context = contextlib.nullcontext()

    def __enter__(self) -> Self:
        """Enter the lock manager context."""
        self._context.__enter__()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        """Exit the lock manager context."""
        self._context.__exit__(exc_type, exc_val, exc_tb)


def _make_base_image(tmp_path: Path) -> Path:
    base_image = tmp_path / "base.qcow2"
    base_image.touch()
    return base_image


def _domblklist_lines(data_lines: Iterable[str]) -> list[str]:
    return ["Target Source", "------ ------", *data_lines]


def test_lock_path_is_stable_for_same_base_image(tmp_path: Path) -> None:
    """Test lock path is stable and scoped to temp lock directory."""
    base_image = tmp_path / "base.qcow2"
    first = lock_path_for_base_image(base_image)
    second = lock_path_for_base_image(base_image)

    assert first == second
    assert first.parent.name == "opsbox-kvm-locks"
    assert first.name.startswith("opsbox-kvm-base.qcow2-")


def test_check_domain_off_raises_when_running(tmp_path: Path) -> None:
    """Test running domains raise KVMStillRunningError."""
    base_image = _make_base_image(tmp_path)
    manager = StubCommandManager(
        log_handler=logging.getLogger("test"),
        domain="test-domain",
        base_image=str(base_image),
        command_output=["running"],
    )

    with pytest.raises(KVMStillRunningError):
        manager.check_domain_off()


def test_check_domain_off_allows_shut_off(tmp_path: Path) -> None:
    """Test shut off domains pass validation."""
    base_image = _make_base_image(tmp_path)
    manager = StubCommandManager(
        log_handler=logging.getLogger("test"),
        domain="test-domain",
        base_image=str(base_image),
        command_output=["shut off"],
    )

    manager.check_domain_off()


def test_extract_head_snapshot_path_returns_path(tmp_path: Path) -> None:
    """Test head snapshot path is extracted from domblklist output."""
    base_image = _make_base_image(tmp_path)
    head_snapshot = tmp_path / "head.qcow2"
    manager = StubDomblklistManager(
        log_handler=logging.getLogger("test"),
        domain="test-domain",
        base_image=str(base_image),
        domblklist_output=_domblklist_lines([f"vda {head_snapshot}"]),
    )

    assert manager.extract_head_snapshot_path() == head_snapshot


def test_extract_head_snapshot_path_raises_on_too_many_lines(tmp_path: Path) -> None:
    """Test too many domblklist data lines raise an error."""
    base_image = _make_base_image(tmp_path)
    manager = StubDomblklistManager(
        log_handler=logging.getLogger("test"),
        domain="test-domain",
        base_image=str(base_image),
        domblklist_output=_domblklist_lines(["vda a", "vdb b", "vdc c"]),
    )

    with pytest.raises(DomblklistTooManyLinesError):
        manager.extract_head_snapshot_path()


def test_extract_head_snapshot_path_raises_when_no_data(tmp_path: Path) -> None:
    """Test empty domblklist data raises an error."""
    base_image = _make_base_image(tmp_path)
    manager = StubDomblklistManager(
        log_handler=logging.getLogger("test"),
        domain="test-domain",
        base_image=str(base_image),
        domblklist_output=_domblklist_lines([]),
    )

    with pytest.raises(NoHeadSnapshotFoundError):
        manager.extract_head_snapshot_path()


def test_extract_head_snapshot_path_raises_when_unparseable(tmp_path: Path) -> None:
    """Test unparseable domblklist data raises an error."""
    base_image = _make_base_image(tmp_path)
    manager = StubDomblklistManager(
        log_handler=logging.getLogger("test"),
        domain="test-domain",
        base_image=str(base_image),
        domblklist_output=_domblklist_lines(["vda"]),
    )

    with pytest.raises(HeadSnapshotParseError):
        manager.extract_head_snapshot_path()


def test_traverse_snapshot_chain_returns_paths_until_base(tmp_path: Path) -> None:
    """Test traversal returns snapshots until base image is reached."""
    base_image = _make_base_image(tmp_path)
    snapshot_a = tmp_path / "snap_a.qcow2"
    snapshot_b = tmp_path / "snap_b.qcow2"
    snapshot_a.touch()
    snapshot_b.touch()
    backing_map = {snapshot_a: snapshot_b, snapshot_b: base_image}

    manager = StubBackingFileManager(
        log_handler=logging.getLogger("test"),
        domain="test-domain",
        base_image=str(base_image),
        backing_map=backing_map,
    )

    assert manager.traverse_snapshot_chain(snapshot_a) == [snapshot_a, snapshot_b]


def test_traverse_snapshot_chain_raises_when_head_missing(tmp_path: Path) -> None:
    """Test missing head snapshot raises SnapshotNotFoundError."""
    base_image = _make_base_image(tmp_path)
    missing_head = tmp_path / "missing.qcow2"
    manager = StubBackingFileManager(
        log_handler=logging.getLogger("test"),
        domain="test-domain",
        base_image=str(base_image),
        backing_map={},
    )

    with pytest.raises(SnapshotNotFoundError):
        manager.traverse_snapshot_chain(missing_head)


def test_main_rejects_remaining_below_minimum(monkeypatch: pytest.MonkeyPatch) -> None:
    """Test CLI rejects remaining values below minimum."""
    monkeypatch.setattr(
        "sys.argv",
        [
            "kvm_snapshot_manager",
            "--domain",
            "test-domain",
            "--base-image",
            "/tmp/base.qcow2",
            "--remaining",
            "4",
        ],
    )

    with pytest.raises(ValueError, match=r"--remaining must be at least 5\."):
        main()


def test_main_rejects_remaining_greater_than_available(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """Test CLI rejects remaining value above available snapshots."""
    base_image = _make_base_image(tmp_path)
    available_snapshot = tmp_path / "snapshot.qcow2"
    available_snapshot.touch()

    class StubManager:
        def __init__(self, *_: object, **__: object) -> None:
            pass

        def check_domain_off(self) -> None:
            return None

        def extract_head_snapshot_path(self) -> Path:
            return available_snapshot

        def traverse_snapshot_chain(self, head_snapshot: Path) -> list[Path]:
            return [available_snapshot]

    monkeypatch.setattr(
        "sys.argv",
        [
            "kvm_snapshot_manager",
            "--domain",
            "test-domain",
            "--base-image",
            str(base_image),
            "--remaining",
            "6",
        ],
    )
    monkeypatch.setattr(
        "opsbox.KVMSnapshotManager.kvm_snapshot_manager.KVMSnapshotManager",
        StubManager,
    )
    monkeypatch.setattr(
        "opsbox.KVMSnapshotManager.kvm_snapshot_manager.LockManager",
        DummyLockManager,
    )
    monkeypatch.setattr(
        "opsbox.KVMSnapshotManager.kvm_snapshot_manager.configure_logging",
        lambda *_args, **_kwargs: logging.getLogger("test"),
    )

    with pytest.raises(ValueError, match=r"only 1 available\."):
        main()

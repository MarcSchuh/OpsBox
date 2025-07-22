"""Tests for backup scripts functionality."""

import tempfile
from pathlib import Path

import pytest

from opsbox.backup.scripts import BackupManager


class TestBackupManager:
    """Test cases for BackupManager class."""

    def test_init_creates_backup_dir(self) -> None:
        """Test that BackupManager creates backup directory on initialization."""
        with tempfile.TemporaryDirectory() as temp_dir:
            backup_dir = Path(temp_dir) / "backups"
            BackupManager(backup_dir)
            assert backup_dir.exists()
            assert backup_dir.is_dir()

    def test_create_backup_with_existing_source(self) -> None:
        """Test creating backup with existing source file."""
        with tempfile.TemporaryDirectory() as temp_dir:
            backup_dir = Path(temp_dir) / "backups"
            source_file = Path(temp_dir) / "test.txt"
            source_file.write_text("test content")

            manager = BackupManager(backup_dir)
            backup_path = manager.create_backup(source_file)

            assert backup_path.parent == backup_dir
            assert backup_path.name == "test.txt.backup"

    def test_create_backup_with_nonexistent_source(self) -> None:
        """Test creating backup with non-existent source raises FileNotFoundError."""
        with tempfile.TemporaryDirectory() as temp_dir:
            backup_dir = Path(temp_dir) / "backups"
            source_file = Path(temp_dir) / "nonexistent.txt"

            manager = BackupManager(backup_dir)
            with pytest.raises(FileNotFoundError):
                manager.create_backup(source_file)

    def test_list_backups_empty_directory(self) -> None:
        """Test listing backups in empty directory."""
        with tempfile.TemporaryDirectory() as temp_dir:
            backup_dir = Path(temp_dir) / "backups"
            manager = BackupManager(backup_dir)
            backups = manager.list_backups()
            assert backups == []

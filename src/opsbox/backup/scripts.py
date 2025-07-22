"""Backup scripts and utilities for server operations."""

from pathlib import Path


class BackupManager:
    """Manages backup operations for server files and databases."""

    def __init__(self, backup_dir: Path) -> None:
        """Initialize the backup manager.

        Args:
        ----
            backup_dir: Directory where backups will be stored

        """
        self.backup_dir = Path(backup_dir)
        self.backup_dir.mkdir(parents=True, exist_ok=True)

    def create_backup(
        self,
        source_path: Path,
        backup_name: str | None = None,
    ) -> Path:
        """Create a backup of the specified source.

        Args:
        ----
            source_path: Path to the file or directory to backup
            backup_name: Optional custom name for the backup

        Returns:
        -------
            Path to the created backup file

        Raises:
        ------
            FileNotFoundError: If source_path doesn't exist

        """
        if not source_path.exists():
            error_msg = f"Source path does not exist: {source_path}"
            raise FileNotFoundError(error_msg)

        # Placeholder implementation
        backup_filename = f"{backup_name or source_path.name}.backup"
        return self.backup_dir / backup_filename

    def list_backups(self) -> list[Path]:
        """List all available backups.

        Returns
        -------
            List of backup file paths

        """
        return list(self.backup_dir.glob("*.backup"))

"""Restic snapshot ID validation and types."""

from opsbox.backup.exceptions import InvalidSnapshotIDError


class ResticSnapshotId:
    """Represents a validated Restic snapshot ID.

    Snapshot IDs are always exactly 8 hexadecimal characters (e.g., "def54c8d").

    Attributes:
        value: The snapshot ID as a string

    Raises:
        InvalidSnapshotIDError: If the snapshot ID format is invalid

    """

    SNAPSHOT_ID_LENGTH = 8

    def __init__(self, value: str) -> None:
        """Initialize ResticSnapshotId with validation.

        Args:
            value: The snapshot ID string to validate

        Raises:
            InvalidSnapshotIDError: If the snapshot ID is not exactly 8 hex characters

        """
        if not isinstance(value, str):
            error_msg = f"Snapshot ID must be a string, got {type(value).__name__}"
            raise InvalidSnapshotIDError(error_msg)

        if len(value) != self.SNAPSHOT_ID_LENGTH:
            error_msg = (
                f"Snapshot ID must be exactly {self.SNAPSHOT_ID_LENGTH} characters, "
                f"got {len(value)}: {value}"
            )
            raise InvalidSnapshotIDError(error_msg)

        try:
            # Validate that all characters are hexadecimal
            int(value, 16)
        except ValueError:
            error_msg = (
                f"Snapshot ID must contain only hexadecimal characters, got: {value}"
            )
            raise InvalidSnapshotIDError(error_msg) from None

        self.value = value

    def __str__(self) -> str:
        """Return the snapshot ID as a string."""
        return self.value

    def __repr__(self) -> str:
        """Return a representation of the snapshot ID."""
        return f"ResticSnapshotId('{self.value}')"

    def __eq__(self, other: object) -> bool:
        """Compare with another ResticSnapshotId or string."""
        if isinstance(other, ResticSnapshotId):
            return self.value == other.value
        if isinstance(other, str):
            return self.value == other
        return False

    def __hash__(self) -> int:
        """Make ResticSnapshotId hashable."""
        return hash(self.value)

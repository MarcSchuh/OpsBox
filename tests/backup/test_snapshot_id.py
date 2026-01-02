"""Tests for the snapshot_id module."""

import pytest

from opsbox.backup.exceptions import InvalidSnapshotIDError
from opsbox.backup.snapshot_id import ResticSnapshotId


class TestResticSnapshotId:
    """Test cases for ResticSnapshotId functionality."""

    def test_init_valid_snapshot_id(self) -> None:
        """Test that ResticSnapshotId initializes with valid 8-character hex string."""
        snapshot_id = ResticSnapshotId("a1b2c3d4")
        assert snapshot_id.value == "a1b2c3d4"

    def test_init_valid_uppercase_hex(self) -> None:
        """Test that ResticSnapshotId accepts uppercase hexadecimal characters."""
        snapshot_id = ResticSnapshotId("A1B2C3D4")
        assert snapshot_id.value == "A1B2C3D4"

    def test_init_valid_mixed_case_hex(self) -> None:
        """Test that ResticSnapshotId accepts mixed case hexadecimal characters."""
        snapshot_id = ResticSnapshotId("a1B2c3D4")
        assert snapshot_id.value == "a1B2c3D4"

    def test_init_invalid_length_too_short(self) -> None:
        """Test that InvalidSnapshotIDError is raised for snapshot ID that's too short."""
        with pytest.raises(
            InvalidSnapshotIDError,
            match="must be exactly 8 characters",
        ):
            ResticSnapshotId("a1b2c3")

    def test_init_invalid_length_too_long(self) -> None:
        """Test that InvalidSnapshotIDError is raised for snapshot ID that's too long."""
        with pytest.raises(
            InvalidSnapshotIDError,
            match="must be exactly 8 characters",
        ):
            ResticSnapshotId("a1b2c3d4e5")

    def test_init_invalid_empty_string(self) -> None:
        """Test that InvalidSnapshotIDError is raised for empty string."""
        with pytest.raises(
            InvalidSnapshotIDError,
            match="must be exactly 8 characters",
        ):
            ResticSnapshotId("")

    def test_init_invalid_non_hex_characters(self) -> None:
        """Test that InvalidSnapshotIDError is raised for non-hexadecimal characters."""
        with pytest.raises(
            InvalidSnapshotIDError,
            match="must contain only hexadecimal characters",
        ):
            ResticSnapshotId("g1h2i3j4")

    def test_init_invalid_special_characters(self) -> None:
        """Test that InvalidSnapshotIDError is raised for special characters."""
        with pytest.raises(
            InvalidSnapshotIDError,
            match="must contain only hexadecimal characters",
        ):
            ResticSnapshotId("a1b2-3d4")

    def test_init_invalid_type_not_string(self) -> None:
        """Test that InvalidSnapshotIDError is raised for non-string types."""
        with pytest.raises(InvalidSnapshotIDError, match="must be a string"):
            ResticSnapshotId(12345678)  # type: ignore[arg-type]

        with pytest.raises(InvalidSnapshotIDError, match="must be a string"):
            ResticSnapshotId(None)  # type: ignore[arg-type]

    def test_str_representation(self) -> None:
        """Test that __str__ returns the snapshot ID value."""
        snapshot_id = ResticSnapshotId("a1b2c3d4")
        assert str(snapshot_id) == "a1b2c3d4"

    def test_repr_representation(self) -> None:
        """Test that __repr__ returns a proper representation."""
        snapshot_id = ResticSnapshotId("a1b2c3d4")
        assert repr(snapshot_id) == "ResticSnapshotId('a1b2c3d4')"

    def test_eq_with_another_restic_snapshot_id(self) -> None:
        """Test that __eq__ works with another ResticSnapshotId."""
        snapshot_id1 = ResticSnapshotId("a1b2c3d4")
        snapshot_id2 = ResticSnapshotId("a1b2c3d4")
        snapshot_id3 = ResticSnapshotId("e5f6a7b8")

        assert snapshot_id1 == snapshot_id2
        assert snapshot_id1 != snapshot_id3

    def test_eq_with_string(self) -> None:
        """Test that __eq__ works with string comparison."""
        snapshot_id = ResticSnapshotId("a1b2c3d4")

        assert snapshot_id == "a1b2c3d4"
        assert snapshot_id != "e5f6a7b8"

    def test_eq_with_different_type(self) -> None:
        """Test that __eq__ returns False for different types."""
        snapshot_id = ResticSnapshotId("a1b2c3d4")

        assert snapshot_id != 123
        assert snapshot_id != None  # noqa: E711
        assert snapshot_id != ["a1b2c3d4"]

    def test_hash(self) -> None:
        """Test that ResticSnapshotId is hashable."""
        snapshot_id1 = ResticSnapshotId("a1b2c3d4")
        snapshot_id2 = ResticSnapshotId("a1b2c3d4")
        snapshot_id3 = ResticSnapshotId("e5f6a7b8")

        # Same snapshot IDs should have the same hash
        assert hash(snapshot_id1) == hash(snapshot_id2)
        # Different snapshot IDs should ideally have different hashes
        # (though hash collisions are possible)
        assert hash(snapshot_id1) != hash(snapshot_id3)

        # Can be used in sets
        snapshot_set = {snapshot_id1, snapshot_id2, snapshot_id3}
        assert len(snapshot_set) == 2  # snapshot_id1 and snapshot_id2 are equal

    def test_snapshot_id_length_constant(self) -> None:
        """Test that SNAPSHOT_ID_LENGTH constant is correct."""
        assert ResticSnapshotId.SNAPSHOT_ID_LENGTH == 8

    def test_valid_edge_cases(self) -> None:
        """Test valid edge cases for snapshot IDs."""
        # All zeros
        snapshot_id = ResticSnapshotId("00000000")
        assert snapshot_id.value == "00000000"

        # All f's (max hex value)
        snapshot_id = ResticSnapshotId("ffffffff")
        assert snapshot_id.value == "ffffffff"

        # All F's (uppercase)
        snapshot_id = ResticSnapshotId("FFFFFFFF")
        assert snapshot_id.value == "FFFFFFFF"

        # Mixed with numbers only
        snapshot_id = ResticSnapshotId("12345678")
        assert snapshot_id.value == "12345678"


if __name__ == "__main__":
    pytest.main([__file__])

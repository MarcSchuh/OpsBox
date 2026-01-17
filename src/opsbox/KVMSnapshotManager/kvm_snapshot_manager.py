"""KVM snapshot management helpers."""

import argparse
import contextlib
import getpass
import hashlib
import logging
import subprocess
import tempfile
from enum import Enum
from pathlib import Path

from opsbox.locking.lock_manager import LockManager
from opsbox.logging.logger_setup import LoggingConfig, configure_logging


class DomblklistConfig(Enum):
    """Configuration values for parsing domblklist output."""

    HEADER_LINES = ("header_lines", 2)
    MAX_DATA_LINES = ("max_data_lines", 2)
    PARTS_EXPECTED = ("parts_expected", 2)

    @property
    def number(self) -> int:
        """Return the numeric configuration value."""
        return self.value[1]


class LockConfig(Enum):
    """Configuration values for snapshot manager locking."""

    DIR_NAME = "opsbox-kvm-locks"


class CliConfig(Enum):
    """Configuration values for command-line validation."""

    MIN_REMAINING = ("min_remaining", 5)

    @property
    def number(self) -> int:
        """Return the numeric configuration value."""
        return self.value[1]


def lock_path_for_base_image(base_image_path: Path) -> Path:
    """Build a lock file path for the given base image."""
    resolved_path = base_image_path.expanduser().resolve()
    digest = hashlib.sha256(str(resolved_path).encode("utf-8")).hexdigest()
    lock_dir = Path(tempfile.gettempdir()) / LockConfig.DIR_NAME.value
    lock_dir.mkdir(parents=True, exist_ok=True)
    filename = f"opsbox-kvm-{resolved_path.name or 'base'}-{digest}.lock"
    return lock_dir / filename


class DomblklistTooManyLinesError(Exception):
    """Raised when domblklist returns too many data lines."""

    def __init__(self, max_lines: int, actual_lines: int) -> None:
        """Initialize the error with domblklist line counts."""
        error_msg = (
            "domblklist output has too many data lines "
            f"(max {max_lines}, got {actual_lines})."
        )
        super().__init__(error_msg)


class KVMStillRunningError(Exception):
    """Raised when a KVM domain is not shut off."""

    def __init__(self, domain: str, state: str) -> None:
        """Initialize the error with the domain and its state."""
        error_msg = f"Domain '{domain}' is in state '{state}'. It must be shut off."
        super().__init__(error_msg)


class VirshError(Exception):
    """Raised when a virsh command fails."""

    def __init__(self, command: list[str], stderr: str | None) -> None:
        """Initialize the error with command details and stderr output."""
        stderr_text = stderr.strip() if stderr else "no error output"
        command_text = " ".join(command)
        error_msg = f"Error running '{command_text}': {stderr_text}"
        super().__init__(error_msg)


class NoHeadSnapshotFoundError(Exception):
    """Raised when domblklist has no data lines."""

    def __init__(self) -> None:
        """Initialize the error for empty domblklist output."""
        super().__init__("No data lines in domblklist output.")


class HeadSnapshotParseError(Exception):
    """Raised when domblklist data cannot be parsed."""

    def __init__(self, line: str) -> None:
        """Initialize the error with the unparseable domblklist line."""
        error_msg = f"Could not parse head snapshot path from line: {line}"
        super().__init__(error_msg)


class NoBaseImageFoundError(Exception):
    """Raised when the configured base image is missing."""

    def __init__(self, base_image_path: Path) -> None:
        """Initialize the error with the missing base image path."""
        error_msg = f"Base image file not found: {base_image_path}"
        super().__init__(error_msg)


class SnapshotNotFoundError(Exception):
    """Raised when a snapshot file in the chain is missing."""

    def __init__(self, snapshot_path: Path) -> None:
        """Initialize the error with the missing snapshot path."""
        error_msg = f"Snapshot file not found in chain: {snapshot_path}"
        super().__init__(error_msg)


class BackingFileNotFoundError(Exception):
    """Raised when a backing file cannot be found."""

    def __init__(self, snapshot_path: Path) -> None:
        """Initialize the error with the snapshot missing a backing file."""
        error_msg = f"No backing file found for snapshot: {snapshot_path}"
        super().__init__(error_msg)


class BaseImageError(Exception):
    """Raised when the base image does not match the snapshot chain."""

    def __init__(self, snapshot_path: Path, base_image_path: Path) -> None:
        """Initialize the error with the snapshot and base image paths."""
        error_msg = (
            f"Snapshot {snapshot_path} does not point to base image {base_image_path}."
        )
        super().__init__(error_msg)


class KVMSnapshotManager:
    """Manage KVM snapshots by inspecting domblklist output."""

    def __init__(
        self,
        log_handler: logging.Logger,
        domain: str,
        base_image: str,
    ) -> None:
        """Initialize the snapshot manager."""
        self.domain = domain
        self.log_handler = log_handler
        self.base_image_path = Path(base_image)
        self.sudo_password: str | None = None
        if not self.base_image_path.is_file():
            raise NoBaseImageFoundError(self.base_image_path)

        self.log_handler.info(f"Using base image: {self.base_image_path}")

    def _run_with_sudo(self, command: list[str]) -> None:
        """Run a command with sudo using a prompted password."""
        if self.sudo_password is None:
            self.sudo_password = getpass.getpass(prompt="Enter sudo password: ")
        if self.sudo_password is None:
            error_msg = "Failed to read sudo password."
            raise RuntimeError(error_msg)

        subprocess.run(  # noqa: S603
            ["sudo", "-S", *command],  # noqa: S607
            input=self.sudo_password + "\n",  # Provide password via stdin
            text=True,
            check=True,
        )

    def _run_command(self, command: list[str]) -> list[str]:
        """Run a virsh command for the configured domain and return output lines."""
        try:
            result = subprocess.run(  # noqa: S603
                command,
                capture_output=True,
                text=True,
                check=True,
            )
        except subprocess.CalledProcessError as e:
            raise VirshError(command, e.stderr) from e

        return result.stdout.strip().split("\n")

    def check_domain_off(self) -> None:
        """Ensure the domain is in the shut off state."""
        self.log_handler.info(f"Checking if domain '{self.domain}' is shut off...")

        lines = self._run_command(["virsh", "domstate", self.domain])
        # domstate usually returns something like "running", "shut off", etc.
        domain_state = lines[0].lower() if lines else ""

        if domain_state != "shut off":
            raise KVMStillRunningError(self.domain, domain_state)

        self.log_handler.info(f"Domain '{self.domain}' is properly shut off.")

    def _run_domblklist(self) -> list[str]:
        """Run 'virsh domblklist' for the configured domain."""
        return self._run_command(["virsh", "domblklist", self.domain])

    def extract_head_snapshot_path(self) -> Path:
        """Extract the head snapshot path from domblklist output."""
        self.log_handler.info("Extracting head snapshot path from domblklist output...")
        lines = self._run_domblklist()

        # Skip the first two lines (header and separator):
        data_lines = lines[DomblklistConfig.HEADER_LINES.number :]

        if len(data_lines) > DomblklistConfig.MAX_DATA_LINES.number:
            raise DomblklistTooManyLinesError(
                DomblklistConfig.MAX_DATA_LINES.number,
                len(data_lines),
            )

        if not data_lines:
            raise NoHeadSnapshotFoundError

        parts = data_lines[0].split(None, 1)
        if len(parts) == DomblklistConfig.PARTS_EXPECTED.number:
            self.log_handler.info(f"Found head snapshot path: {parts[1]}")
            return Path(parts[1])

        raise HeadSnapshotParseError(data_lines[0])

    def _extract_backing_file(self, path_to_snapshot: Path) -> Path:
        """Extract the backing file path for a given snapshot."""
        if not path_to_snapshot.is_file():
            raise SnapshotNotFoundError(path_to_snapshot)
        proc = subprocess.run(  # noqa: S603
            ["qemu-img", "info", str(path_to_snapshot)],  # noqa: S607
            capture_output=True,
            text=True,
            check=True,
        )
        output = proc.stdout.splitlines()

        # Extract "backing file" line if present
        backing_file = None
        for line in output:
            if line.strip().startswith("backing file:"):
                # Format typically: "backing file: /path/to/backing.qcow2"
                # Split on colon once, then strip extra whitespace
                backing_file = Path(line.split(":", 1)[1].strip())
                self.log_handler.info(f"Found backing file: {backing_file}")
                return backing_file
        raise BackingFileNotFoundError(path_to_snapshot)

    def traverse_snapshot_chain(self, head_snapshot: Path) -> list[Path]:
        """Traverse the snapshot chain starting at the head snapshot."""
        chain_info = []
        current = head_snapshot

        while True:
            if not current.is_file():
                raise SnapshotNotFoundError(current)

            try:
                next_snapshot = self._extract_backing_file(current)
            except BackingFileNotFoundError:
                if current == self.base_image_path:
                    self.log_handler.info(f"Reached base image: {current}")
                    break
                raise  # Re-raise the exception

            chain_info.append(current)
            current = next_snapshot

        return chain_info

    def commit_and_rebase_for_last_image(
        self,
        snapshot_chain: list[Path],
        dryrun: bool = True,
    ) -> None:
        """Commit and rebase the last snapshot in the chain."""
        last_snapshot = snapshot_chain[-1]
        # Ensure the last snapshot points to the base image.
        if self._extract_backing_file(last_snapshot) != self.base_image_path:
            raise BaseImageError(last_snapshot, self.base_image_path)

        # 1) Commit command for the last snapshot.
        commit_cmd = [
            "qemu-img",
            "commit",
            "-f",
            "qcow2",
            "-p",
            "-t",
            "none",
            str(last_snapshot),
        ]
        if dryrun:
            self.log_handler.info(f"[DRY RUN] Would run: {' '.join(commit_cmd)}")
        else:
            self._run_with_sudo(commit_cmd)

        # 2) Rebase the second-to-last snapshot to the base image.
        second_last_snapshot = snapshot_chain[-2]
        rebase_cmd = [
            "qemu-img",
            "rebase",
            "-f",
            "qcow2",
            "-F",
            "qcow2",
            "-b",
            str(self.base_image_path),
            str(second_last_snapshot),
        ]
        if dryrun:
            self.log_handler.info(f"[DRY RUN] Would run: {' '.join(rebase_cmd)}")
        else:
            self._run_with_sudo(rebase_cmd)

        # 3) Remove the actual file for the now-committed snapshot.
        if dryrun:
            self.log_handler.info(f"[DRY RUN] Would remove file: {last_snapshot}")
        else:
            last_snapshot.unlink(missing_ok=True)

        # 4) Try to remove the snapshot metadata from libvirt, ignoring errors.
        #    We'll take the snapshot name from the file stem (strip '.qcow2').
        snapshot_name = last_snapshot.stem
        virsh_delete_cmd = [
            "virsh",
            "snapshot-delete",
            self.domain,
            snapshot_name,
            "--metadata",
        ]
        if dryrun:
            self.log_handler.info(f"[DRY RUN] Would run: {' '.join(virsh_delete_cmd)}")
        else:
            with contextlib.suppress(subprocess.CalledProcessError):
                subprocess.run(virsh_delete_cmd, check=True)  # noqa: S603

        # 5) Pop the last snapshot from the chain in memory.
        snapshot_chain.pop()


def main() -> None:
    """Parse command line arguments and run checks."""
    parser = argparse.ArgumentParser(
        description="Manage KVM external snapshots by checking domblklist output.",
    )
    parser.add_argument(
        "--domain",
        help="The name or ID of the KVM domain to check.",
        type=str,
        required=True,
    )
    parser.add_argument(
        "--base-image",
        help="The path to the base image of all snapshots.",
        type=str,
        required=True,
    )
    parser.add_argument(
        "--dry-run",
        help="If given, commands will be logged instead of executed.",
        action="store_true",
        default=False,
    )
    parser.add_argument(
        "--remaining",
        help="Number of snapshots to remain after removal (min 5).",
        type=int,
        required=True,
    )

    args = parser.parse_args()
    if args.remaining < CliConfig.MIN_REMAINING.number:
        error_msg = f"--remaining must be at least {CliConfig.MIN_REMAINING.number}."
        raise ValueError(error_msg)

    log_handler = configure_logging(LoggingConfig(log_name="kvm_snapshot_manager"))
    base_image_path = Path(args.base_image).expanduser().resolve()
    lock_path = lock_path_for_base_image(base_image_path)

    with LockManager(
        lock_file=lock_path,
        logger=log_handler,
        script_name="kvm_snapshot_manager",
    ):
        manager = KVMSnapshotManager(
            log_handler=log_handler,
            domain=args.domain,
            base_image=str(base_image_path),
        )

        manager.check_domain_off()

        head_snapshot_path = manager.extract_head_snapshot_path()
        snapshot_chain = manager.traverse_snapshot_chain(head_snapshot_path)
        remove_count = len(snapshot_chain) - args.remaining
        if remove_count < 0:
            error_msg = (
                f"Cannot keep {args.remaining} snapshots; "
                f"only {len(snapshot_chain)} available."
            )
            raise ValueError(error_msg)

        # Remove the specified number of snapshots
        for _ in range(remove_count):
            manager.commit_and_rebase_for_last_image(
                snapshot_chain,
                dryrun=args.dry_run,
            )


if __name__ == "__main__":
    main()

"""Restic client for executing restic commands with proper error handling and logging."""

import json
import logging
import subprocess
import tempfile
from pathlib import Path

from opsbox.backup.exceptions import (
    ResticCommandFailedError,
    ResticRepositoryLockedError,
    SnapshotIDNotFoundError,
)
from opsbox.backup.snapshot_id import ResticSnapshotId

# Substrings restic prints (to stderr/log) when a repository lock blocks a
# command. Matched case-insensitively so callers can react to stale locks.
LOCK_ERROR_SIGNATURES = (
    "repository is already locked",
    "unable to create lock",
)

# Sentinel for the per-call ``timeout`` argument, meaning "fall back to the
# client's configured ``command_timeout``". A distinct object is used so an
# explicit ``timeout=None`` (run without any timeout) can be told apart from
# "no timeout argument was passed".
_USE_CONFIG_TIMEOUT = object()


def is_lock_error(text: str | None) -> bool:
    """Return True if ``text`` looks like a restic repository-lock error."""
    if not text:
        return False
    lowered = text.lower()
    return any(sig in lowered for sig in LOCK_ERROR_SIGNATURES)


class ResticClient:
    """Handles all restic command execution with proper error handling and logging.

    Does not send notifications: callers (e.g. ``BackupScript``) own alerting.
    """

    SNAPSHOT_PARTS_MIN_LENGTH = 2

    is_lock_error = staticmethod(is_lock_error)

    def __init__(
        self,
        restic_path: str,
        backup_target: str,
        logger: logging.Logger,
        command_timeout: int | None = None,
    ) -> None:
        """Initialize the restic client with path, target, and logger.

        Args:
            restic_path: Path to the restic executable.
            backup_target: The restic repository / backup target.
            logger: Logger used for command and error reporting.
            command_timeout: Timeout in seconds applied to every restic command.
                ``None`` (the default) means no timeout, i.e. commands may run
                indefinitely. Large backups can easily exceed any fixed limit,
                so a timeout is only enforced when explicitly configured.

        """
        self.restic_path = restic_path
        self.backup_target = backup_target
        self.logger = logger
        self.command_timeout = command_timeout
        self.temp_dir = Path(tempfile.gettempdir())
        self.temp_dir.mkdir(parents=True, exist_ok=True)
        self.cache_dir = self.temp_dir / "restic_cache"
        self._restic_env: dict[str, str] | None = None

        # Per-command capture (truncated each run) vs cumulative session log for emails
        with tempfile.NamedTemporaryFile(
            suffix=".log",
            prefix="restic_",
            delete=False,
        ) as temp_file:
            self.log_file = Path(temp_file.name)
        with tempfile.NamedTemporaryFile(
            suffix=".log",
            prefix="restic_session_",
            delete=False,
        ) as session_file:
            self.session_log = Path(session_file.name)
        self.session_log.write_text(
            f"Restic session log\nrepository: {self.backup_target}\n",
            encoding="utf-8",
        )
        self.logger.info(
            f"Created temporary log file: {self.log_file} "
            f"and session log: {self.session_log}",
        )

    def set_environment(
        self,
        restic_password: str,
        ssh_auth_sock: str | None = None,
    ) -> None:
        """Set the restic environment variables."""
        self._restic_env = {
            "RESTIC_PASSWORD": restic_password,
        }
        if ssh_auth_sock:
            self._restic_env["SSH_AUTH_SOCK"] = ssh_auth_sock

    def _get_cache_dir_args(self) -> list[str]:
        """Get cache directory arguments for restic commands."""
        if self.cache_dir:
            # Ensure cache directory exists
            self.cache_dir.mkdir(parents=True, exist_ok=True)
            return ["--cache-dir", str(self.cache_dir)]
        return []

    def _get_environment(self) -> dict[str, str]:
        """Get the restic environment, ensuring it's been set."""
        if self._restic_env is None:
            error_msg = "Restic environment not set. Call set_environment() first."
            raise ValueError(error_msg)
        return self._restic_env

    def _append_to_session_log(
        self,
        command: list[str],
        command_output: str = "",
        stdout: str | None = None,
    ) -> None:
        """Append one command's output to the cumulative session log.

        ``log_file`` stays per-command (truncated) for parsing; ``session_log``
        accumulates everything so email attachments cover the full run.
        """
        parts = [f"\n=== {' '.join(command)} ===\n", command_output]
        if not command_output.endswith("\n") and command_output:
            parts.append("\n")
        if stdout is not None:
            parts.append("--- stdout ---\n")
            parts.append(stdout)
            if stdout and not stdout.endswith("\n"):
                parts.append("\n")
        with self.session_log.open("a", encoding="utf-8") as session_file:
            session_file.write("".join(parts))

    def _resolve_timeout(self, timeout: int | None | object) -> int | None:
        """Resolve a per-call timeout against the configured default.

        When ``timeout`` is the ``_USE_CONFIG_TIMEOUT`` sentinel, the client's
        ``command_timeout`` is used (``None`` = no timeout). An explicit value
        (including ``None``) always overrides the configured default.
        """
        if timeout is _USE_CONFIG_TIMEOUT:
            return self.command_timeout
        return timeout  # type: ignore[return-value]

    def _run_command(
        self,
        command: list[str],
        text: bool = True,
        timeout: int | None | object = _USE_CONFIG_TIMEOUT,
        raise_on_error: bool = True,
    ) -> subprocess.CompletedProcess[str]:
        """Execute a command with proper error handling and logging.

        Args:
            command: The command and arguments to execute
            text: Whether to decode the output as text
            timeout: Timeout in seconds for the command. Defaults to the
                client's configured ``command_timeout`` (``None`` = no timeout).
            raise_on_error: If True, a non-zero exit code raises
                ResticCommandFailedError. If False, the non-zero exit code is
                logged as a warning and the completed process (including its
                output) is returned so the caller can inspect it. Operational
                failures (timeout, subprocess errors) always raise.

        """
        self.logger.debug(f"Running command: {' '.join(command)}")
        effective_timeout = self._resolve_timeout(timeout)

        try:
            # Capture this command only; session_log keeps the full run history
            with self.log_file.open("w") as f:
                result = subprocess.run(  # noqa: S603
                    command,
                    capture_output=False,
                    text=text,
                    timeout=effective_timeout,
                    env=self._get_environment(),
                    check=False,
                    stdout=f,
                    stderr=subprocess.STDOUT,
                )

            result.stdout = self.log_file.read_text()
            self._append_to_session_log(command, result.stdout)
            # Check for non-zero exit code
            if result.returncode != 0:
                error_msg = f"Command returned non-zero exit code: {result.returncode}"
                self.logger.error(f"{error_msg} - Command: {' '.join(command)}")
                if raise_on_error:
                    log_contents = result.stdout or None
                    # A repository lock is potentially recoverable: let the
                    # caller unlock stale locks and retry instead of alerting.
                    if self.is_lock_error(log_contents):
                        self.logger.warning(
                            "Restic reported a repository lock error.",
                        )
                        raise ResticRepositoryLockedError(error_msg)
                    raise ResticCommandFailedError(error_msg)
                self.logger.warning(
                    "Continuing despite non-zero exit code "
                    "(raise_on_error=False); caller will inspect the output.",
                )
            return result  # noqa: TRY300

        except subprocess.TimeoutExpired as e:
            log_contents = self.log_file.read_text() if self.log_file.exists() else None
            self._append_to_session_log(command, log_contents or "")
            error_msg = f"Command timed out after {effective_timeout} seconds"
            self.logger.exception(f"{error_msg}: {' '.join(command)}")
            raise ResticCommandFailedError(error_msg) from e
        except subprocess.SubprocessError as e:
            log_contents = self.log_file.read_text() if self.log_file.exists() else None
            self._append_to_session_log(command, log_contents or "")
            error_msg = f"Command failed: {e}"
            self.logger.exception(f"{error_msg} - Command: {' '.join(command)}")
            raise ResticCommandFailedError(error_msg) from e

    def _run_json_command(
        self,
        command: list[str],
        timeout: int | None | object = _USE_CONFIG_TIMEOUT,
    ) -> str:
        """Execute a restic ``--json`` command and return its raw stdout.

        stdout is captured separately (kept free of any stderr/progress noise)
        so it can be parsed as JSON, while stderr is written to the log file for
        error reporting. Both are appended to ``session_log``.

        Args:
            command: The command and arguments to execute (should include --json)
            timeout: Timeout in seconds for the command. Defaults to the
                client's configured ``command_timeout`` (``None`` = no timeout).

        Returns:
            The command's stdout as a string

        Raises:
            ResticCommandFailedError: If the command fails or times out

        """
        self.logger.debug(f"Running JSON command: {' '.join(command)}")
        effective_timeout = self._resolve_timeout(timeout)

        try:
            with self.log_file.open("w") as f:
                result = subprocess.run(  # noqa: S603
                    command,
                    stdout=subprocess.PIPE,
                    stderr=f,
                    text=True,
                    timeout=effective_timeout,
                    env=self._get_environment(),
                    check=False,
                )

            stderr_text = self.log_file.read_text() if self.log_file.exists() else ""
            stdout_text = result.stdout or ""
            self._append_to_session_log(
                command,
                stderr_text,
                stdout=stdout_text,
            )

            if result.returncode != 0:
                error_msg = f"Command returned non-zero exit code: {result.returncode}"
                self.logger.error(f"{error_msg} - Command: {' '.join(command)}")
                raise ResticCommandFailedError(error_msg)
            return stdout_text  # noqa: TRY300

        except subprocess.TimeoutExpired as e:
            log_contents = self.log_file.read_text() if self.log_file.exists() else None
            self._append_to_session_log(command, log_contents or "")
            error_msg = f"Command timed out after {effective_timeout} seconds"
            self.logger.exception(f"{error_msg}: {' '.join(command)}")
            raise ResticCommandFailedError(error_msg) from e
        except subprocess.SubprocessError as e:
            log_contents = self.log_file.read_text() if self.log_file.exists() else None
            self._append_to_session_log(command, log_contents or "")
            error_msg = f"Command failed: {e}"
            self.logger.exception(f"{error_msg} - Command: {' '.join(command)}")
            raise ResticCommandFailedError(error_msg) from e

    def unlock(self) -> None:
        """Remove stale locks from the restic repository.

        A non-zero exit code is logged as a warning instead of raising, so that
        a failed unlock does not mask the original operation the caller is
        trying to recover (it will retry and surface the real error itself).
        """
        self.logger.info("Unlocking restic repository")
        cmd = [
            self.restic_path,
            "unlock",
            "-r",
            self.backup_target,
            *self._get_cache_dir_args(),
        ]
        result = self._run_command(cmd, raise_on_error=False)
        if result.returncode != 0:
            self.logger.warning(
                f"Unlock command returned non-zero exit code: {result.returncode}",
            )

    def backup(
        self,
        backup_source: str,
        excluded_files: list[str],
    ) -> ResticSnapshotId:
        """Run restic backup and return the snapshot ID."""
        cmd = [
            self.restic_path,
            "backup",
            "--repo",
            self.backup_target,
            backup_source,
            "--exclude-caches",
            "--one-file-system",
            *self._get_cache_dir_args(),
        ]
        self.logger.info(f"Executing command: {' '.join(cmd)}")

        for exclude in excluded_files:
            cmd.extend(["--exclude", exclude])

        self._run_command(cmd)

        # Extract snapshot ID from log file
        snapshot_id = self._extract_snapshot_id(self.log_file.read_text())

        self.logger.info(f"Backup completed successfully. Snapshot ID: {snapshot_id}")
        return snapshot_id

    def _extract_snapshot_id(self, output: str) -> ResticSnapshotId:
        """Extract snapshot ID from restic output."""
        lines = output.splitlines()
        for line in reversed(lines):
            if line.startswith("snapshot"):
                parts = line.split()
                if len(parts) >= self.SNAPSHOT_PARTS_MIN_LENGTH:
                    return ResticSnapshotId(parts[1])
        error_msg = f"Could not find snapshot ID in restic output: {output}"
        raise SnapshotIDNotFoundError(error_msg)

    def get_snapshots(self) -> list[ResticSnapshotId]:
        """Get list of snapshot IDs, ordered from oldest to newest.

        Uses ``restic snapshots --json`` so the result is parsed from structured
        data instead of fragile column-based text scraping.
        """
        cmd = [
            self.restic_path,
            "snapshots",
            "--json",
            "-r",
            self.backup_target,
            *self._get_cache_dir_args(),
        ]
        stdout = self._run_json_command(cmd)

        try:
            snapshots_data = json.loads(stdout) if stdout.strip() else []
        except json.JSONDecodeError as e:
            error_msg = f"Failed to parse restic snapshots JSON output: {e}"
            self.logger.exception(error_msg)
            raise ResticCommandFailedError(error_msg) from e

        snapshot_ids = []
        for entry in snapshots_data:
            short_id = (
                entry.get("short_id")
                or entry.get("id", "")[: ResticSnapshotId.SNAPSHOT_ID_LENGTH]
            )
            if short_id:
                snapshot_ids.append(ResticSnapshotId(short_id))

        return snapshot_ids

    def diff(self, snapshot1: ResticSnapshotId, snapshot2: ResticSnapshotId) -> str:
        """Get diff between two snapshots as newline-delimited JSON.

        Uses ``restic diff --json`` so the caller can parse structured change
        and statistics messages instead of scraping text markers.
        """
        cmd = [
            self.restic_path,
            "diff",
            str(snapshot1),
            str(snapshot2),
            "--json",
            "-r",
            self.backup_target,
            *self._get_cache_dir_args(),
        ]

        stdout = self._run_json_command(cmd)
        self.logger.info(f"Diff output: {stdout}")
        return stdout

    def find(self, file_pattern: str, snapshot_id: ResticSnapshotId) -> str:
        """Find files in a snapshot, returning the raw ``restic find --json`` output.

        The output is a JSON array of objects (one per snapshot) with ``hits``,
        ``snapshot`` and ``matches`` fields, so the caller can determine matches
        from structured data instead of scraping text.
        """
        cmd = [
            self.restic_path,
            "find",
            file_pattern,
            "--json",
            "-s",
            str(snapshot_id),
            "--repo",
            self.backup_target,
            *self._get_cache_dir_args(),
        ]

        return self._run_json_command(cmd)

    def forget(self, keep_last: str, keep_daily: str, keep_monthly: str) -> None:
        """Forget old snapshots according to retention policy."""
        self.logger.info("Running forget operation")
        cmd = [
            self.restic_path,
            "forget",
            "--keep-last",
            keep_last,
            "--keep-daily",
            keep_daily,
            "--keep-monthly",
            keep_monthly,
            "--repo",
            self.backup_target,
            *self._get_cache_dir_args(),
        ]

        result = self._run_command(cmd)
        if result.returncode != 0:
            error_msg = "Failed to forget old snapshots"
            raise ResticCommandFailedError(error_msg)

    def prune(self) -> None:
        """Prune the repository."""
        self.logger.info("Running prune operation")
        cmd = [
            self.restic_path,
            "prune",
            "-r",
            self.backup_target,
            *self._get_cache_dir_args(),
        ]

        result = self._run_command(cmd)
        if result.returncode != 0:
            error_msg = "Failed to prune repository"
            raise ResticCommandFailedError(error_msg)

    def cache_cleanup(self) -> None:
        """Clean up the cache."""
        self.logger.info("Running cache cleanup")
        cmd = [
            self.restic_path,
            "cache",
            "--cleanup",
            *self._get_cache_dir_args(),
        ]

        result = self._run_command(cmd)
        if result.returncode != 0:
            error_msg = "Failed to cleanup cache"
            raise ResticCommandFailedError(error_msg)

    def check(self, read_data_subset: str = "20%") -> str:
        """Check repository integrity and return the check output.

        A non-zero exit code (e.g. the repository has errors) does not raise:
        the output is returned so the caller can distinguish "no errors were
        found" from a repository that reported problems, and report accordingly.
        Operational failures (timeout, subprocess errors) still raise.
        """
        self.logger.info("Running repository check")
        cmd = [
            self.restic_path,
            "check",
            f"--read-data-subset={read_data_subset}",
            "--repo",
            self.backup_target,
            *self._get_cache_dir_args(),
        ]

        result = self._run_command(cmd, raise_on_error=False)
        return result.stdout or ""

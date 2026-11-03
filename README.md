# OpsBox

A collection of standalone Linux server operations tools: restic and rsync backups,
Docker database snapshots, encrypted mail, IMAP mailbox checks, service health
monitoring, KVM snapshot management, and desktop notifications.

Each tool is a self-contained executable built with PyInstaller, so it can be dropped
onto any Debian/Ubuntu server without installing a Python runtime. Most tools are
driven by a YAML config file and report results via GPG-encrypted email.

## Tools

| Tool                     | Binary (APT package)             | Purpose                                                              |
| ------------------------ | -------------------------------- | -------------------------------------------------------------------- |
| `restic_backup`          | `opsbox-restic-backup`           | Run and verify restic backups, including maintenance and retention   |
| `rsync_manager`          | `opsbox-rsync-manager`           | Pull remote directories via rsync with retries and log rotation      |
| `db_backup`              | `opsbox-db-backup`               | Dump a MariaDB database from a Docker container with cleanup         |
| `encrypted_mail`         | `opsbox-encrypted-mail`          | Send GPG-encrypted emails with attachments                           |
| `check_mails`            | `opsbox-check-mails`             | Verify expected emails arrived in an IMAP mailbox                    |
| `health_monitor`         | `opsbox-health-monitor`          | Monitor a service, send warnings, run one-shot remediation           |
| `kvm_snapshot_manager`   | `opsbox-kvm-snapshot-manager`    | Consolidate KVM/libvirt external snapshot chains                     |
| `notifier`               | `opsbox-notifier`                | Send desktop notifications via D-Bus (also usable as root)           |

## Installation

### APT repository (Debian/Ubuntu, amd64)

Every release is published to a GPG-signed APT repository hosted on GitHub Pages:

```bash
sudo mkdir -p /etc/apt/keyrings
curl -fsSL https://marcschuh.github.io/OpsBox/KEY.asc | sudo gpg --dearmor -o /etc/apt/keyrings/opsbox.gpg
echo "deb [signed-by=/etc/apt/keyrings/opsbox.gpg] https://marcschuh.github.io/OpsBox/ stable main" | sudo tee /etc/apt/sources.list.d/opsbox.list
sudo apt update
sudo apt install opsbox
```

The package installs all executables as `opsbox-<tool>` in `/usr/bin`, example
configurations under `/etc/opsbox/`, and a systemd unit template
`opsbox-health-monitor.service`.

### Standalone executables

Individual executables are attached to every [GitHub Release](https://github.com/MarcSchuh/OpsBox/releases).
Download the one you need and make it executable:

```bash
chmod +x restic_backup
./restic_backup --config /etc/opsbox/backup/config.yaml
```

### From source

```bash
git clone https://github.com/MarcSchuh/OpsBox.git
cd OpsBox
uv sync
uv run python -m opsbox.backup.restic_backup --config config.yaml
```

To build the standalone executables yourself, run the build scripts in `scripts/`
(requires PyInstaller, e.g. `./scripts/build_restic_backup.sh`); the resulting
binaries end up in `dist/`.

## Shared concepts

- **Config files** – most tools take a YAML config via `--config`. Example configs
  are shipped next to each module (e.g. `src/opsbox/backup/config.example.yaml`)
  and under `/etc/opsbox/` in the APT package.
- **Encrypted mail** – notifications are sent as GPG-encrypted emails through the
  `envelope` library. SMTP credentials live in an email settings file (JSON or YAML,
  see `src/opsbox/encrypted_mail/email_settings.example.yaml`). The SMTP password is
  either set directly (`password`) or looked up via `secret-tool` using
  `password_lookup_1` / `password_lookup_2`.
- **Locking** – every tool takes an exclusive `flock`-based lock so that cron jobs
  cannot run twice in parallel.
- **Logging** – rotating log files (5 MB, 3 backups), by default in
  `/var/log/opsbox` (fallback: `~/.local/log/opsbox`). Most tools accept
  `--log-level {DEBUG,INFO,WARNING,ERROR,CRITICAL}`.

## The tools

### restic_backup

Runs a full restic backup workflow: verifies the source is non-empty, sets up the
repository password (direct or via `secret-tool`), checks network connectivity and
the SSH agent, runs the backup, verifies a configured file is in the snapshot,
performs maintenance (`forget`, `check --read-data-subset`, conditional `prune`),
and sends a summary email including a `restic diff` report against the previous
snapshot. Stale repository locks are recovered automatically.

```bash
./dist/restic_backup \
    --config /path/to/config.yaml \
    --restic-path /snap/bin/restic \
    --log-level INFO
```

Key config entries (see `src/opsbox/backup/config.example.yaml`):

- `backup_source` / `backup_target`: what to back up and restic repository (e.g. `sftp:user@host:/repo`)
- `excluded_files`: glob patterns to exclude
- `restic_password` **or** `password_lookup_1` + `password_lookup_2` (mutually exclusive)
- `email_settings_path`, `file_to_check`: notification settings and snapshot verification file
- `keep_last`, `keep_daily`, `keep_monthly`: retention policy for `restic forget`
- `ssh_key`, `ssh_user`, `network_host`: SSH agent and connectivity pre-checks

Requires: `restic`, Linux. Exit codes: `1` config error, `2` backup error, `3` unexpected.

### rsync_manager

Pulls a remote directory to a local target using `rsync -avz`, with configurable
options (`--chown`, `--delete`, `--progress`, `--exclude-from`), SSH/network
pre-checks, a retry loop, log rotation, and a summary email with the log attached.

```bash
./dist/rsync_manager --config /path/to/config.yaml --log-level INFO
```

Key config entries (see `src/opsbox/rsync/config.example.yaml`):

- `rsync_source` (`user@host:/path`), `rsync_target`, `email_settings_path` (required)
- `rsync_retry_max`, `rsync_retry_delay`: retry behaviour
- `log_file`, `log_rotate_on_start`, `log_keep_lines`: logging behaviour
- `rsync_options`: `chown`, `delete`, `progress`; `exclude_file` for exclude patterns

Requires: `rsync`, SSH (agent if `ssh_key` is configured).

### db_backup

Dumps a MariaDB database **inside a Docker container** to a timestamped
`<db>_backup_YYYYMMDD_HHMMSS.sql.gz`, verifies the archive, deletes backups older
than `retention_days`, and notifies via email (the dump is attached if < 5 MB).

```bash
./dist/db_backup --config /path/to/config.yaml
```

The configuration file should specify (see `src/opsbox/db_snapshot/env.example`):

- `container_name`: name of the Docker container
- `backup_dir`: directory where backups are stored
- `env_file`: path to the container's `.env` file with `DB_USER`, `DB_PASSWORD`, `DB_NAME`
- `retention_days`: days to keep old backups (default 30)
- `compression_level`: gzip compression level 1–9 (default 6)
- `email_settings`: path to the email settings file for notifications

Requires: Docker, `mariadb`/`mariadb-dump` inside the container. Supports `--dry-run`.

### encrypted_mail

Send GPG-encrypted emails using SMTP. Supports JSON and YAML settings files and
optional attachments (attachments larger than 5 MB are dropped with a warning).

```bash
./dist/encrypted_mail \
    --email-settings /path/to/email_settings.yaml \
    --subject "Server Alert" \
    --message "Backup completed successfully" \
    --attachment /path/to/logfile.log
```

Settings file keys (see `src/opsbox/encrypted_mail/email_settings.example.yaml`):
`sender`, `recipient`, `host`, `port`, `user`, `security` (e.g. `starttls`),
`gpg_key_id`, `default_user`, and either `password` or
`password_lookup_1` + `password_lookup_2` for a `secret-tool` lookup.

Requires: GPG, `secret-tool` (libsecret) when no direct password is set.

### check_mails

Checks an IMAP mailbox for expected emails (by subject, within N days, exact or
substring match), optionally deletes old emails, and sends a desktop notification
if a check fails.

```bash
./dist/check_mails \
    --config /path/to/config.yaml \
    --log-level INFO \
    --notification-username <user>   # required when running as root
```

Key config entries (see `src/opsbox/check_mails/config.example.yaml`):

- `imap_folder`: mailbox to check (the email settings must contain a concrete IMAP `password`)
- `searches`: list of `subject`, `days_in_past`, `number_of_occurrences`, `match_any`
- `delete_old_emails`: `enabled`, `older_than_days`, `folder`

Requires: IMAP access to the mailbox, D-Bus for notifications.

### health_monitor

Runs a `check_command` on a schedule (e.g. via the shipped systemd unit). If the
condition fails, an encrypted warning email is sent and an optional
`remediation_command` runs once per failure episode; a "Recovered" email is sent
when the service is healthy again. The condition passes if the command exits with
code 0 and its output has at least `min_output_lines` lines, or contains
`expected_output_contains`; `invert_check` flips the logic.

```bash
./dist/health_monitor --config /path/to/config.yaml --log-level INFO
```

Key config entries (see `src/opsbox/health_monitor/config.example.yaml`):

- `email_settings_path`, `warning_title`, `check_command` (required)
- `remediation_command`: one-shot remediation (optional)
- `min_output_lines`, `expected_output_contains`, `invert_check`: condition tuning
- `log_file`: optional log location

The APT package ships `opsbox-health-monitor.service` as a template for running
this tool under systemd.

### kvm_snapshot_manager

Consolidates external KVM/libvirt snapshot chains: verifies the domain is shut off,
walks the backing-file chain from the head snapshot down to the base image
(`qemu-img info`), then repeatedly commits and rebases snapshots
(`qemu-img commit` + `qemu-img rebase`) until only `--remaining` snapshots are left,
deleting the merged files and their libvirt metadata along the way.

```bash
./dist/kvm_snapshot_manager \
    --domain <vm-name> \
    --base-image /path/to/base.qcow2 \
    --remaining 5 \
    --dry-run
```

Requires: `virsh` (libvirt), `qemu-img`, and `sudo` (password prompt for rebase).

### notifier

Sends desktop notifications via D-Bus. When run as root, the notification is
relayed to the given user's session via `sudo -u <user> ... notify-send`.

```bash
./dist/notifier "Backup completed" --summary "OpsBox" --username <user> --log-level INFO
```

Requires: D-Bus / `notify-send`; `--username` is required when running as root.

## Development

The project uses [uv](https://docs.astral.sh/uv/) for dependency management.

```bash
uv sync --extra dev   # install dependencies incl. dev tools
pre-commit install    # lint/format/type checks (ruff, mypy, markdownlint)
uv run pytest         # run the test suite with coverage
```

CI runs three jobs on every PR: code quality (ruff, mypy), tests (pytest +
coverage), and security (bandit, pip-audit). See [CI_CD_SETUP.md](CI_CD_SETUP.md)
for details on the pipeline and recommended branch protection settings.

For maintainers: the GPG signing key for the APT repository is managed as
described in [KEY_MANAGEMENT.md](KEY_MANAGEMENT.md).

## License

[Apache License 2.0](LICENSE)

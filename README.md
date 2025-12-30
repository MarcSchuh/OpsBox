# OpsBox

Server operations tools including backup scripts, encrypted mail functionality, logging management, and utility tools.

## Installation

For installation, ask your LLM.

## Standalone Executables

### encrypted_mail

Send encrypted emails using GPG encryption. Supports both JSON and YAML configuration formats:

```bash
./dist/encrypted_mail \
    --email-settings /path/to/email_settings.yaml \
    --subject "Server Alert" \
    --message "Backup completed successfully" \
    --attachment /path/to/logfile.log
```

### db_backup

Backup databases from Docker containers with automatic cleanup and email notifications:

```bash
./dist/db_backup \
    --config /path/to/config.yaml
```

The configuration file should specify:

- `container_name`: Name of the Docker container
- `backup_dir`: Directory where backups will be stored
- `env_file`: Path to the container's .env file with DB credentials
- `retention_days`: Number of days to retain backups
- `compression_level`: Gzip compression level (1-9)
- `email_settings`: Path to email settings file (JSON or YAML) for notifications

### restic_backup

Run Restic backup operations:

```bash
./dist/restic_backup \
    --config /path/to/config.yaml \
    --restic-path /snap/bin/restic \
    --log-level INFO
```

# OpsBox

Server operations tools including backup scripts, encrypted mail functionality, logging management, and utility tools.

## Installation

For installation, ask your LLM.

## Standalone Executables

### encrypted_mail

Send encrypted emails using GPG encryption:

```bash
./dist/encrypted_mail \
    --email-settings /path/to/email_settings.json \
    --subject "Server Alert" \
    --message "Backup completed successfully" \
    --attachment /path/to/logfile.log
```

### restic_backup

Run Restic backup operations:

```bash
./dist/restic_backup \
    --config /path/to/config.yaml \
    --restic-path /snap/bin/restic \
    --log-level INFO
```

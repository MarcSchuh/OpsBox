# OpsBox

A comprehensive Python library for server operations including backup scripts, encrypted mail functionality, logging management, and utility tools.

## Features

- **Backup Management**: Secure backup operations for server files and databases
- **Encrypted Mail**: Secure email communications with GPG encryption support
- **Logging System**: Centralized logging configuration with file rotation and console output
- **Lock Management**: File-based locking mechanisms for concurrent operations
- **Utility Functions**: Common server operation utilities and system information

## Installation

### Option 1: Editable Installation (Recommended for Development)

```bash
git clone https://github.com/MarcSchuh/OpsBox.git
cd OpsBox
uv sync
uv run pip install -e .
```

### Option 2: Add as Local Dependency

Add to your project's `pyproject.toml`:

```toml
[tool.uv.dependencies]
opsbox = {path = "../opsbox", editable = true}
```

Then run:

```bash
uv sync
```

### Option 3: From GitHub

```bash
uv add git+https://github.com/MarcSchuh/OpsBox.git
```

## Quick Start

```python
from opsbox.backup import BackupManager
from opsbox.encrypted_mail import EncryptedMail
from opsbox.logging import configure_logging, LoggingConfig
from opsbox.utils import get_system_info

# Configure logging
logging_config = LoggingConfig(log_name="my_app")
logger = configure_logging(logging_config)

# Get system information
info = get_system_info()
logger.info(f"Platform: {info['platform']}")

# Create a backup manager
backup_mgr = BackupManager("/path/to/backups")
backup_path = backup_mgr.create_backup("/path/to/source")

# Set up encrypted mailer
mailer = EncryptedMail(logger, "/path/to/email_settings.json")
mailer.send_mail_with_retries("Test Subject", "Hello, world!")
```

## Standalone Executable

OpsBox includes a standalone executable for encrypted mail functionality that can be built and distributed independently.

### Building the Executable

```bash
# Build the encrypted_mail executable
./scripts/build_encrypted_mail.sh
```

This creates a self-contained executable at `dist/encrypted_mail` that includes all dependencies.

### Using the Standalone Executable

```bash
# Send an encrypted email
./dist/encrypted_mail \
    --email-settings /path/to/email_settings.json \
    --subject "Server Alert" \
    --message "Backup completed successfully" \
    --attachment /path/to/logfile.log
```

The executable supports the same functionality as the Python library but runs independently without requiring Python installation.

## Usage Examples

### Logging System

```python
from opsbox.logging import configure_logging, LoggingConfig

# Basic setup
config = LoggingConfig(log_name="my_app")
logger = configure_logging(config)

# Quick setup
from opsbox.logging import setup_logging
logger = setup_logging(app_name="my_app", level="INFO")
```

### Encrypted Mail

```python
from opsbox.encrypted_mail import EncryptedMail

# Initialize mail service
mailer = EncryptedMail(logger, "/path/to/email_settings.json")

# Send email with retry logic
mailer.send_mail_with_retries(
    subject="Important Alert",
    message="Server backup completed successfully",
    mail_attachment="/path/to/backup.log"  # Optional
)
```

Email settings JSON format:

```json
{
  "sender": "alerts@example.com",
  "recipient": "admin@example.com",
  "password_lookup_1": "email",
  "password_lookup_2": "password",
  "host": "smtp.gmail.com",
  "port": 587,
  "user": "alerts@example.com",
  "security": "starttls",
  "gpg_key_id": "SomeID",
  "default_user": "opsbox",
  "password": null
}
```

### Backup Management

```python
from opsbox.backup import BackupManager

# Create backup manager
backup_mgr = BackupManager("/path/to/backups")

# Create backup
backup_path = backup_mgr.create_backup("/path/to/source")
print(f"Backup created at: {backup_path}")
```

### Lock Management

```python
from opsbox.locking import LockManager

# Create lock manager
lock_mgr = LockManager("/tmp/locks")

# Acquire lock
with lock_mgr.acquire("backup_operation"):
    # Perform backup operation
    print("Backup operation in progress...")
```

## Development Setup

### Prerequisites

Install `uv`:

```bash
curl -LsSf https://astral.sh/uv/install.sh | sh
export PATH="$HOME/.cargo/bin:$PATH"
```

### Quick Setup

```bash
git clone https://github.com/MarcSchuh/OpsBox.git
cd OpsBox
./scripts/setup-dev.sh
```

### Manual Setup

```bash
uv venv
source .venv/bin/activate
uv sync --optional dev
pre-commit install
```

## Testing

```bash
# Run tests
uv run pytest

# Run with coverage
uv run pytest --cov=src/opsbox

# Run quality checks
uv run ruff check --fix src/ tests/
uv run mypy src/
uv run bandit -r src/
```

## Project Structure

```
OpsBox/
├── src/opsbox/
│   ├── backup/          # Backup functionality
│   ├── encrypted_mail/  # Encrypted email (with standalone executable)
│   ├── locking/         # File-based locking
│   ├── logging/         # Logging configuration
│   └── utils/           # Utility functions
├── tests/               # Test suite
├── scripts/             # Build and setup scripts
├── dist/                # Built executables
└── main.py              # CLI entry point
```

## Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Make your changes
4. Run tests (`uv run pytest`)
5. Commit using conventional commits (`git commit -m "feat: add amazing feature"`)
6. Push and open a Pull Request

## License

MIT License - see [LICENSE](LICENSE) for details.

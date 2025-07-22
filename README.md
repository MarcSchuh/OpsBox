# OpsBox

A comprehensive Python library for server operations including backup scripts, encrypted mail functionality, logging management, and utility tools.

## Features

- **Backup Management**: Secure backup operations for server files and databases
- **Encrypted Mail**: Secure email communications with GPG encryption support
- **Logging System**: Centralized logging configuration with file rotation and console output
- **Lock Management**: File-based locking mechanisms for concurrent operations
- **Utility Functions**: Common server operation utilities and system information

## Installation

Since this is a local package not distributed via PyPI, you have several options for using it in your projects:

### Option 1: Editable Installation (Recommended for Development)

```bash
# Clone the repository
git clone https://github.com/MarcSchuh/OpsBox.git
cd OpsBox

# Install in editable mode using uv
uv sync
uv run pip install -e .

# Or using pip directly
pip install -e .
```

### Option 2: Add as Local Dependency in Another Project

If you want to use OpsBox in another project, add it to your project's `pyproject.toml`:

```toml
[project]
dependencies = [
    # ... other dependencies
]

[project.optional-dependencies]
dev = [
    # ... other dev dependencies
]

# Add OpsBox as a local dependency
[tool.uv.dependencies]
opsbox = {path = "../opsbox", editable = true}
```

Then install dependencies:

```bash
uv sync
```

### Option 3: Using uv to Add from GitHub

You can also add OpsBox directly from GitHub using uv:

```bash
# Add OpsBox from GitHub to your project
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

## Using OpsBox in Your Projects

### Logging System

OpsBox provides a comprehensive logging system with automatic file rotation and console output:

```python
from opsbox.logging import configure_logging, LoggingConfig

# Basic setup
config = LoggingConfig(log_name="my_app")
logger = configure_logging(config)

# Advanced configuration
config = LoggingConfig(
    log_name="my_app",
    log_filename="custom.log",
    log_level="DEBUG",
    log_dir="/var/log/myapp",
    max_bytes=10 * 1024 * 1024,  # 10MB
    backup_count=5,
    enable_console=True,
    enable_file=True
)
logger = configure_logging(config)

# Quick setup for common use cases
from opsbox.logging import setup_logging
logger = setup_logging(
    app_name="my_app",
    level="INFO",
    log_to_file=True,
    log_to_console=True
)
```

### Encrypted Mail

Send encrypted emails using GPG encryption with automatic retry logic:

```python
from opsbox.encrypted_mail import EncryptedMail
from opsbox.logging import configure_logging, LoggingConfig

# Configure logging
logging_config = LoggingConfig(log_name="email_service")
logger = configure_logging(logging_config)

# Initialize encrypted mail service
mailer = EncryptedMail(
    logger=logger,
    email_settings_path="/path/to/email_settings.json",
    fail_silently=False
)

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
  "gpg_key_id": "admin@example.com",
  "default_user": "opsbox",
  "password": null
}
```

### Backup Management

```python
from opsbox.backup import BackupManager
from pathlib import Path

# Create backup manager
backup_mgr = BackupManager("/path/to/backups")

# Create backup
backup_path = backup_mgr.create_backup("/path/to/source")
print(f"Backup created at: {backup_path}")
```

### Utility Functions

```python
from opsbox.utils import get_system_info, validate_path
from pathlib import Path

# Get system information
system_info = get_system_info()
print(f"Running on: {system_info['platform']}")

# Validate a path
is_valid = validate_path(Path("/path/to/file"))
print(f"Path is valid: {is_valid}")
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

Before setting up the development environment, you need to install `uv`:

```bash
# Using the official installer (recommended):
curl -LsSf https://astral.sh/uv/install.sh | sh
export PATH="$HOME/.cargo/bin:$PATH"

# Using pip:
pip install uv

# Using Homebrew (macOS):
brew install uv
```

### Quick Setup

Use the automated setup script:

```bash
git clone https://github.com/MarcSchuh/OpsBox.git
cd OpsBox
./scripts/setup-dev.sh
```

This script will:

- Check if uv is installed
- Set up Python virtual environment
- Install all development dependencies
- Configure pre-commit hooks

### Manual Setup

1. **Clone the repository**:

   ```bash
   git clone https://github.com/MarcSchuh/OpsBox.git
   cd OpsBox
   ```

2. **Setup Python environment**:

   ```bash
   uv venv
   source .venv/bin/activate
   uv sync
   ```

3. **Install dependencies**:

   ```bash
   uv sync --optional dev
   ```

4. **Install pre-commit hooks**:

   ```bash
   pre-commit install
   pre-commit install --hook-type commit-msg
   ```

5. **Run tests**:

   ```bash
   uv run pytest
   ```

## CI/CD Pipeline

This project uses GitHub Actions for continuous integration and deployment. The pipeline ensures code quality, security, and reliability through automated checks.

### Pipeline Overview

The CI pipeline runs on every push and pull request to `main` and `develop` branches and includes:

- **Code Quality Checks**: Linting, formatting, and type checking
- **Test Suite**: Unit tests with coverage reporting
- **Security Scanning**: Automated security vulnerability detection (Bandit + pip-audit)
- **CodeQL Analysis**: Advanced security analysis for vulnerability detection

### Required Status Checks

Before any merge to protected branches, the following checks must pass:

- ✅ **Lint and Format** (`quality`)
- ✅ **Test Suite** (`test`) - Python 3.12
- ✅ **Security Scan** (`security`)
- ✅ **CodeQL Analysis** (`CodeQL`)

### Branch Protection

The repository enforces branch protection rules that require:

1. **Pull Request Reviews**: At least one approval required
2. **Status Checks**: All CI checks must pass
3. **Up-to-date Branches**: Branches must be up to date before merging
4. **Code Owner Review**: Automatic review requests for code owners

## Code Quality

This project uses several tools to maintain code quality:

- **Ruff**: Fast Python linter and formatter
- **MyPy**: Static type checking
- **Bandit**: Security linting
- **Pre-commit**: Automated code quality checks
- **Commitizen**: Conventional commit message enforcement

### Running Quality Checks

#### Manual Commands

```bash
# Format and lint code
uv run ruff check --fix src/ tests/
uv run ruff format src/ tests/

# Type checking
uv run mypy src/

# Security checks
uv run bandit -r src/

# Run all checks
uv run pre-commit run --all-files
```

## Project Structure

```
OpsBox/
├── src/
│   └── opsbox/
│       ├── __init__.py
│       ├── backup/
│       │   ├── __init__.py
│       │   └── scripts.py
│       ├── encrypted_mail/
│       │   ├── __init__.py
│       │   └── encrypted_mail.py
│       ├── locking/
│       │   └── lock_manager.py
│       ├── logging/
│       │   ├── __init__.py
│       │   └── logger_setup.py
│       └── utils/
│           ├── __init__.py
│           └── common.py
├── tests/
│   ├── test_backup/
│   ├── test_encrypted_mail/
│   ├── test_logging/
│   └── test_utils/
├── docs/
├── pyproject.toml
├── .pre-commit-config.yaml
└── README.md
```

## Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Make your changes following the code style guidelines
4. Run the test suite (`uv run pytest`)
5. Commit your changes using conventional commits (`git commit -m "feat: add amazing feature"`)
6. Push to the branch (`git push origin feature/amazing-feature`)
7. Open a Pull Request

### Commit Message Format

This project follows the [Conventional Commits](https://www.conventionalcommits.org/) specification:

- `feat`: A new feature
- `fix`: A bug fix
- `docs`: Documentation only changes
- `style`: Changes that do not affect the meaning of the code
- `refactor`: A code change that neither fixes a bug nor adds a feature
- `test`: Adding missing tests or correcting existing tests
- `chore`: Changes to the build process or auxiliary tools

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Support

- **Documentation**: [https://opsbox.readthedocs.io](https://opsbox.readthedocs.io)
- **Issues**: [https://github.com/MarcSchuh/OpsBox/issues](https://github.com/MarcSchuh/OpsBox/issues)
- **Discussions**: [https://github.com/MarcSchuh/OpsBox/discussions](https://github.com/MarcSchuh/OpsBox/discussions)

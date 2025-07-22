# OpsBox

A comprehensive Python library for server operations including backup scripts, encrypted mail functionality, and utility tools.

## Features

- **Backup Management**: Secure backup operations for server files and databases
- **Encrypted Mail**: Secure email communications with encryption support
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

````bash
# Add OpsBox from GitHub to your project
uv add git+https://github.com/MarcSchuh/OpsBox.git


## Quick Start

```python
from opsbox.backup import BackupManager
from opsbox.mail import EncryptedMailer
from opsbox.utils import get_system_info

# Get system information
info = get_system_info()
print(f"Platform: {info['platform']}")

# Create a backup manager
backup_mgr = BackupManager("/path/to/backups")
backup_path = backup_mgr.create_backup("/path/to/source")

# Set up encrypted mailer
mailer = EncryptedMailer("/path/to/key.pem")
mailer.load_key()
encrypted = mailer.encrypt_message("Hello, world!")
````

## Using OpsBox in Your Projects

### As a Library

```python
# Import and use OpsBox modules
from opsbox.utils.common import get_system_info
from opsbox.backup.scripts import create_backup
from opsbox.mail.encryption import encrypt_message

# Use the functionality
system_info = get_system_info()
print(f"Running on: {system_info['platform']}")
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
- **Build Verification**: Ensures the package can be built successfully

### Required Status Checks

Before any merge to protected branches, the following checks must pass:

- ✅ **Lint and Format** (`lint`)
- ✅ **Test Suite** (`test`) - Python 3.12
- ✅ **Security Scan** (`security`)
- ✅ **Build Check** (`build`)

### Branch Protection

The repository enforces branch protection rules that require:

1. **Pull Request Reviews**: At least one approval required
2. **Status Checks**: All CI checks must pass
3. **Up-to-date Branches**: Branches must be up to date before merging
4. **Code Owner Review**: Automatic review requests for code owners

For detailed setup instructions, see [`.github/BRANCH_PROTECTION.md`](.github/BRANCH_PROTECTION.md).

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
│       ├── mail/
│       │   ├── __init__.py
│       │   └── encryption.py
│       └── utils/
│           ├── __init__.py
│           └── common.py
├── tests/
│   ├── test_backup/
│   ├── test_mail/
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

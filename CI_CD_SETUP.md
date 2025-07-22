# CI/CD Setup

This repository uses GitHub Actions for continuous integration and deployment.

## Pipeline Overview

The CI pipeline consists of three jobs:

1. **Code Quality** - Linting, formatting, and type checking
2. **Tests** - Test execution with coverage reporting
3. **Security** - Security scanning with Bandit and pip-audit

## Required Status Checks

Configure these status checks in branch protection rules:

- `quality` (Code Quality)
- `test` (Tests)
- `security` (Security Scan)

## Branch Protection Setup

1. Go to Repository Settings → Branches
2. Add rule for `main` branch with:
   - ✅ Require pull request before merging
   - ✅ Require approvals (1 or more)
   - ✅ Require status checks to pass
   - ✅ Require branches to be up to date
   - ✅ Include administrators

## Local Development

Install pre-commit hooks:

```bash
uv sync --extra dev
pre-commit install
```

## Tools Used

- **Ruff** - Linting and formatting
- **MyPy** - Type checking
- **Pytest** - Testing with coverage
- **Bandit** - Security scanning
- **pip-audit** - Dependency vulnerability scanning

# CI/CD Setup

This repository uses GitHub Actions for continuous integration and deployment.

## Pipeline Overview

The CI pipeline consists of three jobs:

1. **Code Quality** - Linting, formatting, and type checking
2. **Tests** - Test execution with coverage reporting
3. **Security** - Security scanning with Bandit and pip-audit

## Version Bumps on Dependency Updates

Pull requests that change `uv.lock` (Dependabot or manual) automatically get
a PATCH version bump pushed onto the PR branch
(`.github/workflows/version-bump-on-deps.yml`). The new version therefore
arrives on `main` through the PR merge itself - the release workflow never
pushes to the protected `main` branch, so no PAT or bypass is needed.

If a dependency update still lands on `main` without a version bump (the
bump workflow failed or was skipped, or `uv.lock` was changed outside a pull
request), the release workflow fails with instructions instead of silently
re-releasing the current version. Fix: open a PR that bumps the version in
`pyproject.toml`, merge it, and the release runs automatically.

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

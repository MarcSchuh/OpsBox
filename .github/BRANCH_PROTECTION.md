# Branch Protection Setup

This document explains how to configure branch protection rules in GitHub to enforce the CI/CD pipeline requirements.

## Required Branch Protection Rules

To ensure that merges only occur when all checks pass and code review is completed, you need to configure branch protection rules in your GitHub repository settings.

### Steps to Configure Branch Protection

1. **Navigate to Repository Settings**:
   - Go to your repository on GitHub
   - Click on "Settings" tab
   - Click on "Branches" in the left sidebar

2. **Add Branch Protection Rule**:
   - Click "Add rule" or "Add branch protection rule"
   - In "Branch name pattern", enter: `main`
   - Configure the following settings:

### Required Settings

#### ✅ Require a pull request before merging
- **Require a pull request before merging**: Enabled
- **Require approvals**: 1 (or more as needed)
- **Dismiss stale PR approvals when new commits are pushed**: Enabled
- **Require review from code owners**: Enabled (if you have a CODEOWNERS file)

#### ✅ Require status checks to pass before merging
- **Require status checks to pass before merging**: Enabled
- **Require branches to be up to date before merging**: Enabled
- **Status checks that are required**:
  - `lint` (Lint and Format)
  - `test / 3.12 (ubuntu-latest)` (Test Suite - Python 3.12)
  - `test / 3.11 (ubuntu-latest)` (Test Suite - Python 3.11)
  - `security` (Security Scan)
  - `build` (Build Check)

#### ✅ Additional Settings
- **Require conversation resolution before merging**: Enabled
- **Require signed commits**: Optional (recommended for security)
- **Require linear history**: Optional (prevents merge commits)
- **Include administrators**: Enabled (applies rules to admins too)

### For `develop` Branch (if using)

If you're using a `develop` branch for development:
- Create another branch protection rule for `develop`
- Use the same settings as above
- You might want to require fewer approvals (1 instead of 2)

## Code Owners (Optional but Recommended)

Create a `.github/CODEOWNERS` file to automatically request reviews from specific team members:

```gitignore
# Global code owners
* @MarcSchuh

# Specific file patterns
*.py @python-team
.github/ @devops-team
docs/ @documentation-team
```

## Verification

After setting up branch protection:

1. **Test the workflow**:
   - Create a new branch
   - Make changes
   - Create a pull request
   - Verify that:
     - All CI checks run automatically
     - You cannot merge without approval
     - You cannot merge if any check fails

2. **Check the status**:
   - Go to the "Actions" tab to see CI runs
   - Check that all required status checks appear in PR

## Troubleshooting

### Common Issues

1. **Status checks not appearing**:
   - Ensure the workflow file is in the correct location (`.github/workflows/ci.yml`)
   - Check that the job names match exactly in branch protection settings

2. **Build failing**:
   - Check the Actions tab for detailed error messages
   - Ensure all dependencies are properly specified in `pyproject.toml`

3. **Permission issues**:
   - Ensure the GitHub Actions workflow has the necessary permissions
   - Check repository settings for workflow permissions

### Required Repository Permissions

In Repository Settings → Actions → General:
- **Workflow permissions**: "Read and write permissions"
- **Allow GitHub Actions to create and approve pull requests**: Enabled (if using automated PRs)

## Best Practices

1. **Always require PR reviews** for main branches
2. **Use status checks** to ensure code quality
3. **Keep branch protection rules simple** but effective
4. **Document your CI/CD process** (this file)
5. **Regularly review and update** branch protection rules
6. **Use CODEOWNERS** for automatic review assignment
7. **Monitor CI/CD performance** and optimize as needed

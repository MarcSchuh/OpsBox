#!/usr/bin/env bash

# OpsBox Development Environment Setup Script
# Lightweight setup script that only checks for uv and sets up the dev environment
#
# This script sets up a development environment for OpsBox,
# including dependencies and pre-commit hooks.

set -euo pipefail

# Script configuration
readonly SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly PROJECT_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
readonly SCRIPT_NAME="$(basename "${BASH_SOURCE[0]}")"

# Color codes for output
readonly RED='\033[0;31m'
readonly GREEN='\033[0;32m'
readonly YELLOW='\033[1;33m'
readonly BLUE='\033[0;34m'
readonly NC='\033[0m' # No Color

# Logging functions
log_info() {
    echo -e "${BLUE}[INFO]${NC} $*"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $*"
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $*"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $*" >&2
}

# Function to check if command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Function to check if uv is installed
check_uv() {
    if ! command_exists uv; then
        log_error "uv is not installed on your system."
        echo
        echo "To install uv, run one of the following commands:"
        echo
        echo "  # Using the official installer (recommended):"
        echo "  curl -LsSf https://astral.sh/uv/install.sh | sh"
        echo "  export PATH=\"\$HOME/.cargo/bin:\$PATH\""
        echo
        echo "  # Using pip:"
        echo "  pip install uv"
        echo
        echo "  # Using Homebrew (macOS):"
        echo "  brew install uv"
        echo
        echo "After installation, restart your terminal or run:"
        echo "  source ~/.bashrc  # or ~/.zshrc for zsh"
        echo
        exit 1
    fi

    log_success "uv is installed"
}

# Function to setup Python virtual environment
setup_python_env() {
    log_info "Setting up Python environment..."

    cd "$PROJECT_ROOT"

    # Create virtual environment if it doesn't exist
    if [[ ! -d ".venv" ]]; then
        log_info "Creating virtual environment..."
        uv venv
    else
        log_info "Virtual environment already exists"
    fi

    # Activate virtual environment
    source .venv/bin/activate

    log_success "Python environment setup complete"
}

# Function to install Python dependencies
install_python_dependencies() {
    log_info "Installing Python dependencies..."

    cd "$PROJECT_ROOT"
    source .venv/bin/activate

    # Install project dependencies including dev dependencies
    log_info "Installing project and development dependencies..."
    if ! uv sync --all-extras; then
        log_error "Failed to install dependencies"
        exit 1
    fi

    log_success "Python dependencies installed"
}

# Function to setup pre-commit hooks
setup_pre_commit() {
    log_info "Setting up pre-commit hooks..."

    cd "$PROJECT_ROOT"
    source .venv/bin/activate

    if ! command_exists pre-commit; then
        log_error "pre-commit not found in virtual environment"
        return 1
    fi

    # Install pre-commit hooks
    if ! pre-commit install; then
        log_error "Failed to install pre-commit hooks"
        return 1
    fi

    # Install commit-msg hook for conventional commits
    if ! pre-commit install --hook-type commit-msg; then
        log_warning "Failed to install commit-msg hook"
    fi

    log_success "Pre-commit hooks installed"
}

# Function to display setup summary
show_summary() {
    log_success "OpsBox development environment setup complete!"
    echo
    echo "Next steps:"
    echo "  1. Activate the virtual environment: source .venv/bin/activate"
    echo "  2. Run tests: uv run pytest"
    echo "  3. Run linting: uv run ruff check --fix src/ tests/"
    echo "  4. Start developing!"
    echo
    echo "Pre-commit hooks are installed and will run automatically on commits."
    echo "Make sure to use conventional commit messages (e.g., 'feat: add new feature')."
}

# Main function
main() {
    echo "=========================================="
    echo "  OpsBox Development Environment Setup"
    echo "=========================================="
    echo

    # Check prerequisites
    check_uv

    # Setup steps
    setup_python_env
    install_python_dependencies
    setup_pre_commit

    # Show summary
    show_summary
}

# Run main function
main "$@"

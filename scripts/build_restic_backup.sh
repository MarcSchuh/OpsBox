#!/bin/bash

# Build script for restic_backup executable using PyInstaller

set -e

echo "Building restic_backup executable..."

# Check if we're in the right directory
if [ ! -f "pyproject.toml" ]; then
    echo "Error: Please run this script from the project root directory"
    exit 1
fi

# Clean previous builds
echo "Cleaning previous builds..."
rm -rf build/ dist/restic_backup __pycache__/ *.spec

# Build the executable
echo "Building executable with PyInstaller..."
uv run pyinstaller --onefile \
    --name restic_backup \
    --hidden-import opsbox.logging \
    --hidden-import opsbox.logging.logger_setup \
    --hidden-import opsbox.logging.LoggingConfig \
    --hidden-import opsbox.exceptions \
    --hidden-import opsbox.backup.config_manager \
    --hidden-import opsbox.backup.exceptions \
    --hidden-import opsbox.backup.network_checker \
    --hidden-import opsbox.backup.password_manager \
    --hidden-import opsbox.backup.restic_client \
    --hidden-import opsbox.backup.ssh_manager \
    --hidden-import opsbox.encrypted_mail \
    --hidden-import opsbox.locking \
    --hidden-import opsbox.locking.lock_manager \
    --hidden-import envelope \
    --exclude-module opsbox.utils \
    --strip \
    --upx-dir=/usr/bin \
    src/opsbox/backup/restic_backup.py

# Check if build was successful
if [ -f "dist/restic_backup" ]; then
    echo "✅ Build successful!"
    echo "📦 Executable created: dist/restic_backup"
    echo "📏 File size: $(du -h dist/restic_backup | cut -f1)"

    # Make executable
    chmod +x dist/restic_backup

    echo ""
    echo "🚀 You can now run: ./dist/restic_backup --help"
    echo "📋 Example usage: ./dist/restic_backup --config /path/to/config.yaml"
    rm -rf build/ *.spec
else
    echo "❌ Build failed!"
    exit 1
fi

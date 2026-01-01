#!/bin/bash

# Build script for rsync_manager executable using PyInstaller

set -e

echo "Building rsync_manager executable..."

# Check if we're in the right directory
if [ ! -f "pyproject.toml" ]; then
    echo "Error: Please run this script from the project root directory"
    exit 1
fi

# Clean previous builds
echo "Cleaning previous builds..."
rm -rf build/rsync_manager dist/ __pycache__/ *.spec

# Build the executable
echo "Building executable with PyInstaller..."
uv run pyinstaller --onefile \
    --name rsync_manager \
    --hidden-import opsbox.logging \
    --hidden-import opsbox.logging.logger_setup \
    --hidden-import opsbox.logging.LoggingConfig \
    --hidden-import opsbox.exceptions \
    --hidden-import opsbox.encrypted_mail \
    --hidden-import opsbox.locking \
    --hidden-import opsbox.locking.lock_manager \
    --hidden-import opsbox.backup \
    --hidden-import opsbox.backup.exceptions \
    --hidden-import opsbox.backup.network_checker \
    --hidden-import opsbox.backup.ssh_manager \
    --hidden-import opsbox.rsync \
    --hidden-import yaml \
    --exclude-module opsbox.db_snapshot \
    --exclude-module opsbox.utils \
    --strip \
    --upx-dir=/usr/bin \
    src/opsbox/rsync/rsync-manager.py

# Check if build was successful
if [ -f "dist/rsync_manager" ]; then
    echo "✅ Build successful!"
    echo "📦 Executable created: dist/rsync_manager"
    echo "📏 File size: $(du -h dist/rsync_manager | cut -f1)"

    # Make executable
    chmod +x dist/rsync_manager

    echo ""
    echo "🚀 You can now run: ./dist/rsync_manager --help"
    echo "📋 Example usage: ./dist/rsync_manager --config /path/to/config.yaml"
    rm -rf build/ *.spec
else
    echo "❌ Build failed!"
    exit 1
fi

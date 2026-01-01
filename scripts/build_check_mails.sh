#!/bin/bash

# Build script for check_mails executable using PyInstaller

set -e

echo "Building check_mails executable..."

# Check if we're in the right directory
if [ ! -f "pyproject.toml" ]; then
    echo "Error: Please run this script from the project root directory"
    exit 1
fi

# Clean previous builds
echo "Cleaning previous builds..."
rm -rf build/ dist/check_mails __pycache__/ *.spec

# Build the executable
echo "Building executable with PyInstaller..."
uv run pyinstaller --onefile \
    --name check_mails \
    --hidden-import opsbox.logging \
    --hidden-import opsbox.logging.logger_setup \
    --hidden-import opsbox.logging.LoggingConfig \
    --hidden-import opsbox.exceptions \
    --hidden-import opsbox.encrypted_mail \
    --hidden-import opsbox.encrypted_mail.encrypted_mail \
    --hidden-import opsbox.locking \
    --hidden-import opsbox.locking.lock_manager \
    --hidden-import opsbox.check_mails \
    --hidden-import opsbox.check_mails.check_mails \
    --hidden-import envelope \
    --hidden-import yaml \
    --exclude-module opsbox.backup \
    --exclude-module opsbox.utils \
    --exclude-module opsbox.db_snapshot \
    --exclude-module opsbox.rsync \
    --strip \
    --upx-dir=/usr/bin \
    src/opsbox/check_mails/check_mails.py

# Check if build was successful
if [ -f "dist/check_mails" ]; then
    echo "✅ Build successful!"
    echo "📦 Executable created: dist/check_mails"
    echo "📏 File size: $(du -h dist/check_mails | cut -f1)"

    # Make executable
    chmod +x dist/check_mails

    echo ""
    echo "🚀 You can now run: ./dist/check_mails --help"
    echo "📋 Example usage: ./dist/check_mails --config /path/to/config.yaml"
    rm -rf build/ *.spec
else
    echo "❌ Build failed!"
    exit 1
fi

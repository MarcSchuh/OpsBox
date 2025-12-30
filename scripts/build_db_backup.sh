#!/bin/bash

# Build script for db_backup executable using PyInstaller

set -e

echo "Building db_backup executable..."

# Check if we're in the right directory
if [ ! -f "pyproject.toml" ]; then
    echo "Error: Please run this script from the project root directory"
    exit 1
fi

# Clean previous builds
echo "Cleaning previous builds..."
rm -rf build/ dist/ __pycache__/ *.spec

# Build the executable
echo "Building executable with PyInstaller..."
uv run pyinstaller --onefile \
    --name db_backup \
    --hidden-import opsbox.logging \
    --hidden-import opsbox.logging.logger_setup \
    --hidden-import opsbox.logging.LoggingConfig \
    --hidden-import opsbox.exceptions \
    --hidden-import opsbox.encrypted_mail \
    --hidden-import opsbox.locking \
    --hidden-import opsbox.locking.lock_manager \
    --hidden-import opsbox.db_snapshot \
    --hidden-import opsbox.db_snapshot.db_backup \
    --hidden-import envelope \
    --hidden-import dotenv \
    --exclude-module opsbox.backup \
    --exclude-module opsbox.utils \
    --strip \
    --upx-dir=/usr/bin \
    src/opsbox/db_snapshot/db_backup.py

# Check if build was successful
if [ -f "dist/db_backup" ]; then
    echo "✅ Build successful!"
    echo "📦 Executable created: dist/db_backup"
    echo "📏 File size: $(du -h dist/db_backup | cut -f1)"

    # Make executable
    chmod +x dist/db_backup

    echo ""
    echo "🚀 You can now run: ./dist/db_backup --help"
    echo "📋 Example usage: ./dist/db_backup --config /path/to/config.yaml"
    rm -rf build/ *.spec
else
    echo "❌ Build failed!"
    exit 1
fi

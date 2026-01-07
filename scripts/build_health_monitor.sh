#!/bin/bash

# Build script for health_monitor executable using PyInstaller

set -e

echo "Building health_monitor executable..."

# Check if we're in the right directory
if [ ! -f "pyproject.toml" ]; then
    echo "Error: Please run this script from the project root directory"
    exit 1
fi

# Clean previous builds
echo "Cleaning previous builds..."
rm -rf build/ dist/health_monitor __pycache__/ *.spec

# Build the executable
echo "Building executable with PyInstaller..."
uv run pyinstaller --onefile \
    --name health_monitor \
    --hidden-import opsbox.logging \
    --hidden-import opsbox.logging.logger_setup \
    --hidden-import opsbox.logging.LoggingConfig \
    --hidden-import opsbox.exceptions \
    --hidden-import opsbox.encrypted_mail \
    --hidden-import opsbox.encrypted_mail.encrypted_mail \
    --hidden-import opsbox.locking \
    --hidden-import opsbox.locking.lock_manager \
    --hidden-import opsbox.health_monitor \
    --hidden-import opsbox.health_monitor.health_monitor \
    --hidden-import envelope \
    --hidden-import yaml \
    --exclude-module opsbox.backup \
    --exclude-module opsbox.utils \
    --exclude-module opsbox.db_snapshot \
    --exclude-module opsbox.rsync \
    --exclude-module opsbox.check_mails \
    --strip \
    --upx-dir=/usr/bin \
    src/opsbox/health_monitor/health_monitor.py

# Check if build was successful
if [ -f "dist/health_monitor" ]; then
    echo "✅ Build successful!"
    echo "📦 Executable created: dist/health_monitor"
    echo "📏 File size: $(du -h dist/health_monitor | cut -f1)"

    # Make executable
    chmod +x dist/health_monitor

    echo ""
    echo "🚀 You can now run: ./dist/health_monitor --help"
    echo "📋 Example usage: ./dist/health_monitor --config /path/to/config.yaml"
    rm -rf build/ *.spec
else
    echo "❌ Build failed!"
    exit 1
fi

#!/bin/bash

# Build script for notifier executable using PyInstaller

set -e

echo "Building notifier executable..."

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
    --name notifier \
    --hidden-import opsbox.logging \
    --hidden-import opsbox.logging.logger_setup \
    --hidden-import opsbox.logging.LoggingConfig \
    --hidden-import opsbox.notifier \
    --hidden-import opsbox.notifier.notifier \
    --hidden-import opsbox.notifier.exceptions \
    --exclude-module opsbox.backup \
    --exclude-module opsbox.check_mails \
    --exclude-module opsbox.db_snapshot \
    --exclude-module opsbox.rsync \
    --exclude-module opsbox.encrypted_mail \
    --exclude-module opsbox.locking \
    --exclude-module opsbox.utils \
    --strip \
    --upx-dir=/usr/bin \
    src/opsbox/notifier/notifier.py

# Check if build was successful
if [ -f "dist/notifier" ]; then
    echo "✅ Build successful!"
    echo "📦 Executable created: dist/notifier"
    echo "📏 File size: $(du -h dist/notifier | cut -f1)"

    # Make executable
    chmod +x dist/notifier

    echo ""
    echo "🚀 You can now run: ./dist/notifier --help"
    echo "📋 Example usage: ./dist/notifier \"Your notification message\""
    echo "📋 Example with username: ./dist/notifier \"Your message\" --username myuser"
    echo "📋 Example with custom summary: ./dist/notifier \"Your message\" --summary \"Custom Title\""
    rm -rf build/ *.spec
else
    echo "❌ Build failed!"
    exit 1
fi

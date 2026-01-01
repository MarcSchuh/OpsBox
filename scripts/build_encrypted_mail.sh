#!/bin/bash

# Build script for encrypted_mail executable using PyInstaller

set -e

echo "Building encrypted_mail executable..."

# Check if we're in the right directory
if [ ! -f "pyproject.toml" ]; then
    echo "Error: Please run this script from the project root directory"
    exit 1
fi

# Clean previous builds
echo "Cleaning previous builds..."
rm -rf build/ dist/encrypted_mail __pycache__/ *.spec

# Build the executable
echo "Building executable with PyInstaller..."
uv run pyinstaller --onefile \
    --name encrypted_mail \
    --hidden-import opsbox.logging \
    --hidden-import opsbox.logging.logger_setup \
    --hidden-import opsbox.logging.LoggingConfig \
    --hidden-import opsbox.exceptions \
    --hidden-import envelope \
    --exclude-module opsbox.locking \
    --exclude-module opsbox.backup \
    --exclude-module opsbox.utils \
    --strip \
    --upx-dir=/usr/bin \
    src/opsbox/encrypted_mail/encrypted_mail.py

# Check if build was successful
if [ -f "dist/encrypted_mail" ]; then
    echo "✅ Build successful!"
    echo "📦 Executable created: dist/encrypted_mail"
    echo "📏 File size: $(du -h dist/encrypted_mail | cut -f1)"

    # Make executable
    chmod +x dist/encrypted_mail

    echo ""
    echo "🚀 You can now run: ./dist/encrypted_mail --help"
    rm -rf build/ *.spec
else
    echo "❌ Build failed!"
    exit 1
fi

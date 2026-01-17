#!/bin/bash

# Build script for kvm_snapshot_manager executable using PyInstaller

set -e

echo "Building kvm_snapshot_manager executable..."

# Check if we're in the right directory
if [ ! -f "pyproject.toml" ]; then
    echo "Error: Please run this script from the project root directory"
    exit 1
fi

# Clean previous builds
echo "Cleaning previous builds..."
rm -rf build/ dist/kvm_snapshot_manager __pycache__/ *.spec

# Build the executable
echo "Building executable with PyInstaller..."
uv run pyinstaller --onefile \
    --name kvm_snapshot_manager \
    --hidden-import opsbox.logging \
    --hidden-import opsbox.logging.logger_setup \
    --hidden-import opsbox.logging.LoggingConfig \
    --hidden-import opsbox.exceptions \
    --hidden-import opsbox.encrypted_mail \
    --hidden-import opsbox.locking \
    --hidden-import opsbox.locking.lock_manager \
    --hidden-import envelope \
    --exclude-module opsbox.backup \
    --exclude-module opsbox.db_snapshot \
    --exclude-module opsbox.rsync \
    --exclude-module opsbox.utils \
    --strip \
    --upx-dir=/usr/bin \
    src/opsbox/KVMSnapshotManager/kvm_snapshot_manager.py

# Check if build was successful
if [ -f "dist/kvm_snapshot_manager" ]; then
    echo "✅ Build successful!"
    echo "📦 Executable created: dist/kvm_snapshot_manager"
    echo "📏 File size: $(du -h dist/kvm_snapshot_manager | cut -f1)"

    # Make executable
    chmod +x dist/kvm_snapshot_manager

    echo ""
    echo "🚀 You can now run: ./dist/kvm_snapshot_manager --help"
    echo "📋 Example usage: ./dist/kvm_snapshot_manager --domain <name> --base-image /path/to/base.qcow2 --remove-count 1"
    rm -rf build/ *.spec
else
    echo "❌ Build failed!"
    exit 1
fi

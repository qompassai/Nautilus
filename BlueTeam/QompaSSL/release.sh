#!/bin/bash

# Set error handling
set -e

# Get the current directory
CURRENT_DIR=$(pwd)

# Set the install directory
INSTALL_DIR="$CURRENT_DIR/install"

# Set the release name (you can modify this as needed)
RELEASE_NAME="llvm-clang-lld-release"

# Get the current date for versioning
CURRENT_DATE=$(date +"%Y%m%d")

# Create tar.gz
tar -czf "${RELEASE_NAME}-${CURRENT_DATE}.tar.gz" -C "$INSTALL_DIR" .
echo "Created: ${RELEASE_NAME}-${CURRENT_DATE}.tar.gz"

# Create tar.xz
tar -cJf "${RELEASE_NAME}-${CURRENT_DATE}.tar.xz" -C "$INSTALL_DIR" .
echo "Created: ${RELEASE_NAME}-${CURRENT_DATE}.tar.xz"

# Calculate and display the SHA256 hash of the releases
if command -v sha256sum >/dev/null 2>&1; then
    SHA256_GZ=$(sha256sum "${RELEASE_NAME}-${CURRENT_DATE}.tar.gz" | awk '{ print $1 }')
    SHA256_XZ=$(sha256sum "${RELEASE_NAME}-${CURRENT_DATE}.tar.xz" | awk '{ print $1 }')
    echo "SHA256 (tar.gz): $SHA256_GZ"
    echo "SHA256 (tar.xz): $SHA256_XZ"
elif command -v shasum >/dev/null 2>&1; then
    SHA256_GZ=$(shasum -a 256 "${RELEASE_NAME}-${CURRENT_DATE}.tar.gz" | awk '{ print $1 }')
    SHA256_XZ=$(shasum -a 256 "${RELEASE_NAME}-${CURRENT_DATE}.tar.xz" | awk '{ print $1 }')
    echo "SHA256 (tar.gz): $SHA256_GZ"
    echo "SHA256 (tar.xz): $SHA256_XZ"
else
    echo "SHA256 calculation skipped (sha256sum or shasum not found)"
fi


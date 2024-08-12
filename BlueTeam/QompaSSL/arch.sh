#!/bin/bash

if ! gh auth status &>/dev/null; then
    echo "GitHub CLI is not authenticated. Attempting to authenticate..."
    if ! gh auth login; then
        echo "Failed to authenticate GitHub CLI. Please run 'gh auth login' manually."
        exit 1
    fi
fi

# Ensure a tag is provided
if [ $# -eq 0 ]; then
    echo "Please provide a tag name"
    exit 1
fi

TAG_NAME=$1
DATE_TIME=$(date "+%Y-%m-%d %H:%M:%S")

# Check if Configure script exists
if [ ! -f "./Configure" ]; then
    echo "Configure script not found. Are you in the correct directory?"
    exit 1
fi

# Check for write permissions
if [ ! -w "." ]; then
    echo "No write permission in the current directory"
    exit 1
fi

# Build OpenSSL
CC=gcc ./Configure shared \
linux-x86_64 \
no-weak-ssl-ciphers \
no-deprecated \
no-ssl3 \
no-tls1 \
no-tls1_1 \
enable-dynamic-engine \
enable-ktls \
enable-ssl-trace \
enable-srp \
enable-crypto-mdebug \
enable-crypto-mdebug-backtrace \
enable-fips \
enable-tls1_3 \
-DOPENSSL_NO_HEARTBEATS \
-DOQS_DEFAULT_GROUPS=\"p256_kyber512:p384_kyber768:p521_kyber1024:kyber512:kyber768:kyber1024:p256_falcon512:p384_falcon512:p521_falcon1024:falcon512:falcon1024:p256_dilithium2:p384_dilithium3:p521_dilithium5:dilithium2:dilithium3:dilithium5:p384_mceliece348864:p521_mceliece460896:mceliece348864:mceliece460896:mceliece6688128:mceliece6960119:mceliece8192128:x25519_kyber512:x25519_kyber768:x25519_kyber1024:x25519_falcon512:x25519_falcon1024:x25519_dilithium2:x25519_dilithium3:x25519_dilithium5:x25519_mceliece348864:x25519_mceliece460896:x25519_mceliece6688128:x25519_mceliece6960119:x25519_mceliece8192128:frodo640aes:frodo976aes:frodo1344aes:bike1l1cpa:bike1l3cpa:bike1l5cpa:hqc128:hqc192:hqc256:sphincssha256128frobust:sphincssha256192frobust:sphincssha256256frobust:secp256k1_kyber512:secp256k1_kyber768:secp256k1_kyber1024\" \
-lm \
enable-chacha \
enable-aria \
enable-blake2 \
enable-sm4 \
enable-ec_nistp_64_gcc_128 \
enable-camellia \
enable-seed \
enable-whirlpool \
enable-ocb \
enable-gost \
enable-sm2 \
enable-sm3 \
enable-tfo \
enable-afalg \
enable-comp \
enable-dtls


# Build and test
make
sudo make test

# Create a tar.gz archive
TAR_FILE="qompassl_${TAG_NAME}.tar.gz"
tar -czf "$TAR_FILE" libssl.so libcrypto.so

# Prepare release notes
RELEASE_NOTES="QompaSSL: OpenSSL with classical & post quantum protocols

Release Date: $DATE_TIME

This release includes libssl.so and libcrypto.so compiled with post-quantum algorithms."

# Create a release
gh release create $TAG_NAME \
    --title "QompaSSL Release $TAG_NAME" \
    --notes "$RELEASE_NOTES" \
    "$TAR_FILE"

# Clean up
rm "$TAR_FILE"

echo "Release created successfully with $TAR_FILE"

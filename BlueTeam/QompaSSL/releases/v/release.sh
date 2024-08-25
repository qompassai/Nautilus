#!/bin/bash

# Set variables
SOURCE_DIR="/home/phaedrus/Forge/GH/openssl-openssl-3.3.1"
RELEASE_DIR="/home/phaedrus/Forge/GH/Qompass/Nautilus/BlueTeam/QompaSSL/releases"
TAG_NAME="v$(date +'%Y.%m.%d')"
DATE_TIME=$(date +'%Y-%m-%d %H:%M:%S')

# Create release directory if it doesn't exist
mkdir -p "$RELEASE_DIR"

# Copy files to release directory
cp "$SOURCE_DIR/libssl.so" "$RELEASE_DIR/" || echo "libssl.so not found"
cp "$SOURCE_DIR/libcrypto.so" "$RELEASE_DIR/" || echo "libcrypto.so not found"
cp "$SOURCE_DIR/test_results81824.txt" "$RELEASE_DIR/" || echo "test_results81824.txt not found"

# Change to release directory
cd "$RELEASE_DIR" || exit

# Create a tar.gz archive
TAR_FILE="qompassl_${TAG_NAME}.tar.gz"
tar -czf "$TAR_FILE" libssl.so libcrypto.so test_results81824.txt

# Prepare release notes
RELEASE_NOTES="QompaSSL 1.1: Fork of OpenSSL with classical, quantum and post quantum protocols

Release Date: $DATE_TIME

This release includes libssl.so and libcrypto.so compiled with an extensive set of classical and post-quantum algorithms.

What is libcrypto.so?
This is the core cryptographic library of OpenSSL.
It provides implementations of various cryptographic algorithms, including symmetric and asymmetric encryption, digital signatures, hash functions, and random number generation.
Basically, It's the foundation for all cryptographic operations in OpenSSL.

What is libssl.so?:
This library implements the SSL (Secure Sockets Layer) and TLS (Transport Layer Security) protocols, relying on libcrypto.so for the underlying cryptographic operations.This results in the SSL/TLS handshake, certificate handling, and secure communication.

Changes and Improvements with 1.1:
1. Build Environment:
   - Maintained: Arch Linux x86_64

2. Security Enhancements:
   - Maintained: No weak SSL ciphers, no deprecated features, no SSL3/TLS1.0/TLS1.1, TLS 1.3 enabled, FIPS mode enabled, no heartbeat extension
   - Added: TLS security level set to 2 (-DOPENSSL_TLS_SECURITY_LEVEL=2)

3. Cryptographic Algorithms:
   - Maintained: ChaCha, ARIA, BLAKE2, SM4, Camellia, SEED, Whirlpool, GOST, SM2, SM3
   - Added: IDEA, MDC2, RC5
   - Maintained: EC_NISTP_64_GCC_128 optimization

4. Post-Quantum Algorithms:
   a. Key Encapsulation Mechanisms (KEMs):
      - Maintained: Kyber (512, 768, 1024), FrodoKEM (640, 976, 1344), BIKE, HQC, McEliece
      - Added: Explicit support for more McEliece variants
   b. Signature Schemes:
      - Maintained: Falcon (512, 1024), Dilithium (2, 3, 5), SPHINCS+
   c. Hybrid Schemes:
      - Expanded: More combinations of classical and post-quantum algorithms, including additional McEliece hybrids

5. Performance and Debugging:
   - Maintained: Dynamic engine loading, KTLS support, SSL tracing, Crypto debugging and backtrace
   - Added: Zlib and dynamic zlib support

6. Additional Protocols and Features:
   - Maintained: SRP, OCB mode, TFO, COMP, DTLS
   - Added: CMS (Cryptographic Message Syntax), RFC3779 support

7. Elliptic Curves:
   - Maintained: Standard NIST curves, secp256k1, X25519

New Configuration Highlights:
- Explicit disabling of static engines (-DOPENSSL_NO_STATIC_ENGINE)
- Comprehensive set of post-quantum and hybrid algorithms defined in DOQS_DEFAULT_GROUPS
- Addition of several classical algorithms (IDEA, MDC2, RC5)
- Enhanced support for CMS and RFC3779

This build continues to provide a wide range of cryptographic algorithms, with an expanded focus on post-quantum and hybrid schemes. It maintains the high security standards of the previous release while adding new capabilities and algorithm support. We also include test results with the inclusion of test_results81824.txt (not all of which were passes!) It is our intent of fostering trust via transparency and with gratitude to the giants who developed these encryption protocols and OpenSSL. It is humbling to stand on the shoulders of such giants."

# Create a release using GitHub CLI
gh release create "$TAG_NAME" \
    --repo "qompassai/Nautilus" \
    --title "QompaSSL Release $TAG_NAME" \
    --notes "$RELEASE_NOTES" \
    "$TAR_FILE"

# Clean up
rm "$TAR_FILE"

echo "Release created successfully with $TAR_FILE"

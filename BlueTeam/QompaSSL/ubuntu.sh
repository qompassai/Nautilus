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
./Configure shared linux-aarch64 no-weak-ssl-ciphers no-deprecated no-ssl3 no-tls1 no-tls1_1 enable-tls1_3 enable-ktls enable-ssl-trace enable-srp enable-crypto-mdebug enable-crypto-mdebug-backtrace enable-fips -DOPENSSL_NO_HEARTBEATS -DOQS_DEFAULT_GROUPS="p256_kyber512:p384_kyber768:p521_kyber1024:kyber512:kyber768:kyber1024:p256_falcon512:p384_falcon512:p521_falcon1024:falcon512:falcon1024:p256_dilithium2:p384_dilithium3:p521_dilithium5:dilithium2:dilithium3:dilithium5:p384_mceliece348864:p521_mceliece460896:mceliece348864:mceliece460896:mceliece6688128:mceliece6960119:mceliece8192128:x25519_kyber512:x25519_kyber768:x25519_kyber1024:x25519_falcon512:x25519_falcon1024:x25519_dilithium2:x25519_dilithium3:x25519_dilithium5:x25519_mceliece348864:x25519_mceliece460896:x25519_mceliece6688128:x25519_mceliece6960119:x25519_mceliece8192128:frodo640aes:frodo976aes:frodo1344aes:bike1l1cpa:bike1l3cpa:bike1l5cpa:hqc128:hqc192:hqc256:sphincssha256128frobust:sphincssha256192frobust:sphincssha256256frobust:secp256k1_kyber512:secp256k1_kyber768:secp256k1_kyber1024:sntrup761:ntrulpr761:x25519_sphincssha256128frobust:x25519_frodo640aes:x25519_bike1l1cpa:x25519_hqc128:sphincsshake256128frobust:sphincssha256128ssimple:sphincsshake256128ssimple:x448_kyber768:x448_dilithium3:frodo640shake:frodo976shake:frodo1344shake" -lm enable-chacha enable-aria enable-blake2 enable-sm4 enable-ec_nistp_64_gcc_128 enable-camellia enable-seed enable-whirlpool enable-ocb enable-gost enable-sm2 enable-sm3 enable-dtls enable-dynamic-engine enable-tfo enable-afalg enable-comp
# Build and test
make
sudo make test

# Create a tar.gz archive
TAR_FILE="qompassl_${TAG_NAME}.tar.gz"
tar -czf "$TAR_FILE" libssl.so libcrypto.so

# Prepare release notes
RELEASE_NOTES="QompaSSL: OpenSSL with classical,post-quantum, and hybrid protocols

Release Date: $DATE_TIME

This release includes libssl.so and libcrypto.so compiled on an Ubuntu 24.04 machine with aarch64 processor (NVIDIA AGX Orin Dev Kit).
Security Enhancements:
No weak SSL ciphers
No deprecated features
No SSL3, TLS 1.0, or TLS 1.1
TLS 1.3 enabled
FIPS mode enabled
No heartbeat extension (OPENSSL_NO_HEARTBEATS)

Cryptographic Algorithms:
ChaCha
ARIA
BLAKE2
SM4 (Chinese block cipher)
EC_NISTP_64_GCC_128 (optimized elliptic curve operations)
Camellia
SEED
Whirlpool
GOST (Russian algorithms)
SM2 and SM3 (Chinese algorithms)
Key Encapsulation Mechanisms (KEMs):
Kyber (512, 768, 1024)
FrodoKEM (640, 976, 1344)
BIKE (BIKE1L1CPA, BIKE1L3CPA, BIKE1L5CPA)
HQC (128, 192, 256)
McEliece (348864, 460896, 6688128, 6960119, 8192128)
Signature Schemes:
Falcon (512, 1024)
Dilithium (2, 3, 5)
SPHINCS+ (SHA256-128f-robust, SHA256-192f-robust, SHA256-256f-robust)
Hybrid Schemes (combining traditional and post-quantum):
p256_kyber512
p384_kyber768
p521_kyber1024
p256_falcon512
p384_falcon512
p521_falcon1024
p256_dilithium2
p384_dilithium3
p521_dilithium5
x25519_kyber512
x25519_kyber768
x25519_kyber1024
x25519_falcon512
x25519_falcon1024
x25519_dilithium2
x25519_dilithium3
x25519_dilithium5
x25519_mceliece348864
x25519_mceliece460896
x25519_mceliece6688128
x25519_mceliece6960119
x25519_mceliece8192128
secp256k1_kyber512
secp256k1_kyber768
secp256k1_kyber1024
Performance and Debugging:
Dynamic engine loading
Kernel TLS (KTLS) support
SSL tracing enabled
Crypto debugging and backtrace
Additional Protocols and Features:
SRP (Secure Remote Password) protocol
OCB mode
TFO (TCP Fast Open)
AFALG (Linux kernel crypto API)
COMP (compression)
DTLS (Datagram TLS)
Elliptic Curves:
Standard NIST curves (P-256, P-384, P-521)
secp256k1 (used in Bitcoin)
X25519
This custom build includes a wide range of cryptographic algorithms, post-quantum schemes, and performance enhancements. It prioritizes security by disabling older, less secure protocols and enabling newer, more secure options. The build also includes support for various national standards (e.g., Chinese SM2/SM3/SM4, Russian GOST) and emerging post-quantum cryptography schemes."

# Create a release
gh release create $TAG_NAME \
    --title "QompaSSL Release $TAG_NAME" \
    --notes "$RELEASE_NOTES" \
    "$TAR_FILE"

# Clean up
rm "$TAR_FILE"

echo "Release created successfully with $TAR_FILE"

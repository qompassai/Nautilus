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
TODAY=$(date "+%Y-%m-%d")
TEST_RESULTS_FILE="test_results_${TODAY}.txt"

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
enable-ec_nistp_64_gcc_128 \
enable-sctp \
enable-ssl-trace \
enable-zlib \
enable-zlib-dynamic \
enable-cms \
enable-rfc3779 \
enable-ec_nistp_64_gcc_128 \
enable-idea \
enable-mdc2 \
enable-rc5 \
enable-ssl-trace \
enable-fips \
-DOPENSSL_NO_HEARTBEATS \
-DOPENSSL_TLS_SECURITY_LEVEL=2 \
-DOPENSSL_NO_STATIC_ENGINE \
-DOQS_DEFAULT_GROUPS=\"p256_kyber512:p384_kyber768:p521_kyber1024:kyber512:kyber768:kyber1024:p256_falcon512:p384_falcon512:p521_falcon1024:falcon512:falcon1024:p256_dilithium2:p384_dilithium3:p521_dilithium5:dilithium2:dilithium3:dilithium5:p384_mceliece348864:p521_mceliece460896:mceliece348864:mceliece460896:mceliece6688128:mceliece6960119:mceliece8192128:x25519_kyber512:x25519_kyber768:x25519_kyber1024:x25519_falcon512:x25519_falcon1024:x25519_dilithium2:x25519_dilithium3:x25519_dilithium5:x25519_mceliece348864:x25519_mceliece460896:x25519_mceliece6688128:x25519_mceliece6960119:x25519_mceliece8192128:frodo640aes:frodo976aes:frodo1344aes:bike1l1cpa:bike1l3cpa:bike1l5cpa:hqc128:hqc192:hqc256:sphincssha256128frobust:sphincssha256192frobust:sphincssha256256frobust:secp256k1_kyber512:secp256k1_kyber768:secp256k1_kyber1024:mayo1:mayo2:mayo3:mayo5:mceliece348864_kyber512:mceliece348864_kyber768:mceliece348864_kyber1024:mceliece460896_kyber512:mceliece460896_kyber768:mceliece460896_kyber1024:mceliece6688128_kyber512:mceliece6688128_kyber768:mceliece6688128_kyber1024:mceliece6960119_kyber512:mceliece6960119_kyber768:mceliece6960119_kyber1024:mceliece8192128_kyber512:mceliece8192128_kyber768:mceliece8192128_kyber1024\" \
-lm \
enable-chacha \
enable-aria \
enable-blake2 \
enable-sm4 \
enable-camellia \
enable-seed \
enable-whirlpool \
enable-ocb \
enable-gost \
enable-sm2 \
enable-sm3 \
enable-tfo \
enable-comp \
enable-dtls

# Build and test
sudo make
(HARNESS_TAP_COPY=1 make test | tee "$TEST_RESULTS_FILE") && echo "\n--- Test Summary ---" && tail -n 20 "$TEST_RESULTS_FILE"

# Create a tar.gz archive
TAR_FILE="qompassl_${TAG_NAME}.tar.gz"
tar -czf "$TAR_FILE" libssl.so libcrypto.so

# Define the protocols used
# Build and test
sudo make
(HARNESS_TAP_COPY=1 make test | tee "$TEST_RESULTS_FILE") && echo "\n--- Test Summary ---" && tail -n 20 "$TEST_RESULTS_FILE"

# Create a tar.gz archive
TAR_FILE="qompassl_${TAG_NAME}.tar.gz"
tar -czf "$TAR_FILE" libssl.so libcrypto.so

# Define the protocols used
PROTOCOLS_USED="
Classical Protocols:
- TLS 1.2, TLS 1.3
- DTLS
- CHACHA20
- ARIA
- BLAKE2
- SM4
- CAMELLIA
- SEED
- WHIRLPOOL
- OCB
- GOST
- SM2
- SM3
- IDEA
- MDC2
- RC5

Post-Quantum and Hybrid Protocols:
- KYBER (512, 768, 1024)
- FALCON (512, 1024)
- DILITHIUM (2, 3, 5)
- MCELIECE (348864, 460896, 6688128, 6960119, 8192128)
- FRODO (640AES, 976AES, 1344AES)
- BIKE (L1, L3, L5)
- HQC (128, 192, 256)
- SPHINCS+ (SHA256-128F-ROBUST, SHA256-192F-ROBUST, SHA256-256F-ROBUST)
- MAYO (1, 2, 3, 5)

Hybrid Combinations:
- p256_kyber512, p384_kyber768, p521_kyber1024
- x25519_kyber512, x25519_kyber768, x25519_kyber1024
- p256_falcon512, p384_falcon512, p521_falcon1024
- x25519_falcon512, x25519_falcon1024
- p256_dilithium2, p384_dilithium3, p521_dilithium5
- x25519_dilithium2, x25519_dilithium3, x25519_dilithium5
- secp256k1_kyber512, secp256k1_kyber768, secp256k1_kyber1024
- Various combinations of MCELIECE with KYBER

Additional Features:
- FIPS (Federal Information Processing Standards) mode: A set of security standards required by the U.S. government for computer systems.
- KTLS (Kernel Transport Layer Security): An implementation of TLS in the kernel space for improved performance.
- SRP (Secure Remote Password): A cryptographic protocol for secure password-based authentication and key exchange.
- Crypto debugging: Tools and features to help developers identify and fix issues in cryptographic implementations.
- EC_NISTP_64_GCC_128: Optimized implementation of specific elliptic curve cryptography operations.
- SCTP (Stream Control Transmission Protocol): A transport layer protocol providing message-oriented communication.
- Zlib compression: A data compression library used to reduce the size of data being transmitted or stored.
- CMS (Cryptographic Message Syntax): A standard for protecting messages through digital signatures, encryption, or both.
- RFC (Request for Comments) 3779 support: Implementation of X.509 Extensions for IP Addresses and AS Identifiers.
"
# Parse test results for failed tests
FAILED_TESTS=$(grep -E "^not ok" "$TEST_RESULTS_FILE" | sed 's/^not ok [0-9]* - //')

# Prepare explanations for failed tests
FAILED_TESTS_EXPLANATION=""
for test in $FAILED_TESTS; do
    FAILED_TESTS_EXPLANATION+="
- $test: This test failed during the testing phase. Further investigation is needed to determine the cause of failure."
done

# Prepare release notes
RELEASE_NOTES="QompaSSL: OpenSSL with classical & post quantum protocols

Release Date: $DATE_TIME

This release includes libssl.so and libcrypto.so compiled with classical, post-quantum, and hybrid encryption algorithms.

Protocols used:
$PROTOCOLS_USED

Failed Tests and Explanations:
$FAILED_TESTS_EXPLANATION

For detailed test results, please refer to the attached $TEST_RESULTS_FILE."

# Create a release
gh release create $TAG_NAME \
    --title "QompaSSL Release $TAG_NAME" \
    --notes "$RELEASE_NOTES" \
    "$TAR_FILE" "$TEST_RESULTS_FILE"

# Clean up
rm "$TAR_FILE"

echo "Release created successfully with $TAR_FILE and $TEST_RESULTS_FILE"


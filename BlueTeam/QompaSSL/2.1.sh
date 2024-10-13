#!/bin/bash
export CC=gcc \
./config shared \
	linux-x86_64 \
	enable-engine \
	enable-dynamic-engine \
	no-weak-ssl-ciphers \
	no-deprecated \
	enable-afalgeng \
	no-ssl3 \
	enable-srp \
	no-tls1 \
  enable-sctp \
	no-tls1_1 \
	enable-ktls \
	enable-ssl-trace \
	enable-srp \
	enable-crypto-mdebug \
	enable-crypto-mdebug-backtrace \
	enable-tls1_3 \
	enable-zlib \
	enable-zlib-dynamic \
	enable-tls1_2 \
	enable-cms \
	enable-rfc3779 \
	enable-ec_nistp_64_gcc_128 \
	enable-idea \
	enable-mdc2 \
	enable-rc5 \
	enable-fips \
  enable-legacy \
	-DOPENSSL_NO_HEARTBEATS \
	-DOPENSSL_TLS_SECURITY_LEVEL=2 \
	-DOQS_DEFAULT_GROUPS="p256_kyber512:p384_kyber768:p521_kyber1024:kyber512:kyber768:kyber1024:p256_falcon512:p384_falcon512:p521_falcon1024:falcon512:falcon1024:p256_dilithium2:p384_dilithium3:p521_dilithium5:dilithium2:dilithium3:dilithium5:p384_mceliece348864:p521_mceliece460896:mceliece348864:mceliece460896:mceliece6688128:mceliece6960119:mceliece8192128:x25519_kyber512:x25519_kyber768:x25519_kyber1024:x25519_falcon512:x25519_falcon1024:x25519_dilithium2:x25519_dilithium3:x25519_dilithium5:x25519_mceliece348864:x25519_mceliece460896:x25519_mceliece6688128:x25519_mceliece6960119:x25519_mceliece8192128:frodo640aes:frodo976aes:frodo1344aes:bike1l1cpa:bike1l3cpa:bike1l5cpa:hqc128:hqc192:hqc256:sphincssha256128frobust:sphincssha256192frobust:sphincssha256256frobust:secp256k1_kyber512:secp256k1_kyber768:secp256k1_kyber1024:mayo1:mayo2:mayo3:mayo5:mceliece348864_kyber512:mceliece348864_kyber768:mceliece348864_kyber1024:mceliece460896_kyber512:mceliece460896_kyber768:mceliece460896_kyber1024:mceliece6688128_kyber512:mceliece6688128_kyber768:mceliece6688128_kyber1024:mceliece6960119_kyber512:mceliece6960119_kyber768:mceliece6960119_kyber1024:mceliece8192128_kyber512:mceliece8192128_kyber768:mceliece8192128_kyber1024:lightsaber:saber:firesaber:p384_falcon1024:secp256k1_falcon512:secp256k1_falcon1024:p384_kyber768:p521_kyber1024:secp256k1_dilithium2:secp256k1_dilithium3:secp256k1_dilithium5:falcon512:falcon1024:ntru-hps-2048-509:ntru-hps-2048-677:ntru-hps-4096-821:ntru-hrss-701" \
	enable-chacha \
	enable-asm \
	enable-quic \
	enable-aria \
	enable-blake2 \
	enable-async \
	enable-sm4 \
	enable-rdrand \
	enable-camellia \
	enable-seed \
	enable-whirlpool \
	enable-psk \
	enable-dsa \
	enable-dh \
	enable-ec \
	enable-ecdh \
	enable-ecdsa \
	enable-ocb \
	enable-gost \
	enable-poly1305 \
	enable-nextprotoneg \
	enable-siphash \
	enable-sm2 \
	enable-sm3 \
	enable-tfo \
	enable-comp \
	enable-dtls
# Get current date
CURRENT_DATE=$(date +'%Y%m%d')

# Set variables
SOURCE_DIR="/home/phaedrus/Forge/GH/Qompass/Nautilus/BlueTeam/QompaSSL"
RELEASE_DIR="/home/phaedrus/Forge/GH/Qompass/Nautilus/BlueTeam/QompaSSL/releases"
TAG_NAME="v$(date +'%Y.%m.%d')"
DATE_TIME=$(date +'%Y-%m-%d %H:%M:%S')

# Create release directory if it doesn't exist
mkdir -p "$RELEASE_DIR"

# Run make test and create test report with current date
TEST_REPORT="test_results_${CURRENT_DATE}.txt"
(
	echo "QompaSSL Test Report - ${DATE_TIME}"
	echo "=================================="
	echo
	make test
) 2>&1 | tee "$RELEASE_DIR/$TEST_REPORT"

# Add test summary to the end of the report
echo -e "\n--- Test Summary ---" >>"$RELEASE_DIR/$TEST_REPORT"
tail -n 20 "$RELEASE_DIR/$TEST_REPORT" >>"$RELEASE_DIR/$TEST_REPORT"

# Copy files to release directory
cp "$SOURCE_DIR/libssl.so" "$RELEASE_DIR/" || echo "libssl.so not found"
cp "$SOURCE_DIR/libcrypto.so" "$RELEASE_DIR/" || echo "libcrypto.so not found"

# Create a tar.gz archive
TAR_FILE="qompassl_${TAG_NAME}.tar.gz"
tar -czf "$RELEASE_DIR/$TAR_FILE" -C "$RELEASE_DIR" libssl.so libcrypto.so "$TEST_REPORT"

echo "Release archive created: $RELEASE_DIR/$TAR_FILE"
echo "Test report created: $RELEASE_DIR/$TEST_REPORT"

RELEASE_NOTES="QompaSSL 2.1: Fork of OpenSSL 3.3.2 with Enhanced Post-Quantum and Artificial Intelligence-Ready Cryptography

Release Date: $DATE_TIME

This release includes libssl.so and libcrypto.so compiled with an extensive set of classical, quantum-resistant, and post-quantum algorithms, based on OpenSSL 3.3.2. QompaSSL 1.3 is specifically tailored for securing Artificial Intelligence (AI) systems and preparing for the post-quantum era. Who's using these protocols currently? Great Question!

Industry Adoption and Real-World Applications:

1. Healthcare and Medical Systems:
   - Roche: Implementing post-quantum cryptography to secure sensitive medical data and research information [1].
   - Anthem: Exploring quantum-resistant algorithms to protect health records and patient data [2].

2. Financial Services:
   - JPMorgan Chase: Collaborating with Toshiba to develop quantum-resistant blockchain technology [3].
   - Visa: Researching post-quantum cryptography for secure financial transactions [4].

3. Technology and Cloud Services:
   - Google: Implementing post-quantum key exchange in Chrome to test new cryptographic algorithms [5].
   - IBM: Offering quantum-safe cryptography services in its cloud platform [6].

4. Government and Defense:
   - U.S. Department of Defense: Mandating quantum-resistant cryptography for future systems [7].
   - European Telecommunications Standards Institute (ETSI): Developing standards for quantum-safe cryptography [8].

5. Telecommunications:
   - AT&T: Collaborating on quantum-resistant network security solutions [9].

These industry leaders are at the forefront of adopting post-quantum cryptography, demonstrating the growing importance of quantum-resistant security measures across various sectors.

References:
[1] https://www.roche.com/stories/quantum-computers-calculating-the-unimaginable
[2] https://news.ncsu.edu/2020/02/health-care-anthem-joins-q-hub/
[3] https://www.jpmorgan.com/technology/technology-blog/jpmc-toshiba-ciena-build-first-quantum-key-distribution-network-critical-blockchain-application
[4] https://usa.visa.com/about-visa/visa-research/research-areas.html
[5] https://security.googleblog.com/2016/07/experimenting-with-post-quantum.html
[6] https://www.ibm.com/blogs/research/2019/08/quantum-safe-cryptography/
[7] https://www.defense.gov/News/News-Stories/Article/Article/3682355/pentagon-official-lays-out-dod-vision-for-ai/
[8] https://www.etsi.org/technologies/quantum-safe-cryptography
[9] https://techblog.comsoc.org/2022/10/07/att-will-be-quantum-ready-by-the-year-2025-but-may-not-be-fully-quantum-secured/



Enterprise and Consumer Use Cases for Post-Quantum Cryptography and AI:

1. Secure AI Model Training: Protect sensitive training data and model parameters with quantum-resistant encryption during distributed learning.
2. Long-Term Data Security: Ensure that data encrypted today remains secure against future quantum computer attacks, crucial for AI systems handling sensitive long-term data.
3. Secure Federated Learning: Enable privacy-preserving collaborative AI model training across multiple parties using post-quantum secure multi-party computation.
4. Quantum-Resistant Model Deployment: Protect AI models in transit and at rest with post-quantum algorithms to prevent theft and tampering.
5. Secure AI Inference: Implement homomorphic encryption techniques to perform computations on encrypted data, allowing AI inferences without exposing raw data.
6. Future-Proof IoT Security: Prepare Internet of Things (IoT) devices and AI edge computing for the post-quantum era with lightweight, quantum-resistant cryptographic protocols.
7. Regulatory Compliance: Meet forward-looking cybersecurity regulations that require quantum-resistant cryptography for AI systems in critical infrastructure.

This build provides a comprehensive suite of cryptographic algorithms, with a strong focus on post-quantum and hybrid schemes, tailored for the unique security needs of AI systems. It updates the base to OpenSSL 3.3.2, incorporating the latest security improvements while adding crucial features for quantum-resistant, AI-ready cryptography.

We maintain our commitment to high security standards while expanding the feature set to meet the evolving cryptographic needs of the AI era. As always, we include test results to foster transparency and trust. We remain grateful to the cryptography community and the OpenSSL developers for their invaluable contributions to the field."

# Commands to push release to GitHub repository
git add .
git commit -S -m "QompaSSL 2.1 Release $TAG_NAME"
git tag "$TAG_NAME"
git push origin main
git push origin "$TAG_NAME"
gh release create "$TAG_NAME" --repo qompassai/Nautilus --title "QompaSSL 2.1 Release $TAG_NAME" --notes "$RELEASE_NOTES" "$RELEASE_DIR/$TAR_FILE"

#!/bin/bash
# End-to-end Demonstration Script for ACNS-DSIG
set -e

echo "=== ACNS-DSIG DEMONSTRATION SUITE ==="
CLI_JAR="dsig-cli/target/dsig-cli-1.0.0-SNAPSHOT.jar"

if [ ! -f "$CLI_JAR" ]; then
    echo "CLI Jar not found at $CLI_JAR. Compiling with Maven..."
    ./mvnw package -DskipTests
fi

DEMO_DIR="runtime/demo-temp"
mkdir -p "$DEMO_DIR"

DEMO_DOC="$DEMO_DIR/demo_contract.txt"
ALICE_KEY="$DEMO_DIR/alice_key"
ALICE_PUB="$DEMO_DIR/alice_key.pub.pem"
ALICE_PK8="$DEMO_DIR/alice_key.pk8"
TRUST_STORE="$DEMO_DIR/trusted.json"
ENVELOPE="$DEMO_DIR/demo_contract.txt.dsig.json"

cleanup() {
    echo "Cleaning up demo artifacts from $DEMO_DIR..."
    rm -rf "$DEMO_DIR"
}
trap cleanup EXIT

cp test-data/contract.txt "$DEMO_DOC"

echo "1. Generating Alice's RSA-3072 Key Pair..."
java -jar "$CLI_JAR" keygen -o "$ALICE_KEY" -p secret123

echo ""
echo "2. Calculating Alice's Key Fingerprint..."
ALICE_FP=$(java -jar "$CLI_JAR" fingerprint "$ALICE_PUB" | grep "Hex Fingerprint" | awk '{print $4}')
echo "Alice Fingerprint: $ALICE_FP"

echo ""
echo "3. Pinning Alice's Key in Trust Store..."
java -jar "$CLI_JAR" trust-add "$ALICE_FP" -l "Alice Corporate" --trust-store "$TRUST_STORE"

echo ""
echo "4. Alice Signs Contract..."
java -jar "$CLI_JAR" sign "$DEMO_DOC" -k "$ALICE_PK8" --pub "$ALICE_PUB" -p secret123 -s "Alice Corporate" -o "$ENVELOPE"

echo ""
echo "5. Verifying Legitimate Document (Expect VALID_TRUSTED)..."
java -jar "$CLI_JAR" verify "$DEMO_DOC" -e "$ENVELOPE" --trust-store "$TRUST_STORE"

echo ""
echo "6. Tampering Contract to Demonstrate Integrity Protection..."
echo "[Unauthorized modification by attacker]" >> "$DEMO_DOC"
echo "Verifying Tampered Document (Expect DOCUMENT_TAMPERED)..."
set +e
java -jar "$CLI_JAR" verify "$DEMO_DOC" -e "$ENVELOPE" --trust-store "$TRUST_STORE"
TAMPER_CODE=$?
set -e
if [ $TAMPER_CODE -eq 1 ]; then
    echo "Tamper verification correctly detected alteration (exit code 1)."
else
    echo "Unexpected tamper exit code: $TAMPER_CODE"
    exit 1
fi

echo ""
echo "=== Demo Run Complete ==="

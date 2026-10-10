#!/bin/bash
# End-to-end Demonstration Script for ACNS-DSIG
set -e

echo "=== ACNS-DSIG DEMONSTRATION SUITE ==="
echo "1. Generating Alice's RSA-3072 Key Pair..."
java -jar dsig-cli/target/dsig-cli-1.0.0-SNAPSHOT.jar keygen -o test-data/alice_key -p secret123

echo "2. Calculating Alice's Key Fingerprint..."
ALICE_FP=$(java -jar dsig-cli/target/dsig-cli-1.0.0-SNAPSHOT.jar fingerprint test-data/alice_key.pub.pem | grep "Hex Fingerprint" | awk '{print $4}')
echo "Alice Fingerprint: $ALICE_FP"

echo "3. Pinning Alice's Key in Trust Store..."
java -jar dsig-cli/target/dsig-cli-1.0.0-SNAPSHOT.jar trust-add "$ALICE_FP" -l "Alice Corporate" --trust-store test-data/trusted.json

echo "4. Alice Signs Contract..."
java -jar dsig-cli/target/dsig-cli-1.0.0-SNAPSHOT.jar sign test-data/contract.txt -k test-data/alice_key.pk8 --pub test-data/alice_key.pub.pem -p secret123

echo "5. Verifying Legitimate Document (Expect VALID_TRUSTED)..."
java -jar dsig-cli/target/dsig-cli-1.0.0-SNAPSHOT.jar verify test-data/contract.txt --trust-store test-data/trusted.json

echo "=== Demo Run Complete ==="

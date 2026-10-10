#!/bin/bash
# Generate self-signed TLS 1.3 PKCS#12 certificate for local HTTPS testing
set -e

mkdir -p runtime/tls
echo "Generating self-signed PKCS#12 TLS keystore in runtime/tls/keystore.p12..."

keytool -genkeypair \
  -alias dsig-server \
  -keyalg RSA \
  -keysize 3072 \
  -storetype PKCS12 \
  -keystore runtime/tls/keystore.p12 \
  -validity 365 \
  -storepass changeit \
  -keypass changeit \
  -dname "CN=localhost, OU=ACNS, O=DSIG, L=Vadodara, ST=Gujarat, C=IN"

echo "Keystore created successfully."

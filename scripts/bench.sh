#!/bin/bash
# Microbenchmark Suite for Hashing and RSA-PSS Signing
set -e

echo "Executing ACNS-DSIG performance benchmark suite..."
mvn test -Dtest=CryptoBenchmarkTest || true

#!/bin/bash
# Microbenchmark Suite for Hashing and RSA-PSS Signing
set -e

echo "Executing ACNS-DSIG performance benchmark suite..."
./mvnw test "-Dtest=HashBenchmarkTest,CryptoBenchmarkTest" "-Dsurefire.failIfNoSpecifiedTests=false"

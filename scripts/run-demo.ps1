# PowerShell End-to-end Demonstration Script for ACNS-DSIG
$ErrorActionPreference = "Stop"

Write-Host "=== ACNS-DSIG DEMONSTRATION SUITE (Windows PowerShell) ==="
$cliJar = "dsig-cli/target/dsig-cli-1.0.0-SNAPSHOT.jar"

if (-not (Test-Path $cliJar)) {
    Write-Host "CLI Jar not found at $cliJar. Please compile with ./mvnw package first."
    exit 1
}

Write-Host "1. Generating Alice's RSA-3072 Key Pair..."
java -jar $cliJar keygen -o test-data/alice_key -p secret123

Write-Host "2. Verifying Contract..."
java -jar $cliJar verify test-data/contract.txt --trust-store test-data/trusted.json

# PowerShell End-to-end Demonstration Script for ACNS-DSIG
$ErrorActionPreference = "Stop"

Write-Host "=== ACNS-DSIG DEMONSTRATION SUITE (Windows PowerShell) ==="
$cliJar = "dsig-cli/target/dsig-cli-1.0.0-SNAPSHOT.jar"

if (-not (Test-Path $cliJar)) {
    Write-Host "CLI Jar not found at $cliJar. Compiling with Maven..."
    & .\mvnw.cmd package -DskipTests
}

# Create isolated demo workspace directory
$demoDir = "runtime/demo-temp"
if (-not (Test-Path $demoDir)) {
    New-Item -ItemType Directory -Path $demoDir -Force | Out-Null
}

$demoDoc = "$demoDir/demo_contract.txt"
$aliceKey = "$demoDir/alice_key"
$alicePub = "$demoDir/alice_key.pub.pem"
$alicePk8 = "$demoDir/alice_key.pk8"
$trustStore = "$demoDir/trusted.json"
$envelope = "$demoDir/demo_contract.txt.dsig.json"

try {
    # Prepare sample demo document
    Copy-Item "test-data/contract.txt" $demoDoc -Force

    Write-Host "`n1. Generating Alice's RSA-3072 Key Pair..."
    java -jar $cliJar keygen -o $aliceKey -p secret123

    Write-Host "`n2. Calculating Alice's Key Fingerprint..."
    $fpOutput = java -jar $cliJar fingerprint $alicePub
    $aliceFp = ""
    foreach ($line in ($fpOutput -split "`r?`n")) {
        if ($line -match "Hex Fingerprint\s*:\s*([a-fA-F0-9]{64})") {
            $aliceFp = $Matches[1].Trim()
            break
        }
    }
    Write-Host "Alice Fingerprint: $aliceFp"

    Write-Host "`n3. Pinning Alice's Key in Local Trust Store..."
    java -jar $cliJar trust-add $aliceFp -l "Alice Corporate" --trust-store $trustStore

    Write-Host "`n4. Alice Signs Contract..."
    java -jar $cliJar sign $demoDoc -k $alicePk8 --pub $alicePub -p secret123 -s "Alice Corporate" -o $envelope

    Write-Host "`n5. Verifying Legitimate Document (Expect VALID_TRUSTED)..."
    java -jar $cliJar verify $demoDoc -e $envelope --trust-store $trustStore

    Write-Host "`n6. Tampering Contract to Demonstrate Integrity Protection..."
    Add-Content -Path $demoDoc -Value "`n[Unauthorized clause appended by attacker]"
    Write-Host "Verifying Tampered Document (Expect DOCUMENT_TAMPERED with exit code 1)..."
    try {
        java -jar $cliJar verify $demoDoc -e $envelope --trust-store $trustStore
    } catch {
        Write-Host "Tampered document verification failed as expected."
    }

    Write-Host "`n=== Demo Run Complete ==="
} finally {
    # Clean up generated demo keys and artifacts to avoid sensitive leakage
    Write-Host "Cleaning up demo artifacts from $demoDir..."
    Remove-Item -Path $demoDir -Recurse -Force -ErrorAction SilentlyContinue
}

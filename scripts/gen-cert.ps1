# PowerShell script to generate self-signed TLS 1.3 PKCS#12 certificate
$ErrorActionPreference = "Stop"

if (-not (Test-Path -Path "runtime/tls")) {
    New-Item -ItemType Directory -Path "runtime/tls" -Force | Out-Null
}

Write-Host "Generating self-signed PKCS#12 TLS keystore in runtime/tls/keystore.p12..."

keytool -genkeypair `
  -alias dsig-server `
  -keyalg RSA `
  -keysize 3072 `
  -storetype PKCS12 `
  -keystore runtime/tls/keystore.p12 `
  -validity 365 `
  -storepass changeit `
  -keypass changeit `
  -dname "CN=localhost, OU=ACNS, O=DSIG, L=Vadodara, ST=Gujarat, C=IN"

Write-Host "Keystore created successfully."

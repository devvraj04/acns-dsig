# PowerShell microbenchmark runner
$ErrorActionPreference = "Stop"

Write-Host "Executing ACNS-DSIG performance benchmark suite..."
& .\mvnw.cmd test "-Dtest=HashBenchmarkTest,CryptoBenchmarkTest" "-Dsurefire.failIfNoSpecifiedTests=false"

# PowerShell fuzz testing runner
$ErrorActionPreference = "Stop"

Write-Host "Running ACNS-DSIG fuzz testing against envelope parser..."
& .\mvnw.cmd test "-Dtest=EnvelopeFuzzTest" "-Dsurefire.failIfNoSpecifiedTests=false"

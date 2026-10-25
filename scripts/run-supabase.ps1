# PowerShell Runner for ACNS-DSIG with Supabase (.env)
$ErrorActionPreference = "Stop"

# Auto-detect and set JAVA_HOME if missing in current process
if (-not $env:JAVA_HOME -or -not (Test-Path $env:JAVA_HOME)) {
    $knownJdk = "C:\Program Files\Microsoft\jdk-21.0.12.101-hotspot"
    if (Test-Path $knownJdk) {
        $env:JAVA_HOME = $knownJdk
        $env:Path = "$knownJdk\bin;$env:Path"
    }
}

$envFile = Join-Path $PSScriptRoot "..\.env"
if (-not (Test-Path $envFile)) {
    Write-Error "ERROR: .env file not found at $envFile. Please configure your .env file."
    exit 1
}

Write-Host "Loading environment variables from .env..." -ForegroundColor Cyan
Get-Content $envFile | ForEach-Object {
    $line = $_.Trim()
    if ($line -and (-not $line.StartsWith("#")) -and ($line -match "^([^=]+)=(.*)$")) {
        $key = $Matches[1].Trim()
        $val = $Matches[2].Trim()
        [System.Environment]::SetEnvironmentVariable($key, $val, [System.EnvironmentVariableTarget]::Process)
    }
}

Write-Host "Using JAVA_HOME: $env:JAVA_HOME" -ForegroundColor DarkCyan
Write-Host "Starting ACNS-DSIG Server with Supabase profile..." -ForegroundColor Green
$env:SPRING_PROFILES_ACTIVE = "supabase"
& .\mvnw.cmd spring-boot:run -pl dsig-server -am "-Dspring-boot.run.profiles=supabase"

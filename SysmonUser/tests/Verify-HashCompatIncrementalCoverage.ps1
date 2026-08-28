param()

$ErrorActionPreference = "Stop"

$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$testScript = Join-Path $scriptDir "Invoke-HashCompatVectorTest.ps1"

$output = & cmd /c "powershell -ExecutionPolicy Bypass -File `"$testScript`" 2>&1"
$exitCode = $LASTEXITCODE
$outputText = ($output | Out-String)

if ($exitCode -ne 0) {
    throw "Invoke-HashCompatVectorTest.ps1 failed with exit code $exitCode.`n$outputText"
}

if ($outputText -notmatch "incremental MD5" -or
    $outputText -notmatch "incremental SHA1" -or
    $outputText -notmatch "incremental SHA256") {
    Write-Host "Incremental hash-state coverage is missing from Invoke-HashCompatVectorTest.ps1 output." -ForegroundColor Red
    exit 1
}

Write-Host "OK: incremental hash-state coverage is present" -ForegroundColor Green

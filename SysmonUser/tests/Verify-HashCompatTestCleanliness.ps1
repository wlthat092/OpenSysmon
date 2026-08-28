param()

$ErrorActionPreference = "Stop"

$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$repoRoot = Split-Path (Split-Path $scriptDir -Parent) -Parent
$testScript = Join-Path $scriptDir "Invoke-HashCompatVectorTest.ps1"

$forbiddenPaths = @(
    (Join-Path $repoRoot "hash_compat.obj"),
    (Join-Path $repoRoot "hash_compat_vectors.obj"),
    (Join-Path $repoRoot "symcrypt_backend.obj"),
    (Join-Path $scriptDir "bin")
)

foreach ($path in $forbiddenPaths) {
    if (Test-Path $path) {
        Remove-Item -LiteralPath $path -Recurse -Force
    }
}

$output = & cmd /c "powershell -ExecutionPolicy Bypass -File `"$testScript`" 2>&1"
if ($LASTEXITCODE -ne 0) {
    throw "Invoke-HashCompatVectorTest.ps1 failed with exit code $LASTEXITCODE.`n$($output | Out-String)"
}

$createdPaths = @()
foreach ($path in $forbiddenPaths) {
    if (Test-Path $path) {
        $createdPaths += $path
    }
}

if ($createdPaths.Count -ne 0) {
    Write-Host "Hash compat test created workspace artifacts:" -ForegroundColor Red
    foreach ($path in $createdPaths) {
        Write-Host "  $path" -ForegroundColor Red
    }
    exit 1
}

Write-Host "OK: hash compat test left no workspace artifacts" -ForegroundColor Green

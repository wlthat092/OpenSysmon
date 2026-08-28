param(
    [ValidateSet("Debug", "Release")]
    [string]$Configuration = "Debug"
)

$ErrorActionPreference = "Stop"

$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$repoRoot = Split-Path (Split-Path $scriptDir -Parent) -Parent
$buildScript = Join-Path $repoRoot "SysmonUser\build.ps1"

$output = & cmd /c "powershell -ExecutionPolicy Bypass -File `"$buildScript`" -Configuration $Configuration 2>&1"
$exitCode = $LASTEXITCODE
$outputText = ($output | Out-String)

if ($exitCode -ne 0) {
    throw "SysmonUser build failed for $Configuration.`n$outputText"
}

$forbiddenWarnings = @(
    "LNK4098",
    "LNK4075"
)

$foundWarnings = @()
foreach ($warning in $forbiddenWarnings) {
    if ($outputText -match [regex]::Escape($warning)) {
        $foundWarnings += $warning
    }
}

if ($foundWarnings.Count -ne 0) {
    Write-Host "Forbidden build warnings found for ${Configuration}:" -ForegroundColor Red
    foreach ($warning in $foundWarnings) {
        Write-Host "  $warning" -ForegroundColor Red
    }
    exit 1
}

Write-Host "OK: $Configuration build has no forbidden linker warnings" -ForegroundColor Green

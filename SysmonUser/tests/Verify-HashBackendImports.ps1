param(
    [ValidateSet("Debug", "Release")]
    [string]$Configuration = "Release"
)

$ErrorActionPreference = "Stop"

function Find-VsTool {
    param(
        [Parameter(Mandatory = $true)]
        [string]$ToolName
    )

    $vswherePath = "${env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer\vswhere.exe"
    if (-not (Test-Path $vswherePath)) {
        throw "vswhere.exe not found."
    }

    $vsInstallPath = & $vswherePath -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath 2>$null
    if (-not $vsInstallPath) {
        throw "Visual Studio C++ tools not found."
    }

    $toolsRoot = Join-Path $vsInstallPath "VC\Tools\MSVC"
    $toolPath = Get-ChildItem -Path $toolsRoot -Directory |
        Sort-Object { [version]$_.Name } -Descending |
        ForEach-Object { Join-Path $_.FullName "bin\Hostx64\x64\$ToolName" } |
        Where-Object { Test-Path $_ } |
        Select-Object -First 1

    if (-not $toolPath) {
        throw "$ToolName not found under $toolsRoot."
    }

    return $toolPath
}

$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$projectDir = Split-Path $scriptDir -Parent
$binaryPath = Join-Path $projectDir "x64\$Configuration\Sysmon.exe"

if (-not (Test-Path $binaryPath)) {
    throw "Binary not found: $binaryPath"
}

$dumpbin = Find-VsTool -ToolName "dumpbin.exe"
$imports = & $dumpbin /imports $binaryPath 2>&1
if ($LASTEXITCODE -ne 0) {
    throw "dumpbin failed with exit code $LASTEXITCODE"
}

$forbiddenImports = @(
    "BCryptOpenAlgorithmProvider",
    "BCryptGetProperty",
    "BCryptCreateHash",
    "BCryptHashData",
    "BCryptFinishHash",
    "BCryptDestroyHash"
)

$found = @()
foreach ($name in $forbiddenImports) {
    if ($imports -match [regex]::Escape($name)) {
        $found += $name
    }
}

if ($found.Count -ne 0) {
    Write-Host "Forbidden CNG hash imports are still present in ${binaryPath}:" -ForegroundColor Red
    foreach ($name in $found) {
        Write-Host "  $name" -ForegroundColor Red
    }
    exit 1
}

Write-Host "OK: no forbidden CNG hash imports found in $binaryPath" -ForegroundColor Green

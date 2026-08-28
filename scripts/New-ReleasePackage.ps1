#requires -Version 5.1

[CmdletBinding()]
param(
    [string]$Version = 'local',
    [string]$OutputDirectory = '',
    [string]$UserBinaryPath = '',
    [string]$DriverBinaryPath = ''
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
if (-not $OutputDirectory) { $OutputDirectory = Join-Path $repoRoot 'dist' }
if (-not $UserBinaryPath) { $UserBinaryPath = Join-Path $repoRoot 'SysmonUser\x64\Release\Sysmon.exe' }
if (-not $DriverBinaryPath) { $DriverBinaryPath = Join-Path $repoRoot 'SysmonDrv\x64\Release\SysmonDrv.sys' }

foreach ($path in @($UserBinaryPath, $DriverBinaryPath, (Join-Path $repoRoot 'sysmon_config.xml'))) {
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) { throw "Release input not found: $path" }
}

$safeVersion = $Version -replace '[^A-Za-z0-9._-]', '-'
$stageParent = Join-Path ([IO.Path]::GetTempPath()) ("opensysmon-package-{0}" -f ([guid]::NewGuid().ToString('N')))
$stageRoot = Join-Path $stageParent ("OpenSysmon-{0}" -f $safeVersion)
$zipPath = Join-Path $OutputDirectory ("OpenSysmon-{0}.zip" -f $safeVersion)

try {
    New-Item -ItemType Directory -Path $stageRoot -Force | Out-Null
    New-Item -ItemType Directory -Path $OutputDirectory -Force | Out-Null
    Copy-Item -LiteralPath $UserBinaryPath -Destination (Join-Path $stageRoot 'Sysmon.exe')
    Copy-Item -LiteralPath $DriverBinaryPath -Destination (Join-Path $stageRoot 'SysmonDrv.sys')
    Copy-Item -LiteralPath (Join-Path $repoRoot 'sysmon_config.xml') -Destination (Join-Path $stageRoot 'sysmon_config.xml')
    Copy-Item -LiteralPath (Join-Path $repoRoot 'install.ps1') -Destination (Join-Path $stageRoot 'install.ps1')
    Copy-Item -LiteralPath (Join-Path $repoRoot 'uninstall.ps1') -Destination (Join-Path $stageRoot 'uninstall.ps1')
    Compress-Archive -Path $stageRoot -DestinationPath $zipPath -Force
    Write-Host "Release package: $zipPath" -ForegroundColor Green
} finally {
    if (Test-Path -LiteralPath $stageParent) { Remove-Item -LiteralPath $stageParent -Recurse -Force -ErrorAction SilentlyContinue }
}

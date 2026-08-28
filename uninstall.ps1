#requires -Version 5.1

[CmdletBinding()]
param([switch]$KeepData)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = New-Object Security.Principal.WindowsPrincipal($identity)
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'Administrator privileges are required. Re-open PowerShell as Administrator and run uninstall.ps1 again.'
}

$systemRoot = $env:SystemRoot
$sysmonPath = Join-Path $systemRoot 'System32\Sysmon.exe'
$driverPath = Join-Path $systemRoot 'System32\drivers\SysmonDrv.sys'
$dataRoot = Join-Path $env:ProgramData 'OpenSysmon'

if (Test-Path -LiteralPath $sysmonPath -PathType Leaf) {
    & $sysmonPath -u force
    if ($LASTEXITCODE -ne 0) {
        throw "OpenSysmon uninstall failed with exit code $LASTEXITCODE"
    }
} else {
    Write-Host 'Sysmon.exe is not installed; removing any remaining driver service.' -ForegroundColor Yellow
    & sc.exe stop SysmonDrv 2>$null | Out-Null
    & sc.exe delete SysmonDrv 2>$null | Out-Null
}

if (Test-Path -LiteralPath $sysmonPath) { Remove-Item -LiteralPath $sysmonPath -Force -ErrorAction SilentlyContinue }
if (Test-Path -LiteralPath $driverPath) { Remove-Item -LiteralPath $driverPath -Force -ErrorAction SilentlyContinue }
if (-not $KeepData -and (Test-Path -LiteralPath $dataRoot)) {
    Remove-Item -LiteralPath $dataRoot -Recurse -Force
}

Write-Host 'OpenSysmon has been uninstalled.' -ForegroundColor Green

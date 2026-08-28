<#
.SYNOPSIS
Runs copied Sysmon event tests on the target VM and restores the main configuration.
#>
[CmdletBinding()]
param(
    [string]$TestRoot = $PSScriptRoot,
    [int[]]$EventIds
)

$ErrorActionPreference = 'Stop'
$toolRoot = Join-Path $TestRoot 'tools'
$MainConfigPath = Join-Path $toolRoot 'sysmon_config.xml'
$SysmonExe = Join-Path $toolRoot 'Sysmon.exe'
if (-not (Test-Path -LiteralPath $SysmonExe)) { $SysmonExe = Join-Path $toolRoot 'Sysmon.cmd' }
$SimulatorPath = Join-Path $toolRoot 'SysmonSimulator.exe'
$manifestPath = Join-Path $TestRoot 'shared\EventCases.psd1'
foreach ($requiredPath in @($SysmonExe, $SimulatorPath, $MainConfigPath, $manifestPath)) {
    if (-not (Test-Path -LiteralPath $requiredPath -PathType Leaf)) {
        throw "Required file is missing: $requiredPath"
    }
}

$manifest = Import-PowerShellDataFile -LiteralPath $manifestPath
$supportedIds = @($manifest.Keys | ForEach-Object { [int]$_ } | Sort-Object)
$selectedIds = if ($EventIds -and $EventIds.Count) {
    @($EventIds | Sort-Object -Unique)
}
else {
    $supportedIds
}

$unsupportedIds = @($selectedIds | Where-Object { $_ -notin $supportedIds })
if ($unsupportedIds.Count) { throw "Unsupported Event IDs: $($unsupportedIds -join ', ')" }

foreach ($id in $selectedIds) {
    $eventRoot = Join-Path $TestRoot ('event-{0:D2}' -f $id)
    foreach ($requiredPath in @((Join-Path $eventRoot 'test.ps1'), (Join-Path $eventRoot 'config.xml'))) {
        if (-not (Test-Path -LiteralPath $requiredPath -PathType Leaf)) {
            throw "Required event asset is missing: $requiredPath"
        }
    }
}

foreach ($serviceName in @('Sysmon','SysmonDrv')) {
    $service = Get-Service -Name $serviceName 2>$null
    if (-not $service -or [string]$service.Status -ne 'Running') {
        throw "$serviceName service must be Running"
    }
}

$summary = [System.Collections.Generic.List[object]]::new()
$failed = $false
try {
    foreach ($id in $selectedIds) {
        $wrapperPath = Join-Path $TestRoot ('event-{0:D2}\test.ps1' -f $id)
        $wrapperOutput = @(
            & powershell -NoProfile -NonInteractive -ExecutionPolicy Bypass -File $wrapperPath `
                -SysmonExe $SysmonExe -SimulatorPath $SimulatorPath 2>&1
        )
        $wrapperExitCode = $LASTEXITCODE
        $outputLines = @($wrapperOutput | ForEach-Object { [string]$_ })
        Write-Output $outputLines

        $jsonLine = @($outputLines | ForEach-Object { $_.Trim() } | Where-Object { $_.StartsWith('{') }) | Select-Object -Last 1
        $payload = $null
        $resultError = $null
        if (-not $jsonLine) {
            $resultError = 'Wrapper did not return a JSON result'
        }
        else {
            try { $payload = $jsonLine | ConvertFrom-Json -ErrorAction Stop }
            catch { $resultError = "Wrapper returned invalid JSON: $($_.Exception.Message)" }
        }

        $found = $payload -and [bool]$payload.found
        if ($wrapperExitCode -ne 0 -or -not $found -or $resultError) { $failed = $true }
        if (-not $resultError -and $payload -and $payload.error) { $resultError = [string]$payload.error }
        $summary.Add([pscustomobject]@{
            EventId = $id
            Found = $found
            ExitCode = $wrapperExitCode
            Error = $resultError
        })
    }
}
catch {
    $failed = $true
    $summary.Add([pscustomobject]@{
        EventId = $null
        Found = $false
        ExitCode = 1
        Error = $_.Exception.Message
    })
}
finally {
    try {
        & $SysmonExe -c $MainConfigPath *> $null
        if ($LASTEXITCODE -ne 0) { throw "Main configuration restore failed: $LASTEXITCODE" }
    }
    catch {
        $failed = $true
        $summary.Add([pscustomobject]@{
            EventId = $null
            Found = $false
            ExitCode = 1
            Error = $_.Exception.Message
        })
    }
}

if ($summary.Count) {
    Write-Output ($summary | Format-Table EventId,Found,ExitCode,Error -AutoSize | Out-String)
}
if ($failed) { exit 1 }
exit 0

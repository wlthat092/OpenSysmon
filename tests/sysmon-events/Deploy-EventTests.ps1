<#
.SYNOPSIS
Uploads the Sysmon event suite and runs it on the target VM.

.EXAMPLE
powershell -NoProfile -ExecutionPolicy Bypass -File .\tests\sysmon-events\Deploy-EventTests.ps1 -Target user@host

.EXAMPLE
powershell -NoProfile -ExecutionPolicy Bypass -File .\tests\sysmon-events\Deploy-EventTests.ps1 -Target user@host -EventIds 22
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][ValidateNotNullOrEmpty()][string]$Target,
    [string]$RemoteRoot = 'C:\ProgramData\OpenSysmon\tests',
    [int[]]$EventIds
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function ConvertTo-PowerShellLiteral {
    param([Parameter(Mandatory = $true)][string]$Value)
    return "'" + $Value.Replace("'", "''") + "'"
}

function ConvertTo-EncodedCommand {
    param([Parameter(Mandatory = $true)][string]$Script)
    return [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($Script))
}

function ConvertTo-ScpPath {
    param([Parameter(Mandatory = $true)][string]$Path)
    if ($Path -notmatch '^([A-Za-z]):[\\/](.*)$') { throw "RemoteRoot must be an absolute Windows path: $Path" }
    return '/' + $matches[1].ToUpperInvariant() + ':/' + $matches[2].Replace('\','/').TrimEnd('/')
}

$resolvedLocalRoot = (Resolve-Path -LiteralPath $PSScriptRoot -ErrorAction Stop).Path
$repositoryRoot = Split-Path -Parent (Split-Path -Parent $resolvedLocalRoot)
$mainConfigSourcePath = Join-Path $repositoryRoot 'sysmon_config.xml'
$sysmonSourcePath = Join-Path $repositoryRoot 'SysmonUser\x64\Release\Sysmon.exe'
if (-not (Test-Path -LiteralPath $sysmonSourcePath -PathType Leaf)) { $sysmonSourcePath = Join-Path $repositoryRoot 'SysmonUser\x64\Debug\Sysmon.exe' }
$simulatorSourcePath = Join-Path $resolvedLocalRoot 'tools\SysmonSimulator.exe'
$mainConfigPath = Join-Path $RemoteRoot 'tools\sysmon_config.xml'

$validatorPath = Join-Path $resolvedLocalRoot 'Test-EventTestAssets.ps1'
$manifestPath = Join-Path $resolvedLocalRoot 'shared\EventCases.psd1'
foreach ($requiredPath in @($validatorPath, $manifestPath, (Join-Path $resolvedLocalRoot 'Run-All.ps1'), (Join-Path $resolvedLocalRoot 'Deploy-EventTests.ps1'))) {
    if (-not (Test-Path -LiteralPath $requiredPath -PathType Leaf)) { throw "Required local suite file is missing: $requiredPath" }
}
foreach ($sourcePath in @($mainConfigSourcePath, $sysmonSourcePath, $simulatorSourcePath)) {
    if (-not (Test-Path -LiteralPath $sourcePath -PathType Leaf)) { throw "Required local tool is missing: $sourcePath" }
}

$validationOutput = & powershell -NoProfile -NonInteractive -ExecutionPolicy Bypass -File $validatorPath -Root $resolvedLocalRoot 2>&1
$validationExitCode = $LASTEXITCODE
Write-Output $validationOutput
if ($validationExitCode -ne 0) { throw "Event test asset validation failed with exit code $validationExitCode" }

$manifest = Import-PowerShellDataFile -LiteralPath $manifestPath
$supportedIds = @($manifest.Keys | ForEach-Object { [int]$_ } | Sort-Object)
$selectedIds = if ($EventIds -and $EventIds.Count) { @($EventIds | Sort-Object -Unique) } else { $supportedIds }
$unsupportedIds = @($selectedIds | Where-Object { $_ -notin $supportedIds })
if ($unsupportedIds.Count) { throw "Unsupported Event IDs: $($unsupportedIds -join ', ')" }

$copySources = @(Get-ChildItem -LiteralPath $resolvedLocalRoot -Force | ForEach-Object { $_.FullName })

$mainConfigParent = Split-Path -Parent $mainConfigPath
$createScript = '[System.IO.Directory]::CreateDirectory(' + (ConvertTo-PowerShellLiteral $RemoteRoot) + ') | Out-Null; ' +
    '[System.IO.Directory]::CreateDirectory(' + (ConvertTo-PowerShellLiteral $mainConfigParent) + ') | Out-Null'
$encodedCreate = ConvertTo-EncodedCommand $createScript
& ssh -o BatchMode=yes -o ConnectTimeout=15 $Target "powershell -NoProfile -NonInteractive -ExecutionPolicy Bypass -EncodedCommand $encodedCreate"
if ($LASTEXITCODE -ne 0) { throw "Failed to create remote event-test directory: $LASTEXITCODE" }

$remoteScpRoot = ConvertTo-ScpPath $RemoteRoot
& scp -r -o BatchMode=yes -o ConnectTimeout=15 @copySources "$Target`:$remoteScpRoot/"
if ($LASTEXITCODE -ne 0) { throw "Failed to upload event-test assets: $LASTEXITCODE" }
& scp -o BatchMode=yes -o ConnectTimeout=15 $sysmonSourcePath "$Target`:$remoteScpRoot/tools/Sysmon.exe"
if ($LASTEXITCODE -ne 0) { throw "Failed to upload Sysmon executable: $LASTEXITCODE" }
& scp -o BatchMode=yes -o ConnectTimeout=15 $simulatorSourcePath "$Target`:$remoteScpRoot/tools/SysmonSimulator.exe"
if ($LASTEXITCODE -ne 0) { throw "Failed to upload simulator executable: $LASTEXITCODE" }
$resolvedMainConfigSource = (Resolve-Path -LiteralPath $mainConfigSourcePath -ErrorAction Stop).Path
$mainConfigScpPath = ConvertTo-ScpPath $mainConfigPath
& scp -o BatchMode=yes -o ConnectTimeout=15 $resolvedMainConfigSource "$Target`:$mainConfigScpPath"
if ($LASTEXITCODE -ne 0) { throw "Failed to upload main configuration: $LASTEXITCODE" }

$remoteRunAll = Join-Path $RemoteRoot 'Run-All.ps1'
$eventClause = if ($EventIds -and $EventIds.Count) { ' -EventIds ' + ($selectedIds -join ',') } else { '' }
$runScript = '& ' + (ConvertTo-PowerShellLiteral $remoteRunAll) +
    ' -TestRoot ' + (ConvertTo-PowerShellLiteral $RemoteRoot) +
    '' +
    $eventClause + "`nexit `$LASTEXITCODE"
$encodedRun = ConvertTo-EncodedCommand $runScript
& ssh -o BatchMode=yes -o ConnectTimeout=15 $Target "powershell -NoProfile -NonInteractive -ExecutionPolicy Bypass -EncodedCommand $encodedRun"
if ($LASTEXITCODE -ne 0) { throw "Remote event tests failed with exit code $LASTEXITCODE" }

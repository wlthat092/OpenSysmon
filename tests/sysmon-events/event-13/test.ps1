param(
    [Parameter(Mandatory = $true)][ValidateNotNullOrEmpty()][string]$SysmonExe,
    [Parameter(Mandatory = $true)][ValidateNotNullOrEmpty()][string]$SimulatorPath,
    [int]$TimeoutSeconds = 20
)

$caseTable = Import-PowerShellDataFile (Join-Path $PSScriptRoot '..\shared\EventCases.psd1')
. (Join-Path $PSScriptRoot '..\shared\Invoke-EventTest.ps1')
$case = $caseTable[13]
$result = Invoke-EventTest -EventId 13 -ConfigPath (Join-Path $PSScriptRoot 'config.xml') `
    -SysmonExe $SysmonExe -SimulatorPath $SimulatorPath `
    -RequiredFields $case.RequiredFields -TimeoutSeconds ([int]$TimeoutSeconds)
Write-Output $result.Json
exit ([int]$result.ExitCode)

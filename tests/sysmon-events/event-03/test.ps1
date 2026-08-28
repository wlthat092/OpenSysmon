param(
    [Parameter(Mandatory = $true)][ValidateNotNullOrEmpty()][string]$SysmonExe,
    [Parameter(Mandatory = $true)][ValidateNotNullOrEmpty()][string]$SimulatorPath,
    [int]$TimeoutSeconds = 20
)

$caseTable = Import-PowerShellDataFile (Join-Path $PSScriptRoot '..\shared\EventCases.psd1')
. (Join-Path $PSScriptRoot '..\shared\Invoke-EventTest.ps1')
$case = $caseTable[3]
$result = Invoke-EventTest -EventId 3 -ConfigPath (Join-Path $PSScriptRoot 'config.xml') `
    -SysmonExe $SysmonExe -SimulatorPath $SimulatorPath `
    -RequiredFields $case.RequiredFields -NotPlaceholderFields $case.NotPlaceholderFields -ExpectedCount $(if ($case.ContainsKey('ExpectedCount')) { [int]$case.ExpectedCount } else { 0 }) -TimeoutSeconds ([int]$TimeoutSeconds)
Write-Output $result.Json
exit ([int]$result.ExitCode)

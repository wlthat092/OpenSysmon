param(
    [string]$ProviderName = 'Microsoft-Windows-Sysmon',
    [string]$ProviderGuid = '{5770385F-C22A-43E0-BF4C-06F5698FFBD9}',
    [string]$SysmonExePath = (Join-Path $env:SystemRoot 'System32\Sysmon.exe'),
    [string]$DriverPath = (Join-Path $env:SystemRoot 'System32\drivers\SysmonDrv.sys')
)

$ErrorActionPreference = 'Continue'

function Write-Section {
    param([string]$Title)
    Write-Host ''
    Write-Host ('=== ' + $Title + ' ===')
}

Write-Section 'System32 files'
Get-Item $SysmonExePath, $DriverPath -ErrorAction SilentlyContinue |
    Select-Object FullName, Length, LastWriteTimeUtc |
    Format-Table -AutoSize

Write-Section 'Publisher registry'
$publisherKey = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Publishers\$ProviderGuid"
if (Test-Path $publisherKey) {
    Get-ItemProperty $publisherKey |
        Select-Object ResourceFileName, MessageFileName, ParameterFileName, Enabled, OwningPublisher |
        Format-List
} else {
    Write-Host "Publisher key missing: $publisherKey"
}

Write-Section 'Provider metadata'
try {
    Get-WinEvent -ListProvider $ProviderName | Select-Object Name, Guid, LogLinks, Events |
        Format-List
} catch {
    Write-Host $_
}

Write-Section 'wevtutil provider'
wevtutil gp $ProviderName /ge:true

Write-Section 'Recent Sysmon events'
try {
    Get-WinEvent -LogName 'Microsoft-Windows-Sysmon/Operational' -MaxEvents 3 |
        Select-Object TimeCreated, Id, ProviderName, LevelDisplayName, Message |
        Format-List
} catch {
    Write-Host $_
}

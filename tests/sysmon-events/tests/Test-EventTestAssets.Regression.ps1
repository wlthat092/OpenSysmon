[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
$suiteRoot = Split-Path -Parent $PSScriptRoot
$validatorPath = Join-Path $suiteRoot 'Test-EventTestAssets.ps1'
$root = Join-Path ([System.IO.Path]::GetTempPath()) ('sysmon-event-assets-' + [guid]::NewGuid())

try {
    [System.IO.Directory]::CreateDirectory((Join-Path $root 'shared')) | Out-Null
    Copy-Item (Join-Path $suiteRoot 'shared\EventCases.psd1') (Join-Path $root 'shared\EventCases.psd1')
    $cases = Import-PowerShellDataFile (Join-Path $root 'shared\EventCases.psd1')
    foreach ($id in $cases.Keys) {
        $dir = Join-Path $root ('event-{0:D2}' -f [int]$id)
        [System.IO.Directory]::CreateDirectory($dir) | Out-Null
        $node = $cases[$id].Node
        $matchType = if ([int]$id -eq 22) { 'exclude' } else { 'include' }
        [System.IO.File]::WriteAllText((Join-Path $dir 'config.xml'), "<Sysmon><EventFiltering><RuleGroup name=`"test`" groupRelation=`"or`"><$node onmatch=`"$matchType`" /></RuleGroup></EventFiltering></Sysmon>")
        [System.IO.File]::WriteAllText((Join-Path $dir 'test.ps1'), "Invoke-EventTest -EventId $id")
    }

    $validOutput = & powershell -NoProfile -ExecutionPolicy Bypass -File $validatorPath -Root $root 2>&1 | Out-String
    if ($LASTEXITCODE -ne 0) { throw "Validator rejected valid fixtures: $validOutput" }
    if ($validOutput -notmatch 'Event test assets valid: 23 event cases') { throw "Validator returned unexpected success output: $validOutput" }
    Write-Output 'PASS: valid fixtures were accepted.'

    $invalidWrappers = @{
        'comment-hidden-dynamic-id' = @{ Text = "# Invoke-EventTest -EventId 1`nInvoke-EventTest -EventId `$dynamicEventId"; Expected = 'event-01: Invoke-EventTest -EventId must be integer literal 1' }
        'missing-invocation' = @{ Text = 'Write-Output 1'; Expected = 'event-01: test.ps1 must contain exactly one Invoke-EventTest command' }
        'conflicting-invocations' = @{ Text = "Invoke-EventTest -EventId 1`nInvoke-EventTest -EventId 2"; Expected = 'event-01: test.ps1 must contain exactly one Invoke-EventTest command' }
        'uncalled-function' = @{ Text = "function NeverCalled { Invoke-EventTest -EventId 1 }`nWrite-Output 'no invocation'"; Expected = 'event-01: Invoke-EventTest must be a top-level command' }
        'false-branch' = @{ Text = "if (`$false) { Invoke-EventTest -EventId 1 }`nWrite-Output 'no invocation'"; Expected = 'event-01: Invoke-EventTest must be a top-level command' }
        'shadowed-helper' = @{ Text = "function Invoke-EventTest { param([int]`$EventId) Write-Output `$EventId }`nInvoke-EventTest -EventId 1"; Expected = 'event-01: test.ps1 must not define Invoke-EventTest' }
    }
    foreach ($name in $invalidWrappers.Keys) {
        [System.IO.File]::WriteAllText((Join-Path $root 'event-01\test.ps1'), $invalidWrappers[$name].Text)
        $previousPreference = $ErrorActionPreference
        $ErrorActionPreference = 'Continue'
        $output = & powershell -NoProfile -ExecutionPolicy Bypass -File $validatorPath -Root $root 2>&1 | Out-String
        $exitCode = $LASTEXITCODE
        $ErrorActionPreference = $previousPreference
        if ($exitCode -eq 0) { throw "Validator accepted malformed wrapper: $name" }
        if ($output -notmatch [regex]::Escape($invalidWrappers[$name].Expected)) { throw "Unexpected $name failure: $output" }
        Write-Output "PASS: $name was rejected."
    }

    [System.IO.File]::WriteAllText((Join-Path $root 'event-01\test.ps1'), 'Invoke-EventTest -EventId 1')
    [System.IO.File]::WriteAllText((Join-Path $root 'event-22\config.xml'), '<Sysmon><EventFiltering><RuleGroup groupRelation="or"><DnsQuery onmatch="include" /></RuleGroup></EventFiltering></Sysmon>')
    $previousPreference = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    $output = & powershell -NoProfile -ExecutionPolicy Bypass -File $validatorPath -Root $root 2>&1 | Out-String
    $exitCode = $LASTEXITCODE
    $ErrorActionPreference = $previousPreference
    if ($exitCode -eq 0) { throw 'Validator accepted Event 22 with empty include semantics' }
    if ($output -notmatch [regex]::Escape('event-22: config.xml DnsQuery onmatch must be exclude')) { throw "Unexpected Event 22 match failure: $output" }
    Write-Output 'PASS: Event 22 empty include was rejected.'
}
finally {
    if (Test-Path -LiteralPath $root) { [System.IO.Directory]::Delete($root, $true) }
}

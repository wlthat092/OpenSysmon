param(
    [string]$ConfigPath = (Join-Path (Split-Path $PSScriptRoot -Parent) 'sysmon_config.xml'),
    [string]$WorkRoot = (Join-Path $env:TEMP ('sysmon-fileblock-' + [guid]::NewGuid().ToString('N'))),
    [string]$ArchiveDirectory = 'Sysmon',
    [string]$PeSource = "$env:WINDIR\System32\notepad.exe",
    [string]$LogName = 'Microsoft-Windows-Sysmon/Operational',
    [string]$SysmonExePath = '',
    [ValidateSet('All', 'Block', 'DetectOnly')]
    [string]$Scenario = 'All'
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Assert-True {
    param(
        [Parameter(Mandatory = $true)]
        [bool]$Condition,
        [Parameter(Mandatory = $true)]
        [string]$Message
    )

    if (-not $Condition) {
        throw "FAIL: $Message"
    }
}

function Get-SysmonEventsSince {
    param(
        [Parameter(Mandatory = $true)]
        [datetime]$StartTimeUtc,
        [Parameter(Mandatory = $true)]
        [int[]]$Ids
    )

    try {
        $events = Get-WinEvent -FilterHashtable @{
            LogName   = $LogName
            StartTime = $StartTimeUtc.ToLocalTime()
            Id        = $Ids
        } -ErrorAction Stop
    }
    catch {
        if ($_.FullyQualifiedErrorId -like 'NoMatchingEventsFound*') {
            return @()
        }

        throw
    }

    if ($null -eq $events) {
        return @()
    }

    @($events)
}

function Get-EventDataMap {
    param(
        [Parameter(Mandatory = $true)]
        [System.Diagnostics.Eventing.Reader.EventRecord]$EventRecord
    )

    $map = @{}
    [xml]$xml = $EventRecord.ToXml()
    foreach ($node in @($xml.Event.EventData.Data)) {
        $name = [string]$node.Name
        if ($name) {
            $map[$name] = [string]$node.'#text'
        }
    }

    return $map
}

function Find-FirstEventForPath {
    param(
        [Parameter(Mandatory = $true)]
        [System.Collections.IEnumerable]$Events,
        [Parameter(Mandatory = $true)]
        [int]$Id,
        [Parameter(Mandatory = $true)]
        [string]$TargetPath
    )

    $normalizedTargetPath = Normalize-PathForComparison -Path $TargetPath
    foreach ($eventRecord in $Events) {
        if ($eventRecord.Id -ne $Id) {
            continue
        }

        $eventData = Get-EventDataMap -EventRecord $eventRecord
        if ($eventData.ContainsKey('TargetFilename') -and
            (Normalize-PathForComparison -Path $eventData['TargetFilename']) -eq $normalizedTargetPath) {
            return $eventRecord
        }
    }

    return $null
}

function Test-EventMatchesSample {
    param(
        [Parameter(Mandatory = $true)]
        [System.Diagnostics.Eventing.Reader.EventRecord]$EventRecord,
        [Parameter(Mandatory = $true)]
        [string]$TargetPath,
        [Parameter(Mandatory = $true)]
        [string]$ExpectedSha256
    )

    $eventData = Get-EventDataMap -EventRecord $EventRecord
    $normalizedTargetPath = Normalize-PathForComparison -Path $TargetPath

    if ($eventData.ContainsKey('TargetFilename') -and
        (Normalize-PathForComparison -Path $eventData['TargetFilename']) -eq $normalizedTargetPath) {
        return $true
    }

    if ($eventData.ContainsKey('Hashes')) {
        $hashes = $eventData['Hashes'].ToUpperInvariant()
        if ($hashes.Contains("SHA256=$($ExpectedSha256.ToUpperInvariant())")) {
            return $true
        }
    }

    return $false
}

function Find-FirstEventForSample {
    param(
        [Parameter(Mandatory = $true)]
        [System.Collections.IEnumerable]$Events,
        [Parameter(Mandatory = $true)]
        [int]$Id,
        [Parameter(Mandatory = $true)]
        [string]$TargetPath,
        [Parameter(Mandatory = $true)]
        [string]$ExpectedSha256
    )

    foreach ($eventRecord in $Events) {
        if ($eventRecord.Id -ne $Id) {
            continue
        }

        if (Test-EventMatchesSample -EventRecord $eventRecord -TargetPath $TargetPath -ExpectedSha256 $ExpectedSha256) {
            return $eventRecord
        }
    }

    return $null
}

function Test-AnyEventForSample {
    param(
        [Parameter(Mandatory = $true)]
        [System.Collections.IEnumerable]$Events,
        [Parameter(Mandatory = $true)]
        [int]$Id,
        [Parameter(Mandatory = $true)]
        [string]$TargetPath,
        [Parameter(Mandatory = $true)]
        [string]$ExpectedSha256
    )

    return ($null -ne (Find-FirstEventForSample -Events $Events -Id $Id -TargetPath $TargetPath -ExpectedSha256 $ExpectedSha256))
}

function Normalize-PathForComparison {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path
    )

    $normalized = $Path.Trim()
    if ($normalized.StartsWith('\\?\')) {
        $normalized = $normalized.Substring(4)
    }
    elseif ($normalized.StartsWith('\??\')) {
        $normalized = $normalized.Substring(4)
    }

    $normalized = $normalized.Replace('/', '\')

    try {
        $normalized = [System.IO.Path]::GetFullPath($normalized)
    }
    catch {
        # Preserve the original path string when the event path cannot be canonicalized.
    }

    return $normalized.TrimEnd('\').ToUpperInvariant()
}

function Find-ArchiveSampleMatch {
    param(
        [Parameter(Mandatory = $true)]
        [string]$ArchiveRoot,
        [Parameter(Mandatory = $true)]
        [datetime]$StartTimeUtc,
        [Parameter(Mandatory = $true)]
        [string]$ExpectedHash
    )

    if (-not (Test-Path -LiteralPath $ArchiveRoot)) {
        return $null
    }

    foreach ($candidate in (Get-ChildItem -LiteralPath $ArchiveRoot -File |
            Where-Object { $_.LastWriteTimeUtc -ge $StartTimeUtc })) {
        $candidateHash = (Get-FileHash -LiteralPath $candidate.FullName -Algorithm SHA256).Hash
        if ($candidateHash -eq $ExpectedHash) {
            return $candidate
        }
    }

    return $null
}

function Get-RegressionObservation {
    param(
        [Parameter(Mandatory = $true)]
        [datetime]$StartTimeUtc,
        [Parameter(Mandatory = $true)]
        [string]$BlockedExe,
        [Parameter(Mandatory = $true)]
        [string]$FakeExe,
        [Parameter(Mandatory = $true)]
        [string]$ArchiveRoot,
        [Parameter(Mandatory = $true)]
        [string]$ExpectedArchiveHash,
        [Parameter(Mandatory = $true)]
        [string]$ExpectedSampleSha256
    )

    $events = @(Get-SysmonEventsSince -StartTimeUtc $StartTimeUtc -Ids @(27, 29))

    [pscustomobject]@{
        BlockedExists = Test-Path -LiteralPath $BlockedExe
        FakeExists    = Test-Path -LiteralPath $FakeExe
        Event27       = Find-FirstEventForSample -Events $events -Id 27 -TargetPath $BlockedExe -ExpectedSha256 $ExpectedSampleSha256
        Event29Seen   = Test-AnyEventForSample -Events $events -Id 29 -TargetPath $BlockedExe -ExpectedSha256 $ExpectedSampleSha256
        ArchiveHit    = Find-ArchiveSampleMatch -ArchiveRoot $ArchiveRoot -StartTimeUtc $StartTimeUtc -ExpectedHash $ExpectedArchiveHash
    }
}

function Get-OptionalConfigText {
    param(
        [Parameter(Mandatory = $true)]
        [xml]$Config,
        [Parameter(Mandatory = $true)]
        [string]$XPath
    )

    $node = $Config.SelectSingleNode($XPath)
    if ($null -eq $node) {
        return $null
    }

    $value = [string]$node.InnerText
    if ([string]::IsNullOrWhiteSpace($value)) {
        return $null
    }

    return $value.Trim()
}

function Test-ConfigExpectsArchiveSample {
    param(
        [Parameter(Mandatory = $true)]
        [xml]$Config
    )

    $copyOnDeletePe = Get-OptionalConfigText -Config $Config -XPath '/Sysmon/CopyOnDeletePE'
    if (-not [string]::IsNullOrWhiteSpace($copyOnDeletePe)) {
        $enabled = $false
        if ([bool]::TryParse($copyOnDeletePe, [ref]$enabled) -and $enabled) {
            return $true
        }
    }

    foreach ($path in @(
            '/Sysmon/CopyOnDeleteSIDs',
            '/Sysmon/CopyOnDeleteExtensions',
            '/Sysmon/CopyOnDeleteProcesses')) {
        if (-not [string]::IsNullOrWhiteSpace((Get-OptionalConfigText -Config $Config -XPath $path))) {
            return $true
        }
    }

    return $false
}

function New-MinimalTestConfig {
    param(
        [Parameter(Mandatory = $true)]
        [xml]$SourceConfig,
        [Parameter(Mandatory = $true)]
        [string]$FallbackArchiveDirectory,
        [Parameter(Mandatory = $true)]
        [ValidateSet('Block', 'DetectOnly')]
        [string]$Scenario,
        [Parameter(Mandatory = $true)]
        [string]$DestinationPath
    )

    $minimalConfig = New-Object System.Xml.XmlDocument
    $declaration = $minimalConfig.CreateXmlDeclaration('1.0', 'utf-8', $null)
    [void]$minimalConfig.AppendChild($declaration)

    $sourceRoot = $SourceConfig.SelectSingleNode('/Sysmon')
    if ($null -eq $sourceRoot) {
        throw 'Missing Sysmon root element in source config'
    }

    $sysmonNode = $minimalConfig.CreateElement('Sysmon')
    $schemaVersion = $sourceRoot.GetAttribute('schemaversion')
    if ([string]::IsNullOrWhiteSpace($schemaVersion)) {
        throw 'Missing Sysmon schemaversion in source config'
    }
    [void]$sysmonNode.SetAttribute('schemaversion', $schemaVersion)
    [void]$minimalConfig.AppendChild($sysmonNode)

    foreach ($sourceNode in @($sourceRoot.ChildNodes)) {
        if ($sourceNode.NodeType -ne [System.Xml.XmlNodeType]::Element) {
            continue
        }

        if ($sourceNode.Name -eq 'EventFiltering') {
            continue
        }

        [void]$sysmonNode.AppendChild($minimalConfig.ImportNode($sourceNode, $true))
    }

    if ($null -eq $minimalConfig.SelectSingleNode('/Sysmon/ArchiveDirectory')) {
        $archiveDirectoryNode = $minimalConfig.CreateElement('ArchiveDirectory')
        $archiveDirectoryNode.InnerText = $FallbackArchiveDirectory
        [void]$sysmonNode.AppendChild($archiveDirectoryNode)
    }

    $eventFilteringNode = $minimalConfig.CreateElement('EventFiltering')
    [void]$sysmonNode.AppendChild($eventFilteringNode)

    $ruleNames = if ($Scenario -eq 'DetectOnly') {
        @('FileExecutableDetected')
    }
    else {
        @('FileBlockExecutable', 'FileExecutableDetected')
    }

    foreach ($ruleName in $ruleNames) {
        $ruleGroupNode = $minimalConfig.CreateElement('RuleGroup')
        [void]$ruleGroupNode.SetAttribute('groupRelation', 'or')
        $ruleNode = $minimalConfig.CreateElement($ruleName)
        [void]$ruleNode.SetAttribute('onmatch', 'include')
        [void]$ruleGroupNode.AppendChild($ruleNode)
        [void]$eventFilteringNode.AppendChild($ruleGroupNode)
    }

    $minimalConfig.Save($DestinationPath)
}

function Resolve-SysmonExecutable {
    param(
        [Parameter(Mandatory = $true)]
        [string]$ConfigPath,
        [string]$OverridePath
    )

    if (-not [string]::IsNullOrWhiteSpace($OverridePath)) {
        if (Test-Path -LiteralPath $OverridePath) {
            return (Resolve-Path -LiteralPath $OverridePath).Path
        }

        throw "Missing Sysmon executable: $OverridePath"
    }

    $candidates = @(
        (Join-Path $env:WINDIR 'System32\Sysmon.exe'),
        (Join-Path (Split-Path -Parent $ConfigPath) 'Sysmon.exe'),
        (Join-Path $PSScriptRoot 'Sysmon.exe')
    )

    foreach ($candidate in $candidates) {
        if (Test-Path -LiteralPath $candidate) {
            return (Resolve-Path -LiteralPath $candidate).Path
        }
    }

    throw "Missing Sysmon executable. Checked: $($candidates -join ', ')"
}

function Invoke-FileBlockScenario {
    param(
        [Parameter(Mandatory = $true)]
        [string]$TestConfigPath,
        [Parameter(Mandatory = $true)]
        [xml]$ConfigXml,
        [Parameter(Mandatory = $true)]
        [string]$ConfiguredArchiveDirectory,
        [Parameter(Mandatory = $true)]
        [string]$SysmonExe,
        [Parameter(Mandatory = $true)]
        [string]$ScenarioWorkRoot
    )

    $expectArchiveSample = Test-ConfigExpectsArchiveSample -Config $ConfigXml
    $event29Seen = $false
    $blockedBeforeAppend = $false
    $observation = $null

    & $SysmonExe -c $TestConfigPath | Out-Null
    if ($LASTEXITCODE -ne 0) {
        throw "Sysmon block test config update failed with exit code $LASTEXITCODE"
    }

    $startUtc = [datetime]::UtcNow
    $fakeExe = Join-Path $ScenarioWorkRoot 'fake.exe'
    $blockedExe = Join-Path $ScenarioWorkRoot 'blocked.exe'
    $archiveRoot = Join-Path ([System.IO.Path]::GetPathRoot($blockedExe)) $ConfiguredArchiveDirectory

    Set-Content -LiteralPath $fakeExe -Value 'not a pe' -Encoding ASCII
    Copy-Item -LiteralPath $PeSource -Destination $blockedExe -Force
    $expectedArchiveHash = (Get-FileHash -LiteralPath $blockedExe -Algorithm SHA256).Hash

    if (Test-Path -LiteralPath $blockedExe) {
        $uniqueMarker = [Text.Encoding]::ASCII.GetBytes("`r`nSYSMON-FILEBLOCK-REGRESSION:" + [guid]::NewGuid().ToString('N'))
        $blockedStream = [System.IO.File]::Open($blockedExe, [System.IO.FileMode]::Append, [System.IO.FileAccess]::Write, [System.IO.FileShare]::Read)
        try {
            $blockedStream.Write($uniqueMarker, 0, $uniqueMarker.Length)
        }
        finally {
            $blockedStream.Dispose()
        }

        if (Test-Path -LiteralPath $blockedExe) {
            $expectedArchiveHash = (Get-FileHash -LiteralPath $blockedExe -Algorithm SHA256).Hash
        }
    }
    else {
        $blockedBeforeAppend = $true
    }

    Start-Sleep -Seconds 3

    $deadlineUtc = [datetime]::UtcNow.AddSeconds(10)
    do {
        $observation = Get-RegressionObservation `
            -StartTimeUtc $startUtc `
            -BlockedExe $blockedExe `
            -FakeExe $fakeExe `
            -ArchiveRoot $archiveRoot `
            -ExpectedArchiveHash $expectedArchiveHash `
            -ExpectedSampleSha256 $expectedArchiveHash

        if ($observation.Event29Seen) {
            $event29Seen = $true
        }

        if ([datetime]::UtcNow -ge $deadlineUtc) {
            break
        }

        Start-Sleep -Milliseconds 500
    } while ($true)

    try {
        Assert-True (-not $observation.BlockedExists) 'blocked.exe should not remain at the original path'
        Assert-True $observation.FakeExists 'fake.exe was removed even though it is not a PE sample'
        Assert-True ($null -ne $observation.Event27) 'expected Event 27 FileBlockExecutable for blocked.exe'
        Assert-True (-not $event29Seen) 'did not expect Event 29 for blocked.exe when the file should have been blocked'

        if ($expectArchiveSample) {
            Assert-True ($null -ne $observation.ArchiveHit) "expected a freshly archived sample under $archiveRoot that matches the blocked sample content"
            if ($blockedBeforeAppend) {
                return 'PASS: Event 27 observed, blocked.exe was removed before append, fake.exe preserved, and archive sample present'
            }

            return 'PASS: Event 27 observed, blocked.exe removed, fake.exe preserved, and archive sample present'
        }

        if ($blockedBeforeAppend) {
            return 'PASS: Event 27 observed, blocked.exe was removed before append, fake.exe preserved, and delete-only fallback accepted'
        }

        return 'PASS: Event 27 observed, blocked.exe removed, fake.exe preserved, and delete-only fallback accepted'
    }
    catch {
        $message = $_.Exception.Message
        if ($null -ne $observation) {
            $message = $message + "`nObservation: " + (@(
                    "BlockedExists=$($observation.BlockedExists)"
                    "FakeExists=$($observation.FakeExists)"
                    "ExpectArchiveSample=$expectArchiveSample"
                    "ArchiveHit=$($null -ne $observation.ArchiveHit)"
                    "Event27=$($null -ne $observation.Event27)"
                    "Event29Seen=$event29Seen"
                ) -join '; ')
        }

        throw $message
    }
}

function Invoke-FileDetectOnlyScenario {
    param(
        [Parameter(Mandatory = $true)]
        [string]$TestConfigPath,
        [Parameter(Mandatory = $true)]
        [string]$SysmonExe,
        [Parameter(Mandatory = $true)]
        [string]$ScenarioWorkRoot
    )

    & $SysmonExe -c $TestConfigPath | Out-Null
    if ($LASTEXITCODE -ne 0) {
        throw "Sysmon detect-only test config update failed with exit code $LASTEXITCODE"
    }

    $startUtc = [datetime]::UtcNow
    $detectedExe = Join-Path $ScenarioWorkRoot 'detected.exe'
    Copy-Item -LiteralPath $PeSource -Destination $detectedExe -Force
    $expectedHash = (Get-FileHash -LiteralPath $detectedExe -Algorithm SHA256).Hash

    $uniqueMarker = [Text.Encoding]::ASCII.GetBytes("`r`nSYSMON-FILEDETECT-REGRESSION:" + [guid]::NewGuid().ToString('N'))
    $detectedStream = [System.IO.File]::Open($detectedExe, [System.IO.FileMode]::Append, [System.IO.FileAccess]::Write, [System.IO.FileShare]::ReadWrite)
    try {
        $detectedStream.Write($uniqueMarker, 0, $uniqueMarker.Length)
    }
    finally {
        $detectedStream.Dispose()
    }

    if (Test-Path -LiteralPath $detectedExe) {
        $expectedHash = (Get-FileHash -LiteralPath $detectedExe -Algorithm SHA256).Hash
    }

    $event27Seen = $false
    $event29 = $null
    $deadlineUtc = [datetime]::UtcNow.AddSeconds(10)
    do {
        $events = @(Get-SysmonEventsSince -StartTimeUtc $startUtc -Ids @(27, 29))
        $event27Seen = Test-AnyEventForSample -Events $events -Id 27 -TargetPath $detectedExe -ExpectedSha256 $expectedHash
        $event29 = Find-FirstEventForSample -Events $events -Id 29 -TargetPath $detectedExe -ExpectedSha256 $expectedHash

        if ($event29 -ne $null -or [datetime]::UtcNow -ge $deadlineUtc) {
            break
        }

        Start-Sleep -Milliseconds 500
    } while ($true)

    Assert-True (Test-Path -LiteralPath $detectedExe) 'detected.exe should remain in detect-only mode'
    Assert-True ($null -ne $event29) 'expected Event 29 FileExecutableDetected for detected.exe'
    Assert-True (-not $event27Seen) 'did not expect Event 27 in detect-only mode'

    return 'PASS: Event 29 observed, detected.exe preserved, and Event 27 suppressed in detect-only mode'
}

if (-not (Test-Path -LiteralPath $ConfigPath)) {
    throw "Missing config file: $ConfigPath"
}

if (-not (Test-Path -LiteralPath $PeSource)) {
    throw "Missing PE source: $PeSource"
}

New-Item -Path $WorkRoot -ItemType Directory -Force | Out-Null

[xml]$configXml = Get-Content -LiteralPath $ConfigPath

$configuredArchiveDirectory = $null
$archiveDirectoryNode = $configXml.SelectSingleNode('/Sysmon/ArchiveDirectory')
if ($null -ne $archiveDirectoryNode) {
    $configuredArchiveDirectory = $archiveDirectoryNode.InnerText.Trim()
}
if ([string]::IsNullOrWhiteSpace($configuredArchiveDirectory)) {
    $configuredArchiveDirectory = $ArchiveDirectory
}

$sysmonExe = Resolve-SysmonExecutable -ConfigPath $ConfigPath -OverridePath $SysmonExePath

$testConfigApplied = $false
$primaryFailureMessage = $null
$restoreFailureMessage = $null
$passMessages = New-Object System.Collections.Generic.List[string]

try {
    if ($Scenario -eq 'All' -or $Scenario -eq 'Block') {
        $blockRoot = Join-Path $WorkRoot 'block'
        New-Item -Path $blockRoot -ItemType Directory -Force | Out-Null
        $blockConfigPath = Join-Path $WorkRoot 'sysmon_fileblock_regression.xml'
        New-MinimalTestConfig `
            -SourceConfig $configXml `
            -FallbackArchiveDirectory $ArchiveDirectory `
            -Scenario 'Block' `
            -DestinationPath $blockConfigPath
        $passMessages.Add((Invoke-FileBlockScenario `
                -TestConfigPath $blockConfigPath `
                -ConfigXml $configXml `
                -ConfiguredArchiveDirectory $configuredArchiveDirectory `
                -SysmonExe $sysmonExe `
                -ScenarioWorkRoot $blockRoot))
        $testConfigApplied = $true
    }

    if ($Scenario -eq 'All' -or $Scenario -eq 'DetectOnly') {
        $detectRoot = Join-Path $WorkRoot 'detect'
        New-Item -Path $detectRoot -ItemType Directory -Force | Out-Null
        $detectConfigPath = Join-Path $WorkRoot 'sysmon_filedetect_regression.xml'
        New-MinimalTestConfig `
            -SourceConfig $configXml `
            -FallbackArchiveDirectory $ArchiveDirectory `
            -Scenario 'DetectOnly' `
            -DestinationPath $detectConfigPath
        $passMessages.Add((Invoke-FileDetectOnlyScenario `
                -TestConfigPath $detectConfigPath `
                -SysmonExe $sysmonExe `
                -ScenarioWorkRoot $detectRoot))
        $testConfigApplied = $true
    }
}
catch {
    $primaryFailureMessage = $_.Exception.Message
}
finally {
    if ($testConfigApplied) {
        try {
            & $sysmonExe -c $ConfigPath | Out-Null
            if ($LASTEXITCODE -ne 0) {
                throw "Sysmon original config restore failed with exit code $LASTEXITCODE"
            }
        }
        catch {
            $restoreFailureMessage = $_.Exception.Message
        }
    }
}

if ($null -ne $primaryFailureMessage) {
    if ($null -ne $restoreFailureMessage) {
        Write-Warning "Cleanup notice: $restoreFailureMessage"
    }
    throw $primaryFailureMessage
}

if ($null -ne $restoreFailureMessage) {
    Write-Warning "Cleanup notice: $restoreFailureMessage"
}

foreach ($message in $passMessages) {
    Write-Host $message -ForegroundColor Green
}

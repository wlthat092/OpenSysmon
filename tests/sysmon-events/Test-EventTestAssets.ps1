[CmdletBinding()]
param(
    [string]$Root
)

$ErrorActionPreference = 'Stop'
if ([string]::IsNullOrWhiteSpace($Root)) {
    $Root = Split-Path -Parent $MyInvocation.MyCommand.Path
}
$manifestPath = Join-Path $Root 'shared\EventCases.psd1'
if (-not (Test-Path -LiteralPath $manifestPath -PathType Leaf)) {
    throw "Event test manifest is missing: $manifestPath"
}

$manifest = Import-PowerShellDataFile -LiteralPath $manifestPath
$expectedIds = @(1,2,3,5,6,7,8,9,10,11,12,13,14,15,17,18,19,20,21,22,24,25,26)
$actualIds = @($manifest.Keys | ForEach-Object { [int]$_ } | Sort-Object)
$errors = [System.Collections.Generic.List[string]]::new()
if ([string]::Join(',', [int[]]$actualIds) -ne [string]::Join(',', [int[]]$expectedIds)) {
    $errors.Add("Manifest IDs mismatch. Expected: $($expectedIds -join ','); Actual: $($actualIds -join ',')")
}

$eventDirs = @(Get-ChildItem -LiteralPath $Root -Directory -Filter 'event-*' -ErrorAction SilentlyContinue)
$actualDirNames = @($eventDirs.Name | Sort-Object)
$expectedDirNames = @($expectedIds | ForEach-Object { 'event-{0:D2}' -f $_ })
$unexpected = @($actualDirNames | Where-Object { $_ -notin $expectedDirNames })
if ($unexpected.Count) { $errors.Add("Unsupported event directories: $($unexpected -join ', ')") }
$firstMissing = @($expectedDirNames | Where-Object { $_ -notin $actualDirNames } | Select-Object -First 1)
if ($firstMissing.Count) { $errors.Add("Missing event directory: $firstMissing") }

foreach ($id in $expectedIds) {
    $dir = Join-Path $Root ('event-{0:D2}' -f $id)
    if (-not (Test-Path -LiteralPath $dir -PathType Container)) { continue }
    $case = $manifest[$id]
    $configPath = Join-Path $dir 'config.xml'
    $wrapperPath = Join-Path $dir 'test.ps1'
    foreach ($path in @($configPath, $wrapperPath)) {
        if (-not (Test-Path -LiteralPath $path -PathType Leaf)) { $errors.Add("$($dir | Split-Path -Leaf): missing $(Split-Path $path -Leaf)") }
    }
    if (Test-Path -LiteralPath $configPath -PathType Leaf) {
        try { [xml]$xml = Get-Content -LiteralPath $configPath -Raw } catch { $errors.Add("$($dir | Split-Path -Leaf): config.xml is not valid XML: $($_.Exception.Message)"); continue }
        $node = $xml.SelectSingleNode("/*[local-name()='Sysmon']/*[local-name()='EventFiltering']/*[local-name()='RuleGroup']/*[local-name()='$($case.Node)']")
        if (-not $node) { $errors.Add("$($dir | Split-Path -Leaf): config.xml must contain Sysmon/EventFiltering/RuleGroup/$($case.Node)") }
        else {
            $expectedMatchType = if ($id -eq 22) { 'exclude' } else { 'include' }
            if ($node.GetAttribute('onmatch') -ine $expectedMatchType) {
                $errors.Add("$($dir | Split-Path -Leaf): config.xml $($case.Node) onmatch must be $expectedMatchType")
            }
        }
    }
    if (Test-Path -LiteralPath $wrapperPath -PathType Leaf) {
        $parseTokens = $null
        $parseErrors = $null
        $ast = [System.Management.Automation.Language.Parser]::ParseFile($wrapperPath, [ref]$parseTokens, [ref]$parseErrors)
        if ($parseErrors.Count) {
            $errors.Add("$($dir | Split-Path -Leaf): test.ps1 is not valid PowerShell")
            continue
        }
        $shadowingDefinitions = @($ast.FindAll({ param($node) $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -ieq 'Invoke-EventTest' }, $true))
        if ($shadowingDefinitions.Count) {
            $errors.Add("$($dir | Split-Path -Leaf): test.ps1 must not define Invoke-EventTest")
            continue
        }
        $calls = @($ast.FindAll({ param($node) $node -is [System.Management.Automation.Language.CommandAst] -and $node.GetCommandName() -ieq 'Invoke-EventTest' }, $true))
        if ($calls.Count -ne 1) {
            $errors.Add("$($dir | Split-Path -Leaf): test.ps1 must contain exactly one Invoke-EventTest command")
            continue
        }
        $ancestor = $calls[0].Parent
        $isTopLevelCall = $true
        while ($ancestor -and $ancestor -isnot [System.Management.Automation.Language.NamedBlockAst]) {
            if ($ancestor -isnot [System.Management.Automation.Language.PipelineAst] -and $ancestor -isnot [System.Management.Automation.Language.AssignmentStatementAst]) {
                $isTopLevelCall = $false
                break
            }
            $ancestor = $ancestor.Parent
        }
        if (-not $isTopLevelCall -or $ancestor -ne $ast.EndBlock) {
            $errors.Add("$($dir | Split-Path -Leaf): Invoke-EventTest must be a top-level command")
            continue
        }
        $elements = @($calls[0].CommandElements)
        $eventIdParameterIndexes = @(
            for ($index = 0; $index -lt $elements.Count; $index++) {
                if ($elements[$index] -is [System.Management.Automation.Language.CommandParameterAst] -and $elements[$index].ParameterName -ieq 'EventId') { $index }
            }
        )
        if ($eventIdParameterIndexes.Count -ne 1) {
            $errors.Add("$($dir | Split-Path -Leaf): Invoke-EventTest must specify exactly one -EventId integer literal")
            continue
        }
        $argumentIndex = $eventIdParameterIndexes[0] + 1
        $argument = if ($argumentIndex -lt $elements.Count) { $elements[$argumentIndex] } else { $null }
        $integerTypes = @([sbyte], [byte], [int16], [uint16], [int32], [uint32], [int64], [uint64])
        $isExpectedLiteral = $argument -is [System.Management.Automation.Language.ConstantExpressionAst] -and $argument.Value.GetType() -in $integerTypes -and [int64]$argument.Value -eq $id
        if (-not $isExpectedLiteral) { $errors.Add("$($dir | Split-Path -Leaf): Invoke-EventTest -EventId must be integer literal $id") }
    }
}

if ($errors.Count) {
    Write-Error ("Event test asset validation failed:`n - " + ($errors -join "`n - "))
    exit 1
}
Write-Output "Event test assets valid: $($expectedIds.Count) event cases."
exit 0

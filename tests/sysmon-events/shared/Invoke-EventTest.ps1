function Invoke-EventTest {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][int]$EventId,
        [Parameter(Mandatory = $true)][string]$ConfigPath,
        [Parameter(Mandatory = $true)][ValidateNotNullOrEmpty()][string]$SysmonExe,
        [Parameter(Mandatory = $true)][ValidateNotNullOrEmpty()][string]$SimulatorPath,
        [ValidateSet('Hidden', 'Normal', 'Minimized', 'Maximized')]
        [string]$SimulatorWindowStyle = 'Hidden',
        [ValidateRange(0, 5)]
        [int]$SimulatorRetryCount = 0,
        [Parameter(Mandatory = $true)][string[]]$RequiredFields,
        [string[]]$NotPlaceholderFields = @(),
        [hashtable]$ExpectedFields = @{},
        [int]$ExpectedCount = 0,
        [int]$MinimumCount = 1,
        [int]$TimeoutSeconds = 20
    )

    try {
        & $SysmonExe -c $ConfigPath *> $null
        if ($LASTEXITCODE -ne 0) { throw "Sysmon config update failed: $LASTEXITCODE" }

        Start-Sleep -Seconds 3
        # Configuration reload can itself emit registry/process events. Start
        # the query window only after that quiet period so those records cannot
        # be mistaken for output from the simulator trigger.
        $queryStartUtc = (Get-Date).ToUniversalTime().ToString('o')
        $process = $null
        $simulatorExitCode = $null
        $knownTransientExitCode = -1073740940 # 0xC0000374, simulator heap corruption observed for Event 18.
        for ($attempt = 0; $attempt -le $SimulatorRetryCount; $attempt++) {
            $process = Start-Process -FilePath $SimulatorPath `
                -ArgumentList @('-eid', [string]$EventId) `
                -PassThru -WindowStyle $SimulatorWindowStyle
            if (-not $process.WaitForExit($TimeoutSeconds * 1000)) {
                Stop-Process -Id $process.Id -Force -ErrorAction SilentlyContinue
                throw "Simulator timed out for Event $EventId"
            }

            $simulatorExitCode = $process.ExitCode
            if ($simulatorExitCode -eq 0) {
                break
            }

            if ($simulatorExitCode -ne $knownTransientExitCode -or $attempt -ge $SimulatorRetryCount) {
                throw "Simulator failed for Event $EventId with exit code $simulatorExitCode"
            }

            Start-Sleep -Milliseconds 250
        }

        Start-Sleep -Seconds 5
        $filterXml = @"
<QueryList>
  <Query Id="0" Path="Microsoft-Windows-Sysmon/Operational">
    <Select Path="Microsoft-Windows-Sysmon/Operational">*[System[(EventID=$EventId) and TimeCreated[@SystemTime&gt;='$queryStartUtc']]]</Select>
  </Query>
</QueryList>
"@
        $events = @(Get-WinEvent -FilterXml $filterXml -ErrorAction SilentlyContinue)
        if ($events.Count -gt 0 -and $process.Id) {
            $correlatedEvents = @(
                foreach ($candidate in $events) {
                    try {
                        [xml]$candidateXml = $candidate.ToXml()
                        $candidateProcessFields = @(
                            $candidateXml.Event.EventData.Data |
                                Where-Object { [string]$_.Name -match '(^|Process)(Id|PID)$' -or [string]$_.Name -match 'ProcessId$' } |
                                ForEach-Object { [string]$_['#text'] }
                        )
                        if ($candidateProcessFields -contains ([string]$process.Id)) {
                            $candidate
                        }
                    }
                    catch {
                        # Keep the time-window fallback for malformed records.
                    }
                }
            )
            if ($correlatedEvents.Count -gt 0) {
                $events = $correlatedEvents
            }
        }
        if ($events.Count -lt $MinimumCount) {
            throw "Expected at least $MinimumCount Event $EventId record(s), found $($events.Count)"
        }
        if ($ExpectedCount -gt 0 -and $events.Count -ne $ExpectedCount) {
            throw "Expected $ExpectedCount Event $EventId record(s), found $($events.Count)"
        }
        $event = $events | Select-Object -First 1
        if (-not $event) { throw "Event $EventId was not found after $queryStartUtc" }

        [xml]$eventXml = $event.ToXml()
        $fields = [ordered]@{}
        foreach ($node in @($eventXml.Event.EventData.Data)) {
            $name = [string]$node.Name
            if ($name) { $fields[$name] = [string]$node.'#text' }
        }

        $missingFields = @($RequiredFields | Where-Object { -not $fields.Contains($_) })
        if ($missingFields.Count) { throw "Missing required fields: $($missingFields -join ', ')" }

        $placeholderFields = @($NotPlaceholderFields | Where-Object {
            -not $fields.Contains($_) -or
            [string]::IsNullOrWhiteSpace([string]$fields[$_]) -or
            [string]$fields[$_] -in @('-', '0', '{00000000-0000-0000-0000-000000000000}')
        })
        if ($placeholderFields.Count) {
            throw "Placeholder or missing fields: $($placeholderFields -join ', ')"
        }

        foreach ($expectedName in $ExpectedFields.Keys) {
            if (-not $fields.Contains($expectedName) -or [string]$fields[$expectedName] -notmatch [string]$ExpectedFields[$expectedName]) {
                throw "Unexpected value for field $expectedName"
            }
        }

        $payload = [ordered]@{
            eventId = $EventId
            found = $true
            recordId = [long]$event.RecordId
            fields = $fields
        }
        return [pscustomobject]@{
            ExitCode = 0
            Json = ($payload | ConvertTo-Json -Depth 6 -Compress)
        }
    }
    catch {
        $payload = [ordered]@{
            eventId = $EventId
            found = $false
            fields = [ordered]@{}
            error = $_.Exception.Message
        }
        return [pscustomobject]@{
            ExitCode = 1
            Json = ($payload | ConvertTo-Json -Depth 6 -Compress)
        }
    }
}

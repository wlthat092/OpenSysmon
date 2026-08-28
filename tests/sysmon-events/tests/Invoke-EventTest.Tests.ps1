$helperPath = Join-Path (Split-Path -Parent $PSScriptRoot) 'shared\Invoke-EventTest.ps1'
$helperExists = Test-Path -LiteralPath $helperPath -PathType Leaf
if ($helperExists) {
    . $helperPath
}

Describe 'Invoke-EventTest' {
    It 'is defined by the shared helper' {
        $helperExists | Should Be $true
        (Get-Command Invoke-EventTest -ErrorAction SilentlyContinue) | Should Not BeNullOrEmpty
    }

    if ($helperExists) {
        BeforeEach {
            $script:waitResult = $true
            $script:simulatorExitCode = 0
            $script:capturedFilterXml = $null
            $script:stubRoot = Join-Path ([System.IO.Path]::GetTempPath()) ('invoke-event-test-' + [guid]::NewGuid())
            [System.IO.Directory]::CreateDirectory($script:stubRoot) | Out-Null
            $script:sysmonStubPath = Join-Path $script:stubRoot 'sysmon-stub.cmd'
            [System.IO.File]::WriteAllText($script:sysmonStubPath, '@exit /b 0')
            $script:eventXml = @'
<Event>
  <System><EventRecordID>42</EventRecordID></System>
  <EventData>
    <Data Name="RuleName">-</Data>
    <Data Name="ProcessId">123</Data>
  </EventData>
</Event>
'@

            $script:process = [pscustomobject]@{
                Id = 1234
                ExitCode = $script:simulatorExitCode
                WaitResult = $script:waitResult
            }
            $script:process | Add-Member -MemberType ScriptMethod -Name WaitForExit -Value { param($milliseconds) return $this.WaitResult }

            $script:event = [pscustomobject]@{
                RecordId = 42
                Xml = $script:eventXml
            }
            $script:event | Add-Member -MemberType ScriptMethod -Name ToXml -Value { return $this.Xml }

            Mock Start-Sleep {}
            Mock Start-Process { return $script:process }
            Mock Stop-Process {}
            Mock Get-WinEvent {
                param($FilterXml)
                $script:capturedFilterXml = $FilterXml
                return $script:event
            }
        }

        AfterEach {
            if (Test-Path -LiteralPath $script:stubRoot) { [System.IO.Directory]::Delete($script:stubRoot, $true) }
        }

        It 'returns compact success JSON with fields and record ID' {
            $result = Invoke-EventTest -EventId 22 -ConfigPath 'C:\test\config.xml' `
                -SysmonExe $script:sysmonStubPath -SimulatorPath 'C:\test\simulator.exe' `
                -RequiredFields @('RuleName','ProcessId') -TimeoutSeconds 20

            $payload = $result.Json | ConvertFrom-Json
            $result.ExitCode | Should Be 0
            $payload.eventId | Should Be 22
            $payload.found | Should Be $true
            $payload.recordId | Should Be 42
            $payload.fields.RuleName | Should Be '-'
            $payload.fields.ProcessId | Should Be '123'
            $result.Json | Should Not Match "`r|`n"
            $script:capturedFilterXml.OuterXml | Should Match 'EventID=22'
            $script:capturedFilterXml.OuterXml | Should Match 'TimeCreated'
        }

        It 'returns structured failure when config application fails' {
            [System.IO.File]::WriteAllText($script:sysmonStubPath, '@exit /b 9')

            $result = Invoke-EventTest -EventId 22 -ConfigPath 'C:\test\config.xml' `
                -SysmonExe $script:sysmonStubPath -SimulatorPath 'C:\test\simulator.exe' `
                -RequiredFields @('RuleName')

            $payload = $result.Json | ConvertFrom-Json
            $result.ExitCode | Should Be 1
            $payload.found | Should Be $false
            $payload.error | Should Match 'Sysmon config update failed: 9'
            Assert-MockCalled Start-Process -Times 0 -Scope It
        }

        It 'stops a simulator that exceeds the timeout' {
            $script:process.WaitResult = $false

            $result = Invoke-EventTest -EventId 22 -ConfigPath 'C:\test\config.xml' `
                -SysmonExe $script:sysmonStubPath -SimulatorPath 'C:\test\simulator.exe' `
                -RequiredFields @('RuleName') -TimeoutSeconds 1

            $payload = $result.Json | ConvertFrom-Json
            $result.ExitCode | Should Be 1
            $payload.error | Should Match 'Simulator timed out for Event 22'
            Assert-MockCalled Stop-Process -Times 1 -Scope It -ParameterFilter { $Id -eq 1234 -and $Force }
        }

        It 'returns structured failure for a nonzero simulator exit code' {
            $script:process.ExitCode = 7

            $result = Invoke-EventTest -EventId 22 -ConfigPath 'C:\test\config.xml' `
                -SysmonExe $script:sysmonStubPath -SimulatorPath 'C:\test\simulator.exe' `
                -RequiredFields @('RuleName')

            $payload = $result.Json | ConvertFrom-Json
            $result.ExitCode | Should Be 1
            $payload.error | Should Match 'Simulator failed for Event 22 with exit code 7'
        }

        It 'retries the known Event 18 simulator heap exit code' {
            $script:startProcessCalls = 0
            Mock Start-Process {
                $script:startProcessCalls++
                $script:process.ExitCode = if ($script:startProcessCalls -eq 1) { -1073740940 } else { 0 }
                return $script:process
            }

            $result = Invoke-EventTest -EventId 18 -ConfigPath 'C:\test\config.xml' `
                -SysmonExe $script:sysmonStubPath -SimulatorPath 'C:\test\simulator.exe' `
                -SimulatorWindowStyle Normal -SimulatorRetryCount 1 `
                -RequiredFields @('RuleName','ProcessId')

            $payload = $result.Json | ConvertFrom-Json
            $result.ExitCode | Should Be 0
            $payload.found | Should Be $true
            $script:startProcessCalls | Should Be 2
            Assert-MockCalled Start-Process -Times 2 -Scope It -ParameterFilter { $WindowStyle -eq 'Normal' }
        }

        It 'returns structured failure when no matching event is found' {
            Mock Get-WinEvent { return $null }

            $result = Invoke-EventTest -EventId 22 -ConfigPath 'C:\test\config.xml' `
                -SysmonExe $script:sysmonStubPath -SimulatorPath 'C:\test\simulator.exe' `
                -RequiredFields @('RuleName')

            $payload = $result.Json | ConvertFrom-Json
            $result.ExitCode | Should Be 1
            $payload.found | Should Be $false
            $payload.error | Should Match 'Event 22 was not found'
        }

        It 'reports every missing required field' {
            $result = Invoke-EventTest -EventId 22 -ConfigPath 'C:\test\config.xml' `
                -SysmonExe $script:sysmonStubPath -SimulatorPath 'C:\test\simulator.exe' `
                -RequiredFields @('RuleName','Image','User')

            $payload = $result.Json | ConvertFrom-Json
            $result.ExitCode | Should Be 1
            $payload.error | Should Match 'Missing required fields: Image, User'
        }
    }
}

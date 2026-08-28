$suiteRoot = Split-Path -Parent $PSScriptRoot
$runAllPath = Join-Path $suiteRoot 'Run-All.ps1'
$runAllExists = Test-Path -LiteralPath $runAllPath -PathType Leaf

function ConvertTo-SingleQuotedLiteral {
    param([string]$Value)
    return "'" + $Value.Replace("'", "''") + "'"
}

Describe 'Run-All.ps1' {
    It 'exists as the VM-side orchestrator' {
        $runAllExists | Should Be $true
    }

    if ($runAllExists) {
        BeforeEach {
            $script:testRoot = Join-Path ([System.IO.Path]::GetTempPath()) ('run-all-tests-' + [guid]::NewGuid())
            [System.IO.Directory]::CreateDirectory((Join-Path $script:testRoot 'shared')) | Out-Null
            Copy-Item (Join-Path $suiteRoot 'shared\EventCases.psd1') (Join-Path $script:testRoot 'shared\EventCases.psd1')
            $script:orderPath = Join-Path $script:testRoot 'order.txt'
            $script:restoreLogPath = Join-Path $script:testRoot 'restore.txt'
            $script:mainConfigPath = Join-Path $script:testRoot 'main.xml'
            $script:toolRoot = Join-Path $script:testRoot 'tools'
            [System.IO.Directory]::CreateDirectory($script:toolRoot) | Out-Null
            $script:simulatorPath = Join-Path $script:toolRoot 'SysmonSimulator.exe'
            $script:sysmonPath = Join-Path $script:toolRoot 'Sysmon.cmd'
            $script:mainConfigPath = Join-Path $script:toolRoot 'sysmon_config.xml'
            [System.IO.File]::WriteAllText($script:mainConfigPath, '<Sysmon />')
            [System.IO.File]::WriteAllText($script:simulatorPath, '')
            [System.IO.File]::WriteAllText(
                $script:sysmonPath,
                "@echo off`r`necho %*>>`"$script:restoreLogPath`"`r`nexit /b 0`r`n")

            foreach ($id in @(1,2)) {
                $dir = Join-Path $script:testRoot ('event-{0:D2}' -f $id)
                [System.IO.Directory]::CreateDirectory($dir) | Out-Null
                [System.IO.File]::WriteAllText((Join-Path $dir 'config.xml'), '<Sysmon />')
                $found = if ($id -eq 1) { '$true' } else { '$false' }
                $exitCode = if ($id -eq 1) { 0 } else { 1 }
                $errorProperty = if ($id -eq 1) { '' } else { "; error = 'fixture failure'" }
                $wrapper = @"
param([string]`$SysmonExe,[string]`$SimulatorPath,[string]`$TimeoutSeconds)
[System.IO.File]::AppendAllText($(ConvertTo-SingleQuotedLiteral $script:orderPath), "$id``r``n")
[pscustomobject]@{ eventId = $id; found = $found; recordId = $id; fields = @{}$errorProperty } | ConvertTo-Json -Compress
exit $exitCode
"@
                [System.IO.File]::WriteAllText((Join-Path $dir 'test.ps1'), $wrapper)
            }
        }

        AfterEach {
            if (Test-Path -LiteralPath $script:testRoot) { [System.IO.Directory]::Delete($script:testRoot, $true) }
        }

        function Invoke-RunAllHarness {
            param([string]$SysmonStatus = 'Running')
            $command = @"
function Get-Service {
    param([string]`$Name)
    if (`$Name -eq 'Sysmon') { return [pscustomobject]@{ Name = 'Sysmon'; Status = '$SysmonStatus' } }
    if (`$Name -eq 'SysmonDrv') { return [pscustomobject]@{ Name = 'SysmonDrv'; Status = 'Running' } }
}
& $(ConvertTo-SingleQuotedLiteral $runAllPath) -TestRoot $(ConvertTo-SingleQuotedLiteral $script:testRoot) -EventIds 2,1
"@
            $encoded = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($command))
            $output = & powershell -NoProfile -NonInteractive -ExecutionPolicy Bypass -EncodedCommand $encoded 2>&1
            return [pscustomobject]@{ ExitCode = $LASTEXITCODE; Output = ($output -join [Environment]::NewLine) }
        }

        It 'runs selected events in numeric order, continues failures, and restores config' {
            $result = Invoke-RunAllHarness

            $result.ExitCode | Should Be 1
            @(Get-Content -LiteralPath $script:orderPath) | Should Be @('1','2')
            $result.Output | Should Match '"eventId":1'
            $result.Output | Should Match '"eventId":2'
            (Get-Content -LiteralPath $script:restoreLogPath -Raw) | Should Match ([regex]::Escape("-c $script:mainConfigPath"))
        }

        It 'fails before restoring config when a required service is stopped' {
            $result = Invoke-RunAllHarness -SysmonStatus 'Stopped'

            $result.ExitCode | Should Be 1
            $result.Output | Should Match 'Sysmon service must be Running'
            (Test-Path -LiteralPath $script:restoreLogPath) | Should Be $false
        }
    }
}

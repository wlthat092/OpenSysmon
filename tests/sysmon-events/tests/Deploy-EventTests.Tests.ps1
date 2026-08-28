$suiteRoot = Split-Path -Parent $PSScriptRoot
$repositoryRoot = Split-Path -Parent (Split-Path -Parent $suiteRoot)
$deployPath = Join-Path $suiteRoot 'Deploy-EventTests.ps1'
$deployExists = Test-Path -LiteralPath $deployPath -PathType Leaf
$legacyEventScriptNames = @(
    'Remote-ProcessCreateSmoke.ps1'
    'Remote-DnsQuerySmoke.ps1'
    'Remote-PipeEventSmoke.ps1'
    'Remote-Event8ManualProbe.ps1'
    'Remote-Event9Probe.ps1'
    'Remote-Event25GhostingProbe.ps1'
)
$activeDocumentation = @(
    'README.md'
    'docs\testing.md'
    'docs\deployment.md'
    'docs\troubleshooting.md'
)

function ConvertFrom-CapturedEncodedCommand {
    param([object[]]$Arguments)
    $text = $Arguments -join ' '
    if ($text -notmatch '-EncodedCommand\s+([A-Za-z0-9+/=]+)') { throw "Encoded command not found in: $text" }
    return [Text.Encoding]::Unicode.GetString([Convert]::FromBase64String($matches[1]))
}

Describe 'Deploy-EventTests.ps1' {
    It 'exists as the local deployment entrypoint' {
        $deployExists | Should Be $true
    }

    It 'does not retain superseded event-specific scripts' {
        foreach ($scriptName in $legacyEventScriptNames) {
            Test-Path -LiteralPath (Join-Path $repositoryRoot "scripts\$scriptName") | Should Be $false
        }
    }

    It 'documents the fixed suite as the only simulator-backed event entrypoint' {
        foreach ($documentationPath in $activeDocumentation) {
            $documentation = [System.IO.File]::ReadAllText((Join-Path $repositoryRoot $documentationPath), [System.Text.Encoding]::UTF8)
            foreach ($scriptName in $legacyEventScriptNames) {
                $documentation | Should Not Match ([regex]::Escape($scriptName))
            }
        }

        $testingDocumentation = [System.IO.File]::ReadAllText((Join-Path $repositoryRoot 'docs\testing.md'), [System.Text.Encoding]::UTF8)
        $testingDocumentation | Should Match ([regex]::Escape('tests\sysmon-events\Deploy-EventTests.ps1'))
        $testingDocumentation | Should Match ([regex]::Escape('-EventIds 22'))
        $testingDocumentation | Should Match ([regex]::Escape('-EventIds @(1,8,22)'))
        $testingDocumentation | Should Match ([regex]::Escape('-Target user@host -EventIds 22'))
        $testingDocumentation | Should Match ([regex]::Escape('-RemoteRoot'))
    }

    if ($deployExists) {
        BeforeEach {
            $script:stubRoot = Join-Path ([System.IO.Path]::GetTempPath()) ('deploy-native-stubs-' + [guid]::NewGuid())
            [System.IO.Directory]::CreateDirectory($script:stubRoot) | Out-Null
            $script:sshLog = Join-Path $script:stubRoot 'ssh.log'
            $script:scpLog = Join-Path $script:stubRoot 'scp.log'
            $script:sysmonSourcePath = Join-Path $script:stubRoot 'Sysmon-source.exe'
            $script:simulatorSourcePath = Join-Path $script:stubRoot 'Simulator-source.exe'
            $script:mainConfigSourcePath = Join-Path $script:stubRoot 'main-source.xml'
            [System.IO.File]::WriteAllText($script:sysmonSourcePath, '')
            [System.IO.File]::WriteAllText($script:simulatorSourcePath, '')
            [System.IO.File]::WriteAllText($script:mainConfigSourcePath, '<Sysmon />')
            $script:fixtureToolsRoot = Join-Path $suiteRoot 'tools'
            [System.IO.Directory]::CreateDirectory($script:fixtureToolsRoot) | Out-Null
            [System.IO.File]::WriteAllText((Join-Path $script:fixtureToolsRoot 'SysmonSimulator.exe'), '')
            [System.IO.File]::WriteAllText(
                (Join-Path $script:stubRoot 'ssh.cmd'),
                "@echo off`r`necho %*>>`"$script:sshLog`"`r`necho {`"eventId`":22,`"found`":true,`"recordId`":42,`"fields`":{}}`r`nexit /b 0`r`n")
            [System.IO.File]::WriteAllText(
                (Join-Path $script:stubRoot 'scp.cmd'),
                "@echo off`r`necho %*>>`"$script:scpLog`"`r`nexit /b 0`r`n")
            $script:originalPath = $env:PATH
            $env:PATH = $script:stubRoot + [System.IO.Path]::PathSeparator + $env:PATH
        }

        AfterEach {
            $env:PATH = $script:originalPath
            $fixtureSimulator = Join-Path $script:fixtureToolsRoot 'SysmonSimulator.exe'
            if (Test-Path -LiteralPath $fixtureSimulator) { Remove-Item -LiteralPath $fixtureSimulator -Force }
            if (Test-Path -LiteralPath $script:stubRoot) { [System.IO.Directory]::Delete($script:stubRoot, $true) }
        }

        It 'validates, uploads selected assets, and streams the remote result' {
            $output = & $deployPath -Target 'user@example.test' -RemoteRoot 'C:\test\sysmon\tests\events' -EventIds 22

            ($output -join [Environment]::NewLine) | Should Match '"eventId":22'
            $sshCalls = @(Get-Content -LiteralPath $script:sshLog)
            $scpCalls = @(Get-Content -LiteralPath $script:scpLog)
            $sshCalls.Count | Should Be 2
            $scpCalls.Count | Should Be 4

            $scpText = $scpCalls[0]
            $scpText | Should Match 'Deploy-EventTests.ps1'
            $scpText | Should Match 'Run-All.ps1'
            $scpText | Should Match 'shared'
            $scpText | Should Match 'event-22'
            $scpText | Should Match 'event-01'
            $scpCalls[1] | Should Match 'Sysmon.exe'
            $scpCalls[2] | Should Match 'SysmonSimulator.exe'
            $scpCalls[3] | Should Match 'sysmon_config.xml'

            $createScript = ConvertFrom-CapturedEncodedCommand $sshCalls[0]
            $createScript | Should Match 'CreateDirectory'
            $createScript | Should Match ([regex]::Escape('C:\test\sysmon\tests\events'))

            $runScript = ConvertFrom-CapturedEncodedCommand $sshCalls[1]
            $runScript | Should Match ([regex]::Escape('C:\test\sysmon\tests\events\Run-All.ps1'))
            $runScript | Should Match '-EventIds 22'
        }

        It 'fails local validation before any transfer when the simulator is missing' {
            Remove-Item -LiteralPath (Join-Path $script:fixtureToolsRoot 'SysmonSimulator.exe') -Force
                $threw = $false
                try {
                    & $deployPath -Target 'user@example.test' -RemoteRoot 'C:\test\events' -EventIds 22
                }
                catch {
                    $threw = $true
                }
                $threw | Should Be $true
                (Test-Path -LiteralPath $script:sshLog) | Should Be $false
                (Test-Path -LiteralPath $script:scpLog) | Should Be $false
        }

    }
}

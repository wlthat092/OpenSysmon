param(
    [Parameter(Mandatory = $true)][ValidateNotNullOrEmpty()][string]$Target,
    [string]$RemoteRoot = '',
    [string]$ConfigPath = '',
    [ValidateSet('Debug', 'Release')]
    [string]$DriverConfiguration = 'Release',
    [ValidateSet('Debug', 'Release')]
    [string]$UserConfiguration = 'Release',
    [switch]$SkipBuild
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$scriptRoot = if ($PSScriptRoot) { $PSScriptRoot } else { Split-Path -Parent $MyInvocation.MyCommand.Path }
$driverBuildScript = Join-Path $scriptRoot 'SysmonDrv\build.ps1'
$userBuildScript = Join-Path $scriptRoot 'SysmonUser\build.ps1'
$driverBinary = Join-Path $scriptRoot ("SysmonDrv\\x64\\{0}\\SysmonDrv.sys" -f $DriverConfiguration)
$userBinary = Join-Path $scriptRoot ("SysmonUser\\x64\\{0}\\Sysmon.exe" -f $UserConfiguration)

if (-not $ConfigPath) {
    $ConfigPath = Join-Path $scriptRoot 'sysmon_config.xml'
}

function ConvertTo-RemoteCommand {
    param([Parameter(Mandatory = $true)][string]$Script)

    return [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($Script))
}

function Get-RemoteTempPath {
    $tempPath = (& ssh $Target "powershell -NoProfile -Command ""[IO.Path]::GetTempPath()""").Trim()
    if ($LASTEXITCODE -ne 0 -or -not $tempPath) {
        throw "Failed to resolve remote temp path"
    }

    return $tempPath
}

function Invoke-RemotePowerShell {
    param([Parameter(Mandatory = $true)][string]$Script)

    $encoded = ConvertTo-RemoteCommand -Script $Script
    if ($encoded.Length -lt 7000) {
        & ssh $Target "powershell -NoProfile -NonInteractive -ExecutionPolicy Bypass -EncodedCommand $encoded"
        if ($LASTEXITCODE -ne 0) {
            throw "Remote PowerShell failed with exit code $LASTEXITCODE"
        }
        return
    }

    $localTempScript = Join-Path ([IO.Path]::GetTempPath()) ("sysmon-deploy-{0}.ps1" -f ([guid]::NewGuid().ToString('N')))
    $remoteTempScript = Join-Path (Get-RemoteTempPath) ([IO.Path]::GetFileName($localTempScript))

    try {
        Set-Content -LiteralPath $localTempScript -Value $Script -Encoding Unicode
        Copy-ToRemote -LocalPath $localTempScript -RemotePath (ConvertTo-ScpPath -WindowsPath $remoteTempScript)
        & ssh $Target "powershell -NoProfile -NonInteractive -ExecutionPolicy Bypass -File `"$remoteTempScript`""
        if ($LASTEXITCODE -ne 0) {
            throw "Remote PowerShell file execution failed with exit code $LASTEXITCODE"
        }
    } finally {
        Remove-Item -LiteralPath $localTempScript -Force -ErrorAction SilentlyContinue
        & ssh $Target "powershell -NoProfile -NonInteractive -ExecutionPolicy Bypass -Command ""Remove-Item -LiteralPath '$remoteTempScript' -Force -ErrorAction SilentlyContinue""" | Out-Null
    }
}

function Copy-ToRemote {
    param(
        [Parameter(Mandatory = $true)][string]$LocalPath,
        [Parameter(Mandatory = $true)][string]$RemotePath
    )

    $copyOutput = @(& scp $LocalPath "$Target`:$RemotePath" 2>&1)
    $copyExitCode = $LASTEXITCODE
    if ($copyOutput.Count -gt 0) {
        Write-Verbose ($copyOutput -join [Environment]::NewLine)
    }
    if ($copyExitCode -ne 0) {
        throw "Failed to copy $LocalPath to $RemotePath (scp exit code $copyExitCode)"
    }
}

function ConvertTo-ScpPath {
    param([Parameter(Mandatory = $true)][string]$WindowsPath)

    return ('/' + ($WindowsPath -replace '\\', '/'))
}

Write-Host "=== Deploy Sysmon artifacts to $Target ===" -ForegroundColor Cyan

if (-not $SkipBuild) {
    Write-Host "Building SysmonDrv..." -ForegroundColor Cyan
    & powershell -ExecutionPolicy Bypass -File $driverBuildScript -Configuration $DriverConfiguration -Rebuild
    if ($LASTEXITCODE -ne 0) {
        throw "SysmonDrv build failed"
    }

    Write-Host "Building SysmonUser ($UserConfiguration)..." -ForegroundColor Cyan
    & powershell -ExecutionPolicy Bypass -File $userBuildScript -Configuration $UserConfiguration
    if ($LASTEXITCODE -ne 0) {
        throw "SysmonUser build failed"
    }
}

foreach ($path in @($driverBinary, $userBinary, $ConfigPath)) {
    if (-not (Test-Path -LiteralPath $path)) {
        throw "Required artifact not found: $path"
    }
}

if (-not $RemoteRoot) {
    # Some Windows profiles persist a trailing space in the Desktop known
    # folder value. Normalize it before combining so the staged path matches
    # the actual Desktop directory used by the service account.
    $desktopPathScript = "[IO.Path]::Combine([Environment]::GetFolderPath('Desktop').TrimEnd(' '), 'sysmon')"
    $desktopPathCommand = ConvertTo-RemoteCommand -Script $desktopPathScript
    $remoteDesktopOutput = @(& ssh $Target "powershell -NoProfile -NonInteractive -EncodedCommand $desktopPathCommand" 2>$null)
    $RemoteRoot = @(
        $remoteDesktopOutput |
            ForEach-Object { ([string]$_).Trim() } |
            Where-Object { $_ -match '^[A-Za-z]:\\' }
    ) | Select-Object -Last 1
    if ($null -ne $RemoteRoot) {
        $RemoteRoot = [string]$RemoteRoot
    }
    if ($LASTEXITCODE -ne 0 -or -not $RemoteRoot) {
        throw "Failed to resolve remote Desktop path"
    }
}

Invoke-RemotePowerShell -Script @"
New-Item -ItemType Directory -Path '$RemoteRoot' -Force | Out-Null
"@

$remoteScpRoot = ConvertTo-ScpPath -WindowsPath $RemoteRoot
Write-Verbose "Remote staging root: $RemoteRoot"
Write-Verbose "Remote SCP root: $remoteScpRoot"
$remoteConfigName = Split-Path -Leaf $ConfigPath
Copy-ToRemote -LocalPath $driverBinary -RemotePath "$remoteScpRoot/SysmonDrv.sys"
Copy-ToRemote -LocalPath $userBinary -RemotePath "$remoteScpRoot/Sysmon.exe"
Copy-ToRemote -LocalPath $ConfigPath -RemotePath "$remoteScpRoot/$remoteConfigName"

Invoke-RemotePowerShell -Script @"
`$ErrorActionPreference = 'Stop'

`$stagingDir = '$RemoteRoot'
`$stagedSysmonExe = Join-Path `$stagingDir 'Sysmon.exe'
`$stagedDriver = Join-Path `$stagingDir 'SysmonDrv.sys'
`$stagedConfig = Join-Path `$stagingDir '$remoteConfigName'
`$sysmonExePath = Join-Path `$env:SystemRoot 'System32\Sysmon.exe'
`$driverPath = Join-Path `$env:SystemRoot 'System32\drivers\SysmonDrv.sys'

function Test-ServiceExists {
    param([Parameter(Mandatory = `$true)][string]`$Name)

    if (`$null -ne (Get-Service -Name `$Name -ErrorAction SilentlyContinue)) {
        return `$true
    }

    & cmd.exe /c "sc.exe query `$Name" > `$null 2>&1
    return `$LASTEXITCODE -eq 0
}

function Stop-ServiceIfPresent {
    param([Parameter(Mandatory = `$true)][string]`$Name)

    `$service = Get-Service -Name `$Name -ErrorAction SilentlyContinue
    if (`$service -ne `$null -and `$service.Status -ne 'Stopped') {
        Stop-Service -Name `$Name -Force -ErrorAction SilentlyContinue
    }
}

function Test-FilterLoaded {
    param([Parameter(Mandatory = `$true)][string]`$Name)

    `$filters = & fltmc.exe filters 2>`$null
    if (`$LASTEXITCODE -ne 0 -or `$null -eq `$filters) {
        return `$false
    }

    return (`$filters | Select-String -SimpleMatch `$Name -Quiet)
}

function Unload-FilterIfPresent {
    param(
        [Parameter(Mandatory = `$true)][string]`$Name,
        [int]`$TimeoutSeconds = 30
    )

    if (-not (Test-FilterLoaded -Name `$Name)) {
        return `$true
    }

    & fltmc.exe unload `$Name 2>`$null | Out-Null
    `$deadline = (Get-Date).AddSeconds(`$TimeoutSeconds)
    do {
        if (-not (Test-FilterLoaded -Name `$Name)) {
            return `$true
        }

        Start-Sleep -Seconds 1
    } while ((Get-Date) -lt `$deadline)

    return `$false
}

function Wait-ForServiceStatus {
    param(
        [Parameter(Mandatory = `$true)][string]`$Name,
        [Parameter(Mandatory = `$true)][string]`$DesiredStatus,
        [int]`$TimeoutSeconds = 15
    )

    `$deadline = (Get-Date).AddSeconds(`$TimeoutSeconds)
    do {
        `$service = Get-Service -Name `$Name -ErrorAction SilentlyContinue
        if (`$service -ne `$null -and `$service.Status.ToString() -eq `$DesiredStatus) {
            return `$true
        }

        if (`$service -eq `$null -and `$DesiredStatus -eq 'Stopped') {
            return `$true
        }

        Start-Sleep -Seconds 1
    } while ((Get-Date) -lt `$deadline)

    return `$false
}

function Ensure-CertificateInStore {
    param(
        [Parameter(Mandatory = `$true)]`$Certificate,
        [Parameter(Mandatory = `$true)][string]`$StoreName
    )

    `$store = New-Object System.Security.Cryptography.X509Certificates.X509Store(`$StoreName, 'LocalMachine')
    `$store.Open('ReadWrite')
    try {
        `$existing = `$store.Certificates | Where-Object { `$_.Thumbprint -eq `$Certificate.Thumbprint }
        if (-not `$existing) {
            `$store.Add(`$Certificate)
        }
    } finally {
        `$store.Close()
    }
}

function Invoke-Sc {
    param([Parameter(Mandatory = `$true)][string]`$Arguments)

    `$output = & cmd.exe /c "sc.exe `$Arguments" 2>&1
    if (`$LASTEXITCODE -ne 0) {
        throw "sc.exe `$Arguments failed: `$output"
    }
}

function Ensure-SysmonDrvInstanceRegistration {
    `$instancePath = 'HKLM:\SYSTEM\CurrentControlSet\Services\SysmonDrv\Instances'
    `$instanceName = 'Sysmon Instance'
    `$subPath = Join-Path `$instancePath `$instanceName

    New-Item -Path `$instancePath -Force | Out-Null
    Set-ItemProperty -Path `$instancePath -Name 'DefaultInstance' -Value `$instanceName

    New-Item -Path `$subPath -Force | Out-Null
    Set-ItemProperty -Path `$subPath -Name 'Altitude' -Value '385201'
    Set-ItemProperty -Path `$subPath -Name 'Flags' -Value 0 -Type DWord
}

New-Item -ItemType Directory -Path `$stagingDir -Force | Out-Null

Stop-ServiceIfPresent -Name 'Sysmon'
Stop-ServiceIfPresent -Name 'SysmonDrv'
Start-Sleep -Seconds 2
Wait-ForServiceStatus -Name 'Sysmon' -DesiredStatus 'Stopped' -TimeoutSeconds 10 | Out-Null
if (-not (Unload-FilterIfPresent -Name 'SysmonDrv' -TimeoutSeconds 30)) {
    throw "SysmonDrv filter failed to unload cleanly before file replacement"
}
Wait-ForServiceStatus -Name 'SysmonDrv' -DesiredStatus 'Stopped' -TimeoutSeconds 10 | Out-Null

Copy-Item -LiteralPath `$stagedSysmonExe -Destination `$sysmonExePath -Force
Copy-Item -LiteralPath `$stagedDriver -Destination `$driverPath -Force

function Test-LegacySigningCertificate {
    param([Parameter(Mandatory = `$true)]`$Certificate)

    if (`$null -eq `$Certificate -or -not `$Certificate.HasPrivateKey) {
        return `$false
    }

    try {
        return (`$Certificate.PrivateKey -ne `$null) -and
            (`$Certificate.PrivateKey.CspKeyContainerInfo.ProviderName -eq
                'Microsoft Enhanced RSA and AES Cryptographic Provider')
    } catch {
        return `$false
    }
}

`$cert = Get-ChildItem 'Cert:\LocalMachine\My' |
    Where-Object {
        (`$_.Subject -eq 'CN=SysmonTest' -or `$_.Subject -eq 'CN=SysmonTestLegacy') -and
        (Test-LegacySigningCertificate -Certificate `$_)
    } |
    Sort-Object NotAfter -Descending |
    Select-Object -First 1
if (`$null -eq `$cert) {
    `$certParams = @{
        CertStoreLocation = 'Cert:\LocalMachine\My'
        Type = 'CodeSigningCert'
        DnsName = 'SysmonTestLegacy'
        Subject = 'CN=SysmonTestLegacy'
        KeyUsage = 'DigitalSignature'
        Provider = 'Microsoft Enhanced RSA and AES Cryptographic Provider'
        KeySpec = 'Signature'
        NotAfter = (Get-Date).AddYears(5)
    }
    `$cert = New-SelfSignedCertificate @certParams
}
Ensure-CertificateInStore -Certificate `$cert -StoreName 'Root'
Ensure-CertificateInStore -Certificate `$cert -StoreName 'TrustedPublisher'

`$signature = Set-AuthenticodeSignature -FilePath `$driverPath -Certificate `$cert -HashAlgorithm SHA256
if (`$signature.Status -ne 'Valid') {
    throw "Driver signing failed: `$(`$signature.Status)"
}

if (-not (Test-ServiceExists -Name 'SysmonDrv')) {
    Invoke-Sc ("create SysmonDrv type= kernel start= demand error= normal binPath= `$driverPath DisplayName= SysmonDrv")
}
Invoke-Sc ("config SysmonDrv type= kernel start= demand error= normal binPath= `$driverPath")
Ensure-SysmonDrvInstanceRegistration

if (Test-ServiceExists -Name 'SysmonDrv') {
    Start-Service -Name 'SysmonDrv' -ErrorAction SilentlyContinue
    if (-not (Wait-ForServiceStatus -Name 'SysmonDrv' -DesiredStatus 'Running' -TimeoutSeconds 20)) {
        throw "SysmonDrv failed to reach Running state before Sysmon configuration"
    }
}

`$sysmonServiceExists = Test-ServiceExists -Name 'Sysmon'
if (-not `$sysmonServiceExists) {
    & `$sysmonExePath -i `$stagedConfig
    if (`$LASTEXITCODE -eq 1073 -or `$LASTEXITCODE -eq 1056) {
        & `$sysmonExePath -c `$stagedConfig
        if (`$LASTEXITCODE -ne 0) {
            throw "Sysmon config update after install conflict failed with exit code `$LASTEXITCODE"
        }
    } elseif (`$LASTEXITCODE -ne 0) {
        throw "Sysmon install failed with exit code `$LASTEXITCODE"
    }
} else {
    & `$sysmonExePath -c `$stagedConfig
    if (`$LASTEXITCODE -ne 0) {
        throw "Sysmon config update failed with exit code `$LASTEXITCODE"
    }
}

if (Test-ServiceExists -Name 'Sysmon') {
    Start-Service -Name 'Sysmon' -ErrorAction SilentlyContinue
}

if (-not (Wait-ForServiceStatus -Name 'SysmonDrv' -DesiredStatus 'Running' -TimeoutSeconds 20)) {
    throw "SysmonDrv failed to reach Running state"
}

if (-not (Wait-ForServiceStatus -Name 'Sysmon' -DesiredStatus 'Running' -TimeoutSeconds 20)) {
    throw "Sysmon failed to reach Running state"
}

Write-Output "Deployed Sysmon.exe: `$sysmonExePath"
Write-Output "Deployed SysmonDrv.sys: `$driverPath"
Write-Output "Config used: `$stagedConfig"
"@

Write-Host "Remote artifacts updated:" -ForegroundColor Green
Write-Host "  $RemoteRoot\\SysmonDrv.sys"
Write-Host "  $RemoteRoot\\Sysmon.exe"
Write-Host "  $RemoteRoot\\$(Split-Path -Leaf $ConfigPath)"
Write-Host "  C:\\Windows\\System32\\Sysmon.exe"
Write-Host "  C:\\Windows\\System32\\drivers\\SysmonDrv.sys"

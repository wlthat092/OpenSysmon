#requires -Version 5.1

[CmdletBinding()]
param(
    [string]$ConfigPath = '',
    [switch]$SkipDriverSigning
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Test-IsAdministrator {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

if (-not (Test-IsAdministrator)) {
    throw 'Administrator privileges are required. Re-open PowerShell as Administrator and run install.ps1 again.'
}

$packageRoot = (Resolve-Path -LiteralPath $PSScriptRoot).Path
$dataRoot = Join-Path $env:ProgramData 'OpenSysmon'
$packageConfig = Join-Path $packageRoot 'sysmon_config.xml'
$packageDriver = Join-Path $packageRoot 'SysmonDrv.sys'
$packageUser = Join-Path $packageRoot 'Sysmon.exe'

if (-not $ConfigPath) {
    $ConfigPath = $packageConfig
} elseif (-not [IO.Path]::IsPathRooted($ConfigPath)) {
    $ConfigPath = Join-Path $packageRoot $ConfigPath
}

foreach ($required in @($packageUser, $packageDriver, $ConfigPath)) {
    if (-not (Test-Path -LiteralPath $required -PathType Leaf)) {
        throw "Required package file not found: $required"
    }
}

$systemRoot = $env:SystemRoot
$installedUser = Join-Path $systemRoot 'System32\Sysmon.exe'
$installedDriver = Join-Path $systemRoot 'System32\drivers\SysmonDrv.sys'
$installedConfig = Join-Path $dataRoot 'sysmon_config.xml'

function Stop-ServiceIfPresent {
    param([Parameter(Mandatory = $true)][string]$Name)
    $service = Get-Service -Name $Name -ErrorAction SilentlyContinue
    if ($null -ne $service -and $service.Status -ne 'Stopped') {
        Stop-Service -Name $Name -Force -ErrorAction SilentlyContinue
    }
}

function Test-FilterLoaded {
    param([Parameter(Mandatory = $true)][string]$Name)
    $filters = & fltmc.exe filters 2>$null
    return ($LASTEXITCODE -eq 0 -and $null -ne $filters -and ($filters | Select-String -SimpleMatch $Name -Quiet))
}

function Wait-FilterUnloaded {
    param([int]$TimeoutSeconds = 30)
    $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
    while ((Get-Date) -lt $deadline) {
        if (-not (Test-FilterLoaded -Name 'SysmonDrv')) { return }
        Start-Sleep -Seconds 1
    }
    throw 'SysmonDrv filter did not unload before the timeout.'
}

Write-Host 'Stopping existing OpenSysmon services...' -ForegroundColor Cyan
if (Test-Path -LiteralPath $installedUser) {
    & $installedUser -u force *> $null
}
Stop-ServiceIfPresent -Name 'Sysmon'
Stop-ServiceIfPresent -Name 'SysmonDrv'
if (Test-FilterLoaded -Name 'SysmonDrv') {
    & fltmc.exe unload SysmonDrv 2>$null | Out-Null
    Wait-FilterUnloaded
}

New-Item -ItemType Directory -Path $dataRoot -Force | Out-Null
Copy-Item -LiteralPath $packageUser -Destination $installedUser -Force
Copy-Item -LiteralPath $packageDriver -Destination $installedDriver -Force
Copy-Item -LiteralPath $ConfigPath -Destination $installedConfig -Force

function Ensure-CertificateInStore {
    param(
        [Parameter(Mandatory = $true)]$Certificate,
        [Parameter(Mandatory = $true)][string]$StoreName
    )
    $store = New-Object System.Security.Cryptography.X509Certificates.X509Store($StoreName, 'LocalMachine')
    $store.Open('ReadWrite')
    try {
        if (-not ($store.Certificates | Where-Object { $_.Thumbprint -eq $Certificate.Thumbprint })) {
            $store.Add($Certificate)
        }
    } finally {
        $store.Close()
    }
}

if (-not $SkipDriverSigning) {
    Write-Host 'Preparing a local test certificate and signing SysmonDrv.sys...' -ForegroundColor Cyan
    $cert = Get-ChildItem 'Cert:\LocalMachine\My' |
        Where-Object { $_.Subject -in @('CN=SysmonTest', 'CN=SysmonTestLegacy') -and $_.HasPrivateKey } |
        Sort-Object NotAfter -Descending |
        Select-Object -First 1
    if ($null -eq $cert) {
        $cert = New-SelfSignedCertificate @{
            CertStoreLocation = 'Cert:\LocalMachine\My'
            Type = 'CodeSigningCert'
            DnsName = 'SysmonTestLegacy'
            Subject = 'CN=SysmonTestLegacy'
            KeyUsage = 'DigitalSignature'
            Provider = 'Microsoft Enhanced RSA and AES Cryptographic Provider'
            KeySpec = 'Signature'
            NotAfter = (Get-Date).AddYears(5)
        }
    }
    Ensure-CertificateInStore -Certificate $cert -StoreName 'Root'
    Ensure-CertificateInStore -Certificate $cert -StoreName 'TrustedPublisher'
    $signature = Set-AuthenticodeSignature -FilePath $installedDriver -Certificate $cert -HashAlgorithm SHA256
    if ($signature.Status -ne 'Valid') {
        throw "Driver signing failed with status $($signature.Status). Use a test VM with a signing policy that accepts the local test certificate, or pass -SkipDriverSigning for a pre-signed driver."
    }
}

Write-Host 'Installing OpenSysmon and loading the bundled configuration...' -ForegroundColor Cyan
& $installedUser -i $installedConfig
$installExitCode = $LASTEXITCODE
if ($installExitCode -eq 1073 -or $installExitCode -eq 1056) {
    & $installedUser -c $installedConfig
    if ($LASTEXITCODE -ne 0) { throw "Configuration update failed with exit code $LASTEXITCODE" }
} elseif ($installExitCode -ne 0) {
    throw "OpenSysmon installation failed with exit code $installExitCode"
}

& $installedUser -m
if ($LASTEXITCODE -ne 0) {
    Write-Warning "Event manifest installation returned exit code $LASTEXITCODE. The service was installed, but Event Viewer descriptions may be unavailable."
}

Write-Host "OpenSysmon installed successfully. Configuration: $installedConfig" -ForegroundColor Green
Write-Host 'Use uninstall.ps1 (as Administrator) to remove the services and installed files.'

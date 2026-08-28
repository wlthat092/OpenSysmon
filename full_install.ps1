# Copy driver to System32\drivers
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][ValidateScript({ Test-Path -LiteralPath $_ -PathType Leaf })][string]$DriverSourcePath,
    [Parameter(Mandatory = $true)][ValidateScript({ Test-Path -LiteralPath $_ -PathType Leaf })][string]$SysmonSourcePath,
    [string]$ConfigPath
)

$driverPath = Join-Path $env:SystemRoot 'System32\drivers\SysmonDrv.sys'
$sysmonPath = Join-Path $env:SystemRoot 'System32\Sysmon.exe'
Copy-Item -LiteralPath $DriverSourcePath -Destination $driverPath -Force
Copy-Item -LiteralPath $SysmonSourcePath -Destination $sysmonPath -Force
Write-Host "Files copied"

# Sign the driver with existing cert
$cert = Get-ChildItem Cert:\LocalMachine\My -CodeSigningCert | Where-Object { $_.Subject -like "*SysmonTest*" } | Select-Object -First 1
if ($cert) {
    Set-AuthenticodeSignature -FilePath $driverPath -Certificate $cert -HashAlgorithm SHA256
    Write-Host "Driver signed with existing cert: $($cert.Thumbprint)"
} else {
    Write-Host "ERROR: No signing cert found"
}

# Register minifilter instance
$instancePath = "HKLM:\SYSTEM\CurrentControlSet\Services\SysmonDrv\Instances"
New-Item -Path $instancePath -Force | Out-Null
Set-ItemProperty -Path $instancePath -Name "DefaultInstance" -Value "Sysmon Instance"
$subPath = "$instancePath\Sysmon Instance"
New-Item -Path $subPath -Force | Out-Null
Set-ItemProperty -Path $subPath -Name "Altitude" -Value "385201"
Set-ItemProperty -Path $subPath -Name "Flags" -Value 0 -Type DWord
Write-Host "Minifilter instance registered"

# Create driver service as MANUAL start (NOT boot)
sc.exe create SysmonDrv type= kernel start= demand binPath= $driverPath
sc.exe config SysmonDrv start= demand
Write-Host "Driver service created (manual start)"

# Start driver
sc.exe start SysmonDrv
Write-Host "Driver started"

# Install Sysmon user service via Sysmon.exe -i
if ($ConfigPath) { & $sysmonPath -i $ConfigPath } else { & $sysmonPath -i }
Write-Host "Sysmon installed"

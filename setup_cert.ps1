[CmdletBinding()]
param([Parameter(Mandatory = $true)][ValidateScript({ Test-Path -LiteralPath $_ -PathType Leaf })][string]$DriverSourcePath)

$driverPath = Join-Path $env:SystemRoot 'System32\drivers\SysmonDrv.sys'
$cert = New-SelfSignedCertificate -Subject 'CN=SysmonTest' -Type CodeSigningCert -CertStoreLocation Cert:\LocalMachine\My -NotAfter (Get-Date).AddYears(5)
$store = New-Object System.Security.Cryptography.X509Certificates.X509Store('Root','LocalMachine')
$store.Open('ReadWrite'); $store.Add($cert); $store.Close()
$store2 = New-Object System.Security.Cryptography.X509Certificates.X509Store('TrustedPublisher','LocalMachine')
$store2.Open('ReadWrite'); $store2.Add($cert); $store2.Close()
Copy-Item -LiteralPath $DriverSourcePath -Destination $driverPath -Force
Set-AuthenticodeSignature -FilePath $driverPath -Certificate $cert -HashAlgorithm SHA256
reg delete 'HKLM\SYSTEM\CurrentControlSet\Services\SysmonDrv' /f 2>$null

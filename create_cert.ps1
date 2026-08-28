[CmdletBinding()]
param([Parameter(Mandatory = $true)][ValidateScript({ Test-Path -LiteralPath $_ -PathType Leaf })][string]$DriverPath)

$cert = New-SelfSignedCertificate -CertStoreLocation Cert:\LocalMachine\My -Type CodeSigningCert -Subject 'CN=SysmonTest' -KeyUsage DigitalSignature -NotAfter (Get-Date).AddYears(5)
$store = New-Object System.Security.Cryptography.X509Certificates.X509Store('Root','LocalMachine')
$store.Open('ReadWrite'); $store.Add($cert); $store.Close()
Set-AuthenticodeSignature -FilePath $DriverPath -Certificate $cert -HashAlgorithm SHA256 | Format-List Status, StatusMessage
Get-AuthenticodeSignature $DriverPath | Format-List Status, StatusMessage

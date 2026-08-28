param(
    [int]$ProcessId,
    [string]$ProcessName
)

$ErrorActionPreference = 'Stop'

if (-not $ProcessId) {
    if ([string]::IsNullOrWhiteSpace($ProcessName)) {
        throw 'Specify -ProcessId or -ProcessName.'
    }

    $process = Get-Process -Name $ProcessName -ErrorAction Stop | Select-Object -First 1
    $ProcessId = $process.Id
}

Add-Type @"
using System;
using System.Runtime.InteropServices;

public static class DrvIO {
    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    public static extern IntPtr CreateFileW(
        string name,
        uint desiredAccess,
        uint shareMode,
        IntPtr securityAttributes,
        uint creationDisposition,
        uint flagsAndAttributes,
        IntPtr templateFile);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool DeviceIoControl(
        IntPtr device,
        uint ioControlCode,
        byte[] inBuffer,
        uint inBufferSize,
        byte[] outBuffer,
        uint outBufferSize,
        out uint bytesReturned,
        IntPtr overlapped);

    [DllImport("kernel32.dll")]
    public static extern bool CloseHandle(IntPtr handle);
}
"@

$handle = [DrvIO]::CreateFileW("\\.\Sysmon", 0xC0000000, 0, [IntPtr]::Zero, 3, 0, [IntPtr]::Zero)
if ($handle -eq [IntPtr]::new(-1)) {
    throw "CreateFileW failed: $([Runtime.InteropServices.Marshal]::GetLastWin32Error())"
}

try {
    $input = New-Object byte[] 8
    [BitConverter]::GetBytes([uint32]$ProcessId).CopyTo($input, 0)
    [BitConverter]::GetBytes([uint32]1).CopyTo($input, 4)

    $output = New-Object byte[] 4098
    [uint32]$returned = 0
    $ok = [DrvIO]::DeviceIoControl(
        $handle,
        0x8340000c,
        $input,
        [uint32]$input.Length,
        $output,
        [uint32]$output.Length,
        [ref]$returned,
        [IntPtr]::Zero)

    if (-not $ok) {
        throw "DeviceIoControl failed: $([Runtime.InteropServices.Marshal]::GetLastWin32Error())"
    }

    $guid = [Text.Encoding]::Unicode.GetString($output, 24, 80).Trim([char]0)
    $image = [Text.Encoding]::Unicode.GetString($output, 104, 520).Trim([char]0)
    $userSid = [Text.Encoding]::Unicode.GetString($output, 624, 256).Trim([char]0)

    Write-Host ("BytesReturned={0}" -f $returned)
    Write-Host ("Signature=0x{0:X8}" -f [BitConverter]::ToUInt32($output, 0))
    Write-Host ("Version={0}" -f [BitConverter]::ToUInt32($output, 4))
    Write-Host ("ProcessId={0}" -f [BitConverter]::ToUInt32($output, 8))
    Write-Host ("CreateTime={0}" -f [BitConverter]::ToUInt64($output, 16))
    Write-Host ("ProcessGuid={0}" -f $guid)
    Write-Host ("Image={0}" -f $image)
    Write-Host ("UserSid={0}" -f $userSid)
}
finally {
    [DrvIO]::CloseHandle($handle) | Out-Null
}

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][ValidateNotNullOrEmpty()][string]$RemoteRoot,
    [string]$ConfigPath = (Join-Path $RemoteRoot 'sysmon_config.xml')
)

$ErrorActionPreference = 'Stop'
$logPath = Join-Path $RemoteRoot 'driver_reload.log'
$systemDriver = Join-Path $env:SystemRoot 'System32\drivers\SysmonDrv.sys'
$sysmonExe = "$env:SystemRoot\System32\Sysmon.exe"

function Write-Log {
    param([string]$Message)

    $line = '{0} {1}' -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss.fff'), $Message
    $line | Tee-Object -FilePath $logPath -Append
}

function Capture-Command {
    param([scriptblock]$Action)

    try {
        & $Action 2>&1 | ForEach-Object {
            Write-Log ($_ | Out-String).TrimEnd()
        }
    } catch {
        Write-Log ('ERROR: ' + $_.Exception.Message)
        throw
    }
}

function Get-ServiceStateText {
    param([string]$Name)

    try {
        $query = & sc.exe query $Name 2>&1
        foreach ($line in $query) {
            if ($line -match 'STATE\s+:\s+\d+\s+(\S+)') {
                return $matches[1]
            }
        }
    } catch {
    }

    return 'UNKNOWN'
}

function Wait-ForState {
    param(
        [string]$Name,
        [string]$DesiredState,
        [int]$TimeoutSeconds
    )

    $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
    do {
        $state = Get-ServiceStateText -Name $Name
        Write-Log ("state[{0}]={1}" -f $Name, $state)
        if ($state -eq $DesiredState) {
            return $true
        }

        Start-Sleep -Seconds 1
    } while ((Get-Date) -lt $deadline)

    return $false
}

Remove-Item -LiteralPath $logPath -Force -ErrorAction SilentlyContinue
Write-Log 'reload_begin'
if (Test-Path -LiteralPath $systemDriver) {
    Write-Log ('system_driver_size=' + (Get-Item -LiteralPath $systemDriver).Length)
}

Capture-Command { sc.exe stop Sysmon }
Start-Sleep -Seconds 2

Capture-Command { sc.exe stop SysmonDrv }
if (-not (Wait-ForState -Name 'SysmonDrv' -DesiredState 'STOPPED' -TimeoutSeconds 15)) {
    Write-Log 'sc_stop_timeout_try_fltmc'
    Capture-Command { fltmc unload SysmonDrv }
    if (-not (Wait-ForState -Name 'SysmonDrv' -DesiredState 'STOPPED' -TimeoutSeconds 20)) {
        Write-Log 'reload_abort_driver_not_stopped'
        exit 1
    }
}

Capture-Command { sc.exe start SysmonDrv }
if (-not (Wait-ForState -Name 'SysmonDrv' -DesiredState 'RUNNING' -TimeoutSeconds 20)) {
    Write-Log 'reload_abort_driver_not_running'
    exit 1
}

if (Test-Path -LiteralPath $sysmonExe) {
    Capture-Command { & $sysmonExe -c $ConfigPath }
}

Capture-Command { sc.exe start Sysmon }
Wait-ForState -Name 'Sysmon' -DesiredState 'RUNNING' -TimeoutSeconds 20 | Out-Null

Write-Log 'reload_end'

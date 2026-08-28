param(
    [string]$Treeish
)

$ErrorActionPreference = "Stop"

$repoRoot = Split-Path (Split-Path $PSScriptRoot -Parent) -Parent

function Get-TrackedText {
    param(
        [Parameter(Mandatory = $true)]
        [string]$RelativePath
    )

    try {
        if ([string]::IsNullOrWhiteSpace($Treeish)) {
            $path = Join-Path $repoRoot $RelativePath
            if (-not (Test-Path $path)) {
                return ""
            }

            return Get-Content $path -Raw
        }

        return git -C $repoRoot show "${Treeish}:${RelativePath}" 2>$null
    } catch {
        return ""
    }
}

$eventHeader = Get-TrackedText "SysmonUser/include/event.h"
$eventFields = Get-TrackedText "SysmonUser/include/event_field_tables.inc"
$dnsTrace = Get-TrackedText "SysmonUser/src/dns_trace.cpp"
$sourceCommon = Get-TrackedText "SysmonUser/src/source_common.cpp"
$sourceCommonHeader = Get-TrackedText "SysmonUser/include/source_common.h"
$processStore = Get-TrackedText "SysmonUser/src/process_store.cpp"
$outputCpp = Get-TrackedText "SysmonUser/src/output.cpp"
$driverEventHeader = Get-TrackedText "SysmonDrv/include/event.h"
$driverDns = Get-TrackedText "SysmonDrv/src/dns.c"
$legacySourceCommonTokens = @(
    'SYSMON_' + 'LOCAL_PROCESS_CACHE_BUCKET_COUNT',
    'g_' + 'LocalProcessCache',
    'Sysmon' + 'RememberProcessCacheResponse',
    'Sysmon' + 'LookupCachedProcessMetadata',
    'Sysmon' + 'TryRememberDnsEventInProcessCache',
    'Sysmon' + 'CleanupLocalProcessCache'
) -join '|'
$legacySourceCommonDeclarations = @(
    'Sysmon' + 'TryRememberDnsEventInProcessCache',
    'Sysmon' + 'CleanupLocalProcessCache'
) -join '|'

$failures = @()

if ($eventHeader -notmatch 'typedef struct _SYSMON_EVENT_DNS_QUERY_PAYLOAD[\s\S]*SYSMON_EVENT_STRING_REF QueryStatus;') {
    $failures += "DnsQuery payload QueryStatus is not modeled as SYSMON_EVENT_STRING_REF."
}

if ($eventFields -notmatch 'SYSMON_DEFINE_EVENT_FIELD_TABLE\(DnsQuery, SYSMON_EVENT_DNS_QUERY_PAYLOAD,[\s\S]*EVT_FIELD_QUERY_STATUS,\s*SYSMON_FIELD_STRINGREF,\s*QueryStatus\)') {
    $failures += "DnsQuery schema still treats QueryStatus as a non-string field."
}

if ($dnsTrace -notmatch 'ERROR_INVALID_PARAMETER|queryStatus\s*==\s*87') {
    $failures += "dns_trace.cpp does not suppress QueryStatus=87 like the original Sysmon ETW path."
}

if ($dnsTrace -notmatch 'SysmonAddStringField\(eventBuffer,\s*(sizeof\(eventBuffer\)|eventBufferSize),\s*&builder,\s*&payload->QueryStatus,') {
    $failures += "dns_trace.cpp is not emitting QueryStatus through the string-field path."
}

if (($dnsTrace + "`n" + $sourceCommon + "`n" + $processStore) -notmatch 'SYSMON_DNS_DEDUP_PER_PROCESS_LIMIT\s+1000') {
    $failures += "DnsQuery implementation does not mirror the original per-process DNS deduplication budget."
}

if ($dnsTrace -match 'SYSMON_DNS_DEDUP_PROCESS_BUCKET_COUNT|typedef struct _SYSMON_DNS_DEDUP_PROCESS|DedupProcessBuckets|DedupProcesses') {
    $failures += "dns_trace.cpp still owns a standalone DNS process table instead of using the shared process-store-backed dedup state."
}

if ($dnsTrace -notmatch 'SysmonProcessStoreRememberDnsEvent\s*\(') {
    $failures += "dns_trace.cpp is not using the process-store DNS dedup path."
}

if ($dnsTrace -notmatch 'SysmonCollectProcessMetadataAtTime\s*\(') {
    $failures += "dns_trace.cpp is not using timestamp-aware metadata lookup for Event 22."
}

if ($sourceCommonHeader -match $legacySourceCommonDeclarations) {
    $failures += "source_common.h still declares the intermediate local-process-cache helpers."
}

if ($sourceCommon -match $legacySourceCommonTokens) {
    $failures += "source_common.cpp still owns the intermediate local process cache."
}

if ($processStore -notmatch 'SysmonProcessStoreRememberDnsEventLocked\s*\(') {
    $failures += "process_store.cpp is missing the Event 22 dedup implementation."
}

if ($processStore -notmatch 'return _wcsicmp\(Entry->QueryName,\s*QueryName\)\s*==\s*0[\s\S]*_wcsicmp\(Entry->QueryStatus,\s*QueryStatus\)\s*==\s*0[\s\S]*_wcsicmp\(Entry->QueryResults,\s*QueryResults\)\s*==\s*0;') {
    $failures += "process_store.cpp is not comparing the original DNS dedup key fields (QueryName/QueryStatus/QueryResults) case-insensitively."
}

if ($processStore -match 'QueryType') {
    $failures += "process_store.cpp should not pull QueryType into the Event 22 dedup key."
}

if ($dnsTrace -notmatch 'if\s*\(\s*!SysmonProcessStoreRememberDnsEvent\s*\([\s\S]*?if\s*\(\s*queryStatus\s*==\s*87\s*\)') {
    $failures += "dns_trace.cpp is not applying original-style duplicate suppression before the QueryStatus=87 drop path."
}

if ($dnsTrace -notmatch 'SysmonProcessStoreRememberDnsEvent[\s\S]*if\s*\(\s*queryStatus\s*==\s*87\s*\)') {
    $failures += "dns_trace.cpp is not preserving original-style dedup-before-status-87 filtering."
}

if ($processStore -notmatch 'if\s*\(\s*instance\s*==\s*NULL\s*\)\s*\{[\s\S]*?return TRUE;\s*\}') {
    $failures += "process_store.cpp should fail open when the shared process store does not yet know the PID instance, like the original Sysmon DNS path."
}

if ($outputCpp -match 'EventId == SysmonEventDnsQuery[\s\S]*EVT_FIELD_QUERY_STATUS') {
    $failures += "output.cpp still relies on the DnsQuery QueryStatus UInt32->UnicodeString special case."
}

if ($driverEventHeader -notmatch 'typedef struct _SYSMON_EVENT_DNS_QUERY_PAYLOAD[\s\S]*SYSMON_EVENT_STRING_REF QueryStatus;') {
    $failures += "Driver DnsQuery payload QueryStatus is not modeled as SYSMON_EVENT_STRING_REF."
}

if ($driverDns -notmatch 'QueryStatus\s*==\s*87') {
    $failures += "Driver dns.c does not suppress QueryStatus=87 like the original Sysmon ETW path."
}

if ($driverDns -notmatch 'SysmonAddStringField\(event,\s*&builder,\s*&eventData->QueryStatus,') {
    $failures += "Driver dns.c is not emitting QueryStatus through the string-field path."
}

if ($failures.Count -ne 0) {
    Write-Host "DnsQuery implementation verification failed:" -ForegroundColor Red
    foreach ($failure in $failures) {
        Write-Host "  $failure" -ForegroundColor Red
    }
    exit 1
}

if ([string]::IsNullOrWhiteSpace($Treeish)) {
    Write-Host "OK: working tree DnsQuery implementation matches the expected contract" -ForegroundColor Green
} else {
    Write-Host "OK: ${Treeish} DnsQuery implementation matches the expected contract" -ForegroundColor Green
}

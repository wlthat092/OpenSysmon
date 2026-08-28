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

$vcxproj = Get-TrackedText "SysmonUser/SysmonUser.vcxproj"
$processStoreHeader = Get-TrackedText "SysmonUser/include/process_store.h"
$processStore = Get-TrackedText "SysmonUser/src/process_store.cpp"
$sourceCommonHeader = Get-TrackedText "SysmonUser/include/source_common.h"
$sourceCommon = Get-TrackedText "SysmonUser/src/source_common.cpp"
$dnsTrace = Get-TrackedText "SysmonUser/src/dns_trace.cpp"
$service = Get-TrackedText "SysmonUser/src/service.cpp"
$legacySourceCommonOwnershipTokens = @(
    'SYSMON_' + 'LOCAL_PROCESS_CACHE_BUCKET_COUNT',
    'g_' + 'LocalProcessCache',
    'Sysmon' + 'RememberProcessCacheResponse',
    'Sysmon' + 'LookupCachedProcessMetadata'
) -join '|'

$failures = @()

if ([string]::IsNullOrWhiteSpace($processStoreHeader)) {
    $failures += "process_store.h is missing."
}

if ([string]::IsNullOrWhiteSpace($processStore)) {
    $failures += "process_store.cpp is missing."
}

if ($vcxproj -notmatch 'include\\process_store\.h') {
    $failures += "SysmonUser.vcxproj does not include process_store.h."
}

if ($vcxproj -notmatch 'src\\process_store\.cpp') {
    $failures += "SysmonUser.vcxproj does not include process_store.cpp."
}

if ($processStoreHeader -notmatch 'SysmonProcessStoreEnsureInitialized\s*\(') {
    $failures += "process_store.h is missing SysmonProcessStoreEnsureInitialized."
}

if ($processStoreHeader -notmatch 'SysmonProcessStoreCleanup\s*\(') {
    $failures += "process_store.h is missing SysmonProcessStoreCleanup."
}

if ($processStoreHeader -notmatch 'SysmonProcessStoreLookupProcessByPidAndTime\s*\(') {
    $failures += "process_store.h is missing PID+time lookup."
}

if ($processStoreHeader -notmatch 'SysmonProcessStoreInsertProcessCacheResponse\s*\(') {
    $failures += "process_store.h is missing process-cache insertion."
}

if ($processStoreHeader -notmatch 'SysmonProcessStoreTouch\s*\(') {
    $failures += "process_store.h is missing SysmonProcessStoreTouch."
}

if ($processStoreHeader -notmatch 'SysmonProcessStoreRememberDnsEvent\s*\(') {
    $failures += "process_store.h is missing process-store DNS dedup."
}

if ($processStoreHeader -notmatch 'SysmonProcessStoreResolveImage\s*\(') {
    $failures += "process_store.h is missing process-store image resolution."
}

if ($processStore -notmatch 'SYSMON_PROCESS_STORE_BUCKET_COUNT\s+8') {
    $failures += "process_store.cpp is missing the original-style 8-bucket PID store."
}

if ($processStore -notmatch 'SYSMON_PROCESS_STORE_STALE_WINDOW\s+600000000ull') {
    $failures += "process_store.cpp is missing the 60-second stale eviction window."
}

if ($processStore -match 'SYSMON_PROCESS_STORE_ACTIVITY_CAPACITY') {
    $failures += "process_store.cpp should not keep the clone-style fixed initial activity capacity constant."
}

if ($processStore -match 'g_ProcessStore\.ActivityHeapBase\s*=\s*\r?\n\s*\(PSYSMON_PROCESS_ACTIVITY_ENTRY\)SYSMON_ALLOC\(\s*\r?\n\s*sizeof\(\*g_ProcessStore\.ActivityHeapBase\)\s*\*\s*\r?\n\s*SYSMON_PROCESS_STORE_ACTIVITY_CAPACITY\)') {
    $failures += "process_store.cpp should not preallocate the activity buffer during InitOnce."
}

if ($processStore -match 'oldCapacity\s*\*\s*2') {
    $failures += "process_store.cpp should not use clone-style doubling for activity buffer growth."
}

if ($processStore -notmatch 'grownCapacity\s*=\s*oldCapacity\s*\+\s*\(oldCapacity\s*>>\s*1\)') {
    $failures += "process_store.cpp is missing the original-style 1.5x activity buffer growth shape."
}

if ($processStore -notmatch 'if\s*\(oldCapacity\s*==\s*0\)\s*\{\s*newCapacity\s*=\s*minCapacity;') {
    $failures += "process_store.cpp should lazily allocate the activity buffer on first use."
}

if ($processStore -notmatch 'SYSMON_DNS_DEDUP_PER_PROCESS_LIMIT\s+1000') {
    $failures += "process_store.cpp is missing the original per-process DNS dedup budget."
}

if ($processStore -notmatch 'typedef struct _SYSMON_DNS_DEDUP_ENTRY') {
    $failures += "process_store.cpp is missing the DNS dedup entry structure."
}

if ($processStore -notmatch 'typedef struct _SYSMON_PROCESS_NODE') {
    $failures += "process_store.cpp is missing the PID node structure."
}

if ($processStore -notmatch 'typedef struct _SYSMON_PROCESS_INSTANCE') {
    $failures += "process_store.cpp is missing the process-instance structure."
}

if ($processStore -notmatch 'typedef struct _SYSMON_PROCESS_ACTIVITY_ENTRY') {
    $failures += "process_store.cpp is missing the activity-entry structure."
}

if ($processStore -notmatch 'typedef struct _SYSMON_PROCESS_STORE') {
    $failures += "process_store.cpp is missing the top-level process-store structure."
}

if ($processStore -notmatch 'static SYSMON_PROCESS_STORE g_ProcessStore') {
    $failures += "process_store.cpp is missing the global process-store instance."
}

if ($processStore -notmatch 'static INIT_ONCE g_ProcessStoreInitOnce') {
    $failures += "process_store.cpp is missing the process-store InitOnce gate."
}

if ($processStore -notmatch 'static volatile LONG g_ProcessStoreInitialized') {
    $failures += "process_store.cpp is missing the process-store initialized flag."
}

if ($processStore -notmatch 'SysmonProcessStoreInitOnceCallback\s*\(') {
    $failures += "process_store.cpp is missing the InitOnce callback."
}

if ($processStore -notmatch 'SysmonProcessStoreFreeDnsEntriesLocked\s*\(') {
    $failures += "process_store.cpp is missing DNS dedup cleanup."
}

if ($processStore -notmatch 'SysmonProcessStoreFreeNodeLocked\s*\(') {
    $failures += "process_store.cpp is missing PID-node cleanup."
}

if ($processStore -notmatch 'SysmonProcessStoreRecordActivityLocked\s*\(') {
    $failures += "process_store.cpp is missing activity recording."
}

if ($processStore -notmatch 'SysmonProcessStoreEvictStaleNodesLocked\s*\(') {
    $failures += "process_store.cpp is missing stale-node eviction."
}

if ($processStore -notmatch 'LowerTimeBound') {
    $failures += "process_store.cpp is missing the lower time bound on process instances."
}

if ($processStore -notmatch 'UpperTimeBound') {
    $failures += "process_store.cpp is missing the upper time bound on process instances."
}

if ($processStore -notmatch 'SysmonProcessStoreSelectBucket\s*\(') {
    $failures += "process_store.cpp is missing PID bucket selection."
}

if ($processStore -notmatch 'SysmonProcessStoreFindNodeLocked\s*\(') {
    $failures += "process_store.cpp is missing PID node lookup."
}

if ($processStore -notmatch 'SysmonProcessStoreFindOrCreateNodeLocked\s*\(') {
    $failures += "process_store.cpp is missing PID node insertion."
}

if ($processStore -notmatch 'SysmonProcessStoreSelectInstanceLocked\s*\(') {
    $failures += "process_store.cpp is missing PID+time instance selection."
}

if ($processStore -notmatch 'SysmonProcessStoreLookupProcessByPidAndTime\s*\(') {
    $failures += "process_store.cpp is missing store lookup by PID and time."
}

if ($processStore -notmatch 'SysmonProcessStoreInsertProcessCacheResponse\s*\(') {
    $failures += "process_store.cpp is missing process-cache insertion."
}

if ($processStore -notmatch 'SysmonProcessStoreRememberDnsEventLocked\s*\(') {
    $failures += "process_store.cpp is missing instance-local DNS dedup."
}

if ($processStore -match 'QueryType') {
    $failures += "process_store.cpp should not use QueryType in the Event 22 dedup key."
}

if ($processStore -notmatch 'SysmonProcessStoreRecordActivityLocked\s*\(\s*ProcessId,\s*instance->LastSeenTime\s*\)') {
    $failures += "process_store.cpp is not recording process-store activity on PID+time lookup hits."
}

if ($processStore -notmatch 'SysmonProcessStoreRememberDnsEvent\s*\([\s\S]*?SysmonProcessStoreRecordActivityLocked\s*\(') {
    $failures += "process_store.cpp is not recording process-store activity from Event 22 DNS dedup."
}

if ($processStore -notmatch 'node->LastActivityTime\s*!=\s*entry\.Timestamp') {
    $failures += "process_store.cpp is missing the stale-eviction guard that ignores superseded activity entries."
}

if ($processStore -match 'node->LastActivityTime\s*\+\s*SYSMON_PROCESS_STORE_STALE_WINDOW\s*<\s*Now') {
    $failures += "process_store.cpp should not keep the clone-only second stale-window guard in stale eviction."
}

if ($sourceCommonHeader -notmatch 'SysmonCollectProcessMetadataAtTime\s*\(') {
    $failures += "source_common.h is missing the timestamp-aware metadata helper."
}

if ($sourceCommon -notmatch 'SysmonProcessStoreLookupProcessByPidAndTime\s*\(') {
    $failures += "source_common.cpp is not using process-store lookup for metadata."
}

if ($sourceCommon -notmatch 'SysmonProcessStoreInsertProcessCacheResponse\s*\(') {
    $failures += "source_common.cpp is not hydrating the process store after PROCESS_CACHE IOCTL success."
}

if ($sourceCommon -notmatch 'SysmonProcessStoreResolveImage\s*\(') {
    $failures += "source_common.cpp is not using process-store image resolution."
}

if ($dnsTrace -notmatch 'SysmonProcessStoreRememberDnsEvent\s*\(') {
    $failures += "dns_trace.cpp is missing process-store backed DNS dedup."
}

if ($service -notmatch 'SysmonProcessStoreCleanup\s*\(') {
    $failures += "service.cpp is not cleaning up the process store."
}

if ($processStore -notmatch 'ProcessId & \(SYSMON_PROCESS_STORE_BUCKET_COUNT - 1\)') {
    $failures += "process_store.cpp is not hashing PIDs into the original-style 8-bucket table."
}

if ($sourceCommon -match $legacySourceCommonOwnershipTokens) {
    $failures += "source_common.cpp still contains process-store ownership leftovers."
}

if ($failures.Count -ne 0) {
    Write-Host "ProcessStore verification failed:" -ForegroundColor Red
    foreach ($failure in $failures) {
        Write-Host "  $failure" -ForegroundColor Red
    }
    exit 1
}

if ([string]::IsNullOrWhiteSpace($Treeish)) {
    Write-Host "OK: working tree process-store reconstruction matches the expected contract" -ForegroundColor Green
} else {
    Write-Host "OK: ${Treeish} process-store reconstruction matches the expected contract" -ForegroundColor Green
}

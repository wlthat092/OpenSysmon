#pragma once

#include "common.h"
#include "protocol.h"

BOOL
SysmonProcessStoreEnsureInitialized(void);

void
SysmonProcessStoreCleanup(void);

BOOL
SysmonProcessStoreLookupProcessByPidAndTime(
    _In_ DWORD ProcessId,
    _In_opt_ const ULONGLONG *Timestamp,
    _Out_ PSYSMON_PROCESS_CACHE_RESPONSE Response);

BOOL
SysmonProcessStoreInsertProcessCacheResponse(
    _In_ DWORD ProcessId,
    _In_ const SYSMON_PROCESS_CACHE_RESPONSE *Response);

void
SysmonProcessStoreTouch(
    _In_ DWORD ProcessId,
    _In_opt_ const ULONGLONG *Timestamp);

BOOL
SysmonProcessStoreRememberDnsEvent(
    _In_ DWORD ProcessId,
    _In_opt_ const ULONGLONG *Timestamp,
    _In_z_ PCWSTR QueryName,
    _In_z_ PCWSTR QueryStatus,
    _In_z_ PCWSTR QueryResults);

BOOL
SysmonProcessStoreResolveImage(
    _In_ DWORD ProcessId,
    _In_opt_ const ULONGLONG *Timestamp,
    _Out_writes_(BufferChars) PWCHAR Buffer,
    _In_ size_t BufferChars);

#include "../include/source_common.h"

#include "../include/event.h"
#include "../include/process_store.h"
#include "../include/protocol.h"
#include "../include/runtime.hpp"
#include "../include/service.h"

#include <psapi.h>
#include <sddl.h>
#include <wincrypt.h>

#ifndef PROCESS_QUERY_LIMITED_INFORMATION
#define PROCESS_QUERY_LIMITED_INFORMATION 0x1000
#endif

static void
SysmonPopulateMetadataFromCacheResponse(
    _Out_ PSYSMON_PROCESS_METADATA Metadata,
    _In_ const SYSMON_PROCESS_CACHE_RESPONSE *Response)
{
    if (Metadata == NULL || Response == NULL) {
        return;
    }

    Metadata->CreateTime = Response->CreateTime;
    SysmonCopyOrPlaceholder(
        Metadata->ProcessGuid,
        _countof(Metadata->ProcessGuid),
        Response->ProcessGuid);
    SysmonCopyOrPlaceholder(
        Metadata->Image,
        _countof(Metadata->Image),
        Response->Image);
    if (!SysmonResolveSidStringToAccountName(
            Response->UserSid,
            Metadata->UserName,
            _countof(Metadata->UserName))) {
        SysmonCopyOrPlaceholder(
            Metadata->UserName,
            _countof(Metadata->UserName),
            Response->UserSid);
    }
}

void
SysmonCopyOrPlaceholder(
    _Out_writes_(BufferChars) PWCHAR Buffer,
    _In_ size_t BufferChars,
    _In_opt_z_ PCWSTR Value)
{
    if (Buffer == NULL || BufferChars == 0) {
        return;
    }

    if (Value == NULL || Value[0] == L'\0') {
        wcscpy_s(Buffer, BufferChars, L"-");
    } else {
        wcscpy_s(Buffer, BufferChars, Value);
    }
}

BOOL
SysmonHasValueString(
    _In_opt_z_ PCWSTR Value)
{
    return Value != NULL &&
        Value[0] != L'\0' &&
        !(Value[0] == L'-' && Value[1] == L'\0');
}

BOOL
SysmonFormatCurrentUtcTime(
    _Out_writes_(BufferChars) PWCHAR Buffer,
    _In_ size_t BufferChars,
    _Out_opt_ PULONGLONG Timestamp)
{
    return SysmonFormatSyntheticUtcTimestamp(0, Buffer, BufferChars, Timestamp);
}

void
SysmonResolveAccountName(
    _In_opt_ PSID Sid,
    _Out_writes_(BufferChars) PWCHAR Buffer,
    _In_ size_t BufferChars)
{
    WCHAR userName[128];
    WCHAR domainName[128];
    DWORD userNameChars = (DWORD)_countof(userName);
    DWORD domainNameChars = (DWORD)_countof(domainName);
    SID_NAME_USE sidUse;

    if (Buffer == NULL || BufferChars == 0) {
        return;
    }

    if (Sid != NULL &&
        LookupAccountSidW(
            NULL,
            Sid,
            userName,
            &userNameChars,
            domainName,
            &domainNameChars,
            &sidUse) &&
        userName[0] != L'\0') {
        if (domainName[0] != L'\0') {
            _snwprintf_s(
                Buffer,
                BufferChars,
                _TRUNCATE,
                L"%ls\\%ls",
                domainName,
                userName);
        } else {
            SysmonCopyOrPlaceholder(Buffer, BufferChars, userName);
        }
        return;
    }

    if (Sid != NULL) {
        LPWSTR sidText = NULL;

        if (ConvertSidToStringSidW(Sid, &sidText)) {
            SysmonCopyOrPlaceholder(Buffer, BufferChars, sidText);
            LocalFree(sidText);
            return;
        }
    }

    SysmonCopyOrPlaceholder(Buffer, BufferChars, L"-");
}

static BOOL
SysmonResolveProcessImageFromHandle(
    _In_ HANDLE ProcessHandle,
    _Out_writes_(BufferChars) PWCHAR Buffer,
    _In_ size_t BufferChars)
{
    DWORD imageChars;

    if (ProcessHandle == NULL || Buffer == NULL || BufferChars == 0) {
        return FALSE;
    }

    imageChars = (DWORD)BufferChars;
    if (QueryFullProcessImageNameW(ProcessHandle, 0, Buffer, &imageChars)) {
        return TRUE;
    }

    imageChars = (DWORD)BufferChars;
    if (GetProcessImageFileNameW(ProcessHandle, Buffer, imageChars) != 0) {
        return TRUE;
    }

    SysmonCopyOrPlaceholder(Buffer, BufferChars, L"-");
    return FALSE;
}

BOOL
SysmonGenerateProcessGuid(
    _In_ DWORD ProcessId,
    _In_ ULONGLONG CreateTime,
    _Out_writes_(BufferChars) PWCHAR Buffer,
    _In_ size_t BufferChars)
{
    static const WCHAR g_HexDigits[] = L"0123456789abcdef";
    HCRYPTPROV provider = 0;
    HCRYPTHASH hash = 0;
    BYTE digest[16];
    DWORD digestSize = sizeof(digest);
    BYTE source[sizeof(DWORD) + sizeof(ULONGLONG)];
    size_t index;
    BOOL success = FALSE;

    if (Buffer == NULL || BufferChars < 39) {
        return FALSE;
    }

    CopyMemory(source, &ProcessId, sizeof(ProcessId));
    CopyMemory(source + sizeof(ProcessId), &CreateTime, sizeof(CreateTime));

    if (!CryptAcquireContextW(&provider, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) {
        goto cleanup;
    }

    if (!CryptCreateHash(provider, CALG_MD5, 0, 0, &hash)) {
        goto cleanup;
    }

    if (!CryptHashData(hash, source, sizeof(source), 0)) {
        goto cleanup;
    }

    if (!CryptGetHashParam(hash, HP_HASHVAL, digest, &digestSize, 0) ||
        digestSize != sizeof(digest)) {
        goto cleanup;
    }

    Buffer[0] = L'{';
    for (index = 0; index < 4; index++) {
        Buffer[1 + index * 2] = g_HexDigits[(digest[index] >> 4) & 0x0F];
        Buffer[2 + index * 2] = g_HexDigits[digest[index] & 0x0F];
    }
    Buffer[9] = L'-';
    for (index = 0; index < 2; index++) {
        Buffer[10 + index * 2] = g_HexDigits[(digest[4 + index] >> 4) & 0x0F];
        Buffer[11 + index * 2] = g_HexDigits[digest[4 + index] & 0x0F];
    }
    Buffer[14] = L'-';
    for (index = 0; index < 2; index++) {
        Buffer[15 + index * 2] = g_HexDigits[(digest[6 + index] >> 4) & 0x0F];
        Buffer[16 + index * 2] = g_HexDigits[digest[6 + index] & 0x0F];
    }
    Buffer[19] = L'-';
    for (index = 0; index < 2; index++) {
        Buffer[20 + index * 2] = g_HexDigits[(digest[8 + index] >> 4) & 0x0F];
        Buffer[21 + index * 2] = g_HexDigits[digest[8 + index] & 0x0F];
    }
    Buffer[24] = L'-';
    for (index = 0; index < 6; index++) {
        Buffer[25 + index * 2] = g_HexDigits[(digest[10 + index] >> 4) & 0x0F];
        Buffer[26 + index * 2] = g_HexDigits[digest[10 + index] & 0x0F];
    }
    Buffer[37] = L'}';
    Buffer[38] = L'\0';
    success = TRUE;

cleanup:
    if (hash != 0) {
        CryptDestroyHash(hash);
    }
    if (provider != 0) {
        CryptReleaseContext(provider, 0);
    }
    return success;
}

/* Negative PID cache (U8): avoid repeatedly paying OpenProcess/token/SID work
   for PIDs that recently failed to open (dead or access-denied) while their
   events are still being delivered. Entries are time-bounded so a recycled PID
   is retried after the TTL. */
#define SYSMON_NEGATIVE_PID_CACHE_SIZE  64
#define SYSMON_NEGATIVE_PID_CACHE_TTL_MS 5000

struct SYSMON_NEGATIVE_PID_ENTRY {
    DWORD Pid;
    ULONGLONG ExpireTick;
};

static SRWLOCK g_NegativePidLock = SRWLOCK_INIT;
static SYSMON_NEGATIVE_PID_ENTRY g_NegativePidCache[SYSMON_NEGATIVE_PID_CACHE_SIZE];

static BOOL
SysmonIsPidNegativeCached(_In_ DWORD ProcessId)
{
    ULONGLONG now = (ULONGLONG)GetTickCount64();
    BOOL cached = FALSE;
    LONG i;

    if (ProcessId == 0) {
        return FALSE;
    }

    AcquireSRWLockExclusive(&g_NegativePidLock);
    for (i = 0; i < SYSMON_NEGATIVE_PID_CACHE_SIZE; i++) {
        if (g_NegativePidCache[i].Pid == ProcessId) {
            if (g_NegativePidCache[i].ExpireTick >= now) {
                cached = TRUE;
            } else {
                g_NegativePidCache[i].Pid = 0;  /* expired: reuse the slot */
            }
            break;
        }
    }
    ReleaseSRWLockExclusive(&g_NegativePidLock);

    return cached;
}

static void
SysmonCachePidNegative(_In_ DWORD ProcessId)
{
    ULONGLONG now = (ULONGLONG)GetTickCount64();
    LONG i;

    if (ProcessId == 0) {
        return;
    }

    AcquireSRWLockExclusive(&g_NegativePidLock);
    for (i = 0; i < SYSMON_NEGATIVE_PID_CACHE_SIZE; i++) {
        /* Reuse the same PID, a free slot, or an already-expired slot. */
        if (g_NegativePidCache[i].Pid == ProcessId ||
            g_NegativePidCache[i].Pid == 0 ||
            g_NegativePidCache[i].ExpireTick < now) {
            g_NegativePidCache[i].Pid = ProcessId;
            g_NegativePidCache[i].ExpireTick = now + SYSMON_NEGATIVE_PID_CACHE_TTL_MS;
            ReleaseSRWLockExclusive(&g_NegativePidLock);
            return;
        }
    }
    /* All slots hold live, distinct PIDs: evict the one expiring soonest so new
       failures are not stuck reusing a single slot (P2 in the review). */
    {
        LONG oldest = 0;
        ULONGLONG oldestTick = g_NegativePidCache[0].ExpireTick;

        for (i = 1; i < SYSMON_NEGATIVE_PID_CACHE_SIZE; i++) {
            if (g_NegativePidCache[i].ExpireTick < oldestTick) {
                oldestTick = g_NegativePidCache[i].ExpireTick;
                oldest = i;
            }
        }
        g_NegativePidCache[oldest].Pid = ProcessId;
        g_NegativePidCache[oldest].ExpireTick = now + SYSMON_NEGATIVE_PID_CACHE_TTL_MS;
    }
    ReleaseSRWLockExclusive(&g_NegativePidLock);
}

BOOL
SysmonCollectProcessMetadataAtTime(
    _In_opt_ PSYSMON_SERVICE_CONTEXT ServiceContext,
    _In_ DWORD ProcessId,
    _In_opt_ const ULONGLONG *Timestamp,
    _Out_ PSYSMON_PROCESS_METADATA Metadata)
{
    HANDLE processHandle = NULL;
    HANDLE tokenHandle = NULL;
    FILETIME createTime;
    FILETIME exitTime;
    FILETIME kernelTime;
    FILETIME userTime;
    DWORD sidSize = 0;
    PTOKEN_USER tokenUser = NULL;
    SYSMON_PROCESS_CACHE_RESPONSE cachedMetadata;
    BOOL cacheHit = FALSE;
    BOOL success = FALSE;

    if (Metadata == NULL) {
        return FALSE;
    }

    ZeroMemory(Metadata, sizeof(*Metadata));
    Metadata->ProcessId = ProcessId;
    SysmonCopyOrPlaceholder(Metadata->Image, _countof(Metadata->Image), L"-");
    SysmonCopyOrPlaceholder(Metadata->UserName, _countof(Metadata->UserName), L"-");
    SysmonCopyOrPlaceholder(Metadata->ProcessGuid, _countof(Metadata->ProcessGuid), L"-");

    ZeroMemory(&cachedMetadata, sizeof(cachedMetadata));
    if (SysmonProcessStoreLookupProcessByPidAndTime(ProcessId, Timestamp, &cachedMetadata)) {
        cacheHit = TRUE;
        SysmonPopulateMetadataFromCacheResponse(Metadata, &cachedMetadata);
        success = TRUE;
    } else if (ServiceContext != NULL &&
               SysmonQueryProcessCache(
                   &ServiceContext->Transport,
                   ProcessId,
                   &cachedMetadata) == SYSMON_SUCCESS) {
        SysmonProcessStoreInsertProcessCacheResponse(ProcessId, &cachedMetadata);
        cacheHit = TRUE;
        SysmonPopulateMetadataFromCacheResponse(Metadata, &cachedMetadata);
        success = TRUE;
    }

    if (!cacheHit && SysmonIsPidNegativeCached(ProcessId)) {
        /* A PID that recently failed to open: return the same no-metadata result
           as the triggering failure instead of fabricating a CreateTime/GUID that
           would differ every TTL cycle. */
        return success;
    }

    if (!cacheHit ||
        !SysmonHasValueString(Metadata->ProcessGuid) ||
        !SysmonHasValueString(Metadata->Image) ||
        Metadata->CreateTime == 0) {
        /* On a complete cache hit all fields (Image, UserName, ProcessGuid,
           CreateTime) are already populated, so the heavyweight OpenProcess/token
           work is unnecessary on the ETW hot path (U8 in the 2026-08-04 review).
           An incomplete cache response (the driver can return success without
           collecting process info) is not trusted and falls through to the full
           query. */
        processHandle = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, ProcessId);
        if (processHandle == NULL) {
            processHandle = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, ProcessId);
        }
        if (processHandle == NULL) {
            SysmonCachePidNegative(ProcessId);
            return success;
        }

        if (OpenProcessToken(processHandle, TOKEN_QUERY, &tokenHandle)) {
            GetTokenInformation(tokenHandle, TokenUser, NULL, 0, &sidSize);
            if (sidSize != 0) {
                tokenUser = (PTOKEN_USER)SYSMON_ALLOC(sidSize);
                if (tokenUser != NULL &&
                    GetTokenInformation(tokenHandle, TokenUser, tokenUser, sidSize, &sidSize)) {
                    SysmonResolveAccountName(
                        tokenUser->User.Sid,
                        Metadata->UserName,
                        _countof(Metadata->UserName));
                }
            }
        }

        if (!SysmonHasValueString(Metadata->Image)) {
            if (!SysmonProcessStoreResolveImage(
                    ProcessId,
                    Timestamp,
                    Metadata->Image,
                    _countof(Metadata->Image))) {
                SysmonResolveProcessImageFromHandle(
                    processHandle,
                    Metadata->Image,
                    _countof(Metadata->Image));
            }
        }

        if (GetProcessTimes(processHandle, &createTime, &exitTime, &kernelTime, &userTime)) {
            ULARGE_INTEGER createTimeValue;

            createTimeValue.LowPart = createTime.dwLowDateTime;
            createTimeValue.HighPart = createTime.dwHighDateTime;
            Metadata->CreateTime = createTimeValue.QuadPart;
        }
    }

    if (Metadata->CreateTime == 0) {
        FILETIME now;
        ULARGE_INTEGER nowValue;

        GetSystemTimeAsFileTime(&now);
        nowValue.LowPart = now.dwLowDateTime;
        nowValue.HighPart = now.dwHighDateTime;
        Metadata->CreateTime = nowValue.QuadPart;
    }

    if (!SysmonHasValueString(Metadata->ProcessGuid)) {
        SysmonGenerateProcessGuid(
            ProcessId,
            Metadata->CreateTime,
            Metadata->ProcessGuid,
            _countof(Metadata->ProcessGuid));
    }

    success = TRUE;

    SYSMON_FREE(tokenUser);
    SYSMON_SAFE_CLOSE_HANDLE(tokenHandle);
    SYSMON_SAFE_CLOSE_HANDLE(processHandle);
    return success;
}

BOOL
SysmonCollectProcessMetadata(
    _In_opt_ PSYSMON_SERVICE_CONTEXT ServiceContext,
    _In_ DWORD ProcessId,
    _Out_ PSYSMON_PROCESS_METADATA Metadata)
{
    return SysmonCollectProcessMetadataAtTime(ServiceContext, ProcessId, NULL, Metadata);
}

void
SysmonRefreshSourceRuleRuntime(
    _Inout_ PSYSMON_SERVICE_CONTEXT ServiceContext,
    _Inout_ PSYSMON_RULE_RUNTIME *RuleRuntime,
    _Inout_ const BYTE **RuleSourceBlob,
    _Inout_ DWORD *RuleSourceBlobSize,
    _In_ DWORD RefreshFlags,
    _In_opt_z_ const char *SourceName)
{
    PSYSMON_RULE_RUNTIME newRuntime = NULL;

    if (ServiceContext == NULL ||
        RuleRuntime == NULL ||
        RuleSourceBlob == NULL ||
        RuleSourceBlobSize == NULL) {
        return;
    }

    {
        CriticalSectionGuard configLock(&ServiceContext->ConfigLock);

        if (*RuleSourceBlob != ServiceContext->Config.Rules ||
            *RuleSourceBlobSize != ServiceContext->Config.RulesSize) {
            BOOL shouldSwap = FALSE;

            if (ServiceContext->Config.Rules == NULL || ServiceContext->Config.RulesSize == 0) {
                shouldSwap = TRUE;
            } else {
                SYSMON_STATUS status = SysmonLoadRuleRuntime(
                    ServiceContext->Config.Rules,
                    ServiceContext->Config.RulesSize,
                    &newRuntime);

                if (status == SYSMON_SUCCESS) {
                    shouldSwap = TRUE;
                } else if ((RefreshFlags & SYSMON_SOURCE_RULE_REFRESH_KEEP_OLD_ON_FAILURE) == 0) {
                    shouldSwap = TRUE;
                } else if (SourceName != NULL) {
                    SysmonLogWarning(
                        SYSMON_COMPONENT_CONFIG,
                        "Failed to refresh %s rule runtime (%lu)",
                        SourceName,
                        (unsigned long)status);
                }
            }

            if (shouldSwap) {
                PSYSMON_RULE_RUNTIME oldRuntime = *RuleRuntime;

                *RuleRuntime = newRuntime;
                *RuleSourceBlob = ServiceContext->Config.Rules;
                *RuleSourceBlobSize = ServiceContext->Config.RulesSize;
                newRuntime = NULL;
                SysmonFreeRuleRuntime(oldRuntime);
            }
        }
    }

    if (newRuntime != NULL) {
        SysmonFreeRuleRuntime(newRuntime);
    }
}

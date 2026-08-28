#include "../include/output_enrichment.h"
#include "../include/config.h"
#include "../include/hash_compat.h"
#include "../include/path_cache.h"
#include "../include/packed_read.hpp"
#include "../include/service.h"
#include "../include/runtime.hpp"

#include <sddl.h>
#include <winver.h>

static DWORD
SysmonConfiguredFieldSize(
    _In_opt_z_ PCWSTR FieldName)
{
    PCWSTR cursor;
    DWORD configuredSize = 0;

    if (FieldName == NULL || FieldName[0] == L'\0') {
        return 0;
    }

    CriticalSectionGuard configLock(&g_ServiceCtx.ConfigLock);
    cursor = g_ServiceCtx.Config.FieldSizes;
    while (cursor != NULL && *cursor != L'\0') {
        PCWSTR tokenStart;
        PCWSTR tokenEnd;
        PCWSTR colon;
        PCWSTR value;
        size_t nameLength;
        ULONGLONG valueNumber = 0;

        while (*cursor == L',' || *cursor == L' ' || *cursor == L'\t') {
            cursor++;
        }
        tokenStart = cursor;
        tokenEnd = wcschr(cursor, L',');
        if (tokenEnd == NULL) {
            tokenEnd = cursor + wcslen(cursor);
        }
        colon = wcschr(tokenStart, L':');
        if (colon != NULL && colon < tokenEnd) {
            while (colon > tokenStart && (colon[-1] == L' ' || colon[-1] == L'\t')) {
                colon--;
            }
            nameLength = (size_t)(colon - tokenStart);
            if (nameLength == wcslen(FieldName) &&
                _wcsnicmp(tokenStart, FieldName, nameLength) == 0) {
                value = colon + 1;
                while (value < tokenEnd && (*value == L' ' || *value == L'\t')) {
                    value++;
                }
                while (value < tokenEnd && *value >= L'0' && *value <= L'9') {
                    valueNumber = valueNumber * 10 + (ULONG)(*value - L'0');
                    if (valueNumber > 1024 * 1024) {
                        return 0;
                    }
                    value++;
                }
                if (value > colon + 1 && valueNumber != 0) {
                    configuredSize = (DWORD)valueNumber;
                    break;
                }
            }
        }
        cursor = *tokenEnd == L',' ? tokenEnd + 1 : tokenEnd;
    }
    return configuredSize;
}

BOOL
SysmonHasConfiguredFieldSize(
    _In_opt_z_ PCWSTR FieldName)
{
    return SysmonConfiguredFieldSize(FieldName) != 0;
}

static void
SysmonApplyConfiguredFieldSize(
    _In_ const SYSMON_EVENT_FIELD_DESCRIPTOR *Field,
    _Inout_updates_(BufferChars) PWCHAR Buffer,
    _In_ size_t BufferChars)
{
    DWORD configuredSize;

    if (Field == NULL || Buffer == NULL || BufferChars == 0) {
        return;
    }
    configuredSize = SysmonConfiguredFieldSize(Field->Name);
    if (configuredSize != 0 && configuredSize < BufferChars) {
        Buffer[configuredSize] = L'\0';
    }
}

#define SYSMON_SID_DISPLAY_CACHE_CAPACITY 128
#define SYSMON_SID_DISPLAY_CACHE_BUCKET_COUNT 256
#define SYSMON_VERSION_INFO_CACHE_CAPACITY 4096
#define SYSMON_VERSION_INFO_CACHE_BUCKET_COUNT 8192
#define SYSMON_VERSION_INFO_CACHE_PATH_CHARS 1024

typedef struct _SYSMON_VERSION_INFO_CACHE_VALUE {
    WCHAR FileVersion[256];
    WCHAR Description[256];
    WCHAR Product[256];
    WCHAR Company[256];
    WCHAR OriginalFileName[256];
} SYSMON_VERSION_INFO_CACHE_VALUE;

typedef struct _SYSMON_SID_DISPLAY_CACHE_ENTRY {
    BOOL InUse;
    DWORD SidHash;
    DWORD SidLength;
    LONG NextInBucket;
    WCHAR SidText[256];
    WCHAR Display[256];
} SYSMON_SID_DISPLAY_CACHE_ENTRY;

typedef struct _SYSMON_VERSION_INFO_CACHE_ENTRY {
    BOOL InUse;
    DWORD PathHash;
    DWORD PathLength;
    LONG NextInBucket;
    ULONGLONG FileSize;
    FILETIME LastWriteTime;
    WCHAR FilePath[SYSMON_VERSION_INFO_CACHE_PATH_CHARS];
    SYSMON_VERSION_INFO_CACHE_VALUE Value;
} SYSMON_VERSION_INFO_CACHE_ENTRY;

typedef struct _SYSMON_VERSION_TRANSLATION {
    WORD Language;
    WORD CodePage;
} SYSMON_VERSION_TRANSLATION;

static SYSMON_SID_DISPLAY_CACHE_ENTRY g_SidDisplayCache[SYSMON_SID_DISPLAY_CACHE_CAPACITY];
static DWORD g_SidDisplayCacheVictim = 0;
static LONG g_SidDisplayCacheBuckets[SYSMON_SID_DISPLAY_CACHE_BUCKET_COUNT];
static CRITICAL_SECTION g_SidDisplayCacheLock;
static INIT_ONCE g_VersionInfoCacheInitOnce = INIT_ONCE_STATIC_INIT;
static volatile LONG g_VersionInfoCacheLockInitialized = FALSE;
static CRITICAL_SECTION g_VersionInfoCacheLock;
static SYSMON_VERSION_INFO_CACHE_ENTRY g_VersionInfoCache[SYSMON_VERSION_INFO_CACHE_CAPACITY];
static DWORD g_VersionInfoCacheVictim = 0;
static LONG g_VersionInfoCacheBuckets[SYSMON_VERSION_INFO_CACHE_BUCKET_COUNT];

#include "output_enrichment.inc"

void
SysmonInitializeOutputEnrichmentCaches(VOID)
{
    ZeroMemory(g_SidDisplayCache, sizeof(g_SidDisplayCache));
    g_SidDisplayCacheVictim = 0;
    SysmonInitializeBucketHeads(
        g_SidDisplayCacheBuckets,
        RTL_NUMBER_OF(g_SidDisplayCacheBuckets));
    InitializeCriticalSection(&g_SidDisplayCacheLock);
}

void
SysmonCleanupOutputEnrichmentCaches(VOID)
{
    ZeroMemory(g_SidDisplayCache, sizeof(g_SidDisplayCache));
    g_SidDisplayCacheVictim = 0;
    SysmonInitializeBucketHeads(
        g_SidDisplayCacheBuckets,
        RTL_NUMBER_OF(g_SidDisplayCacheBuckets));

    if (InterlockedCompareExchange(&g_VersionInfoCacheLockInitialized, FALSE, TRUE) == TRUE) {
        DeleteCriticalSection(&g_VersionInfoCacheLock);
    }

    ZeroMemory(g_VersionInfoCache, sizeof(g_VersionInfoCache));
    g_VersionInfoCacheVictim = 0;
    SysmonInitializeBucketHeads(
        g_VersionInfoCacheBuckets,
        RTL_NUMBER_OF(g_VersionInfoCacheBuckets));
    InitOnceInitialize(&g_VersionInfoCacheInitOnce);
    DeleteCriticalSection(&g_SidDisplayCacheLock);
}

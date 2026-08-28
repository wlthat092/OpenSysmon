/*
 * path_cache.cpp - Shared NT path normalization cache for user-mode modules
 */

#include "../include/path_cache.h"
#include "../include/runtime.hpp"

#define SYSMON_SHARED_PATH_CACHE_CAPACITY      2048
#define SYSMON_SHARED_PATH_CACHE_BUCKET_COUNT  4096
#define SYSMON_SHARED_DEVICE_MAP_CAPACITY      32
#define SYSMON_SHARED_PATH_MAX_CHARS           1024

typedef struct _SYSMON_DEVICE_MAP_ENTRY {
    BOOL InUse;
    WCHAR DriveName[3];
    WCHAR DevicePath[512];
    size_t DevicePathLength;
} SYSMON_DEVICE_MAP_ENTRY, *PSYSMON_DEVICE_MAP_ENTRY;

typedef struct _SYSMON_PATH_CONVERSION_CACHE_ENTRY {
    BOOL InUse;
    DWORD PathHash;
    DWORD PathLength;
    LONG NextInBucket;
    WCHAR NtPath[SYSMON_SHARED_PATH_MAX_CHARS];
    WCHAR Win32Path[SYSMON_SHARED_PATH_MAX_CHARS];
} SYSMON_PATH_CONVERSION_CACHE_ENTRY, *PSYSMON_PATH_CONVERSION_CACHE_ENTRY;

static INIT_ONCE g_PathConversionCacheInitOnce = INIT_ONCE_STATIC_INIT;
static CRITICAL_SECTION g_PathConversionCacheLock;
static SYSMON_DEVICE_MAP_ENTRY g_DeviceMap[SYSMON_SHARED_DEVICE_MAP_CAPACITY];
static DWORD g_DeviceMapCount = 0;
static SYSMON_PATH_CONVERSION_CACHE_ENTRY g_PathConversionCache[SYSMON_SHARED_PATH_CACHE_CAPACITY];
static DWORD g_PathConversionCacheVictim = 0;
static LONG g_PathConversionCacheBuckets[SYSMON_SHARED_PATH_CACHE_BUCKET_COUNT];

static DWORD
SysmonSelectPathConversionCacheBucket(
    _In_ DWORD PathHash)
{
    return PathHash % SYSMON_SHARED_PATH_CACHE_BUCKET_COUNT;
}

static VOID
SysmonUnlinkPathConversionCacheSlot(
    _In_ DWORD Slot)
{
    DWORD bucket;
    LONG current;
    LONG previous;

    if (Slot >= SYSMON_SHARED_PATH_CACHE_CAPACITY ||
        !g_PathConversionCache[Slot].InUse) {
        return;
    }

    bucket = SysmonSelectPathConversionCacheBucket(g_PathConversionCache[Slot].PathHash);
    current = g_PathConversionCacheBuckets[bucket];
    previous = -1;
    while (current >= 0) {
        if ((DWORD)current == Slot) {
            if (previous < 0) {
                g_PathConversionCacheBuckets[bucket] = g_PathConversionCache[Slot].NextInBucket;
            } else {
                g_PathConversionCache[previous].NextInBucket = g_PathConversionCache[Slot].NextInBucket;
            }
            break;
        }

        previous = current;
        current = g_PathConversionCache[current].NextInBucket;
    }

    g_PathConversionCache[Slot].NextInBucket = -1;
}

static VOID
SysmonLinkPathConversionCacheSlot(
    _In_ DWORD Slot)
{
    DWORD bucket;

    if (Slot >= SYSMON_SHARED_PATH_CACHE_CAPACITY ||
        !g_PathConversionCache[Slot].InUse) {
        return;
    }

    bucket = SysmonSelectPathConversionCacheBucket(g_PathConversionCache[Slot].PathHash);
    g_PathConversionCache[Slot].NextInBucket = g_PathConversionCacheBuckets[bucket];
    g_PathConversionCacheBuckets[bucket] = (LONG)Slot;
}

static BOOL CALLBACK
SysmonInitializePathConversionCaches(
    PINIT_ONCE InitOnce,
    PVOID Parameter,
    PVOID *Context)
{
    UNREFERENCED_PARAMETER(InitOnce);
    UNREFERENCED_PARAMETER(Parameter);
    UNREFERENCED_PARAMETER(Context);

    InitializeCriticalSection(&g_PathConversionCacheLock);
    ZeroMemory(g_DeviceMap, sizeof(g_DeviceMap));
    g_DeviceMapCount = 0;
    ZeroMemory(g_PathConversionCache, sizeof(g_PathConversionCache));
    g_PathConversionCacheVictim = 0;
    SysmonInitializeBucketHeads(
        g_PathConversionCacheBuckets,
        RTL_NUMBER_OF(g_PathConversionCacheBuckets));
    return TRUE;
}

static BOOL
SysmonEnsurePathConversionCachesInitialized(VOID)
{
    return InitOnceExecuteOnce(
        &g_PathConversionCacheInitOnce,
        SysmonInitializePathConversionCaches,
        NULL,
        NULL);
}

static VOID
SysmonRefreshDeviceMapUnlocked(VOID)
{
    WCHAR driveStrings[512];
    DWORD driveChars;
    PWCHAR drive;

    ZeroMemory(g_DeviceMap, sizeof(g_DeviceMap));
    g_DeviceMapCount = 0;

    driveChars = GetLogicalDriveStringsW(_countof(driveStrings), driveStrings);
    if (driveChars == 0 || driveChars >= _countof(driveStrings)) {
        return;
    }

    for (drive = driveStrings;
         drive != NULL && *drive != L'\0' && g_DeviceMapCount < _countof(g_DeviceMap);
         drive += wcslen(drive) + 1) {
        WCHAR driveName[3];
        DWORD slot;

        driveName[0] = drive[0];
        driveName[1] = L':';
        driveName[2] = L'\0';

        slot = g_DeviceMapCount;
        if (QueryDosDeviceW(
                driveName,
                g_DeviceMap[slot].DevicePath,
                _countof(g_DeviceMap[slot].DevicePath)) == 0) {
            continue;
        }

        g_DeviceMap[slot].InUse = TRUE;
        g_DeviceMap[slot].DriveName[0] = driveName[0];
        g_DeviceMap[slot].DriveName[1] = driveName[1];
        g_DeviceMap[slot].DriveName[2] = L'\0';
        g_DeviceMap[slot].DevicePathLength = wcslen(g_DeviceMap[slot].DevicePath);
        g_DeviceMapCount++;
    }
}

static BOOL
SysmonLookupPathConversionCache(
    _In_z_ PCWSTR NtPath,
    _Out_writes_(BufferChars) PWCHAR Buffer,
    _In_ size_t BufferChars)
{
    DWORD pathHash;
    DWORD pathLength;
    DWORD bucket;
    LONG index;

    if (NtPath == NULL || Buffer == NULL || BufferChars == 0) {
        return FALSE;
    }

    if (!SysmonEnsurePathConversionCachesInitialized()) {
        return FALSE;
    }

    pathHash = SysmonComputeInsensitiveWideHash(NtPath, &pathLength);
    bucket = SysmonSelectPathConversionCacheBucket(pathHash);

    {
        CriticalSectionGuard cacheLock(&g_PathConversionCacheLock);

        for (index = g_PathConversionCacheBuckets[bucket];
             index >= 0;
             index = g_PathConversionCache[index].NextInBucket) {
            if (!SysmonInsensitiveWideTextMatches(
                    g_PathConversionCache[index].PathHash,
                    g_PathConversionCache[index].PathLength,
                    g_PathConversionCache[index].NtPath,
                    pathHash,
                    pathLength,
                    NtPath)) {
                continue;
            }

            return SysmonCopyWideText(
                Buffer,
                BufferChars,
                g_PathConversionCache[index].Win32Path);
        }
    }

    return FALSE;
}

static VOID
SysmonStorePathConversionCache(
    _In_z_ PCWSTR NtPath,
    _In_z_ PCWSTR Win32Path)
{
    DWORD pathHash;
    DWORD pathLength;
    DWORD bucket;
    LONG index;

    if (NtPath == NULL || Win32Path == NULL ||
        NtPath[0] == L'\0' || Win32Path[0] == L'\0') {
        return;
    }

    if (!SysmonEnsurePathConversionCachesInitialized()) {
        return;
    }

    pathHash = SysmonComputeInsensitiveWideHash(NtPath, &pathLength);
    bucket = SysmonSelectPathConversionCacheBucket(pathHash);

    {
        CriticalSectionGuard cacheLock(&g_PathConversionCacheLock);

        for (index = g_PathConversionCacheBuckets[bucket];
             index >= 0;
             index = g_PathConversionCache[index].NextInBucket) {
            if (SysmonInsensitiveWideTextMatches(
                    g_PathConversionCache[index].PathHash,
                    g_PathConversionCache[index].PathLength,
                    g_PathConversionCache[index].NtPath,
                    pathHash,
                    pathLength,
                    NtPath)) {
                (void)SysmonCopyWideText(
                    g_PathConversionCache[index].Win32Path,
                    _countof(g_PathConversionCache[index].Win32Path),
                    Win32Path);
                return;
            }
        }

        index = (LONG)(g_PathConversionCacheVictim++ % SYSMON_SHARED_PATH_CACHE_CAPACITY);
        SysmonUnlinkPathConversionCacheSlot((DWORD)index);
        ZeroMemory(&g_PathConversionCache[index], sizeof(g_PathConversionCache[index]));
        g_PathConversionCache[index].InUse = TRUE;
        g_PathConversionCache[index].PathHash = pathHash;
        g_PathConversionCache[index].PathLength = pathLength;
        g_PathConversionCache[index].NextInBucket = -1;
        (void)SysmonCopyWideText(
            g_PathConversionCache[index].NtPath,
            _countof(g_PathConversionCache[index].NtPath),
            NtPath);
        (void)SysmonCopyWideText(
            g_PathConversionCache[index].Win32Path,
            _countof(g_PathConversionCache[index].Win32Path),
            Win32Path);
        SysmonLinkPathConversionCacheSlot((DWORD)index);
    }
}

BOOL
SysmonConvertNtPathToWin32Path(
    _In_z_ PCWSTR NtPath,
    _Out_writes_(BufferChars) PWCHAR Buffer,
    _In_ size_t BufferChars)
{
    BOOL converted;
    DWORD index;

    if (Buffer == NULL || BufferChars == 0 || NtPath == NULL || NtPath[0] == L'\0') {
        return FALSE;
    }

    Buffer[0] = L'\0';

    if (SysmonLookupPathConversionCache(NtPath, Buffer, BufferChars)) {
        return TRUE;
    }

    if (((NtPath[0] >= L'A' && NtPath[0] <= L'Z') ||
         (NtPath[0] >= L'a' && NtPath[0] <= L'z')) &&
        NtPath[1] == L':') {
        converted = SysmonCopyWideText(Buffer, BufferChars, NtPath);
        if (converted) {
            SysmonStorePathConversionCache(NtPath, Buffer);
        }
        return converted;
    }

    if (_wcsnicmp(NtPath, L"\\??\\UNC\\", 8) == 0 ||
        _wcsnicmp(NtPath, L"\\\\?\\UNC\\", 8) == 0) {
        converted = SUCCEEDED(_snwprintf_s(
            Buffer,
            BufferChars,
            _TRUNCATE,
            L"\\\\%ls",
            NtPath + 8));
        if (converted) {
            SysmonStorePathConversionCache(NtPath, Buffer);
        }
        return converted;
    }

    if (_wcsnicmp(NtPath, L"\\??\\", 4) == 0 ||
        _wcsnicmp(NtPath, L"\\\\?\\", 4) == 0) {
        converted = SysmonCopyWideText(Buffer, BufferChars, NtPath + 4);
        if (converted) {
            SysmonStorePathConversionCache(NtPath, Buffer);
        }
        return converted;
    }

    if (_wcsnicmp(NtPath, L"\\\\?\\", 4) == 0 ||
        _wcsnicmp(NtPath, L"\\\\", 2) == 0) {
        converted = SysmonCopyWideText(Buffer, BufferChars, NtPath);
        if (converted) {
            SysmonStorePathConversionCache(NtPath, Buffer);
        }
        return converted;
    }

    if (_wcsnicmp(NtPath, L"\\SystemRoot\\", 12) == 0) {
        WCHAR windowsDir[MAX_PATH];

        if (GetWindowsDirectoryW(windowsDir, _countof(windowsDir)) == 0) {
            return FALSE;
        }

        converted = SUCCEEDED(_snwprintf_s(
            Buffer,
            BufferChars,
            _TRUNCATE,
            L"%ls\\%ls",
            windowsDir,
            NtPath + 12));
        if (converted) {
            SysmonStorePathConversionCache(NtPath, Buffer);
        }
        return converted;
    }

    if (_wcsnicmp(NtPath, L"\\Device\\Mup\\", 12) == 0) {
        converted = SUCCEEDED(_snwprintf_s(
            Buffer,
            BufferChars,
            _TRUNCATE,
            L"\\\\%ls",
            NtPath + 12));
        if (converted) {
            SysmonStorePathConversionCache(NtPath, Buffer);
        }
        return converted;
    }

    if (_wcsnicmp(NtPath, L"\\Device\\", 8) != 0) {
        converted = SysmonCopyWideText(Buffer, BufferChars, NtPath);
        if (converted) {
            SysmonStorePathConversionCache(NtPath, Buffer);
        }
        return converted;
    }

    if (!SysmonEnsurePathConversionCachesInitialized()) {
        return FALSE;
    }

    converted = FALSE;
    {
        CriticalSectionGuard cacheLock(&g_PathConversionCacheLock);

        if (g_DeviceMapCount == 0) {
            SysmonRefreshDeviceMapUnlocked();
        }

        for (index = 0; index < g_DeviceMapCount; index++) {
            size_t devicePathLength;

            if (!g_DeviceMap[index].InUse) {
                continue;
            }

            devicePathLength = g_DeviceMap[index].DevicePathLength;
            if (_wcsnicmp(NtPath, g_DeviceMap[index].DevicePath, devicePathLength) != 0) {
                continue;
            }

            if (NtPath[devicePathLength] != L'\0' && NtPath[devicePathLength] != L'\\') {
                continue;
            }

            converted = SUCCEEDED(_snwprintf_s(
                Buffer,
                BufferChars,
                _TRUNCATE,
                L"%ls%ls",
                g_DeviceMap[index].DriveName,
                NtPath + devicePathLength));
            break;
        }
    }

    if (converted) {
        SysmonStorePathConversionCache(NtPath, Buffer);
    }

    return converted;
}

#include "fileinfo.h"
#include "hash.h"
#include "pe_utils.h"
#include "driver.h"

#define SYSMON_FILEINFO_CACHE_CAPACITY 1024u
#define SYSMON_FILEINFO_CACHE_BUCKET_COUNT 64u
#define SYSMON_FILEINFO_CACHE_ENTRIES_PER_BUCKET \
    (SYSMON_FILEINFO_CACHE_CAPACITY / SYSMON_FILEINFO_CACHE_BUCKET_COUNT)

#if (SYSMON_FILEINFO_CACHE_CAPACITY % SYSMON_FILEINFO_CACHE_BUCKET_COUNT) != 0
#error "SYSMON_FILEINFO_CACHE_CAPACITY must be divisible by SYSMON_FILEINFO_CACHE_BUCKET_COUNT"
#endif

typedef struct _SYSMON_FILE_INFO_CACHE_ENTRY {
    BOOLEAN Valid;
    BOOLEAN HasFileId;
    USHORT Reserved;
    ULONG PathHash;
    ULONG AvailableMask;
    ULONG HashMask;
    ULONGLONG FileId;
    ULONGLONG LastAccessTick;
    WCHAR FilePath[SYSMON_MAX_PATH];
    SYSMON_HASH_DIGEST_SET HashDigests;
    SYSMON_FILE_INFO FileInfo;
} SYSMON_FILE_INFO_CACHE_ENTRY, *PSYSMON_FILE_INFO_CACHE_ENTRY;

typedef struct _SYSMON_FILE_CONTENT {
    PUCHAR Data;
    ULONG Size;
    HANDLE SectionHandle;
    BOOLEAN MappedView;
} SYSMON_FILE_CONTENT, *PSYSMON_FILE_CONTENT;

static SYSMON_FILE_INFO_CACHE_ENTRY g_FileInfoCache[SYSMON_FILEINFO_CACHE_CAPACITY];
static FAST_MUTEX g_FileInfoCacheBucketLocks[SYSMON_FILEINFO_CACHE_BUCKET_COUNT];
static volatile LONG g_FileInfoCacheInitState = 0; /* 0=uninitialized, 1=initializing, 2=ready */
static KEVENT g_FileInfoCacheInitEvent;
static volatile LONG g_FileInfoCacheInitEventState = 0;
static ULONGLONG g_FileInfoCacheBucketAccessClocks[SYSMON_FILEINFO_CACHE_BUCKET_COUNT];
static volatile LONG g_LastFileInfoHashMaskUsed = 0;
static volatile LONG g_LastFileInfoHashStatus = 0;
static volatile LONG g_LastFileInfoAvailableMask = 0;
static volatile LONG g_LastFileInfoContentMode = 0;
static volatile LONG g_FileInfoCollectCallCount = 0;
static volatile LONG g_FileInfoCacheLookupCount = 0;
static volatile LONG g_FileInfoCacheHitCount = 0;
static volatile LONG g_FileInfoCacheStoreCount = 0;
static volatile LONG g_FileInfoMapAttemptCount = 0;
static volatile LONG g_FileInfoMapSuccessCount = 0;
static volatile LONG g_FileInfoReadFallbackCount = 0;
static volatile LONG g_FileInfoReadRetryCount = 0;
static volatile LONG g_FileInfoHashComputeCount = 0;
static volatile LONG g_FileInfoVersionParseCount = 0;
static volatile LONG g_FileInfoMapUsecTotal = 0;
static volatile LONG g_FileInfoReadUsecTotal = 0;
static volatile LONG g_FileInfoHashUsecTotal = 0;
static volatile LONG g_FileInfoVersionUsecTotal = 0;

#define SYSMON_FILEINFO_STAT_INC(_Counter) \
    ((void)InterlockedIncrement(&(_Counter)))

#define SYSMON_FILEINFO_STAT_ADD(_Counter, _Value) \
    ((void)InterlockedExchangeAdd(&(_Counter), (LONG)(_Value)))

static VOID
SysmonEnsureFileInfoCacheInitEventInitialized(VOID)
{
    if (InterlockedCompareExchange(&g_FileInfoCacheInitEventState, 1, 0) == 0) {
        KeInitializeEvent(&g_FileInfoCacheInitEvent, NotificationEvent, FALSE);
    }
}

static ULONG
SysmonComputeElapsedUsec(
    _In_ LARGE_INTEGER StartCounter,
    _In_ LARGE_INTEGER EndCounter,
    _In_ LARGE_INTEGER CounterFrequency)
{
    ULONGLONG deltaCounts;
    ULONGLONG elapsedUsec;
    ULONGLONG frequencyCounts;

    if (EndCounter.QuadPart <= StartCounter.QuadPart ||
        CounterFrequency.QuadPart <= 0) {
        return 0;
    }

    deltaCounts = (ULONGLONG)(EndCounter.QuadPart - StartCounter.QuadPart);
    frequencyCounts = (ULONGLONG)CounterFrequency.QuadPart;
    elapsedUsec = (deltaCounts * 1000000ull) / frequencyCounts;
    if (elapsedUsec > MAXULONG) {
        return MAXULONG;
    }

    return (ULONG)elapsedUsec;
}

static ULONG
SysmonHashFilePath(
    _In_z_ PCWSTR Path)
{
    ULONG hash;

    hash = 5381u;
    while (*Path != L'\0') {
        hash = ((hash << 5) + hash) + (ULONG)RtlUpcaseUnicodeChar(*Path);
        Path++;
    }

    return hash;
}

static ULONG
SysmonGetFileInfoCacheBucketIndex(
    _In_ ULONG PathHash)
{
    return PathHash % SYSMON_FILEINFO_CACHE_BUCKET_COUNT;
}

static VOID
SysmonGetFileInfoCacheBucketRange(
    _In_ ULONG BucketIndex,
    _Out_ PULONG StartIndex,
    _Out_ PULONG EndIndex)
{
    ULONG startIndex;

    startIndex = BucketIndex * SYSMON_FILEINFO_CACHE_ENTRIES_PER_BUCKET;
    *StartIndex = startIndex;
    *EndIndex = startIndex + SYSMON_FILEINFO_CACHE_ENTRIES_PER_BUCKET;
}

static ULONGLONG
SysmonAdvanceFileInfoCacheClock(
    _In_ ULONG BucketIndex)
{
    g_FileInfoCacheBucketAccessClocks[BucketIndex]++;
    return g_FileInfoCacheBucketAccessClocks[BucketIndex];
}

VOID
SysmonQueryFileInfoDebugSnapshot(
    _Out_ PSYSMON_FILEINFO_DEBUG_SNAPSHOT Snapshot)
{
    if (Snapshot == NULL) {
        return;
    }

    RtlZeroMemory(Snapshot, sizeof(*Snapshot));
    Snapshot->LastHashMaskUsed = (ULONG)InterlockedCompareExchange(&g_LastFileInfoHashMaskUsed, 0, 0);
    Snapshot->LastHashStatus = (ULONG)InterlockedCompareExchange(&g_LastFileInfoHashStatus, 0, 0);
    Snapshot->LastAvailableMask = (ULONG)InterlockedCompareExchange(&g_LastFileInfoAvailableMask, 0, 0);
    Snapshot->LastFileContentMode = (ULONG)InterlockedCompareExchange(&g_LastFileInfoContentMode, 0, 0);
    Snapshot->FileInfoCollectCallCount = (ULONG)InterlockedCompareExchange(&g_FileInfoCollectCallCount, 0, 0);
    Snapshot->FileInfoCacheLookupCount = (ULONG)InterlockedCompareExchange(&g_FileInfoCacheLookupCount, 0, 0);
    Snapshot->FileInfoCacheHitCount = (ULONG)InterlockedCompareExchange(&g_FileInfoCacheHitCount, 0, 0);
    Snapshot->FileInfoCacheStoreCount = (ULONG)InterlockedCompareExchange(&g_FileInfoCacheStoreCount, 0, 0);
    Snapshot->FileInfoMapAttemptCount = (ULONG)InterlockedCompareExchange(&g_FileInfoMapAttemptCount, 0, 0);
    Snapshot->FileInfoMapSuccessCount = (ULONG)InterlockedCompareExchange(&g_FileInfoMapSuccessCount, 0, 0);
    Snapshot->FileInfoReadFallbackCount = (ULONG)InterlockedCompareExchange(&g_FileInfoReadFallbackCount, 0, 0);
    Snapshot->FileInfoReadRetryCount = (ULONG)InterlockedCompareExchange(&g_FileInfoReadRetryCount, 0, 0);
    Snapshot->FileInfoHashComputeCount = (ULONG)InterlockedCompareExchange(&g_FileInfoHashComputeCount, 0, 0);
    Snapshot->FileInfoVersionParseCount = (ULONG)InterlockedCompareExchange(&g_FileInfoVersionParseCount, 0, 0);
    Snapshot->FileInfoMapUsecTotal = (ULONG)InterlockedCompareExchange(&g_FileInfoMapUsecTotal, 0, 0);
    Snapshot->FileInfoReadUsecTotal = (ULONG)InterlockedCompareExchange(&g_FileInfoReadUsecTotal, 0, 0);
    Snapshot->FileInfoHashUsecTotal = (ULONG)InterlockedCompareExchange(&g_FileInfoHashUsecTotal, 0, 0);
    Snapshot->FileInfoVersionUsecTotal = (ULONG)InterlockedCompareExchange(&g_FileInfoVersionUsecTotal, 0, 0);
}

static VOID
SysmonEnsureFileInfoCacheInitialized(VOID)
{
    LONG state;

    SysmonEnsureFileInfoCacheInitEventInitialized();
    for (;;) {
        state = InterlockedCompareExchange(&g_FileInfoCacheInitState, 2, 2);
        if (state == 2) {
            return;
        }

        if (state == 0 &&
            InterlockedCompareExchange(&g_FileInfoCacheInitState, 1, 0) == 0) {
            ULONG bucketIndex;

            for (bucketIndex = 0; bucketIndex < SYSMON_FILEINFO_CACHE_BUCKET_COUNT; bucketIndex++) {
                ExInitializeFastMutex(&g_FileInfoCacheBucketLocks[bucketIndex]);
                g_FileInfoCacheBucketAccessClocks[bucketIndex] = 0;
            }
            RtlZeroMemory(g_FileInfoCache, sizeof(g_FileInfoCache));
            InterlockedExchange(&g_FileInfoCacheInitState, 2);
            KeSetEvent(&g_FileInfoCacheInitEvent, IO_NO_INCREMENT, FALSE);
            return;
        }

        (void)KeWaitForSingleObject(
            &g_FileInfoCacheInitEvent,
            Executive,
            KernelMode,
            FALSE,
            NULL);
    }
}

static BOOLEAN
SysmonLookupFileInfoCache(
    _In_z_ PCWSTR FilePath,
    _In_ BOOLEAN HasFileId,
    _In_ ULONGLONG FileId,
    _In_ ULONG RequestMask,
    _In_ ULONG HashMask,
    _Out_ PSYSMON_FILE_INFO FileInfo)
{
    ULONG bucketIndex;
    ULONG endIndex;
    ULONG index;
    ULONG pathHash;
    ULONG startIndex;
    BOOLEAN found = FALSE;

    if (FilePath == NULL || FileInfo == NULL) {
        return FALSE;
    }

    SYSMON_FILEINFO_STAT_INC(g_FileInfoCacheLookupCount);
    SysmonEnsureFileInfoCacheInitialized();
    pathHash = SysmonHashFilePath(FilePath);
    bucketIndex = SysmonGetFileInfoCacheBucketIndex(pathHash);
    SysmonGetFileInfoCacheBucketRange(bucketIndex, &startIndex, &endIndex);

    ExAcquireFastMutex(&g_FileInfoCacheBucketLocks[bucketIndex]);
    for (index = startIndex; index < endIndex; index++) {
        if (!g_FileInfoCache[index].Valid) {
            continue;
        }

        if (g_FileInfoCache[index].PathHash != pathHash) {
            continue;
        }

        if (_wcsicmp(g_FileInfoCache[index].FilePath, FilePath) != 0) {
            continue;
        }

        if (g_FileInfoCache[index].HasFileId != HasFileId) {
            continue;
        }

        if (HasFileId &&
            g_FileInfoCache[index].FileId != FileId) {
            continue;
        }

        if ((RequestMask & SYSMON_FILEINFO_REQUEST_HASHES) != 0) {
            if ((g_FileInfoCache[index].AvailableMask & SYSMON_FILEINFO_REQUEST_HASHES) == 0 ||
                g_FileInfoCache[index].HashMask != HashMask) {
                continue;
            }
        }

        if ((RequestMask & SYSMON_FILEINFO_REQUEST_VERSION_INFO) != 0 &&
            (g_FileInfoCache[index].AvailableMask & SYSMON_FILEINFO_REQUEST_VERSION_INFO) == 0) {
            continue;
        }

        *FileInfo = g_FileInfoCache[index].FileInfo;
        if ((RequestMask & SYSMON_FILEINFO_REQUEST_HASHES) != 0 &&
            (g_FileInfoCache[index].AvailableMask & SYSMON_FILEINFO_REQUEST_HASHES) != 0) {
            if (!NT_SUCCESS(SysmonFormatHashDigestsMasked(
                    &g_FileInfoCache[index].HashDigests,
                    FileInfo->Hashes,
                    RTL_NUMBER_OF(FileInfo->Hashes)))) {
                SysmonCopyWideString(
                    FileInfo->Hashes,
                    RTL_NUMBER_OF(FileInfo->Hashes),
                    L"-");
            }
        }
        g_FileInfoCache[index].LastAccessTick = SysmonAdvanceFileInfoCacheClock(bucketIndex);
        SYSMON_FILEINFO_STAT_INC(g_FileInfoCacheHitCount);
        found = TRUE;
        break;
    }
    ExReleaseFastMutex(&g_FileInfoCacheBucketLocks[bucketIndex]);

    return found;
}

static VOID
SysmonStoreFileInfoCache(
    _In_z_ PCWSTR FilePath,
    _In_ BOOLEAN HasFileId,
    _In_ ULONGLONG FileId,
    _In_ ULONG AvailableMask,
    _In_ ULONG HashMask,
    _In_ const SYSMON_FILE_INFO *FileInfo,
    _In_opt_ const SYSMON_HASH_DIGEST_SET *HashDigests)
{
    ULONG bucketIndex;
    ULONG endIndex;
    ULONG slot = SYSMON_FILEINFO_CACHE_CAPACITY;
    ULONG exactMatchSlot = SYSMON_FILEINFO_CACHE_CAPACITY;
    ULONG stalePathSlot = SYSMON_FILEINFO_CACHE_CAPACITY;
    ULONG invalidSlot = SYSMON_FILEINFO_CACHE_CAPACITY;
    ULONG lruSlot = SYSMON_FILEINFO_CACHE_CAPACITY;
    ULONG index;
    ULONG existingMask = 0;
    ULONG mergedHashMask = 0;
    ULONG pathHash;
    ULONG startIndex;
    BOOLEAN canMergeExisting = FALSE;
    ULONGLONG oldestTick = ~0ULL;
    SYSMON_HASH_DIGEST_SET mergedHashDigests;
    SYSMON_FILE_INFO mergedInfo;

    if (FilePath == NULL || FileInfo == NULL) {
        return;
    }

    SysmonEnsureFileInfoCacheInitialized();
    RtlZeroMemory(&mergedHashDigests, sizeof(mergedHashDigests));
    mergedInfo = *FileInfo;
    pathHash = SysmonHashFilePath(FilePath);
    bucketIndex = SysmonGetFileInfoCacheBucketIndex(pathHash);
    SysmonGetFileInfoCacheBucketRange(bucketIndex, &startIndex, &endIndex);

    ExAcquireFastMutex(&g_FileInfoCacheBucketLocks[bucketIndex]);
    for (index = startIndex; index < endIndex; index++) {
        if (!g_FileInfoCache[index].Valid) {
            if (invalidSlot == SYSMON_FILEINFO_CACHE_CAPACITY) {
                invalidSlot = index;
            }
            continue;
        }

        if (g_FileInfoCache[index].LastAccessTick < oldestTick) {
            oldestTick = g_FileInfoCache[index].LastAccessTick;
            lruSlot = index;
        }

        if (g_FileInfoCache[index].PathHash != pathHash) {
            continue;
        }

        if (_wcsicmp(g_FileInfoCache[index].FilePath, FilePath) != 0) {
            continue;
        }

        if (g_FileInfoCache[index].HasFileId != HasFileId) {
            if (stalePathSlot == SYSMON_FILEINFO_CACHE_CAPACITY) {
                stalePathSlot = index;
            }
            continue;
        }

        if (HasFileId &&
            g_FileInfoCache[index].FileId != FileId) {
            if (stalePathSlot == SYSMON_FILEINFO_CACHE_CAPACITY) {
                stalePathSlot = index;
            }
            continue;
        }

        exactMatchSlot = index;
        existingMask = g_FileInfoCache[index].AvailableMask;
        canMergeExisting = TRUE;
        break;
    }

    if (exactMatchSlot != SYSMON_FILEINFO_CACHE_CAPACITY) {
        slot = exactMatchSlot;
    } else if (stalePathSlot != SYSMON_FILEINFO_CACHE_CAPACITY) {
        slot = stalePathSlot;
    } else if (invalidSlot != SYSMON_FILEINFO_CACHE_CAPACITY) {
        slot = invalidSlot;
    } else {
        slot = lruSlot;
    }

    if (slot == SYSMON_FILEINFO_CACHE_CAPACITY) {
        ExReleaseFastMutex(&g_FileInfoCacheBucketLocks[bucketIndex]);
        return;
    }

    SYSMON_FILEINFO_STAT_INC(g_FileInfoCacheStoreCount);
    g_FileInfoCache[slot].Valid = TRUE;
    if (canMergeExisting &&
        (existingMask & SYSMON_FILEINFO_REQUEST_HASHES) != 0 &&
        (AvailableMask & SYSMON_FILEINFO_REQUEST_HASHES) == 0) {
        mergedHashDigests = g_FileInfoCache[slot].HashDigests;
        mergedHashMask = g_FileInfoCache[slot].HashMask;
    } else if ((AvailableMask & SYSMON_FILEINFO_REQUEST_HASHES) != 0) {
        if (HashDigests != NULL) {
            mergedHashDigests = *HashDigests;
        }
        mergedHashMask = HashMask;
    }

    if (canMergeExisting &&
        (existingMask & SYSMON_FILEINFO_REQUEST_VERSION_INFO) != 0 &&
        (AvailableMask & SYSMON_FILEINFO_REQUEST_VERSION_INFO) == 0) {
        SysmonCopyWideString(
            mergedInfo.FileVersion,
            RTL_NUMBER_OF(mergedInfo.FileVersion),
            g_FileInfoCache[slot].FileInfo.FileVersion);
        SysmonCopyWideString(
            mergedInfo.ProductName,
            RTL_NUMBER_OF(mergedInfo.ProductName),
            g_FileInfoCache[slot].FileInfo.ProductName);
        SysmonCopyWideString(
            mergedInfo.CompanyName,
            RTL_NUMBER_OF(mergedInfo.CompanyName),
            g_FileInfoCache[slot].FileInfo.CompanyName);
        SysmonCopyWideString(
            mergedInfo.OriginalFileName,
            RTL_NUMBER_OF(mergedInfo.OriginalFileName),
            g_FileInfoCache[slot].FileInfo.OriginalFileName);
        SysmonCopyWideString(
            mergedInfo.FileDescription,
            RTL_NUMBER_OF(mergedInfo.FileDescription),
            g_FileInfoCache[slot].FileInfo.FileDescription);
    }

    g_FileInfoCache[slot].AvailableMask = existingMask | AvailableMask;
    g_FileInfoCache[slot].HashMask = mergedHashMask;
    g_FileInfoCache[slot].HasFileId = HasFileId;
    g_FileInfoCache[slot].FileId = FileId;
    g_FileInfoCache[slot].PathHash = pathHash;
    g_FileInfoCache[slot].LastAccessTick = SysmonAdvanceFileInfoCacheClock(bucketIndex);
    g_FileInfoCache[slot].HashDigests = mergedHashDigests;
    RtlZeroMemory(g_FileInfoCache[slot].FilePath, sizeof(g_FileInfoCache[slot].FilePath));
    SysmonCopyWideString(
        g_FileInfoCache[slot].FilePath,
        RTL_NUMBER_OF(g_FileInfoCache[slot].FilePath),
        FilePath);
    g_FileInfoCache[slot].FileInfo = mergedInfo;
    ExReleaseFastMutex(&g_FileInfoCacheBucketLocks[bucketIndex]);
}

/*
 * Query file path via FltGetFileNameInformation.
 */
NTSTATUS
SysmonQueryFilePath(
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Out_ PUNICODE_STRING FileName)
{
    NTSTATUS status;
    PFLT_FILE_NAME_INFORMATION nameInfo = NULL;

    status = FltGetFileNameInformation(
        FltObjects->Instance,
        FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_DEFAULT,
        &nameInfo);

    if (!NT_SUCCESS(status)) {
        return status;
    }

    status = FltParseFileNameInformation(nameInfo);
    if (NT_SUCCESS(status)) {
        FileName->Length = nameInfo->Name.Length;
        FileName->MaximumLength = nameInfo->Name.MaximumLength;
        FileName->Buffer = nameInfo->Name.Buffer;
        /* Note: caller must call FltReleaseFileNameInformation(nameInfo) after use */
        /* We attach nameInfo pointer for caller to release */
    }

    if (!NT_SUCCESS(status)) {
        FltReleaseFileNameInformation(nameInfo);
    }
    return status;
}

/*
 * Query file basic info (size, timestamps, attributes).
 */
NTSTATUS
SysmonQueryFileBasicInfo(
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Out_ PSYSMON_FILE_INFO FileInfo)
{
    NTSTATUS basicStatus;
    NTSTATUS sizeStatus;
    FILE_STANDARD_INFORMATION stdInfo;
    FILE_BASIC_INFORMATION basicInfo;
    ULONG returnedBytes = 0;

    RtlZeroMemory(&stdInfo, sizeof(stdInfo));
    RtlZeroMemory(&basicInfo, sizeof(basicInfo));

    /* File size */
    sizeStatus = FltQueryInformationFile(
        FltObjects->Instance,
        FltObjects->FileObject,
        &stdInfo,
        sizeof(FILE_STANDARD_INFORMATION),
        FileStandardInformation,
        &returnedBytes);
    if (NT_SUCCESS(sizeStatus)) {
        FileInfo->FileSize = stdInfo.EndOfFile;
    }

    /* Timestamps and attributes */
    basicStatus = FltQueryInformationFile(
        FltObjects->Instance,
        FltObjects->FileObject,
        &basicInfo,
        sizeof(FILE_BASIC_INFORMATION),
        FileBasicInformation,
        &returnedBytes);
    if (NT_SUCCESS(basicStatus)) {
        FileInfo->CreationTime = basicInfo.CreationTime;
        FileInfo->LastWriteTime = basicInfo.LastWriteTime;
        FileInfo->LastAccessTime = basicInfo.LastAccessTime;
        FileInfo->FileAttributes = basicInfo.FileAttributes;
    }

    if (!NT_SUCCESS(sizeStatus)) {
        return sizeStatus;
    }

    return basicStatus;
}

/*
 * Read file content into a buffer for hash computation.
 * Uses FltReadFile. Reads up to MaxBytes.
 */
NTSTATUS
SysmonReadFileContent(
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ ULONG MaxBytes,
    _Out_ PUCHAR *Buffer,
    _Out_ PULONG BytesRead)
{
    NTSTATUS status;
    PUCHAR buf = NULL;
    LARGE_INTEGER byteOffset;
    ULONG readLen;
    *Buffer = NULL;
    *BytesRead = 0;

    /* Allocate read buffer */
    buf = (PUCHAR)SysmonAllocatePool(MaxBytes);
    if (buf == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    byteOffset.QuadPart = 0;

    status = FltReadFile(
        FltObjects->Instance,
        FltObjects->FileObject,
        &byteOffset,
        MaxBytes,
        buf,
        FLTFL_IO_OPERATION_NON_CACHED | FLTFL_IO_OPERATION_DO_NOT_UPDATE_BYTE_OFFSET,
        BytesRead,
        NULL,  /* No completion routine */
        NULL);

    if (!NT_SUCCESS(status)) {
        SysmonFreePool(buf);
        *Buffer = NULL;
        *BytesRead = 0;
        return status;
    }

    *Buffer = buf;
    return STATUS_SUCCESS;
}

/* ========================================================================
 * PE Version Info Parser
 * ======================================================================== */

/* Align to 4-byte boundary */
#define ALIGN4(x) (((x) + 3) & ~3)

static BOOLEAN
SysmonAlign4Ulong(
    _In_ ULONG Value,
    _Out_ ULONG *AlignedValue)
{
    if (Value > (MAXULONG - 3)) {
        return FALSE;
    }

    *AlignedValue = ALIGN4(Value);
    return TRUE;
}

static BOOLEAN
SysmonPeFindSection(
    _In_reads_(FileSize) const UCHAR *FileData,
    _In_ ULONG FileSize,
    _In_ ULONG SectionTableOffset,
    _In_ USHORT NumSections,
    _In_ ULONG Rva,
    _Out_ ULONG *SectionRva,
    _Out_ ULONG *SectionRawOffset)
{
    ULONG i;

    for (i = 0; i < NumSections; i++) {
        ULONG secOff;
        ULONG secRva;
        ULONG secSize;
        ULONG secRawOff;

        if (i > (MAXULONG / 40) ||
            !SysmonPeAddUlong(SectionTableOffset, i * 40, &secOff) ||
            !SysmonPeHasRange(FileSize, secOff, 40)) {
            return FALSE;
        }

        if (!SysmonPeReadUlong(FileData, FileSize, secOff + 0x0C, &secRva) ||
            !SysmonPeReadUlong(FileData, FileSize, secOff + 0x08, &secSize) ||
            !SysmonPeReadUlong(FileData, FileSize, secOff + 0x14, &secRawOff)) {
            return FALSE;
        }

        if (Rva >= secRva && (Rva - secRva) < secSize) {
            *SectionRva = secRva;
            *SectionRawOffset = secRawOff;
            return TRUE;
        }
    }

    return FALSE;
}

static BOOLEAN
SysmonPeRvaToOffset(
    _In_reads_(FileSize) const UCHAR *FileData,
    _In_ ULONG FileSize,
    _In_ ULONG SectionTableOffset,
    _In_ USHORT NumSections,
    _In_ ULONG Rva,
    _Out_ ULONG *FileOffset)
{
    ULONG secRva;
    ULONG secRawOff;
    ULONG delta;

    if (!SysmonPeFindSection(
            FileData, FileSize, SectionTableOffset, NumSections,
            Rva, &secRva, &secRawOff)) {
        return FALSE;
    }

    delta = Rva - secRva;
    if (!SysmonPeAddUlong(secRawOff, delta, FileOffset)) {
        return FALSE;
    }

    return (*FileOffset < FileSize);
}

/*
 * Search for a wide string key within VS_VERSION_INFO StringFileInfo block.
 * Returns pointer to value string, or NULL if not found.
 */
static const WCHAR *
SysmonFindVersionString(
    _In_ const UCHAR *Data,
    _In_ ULONG DataLen,
    _In_ const WCHAR *Key,
    _Out_opt_ ULONG *ValueCharsAvailable)
{
    ULONG offset = 0;
    ULONG keyChars = (ULONG)wcslen(Key);
    ULONG keyBytes = keyChars * sizeof(WCHAR);

    if (ValueCharsAvailable != NULL) {
        *ValueCharsAvailable = 0;
    }

    while (SysmonPeHasRange(DataLen, offset, 6)) {
        USHORT structLen = *(USHORT *)(Data + offset);
        USHORT valueLen  = *(USHORT *)(Data + offset + 2);
        ULONG nameChars;
        ULONG blockEnd;
        ULONG valueOffset;
        ULONG valueStart;
        ULONG alignedStructLen;

        if (structLen < 6 || !SysmonPeHasRange(DataLen, offset, structLen)) {
            break;
        }

        /* Check if this key matches */
        nameChars = (structLen - 6) / sizeof(WCHAR);
        if (valueLen > 0 && nameChars >= keyChars && keyBytes <= (ULONG)(structLen - 6)) {
            const WCHAR *name = (const WCHAR *)(Data + offset + 6);

            if (_wcsnicmp(name, Key, keyChars) == 0) {
                /* Value starts after the name (aligned to 4 bytes) */
                if (!SysmonPeAddUlong(offset, 6 + keyBytes, &valueOffset) ||
                    !SysmonAlign4Ulong(valueOffset, &valueOffset) ||
                    !SysmonPeAddUlong(offset, structLen, &blockEnd) ||
                    !SysmonPeHasRange(DataLen, valueOffset, sizeof(WCHAR)) ||
                    !SysmonPeAddUlong(valueOffset, sizeof(WCHAR), &valueStart) ||
                    valueStart > blockEnd) {
                    return NULL;
                }

                if (ValueCharsAvailable != NULL) {
                    *ValueCharsAvailable = (blockEnd - valueStart) / sizeof(WCHAR);
                }

                return (const WCHAR *)(Data + valueStart);
                /* Skip the null terminator padding */
            }
        }

        if (!SysmonAlign4Ulong(structLen, &alignedStructLen) ||
            alignedStructLen == 0 ||
            !SysmonPeAddUlong(offset, alignedStructLen, &offset)) {
            break;
        }
    }
    return NULL;
}

/*
 * Copy a version string value to a WCHAR buffer.
 */
static VOID
SysmonCopyVersionValue(
    _In_ const UCHAR *BlockData,
    _In_ ULONG BlockLen,
    _In_ const WCHAR *Key,
    _Out_writes_(MaxChars) WCHAR *Dst,
    _In_ ULONG MaxChars)
{
    const WCHAR *value;
    ULONG copyLen;
    ULONG valueCharsAvailable;

    if (MaxChars == 0) {
        return;
    }

    Dst[0] = L'\0';

    value = SysmonFindVersionString(BlockData, BlockLen, Key, &valueCharsAvailable);
    if (value == NULL) return;

    /* Value is null-terminated wide string */
    copyLen = 0;
    while (copyLen < valueCharsAvailable &&
           value[copyLen] != L'\0' &&
           copyLen < MaxChars - 1) {
        copyLen++;
    }
    RtlCopyMemory(Dst, value, copyLen * sizeof(WCHAR));
    Dst[copyLen] = L'\0';
}

/*
 * Parse VS_VERSION_INFO resource from a PE file.
 * Finds StringFileInfo block and extracts version strings.
 */
static NTSTATUS
SysmonParseVersionInfo(
    _In_ const UCHAR *FileData,
    _In_ ULONG FileSize,
    _Inout_ PSYSMON_FILE_INFO FileInfo)
{
    ULONG peOffset;
    USHORT numSections;
    ULONG sectionTableOffset;
    ULONG resourceDirRva = 0;
    ULONG resourceOffset;
    BOOLEAN is64;
    ULONG dirOffset;
    ULONG typeDirOffset;
    ULONG nameDirOffset;
    ULONG dataEntryOffset;
    ULONG dataRva;
    ULONG dataSize;
    ULONG dataFileOff;
    ULONG entryOffset;
    ULONG i;
    ULONG entryCount;
    USHORT namedEntries;
    USHORT idEntries;
    const ULONG resourceDirectorySize = 16;
    const ULONG resourceDirectoryEntrySize = 8;
    const ULONG resourceDataEntrySize = 16;
    BOOLEAN found;

    /*
     * Version strings are currently not consumed in-kernel, so prefer
     * safe detection over deep resource parsing. We only prove that a
     * version resource data entry is reachable and leave fields empty.
     */

    if (!SysmonPeGetLayout(
            FileData,
            FileSize,
            &peOffset,
            &numSections,
            &sectionTableOffset,
            NULL,
            &is64)) {
        return STATUS_INVALID_PARAMETER;
    }

    /* Get resource directory from data directory (index 2) */
    if (is64) {
        if (!SysmonPeAddUlong(peOffset, 0x90, &dirOffset) ||
            !SysmonPeHasRange(FileSize, dirOffset, 8)) {
            return STATUS_INVALID_PARAMETER;
        }
    } else {
        if (!SysmonPeAddUlong(peOffset, 0x80, &dirOffset) ||
            !SysmonPeHasRange(FileSize, dirOffset, 8)) {
            return STATUS_INVALID_PARAMETER;
        }
    }

    if (!SysmonPeReadUlong(FileData, FileSize, dirOffset, &resourceDirRva)) {
        return STATUS_INVALID_PARAMETER;
    }

    if (resourceDirRva == 0) {
        return STATUS_NOT_FOUND;
    }

    if (!SysmonPeRvaToOffset(
            FileData, FileSize, sectionTableOffset, numSections,
            resourceDirRva, &resourceOffset)) {
        return STATUS_NOT_FOUND;
    }

    if (!SysmonPeHasRange(FileSize, resourceOffset, resourceDirectorySize) ||
        !SysmonPeReadUshort(FileData, FileSize, resourceOffset + 12, &namedEntries) ||
        !SysmonPeReadUshort(FileData, FileSize, resourceOffset + 14, &idEntries) ||
        !SysmonPeAddUlong((ULONG)namedEntries, (ULONG)idEntries, &entryCount) ||
        !SysmonPeAddUlong(resourceOffset, resourceDirectorySize, &entryOffset)) {
        return STATUS_INVALID_PARAMETER;
    }

    found = FALSE;
    for (i = 0; i < entryCount; i++) {
        ULONG typeId;
        ULONG typeChild;
        ULONG currentEntryOffset;

        if (i > (MAXULONG / resourceDirectoryEntrySize) ||
            !SysmonPeAddUlong(entryOffset, i * resourceDirectoryEntrySize, &currentEntryOffset) ||
            !SysmonPeHasRange(FileSize, currentEntryOffset, resourceDirectoryEntrySize) ||
            !SysmonPeReadUlong(FileData, FileSize, currentEntryOffset, &typeId) ||
            !SysmonPeReadUlong(FileData, FileSize, currentEntryOffset + sizeof(ULONG), &typeChild)) {
            return STATUS_INVALID_PARAMETER;
        }

        if (typeId == 16 && (typeChild & 0x80000000) != 0) {
            if (!SysmonPeAddUlong(resourceOffset, typeChild & 0x7FFFFFFF, &typeDirOffset) ||
                !SysmonPeHasRange(FileSize, typeDirOffset, resourceDirectorySize)) {
                return STATUS_INVALID_PARAMETER;
            }

            found = TRUE;
            break;
        }
    }

    if (!found ||
        !SysmonPeReadUshort(FileData, FileSize, typeDirOffset + 12, &namedEntries) ||
        !SysmonPeReadUshort(FileData, FileSize, typeDirOffset + 14, &idEntries) ||
        !SysmonPeAddUlong((ULONG)namedEntries, (ULONG)idEntries, &entryCount) ||
        !SysmonPeAddUlong(typeDirOffset, resourceDirectorySize, &entryOffset)) {
        return STATUS_NOT_FOUND;
    }

    found = FALSE;
    for (i = 0; i < entryCount; i++) {
        ULONG child;
        ULONG currentEntryOffset;

        if (i > (MAXULONG / resourceDirectoryEntrySize) ||
            !SysmonPeAddUlong(entryOffset, i * resourceDirectoryEntrySize, &currentEntryOffset) ||
            !SysmonPeHasRange(FileSize, currentEntryOffset, resourceDirectoryEntrySize) ||
            !SysmonPeReadUlong(FileData, FileSize, currentEntryOffset + sizeof(ULONG), &child)) {
            return STATUS_INVALID_PARAMETER;
        }

        if ((child & 0x80000000) != 0 &&
            SysmonPeAddUlong(resourceOffset, child & 0x7FFFFFFF, &nameDirOffset) &&
            SysmonPeHasRange(FileSize, nameDirOffset, resourceDirectorySize)) {
            found = TRUE;
            break;
        }
    }

    if (!found ||
        !SysmonPeReadUshort(FileData, FileSize, nameDirOffset + 12, &namedEntries) ||
        !SysmonPeReadUshort(FileData, FileSize, nameDirOffset + 14, &idEntries) ||
        !SysmonPeAddUlong((ULONG)namedEntries, (ULONG)idEntries, &entryCount) ||
        !SysmonPeAddUlong(nameDirOffset, resourceDirectorySize, &entryOffset)) {
        return STATUS_NOT_FOUND;
    }

    found = FALSE;
    for (i = 0; i < entryCount; i++) {
        ULONG child;
        ULONG currentEntryOffset;

        if (i > (MAXULONG / resourceDirectoryEntrySize) ||
            !SysmonPeAddUlong(entryOffset, i * resourceDirectoryEntrySize, &currentEntryOffset) ||
            !SysmonPeHasRange(FileSize, currentEntryOffset, resourceDirectoryEntrySize) ||
            !SysmonPeReadUlong(FileData, FileSize, currentEntryOffset + sizeof(ULONG), &child)) {
            return STATUS_INVALID_PARAMETER;
        }

        if ((child & 0x80000000) == 0 &&
            SysmonPeAddUlong(resourceOffset, child, &dataEntryOffset) &&
            SysmonPeHasRange(FileSize, dataEntryOffset, resourceDataEntrySize)) {
            found = TRUE;
            break;
        }
    }

    if (!found ||
        !SysmonPeReadUlong(FileData, FileSize, dataEntryOffset, &dataRva) ||
        !SysmonPeReadUlong(FileData, FileSize, dataEntryOffset + sizeof(ULONG), &dataSize) ||
        dataRva == 0 ||
        dataSize == 0) {
        return STATUS_NOT_FOUND;
    }

    if (!SysmonPeRvaToOffset(
            FileData, FileSize, sectionTableOffset, numSections, dataRva, &dataFileOff) ||
        !SysmonPeHasRange(FileSize, dataFileOff, dataSize)) {
        return STATUS_NOT_FOUND;
    }

    SysmonCopyVersionValue(FileData + dataFileOff, dataSize, L"FileVersion", FileInfo->FileVersion, RTL_NUMBER_OF(FileInfo->FileVersion));
    SysmonCopyVersionValue(FileData + dataFileOff, dataSize, L"FileDescription", FileInfo->FileDescription, RTL_NUMBER_OF(FileInfo->FileDescription));
    SysmonCopyVersionValue(FileData + dataFileOff, dataSize, L"ProductName", FileInfo->ProductName, RTL_NUMBER_OF(FileInfo->ProductName));
    SysmonCopyVersionValue(FileData + dataFileOff, dataSize, L"CompanyName", FileInfo->CompanyName, RTL_NUMBER_OF(FileInfo->CompanyName));
    SysmonCopyVersionValue(FileData + dataFileOff, dataSize, L"OriginalFileName", FileInfo->OriginalFileName, RTL_NUMBER_OF(FileInfo->OriginalFileName));
    if (FileInfo->OriginalFileName[0] == L'\0') {
        SysmonCopyVersionValue(FileData + dataFileOff, dataSize, L"OriginalFilename", FileInfo->OriginalFileName, RTL_NUMBER_OF(FileInfo->OriginalFileName));
    }

    return STATUS_SUCCESS;
}

/*
 * Detect PE file by MZ/PE magic.
 */
static BOOLEAN
SysmonIsPeFile(_In_ const UCHAR *Data, _In_ ULONG Size)
{
    return SysmonPeGetLayout(Data, Size, NULL, NULL, NULL, NULL, NULL);
}

#define SYSMON_MAX_IMAGE_METADATA_FILE_SIZE (64UL * 1024UL * 1024UL)

static BOOLEAN
SysmonBuildNtFilePath(
    _In_z_ PCWSTR FilePath,
    _Out_ PUNICODE_STRING NtPath,
    _Out_writes_(BufferChars) PWCHAR Buffer,
    _In_ ULONG BufferChars)
{
    if (FilePath == NULL || FilePath[0] == L'\0' ||
        NtPath == NULL || Buffer == NULL || BufferChars == 0) {
        return FALSE;
    }

    Buffer[0] = L'\0';
    if (((FilePath[0] >= L'A' && FilePath[0] <= L'Z') ||
         (FilePath[0] >= L'a' && FilePath[0] <= L'z')) &&
        FilePath[1] == L':') {
        if (_snwprintf_s(Buffer, BufferChars, _TRUNCATE, L"\\??\\%ls", FilePath) < 0) {
            return FALSE;
        }
    } else {
        SysmonCopyWideString(Buffer, BufferChars, FilePath);
    }

    RtlInitUnicodeString(NtPath, Buffer);
    return NtPath->Buffer != NULL && NtPath->Length != 0;
}

static NTSTATUS
SysmonOpenFileByPath(
    _In_z_ PCWSTR FilePath,
    _Out_ PHANDLE FileHandle,
    _Out_ PULONG FileSize)
{
    WCHAR ntPathBuffer[SYSMON_MAX_PATH + 8];
    UNICODE_STRING ntPath;
    OBJECT_ATTRIBUTES objectAttributes;
    IO_STATUS_BLOCK ioStatusBlock;
    FILE_STANDARD_INFORMATION standardInfo;
    NTSTATUS status;

    if (FileHandle == NULL || FileSize == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    *FileHandle = NULL;
    *FileSize = 0;

    if (!SysmonBuildNtFilePath(FilePath, &ntPath, ntPathBuffer, RTL_NUMBER_OF(ntPathBuffer))) {
        return STATUS_INVALID_PARAMETER;
    }

    InitializeObjectAttributes(
        &objectAttributes,
        &ntPath,
        OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
        NULL,
        NULL);

    status = ZwOpenFile(
        FileHandle,
        FILE_GENERIC_READ | SYNCHRONIZE,
        &objectAttributes,
        &ioStatusBlock,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    RtlZeroMemory(&standardInfo, sizeof(standardInfo));
    status = ZwQueryInformationFile(
        *FileHandle,
        &ioStatusBlock,
        &standardInfo,
        sizeof(standardInfo),
        FileStandardInformation);
    if (!NT_SUCCESS(status) ||
        standardInfo.EndOfFile.QuadPart <= 0 ||
        standardInfo.EndOfFile.QuadPart > SYSMON_MAX_IMAGE_METADATA_FILE_SIZE) {
        if (NT_SUCCESS(status)) {
            status = STATUS_FILE_TOO_LARGE;
        }
        ZwClose(*FileHandle);
        *FileHandle = NULL;
        return status;
    }

    *FileSize = (ULONG)standardInfo.EndOfFile.QuadPart;
    return STATUS_SUCCESS;
}

static VOID
SysmonTryQueryFileIdByHandle(
    _In_ HANDLE FileHandle,
    _Out_ PBOOLEAN HasFileId,
    _Out_ PULONGLONG FileId)
{
    FILE_INTERNAL_INFORMATION internalInfo;
    IO_STATUS_BLOCK ioStatusBlock;

    if (HasFileId == NULL || FileId == NULL) {
        return;
    }

    *HasFileId = FALSE;
    *FileId = 0;
    RtlZeroMemory(&internalInfo, sizeof(internalInfo));

    if (!NT_SUCCESS(ZwQueryInformationFile(
            FileHandle,
            &ioStatusBlock,
            &internalInfo,
            sizeof(internalInfo),
            FileInternalInformation))) {
        return;
    }

    *HasFileId = TRUE;
    *FileId = (ULONGLONG)internalInfo.IndexNumber.QuadPart;
}

static NTSTATUS
SysmonReadFileByHandle(
    _In_ HANDLE FileHandle,
    _In_ ULONG FileSize,
    _Out_ PSYSMON_FILE_CONTENT Content)
{
    PUCHAR fileBuffer = NULL;
    LARGE_INTEGER byteOffset;
    ULONG totalRead = 0;
    NTSTATUS status;

    if (Content == NULL || FileSize == 0) {
        return STATUS_INVALID_PARAMETER;
    }

    RtlZeroMemory(Content, sizeof(*Content));

    fileBuffer = (PUCHAR)SysmonAllocatePool(FileSize);
    if (fileBuffer == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    byteOffset.QuadPart = 0;
    while (totalRead < FileSize) {
        IO_STATUS_BLOCK ioStatusBlock;
        ULONG chunkRead = 0;

        status = ZwReadFile(
            FileHandle,
            NULL,
            NULL,
            NULL,
            &ioStatusBlock,
            fileBuffer + totalRead,
            FileSize - totalRead,
            &byteOffset,
            NULL);
        if (status == STATUS_END_OF_FILE) {
            status = STATUS_SUCCESS;
            break;
        }
        if (!NT_SUCCESS(status)) {
            SysmonFreePool(fileBuffer);
            return status;
        }

        chunkRead = (ULONG)(ULONG_PTR)ioStatusBlock.Information;
        if (chunkRead == 0) {
            break;
        }

        totalRead += chunkRead;
        byteOffset.QuadPart += chunkRead;
    }

    if (totalRead == 0) {
        SysmonFreePool(fileBuffer);
        return STATUS_END_OF_FILE;
    }

    Content->Data = fileBuffer;
    Content->Size = totalRead;
    Content->MappedView = FALSE;
    Content->SectionHandle = NULL;
    return STATUS_SUCCESS;
}

static NTSTATUS
SysmonMapFileByHandle(
    _In_ HANDLE FileHandle,
    _In_ ULONG FileSize,
    _Out_ PSYSMON_FILE_CONTENT Content)
{
    LARGE_INTEGER counterFrequency;
    LARGE_INTEGER startCounter;
    PFILE_OBJECT fileObject = NULL;
    OBJECT_ATTRIBUTES objectAttributes;
    HANDLE sectionHandle = NULL;
    PVOID sectionObject = NULL;
    PVOID mappedBase = NULL;
    LARGE_INTEGER sectionFileSize;
    SIZE_T viewSize = 0;
    NTSTATUS status;

    startCounter = KeQueryPerformanceCounter(&counterFrequency);
    SYSMON_FILEINFO_STAT_INC(g_FileInfoMapAttemptCount);

    if (Content == NULL || FileSize == 0) {
        status = STATUS_INVALID_PARAMETER;
        goto Exit;
    }

    RtlZeroMemory(Content, sizeof(*Content));
    if (IoFileObjectType == NULL || *IoFileObjectType == NULL) {
        status = STATUS_INVALID_DEVICE_STATE;
        goto Exit;
    }

    status = ObReferenceObjectByHandle(
        FileHandle,
        FILE_READ_DATA | FILE_READ_ATTRIBUTES,
        *IoFileObjectType,
        KernelMode,
        (PVOID *)&fileObject,
        NULL);
    if (!NT_SUCCESS(status)) {
        goto Exit;
    }

    InitializeObjectAttributes(
        &objectAttributes,
        NULL,
        OBJ_KERNEL_HANDLE,
        NULL,
        NULL);
    RtlZeroMemory(&sectionFileSize, sizeof(sectionFileSize));

    status = FsRtlCreateSectionForDataScan(
        &sectionHandle,
        &sectionObject,
        &sectionFileSize,
        fileObject,
        SECTION_MAP_READ | SECTION_QUERY,
        &objectAttributes,
        NULL,
        PAGE_READONLY,
        SEC_COMMIT,
        0);
    ObDereferenceObject(fileObject);
    fileObject = NULL;
    if (!NT_SUCCESS(status)) {
        goto Exit;
    }

    status = ZwMapViewOfSection(
        sectionHandle,
        ZwCurrentProcess(),
        &mappedBase,
        0,
        0,
        NULL,
        &viewSize,
        ViewUnmap,
        0,
        PAGE_READONLY);
    if (!NT_SUCCESS(status)) {
        goto Exit;
    }

    if (mappedBase == NULL || viewSize < FileSize) {
        status = STATUS_INVALID_VIEW_SIZE;
        goto Exit;
    }

    Content->Data = (PUCHAR)mappedBase;
    Content->Size = FileSize;
    Content->MappedView = TRUE;
    Content->SectionHandle = sectionHandle;
    mappedBase = NULL;
    sectionHandle = NULL;
    SYSMON_FILEINFO_STAT_INC(g_FileInfoMapSuccessCount);

Exit:
    if (mappedBase != NULL) {
        ZwUnmapViewOfSection(ZwCurrentProcess(), mappedBase);
    }
    if (sectionHandle != NULL) {
        ZwClose(sectionHandle);
    }
    if (sectionObject != NULL) {
        ObDereferenceObject(sectionObject);
    }
    if (fileObject != NULL) {
        ObDereferenceObject(fileObject);
    }
    SYSMON_FILEINFO_STAT_ADD(
        g_FileInfoMapUsecTotal,
        SysmonComputeElapsedUsec(
            startCounter,
            KeQueryPerformanceCounter(NULL),
            counterFrequency));

    if (!NT_SUCCESS(status) && Content != NULL) {
        RtlZeroMemory(Content, sizeof(*Content));
    }

    return status;
}

static VOID
SysmonReleaseFileContent(
    _Inout_ PSYSMON_FILE_CONTENT Content)
{
    if (Content == NULL) {
        return;
    }

    if (Content->MappedView) {
        if (Content->Data != NULL) {
            ZwUnmapViewOfSection(ZwCurrentProcess(), Content->Data);
        }
        if (Content->SectionHandle != NULL) {
            ZwClose(Content->SectionHandle);
        }
    } else if (Content->Data != NULL) {
        SysmonFreePool(Content->Data);
    }

    RtlZeroMemory(Content, sizeof(*Content));
}

/*
 * Collect all file info: path, basic info, version, hashes.
 * Called from minifilter pre-operation callbacks.
 */
NTSTATUS
SysmonCollectFileInfo(
    _In_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Out_ PSYSMON_FILE_INFO FileInfo)
{
    NTSTATUS status;
    PFLT_FILE_NAME_INFORMATION nameInfo = NULL;
    PUCHAR fileBuffer = NULL;
    ULONG bytesRead = 0;
    ULONG hashReadSize;

    RtlZeroMemory(FileInfo, sizeof(SYSMON_FILE_INFO));

    /* Get file name info */
    status = FltGetFileNameInformation(
        Data,
        FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_DEFAULT,
        &nameInfo);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    status = FltParseFileNameInformation(nameInfo);
    if (NT_SUCCESS(status)) {
        SysmonCopyUnicodeString(FileInfo->FilePath, SYSMON_MAX_PATH, &nameInfo->Name);
        SysmonCopyUnicodeString(FileInfo->FileName, SYSMON_MAX_PATH, &nameInfo->FinalComponent);
        SysmonCopyUnicodeString(FileInfo->FileExtension, 64, &nameInfo->Extension);
    }
    FltReleaseFileNameInformation(nameInfo);

    /* Basic info */
    SysmonQueryFileBasicInfo(FltObjects, FileInfo);

    /* Check file size limit for reading */
    hashReadSize = 1024 * 1024; /* 1 MB max for hashing */
    if (FileInfo->FileSize.QuadPart > 0 && FileInfo->FileSize.QuadPart < hashReadSize) {
        hashReadSize = (ULONG)FileInfo->FileSize.QuadPart;
    }

    /* Read file content for hashing and PE parsing */
    status = SysmonReadFileContent(FltObjects, hashReadSize, &fileBuffer, &bytesRead);
    if (NT_SUCCESS(status) && fileBuffer != NULL && bytesRead > 0) {
        FileInfo->IsPeFile = SysmonIsPeFile(fileBuffer, bytesRead);

        /* Compute hashes */
        SysmonComputeHashes(fileBuffer, bytesRead, FileInfo->Hashes, SYSMON_MAX_HASH_STRING);

        /*
         * Keep kernel-side file enrichment conservative: the version-resource
         * parser is not required for the currently emitted file event payloads,
         * while hashes and PE detection are. User mode can enrich process image
         * metadata separately without exposing the driver to extra PE parsing.
         */

        SysmonFreePool(fileBuffer);
    }

    return STATUS_SUCCESS;
}

NTSTATUS
SysmonCollectFileInfoByPath(
    _In_z_ PCWSTR FilePath,
    _Out_ PSYSMON_FILE_INFO FileInfo)
{
    return SysmonCollectFileInfoByPathEx(
        FilePath,
        SYSMON_FILEINFO_REQUEST_HASHES | SYSMON_FILEINFO_REQUEST_VERSION_INFO,
        FileInfo);
}

NTSTATUS
SysmonCollectFileInfoByPathEx(
    _In_z_ PCWSTR FilePath,
    _In_ ULONG RequestMask,
    _Out_ PSYSMON_FILE_INFO FileInfo)
{
    SYSMON_FILE_CONTENT fileContent;
    SYSMON_FILE_CONTENT hashRetryContent;
    HANDLE fileHandle = NULL;
    ULONG fileSize = 0;
    ULONGLONG fileId = 0;
    BOOLEAN hasFileId = FALSE;
    ULONG hashMask;
    ULONG availableMask;
    SYSMON_HASH_DIGEST_SET hashDigests;
    NTSTATUS hashStatus;
    NTSTATUS versionStatus;
    NTSTATUS status;

    if (FileInfo == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    RtlZeroMemory(FileInfo, sizeof(*FileInfo));
    if (FilePath == NULL || FilePath[0] == L'\0') {
        return STATUS_INVALID_PARAMETER;
    }

    RequestMask &= (SYSMON_FILEINFO_REQUEST_HASHES | SYSMON_FILEINFO_REQUEST_VERSION_INFO);
    if (RequestMask == 0) {
        SysmonCopyWideString(FileInfo->FilePath, RTL_NUMBER_OF(FileInfo->FilePath), FilePath);
        return STATUS_SUCCESS;
    }

    SYSMON_FILEINFO_STAT_INC(g_FileInfoCollectCallCount);
    hashMask = 0;
    availableMask = 0;
    hashStatus = STATUS_NOT_SUPPORTED;
    versionStatus = STATUS_NOT_SUPPORTED;
    if ((RequestMask & SYSMON_FILEINFO_REQUEST_HASHES) != 0) {
        hashMask = g_Context.HashingAlgorithm;
        if (hashMask == 0) {
            hashMask = SysmonHashSHA1 | SysmonHashMD5;
        }
    }
    InterlockedExchange(&g_LastFileInfoHashMaskUsed, (LONG)hashMask);
    InterlockedExchange(&g_LastFileInfoHashStatus, (LONG)hashStatus);
    InterlockedExchange(&g_LastFileInfoAvailableMask, 0);
    InterlockedExchange(&g_LastFileInfoContentMode, 0);

    RtlZeroMemory(&fileContent, sizeof(fileContent));
    RtlZeroMemory(&hashRetryContent, sizeof(hashRetryContent));
    RtlZeroMemory(&hashDigests, sizeof(hashDigests));
    status = SysmonOpenFileByPath(FilePath, &fileHandle, &fileSize);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    SysmonTryQueryFileIdByHandle(fileHandle, &hasFileId, &fileId);
    if (SysmonLookupFileInfoCache(FilePath, hasFileId, fileId, RequestMask, hashMask, FileInfo)) {
        ZwClose(fileHandle);
        return STATUS_SUCCESS;
    }

    SysmonCopyWideString(FileInfo->FilePath, RTL_NUMBER_OF(FileInfo->FilePath), FilePath);
    status = SysmonMapFileByHandle(fileHandle, fileSize, &fileContent);
    if (!NT_SUCCESS(status)) {
        /*
         * Some image-backed paths report STATUS_FILE_CLOSED after a failed
         * section-map attempt if we immediately reuse the same handle for raw
         * reads. Reopen the path for the buffered fallback so hash collection
         * does not inherit a poisoned handle state.
         */
        if (fileHandle != NULL) {
            ZwClose(fileHandle);
            fileHandle = NULL;
        }

        status = SysmonOpenFileByPath(FilePath, &fileHandle, &fileSize);
        if (NT_SUCCESS(status)) {
            LARGE_INTEGER counterFrequency;
            LARGE_INTEGER startCounter;

            SYSMON_FILEINFO_STAT_INC(g_FileInfoReadFallbackCount);
            startCounter = KeQueryPerformanceCounter(&counterFrequency);
            status = SysmonReadFileByHandle(fileHandle, fileSize, &fileContent);
            SYSMON_FILEINFO_STAT_ADD(
                g_FileInfoReadUsecTotal,
                SysmonComputeElapsedUsec(
                    startCounter,
                    KeQueryPerformanceCounter(NULL),
                    counterFrequency));
        }
        if (NT_SUCCESS(status)) {
            InterlockedExchange(&g_LastFileInfoContentMode, 2);
        }
    } else {
        InterlockedExchange(&g_LastFileInfoContentMode, 1);
    }
    if (!NT_SUCCESS(status)) {
        ZwClose(fileHandle);
        fileHandle = NULL;
        return status;
    }

    FileInfo->FileSize.QuadPart = fileContent.Size;

    if ((RequestMask & SYSMON_FILEINFO_REQUEST_HASHES) != 0) {
        __try {
            LARGE_INTEGER counterFrequency;
            LARGE_INTEGER startCounter;

            SYSMON_FILEINFO_STAT_INC(g_FileInfoHashComputeCount);
            startCounter = KeQueryPerformanceCounter(&counterFrequency);
            hashStatus = SysmonComputeHashDigestsMasked(
                fileContent.Data,
                fileContent.Size,
                hashMask,
                &hashDigests);
            if (NT_SUCCESS(hashStatus)) {
                hashStatus = SysmonFormatHashDigestsMasked(
                    &hashDigests,
                    FileInfo->Hashes,
                    RTL_NUMBER_OF(FileInfo->Hashes));
            }
            SYSMON_FILEINFO_STAT_ADD(
                g_FileInfoHashUsecTotal,
                SysmonComputeElapsedUsec(
                    startCounter,
                    KeQueryPerformanceCounter(NULL),
                    counterFrequency));
            if (NT_SUCCESS(hashStatus) &&
                FileInfo->Hashes[0] != L'\0' &&
                FileInfo->Hashes[0] != L'-') {
                availableMask |= SYSMON_FILEINFO_REQUEST_HASHES;
            }
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            SysmonCopyWideString(
                FileInfo->Hashes,
                RTL_NUMBER_OF(FileInfo->Hashes),
                L"-");
            hashStatus = GetExceptionCode();
        }
        InterlockedExchange(&g_LastFileInfoHashStatus, (LONG)hashStatus);
    }

    if ((RequestMask & SYSMON_FILEINFO_REQUEST_VERSION_INFO) != 0) {
        FileInfo->IsPeFile = SysmonIsPeFile(fileContent.Data, fileContent.Size);
        if (FileInfo->IsPeFile) {
            __try {
                LARGE_INTEGER counterFrequency;
                LARGE_INTEGER startCounter;

                SYSMON_FILEINFO_STAT_INC(g_FileInfoVersionParseCount);
                startCounter = KeQueryPerformanceCounter(&counterFrequency);
                versionStatus = SysmonParseVersionInfo(fileContent.Data, fileContent.Size, FileInfo);
                SYSMON_FILEINFO_STAT_ADD(
                    g_FileInfoVersionUsecTotal,
                    SysmonComputeElapsedUsec(
                        startCounter,
                        KeQueryPerformanceCounter(NULL),
                        counterFrequency));
                if (NT_SUCCESS(versionStatus)) {
                    availableMask |= SYSMON_FILEINFO_REQUEST_VERSION_INFO;
                }
            } __except (EXCEPTION_EXECUTE_HANDLER) {
                versionStatus = GetExceptionCode();
            }
        }
    }

    if ((RequestMask & SYSMON_FILEINFO_REQUEST_HASHES) != 0 &&
        !NT_SUCCESS(hashStatus) &&
        fileContent.MappedView &&
        fileHandle != NULL) {
        LARGE_INTEGER hashCounterFrequency;
        LARGE_INTEGER hashStartCounter;
        LARGE_INTEGER readCounterFrequency;
        LARGE_INTEGER readStartCounter;

        hashRetryContent.Data = NULL;
        hashRetryContent.Size = 0;
        hashRetryContent.SectionHandle = NULL;
        hashRetryContent.MappedView = FALSE;

        SYSMON_FILEINFO_STAT_INC(g_FileInfoReadRetryCount);
        readStartCounter = KeQueryPerformanceCounter(&readCounterFrequency);
        status = SysmonReadFileByHandle(fileHandle, fileSize, &hashRetryContent);
        SYSMON_FILEINFO_STAT_ADD(
            g_FileInfoReadUsecTotal,
            SysmonComputeElapsedUsec(
                readStartCounter,
                KeQueryPerformanceCounter(NULL),
                readCounterFrequency));
        if (NT_SUCCESS(status)) {
            InterlockedExchange(&g_LastFileInfoContentMode, 3);
            SYSMON_FILEINFO_STAT_INC(g_FileInfoHashComputeCount);
            hashStartCounter = KeQueryPerformanceCounter(&hashCounterFrequency);
            hashStatus = SysmonComputeHashDigestsMasked(
                hashRetryContent.Data,
                hashRetryContent.Size,
                hashMask,
                &hashDigests);
            if (NT_SUCCESS(hashStatus)) {
                hashStatus = SysmonFormatHashDigestsMasked(
                    &hashDigests,
                    FileInfo->Hashes,
                    RTL_NUMBER_OF(FileInfo->Hashes));
            }
            SYSMON_FILEINFO_STAT_ADD(
                g_FileInfoHashUsecTotal,
                SysmonComputeElapsedUsec(
                    hashStartCounter,
                    KeQueryPerformanceCounter(NULL),
                    hashCounterFrequency));
            if (NT_SUCCESS(hashStatus) &&
                FileInfo->Hashes[0] != L'\0' &&
                FileInfo->Hashes[0] != L'-') {
                availableMask |= SYSMON_FILEINFO_REQUEST_HASHES;
            } else {
                SysmonCopyWideString(
                    FileInfo->Hashes,
                    RTL_NUMBER_OF(FileInfo->Hashes),
                    L"-");
            }
            InterlockedExchange(&g_LastFileInfoHashStatus, (LONG)hashStatus);
        }

        SysmonReleaseFileContent(&hashRetryContent);
    }

    if ((RequestMask & SYSMON_FILEINFO_REQUEST_HASHES) != 0 &&
        !NT_SUCCESS(hashStatus)) {
        if (_snwprintf_s(
                FileInfo->Hashes,
                RTL_NUMBER_OF(FileInfo->Hashes),
                _TRUNCATE,
                L"ERR=0x%08X",
                hashStatus) < 0) {
            SysmonCopyWideString(
                FileInfo->Hashes,
                RTL_NUMBER_OF(FileInfo->Hashes),
                L"-");
        }
    }

    SysmonReleaseFileContent(&fileContent);
    if (fileHandle != NULL) {
        ZwClose(fileHandle);
        fileHandle = NULL;
    }

    if (availableMask != 0) {
        SysmonStoreFileInfoCache(
            FilePath,
            hasFileId,
            fileId,
            availableMask,
            hashMask,
            FileInfo,
            ((availableMask & SYSMON_FILEINFO_REQUEST_HASHES) != 0) ? &hashDigests : NULL);
    }
    InterlockedExchange(&g_LastFileInfoAvailableMask, (LONG)availableMask);
    return STATUS_SUCCESS;
}

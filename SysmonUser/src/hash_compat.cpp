#include "../include/hash_compat.h"

#include <bcrypt.h>
#include <malloc.h>
#include <symcrypt.h>

#ifndef RtlZeroMemory
#define RtlZeroMemory(Destination, Length) ZeroMemory((Destination), (Length))
#endif

#ifndef RtlCopyMemory
#define RtlCopyMemory(Destination, Source, Length) CopyMemory((Destination), (Source), (Length))
#endif

#ifndef RtlCompareMemory
#define RtlCompareMemory(Source1, Source2, Length) ((memcmp((Source1), (Source2), (Length)) == 0) ? (Length) : 0)
#endif

#ifndef MAXULONG
#define MAXULONG ((ULONG)0xFFFFFFFFUL)
#endif

#define SYSMON_FILE_HASH_CACHE_CAPACITY 128
#define SYSMON_FILE_HASH_CACHE_BUCKET_COUNT 256
#define SYSMON_FILE_HASH_CACHE_PATH_CHARS 1024
#define SYSMON_FILE_HASH_CACHE_VALUE_CHARS 512

typedef struct _SYSMON_FILE_HASH_CACHE_ENTRY {
    BOOL InUse;
    DWORD HashMask;
    DWORD PathHash;
    DWORD PathLength;
    LONG NextInBucket;
    ULONGLONG FileSize;
    FILETIME LastWriteTime;
    WCHAR FilePath[SYSMON_FILE_HASH_CACHE_PATH_CHARS];
    WCHAR HashString[SYSMON_FILE_HASH_CACHE_VALUE_CHARS];
} SYSMON_FILE_HASH_CACHE_ENTRY, *PSYSMON_FILE_HASH_CACHE_ENTRY;

typedef struct _SYSMON_HASH_DESCRIPTOR {
    PCSYMCRYPT_HASH Algorithm;
    DWORD HashLength;
} SYSMON_HASH_DESCRIPTOR, *PSYSMON_HASH_DESCRIPTOR;

typedef struct _SYSMON_HASH_INSTANCE {
    PCSYMCRYPT_HASH Algorithm;
    SYMCRYPT_HASH_STATE State;
    DWORD HashLength;
    BOOL Active;
} SYSMON_HASH_INSTANCE, *PSYSMON_HASH_INSTANCE;

typedef struct _SYSMON_MD5_HASH_STATE {
    SYSMON_HASH_INSTANCE Instance;
} SYSMON_MD5_HASH_STATE, *PSYSMON_MD5_HASH_STATE;

typedef struct _SYSMON_PE_SECTION_INFO {
    ULONG VirtualAddress;
    ULONG RawOffset;
    ULONG RawSize;
    ULONG Span;
    PUCHAR Data;
    ULONG DataSize;
    BOOL Loaded;
} SYSMON_PE_SECTION_INFO, *PSYSMON_PE_SECTION_INFO;

typedef struct _SYSMON_PE_SECTION_CACHE {
    PSYSMON_PE_SECTION_INFO Sections;
    USHORT SectionCount;
    ULONG LastHitIndex;
} SYSMON_PE_SECTION_CACHE, *PSYSMON_PE_SECTION_CACHE;

typedef struct _SYSMON_IMPHASH_BUFFER_CONTEXT {
    const UCHAR *FileData;
    ULONG FileSize;
    ULONG SectionTableOffset;
    USHORT NumSections;
} SYSMON_IMPHASH_BUFFER_CONTEXT, *PSYSMON_IMPHASH_BUFFER_CONTEXT;

typedef struct _SYSMON_IMPHASH_FILE_CONTEXT {
    HANDLE FileHandle;
    ULONG FileSize;
    const SYSMON_PE_SECTION_CACHE *SectionCache;
    const UCHAR *HeaderData;
    ULONG HeaderSize;
} SYSMON_IMPHASH_FILE_CONTEXT, *PSYSMON_IMPHASH_FILE_CONTEXT;

typedef BOOLEAN (*PFN_SYSMON_IMPHASH_READ_RVA)(
    _In_ const void *Context,
    _In_ ULONG Rva,
    _In_ ULONG RequiredLength,
    _Outptr_result_bytebuffer_(RequiredLength) const UCHAR **Data,
    _Out_opt_ PULONG AvailableLength);

static INIT_ONCE g_FileHashCacheInitOnce = INIT_ONCE_STATIC_INIT;
static CRITICAL_SECTION g_FileHashCacheLock;
static SYSMON_FILE_HASH_CACHE_ENTRY g_FileHashCache[SYSMON_FILE_HASH_CACHE_CAPACITY];
static ULONG g_FileHashCacheVictim = 0;
static LONG g_FileHashCacheBuckets[SYSMON_FILE_HASH_CACHE_BUCKET_COUNT];
static INIT_ONCE g_SymCryptInitOnce = INIT_ONCE_STATIC_INIT;

// SymCrypt environment glue. This must appear at file scope in exactly one
// translation unit so SymCryptInit/SymCryptFatal resolve through this module.
SYMCRYPT_ENVIRONMENT_WINDOWS_USERMODE_LATEST;

static const SYSMON_HASH_DESCRIPTOR g_Md5HashDescriptor = {
    SymCryptMd5Algorithm,
    16
};

static const SYSMON_HASH_DESCRIPTOR g_Sha1HashDescriptor = {
    SymCryptSha1Algorithm,
    20
};

static const SYSMON_HASH_DESCRIPTOR g_Sha256HashDescriptor = {
    SymCryptSha256Algorithm,
    32
};

static BOOL CALLBACK
SysmonInitializeSymCrypt(
    PINIT_ONCE InitOnce,
    PVOID Parameter,
    PVOID *Context)
{
    UNREFERENCED_PARAMETER(InitOnce);
    UNREFERENCED_PARAMETER(Parameter);
    UNREFERENCED_PARAMETER(Context);

    SymCryptInit();
    return TRUE;
}

static BOOL
SysmonEnsureSymCryptInitialized(void)
{
    return InitOnceExecuteOnce(
        &g_SymCryptInitOnce,
        SysmonInitializeSymCrypt,
        NULL,
        NULL);
}

extern "C"
PVOID
SYMCRYPT_CALL
SymCryptCallbackAlloc(SIZE_T nBytes)
{
    return _aligned_malloc(nBytes, SYMCRYPT_ASYM_ALIGN_VALUE);
}

extern "C"
VOID
SYMCRYPT_CALL
SymCryptCallbackFree(PVOID ptr)
{
    _aligned_free(ptr);
}

extern "C"
VOID
SYMCRYPT_CALL
SymCryptProvideEntropy(
    _In_reads_(cbEntropy) PCBYTE pbEntropy,
    SIZE_T cbEntropy)
{
    // Not needed here: SymCryptRandom/SymCryptCallbackRandom source entropy
    // directly from BCryptGenRandom.
    UNREFERENCED_PARAMETER(pbEntropy);
    UNREFERENCED_PARAMETER(cbEntropy);
}

extern "C"
VOID
SYMCRYPT_CALL
SymCryptRandom(
    _Out_writes_bytes_(cbBuffer) PBYTE pbBuffer,
    SIZE_T cbBuffer)
{
    NTSTATUS status = BCryptGenRandom(BCRYPT_RNG_ALG_HANDLE, pbBuffer, (ULONG)cbBuffer, 0);
    if (!NT_SUCCESS(status)) {
        SymCryptFatal(status);
    }
}

extern "C"
SYMCRYPT_ERROR
SYMCRYPT_CALL
SymCryptCallbackRandom(
    _Out_writes_bytes_(cbBuffer) PBYTE pbBuffer,
    SIZE_T cbBuffer)
{
    NTSTATUS status = BCryptGenRandom(BCRYPT_RNG_ALG_HANDLE, pbBuffer, (ULONG)cbBuffer, 0);
    return NT_SUCCESS(status) ? SYMCRYPT_NO_ERROR : SYMCRYPT_EXTERNAL_FAILURE;
}

extern "C"
PVOID
SYMCRYPT_CALL
SymCryptCallbackAllocateMutexFastInproc(void)
{
    LPCRITICAL_SECTION criticalSection;

    criticalSection = (LPCRITICAL_SECTION)malloc(sizeof(CRITICAL_SECTION));
    if (criticalSection == NULL) {
        return NULL;
    }

    InitializeCriticalSection(criticalSection);
    return criticalSection;
}

extern "C"
VOID
SYMCRYPT_CALL
SymCryptCallbackFreeMutexFastInproc(PVOID pMutex)
{
    LPCRITICAL_SECTION criticalSection = (LPCRITICAL_SECTION)pMutex;

    if (criticalSection == NULL) {
        return;
    }

    DeleteCriticalSection(criticalSection);
    free(criticalSection);
}

extern "C"
VOID
SYMCRYPT_CALL
SymCryptCallbackAcquireMutexFastInproc(PVOID pMutex)
{
    EnterCriticalSection((LPCRITICAL_SECTION)pMutex);
}

extern "C"
VOID
SYMCRYPT_CALL
SymCryptCallbackReleaseMutexFastInproc(PVOID pMutex)
{
    LeaveCriticalSection((LPCRITICAL_SECTION)pMutex);
}

static BOOL
SysmonCreateHashInstance(
    _Out_ PSYSMON_HASH_INSTANCE Instance,
    _In_ const SYSMON_HASH_DESCRIPTOR *Descriptor,
    _In_ ULONG DigestLength)
{
    if (Instance == NULL || Descriptor == NULL || DigestLength < Descriptor->HashLength) {
        return FALSE;
    }

    ZeroMemory(Instance, sizeof(*Instance));
    if (!SysmonEnsureSymCryptInitialized()) {
        return FALSE;
    }

    Instance->Algorithm = Descriptor->Algorithm;
    Instance->HashLength = Descriptor->HashLength;
    SymCryptHashInit(Instance->Algorithm, &Instance->State);
    Instance->Active = TRUE;
    return TRUE;
}

static BOOL
SysmonUpdateHashInstance(
    _Inout_ PSYSMON_HASH_INSTANCE Instance,
    _In_reads_(Length) const UCHAR *Data,
    _In_ ULONG Length)
{
    if (Instance == NULL || !Instance->Active || Instance->Algorithm == NULL) {
        return FALSE;
    }

    if (Length == 0) {
        return TRUE;
    }

    if (Data == NULL) {
        return FALSE;
    }

    SymCryptHashAppend(Instance->Algorithm, &Instance->State, Data, Length);
    return TRUE;
}

static BOOL
SysmonFinishHashInstance(
    _Inout_ PSYSMON_HASH_INSTANCE Instance,
    _Out_writes_bytes_(DigestLength) PUCHAR Digest,
    _In_ ULONG DigestLength)
{
    if (Instance == NULL || !Instance->Active || Instance->Algorithm == NULL || Digest == NULL ||
        DigestLength < Instance->HashLength) {
        return FALSE;
    }

    SymCryptHashResult(Instance->Algorithm, &Instance->State, Digest, Instance->HashLength);
    Instance->Active = FALSE;
    return TRUE;
}

static VOID
SysmonDestroyHashInstance(_Inout_opt_ PSYSMON_HASH_INSTANCE Instance)
{
    if (Instance == NULL) {
        return;
    }

    SymCryptWipeKnownSize(&Instance->State, sizeof(Instance->State));
    ZeroMemory(Instance, sizeof(*Instance));
}

static BOOL
SysmonMd5HashBegin(_Out_ PSYSMON_MD5_HASH_STATE State)
{
    if (State == NULL) {
        return FALSE;
    }

    ZeroMemory(State, sizeof(*State));
    return SysmonCreateHashInstance(&State->Instance, &g_Md5HashDescriptor, 16);
}

static BOOL
SysmonMd5HashUpdate(
    _Inout_ PSYSMON_MD5_HASH_STATE State,
    _In_reads_(Length) const UCHAR *Data,
    _In_ ULONG Length)
{
    if (State == NULL || !State->Instance.Active) {
        return FALSE;
    }

    return SysmonUpdateHashInstance(&State->Instance, Data, Length);
}

static BOOL
SysmonMd5HashFinish(
    _Inout_ PSYSMON_MD5_HASH_STATE State,
    _Out_writes_(16) UCHAR Digest[16])
{
    if (State == NULL || !State->Instance.Active || Digest == NULL) {
        return FALSE;
    }

    return SysmonFinishHashInstance(&State->Instance, Digest, 16);
}

static VOID
SysmonMd5HashDestroy(_Inout_opt_ PSYSMON_MD5_HASH_STATE State)
{
    if (State == NULL) {
        return;
    }

    SysmonDestroyHashInstance(&State->Instance);
}

static BOOL CALLBACK
SysmonInitializeFileHashCache(
    PINIT_ONCE InitOnce,
    PVOID Parameter,
    PVOID *Context)
{
    UNREFERENCED_PARAMETER(InitOnce);
    UNREFERENCED_PARAMETER(Parameter);
    UNREFERENCED_PARAMETER(Context);

    InitializeCriticalSection(&g_FileHashCacheLock);
    ZeroMemory(g_FileHashCache, sizeof(g_FileHashCache));
    g_FileHashCacheVictim = 0;
    SysmonInitializeBucketHeads(
        g_FileHashCacheBuckets,
        RTL_NUMBER_OF(g_FileHashCacheBuckets));
    return TRUE;
}

static BOOL
SysmonEnsureFileHashCacheInitialized(VOID)
{
    return InitOnceExecuteOnce(
        &g_FileHashCacheInitOnce,
        SysmonInitializeFileHashCache,
        NULL,
        NULL);
}

static DWORD
SysmonSelectFileHashCacheBucket(
    _In_ DWORD PathHash)
{
    return PathHash % SYSMON_FILE_HASH_CACHE_BUCKET_COUNT;
}

static VOID
SysmonUnlinkFileHashCacheSlot(
    _In_ ULONG Slot)
{
    DWORD bucket;
    LONG current;
    LONG previous;

    if (Slot >= SYSMON_FILE_HASH_CACHE_CAPACITY ||
        !g_FileHashCache[Slot].InUse) {
        return;
    }

    bucket = SysmonSelectFileHashCacheBucket(g_FileHashCache[Slot].PathHash);
    current = g_FileHashCacheBuckets[bucket];
    previous = -1;
    while (current >= 0) {
        if ((ULONG)current == Slot) {
            if (previous < 0) {
                g_FileHashCacheBuckets[bucket] = g_FileHashCache[Slot].NextInBucket;
            } else {
                g_FileHashCache[previous].NextInBucket = g_FileHashCache[Slot].NextInBucket;
            }
            break;
        }

        previous = current;
        current = g_FileHashCache[current].NextInBucket;
    }

    g_FileHashCache[Slot].NextInBucket = -1;
}

static VOID
SysmonLinkFileHashCacheSlot(
    _In_ ULONG Slot)
{
    DWORD bucket;

    if (Slot >= SYSMON_FILE_HASH_CACHE_CAPACITY ||
        !g_FileHashCache[Slot].InUse) {
        return;
    }

    bucket = SysmonSelectFileHashCacheBucket(g_FileHashCache[Slot].PathHash);
    g_FileHashCache[Slot].NextInBucket = g_FileHashCacheBuckets[bucket];
    g_FileHashCacheBuckets[bucket] = (LONG)Slot;
}

static BOOL
SysmonLookupFileHashCache(
    _In_z_ PCWSTR FilePath,
    _In_ DWORD HashMask,
    _In_ ULONGLONG FileSize,
    _In_ const FILETIME *LastWriteTime,
    _Out_writes_(MaxLen) PWCHAR HashString,
    _In_ ULONG MaxLen)
{
    DWORD pathHash;
    DWORD pathLength;
    DWORD bucket;
    LONG index;
    BOOL found = FALSE;

    if (FilePath == NULL || LastWriteTime == NULL || HashString == NULL || MaxLen == 0) {
        return FALSE;
    }

    if (!SysmonEnsureFileHashCacheInitialized()) {
        return FALSE;
    }

    pathHash = SysmonComputeInsensitiveWideHash(FilePath, &pathLength);
    bucket = SysmonSelectFileHashCacheBucket(pathHash);

    EnterCriticalSection(&g_FileHashCacheLock);
    for (index = g_FileHashCacheBuckets[bucket];
         index >= 0;
         index = g_FileHashCache[index].NextInBucket) {
        const SYSMON_FILE_HASH_CACHE_ENTRY *entry = &g_FileHashCache[index];

        if (!entry->InUse ||
            entry->HashMask != HashMask ||
            entry->FileSize != FileSize ||
            entry->LastWriteTime.dwLowDateTime != LastWriteTime->dwLowDateTime ||
            entry->LastWriteTime.dwHighDateTime != LastWriteTime->dwHighDateTime) {
            continue;
        }

        if (!SysmonInsensitiveWideTextMatches(
                entry->PathHash,
                entry->PathLength,
                entry->FilePath,
                pathHash,
                pathLength,
                FilePath)) {
            continue;
        }

        wcscpy_s(HashString, MaxLen, entry->HashString);
        found = TRUE;
        break;
    }
    LeaveCriticalSection(&g_FileHashCacheLock);

    return found;
}

static VOID
SysmonStoreFileHashCache(
    _In_z_ PCWSTR FilePath,
    _In_ DWORD HashMask,
    _In_ ULONGLONG FileSize,
    _In_ const FILETIME *LastWriteTime,
    _In_z_ PCWSTR HashString)
{
    DWORD pathHash;
    DWORD pathLength;
    DWORD bucket;
    LONG index;
    ULONG slot;
    PSYSMON_FILE_HASH_CACHE_ENTRY entry;

    if (FilePath == NULL ||
        LastWriteTime == NULL ||
        HashString == NULL ||
        !SysmonEnsureFileHashCacheInitialized()) {
        return;
    }

    pathHash = SysmonComputeInsensitiveWideHash(FilePath, &pathLength);
    bucket = SysmonSelectFileHashCacheBucket(pathHash);

    EnterCriticalSection(&g_FileHashCacheLock);
    for (index = g_FileHashCacheBuckets[bucket];
         index >= 0;
         index = g_FileHashCache[index].NextInBucket) {
        entry = &g_FileHashCache[index];
        if (entry->HashMask != HashMask ||
            entry->FileSize != FileSize ||
            entry->LastWriteTime.dwLowDateTime != LastWriteTime->dwLowDateTime ||
            entry->LastWriteTime.dwHighDateTime != LastWriteTime->dwHighDateTime ||
            !SysmonInsensitiveWideTextMatches(
                entry->PathHash,
                entry->PathLength,
                entry->FilePath,
                pathHash,
                pathLength,
                FilePath)) {
            continue;
        }

        wcscpy_s(entry->HashString, _countof(entry->HashString), HashString);
        LeaveCriticalSection(&g_FileHashCacheLock);
        return;
    }

    slot = g_FileHashCacheVictim;
    g_FileHashCacheVictim = (g_FileHashCacheVictim + 1) % SYSMON_FILE_HASH_CACHE_CAPACITY;
    SysmonUnlinkFileHashCacheSlot(slot);
    entry = &g_FileHashCache[slot];
    ZeroMemory(entry, sizeof(*entry));
    entry->InUse = TRUE;
    entry->HashMask = HashMask;
    entry->PathHash = pathHash;
    entry->PathLength = pathLength;
    entry->NextInBucket = -1;
    entry->FileSize = FileSize;
    entry->LastWriteTime = *LastWriteTime;
    wcscpy_s(entry->FilePath, _countof(entry->FilePath), FilePath);
    wcscpy_s(entry->HashString, _countof(entry->HashString), HashString);
    SysmonLinkFileHashCacheSlot(slot);
    LeaveCriticalSection(&g_FileHashCacheLock);
}

/* ========================================================================
 * Hex encoding helper
 * ======================================================================== */

static VOID
SysmonBytesToHex(
    _In_reads_(ByteLen) const UCHAR *Bytes,
    _In_ ULONG ByteLen,
    _Out_writes_(ByteLen * 2 + 1) CHAR *Hex,
    _In_ ULONG HexMaxLen)
{
    static const char hexchars[] = "0123456789abcdef";
    ULONG i;

    if (HexMaxLen < ByteLen * 2 + 1) return;

    for (i = 0; i < ByteLen; i++) {
        Hex[i * 2]     = hexchars[(Bytes[i] >> 4) & 0x0F];
        Hex[i * 2 + 1] = hexchars[Bytes[i] & 0x0F];
    }
    Hex[ByteLen * 2] = '\0';
}

/* ========================================================================
 * IMPHASH: PE Import Table Hash
 * ======================================================================== */

static BOOLEAN
SysmonPeHasRange(
    _In_ ULONG FileSize,
    _In_ ULONG Offset,
    _In_ ULONG Length)
{
    return (Offset <= FileSize && Length <= (FileSize - Offset));
}

static BOOLEAN
SysmonPeAddUlong(
    _In_ ULONG Left,
    _In_ ULONG Right,
    _Out_ ULONG *Result)
{
    if (Left > (MAXULONG - Right)) {
        return FALSE;
    }

    *Result = Left + Right;
    return TRUE;
}

static USHORT
SysmonReadUnalignedUshort(_In_reads_bytes_(sizeof(USHORT)) const void *Data)
{
    USHORT value = 0;

    if (Data != NULL) {
        RtlCopyMemory(&value, Data, sizeof(value));
    }
    return value;
}

static ULONG
SysmonReadUnalignedUlong(_In_reads_bytes_(sizeof(ULONG)) const void *Data)
{
    ULONG value = 0;

    if (Data != NULL) {
        RtlCopyMemory(&value, Data, sizeof(value));
    }
    return value;
}

static ULONGLONG
SysmonReadUnalignedUlongLong(_In_reads_bytes_(sizeof(ULONGLONG)) const void *Data)
{
    ULONGLONG value = 0;

    if (Data != NULL) {
        RtlCopyMemory(&value, Data, sizeof(value));
    }
    return value;
}

static BOOLEAN
SysmonPeGetLayout(
    _In_reads_(FileSize) const UCHAR *FileData,
    _In_ ULONG FileSize,
    _Out_opt_ ULONG *PeOffset,
    _Out_opt_ USHORT *NumSections,
    _Out_opt_ ULONG *SectionTableOffset,
    _Out_opt_ USHORT *OptHdrSize,
    _Out_opt_ BOOLEAN *Is64)
{
    ULONG peOffset;
    ULONG sectionTableOffset;
    USHORT numSections;
    USHORT optHdrSize;
    USHORT magic;
    ULONG sectionTableSize;

    if (FileData == NULL || !SysmonPeHasRange(FileSize, 0, 0x40)) {
        return FALSE;
    }

    if (FileData[0] != 'M' || FileData[1] != 'Z') {
        return FALSE;
    }

    peOffset = SysmonReadUnalignedUlong(FileData + 0x3C);
    if (!SysmonPeHasRange(FileSize, peOffset, 0x1A)) {
        return FALSE;
    }

    if (RtlCompareMemory(FileData + peOffset, "PE\0\0", 4) != 4) {
        return FALSE;
    }

    numSections = SysmonReadUnalignedUshort(FileData + peOffset + 0x06);
    optHdrSize = SysmonReadUnalignedUshort(FileData + peOffset + 0x14);
    magic = SysmonReadUnalignedUshort(FileData + peOffset + 0x18);

    if (magic != 0x10b && magic != 0x20b) {
        return FALSE;
    }

    if (!SysmonPeAddUlong(peOffset, 0x18, &sectionTableOffset) ||
        !SysmonPeAddUlong(sectionTableOffset, optHdrSize, &sectionTableOffset)) {
        return FALSE;
    }

    if (numSections > (MAXULONG / 40)) {
        return FALSE;
    }
    sectionTableSize = (ULONG)numSections * 40;
    if (!SysmonPeHasRange(FileSize, sectionTableOffset, sectionTableSize)) {
        return FALSE;
    }

    if (PeOffset != NULL) {
        *PeOffset = peOffset;
    }
    if (NumSections != NULL) {
        *NumSections = numSections;
    }
    if (SectionTableOffset != NULL) {
        *SectionTableOffset = sectionTableOffset;
    }
    if (OptHdrSize != NULL) {
        *OptHdrSize = optHdrSize;
    }
    if (Is64 != NULL) {
        *Is64 = (magic == 0x20b);
    }

    return TRUE;
}

static BOOLEAN
SysmonPeBufferLooksValid(
    _In_reads_(FileSize) const UCHAR *FileData,
    _In_ ULONG FileSize)
{
    return SysmonPeGetLayout(FileData, FileSize, NULL, NULL, NULL, NULL, NULL);
}

/* Normalize a name to lowercase ASCII */
static VOID
SysmonNormalizeName(
    _Inout_ CHAR *Name,
    _In_ ULONG Len)
{
    ULONG i;
    for (i = 0; i < Len && Name[i] != '\0'; i++) {
        if (Name[i] >= 'A' && Name[i] <= 'Z') {
            Name[i] = Name[i] - 'A' + 'a';
        }
    }
}

/* Strip .dll/.drv/.sys extension from DLL name */
static ULONG
SysmonStripExtension(_Inout_ CHAR *Name)
{
    ULONG len = 0;
    ULONG lastDot = 0;
    ULONG i;

    for (i = 0; Name[i] != '\0'; i++) {
        if (Name[i] == '.') lastDot = i;
        len++;
    }

    if (lastDot > 0) {
        /* Check common extensions */
        CHAR *ext = Name + lastDot;
        if (_stricmp(ext, ".dll") == 0 || _stricmp(ext, ".drv") == 0 ||
            _stricmp(ext, ".sys") == 0 || _stricmp(ext, ".ocx") == 0) {
            Name[lastDot] = '\0';
            return lastDot;
        }
    }
    return len;
}

static BOOLEAN
SysmonPeMapRvaToPointer(
    _In_reads_(FileSize) const UCHAR *FileData,
    _In_ ULONG FileSize,
    _In_ ULONG SectionTableOffset,
    _In_ USHORT NumSections,
    _In_ ULONG Rva,
    _In_ ULONG RequiredLength,
    _Outptr_result_bytebuffer_(RequiredLength) const UCHAR **Data,
    _Out_opt_ ULONG *AvailableLength)
{
    USHORT index;

    if (Data == NULL) {
        return FALSE;
    }

    *Data = NULL;
    if (AvailableLength != NULL) {
        *AvailableLength = 0;
    }

    for (index = 0; index < NumSections; index++) {
        const UCHAR *section;
        ULONG virtualSize;
        ULONG virtualAddress;
        ULONG rawSize;
        ULONG rawOffset;
        ULONG span;
        ULONG delta;
        ULONG available;

        if (!SysmonPeHasRange(FileSize, SectionTableOffset + (ULONG)index * 40, 40)) {
            return FALSE;
        }

        section = FileData + SectionTableOffset + (ULONG)index * 40;
        virtualSize = *(const ULONG *)(section + 8);
        virtualAddress = *(const ULONG *)(section + 12);
        rawSize = *(const ULONG *)(section + 16);
        rawOffset = *(const ULONG *)(section + 20);
        span = (virtualSize > rawSize) ? virtualSize : rawSize;

        if (Rva < virtualAddress || Rva >= virtualAddress + span) {
            continue;
        }

        delta = Rva - virtualAddress;
        if (delta > rawSize || !SysmonPeHasRange(FileSize, rawOffset, rawSize)) {
            return FALSE;
        }

        available = rawSize - delta;
        if (RequiredLength > available || !SysmonPeHasRange(FileSize, rawOffset + delta, RequiredLength)) {
            return FALSE;
        }

        *Data = FileData + rawOffset + delta;
        if (AvailableLength != NULL) {
            *AvailableLength = available;
        }
        return TRUE;
    }

    if (SysmonPeHasRange(FileSize, Rva, RequiredLength)) {
        *Data = FileData + Rva;
        if (AvailableLength != NULL) {
            *AvailableLength = FileSize - Rva;
        }
        return TRUE;
    }

    return FALSE;
}

static ULONG
SysmonFormatImportOrdinalName(
    _Out_writes_(BufferChars) CHAR *Buffer,
    _In_ ULONG BufferChars,
    _In_ USHORT Ordinal)
{
    CHAR reversed[8];
    ULONG reversedLength = 0;
    ULONG length = 0;

    if (Buffer == NULL || BufferChars < 5) {
        return 0;
    }

    Buffer[length++] = 'o';
    Buffer[length++] = 'r';
    Buffer[length++] = 'd';

    if (Ordinal == 0) {
        Buffer[length++] = '0';
    } else {
        USHORT value = Ordinal;
        while (value > 0 && reversedLength < RTL_NUMBER_OF(reversed)) {
            reversed[reversedLength++] = (CHAR)('0' + (value % 10));
            value = (USHORT)(value / 10);
        }

        while (reversedLength > 0 && length + 1 < BufferChars) {
            Buffer[length++] = reversed[--reversedLength];
        }
    }

    Buffer[length] = '\0';
    return length;
}


/* Forward declaration */
static NTSTATUS
SysmonParseImportsAndHash(
    _In_ const UCHAR *FileData,
    _In_ ULONG FileSize,
    _Out_ UCHAR Digest[16]);

static BOOL
SysmonComputeHashesMasked(
    _In_reads_(FileSize) const UCHAR *FileData,
    _In_ ULONG FileSize,
    _In_ DWORD HashMask,
    _Out_writes_(MaxLen) PWCHAR HashString,
    _In_ ULONG MaxLen);

NTSTATUS
SysmonComputeImphash(
    _In_reads_(FileSize) const UCHAR *FileData,
    _In_ ULONG FileSize,
    _Out_writes_(16) UCHAR Digest[16])
{
    return SysmonParseImportsAndHash(FileData, FileSize, Digest);
}

/* Helper: read a VA from the PE, validate it's within file bounds */
static BOOLEAN
SysmonPeReadVa(
    _In_ const UCHAR *FileData,
    _In_ ULONG FileSize,
    _In_ ULONGLONG Va,
    _In_ ULONG Rva,
    _Out_ ULONG *FileOffset)
{
    ULONGLONG offset;
    if (Va < Rva) return FALSE;
    offset = Va - Rva;
    if (offset >= FileSize) return FALSE;
    *FileOffset = (ULONG)offset;
    return TRUE;
}

/* Helper: find section containing RVA */
static BOOLEAN
SysmonInitializeSectionCache(
    _In_reads_(FileSize) const UCHAR *FileData,
    _In_ ULONG FileSize,
    _Out_ PSYSMON_PE_SECTION_CACHE Cache)
{
    USHORT numSections;
    ULONG sectionTableOffset;
    ULONG i;

    if (Cache == NULL) {
        return FALSE;
    }

    ZeroMemory(Cache, sizeof(*Cache));
    if (!SysmonPeGetLayout(FileData, FileSize, NULL, &numSections, &sectionTableOffset, NULL, NULL)) {
        return FALSE;
    }

    Cache->Sections = (PSYSMON_PE_SECTION_INFO)SYSMON_ALLOC(
        (SIZE_T)numSections * sizeof(*Cache->Sections));
    if (Cache->Sections == NULL) {
        return FALSE;
    }

    Cache->SectionCount = numSections;
    Cache->LastHitIndex = MAXULONG;

    for (i = 0; i < numSections; i++) {
        ULONG secOff = sectionTableOffset + i * 40;
        ULONG secRva, secSize, secRawOff, secRawSize;
        PSYSMON_PE_SECTION_INFO section;

        if (!SysmonPeHasRange(FileSize, secOff, 40)) {
            SYSMON_FREE(Cache->Sections);
            ZeroMemory(Cache, sizeof(*Cache));
            return FALSE;
        }

        section = &Cache->Sections[i];
        secRva = *(ULONG *)(FileData + secOff + 0x0C);
        secSize = *(ULONG *)(FileData + secOff + 0x08);
        secRawSize = *(ULONG *)(FileData + secOff + 0x10);
        secRawOff = *(ULONG *)(FileData + secOff + 0x14);
        section->VirtualAddress = secRva;
        section->RawOffset = secRawOff;
        section->RawSize = secRawSize;
        section->Span = (secRawSize > secSize) ? secRawSize : secSize;
        section->Data = NULL;
        section->DataSize = 0;
        section->Loaded = FALSE;
    }

    return TRUE;
}

static VOID
SysmonFreeSectionCache(
    _Inout_ PSYSMON_PE_SECTION_CACHE Cache)
{
    if (Cache == NULL) {
        return;
    }

    if (Cache->Sections != NULL) {
        USHORT index;

        for (index = 0; index < Cache->SectionCount; index++) {
            SYSMON_FREE(Cache->Sections[index].Data);
            Cache->Sections[index].Data = NULL;
            Cache->Sections[index].DataSize = 0;
            Cache->Sections[index].Loaded = FALSE;
        }
    }

    SYSMON_FREE(Cache->Sections);
    ZeroMemory(Cache, sizeof(*Cache));
}

static BOOLEAN
SysmonFindSectionInfo(
    _In_ const SYSMON_PE_SECTION_CACHE *Cache,
    _In_ ULONG Rva,
    _Out_ PSYSMON_PE_SECTION_INFO *SectionInfo)
{
    ULONG index;

    if (Cache == NULL || Cache->Sections == NULL || SectionInfo == NULL) {
        return FALSE;
    }

    if (Cache->LastHitIndex < Cache->SectionCount) {
        PSYSMON_PE_SECTION_INFO section = &Cache->Sections[Cache->LastHitIndex];

        if (Rva >= section->VirtualAddress &&
            (Rva - section->VirtualAddress) < section->Span) {
            *SectionInfo = section;
            return TRUE;
        }
    }

    for (index = 0; index < Cache->SectionCount; index++) {
        PSYSMON_PE_SECTION_INFO section = &Cache->Sections[index];

        if (Rva >= section->VirtualAddress &&
            (Rva - section->VirtualAddress) < section->Span) {
            ((PSYSMON_PE_SECTION_CACHE)Cache)->LastHitIndex = index;
            *SectionInfo = section;
            return TRUE;
        }
    }

    return FALSE;
}

static BOOLEAN
SysmonFindSection(
    _In_ const SYSMON_PE_SECTION_CACHE *Cache,
    _In_ ULONG Rva,
    _Out_ ULONG *SectionRva,
    _Out_ ULONG *SectionOffset,
    _Out_ ULONG *SectionRawSize)
{
    PSYSMON_PE_SECTION_INFO section;

    if (Cache == NULL || Cache->Sections == NULL) {
        return FALSE;
    }

    if (SysmonFindSectionInfo(Cache, Rva, &section)) {
        *SectionRva = section->VirtualAddress;
        *SectionOffset = section->RawOffset;
        *SectionRawSize = section->RawSize;
        return TRUE;
    }

    return FALSE;
}

/* Convert RVA to file offset */
static BOOLEAN
SysmonRvaToOffset(
    _In_ const SYSMON_PE_SECTION_CACHE *Cache,
    _In_ ULONG FileSize,
    _In_ ULONG Rva,
    _In_ ULONG RequiredLength,
    _Out_ ULONG *FileOffset)
{
    ULONG secRva, secRawOff, secRawSize;

    if (SysmonFindSection(Cache, Rva, &secRva, &secRawOff, &secRawSize)) {
        ULONG delta = Rva - secRva;

        if (delta > secRawSize || RequiredLength > (secRawSize - delta)) {
            return FALSE;
        }

        if (!SysmonPeAddUlong(secRawOff, delta, FileOffset)) {
            return FALSE;
        }

        if (SysmonPeHasRange(FileSize, *FileOffset, RequiredLength)) {
            return TRUE;
        }
    }

    if (SysmonPeHasRange(FileSize, Rva, RequiredLength)) {
        *FileOffset = Rva;
        return TRUE;
    }

    return FALSE;
}

static BOOLEAN
SysmonPeGetDataViewAtRva(
    _In_ const SYSMON_PE_SECTION_CACHE *Cache,
    _In_reads_(FileSize) const UCHAR *FileData,
    _In_ ULONG FileSize,
    _In_ ULONG Rva,
    _In_ ULONG RequiredLength,
    _Outptr_result_bytebuffer_(RequiredLength) const UCHAR **Data,
    _Out_opt_ PULONG AvailableLength)
{
    PSYSMON_PE_SECTION_INFO section;
    ULONG delta;
    ULONG offset;
    ULONG available;

    if (Data == NULL) {
        return FALSE;
    }

    *Data = NULL;
    if (AvailableLength != NULL) {
        *AvailableLength = 0;
    }

    if (FileData == NULL || Cache == NULL) {
        return FALSE;
    }

    if (SysmonFindSectionInfo(Cache, Rva, &section)) {
        delta = Rva - section->VirtualAddress;
        if (delta > section->RawSize || RequiredLength > (section->RawSize - delta)) {
            return FALSE;
        }

        if (!SysmonPeAddUlong(section->RawOffset, delta, &offset) ||
            !SysmonPeHasRange(FileSize, offset, RequiredLength)) {
            return FALSE;
        }

        available = section->RawSize - delta;
        if (available > (FileSize - offset)) {
            available = FileSize - offset;
        }

        *Data = FileData + offset;
        if (AvailableLength != NULL) {
            *AvailableLength = available;
        }
        return TRUE;
    }

    if (!SysmonPeHasRange(FileSize, Rva, RequiredLength)) {
        return FALSE;
    }

    *Data = FileData + Rva;
    if (AvailableLength != NULL) {
        *AvailableLength = FileSize - Rva;
    }
    return TRUE;
}

static BOOLEAN
SysmonReadFileBytesAtOffset(
    _In_ HANDLE FileHandle,
    _In_ ULONG FileOffset,
    _Out_writes_bytes_(Length) PUCHAR Buffer,
    _In_ ULONG Length)
{
    LARGE_INTEGER offset;
    DWORD bytesRead = 0;

    if (FileHandle == INVALID_HANDLE_VALUE || Buffer == NULL || Length == 0) {
        return FALSE;
    }

    offset.QuadPart = FileOffset;
    if (!SetFilePointerEx(FileHandle, offset, NULL, FILE_BEGIN)) {
        return FALSE;
    }

    return ReadFile(FileHandle, Buffer, Length, &bytesRead, NULL) && bytesRead == Length;
}

static BOOLEAN
SysmonEnsureSectionLoadedFromFile(
    _In_ HANDLE FileHandle,
    _In_ ULONG FileSize,
    _Inout_ PSYSMON_PE_SECTION_INFO Section)
{
    if (Section == NULL) {
        return FALSE;
    }

    if (Section->Loaded) {
        return Section->Data != NULL || Section->DataSize == 0;
    }

    Section->Loaded = TRUE;
    Section->Data = NULL;
    Section->DataSize = 0;

    if (Section->RawSize == 0) {
        return TRUE;
    }

    if (!SysmonPeHasRange(FileSize, Section->RawOffset, Section->RawSize)) {
        return FALSE;
    }

    Section->Data = (PUCHAR)SYSMON_ALLOC(Section->RawSize);
    if (Section->Data == NULL) {
        return FALSE;
    }

    if (!SysmonReadFileBytesAtOffset(FileHandle, Section->RawOffset, Section->Data, Section->RawSize)) {
        SYSMON_FREE(Section->Data);
        Section->Data = NULL;
        return FALSE;
    }

    Section->DataSize = Section->RawSize;
    return TRUE;
}

static BOOLEAN
SysmonPeReadFileRva(
    _In_ HANDLE FileHandle,
    _In_ ULONG FileSize,
    _In_ const SYSMON_PE_SECTION_CACHE *Cache,
    _In_reads_(HeaderSize) const UCHAR *HeaderData,
    _In_ ULONG HeaderSize,
    _In_ ULONG Rva,
    _In_ ULONG RequiredLength,
    _Outptr_result_bytebuffer_(RequiredLength) const UCHAR **Data,
    _Out_opt_ PULONG AvailableLength)
{
    PSYSMON_PE_SECTION_INFO section;
    ULONG delta;

    if (Data == NULL) {
        return FALSE;
    }

    *Data = NULL;
    if (AvailableLength != NULL) {
        *AvailableLength = 0;
    }
    if (!SysmonFindSectionInfo(Cache, Rva, &section)) {
        if (HeaderData != NULL &&
            SysmonPeHasRange(HeaderSize, Rva, RequiredLength)) {
            *Data = HeaderData + Rva;
            if (AvailableLength != NULL) {
                *AvailableLength = HeaderSize - Rva;
            }
            return TRUE;
        }
        return FALSE;
    }

    delta = Rva - section->VirtualAddress;
    if (delta > section->RawSize || RequiredLength > (section->RawSize - delta)) {
        return FALSE;
    }

    if (!SysmonEnsureSectionLoadedFromFile(FileHandle, FileSize, section)) {
        return FALSE;
    }

    if (section->Data == NULL || RequiredLength > (section->DataSize - delta)) {
        return FALSE;
    }

    *Data = section->Data + delta;
    if (AvailableLength != NULL) {
        *AvailableLength = section->DataSize - delta;
    }
    return TRUE;
}

static BOOLEAN
SysmonReadImportRvaFromBuffer(
    _In_ const void *Context,
    _In_ ULONG Rva,
    _In_ ULONG RequiredLength,
    _Outptr_result_bytebuffer_(RequiredLength) const UCHAR **Data,
    _Out_opt_ PULONG AvailableLength)
{
    const SYSMON_IMPHASH_BUFFER_CONTEXT *bufferContext;

    bufferContext = (const SYSMON_IMPHASH_BUFFER_CONTEXT *)Context;
    if (bufferContext == NULL) {
        return FALSE;
    }

    return SysmonPeMapRvaToPointer(
        bufferContext->FileData,
        bufferContext->FileSize,
        bufferContext->SectionTableOffset,
        bufferContext->NumSections,
        Rva,
        RequiredLength,
        Data,
        AvailableLength);
}

static BOOLEAN
SysmonReadImportRvaFromFile(
    _In_ const void *Context,
    _In_ ULONG Rva,
    _In_ ULONG RequiredLength,
    _Outptr_result_bytebuffer_(RequiredLength) const UCHAR **Data,
    _Out_opt_ PULONG AvailableLength)
{
    const SYSMON_IMPHASH_FILE_CONTEXT *fileContext;

    fileContext = (const SYSMON_IMPHASH_FILE_CONTEXT *)Context;
    if (fileContext == NULL) {
        return FALSE;
    }

    return SysmonPeReadFileRva(
        fileContext->FileHandle,
        fileContext->FileSize,
        fileContext->SectionCache,
        fileContext->HeaderData,
        fileContext->HeaderSize,
        Rva,
        RequiredLength,
        Data,
        AvailableLength);
}

static NTSTATUS
SysmonHashImportsFromReader(
    _In_ BOOLEAN Is64,
    _In_ ULONG ImportDirRva,
    _In_ ULONG ImportDirSize,
    _In_ PFN_SYSMON_IMPHASH_READ_RVA ReadRva,
    _In_ const void *ReadContext,
    _Out_ UCHAR Digest[16])
{
    SYSMON_MD5_HASH_STATE md5ctx;
    ULONG importEnd;
    ULONG descriptorIndex;
    BOOLEAN firstFunc;
    NTSTATUS status;
    BOOL md5Initialized;

    if (ReadRva == NULL || Digest == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    status = STATUS_INVALID_PARAMETER;
    if (ImportDirRva == 0 || ImportDirSize == 0) {
        if (!SysmonMd5HashBegin(&md5ctx)) {
            return STATUS_INVALID_PARAMETER;
        }
        md5Initialized = TRUE;
        if (!SysmonMd5HashFinish(&md5ctx, Digest)) {
            goto cleanup;
        }
        status = STATUS_SUCCESS;
        goto cleanup;
    }

    if (!SysmonPeAddUlong(ImportDirRva, ImportDirSize, &importEnd) ||
        ImportDirSize < 20 ||
        !SysmonMd5HashBegin(&md5ctx)) {
        return STATUS_INVALID_PARAMETER;
    }

    md5Initialized = TRUE;
    firstFunc = TRUE;
    for (descriptorIndex = 0; descriptorIndex < (ImportDirSize / 20); descriptorIndex++) {
        const UCHAR *descriptor;
        ULONG descriptorRva;
        ULONG descriptorAvailable;
        ULONG nameRva;
        ULONG iltRva;
        CHAR dllName[256];
        ULONG dllNameLen;
        ULONG entryIndex;

        if (descriptorIndex > (MAXULONG / 20) ||
            !SysmonPeAddUlong(ImportDirRva, descriptorIndex * 20, &descriptorRva) ||
            !SysmonPeHasRange(importEnd, descriptorRva, 20) ||
            !ReadRva(ReadContext, descriptorRva, 20, &descriptor, &descriptorAvailable) ||
            descriptorAvailable < 20) {
            break;
        }

        iltRva = SysmonReadUnalignedUlong(descriptor + 0x00);
        nameRva = SysmonReadUnalignedUlong(descriptor + 0x0C);
        if (nameRva == 0 && iltRva == 0) {
            break;
        }
        if (nameRva == 0) {
            continue;
        }

        {
            const UCHAR *dllNameData;
            ULONG dllNameAvailable = 0;

            dllNameLen = 0;
            if (!ReadRva(ReadContext, nameRva, 1, &dllNameData, &dllNameAvailable)) {
                continue;
            }

            while (dllNameLen < 255 &&
                   dllNameLen < dllNameAvailable &&
                   dllNameData[dllNameLen] != 0) {
                dllName[dllNameLen] = (CHAR)dllNameData[dllNameLen];
                dllNameLen++;
            }
            dllName[dllNameLen] = '\0';
        }

        SysmonNormalizeName(dllName, dllNameLen);
        dllNameLen = SysmonStripExtension(dllName);
        if (dllNameLen == 0) {
            continue;
        }

        if (iltRva == 0) {
            ULONG origFirstThunkRva = SysmonReadUnalignedUlong(descriptor + 0x10);
            if (origFirstThunkRva == 0) {
                continue;
            }
            iltRva = origFirstThunkRva;
        }

        for (entryIndex = 0; ; entryIndex++) {
            const UCHAR *entryData;
            ULONG entrySize = Is64 ? 8 : 4;
            ULONG entryRva;
            ULONG entryAvailable = 0;
            ULONGLONG entry;
            CHAR funcName[256];
            ULONG funcNameLen;

            if (entryIndex > (MAXULONG / entrySize) ||
                !SysmonPeAddUlong(iltRva, entryIndex * entrySize, &entryRva) ||
                !ReadRva(ReadContext, entryRva, entrySize, &entryData, &entryAvailable) ||
                entryAvailable < entrySize) {
                break;
            }

            entry = Is64
                ? SysmonReadUnalignedUlongLong(entryData)
                : (ULONGLONG)SysmonReadUnalignedUlong(entryData);
            if (entry == 0) {
                break;
            }

            if ((Is64 && (entry & 0x8000000000000000ULL) != 0) ||
                (!Is64 && (entry & 0x80000000U) != 0)) {
                funcNameLen = SysmonFormatImportOrdinalName(
                    funcName,
                    RTL_NUMBER_OF(funcName),
                    (USHORT)(entry & 0xFFFF));
            } else {
                ULONG hintRva;
                const UCHAR *funcNameData;
                ULONG funcNameAvailable = 0;

                hintRva = Is64 ? (ULONG)(entry & 0x7FFFFFFFFFFFFFFFULL) : (ULONG)entry;
                if (!ReadRva(ReadContext, hintRva, 3, &funcNameData, &funcNameAvailable) ||
                    funcNameAvailable <= 2) {
                    continue;
                }

                funcNameData += 2;
                funcNameAvailable -= 2;
                funcNameLen = 0;
                while (funcNameLen < 255 &&
                       funcNameLen < funcNameAvailable &&
                       funcNameData[funcNameLen] != 0) {
                    funcName[funcNameLen] = (CHAR)funcNameData[funcNameLen];
                    funcNameLen++;
                }
                funcName[funcNameLen] = '\0';
                SysmonNormalizeName(funcName, funcNameLen);
            }

            if (funcNameLen == 0) {
                continue;
            }

            if (!firstFunc) {
                if (!SysmonMd5HashUpdate(&md5ctx, (const UCHAR *)",", 1)) {
                    goto cleanup;
                }
            }
            if (!SysmonMd5HashUpdate(&md5ctx, (const UCHAR *)dllName, dllNameLen) ||
                !SysmonMd5HashUpdate(&md5ctx, (const UCHAR *)".", 1) ||
                !SysmonMd5HashUpdate(&md5ctx, (const UCHAR *)funcName, funcNameLen)) {
                goto cleanup;
            }
            firstFunc = FALSE;
        }
    }

    if (!SysmonMd5HashFinish(&md5ctx, Digest)) {
        goto cleanup;
    }
    status = STATUS_SUCCESS;

cleanup:
    if (md5Initialized) {
        SysmonMd5HashDestroy(&md5ctx);
    }
    return status;
}

static NTSTATUS
SysmonParseImportsAndHash(
    _In_ const UCHAR *FileData,
    _In_ ULONG FileSize,
    _Out_ UCHAR Digest[16])
{
    SYSMON_IMPHASH_BUFFER_CONTEXT bufferContext;
    ULONG peOffset;
    USHORT numSections;
    ULONG sectionTableOffset;
    USHORT optHdrSize;
    ULONG importDirRva = 0;
    ULONG importDirSize = 0;
    BOOLEAN is64;
    ULONG dirOffset;

    if (!SysmonPeGetLayout(
            FileData,
            FileSize,
            &peOffset,
            &numSections,
            &sectionTableOffset,
            &optHdrSize,
            &is64)) {
        return STATUS_INVALID_PARAMETER;
    }

    /* Get import directory from optional header data directory */
    if (is64) {
        if (optHdrSize < 0x78) {
            return STATUS_INVALID_PARAMETER;
        }
        if (!SysmonPeAddUlong(peOffset, 0x88, &dirOffset) ||
            !SysmonPeHasRange(FileSize, dirOffset, 8)) {
            return STATUS_INVALID_PARAMETER;
        }
    } else {
        if (optHdrSize < 0x68) {
            return STATUS_INVALID_PARAMETER;
        }
        if (!SysmonPeAddUlong(peOffset, 0x78, &dirOffset) ||
            !SysmonPeHasRange(FileSize, dirOffset, 8)) {
            return STATUS_INVALID_PARAMETER;
        }
    }

    importDirRva = SysmonReadUnalignedUlong(FileData + dirOffset);
    importDirSize = SysmonReadUnalignedUlong(FileData + dirOffset + 4);

    bufferContext.FileData = FileData;
    bufferContext.FileSize = FileSize;
    bufferContext.SectionTableOffset = sectionTableOffset;
    bufferContext.NumSections = numSections;

    return SysmonHashImportsFromReader(
        is64,
        importDirRva,
        importDirSize,
        SysmonReadImportRvaFromBuffer,
        &bufferContext,
        Digest);
}

static NTSTATUS
SysmonComputeFileImphash(
    _In_ HANDLE FileHandle,
    _In_ ULONG FileSize,
    _Out_ UCHAR Digest[16])
{
    SYSMON_PE_SECTION_CACHE sectionCache;
    SYSMON_IMPHASH_FILE_CONTEXT fileContext;
    UCHAR *headerData;
    NTSTATUS status;
    ULONG peOffset;
    USHORT optHdrSize;
    ULONG importDirRva = 0;
    ULONG importDirSize = 0;
    ULONG headerBytes;
    BOOLEAN is64;
    ULONG dirOffset;

    if (FileHandle == INVALID_HANDLE_VALUE || Digest == NULL || FileSize == 0) {
        return STATUS_INVALID_PARAMETER;
    }

    status = STATUS_INVALID_PARAMETER;
    ZeroMemory(&sectionCache, sizeof(sectionCache));
    headerData = NULL;
    headerBytes = (FileSize < 0x10000) ? FileSize : 0x10000;
    headerData = (UCHAR *)SYSMON_ALLOC(headerBytes);
    if (headerData == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    if (!SysmonReadFileBytesAtOffset(
            FileHandle,
            0,
            headerData,
            headerBytes)) {
        goto cleanup;
    }

    if (!SysmonPeGetLayout(
            headerData,
            headerBytes,
            &peOffset,
            NULL,
            NULL,
            &optHdrSize,
            &is64)) {
        goto cleanup;
    }

    if (!SysmonInitializeSectionCache(headerData, headerBytes, &sectionCache)) {
        goto cleanup;
    }

    if (is64) {
        if (optHdrSize < 0x78) {
            goto cleanup;
        }
        if (!SysmonPeAddUlong(peOffset, 0x88, &dirOffset) ||
            !SysmonPeHasRange(headerBytes, dirOffset, 8)) {
            goto cleanup;
        }
    } else {
        if (optHdrSize < 0x68) {
            goto cleanup;
        }
        if (!SysmonPeAddUlong(peOffset, 0x78, &dirOffset) ||
            !SysmonPeHasRange(headerBytes, dirOffset, 8)) {
            goto cleanup;
        }
    }

    importDirRva = SysmonReadUnalignedUlong(headerData + dirOffset);
    importDirSize = SysmonReadUnalignedUlong(headerData + dirOffset + 4);

    fileContext.FileHandle = FileHandle;
    fileContext.FileSize = FileSize;
    fileContext.SectionCache = &sectionCache;
    fileContext.HeaderData = headerData;
    fileContext.HeaderSize = headerBytes;

    status = SysmonHashImportsFromReader(
        is64,
        importDirRva,
        importDirSize,
        SysmonReadImportRvaFromFile,
        &fileContext,
        Digest);

cleanup:
    SysmonFreeSectionCache(&sectionCache);
    if (headerData != NULL) {
        SYSMON_FREE(headerData);
    }
    return status;
}

static BOOL
SysmonAppendSelectedHash(
    _Inout_updates_(MaxLen) PWCHAR HashString,
    _In_ ULONG MaxLen,
    _In_z_ PCWSTR Name,
    _In_z_ PCSTR Value,
    _Inout_ PBOOL First)
{
    size_t offset;

    if (HashString == NULL || Name == NULL || Value == NULL || First == NULL || MaxLen == 0) {
        return FALSE;
    }

    if (!*First) {
        wcscat_s(HashString, MaxLen, L",");
    }

    offset = wcslen(HashString);
    if (_snwprintf_s(
            HashString + offset,
            MaxLen - offset,
            _TRUNCATE,
            L"%ls=%S",
            Name,
            Value) < 0) {
        return FALSE;
    }

    *First = FALSE;
    return TRUE;
}

static BOOL
SysmonFormatSelectedHashes(
    _In_ DWORD HashMask,
    _In_z_ PCSTR Md5Hex,
    _In_z_ PCSTR Sha1Hex,
    _In_z_ PCSTR Sha256Hex,
    _In_z_ PCSTR ImphashHex,
    _Out_writes_(MaxLen) PWCHAR HashString,
    _In_ ULONG MaxLen)
{
    BOOL first = TRUE;
    BOOL any = FALSE;

    if (HashString == NULL || MaxLen == 0) {
        return FALSE;
    }

    HashString[0] = L'\0';
    if ((HashMask & SYSMON_HASH_SHA1) != 0) {
        any = SysmonAppendSelectedHash(HashString, MaxLen, L"SHA1", Sha1Hex, &first) || any;
    }
    if ((HashMask & SYSMON_HASH_MD5) != 0) {
        any = SysmonAppendSelectedHash(HashString, MaxLen, L"MD5", Md5Hex, &first) || any;
    }
    if ((HashMask & SYSMON_HASH_SHA256) != 0) {
        any = SysmonAppendSelectedHash(HashString, MaxLen, L"SHA256", Sha256Hex, &first) || any;
    }
    if ((HashMask & SYSMON_HASH_IMPHASH) != 0) {
        any = SysmonAppendSelectedHash(HashString, MaxLen, L"IMPHASH", ImphashHex, &first) || any;
    }

    return any && HashString[0] != L'\0';
}

static BOOL
SysmonHashBufferWithDescriptor(
    _In_ const SYSMON_HASH_DESCRIPTOR *Descriptor,
    _In_reads_(DataLength) const UCHAR *Data,
    _In_ ULONG DataLength,
    _Out_writes_bytes_(DigestLength) PUCHAR Digest,
    _In_ ULONG DigestLength)
{
    SYSMON_HASH_INSTANCE instance;
    BOOL success = FALSE;

    ZeroMemory(&instance, sizeof(instance));
    if (!SysmonCreateHashInstance(&instance, Descriptor, DigestLength)) {
        return FALSE;
    }

    success = SysmonUpdateHashInstance(&instance, Data, DataLength) &&
        SysmonFinishHashInstance(&instance, Digest, DigestLength);
    SysmonDestroyHashInstance(&instance);
    return success;
}

NTSTATUS
SysmonComputeHashes(
    _In_reads_(FileSize) const UCHAR *FileData,
    _In_ ULONG FileSize,
    _Out_writes_(MaxLen) WCHAR *HashString,
    _In_ ULONG MaxLen)
{
    return SysmonComputeHashesMasked(
        FileData,
        FileSize,
        SYSMON_HASH_MD5 | SYSMON_HASH_SHA1 | SYSMON_HASH_SHA256 | SYSMON_HASH_IMPHASH,
        HashString,
        MaxLen)
            ? STATUS_SUCCESS
            : STATUS_INVALID_PARAMETER;
}

static BOOL
SysmonComputeHashesMasked(
    _In_reads_(FileSize) const UCHAR *FileData,
    _In_ ULONG FileSize,
    _In_ DWORD HashMask,
    _Out_writes_(MaxLen) PWCHAR HashString,
    _In_ ULONG MaxLen)
{
    UCHAR md5Digest[16];
    UCHAR sha1Digest[20];
    UCHAR sha256Digest[32];
    UCHAR imphashDigest[16];
    CHAR md5Hex[33];
    CHAR sha1Hex[41];
    CHAR sha256Hex[65];
    CHAR imphashHex[33];
    NTSTATUS status;

    if (HashString == NULL || MaxLen == 0) {
        return FALSE;
    }

    wcscpy_s(HashString, MaxLen, L"-");
    if (FileData == NULL || FileSize == 0 || HashMask == 0) {
        return FALSE;
    }

    if ((HashMask & SYSMON_HASH_MD5) != 0) {
        if (!SysmonHashBufferWithDescriptor(&g_Md5HashDescriptor, FileData, FileSize, md5Digest, sizeof(md5Digest))) {
            return FALSE;
        }
        SysmonBytesToHex(md5Digest, 16, md5Hex, sizeof(md5Hex));
    }

    if ((HashMask & SYSMON_HASH_SHA1) != 0) {
        if (!SysmonHashBufferWithDescriptor(&g_Sha1HashDescriptor, FileData, FileSize, sha1Digest, sizeof(sha1Digest))) {
            return FALSE;
        }
        SysmonBytesToHex(sha1Digest, 20, sha1Hex, sizeof(sha1Hex));
    }

    if ((HashMask & SYSMON_HASH_SHA256) != 0) {
        if (!SysmonHashBufferWithDescriptor(&g_Sha256HashDescriptor, FileData, FileSize, sha256Digest, sizeof(sha256Digest))) {
            return FALSE;
        }
        SysmonBytesToHex(sha256Digest, 32, sha256Hex, sizeof(sha256Hex));
    }

    if ((HashMask & SYSMON_HASH_IMPHASH) != 0) {
        if (SysmonPeBufferLooksValid(FileData, FileSize)) {
            status = SysmonComputeImphash(FileData, FileSize, imphashDigest);
        } else {
            status = STATUS_INVALID_PARAMETER;
        }

        if (NT_SUCCESS(status)) {
            SysmonBytesToHex(imphashDigest, 16, imphashHex, sizeof(imphashHex));
        } else {
            RtlCopyMemory(imphashHex, "00000000000000000000000000000000", 33);
        }
    }

    if (!SysmonFormatSelectedHashes(
            HashMask,
            md5Hex,
            sha1Hex,
            sha256Hex,
            imphashHex,
            HashString,
            MaxLen)) {
        wcscpy_s(HashString, MaxLen, L"-");
        return FALSE;
    }

    return TRUE;
}

BOOL
SysmonComputeFileHashes(
    _In_z_ PCWSTR FilePath,
    _In_ DWORD HashMask,
    _Out_writes_(MaxLen) WCHAR *HashString,
    _In_ ULONG MaxLen)
{
    HANDLE fileHandle = INVALID_HANDLE_VALUE;
    HANDLE mappingHandle = NULL;
    LARGE_INTEGER fileSize;
    WIN32_FILE_ATTRIBUTE_DATA fileAttributes;
    FILETIME lastWriteTime;
    BYTE *buffer = NULL;
    const UCHAR *mappedFileData = NULL;
    DWORD totalBytesRead = 0;
    BOOL success = FALSE;
    SYSMON_HASH_INSTANCE md5Hash;
    SYSMON_HASH_INSTANCE sha1Hash;
    SYSMON_HASH_INSTANCE sha256Hash;
    UCHAR md5Digest[16], sha1Digest[20], sha256Digest[32], imphashDigest[16];
    CHAR md5Hex[33], sha1Hex[41], sha256Hex[65], imphashHex[33];
    const DWORD chunkBytes = 1024 * 1024;
    BOOL wantsImphash;

    if (HashString == NULL || MaxLen == 0) {
        return FALSE;
    }

    wcscpy_s(HashString, MaxLen, L"-");
    if (FilePath == NULL || FilePath[0] == L'\0' || HashMask == 0) {
        return FALSE;
    }

    ZeroMemory(&fileAttributes, sizeof(fileAttributes));
    ZeroMemory(&lastWriteTime, sizeof(lastWriteTime));
    ZeroMemory(&md5Hash, sizeof(md5Hash));
    ZeroMemory(&sha1Hash, sizeof(sha1Hash));
    ZeroMemory(&sha256Hash, sizeof(sha256Hash));

    if (GetFileAttributesExW(FilePath, GetFileExInfoStandard, &fileAttributes)) {
        lastWriteTime = fileAttributes.ftLastWriteTime;
        fileSize.HighPart = fileAttributes.nFileSizeHigh;
        fileSize.LowPart = fileAttributes.nFileSizeLow;
        if (fileSize.QuadPart > 0 &&
            SysmonLookupFileHashCache(
                FilePath,
                HashMask,
                (ULONGLONG)fileSize.QuadPart,
                &lastWriteTime,
                HashString,
                MaxLen)) {
            return TRUE;
        }
    }

    fileHandle = CreateFileW(
        FilePath,
        GENERIC_READ,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        NULL,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL | FILE_FLAG_SEQUENTIAL_SCAN,
        NULL);
    if (fileHandle == INVALID_HANDLE_VALUE) {
        return FALSE;
    }

    if (!GetFileSizeEx(fileHandle, &fileSize) ||
        fileSize.QuadPart <= 0 ||
        fileSize.QuadPart > MAXULONG) {
        goto cleanup;
    }

    wantsImphash = ((HashMask & SYSMON_HASH_IMPHASH) != 0);

    if ((HashMask & SYSMON_HASH_MD5) != 0 &&
        !SysmonCreateHashInstance(&md5Hash, &g_Md5HashDescriptor, sizeof(md5Digest))) {
        goto cleanup;
    }
    if ((HashMask & SYSMON_HASH_SHA1) != 0 &&
        !SysmonCreateHashInstance(&sha1Hash, &g_Sha1HashDescriptor, sizeof(sha1Digest))) {
        goto cleanup;
    }
    if ((HashMask & SYSMON_HASH_SHA256) != 0 &&
        !SysmonCreateHashInstance(&sha256Hash, &g_Sha256HashDescriptor, sizeof(sha256Digest))) {
        goto cleanup;
    }

    mappingHandle = CreateFileMappingW(
        fileHandle,
        NULL,
        PAGE_READONLY,
        0,
        0,
        NULL);
    if (mappingHandle != NULL) {
        mappedFileData = (const UCHAR *)MapViewOfFile(
            mappingHandle,
            FILE_MAP_READ,
            0,
            0,
            0);
    }

    if (mappedFileData != NULL) {
        if (((HashMask & SYSMON_HASH_MD5) != 0 &&
             !SysmonUpdateHashInstance(&md5Hash, mappedFileData, (ULONG)fileSize.QuadPart)) ||
            ((HashMask & SYSMON_HASH_SHA1) != 0 &&
             !SysmonUpdateHashInstance(&sha1Hash, mappedFileData, (ULONG)fileSize.QuadPart)) ||
            ((HashMask & SYSMON_HASH_SHA256) != 0 &&
             !SysmonUpdateHashInstance(&sha256Hash, mappedFileData, (ULONG)fileSize.QuadPart))) {
            goto cleanup;
        }
    } else {
        buffer = (BYTE *)SYSMON_ALLOC(
            (SIZE_T)min((ULONGLONG)chunkBytes, (ULONGLONG)fileSize.QuadPart));
        if (buffer == NULL) {
            goto cleanup;
        }

        while (totalBytesRead < (DWORD)fileSize.QuadPart) {
            DWORD bytesToRead;
            DWORD bytesRead = 0;

            bytesToRead = min(chunkBytes, (DWORD)fileSize.QuadPart - totalBytesRead);
            if (!ReadFile(fileHandle, buffer, bytesToRead, &bytesRead, NULL) ||
                bytesRead != bytesToRead) {
                goto cleanup;
            }

            if (((HashMask & SYSMON_HASH_MD5) != 0 &&
                 !SysmonUpdateHashInstance(&md5Hash, buffer, bytesRead)) ||
                ((HashMask & SYSMON_HASH_SHA1) != 0 &&
                 !SysmonUpdateHashInstance(&sha1Hash, buffer, bytesRead)) ||
                ((HashMask & SYSMON_HASH_SHA256) != 0 &&
                 !SysmonUpdateHashInstance(&sha256Hash, buffer, bytesRead))) {
                goto cleanup;
            }

            totalBytesRead += bytesRead;
        }
    }

    if ((HashMask & SYSMON_HASH_MD5) != 0) {
        if (!SysmonFinishHashInstance(&md5Hash, md5Digest, sizeof(md5Digest))) {
            goto cleanup;
        }
        SysmonBytesToHex(md5Digest, 16, md5Hex, sizeof(md5Hex));
    }
    if ((HashMask & SYSMON_HASH_SHA1) != 0) {
        if (!SysmonFinishHashInstance(&sha1Hash, sha1Digest, sizeof(sha1Digest))) {
            goto cleanup;
        }
        SysmonBytesToHex(sha1Digest, 20, sha1Hex, sizeof(sha1Hex));
    }
    if ((HashMask & SYSMON_HASH_SHA256) != 0) {
        if (!SysmonFinishHashInstance(&sha256Hash, sha256Digest, sizeof(sha256Digest))) {
            goto cleanup;
        }
        SysmonBytesToHex(sha256Digest, 32, sha256Hex, sizeof(sha256Hex));
    }

    if (wantsImphash) {
        NTSTATUS status;

        if (mappedFileData != NULL && SysmonPeBufferLooksValid(mappedFileData, (ULONG)fileSize.QuadPart)) {
            status = SysmonComputeImphash(mappedFileData, (ULONG)fileSize.QuadPart, imphashDigest);
        } else {
            if (SetFilePointer(fileHandle, 0, NULL, FILE_BEGIN) == INVALID_SET_FILE_POINTER &&
                GetLastError() != NO_ERROR) {
                goto cleanup;
            }
            status = SysmonComputeFileImphash(
                fileHandle,
                (ULONG)fileSize.QuadPart,
                imphashDigest);
        }

        if (NT_SUCCESS(status)) {
            SysmonBytesToHex(imphashDigest, 16, imphashHex, sizeof(imphashHex));
        } else {
            RtlCopyMemory(imphashHex, "00000000000000000000000000000000", 33);
        }
    }

    success = SysmonFormatSelectedHashes(
        HashMask,
        md5Hex,
        sha1Hex,
        sha256Hex,
        imphashHex,
        HashString,
        MaxLen);
    if (!success) {
        wcscpy_s(HashString, MaxLen, L"-");
    }
    if (success) {
        /* Re-read the file attributes after hashing. If the size or write time
           changed relative to the snapshot used while hashing, the file was
           modified concurrently: the digest may be torn, so report no hash for
           this event and do not seed the cache with it (P1 in the review). */
        WIN32_FILE_ATTRIBUTE_DATA currentAttributes;
        BOOL attributesChanged = TRUE;

        /* Recover a write-time baseline if the initial attribute read failed. */
        if (lastWriteTime.dwLowDateTime == 0 &&
            lastWriteTime.dwHighDateTime == 0) {
            FILETIME writeTime;

            ZeroMemory(&writeTime, sizeof(writeTime));
            if (GetFileTime(fileHandle, NULL, NULL, &writeTime)) {
                lastWriteTime = writeTime;
            }
        }

        ZeroMemory(&currentAttributes, sizeof(currentAttributes));
        if (GetFileAttributesExW(FilePath, GetFileExInfoStandard, &currentAttributes)) {
            ULONGLONG currentSize =
                ((ULONGLONG)currentAttributes.nFileSizeHigh << 32) |
                currentAttributes.nFileSizeLow;

            attributesChanged =
                currentSize != (ULONGLONG)fileSize.QuadPart ||
                currentAttributes.ftLastWriteTime.dwLowDateTime != lastWriteTime.dwLowDateTime ||
                currentAttributes.ftLastWriteTime.dwHighDateTime != lastWriteTime.dwHighDateTime;
        }

        if (attributesChanged) {
            success = FALSE;
            wcscpy_s(HashString, MaxLen, L"-");
        } else if (fileSize.QuadPart > 0 &&
                   !(lastWriteTime.dwLowDateTime == 0 &&
                     lastWriteTime.dwHighDateTime == 0)) {
            SysmonStoreFileHashCache(
                FilePath,
                HashMask,
                (ULONGLONG)fileSize.QuadPart,
                &lastWriteTime,
                HashString);
        }
    }

cleanup:
    if (mappedFileData != NULL) {
        UnmapViewOfFile(mappedFileData);
        mappedFileData = NULL;
    }
    if (mappingHandle != NULL) {
        CloseHandle(mappingHandle);
        mappingHandle = NULL;
    }
    SysmonDestroyHashInstance(&md5Hash);
    SysmonDestroyHashInstance(&sha1Hash);
    SysmonDestroyHashInstance(&sha256Hash);
    SYSMON_SAFE_CLOSE_HANDLE(fileHandle);
    SYSMON_FREE(buffer);
    return success;
}

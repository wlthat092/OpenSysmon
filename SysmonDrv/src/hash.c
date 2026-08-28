#include "hash.h"
#include "pe_utils.h"
#include <symcrypt.h>

SYMCRYPT_ENVIRONMENT_WINDOWS_KERNELMODE_LATEST;

static volatile LONG g_SymCryptInitialized = 0;
#define SYSMON_HASH_STREAM_CHUNK_SIZE (64UL * 1024UL)
#define SYSMON_MAX_STACK_SECTIONS 16
static volatile LONG g_ImphashCallCount = 0;
static volatile LONG g_ImphashReadRvaCallCount = 0;
static volatile LONG g_ImphashImportDescriptorCount = 0;
static volatile LONG g_ImphashImportEntryCount = 0;
static volatile LONG g_ImphashHashedImportCount = 0;
static volatile LONG g_ImphashOrdinalImportCount = 0;
static volatile LONG g_ImphashSectionCachePoolAllocCount = 0;
static volatile LONG g_ImphashSectionCountTotal = 0;

#define SYSMON_HASH_STAT_INC(_Counter) \
    ((void)InterlockedIncrement(&(_Counter)))
#define SYSMON_HASH_STAT_ADD(_Counter, _Value) \
    ((void)InterlockedExchangeAdd(&(_Counter), (LONG)(_Value)))

typedef struct _SysmonHashBufferState {
    BOOLEAN Md5Active;
    BOOLEAN Sha1Active;
    BOOLEAN Sha256Active;
    SYMCRYPT_MD5_STATE Md5State;
    SYMCRYPT_SHA1_STATE Sha1State;
    SYMCRYPT_SHA256_STATE Sha256State;
} SYSMON_HASH_BUFFER_STATE, *PSYSMON_HASH_BUFFER_STATE;

typedef struct _SYSMON_PE_SECTION_INFO {
    ULONG VirtualAddress;
    ULONG RawOffset;
    ULONG RawSize;
    ULONG Span;
} SYSMON_PE_SECTION_INFO, *PSYSMON_PE_SECTION_INFO;

typedef struct _SYSMON_PE_SECTION_CACHE {
    PSYSMON_PE_SECTION_INFO Sections;
    PSYSMON_PE_SECTION_INFO AllocatedSections;
    USHORT SectionCount;
    ULONG LastHitIndex;
} SYSMON_PE_SECTION_CACHE, *PSYSMON_PE_SECTION_CACHE;

typedef struct _SYSMON_IMPHASH_BUFFER_CONTEXT {
    const UCHAR *FileData;
    ULONG FileSize;
    const SYSMON_PE_SECTION_CACHE *SectionCache;
} SYSMON_IMPHASH_BUFFER_CONTEXT, *PSYSMON_IMPHASH_BUFFER_CONTEXT;

typedef BOOLEAN (*PFN_SYSMON_IMPHASH_READ_RVA)(
    _In_ const void *Context,
    _In_ ULONG Rva,
    _In_ ULONG RequiredLength,
    _Outptr_result_bytebuffer_(RequiredLength) const UCHAR **Data,
    _Out_opt_ PULONG AvailableLength);

VOID
SysmonQueryHashDebugSnapshot(
    _Out_ PSYSMON_HASH_DEBUG_SNAPSHOT Snapshot)
{
    if (Snapshot == NULL) {
        return;
    }

    RtlZeroMemory(Snapshot, sizeof(*Snapshot));
    Snapshot->ImphashCallCount = (ULONG)InterlockedCompareExchange(&g_ImphashCallCount, 0, 0);
    Snapshot->ImphashReadRvaCallCount = (ULONG)InterlockedCompareExchange(&g_ImphashReadRvaCallCount, 0, 0);
    Snapshot->ImphashImportDescriptorCount = (ULONG)InterlockedCompareExchange(&g_ImphashImportDescriptorCount, 0, 0);
    Snapshot->ImphashImportEntryCount = (ULONG)InterlockedCompareExchange(&g_ImphashImportEntryCount, 0, 0);
    Snapshot->ImphashHashedImportCount = (ULONG)InterlockedCompareExchange(&g_ImphashHashedImportCount, 0, 0);
    Snapshot->ImphashOrdinalImportCount = (ULONG)InterlockedCompareExchange(&g_ImphashOrdinalImportCount, 0, 0);
    Snapshot->ImphashSectionCachePoolAllocCount = (ULONG)InterlockedCompareExchange(&g_ImphashSectionCachePoolAllocCount, 0, 0);
    Snapshot->ImphashSectionCountTotal = (ULONG)InterlockedCompareExchange(&g_ImphashSectionCountTotal, 0, 0);
}

NTSTATUS
SysmonInitializeHashing(VOID)
{
    if (InterlockedCompareExchange(&g_SymCryptInitialized, 1, 0) == 0) {
        SymCryptInit();
        MemoryBarrier();
    }

    return STATUS_SUCCESS;
}

VOID
SysmonCleanupHashing(VOID)
{
    InterlockedExchange(&g_SymCryptInitialized, 0);
}

NTSTATUS
SysmonComputeMd5Buffer(
    _In_reads_bytes_(DataLength) const UCHAR *Data,
    _In_ ULONG DataLength,
    _Out_writes_(16) UCHAR Digest[16])
{
    if (Data == NULL || Digest == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    SymCryptMd5(Data, DataLength, Digest);
    return STATUS_SUCCESS;
}

static NTSTATUS
SysmonInitializeHashBufferState(
    _Out_ PSYSMON_HASH_BUFFER_STATE State,
    _In_ ULONG HashMask)
{
    if (State == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    RtlZeroMemory(State, sizeof(*State));
    if ((HashMask & SysmonHashMD5) != 0) {
        SymCryptMd5Init(&State->Md5State);
        State->Md5Active = TRUE;
    }
    if ((HashMask & SysmonHashSHA1) != 0) {
        SymCryptSha1Init(&State->Sha1State);
        State->Sha1Active = TRUE;
    }
    if ((HashMask & SysmonHashSHA256) != 0) {
        SymCryptSha256Init(&State->Sha256State);
        State->Sha256Active = TRUE;
    }

    return STATUS_SUCCESS;
}

static VOID
SysmonAppendHashBufferState(
    _Inout_ PSYSMON_HASH_BUFFER_STATE State,
    _In_reads_bytes_(DataLength) const UCHAR *Data,
    _In_ ULONG DataLength,
    _In_ ULONG HashMask)
{
    if (State == NULL || Data == NULL || DataLength == 0) {
        return;
    }

    if ((HashMask & SysmonHashMD5) != 0 && State->Md5Active) {
        SymCryptMd5Append(&State->Md5State, Data, DataLength);
    }
    if ((HashMask & SysmonHashSHA1) != 0 && State->Sha1Active) {
        SymCryptSha1Append(&State->Sha1State, Data, DataLength);
    }
    if ((HashMask & SysmonHashSHA256) != 0 && State->Sha256Active) {
        SymCryptSha256Append(&State->Sha256State, Data, DataLength);
    }
}

static VOID
SysmonFinalizeHashBufferState(
    _Inout_ PSYSMON_HASH_BUFFER_STATE State,
    _In_ ULONG HashMask,
    _Out_writes_opt_(16) UCHAR Md5Digest[16],
    _Out_writes_opt_(20) UCHAR Sha1Digest[20],
    _Out_writes_opt_(32) UCHAR Sha256Digest[32])
{
    if (State == NULL) {
        return;
    }

    if ((HashMask & SysmonHashMD5) != 0 && State->Md5Active && Md5Digest != NULL) {
        SymCryptMd5Result(&State->Md5State, Md5Digest);
    }
    if ((HashMask & SysmonHashSHA1) != 0 && State->Sha1Active && Sha1Digest != NULL) {
        SymCryptSha1Result(&State->Sha1State, Sha1Digest);
    }
    if ((HashMask & SysmonHashSHA256) != 0 && State->Sha256Active && Sha256Digest != NULL) {
        SymCryptSha256Result(&State->Sha256State, Sha256Digest);
    }
}

static NTSTATUS
SysmonComputeSelectedDigests(
    _In_reads_bytes_(FileSize) const UCHAR *FileData,
    _In_ ULONG FileSize,
    _In_ ULONG HashMask,
    _Out_writes_opt_(16) UCHAR Md5Digest[16],
    _Out_writes_opt_(20) UCHAR Sha1Digest[20],
    _Out_writes_opt_(32) UCHAR Sha256Digest[32])
{
    SYSMON_HASH_BUFFER_STATE state;
    ULONG offset;

    if (FileData == NULL || FileSize == 0) {
        return STATUS_INVALID_PARAMETER;
    }

    if ((HashMask & (SysmonHashMD5 | SysmonHashSHA1 | SysmonHashSHA256)) == 0) {
        return STATUS_SUCCESS;
    }

    if (!NT_SUCCESS(SysmonInitializeHashBufferState(&state, HashMask))) {
        return STATUS_INVALID_PARAMETER;
    }

    for (offset = 0; offset < FileSize; ) {
        ULONG chunkSize;

        chunkSize = FileSize - offset;
        if (chunkSize > SYSMON_HASH_STREAM_CHUNK_SIZE) {
            chunkSize = SYSMON_HASH_STREAM_CHUNK_SIZE;
        }

        SysmonAppendHashBufferState(&state, FileData + offset, chunkSize, HashMask);
        offset += chunkSize;
    }

    SysmonFinalizeHashBufferState(&state, HashMask, Md5Digest, Sha1Digest, Sha256Digest);
    return STATUS_SUCCESS;
}

static VOID
SysmonBytesToHex(
    _In_reads_(ByteLen) const UCHAR *Bytes,
    _In_ ULONG ByteLen,
    _Out_writes_(ByteLen * 2 + 1) CHAR *Hex,
    _In_ ULONG HexMaxLen)
{
    static const char hexchars[] = "0123456789abcdef";
    ULONG i;

    if (HexMaxLen < ByteLen * 2 + 1) {
        return;
    }

    for (i = 0; i < ByteLen; i++) {
        Hex[i * 2] = hexchars[(Bytes[i] >> 4) & 0x0F];
        Hex[i * 2 + 1] = hexchars[Bytes[i] & 0x0F];
    }
    Hex[ByteLen * 2] = '\0';
}

static BOOLEAN
SysmonAppendSelectedHash(
    _Inout_updates_(MaxLen) PWCHAR HashString,
    _In_ ULONG MaxLen,
    _In_z_ PCWSTR Name,
    _In_z_ PCSTR Value,
    _Inout_ PBOOLEAN First)
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
            MaxLen - (ULONG)offset,
            _TRUNCATE,
            L"%ls=%S",
            Name,
            Value) < 0) {
        return FALSE;
    }

    *First = FALSE;
    return TRUE;
}

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

static ULONG
SysmonStripExtension(_Inout_ CHAR *Name)
{
    CHAR *ext = NULL;
    ULONG len = 0;
    ULONG i;

    if (Name == NULL) {
        return 0;
    }

    for (i = 0; Name[i] != '\0'; i++) {
        if (Name[i] == '.') {
            ext = &Name[i];
        }
        len++;
    }

    if (ext != NULL) {
        if (_stricmp(ext, ".dll") == 0 ||
            _stricmp(ext, ".sys") == 0 ||
            _stricmp(ext, ".ocx") == 0) {
            *ext = '\0';
            return (ULONG)(ext - Name);
        }
    }

    return len;
}

#include "hash_ordinal_lookup.inl"

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

static BOOLEAN
SysmonAppendImportHashFragment(
    _Inout_ SYMCRYPT_MD5_STATE *Md5State,
    _In_reads_(DllNameLen) const CHAR *DllName,
    _In_ ULONG DllNameLen,
    _In_reads_(FuncNameLen) const CHAR *FuncName,
    _In_ ULONG FuncNameLen,
    _Inout_ PBOOLEAN FirstFunc)
{
    CHAR fragment[512];
    ULONG length = 0;
    ULONG required;

    if (Md5State == NULL || DllName == NULL || FuncName == NULL || FirstFunc == NULL) {
        return FALSE;
    }

    if (!*FirstFunc) {
        fragment[length++] = ',';
    }

    required = DllNameLen + 1 + FuncNameLen;
    if ((RTL_NUMBER_OF(fragment) - length) < required) {
        return FALSE;
    }

    RtlCopyMemory(fragment + length, DllName, DllNameLen);
    length += DllNameLen;
    fragment[length++] = '.';
    RtlCopyMemory(fragment + length, FuncName, FuncNameLen);
    length += FuncNameLen;

    SymCryptMd5Append(Md5State, (PCBYTE)fragment, length);
    *FirstFunc = FALSE;
    return TRUE;
}

static ULONG
SysmonCopyLookupImportName(
    _Out_writes_(BufferChars) CHAR *Buffer,
    _In_ ULONG BufferChars,
    _In_z_ const CHAR *Name)
{
    ULONG length = 0;

    if (Buffer == NULL || BufferChars == 0 || Name == NULL) {
        return 0;
    }

    while (length + 1 < BufferChars && Name[length] != '\0') {
        Buffer[length] = Name[length];
        length++;
    }

    Buffer[length] = '\0';
    return length;
}

static BOOLEAN
SysmonInitializeSectionCacheFromLayout(
    _In_ const UCHAR *FileData,
    _In_ ULONG FileSize,
    _In_ USHORT NumSections,
    _In_ ULONG SectionTableOffset,
    _Out_writes_(StackSectionCapacity) PSYSMON_PE_SECTION_INFO StackSections,
    _In_ ULONG StackSectionCapacity,
    _Out_ PSYSMON_PE_SECTION_CACHE Cache)
{
    ULONG index;

    if (Cache == NULL) {
        return FALSE;
    }

    RtlZeroMemory(Cache, sizeof(*Cache));
    if (NumSections == 0 ||
        !SysmonPeMultiplyUlong((ULONG)NumSections, 40, &index) ||
        !SysmonPeHasRange(FileSize, SectionTableOffset, index)) {
        return FALSE;
    }

    if (NumSections <= StackSectionCapacity) {
        if (StackSections == NULL) {
            return FALSE;
        }
        Cache->Sections = StackSections;
    } else {
        SYSMON_HASH_STAT_INC(g_ImphashSectionCachePoolAllocCount);
        Cache->AllocatedSections = (PSYSMON_PE_SECTION_INFO)SysmonAllocatePool(
            (SIZE_T)NumSections * sizeof(*Cache->AllocatedSections));
        if (Cache->AllocatedSections == NULL) {
            return FALSE;
        }
        Cache->Sections = Cache->AllocatedSections;
    }

    Cache->SectionCount = NumSections;
    SYSMON_HASH_STAT_ADD(g_ImphashSectionCountTotal, NumSections);
    Cache->LastHitIndex = MAXULONG;
    for (index = 0; index < NumSections; index++) {
        ULONG sectionOffset;
        ULONG sectionRawOffset;
        ULONG sectionRawSize;
        ULONG sectionRva;
        PSYSMON_PE_SECTION_INFO section;

        if (index > (MAXULONG / 40) ||
            !SysmonPeAddUlong(SectionTableOffset, index * 40, &sectionOffset) ||
            !SysmonPeHasRange(FileSize, sectionOffset, 40)) {
            SysmonFreePool(Cache->AllocatedSections);
            RtlZeroMemory(Cache, sizeof(*Cache));
            return FALSE;
        }

        section = &Cache->Sections[index];
        sectionRva = SysmonReadPackedUlong(FileData + sectionOffset + 0x0C);
        sectionRawSize = SysmonReadPackedUlong(FileData + sectionOffset + 0x10);
        sectionRawOffset = SysmonReadPackedUlong(FileData + sectionOffset + 0x14);
        section->VirtualAddress = sectionRva;
        section->RawOffset = sectionRawOffset;
        section->RawSize = sectionRawSize;
        /* Keep the section hit range raw-backed; virtual-only tail RVAs use the raw-offset fallback. */
        section->Span = sectionRawSize;
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

    SysmonFreePool(Cache->AllocatedSections);
    RtlZeroMemory(Cache, sizeof(*Cache));
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
SysmonPeMapRvaToPointer(
    _In_ const SYSMON_PE_SECTION_CACHE *Cache,
    _In_reads_(FileSize) const UCHAR *FileData,
    _In_ ULONG FileSize,
    _In_ ULONG Rva,
    _In_ ULONG RequiredLength,
    _Outptr_result_bytebuffer_(RequiredLength) const UCHAR **Data,
    _Out_opt_ PULONG AvailableLength)
{
    PSYSMON_PE_SECTION_INFO section;
    ULONG available;
    ULONG delta;
    ULONG offset;

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

    SYSMON_HASH_STAT_INC(g_ImphashReadRvaCallCount);
    return SysmonPeMapRvaToPointer(
        bufferContext->SectionCache,
        bufferContext->FileData,
        bufferContext->FileSize,
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
    SYMCRYPT_MD5_STATE md5State;
    ULONG descriptorIndex;
    ULONG importEnd;
    BOOLEAN firstFunc;

    if (ReadRva == NULL || Digest == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    SymCryptMd5Init(&md5State);
    if (ImportDirRva == 0 || ImportDirSize == 0) {
        SymCryptMd5Result(&md5State, Digest);
        return STATUS_SUCCESS;
    }

    if (!SysmonPeAddUlong(ImportDirRva, ImportDirSize, &importEnd) ||
        ImportDirSize < 20) {
        return STATUS_INVALID_PARAMETER;
    }

    firstFunc = TRUE;
    for (descriptorIndex = 0; descriptorIndex < (ImportDirSize / 20); descriptorIndex++) {
        const UCHAR *descriptor;
        ULONG descriptorAvailable = 0;
        ULONG descriptorRva;
        ULONG entryIndex;
        ULONG iltRva;
        ULONG nameRva;
        CHAR dllName[256];
        ULONG dllNameLen;

        if (descriptorIndex > (MAXULONG / 20) ||
            !SysmonPeAddUlong(ImportDirRva, descriptorIndex * 20, &descriptorRva) ||
            !SysmonPeHasRange(importEnd, descriptorRva, 20) ||
            !ReadRva(ReadContext, descriptorRva, 20, &descriptor, &descriptorAvailable) ||
            descriptorAvailable < 20) {
            break;
        }

        iltRva = SysmonReadPackedUlong(descriptor + 0x00);
        nameRva = SysmonReadPackedUlong(descriptor + 0x0C);
        if (iltRva == 0) {
            break;
        }
        SYSMON_HASH_STAT_INC(g_ImphashImportDescriptorCount);
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
        for (entryIndex = 0; ; entryIndex++) {
            const UCHAR *entryData;
            ULONG entryAvailable = 0;
            ULONG entryRva;
            ULONG entrySize = Is64 ? 8 : 4;
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
                ? SysmonReadPackedUlongLong(entryData)
                : (ULONGLONG)SysmonReadPackedUlong(entryData);
            if (entry == 0) {
                break;
            }
            SYSMON_HASH_STAT_INC(g_ImphashImportEntryCount);

            if ((Is64 && (entry & 0x8000000000000000ULL) != 0) ||
                (!Is64 && (entry & 0x80000000U) != 0)) {
                const CHAR *ordinalName;

                SYSMON_HASH_STAT_INC(g_ImphashOrdinalImportCount);
                ordinalName = SysmonLookupImportOrdinalName(
                    dllName,
                    (USHORT)(entry & 0xFFFF));
                if (ordinalName != NULL) {
                    funcNameLen = SysmonCopyLookupImportName(
                        funcName,
                        RTL_NUMBER_OF(funcName),
                        ordinalName);
                    SysmonNormalizeName(funcName, funcNameLen);
                } else {
                    funcNameLen = SysmonFormatImportOrdinalName(
                        funcName,
                        RTL_NUMBER_OF(funcName),
                        (USHORT)(entry & 0xFFFF));
                }
            } else {
                const UCHAR *funcNameData;
                ULONG funcNameAvailable = 0;
                ULONG hintRva;

                if (Is64) {
                    ULONGLONG hintRva64 = entry & 0x7FFFFFFFFFFFFFFFULL;
                    if (hintRva64 > MAXULONG) {
                        continue;
                    }
                    hintRva = (ULONG)hintRva64;
                } else {
                    hintRva = (ULONG)entry;
                }

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

            if (!SysmonAppendImportHashFragment(
                    &md5State,
                    dllName,
                    dllNameLen,
                    funcName,
                    funcNameLen,
                    &firstFunc)) {
                return STATUS_INVALID_PARAMETER;
            }
            SYSMON_HASH_STAT_INC(g_ImphashHashedImportCount);
        }
    }

    SymCryptMd5Result(&md5State, Digest);
    return STATUS_SUCCESS;
}

static NTSTATUS
SysmonParseImportsAndHash(
    _In_ const UCHAR *FileData,
    _In_ ULONG FileSize,
    _Out_ UCHAR Digest[16])
{
    SYSMON_IMPHASH_BUFFER_CONTEXT bufferContext;
    SYSMON_PE_SECTION_CACHE sectionCache;
    SYSMON_PE_SECTION_INFO stackSections[SYSMON_MAX_STACK_SECTIONS];
    ULONG peOffset;
    ULONG sectionTableOffset;
    ULONG dirOffset;
    ULONG importDirRva;
    ULONG importDirSize;
    USHORT numSections;
    USHORT optHdrSize;
    BOOLEAN is64;
    NTSTATUS status;

    if (Digest == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

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

    if (is64) {
        if (optHdrSize < 0x80) {
            return STATUS_INVALID_PARAMETER;
        }
        if (!SysmonPeAddUlong(peOffset, 0x90, &dirOffset) ||
            !SysmonPeHasRange(FileSize, dirOffset, 8)) {
            return STATUS_INVALID_PARAMETER;
        }
    } else {
        if (optHdrSize < 0x70) {
            return STATUS_INVALID_PARAMETER;
        }
        if (!SysmonPeAddUlong(peOffset, 0x80, &dirOffset) ||
            !SysmonPeHasRange(FileSize, dirOffset, 8)) {
            return STATUS_INVALID_PARAMETER;
        }
    }

    if (!SysmonPeReadUlong(FileData, FileSize, dirOffset, &importDirRva) ||
        !SysmonPeReadUlong(FileData, FileSize, dirOffset + 4, &importDirSize)) {
        return STATUS_INVALID_PARAMETER;
    }

    if (importDirRva == 0 || importDirSize == 0) {
        return SysmonHashImportsFromReader(
            is64,
            importDirRva,
            importDirSize,
            SysmonReadImportRvaFromBuffer,
            NULL,
            Digest);
    }

    if (!SysmonInitializeSectionCacheFromLayout(
            FileData,
            FileSize,
            numSections,
            sectionTableOffset,
            stackSections,
            RTL_NUMBER_OF(stackSections),
            &sectionCache)) {
        return STATUS_INVALID_PARAMETER;
    }

    bufferContext.FileData = FileData;
    bufferContext.FileSize = FileSize;
    bufferContext.SectionCache = &sectionCache;

    status = SysmonHashImportsFromReader(
        is64,
        importDirRva,
        importDirSize,
        SysmonReadImportRvaFromBuffer,
        &bufferContext,
        Digest);
    SysmonFreeSectionCache(&sectionCache);
    return status;
}

NTSTATUS
SysmonComputeImphash(
    _In_reads_(FileSize) const UCHAR *FileData,
    _In_ ULONG FileSize,
    _Out_writes_(16) UCHAR Digest[16])
{
    SYSMON_HASH_STAT_INC(g_ImphashCallCount);
    return SysmonParseImportsAndHash(FileData, FileSize, Digest);
}

NTSTATUS
SysmonComputeHashDigestsMasked(
    _In_reads_(FileSize) const UCHAR *FileData,
    _In_ ULONG FileSize,
    _In_ ULONG HashMask,
    _Out_ PSYSMON_HASH_DIGEST_SET Digests)
{
    if (FileData == NULL || FileSize == 0 || Digests == NULL || HashMask == 0) {
        return STATUS_INVALID_PARAMETER;
    }

    RtlZeroMemory(Digests, sizeof(*Digests));
    Digests->RequestedMask = HashMask;

    if ((HashMask & (SysmonHashMD5 | SysmonHashSHA1 | SysmonHashSHA256)) != 0) {
        NTSTATUS status;

        status = SysmonComputeSelectedDigests(
            FileData,
            FileSize,
            HashMask,
            Digests->Md5,
            Digests->Sha1,
            Digests->Sha256);
        if (!NT_SUCCESS(status)) {
            return status;
        }

        Digests->PresentMask |= (HashMask & (SysmonHashMD5 | SysmonHashSHA1 | SysmonHashSHA256));
    }

    if ((HashMask & SysmonHashIMPHASH) != 0) {
        if (NT_SUCCESS(SysmonComputeImphash(FileData, FileSize, Digests->Imphash))) {
            Digests->PresentMask |= SysmonHashIMPHASH;
        } else {
            /*
             * Preserve the requested output surface even when PE-specific
             * IMPHASH parsing fails; callers format a zero digest in this case.
             */
            RtlZeroMemory(Digests->Imphash, sizeof(Digests->Imphash));
            Digests->PresentMask |= SysmonHashIMPHASH;
        }
    }

    return STATUS_SUCCESS;
}

NTSTATUS
SysmonFormatHashDigestsMasked(
    _In_ const SYSMON_HASH_DIGEST_SET *Digests,
    _Out_writes_(MaxLen) WCHAR *HashString,
    _In_ ULONG MaxLen)
{
    CHAR md5Hex[33];
    CHAR sha1Hex[41];
    CHAR sha256Hex[65];
    CHAR imphashHex[33];
    BOOLEAN first = TRUE;
    BOOLEAN any = FALSE;

    if (Digests == NULL || HashString == NULL || MaxLen == 0) {
        return STATUS_INVALID_PARAMETER;
    }

    HashString[0] = L'\0';

    if ((Digests->PresentMask & SysmonHashSHA1) != 0) {
        SysmonBytesToHex(Digests->Sha1, 20, sha1Hex, sizeof(sha1Hex));
        any = SysmonAppendSelectedHash(HashString, MaxLen, L"SHA1", sha1Hex, &first) || any;
    }
    if ((Digests->PresentMask & SysmonHashMD5) != 0) {
        SysmonBytesToHex(Digests->Md5, 16, md5Hex, sizeof(md5Hex));
        any = SysmonAppendSelectedHash(HashString, MaxLen, L"MD5", md5Hex, &first) || any;
    }
    if ((Digests->PresentMask & SysmonHashSHA256) != 0) {
        SysmonBytesToHex(Digests->Sha256, 32, sha256Hex, sizeof(sha256Hex));
        any = SysmonAppendSelectedHash(HashString, MaxLen, L"SHA256", sha256Hex, &first) || any;
    }
    if ((Digests->PresentMask & SysmonHashIMPHASH) != 0) {
        SysmonBytesToHex(Digests->Imphash, 16, imphashHex, sizeof(imphashHex));
        any = SysmonAppendSelectedHash(HashString, MaxLen, L"IMPHASH", imphashHex, &first) || any;
    }

    if (!any || HashString[0] == L'\0') {
        wcscpy_s(HashString, MaxLen, L"-");
        return STATUS_UNSUCCESSFUL;
    }

    return STATUS_SUCCESS;
}

NTSTATUS
SysmonComputeHashesMasked(
    _In_reads_(FileSize) const UCHAR *FileData,
    _In_ ULONG FileSize,
    _In_ ULONG HashMask,
    _Out_writes_(MaxLen) WCHAR *HashString,
    _In_ ULONG MaxLen)
{
    SYSMON_HASH_DIGEST_SET digests;
    NTSTATUS status;

    if (HashString == NULL || MaxLen == 0) {
        return STATUS_INVALID_PARAMETER;
    }

    wcscpy_s(HashString, MaxLen, L"-");
    status = SysmonComputeHashDigestsMasked(FileData, FileSize, HashMask, &digests);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    return SysmonFormatHashDigestsMasked(&digests, HashString, MaxLen);
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
        SysmonHashSHA1 | SysmonHashMD5 | SysmonHashSHA256 | SysmonHashIMPHASH,
        HashString,
        MaxLen);
}

#pragma once
#include "common.h"
#include "event.h"

NTSTATUS
SysmonInitializeHashing(VOID);

VOID
SysmonCleanupHashing(VOID);

NTSTATUS
SysmonComputeMd5Buffer(
    _In_reads_bytes_(DataLength) const UCHAR *Data,
    _In_ ULONG DataLength,
    _Out_writes_(16) UCHAR Digest[16]);

typedef struct _SYSMON_HASH_DIGEST_SET {
    ULONG RequestedMask;
    /* Output-presence mask; requested IMPHASH may remain present with a zero digest on parse failure. */
    ULONG PresentMask;
    UCHAR Md5[16];
    UCHAR Sha1[20];
    UCHAR Sha256[32];
    UCHAR Imphash[16];
} SYSMON_HASH_DIGEST_SET, *PSYSMON_HASH_DIGEST_SET;

typedef struct _SYSMON_HASH_DEBUG_SNAPSHOT {
    ULONG ImphashCallCount;
    ULONG ImphashReadRvaCallCount;
    ULONG ImphashImportDescriptorCount;
    ULONG ImphashImportEntryCount;
    ULONG ImphashHashedImportCount;
    ULONG ImphashOrdinalImportCount;
    ULONG ImphashSectionCachePoolAllocCount;
    ULONG ImphashSectionCountTotal;
} SYSMON_HASH_DEBUG_SNAPSHOT, *PSYSMON_HASH_DEBUG_SNAPSHOT;

VOID
SysmonQueryHashDebugSnapshot(
    _Out_ PSYSMON_HASH_DEBUG_SNAPSHOT Snapshot);

NTSTATUS
SysmonComputeHashDigestsMasked(
    _In_reads_(FileSize) const UCHAR *FileData,
    _In_ ULONG FileSize,
    _In_ ULONG HashMask,
    _Out_ PSYSMON_HASH_DIGEST_SET Digests
);

NTSTATUS
SysmonFormatHashDigestsMasked(
    _In_ const SYSMON_HASH_DIGEST_SET *Digests,
    _Out_writes_(MaxLen) WCHAR *HashString,
    _In_ ULONG MaxLen
);

/* High-level: compute all hashes for a file buffer and format as "SHA1=xx,MD5=xx,SHA256=xx,IMPHASH=xx" */
NTSTATUS
SysmonComputeHashes(
    _In_reads_(FileSize) const UCHAR *FileData,
    _In_ ULONG FileSize,
    _Out_writes_(MaxLen) WCHAR *HashString,
    _In_ ULONG MaxLen
);

NTSTATUS
SysmonComputeHashesMasked(
    _In_reads_(FileSize) const UCHAR *FileData,
    _In_ ULONG FileSize,
    _In_ ULONG HashMask,
    _Out_writes_(MaxLen) WCHAR *HashString,
    _In_ ULONG MaxLen
);

/* IMPHASH: parse PE imports, normalize, MD5 */
NTSTATUS
SysmonComputeImphash(
    _In_reads_(FileSize) const UCHAR *FileData,
    _In_ ULONG FileSize,
    _Out_writes_(16) UCHAR Digest[16]
);

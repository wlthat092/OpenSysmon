#pragma once
#include "common.h"
#include "config.h"

#ifndef NTSTATUS
typedef LONG NTSTATUS;
#endif

#ifndef NT_SUCCESS
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#endif

#ifndef STATUS_SUCCESS
#define STATUS_SUCCESS ((NTSTATUS)0x00000000L)
#endif

#ifndef STATUS_INVALID_PARAMETER
#define STATUS_INVALID_PARAMETER ((NTSTATUS)0xC000000DL)
#endif

#ifndef STATUS_BUFFER_OVERFLOW
#define STATUS_BUFFER_OVERFLOW ((NTSTATUS)0x80000005L)
#endif

/* High-level: compute all hashes for a file buffer and format as "SHA1=xx,MD5=xx,SHA256=xx,IMPHASH=xx" */
NTSTATUS
SysmonComputeHashes(
    _In_reads_(FileSize) const UCHAR *FileData,
    _In_ ULONG FileSize,
    _Out_writes_(MaxLen) WCHAR *HashString,
    _In_ ULONG MaxLen
);

BOOL
SysmonComputeFileHashes(
    _In_z_ PCWSTR FilePath,
    _In_ DWORD HashMask,
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

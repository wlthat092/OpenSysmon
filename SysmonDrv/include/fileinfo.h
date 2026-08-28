#pragma once
#include "common.h"

/* File information structure */
typedef struct _SYSMON_FILE_INFO {
    WCHAR FilePath[SYSMON_MAX_PATH];
    WCHAR FileName[SYSMON_MAX_PATH];
    WCHAR FileExtension[64];
    WCHAR FileVersion[256];
    WCHAR ProductName[256];
    WCHAR CompanyName[256];
    WCHAR OriginalFileName[256];
    WCHAR FileDescription[256];
    WCHAR Hashes[SYSMON_MAX_HASH_STRING];
    LARGE_INTEGER FileSize;
    LARGE_INTEGER CreationTime;
    LARGE_INTEGER LastWriteTime;
    LARGE_INTEGER LastAccessTime;
    ULONG FileAttributes;
    BOOLEAN IsPeFile;
} SYSMON_FILE_INFO, *PSYSMON_FILE_INFO;

typedef struct _SYSMON_FILEINFO_DEBUG_SNAPSHOT {
    ULONG LastHashMaskUsed;
    ULONG LastHashStatus;
    ULONG LastAvailableMask;
    ULONG LastFileContentMode;
    ULONG FileInfoCollectCallCount;
    ULONG FileInfoCacheLookupCount;
    ULONG FileInfoCacheHitCount;
    ULONG FileInfoCacheStoreCount;
    ULONG FileInfoMapAttemptCount;
    ULONG FileInfoMapSuccessCount;
    ULONG FileInfoReadFallbackCount;
    ULONG FileInfoReadRetryCount;
    ULONG FileInfoHashComputeCount;
    ULONG FileInfoVersionParseCount;
    ULONG FileInfoMapUsecTotal;
    ULONG FileInfoReadUsecTotal;
    ULONG FileInfoHashUsecTotal;
    ULONG FileInfoVersionUsecTotal;
} SYSMON_FILEINFO_DEBUG_SNAPSHOT, *PSYSMON_FILEINFO_DEBUG_SNAPSHOT;

#define SYSMON_FILEINFO_REQUEST_HASHES       0x00000001UL
#define SYSMON_FILEINFO_REQUEST_VERSION_INFO 0x00000002UL

/* Query file path from FltObjects */
NTSTATUS
SysmonQueryFilePath(
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Out_ PUNICODE_STRING FileName
);

/* Query file basic info (size, timestamps, attributes) */
NTSTATUS
SysmonQueryFileBasicInfo(
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Out_ PSYSMON_FILE_INFO FileInfo
);

/* Read file content for hashing (uses FltReadFile) */
NTSTATUS
SysmonReadFileContent(
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ ULONG MaxBytes,
    _Out_ PUCHAR *Buffer,
    _Out_ PULONG BytesRead
);

/* Parse PE version info (VS_VERSION_INFO resource) */
NTSTATUS
SysmonQueryFileVersionInfo(
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Inout_ PSYSMON_FILE_INFO FileInfo
);

/* Fill in complete file info (path, basic info, version, hashes) */
NTSTATUS
SysmonCollectFileInfo(
    _In_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Out_ PSYSMON_FILE_INFO FileInfo
);

NTSTATUS
SysmonCollectFileInfoByPath(
    _In_z_ PCWSTR FilePath,
    _Out_ PSYSMON_FILE_INFO FileInfo
);

NTSTATUS
SysmonCollectFileInfoByPathEx(
    _In_z_ PCWSTR FilePath,
    _In_ ULONG RequestMask,
    _Out_ PSYSMON_FILE_INFO FileInfo
);

VOID
SysmonQueryFileInfoDebugSnapshot(
    _Out_ PSYSMON_FILEINFO_DEBUG_SNAPSHOT Snapshot);

#pragma once
#include "common.h"

/* Process information structure */
typedef struct _SYSMON_PROCESS_INFO {
    ULONG       ProcessId;
    ULONG       ParentProcessId;
    ULONG       SessionId;
    WCHAR       ImagePath[SYSMON_MAX_PATH];
    WCHAR       CommandLine[SYSMON_MAX_CMDLINE];
    WCHAR       CurrentDirectory[SYSMON_MAX_PATH];
    /* Kernel producers currently carry SID strings here; account-name resolution is deferred. */
    WCHAR       UserSid[SYSMON_MAX_SID_STRING];
    WCHAR       IntegrityLevel[64];
    WCHAR       LogonGuid[SYSMON_MAX_GUID_STRING];
    ULONGLONG   LogonId;
    WCHAR       ProcessGuid[SYSMON_MAX_GUID_STRING];
    LONGLONG    CreateTime;
    BOOLEAN     IsElevated;
    TOKEN_ELEVATION_TYPE ElevationType;
} SYSMON_PROCESS_INFO, *PSYSMON_PROCESS_INFO;

/* Open process and collect full process info */
NTSTATUS
SysmonCollectProcessInfo(
    _In_ HANDLE ProcessId,
    _Out_ PSYSMON_PROCESS_INFO Info
);

NTSTATUS
SysmonCollectProcessInfoForCreateNotify(
    _In_ HANDLE ProcessId,
    _Out_ PSYSMON_PROCESS_INFO Info
);

NTSTATUS
SysmonCollectProcessIdentity(
    _In_ HANDLE ProcessId,
    _Out_ PSYSMON_PROCESS_INFO Info
);

NTSTATUS
SysmonCollectProcessTokenIdentity(
    _In_ HANDLE ProcessId,
    _Out_ PSYSMON_PROCESS_INFO Info
);

NTSTATUS
SysmonQueryPrimaryTokenUserSidForProcessObject(
    _In_ PEPROCESS Process,
    _Out_writes_(UserSidChars) PWCHAR UserSid,
    _In_ ULONG UserSidChars
);

NTSTATUS
SysmonResolveUserAddress(
    _In_ HANDLE ProcessId,
    _In_ ULONGLONG Address,
    _Out_writes_(ModulePathChars) PWCHAR ModulePath,
    _In_ ULONG ModulePathChars,
    _Out_opt_ PULONGLONG ModuleBase,
    _Out_opt_ PULONG ModuleSize
);

NTSTATUS
SysmonResolveUserExportName(
    _In_ HANDLE ProcessId,
    _In_ ULONGLONG Address,
    _Out_writes_(FunctionNameChars) PWCHAR FunctionName,
    _In_ ULONG FunctionNameChars
);

NTSTATUS
SysmonResolveUserStartContextForProcessObject(
    _In_ PEPROCESS ProcessObject,
    _In_ ULONGLONG Address,
    _Out_writes_(ModulePathChars) PWCHAR ModulePath,
    _In_ ULONG ModulePathChars,
    _Out_writes_(FunctionNameChars) PWCHAR FunctionName,
    _In_ ULONG FunctionNameChars
);

NTSTATUS
SysmonFormatCallTraceForProcess(
    _In_ HANDLE ProcessId,
    _In_reads_(FrameCount) PVOID *Frames,
    _In_ USHORT FrameCount,
    _Out_writes_(BufferChars) PWCHAR Buffer,
    _In_ ULONG BufferChars
);

/* Generate deterministic GUID from PID + creation time */
VOID
SysmonGenerateProcessGuid(
    _In_ ULONG ProcessId,
    _In_ LONGLONG CreateTime,
    _Out_writes_(40) WCHAR *GuidString
);

/* Query process token info (SID, integrity, elevation) */
NTSTATUS
SysmonQueryProcessTokenInfo(
    _In_ HANDLE ProcessHandle,
    _Out_ PSYSMON_PROCESS_INFO Info
);

#pragma once

#include "common.h"
#include "rules.h"

struct _SYSMON_SERVICE_CONTEXT;

typedef struct _SYSMON_PROCESS_METADATA {
    DWORD ProcessId;
    ULONGLONG CreateTime;
    WCHAR ProcessGuid[40];
    WCHAR Image[MAX_PATH];
    WCHAR UserName[256];
} SYSMON_PROCESS_METADATA, *PSYSMON_PROCESS_METADATA;

#define SYSMON_SOURCE_RULE_REFRESH_KEEP_OLD_ON_FAILURE 0x00000001UL

void
SysmonCopyOrPlaceholder(
    _Out_writes_(BufferChars) PWCHAR Buffer,
    _In_ size_t BufferChars,
    _In_opt_z_ PCWSTR Value);

BOOL
SysmonHasValueString(
    _In_opt_z_ PCWSTR Value);

BOOL
SysmonFormatCurrentUtcTime(
    _Out_writes_(BufferChars) PWCHAR Buffer,
    _In_ size_t BufferChars,
    _Out_opt_ PULONGLONG Timestamp);

void
SysmonResolveAccountName(
    _In_opt_ PSID Sid,
    _Out_writes_(BufferChars) PWCHAR Buffer,
    _In_ size_t BufferChars);

BOOL
SysmonGenerateProcessGuid(
    _In_ DWORD ProcessId,
    _In_ ULONGLONG CreateTime,
    _Out_writes_(BufferChars) PWCHAR Buffer,
    _In_ size_t BufferChars);

BOOL
SysmonCollectProcessMetadataAtTime(
    _In_opt_ struct _SYSMON_SERVICE_CONTEXT *ServiceContext,
    _In_ DWORD ProcessId,
    _In_opt_ const ULONGLONG *Timestamp,
    _Out_ PSYSMON_PROCESS_METADATA Metadata);

BOOL
SysmonCollectProcessMetadata(
    _In_opt_ struct _SYSMON_SERVICE_CONTEXT *ServiceContext,
    _In_ DWORD ProcessId,
    _Out_ PSYSMON_PROCESS_METADATA Metadata);

void
SysmonRefreshSourceRuleRuntime(
    _Inout_ struct _SYSMON_SERVICE_CONTEXT *ServiceContext,
    _Inout_ PSYSMON_RULE_RUNTIME *RuleRuntime,
    _Inout_ const BYTE **RuleSourceBlob,
    _Inout_ DWORD *RuleSourceBlobSize,
    _In_ DWORD RefreshFlags,
    _In_opt_z_ const char *SourceName);

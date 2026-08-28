#pragma once

#include "output.h"
#include "event_schema.h"

typedef struct _SYSMON_PROCESS_CREATE_ENRICHMENT {
    WCHAR Image[1024];
    WCHAR ParentImage[1024];
    WCHAR User[256];
    WCHAR ParentUser[256];
    WCHAR FileVersion[256];
    WCHAR Description[256];
    WCHAR Product[256];
    WCHAR Company[256];
    WCHAR OriginalFileName[256];
    WCHAR Hashes[256];
    BOOL NeedsVersionInfo;
    BOOL NeedsHashes;
    BOOL VersionInfoLoaded;
    BOOL HashesLoaded;
} SYSMON_PROCESS_CREATE_ENRICHMENT;

typedef struct _SYSMON_OUTPUT_EVENT_CONTEXT {
    const SYSMON_EVENT_SCHEMA *Schema;
    const UCHAR *PayloadBase;
    DWORD PayloadSize;
    const SYSMON_PROCESS_CREATE_ENRICHMENT *ProcessCreateEnrichment;
    SYSMON_PROCESS_CREATE_ENRICHMENT *ImageLoadEnrichment;
    SYSMON_PROCESS_CREATE_ENRICHMENT ProcessCreateStorage;
    SYSMON_PROCESS_CREATE_ENRICHMENT ImageLoadStorage;
} SYSMON_OUTPUT_EVENT_CONTEXT, *PSYSMON_OUTPUT_EVENT_CONTEXT;

void
SysmonInitializeOutputEnrichmentCaches(VOID);

void
SysmonCleanupOutputEnrichmentCaches(VOID);

void
SysmonFormatProductVersion(
    _Out_writes_(BufferChars) PWCHAR Buffer,
    _In_ size_t BufferChars);

BOOL
SysmonHasConfiguredFieldSize(
    _In_opt_z_ PCWSTR FieldName);

BOOL
HasPayloadBytes(
    _In_ DWORD PayloadSize,
    _In_ size_t Offset,
    _In_ size_t Size);

BOOL
CopyStringRefValue(
    _In_reads_bytes_(PayloadSize) const UCHAR *PayloadBase,
    _In_ DWORD PayloadSize,
    _In_ const SYSMON_EVENT_STRING_REF *StringRefAddress,
    _Out_writes_(BufferChars) PWCHAR Buffer,
    _In_ size_t BufferChars);

BOOL
SysmonGetStringRefValueView(
    _In_reads_bytes_(PayloadSize) const UCHAR *PayloadBase,
    _In_ DWORD PayloadSize,
    _In_ const SYSMON_EVENT_STRING_REF *StringRefAddress,
    _Outptr_result_z_ const WCHAR **Value,
    _Out_ ULONG *ValueSizeBytes);

BOOL
FormatFieldValue(
    _In_reads_bytes_(PayloadSize) const UCHAR *PayloadBase,
    _In_ DWORD PayloadSize,
    _In_ const SYSMON_EVENT_FIELD_DESCRIPTOR *Field,
    _Out_writes_(BufferChars) PWCHAR Buffer,
    _In_ size_t BufferChars);

BOOL
ShouldPreserveEmptyEtwString(
    _In_ SYSMON_EVENT_ID EventId,
    _In_ const SYSMON_EVENT_FIELD_DESCRIPTOR *Field);

void
SysmonResolveCurrentModuleFileVersion(
    _Out_writes_(BufferChars) PWCHAR Buffer,
    _In_ size_t BufferChars);

BOOL
FormatFieldValueForEvent(
    _In_ SYSMON_EVENT_ID EventId,
    _In_reads_bytes_(PayloadSize) const UCHAR *PayloadBase,
    _In_ DWORD PayloadSize,
    _In_ const SYSMON_EVENT_FIELD_DESCRIPTOR *Field,
    _In_opt_ const SYSMON_PROCESS_CREATE_ENRICHMENT *ProcessCreateEnrichment,
    _Inout_opt_ SYSMON_PROCESS_CREATE_ENRICHMENT *ImageLoadEnrichment,
    _Out_writes_(BufferChars) PWCHAR Buffer,
    _In_ size_t BufferChars);

BOOL
SysmonCanUseDirectEtwStringRef(
    _In_ SYSMON_EVENT_ID EventId,
    _In_ const SYSMON_EVENT_FIELD_DESCRIPTOR *Field,
    _In_opt_z_ PCWSTR RawValue,
    _In_opt_ const SYSMON_PROCESS_CREATE_ENRICHMENT *ProcessCreateEnrichment,
    _In_opt_ const SYSMON_PROCESS_CREATE_ENRICHMENT *ImageLoadEnrichment);

void
SysmonPrepareOutputEventContext(
    _In_ SYSMON_EVENT_ID EventId,
    _In_reads_bytes_(PayloadSize) const UCHAR *PayloadBase,
    _In_ DWORD PayloadSize,
    _Out_ PSYSMON_OUTPUT_EVENT_CONTEXT Context);

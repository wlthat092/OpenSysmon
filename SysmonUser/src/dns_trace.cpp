#include "../include/dns_trace.h"

#include "../include/config.h"
#include "../include/event.h"
#include "../include/packed_read.hpp"
#include "../include/pipeline.h"
#include "../include/process_store.h"
#include "../include/rules.h"
#include "../include/service.h"
#include "../include/source_common.h"
#include "../include/runtime.hpp"

#include <evntrace.h>
#include <evntcons.h>
#include <tdh.h>
#include <psapi.h>
#include <sddl.h>
#include <wincrypt.h>

#ifndef PROCESS_QUERY_LIMITED_INFORMATION
#define PROCESS_QUERY_LIMITED_INFORMATION 0x1000
#endif

#define SYSMON_DNS_TRACE_SESSION_NAME L"SysmonDnsEtwSession"
#define SYSMON_DNS_TRACE_BUFFER_SIZE  65536
#define SYSMON_DNS_EVENT_MAX_SIZE     SYSMON_EVENT_BUFFER_SIZE
#define SYSMON_DNS_QUERY_EVENT_ID     3008

static const GUID SYSMON_DNS_PROVIDER = {
    0x1c95126e, 0x7eea, 0x49a9, { 0xa3, 0xfe, 0xa3, 0x78, 0xb0, 0x3d, 0xdb, 0x4d }
};

typedef struct _SYSMON_TRACE_PROPERTIES_BUFFER {
    EVENT_TRACE_PROPERTIES Properties;
    WCHAR SessionName[64];
} SYSMON_TRACE_PROPERTIES_BUFFER, *PSYSMON_TRACE_PROPERTIES_BUFFER;

struct _SYSMON_DNS_TRACE_CONTEXT {
    PSYSMON_SERVICE_CONTEXT ServiceContext;
    HANDLE ThreadHandle;
    TRACEHANDLE SessionHandle;
    TRACEHANDLE ConsumerHandle;
    BOOL OwnsSession;
    SYSMON_TRACE_PROPERTIES_BUFFER Properties;
    PSYSMON_RULE_RUNTIME RuleRuntime;
    const BYTE *RuleSourceBlob;
    DWORD RuleSourceBlobSize;
    volatile LONG StopRequested;
};

static void
SysmonRefreshRuleRuntime(
    _Inout_ PSYSMON_DNS_TRACE_CONTEXT Context)
{
    if (Context == NULL || Context->ServiceContext == NULL) {
        return;
    }

    SysmonRefreshSourceRuleRuntime(
        Context->ServiceContext,
        &Context->RuleRuntime,
        &Context->RuleSourceBlob,
        &Context->RuleSourceBlobSize,
        SYSMON_SOURCE_RULE_REFRESH_KEEP_OLD_ON_FAILURE,
        "user-mode DNS");
}

static BOOL
SysmonGetPropertySizeByName(
    _In_ PEVENT_RECORD EventRecord,
    _In_z_ PCWSTR PropertyName,
    _Out_ PULONG PropertySize)
{
    PROPERTY_DATA_DESCRIPTOR descriptor;
    TDHSTATUS status;

    if (EventRecord == NULL || PropertyName == NULL || PropertySize == NULL) {
        return FALSE;
    }

    ZeroMemory(&descriptor, sizeof(descriptor));
    descriptor.PropertyName = (ULONGLONG)(ULONG_PTR)PropertyName;
    descriptor.ArrayIndex = ULONG_MAX;

    status = TdhGetPropertySize(EventRecord, 0, NULL, 1, &descriptor, PropertySize);
    return status == ERROR_SUCCESS;
}

static BOOL
SysmonTryGetUnicodeProperty(
    _In_ PEVENT_RECORD EventRecord,
    _In_z_ PCWSTR PropertyName,
    _Out_writes_(BufferChars) PWCHAR Buffer,
    _In_ size_t BufferChars)
{
    PROPERTY_DATA_DESCRIPTOR descriptor;
    ULONG propertySize = 0;
    PWCHAR valueBuffer = NULL;
    TDHSTATUS status;
    size_t index;
    size_t maxChars;

    if (Buffer == NULL || BufferChars == 0) {
        return FALSE;
    }

    Buffer[0] = L'\0';
    if (!SysmonGetPropertySizeByName(EventRecord, PropertyName, &propertySize) ||
        propertySize == 0) {
        return FALSE;
    }

    valueBuffer = (PWCHAR)SYSMON_ALLOC(propertySize + sizeof(WCHAR));
    if (valueBuffer == NULL) {
        return FALSE;
    }

    ZeroMemory(&descriptor, sizeof(descriptor));
    descriptor.PropertyName = (ULONGLONG)(ULONG_PTR)PropertyName;
    descriptor.ArrayIndex = ULONG_MAX;

    status = TdhGetProperty(
        EventRecord,
        0,
        NULL,
        1,
        &descriptor,
        propertySize,
        (PBYTE)valueBuffer);
    if (status != ERROR_SUCCESS) {
        SYSMON_FREE(valueBuffer);
        return FALSE;
    }

    maxChars = propertySize / sizeof(WCHAR);
    for (index = 0; index + 1 < maxChars; index++) {
        if (valueBuffer[index] == L'\0') {
            if (valueBuffer[index + 1] == L'\0') {
                break;
            }
            valueBuffer[index] = L';';
        }
    }
    valueBuffer[maxChars] = L'\0';

    SysmonCopyOrPlaceholder(Buffer, BufferChars, valueBuffer);
    SYSMON_FREE(valueBuffer);
    return TRUE;
}

static BOOL
SysmonGetUnicodePropertyAlloc(
    _In_ PEVENT_RECORD EventRecord,
    _In_z_ PCWSTR PropertyName,
    _Outptr_result_z_ PWCHAR *Value)
{
    PROPERTY_DATA_DESCRIPTOR descriptor;
    ULONG propertySize = 0;
    ULONG maxChars;
    ULONG index;
    PWCHAR buffer;
    TDHSTATUS status;

    if (Value == NULL) {
        return FALSE;
    }
    *Value = NULL;
    if (!SysmonGetPropertySizeByName(EventRecord, PropertyName, &propertySize) ||
        propertySize == 0 || propertySize > (1024 * 1024) ||
        (propertySize % sizeof(WCHAR)) != 0) {
        return FALSE;
    }

    buffer = (PWCHAR)SYSMON_ALLOC(propertySize + sizeof(WCHAR));
    if (buffer == NULL) {
        return FALSE;
    }
    ZeroMemory(buffer, propertySize + sizeof(WCHAR));
    ZeroMemory(&descriptor, sizeof(descriptor));
    descriptor.PropertyName = (ULONGLONG)(ULONG_PTR)PropertyName;
    descriptor.ArrayIndex = ULONG_MAX;
    status = TdhGetProperty(
        EventRecord,
        0,
        NULL,
        1,
        &descriptor,
        propertySize,
        (PBYTE)buffer);
    if (status != ERROR_SUCCESS) {
        SYSMON_FREE(buffer);
        return FALSE;
    }

    maxChars = propertySize / sizeof(WCHAR);
    for (index = 0; index + 1 < maxChars; index++) {
        if (buffer[index] == L'\0') {
            if (buffer[index + 1] == L'\0') {
                break;
            }
            buffer[index] = L';';
        }
    }
    buffer[maxChars] = L'\0';
    *Value = buffer;
    return TRUE;
}

static BOOL
SysmonTryGetUInt32Property(
    _In_ PEVENT_RECORD EventRecord,
    _In_z_ PCWSTR PropertyName,
    _Out_ PDWORD Value)
{
    PROPERTY_DATA_DESCRIPTOR descriptor;
    ULONG propertySize = 0;
    BYTE rawBuffer[sizeof(ULONGLONG)] = { 0 };
    WCHAR textBuffer[64];
    TDHSTATUS status;

    if (Value == NULL) {
        return FALSE;
    }

    *Value = 0;
    if (!SysmonGetPropertySizeByName(EventRecord, PropertyName, &propertySize) ||
        propertySize == 0) {
        return FALSE;
    }

    if (propertySize <= sizeof(rawBuffer)) {
        ZeroMemory(&descriptor, sizeof(descriptor));
        descriptor.PropertyName = (ULONGLONG)(ULONG_PTR)PropertyName;
        descriptor.ArrayIndex = ULONG_MAX;

        status = TdhGetProperty(
            EventRecord,
            0,
            NULL,
            1,
            &descriptor,
            propertySize,
            rawBuffer);
        if (status == ERROR_SUCCESS) {
            switch (propertySize) {
            case sizeof(BYTE):
                *Value = rawBuffer[0];
                return TRUE;
            case sizeof(USHORT):
                *Value = *(const USHORT *)rawBuffer;
                return TRUE;
            case sizeof(ULONG):
                *Value = *(const ULONG *)rawBuffer;
                return TRUE;
            default:
                break;
            }
        }
    }

    if (SysmonTryGetUnicodeProperty(EventRecord, PropertyName, textBuffer, _countof(textBuffer))) {
        *Value = wcstoul(textBuffer, NULL, 10);
        return TRUE;
    }

    return FALSE;
}

static BOOL
SysmonFormatDnsStatusString(
    _In_ DWORD QueryStatus,
    _Out_writes_(BufferChars) PWCHAR Buffer,
    _In_ size_t BufferChars)
{
    if (Buffer == NULL || BufferChars == 0) {
        return FALSE;
    }

    Buffer[0] = L'\0';
    return _snwprintf_s(Buffer, BufferChars, _TRUNCATE, L"%lu", (unsigned long)QueryStatus) >= 0;
}

static void
SysmonDispatchDnsEvent(
    _Inout_ PSYSMON_DNS_TRACE_CONTEXT Context,
    _In_ PEVENT_RECORD EventRecord)
{
    PBYTE eventBuffer;
    SYSMON_EVENT_PAYLOAD_BUILDER builder;
    PSYSMON_EVENT_HEADER header;
    SYSMON_EVENT_DNS_QUERY_PAYLOAD *payload;
    SYSMON_PROCESS_METADATA metadata;
    WCHAR utcTime[64];
    WCHAR queryName[512];
    WCHAR queryStatusText[32];
    WCHAR queryTypeText[32];
    WCHAR queryResultsFallback[2];
    PWCHAR allocatedQueryResults;
    PWCHAR queryResults;
    PCWSTR fieldValues[8];
    DWORD eventBufferSize;
    DWORD fieldIndex;
    SYSMON_STATUS fieldStatus;
    DWORD queryStatus = 0;
    ULONGLONG timestamp = 0;
    BOOL dispatch = FALSE;

    if (Context == NULL || EventRecord == NULL) {
        return;
    }

    eventBuffer = NULL;
    allocatedQueryResults = NULL;
    queryResultsFallback[0] = L'-';
    queryResultsFallback[1] = L'\0';
    queryResults = queryResultsFallback;
    ZeroMemory(&builder, sizeof(builder));
    ZeroMemory(&metadata, sizeof(metadata));

    SysmonRefreshRuleRuntime(Context);
    if (Context->RuleRuntime != NULL &&
        !SysmonRuleRuntimeEventCanProduceLogs(Context->RuleRuntime, SysmonEventDnsQuery)) {
        return;
    }

    do {
        if (!SysmonTryGetUnicodeProperty(EventRecord, L"QueryName", queryName, _countof(queryName)) ||
            queryName[0] == L'\0') {
            break;
        }

        if (!SysmonTryGetUInt32Property(EventRecord, L"QueryStatus", &queryStatus)) {
            queryStatus = 0;
        }

        if (SysmonGetUnicodePropertyAlloc(EventRecord, L"QueryResults", &allocatedQueryResults)) {
            queryResults = allocatedQueryResults;
        }

        if (!SysmonTryGetUnicodeProperty(EventRecord, L"QueryType", queryTypeText, _countof(queryTypeText))) {
            SysmonCopyOrPlaceholder(queryTypeText, _countof(queryTypeText), L"-");
        } else {
            if (wcscmp(queryTypeText, L"1") == 0) {
                wcscpy_s(queryTypeText, _countof(queryTypeText), L"IPv4");
            } else if (wcscmp(queryTypeText, L"28") == 0) {
                wcscpy_s(queryTypeText, _countof(queryTypeText), L"IPv6");
            }
        }

        if (!SysmonFormatDnsStatusString(queryStatus, queryStatusText, _countof(queryStatusText))) {
            break;
        }

        if (!SysmonFormatSyntheticUtcTimestamp(
                EventRecord->EventHeader.TimeStamp.QuadPart,
                utcTime,
                _countof(utcTime),
                &timestamp)) {
            break;
        }

        if (!SysmonProcessStoreRememberDnsEvent(
                EventRecord->EventHeader.ProcessId,
                &timestamp,
                queryName,
                queryStatusText,
                queryResults)) {
            break;
        }

        if (queryStatus == 87) {
            break;
        }

        SysmonCollectProcessMetadataAtTime(
            Context->ServiceContext,
            EventRecord->EventHeader.ProcessId,
            &timestamp,
            &metadata);

        fieldValues[0] = L"-";
        fieldValues[1] = utcTime;
        fieldValues[2] = metadata.ProcessGuid;
        fieldValues[3] = queryName;
        fieldValues[4] = queryStatusText;
        fieldValues[5] = queryResults;
        fieldValues[6] = metadata.Image;
        fieldValues[7] = metadata.UserName;
        eventBufferSize = SYSMON_EVENT_HEADER_SIZE + sizeof(*payload);
        for (fieldIndex = 0; fieldIndex < _countof(fieldValues); fieldIndex++) {
            size_t chars = fieldValues[fieldIndex] != NULL ? wcslen(fieldValues[fieldIndex]) : 0;
            if (chars > (MAXDWORD - eventBufferSize - sizeof(WCHAR)) / sizeof(WCHAR)) {
                eventBufferSize = 0;
                break;
            }
            eventBufferSize += (DWORD)((chars + 1) * sizeof(WCHAR));
        }
        if (eventBufferSize == 0 || eventBufferSize > SYSMON_DNS_EVENT_MAX_SIZE) {
            break;
        }

        eventBuffer = (PBYTE)SYSMON_ALLOC(eventBufferSize);
        if (eventBuffer == NULL) {
            break;
        }

        SysmonInitializeEventBuffer(
            eventBuffer,
            eventBufferSize,
            SysmonEventDnsQuery,
            sizeof(*payload),
            &builder,
            timestamp);

        header = (PSYSMON_EVENT_HEADER)eventBuffer;
        if (header->EventSize == 0) {
            break;
        }

        payload = (SYSMON_EVENT_DNS_QUERY_PAYLOAD *)(eventBuffer + SYSMON_EVENT_HEADER_SIZE);
        ZeroMemory(payload, sizeof(*payload));
        SysmonWritePackedValue<DWORD>(&payload->ProcessId, EventRecord->EventHeader.ProcessId);

        fieldStatus = SysmonAddStringField(eventBuffer, eventBufferSize, &builder, &payload->RuleName, fieldValues[0]);
        if (fieldStatus != SYSMON_SUCCESS) break;
        fieldStatus = SysmonAddStringField(eventBuffer, eventBufferSize, &builder, &payload->UtcTime, fieldValues[1]);
        if (fieldStatus != SYSMON_SUCCESS) break;
        fieldStatus = SysmonAddStringField(eventBuffer, eventBufferSize, &builder, &payload->ProcessGuid, fieldValues[2]);
        if (fieldStatus != SYSMON_SUCCESS) break;
        fieldStatus = SysmonAddStringField(eventBuffer, eventBufferSize, &builder, &payload->QueryName, fieldValues[3]);
        if (fieldStatus != SYSMON_SUCCESS) break;
        fieldStatus = SysmonAddStringField(eventBuffer, eventBufferSize, &builder, &payload->QueryStatus, fieldValues[4]);
        if (fieldStatus != SYSMON_SUCCESS) break;
        fieldStatus = SysmonAddStringField(eventBuffer, eventBufferSize, &builder, &payload->QueryResults, fieldValues[5]);
        if (fieldStatus != SYSMON_SUCCESS) break;
        fieldStatus = SysmonAddStringField(eventBuffer, eventBufferSize, &builder, &payload->Image, fieldValues[6]);
        if (fieldStatus != SYSMON_SUCCESS) break;
        fieldStatus = SysmonAddStringField(eventBuffer, eventBufferSize, &builder, &payload->User, fieldValues[7]);
        if (fieldStatus != SYSMON_SUCCESS) break;

        dispatch = Context->RuleRuntime == NULL ||
            SysmonShouldCaptureEvent(
                Context->RuleRuntime,
                SysmonEventDnsQuery,
                eventBuffer,
                ((PSYSMON_EVENT_HEADER)eventBuffer)->EventSize);
    } while (0);

    if (dispatch && eventBuffer != NULL) {
        SysmonPipelineDispatch(eventBuffer, ((PSYSMON_EVENT_HEADER)eventBuffer)->EventSize);
    }
    if (eventBuffer != NULL) {
        SYSMON_FREE(eventBuffer);
    }
    if (allocatedQueryResults != NULL) {
        SYSMON_FREE(allocatedQueryResults);
    }
}

static VOID WINAPI
SysmonDnsTraceRecordCallback(
    _In_ PEVENT_RECORD EventRecord)
{
    PSYSMON_DNS_TRACE_CONTEXT context;

    if (EventRecord == NULL) {
        return;
    }

    context = (PSYSMON_DNS_TRACE_CONTEXT)EventRecord->UserContext;
    if (context == NULL || InterlockedCompareExchange(&context->StopRequested, 0, 0) != 0) {
        return;
    }

    if (!IsEqualGUID(EventRecord->EventHeader.ProviderId, SYSMON_DNS_PROVIDER) ||
        EventRecord->EventHeader.EventDescriptor.Id != SYSMON_DNS_QUERY_EVENT_ID) {
        return;
    }

    SysmonDispatchDnsEvent(context, EventRecord);
}

static DWORD WINAPI
SysmonDnsTraceThread(
    _In_ LPVOID Parameter)
{
    PSYSMON_DNS_TRACE_CONTEXT context = (PSYSMON_DNS_TRACE_CONTEXT)Parameter;
    TRACEHANDLE handles[1];
    ULONG status;

    if (context == NULL || context->ConsumerHandle == INVALID_PROCESSTRACE_HANDLE) {
        return ERROR_INVALID_HANDLE;
    }

    handles[0] = context->ConsumerHandle;
    status = ProcessTrace(handles, 1, NULL, NULL);
    if (InterlockedCompareExchange(&context->StopRequested, 0, 0) == 0) {
        /* ProcessTrace can return ERROR_SUCCESS when the ETW session is
           stopped externally. The consumer is still dead in that case and
           the service must rebuild it on the next health pass. */
        InterlockedExchange(&context->ServiceContext->DnsTraceFaulted, 1);
        SysmonLogWarning(
            SYSMON_COMPONENT_SERVICE,
            "ProcessTrace for DNS session ended with status %lu while the source was active",
            (unsigned long)status);
    }

    return status;
}

SYSMON_STATUS
SysmonDnsTraceStart(
    PSYSMON_SERVICE_CONTEXT ServiceContext,
    PSYSMON_DNS_TRACE_CONTEXT *Context)
{
    EVENT_TRACE_LOGFILEW logfile;
    PSYSMON_DNS_TRACE_CONTEXT context;
    ULONG status;

    if (ServiceContext == NULL || Context == NULL) {
        return SYSMON_ERROR_INVALID_PARAM;
    }

    *Context = NULL;
    context = (PSYSMON_DNS_TRACE_CONTEXT)SYSMON_ALLOC(sizeof(*context));
    if (context == NULL) {
        return SYSMON_ERROR_OUT_OF_MEMORY;
    }

    ZeroMemory(context, sizeof(*context));
    context->ServiceContext = ServiceContext;
    context->ConsumerHandle = INVALID_PROCESSTRACE_HANDLE;
    wcscpy_s(
        context->Properties.SessionName,
        _countof(context->Properties.SessionName),
        SYSMON_DNS_TRACE_SESSION_NAME);
    context->Properties.Properties.Wnode.BufferSize = sizeof(context->Properties);
    /* Keep EventHeader.TimeStamp in the FILETIME epoch used by the process
       store and SysmonFormatSyntheticUtcTimestamp. */
    context->Properties.Properties.Wnode.ClientContext = 2;
    context->Properties.Properties.Wnode.Flags = WNODE_FLAG_TRACED_GUID;
    context->Properties.Properties.LogFileMode = EVENT_TRACE_REAL_TIME_MODE;
    context->Properties.Properties.LoggerNameOffset = offsetof(SYSMON_TRACE_PROPERTIES_BUFFER, SessionName);
    context->Properties.Properties.FlushTimer = 1;

    status = StartTraceW(
        &context->SessionHandle,
        context->Properties.SessionName,
        &context->Properties.Properties);
    if (status == ERROR_ALREADY_EXISTS) {
        SysmonLogWarning(
            SYSMON_COMPONENT_SERVICE,
            "DNS ETW session '%ls' is already owned by another producer",
            context->Properties.SessionName);
    }
    if (status != ERROR_SUCCESS) {
        SysmonDnsTraceStop(context);
        return status;
    }
    context->OwnsSession = TRUE;

    status = EnableTraceEx2(
        context->SessionHandle,
        &SYSMON_DNS_PROVIDER,
        EVENT_CONTROL_CODE_ENABLE_PROVIDER,
        TRACE_LEVEL_INFORMATION,
        0,
        0,
        0,
        NULL);
    if (status != ERROR_SUCCESS) {
        SysmonDnsTraceStop(context);
        return status;
    }

    ZeroMemory(&logfile, sizeof(logfile));
    logfile.LoggerName = context->Properties.SessionName;
    logfile.ProcessTraceMode = PROCESS_TRACE_MODE_REAL_TIME | PROCESS_TRACE_MODE_EVENT_RECORD;
    logfile.EventRecordCallback = SysmonDnsTraceRecordCallback;
    logfile.Context = context;

    context->ConsumerHandle = OpenTraceW(&logfile);
    if (context->ConsumerHandle == INVALID_PROCESSTRACE_HANDLE) {
        status = GetLastError();
        SysmonDnsTraceStop(context);
        return status;
    }

    context->ThreadHandle = CreateThread(NULL, 0, SysmonDnsTraceThread, context, 0, NULL);
    if (context->ThreadHandle == NULL) {
        status = GetLastError();
        SysmonDnsTraceStop(context);
        return status;
    }

    *Context = context;
    return SYSMON_SUCCESS;
}

void
SysmonDnsTraceStop(
    PSYSMON_DNS_TRACE_CONTEXT Context)
{
    if (Context == NULL) {
        return;
    }

    InterlockedExchange(&Context->StopRequested, 1);

    if (Context->ConsumerHandle != INVALID_PROCESSTRACE_HANDLE) {
        CloseTrace(Context->ConsumerHandle);
        Context->ConsumerHandle = INVALID_PROCESSTRACE_HANDLE;
    }

    if (Context->OwnsSession && Context->SessionHandle != 0) {
        ControlTraceW(
            Context->SessionHandle,
            Context->Properties.SessionName,
            &Context->Properties.Properties,
            EVENT_TRACE_CONTROL_STOP);
    }
    Context->SessionHandle = 0;
    Context->OwnsSession = FALSE;

    if (Context->ThreadHandle != NULL) {
        WaitForSingleObject(Context->ThreadHandle, INFINITE);
        CloseHandle(Context->ThreadHandle);
        Context->ThreadHandle = NULL;
    }

    SysmonFreeRuleRuntime(Context->RuleRuntime);
    Context->RuleRuntime = NULL;
    SYSMON_FREE(Context);
}

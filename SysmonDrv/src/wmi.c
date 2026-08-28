#include "wmi.h"
#include "queue.h"
#include "event.h"
#include "driver.h"
#include "processinfo.h"
#include "utils.h"

/*
 * WmiEvent (Events 19, 20, 21) - WMI Event Monitoring
 *
 * Monitors WMI activity by detecting registry operations under:
 *   HKLM\SOFTWARE\Microsoft\WBEM
 *   HKLM\SYSTEM\CurrentControlSet\Control\WMI
 *
 * The canonical WMI producer is the user-mode ROOT\\Subscription watcher.
 * This file retains payload/schema helpers for compatibility only; it is not
 * registered as a runtime producer because registry callbacks cannot recover
 * the WMI object fields required by Events 19/20/21.
 */

/* WMI-related registry path prefixes */
static const WCHAR g_WbemPath[] = L"\\REGISTRY\\MACHINE\\SOFTWARE\\Microsoft\\WBEM";
static const WCHAR g_WmiControlPath[] = L"\\REGISTRY\\MACHINE\\SYSTEM\\CurrentControlSet\\Control\\WMI";
static const WCHAR g_EventFilterPath[] = L"__EventFilter";
static const WCHAR g_EventConsumerPath[] = L"__EventConsumer";
static const WCHAR g_FilterToConsumerPath[] = L"__FilterToConsumerBinding";

typedef struct _SYSMON_WMI_CONTEXT {
    ULONG EventId;
    ULONG ProcessId;
    WCHAR EventType[32];
    WCHAR UtcTime[64];
    WCHAR Operation[64];
    WCHAR User[SYSMON_MAX_SID_STRING];
    WCHAR Path[SYSMON_MAX_PATH];
    WCHAR Name[SYSMON_MAX_PATH];
} SYSMON_WMI_CONTEXT, *PSYSMON_WMI_CONTEXT;

static PCWSTR
SysmonWmiEventTypeName(_In_ ULONG EventId)
{
    switch (EventId) {
    case SysmonEventWmiFilter:
        return L"WmiFilterEvent";
    case SysmonEventWmiConsumer:
        return L"WmiConsumerEvent";
    case SysmonEventWmiConsumerToFilter:
        return L"WmiBindingEvent";
    default:
        return L"WmiEvent";
    }
}

static NTSTATUS
SysmonAddWmiEventTypeField(
    _Inout_ PSYSMON_EVENT_UNION Event,
    _Inout_ PSYSMON_EVENT_PAYLOAD_BUILDER Builder,
    _Out_ SYSMON_EVENT_STRING_REF *Ref,
    _In_ ULONG EventId)
{
    switch (EventId) {
    case SysmonEventWmiFilter:
        return SysmonAddStringLiteralField(Event, Builder, Ref, L"WmiFilterEvent");
    case SysmonEventWmiConsumer:
        return SysmonAddStringLiteralField(Event, Builder, Ref, L"WmiConsumerEvent");
    case SysmonEventWmiConsumerToFilter:
        return SysmonAddStringLiteralField(Event, Builder, Ref, L"WmiBindingEvent");
    default:
        return SysmonAddStringLiteralField(Event, Builder, Ref, L"WmiEvent");
    }
}

static NTSTATUS
SysmonAddWmiOperationField(
    _Inout_ PSYSMON_EVENT_UNION Event,
    _Inout_ PSYSMON_EVENT_PAYLOAD_BUILDER Builder,
    _Out_ SYSMON_EVENT_STRING_REF *Ref,
    _In_opt_z_ PCWSTR Operation)
{
    if (Operation == NULL || Operation[0] == L'\0') {
        return SysmonAddStringLiteralField(Event, Builder, Ref, L"RegistryOperation");
    }

    if (_wcsicmp(Operation, L"Created") == 0) {
        return SysmonAddStringLiteralField(Event, Builder, Ref, L"Created");
    }
    if (_wcsicmp(Operation, L"Deleted") == 0) {
        return SysmonAddStringLiteralField(Event, Builder, Ref, L"Deleted");
    }
    if (_wcsicmp(Operation, L"Renamed") == 0) {
        return SysmonAddStringLiteralField(Event, Builder, Ref, L"Renamed");
    }
    if (_wcsicmp(Operation, L"Modified") == 0) {
        return SysmonAddStringLiteralField(Event, Builder, Ref, L"Modified");
    }
    if (_wcsicmp(Operation, L"RegistryOperation") == 0) {
        return SysmonAddStringLiteralField(Event, Builder, Ref, L"RegistryOperation");
    }

    return SysmonAddStringField(Event, Builder, Ref, Operation);
}

static VOID
SysmonCopyLastPathComponent(
    _Out_writes_(DstChars) PWCHAR Dst,
    _In_ ULONG DstChars,
    _In_z_ PCWSTR Path)
{
    PCWSTR cursor;
    PCWSTR component;

    if (Dst == NULL || DstChars == 0) {
        return;
    }

    Dst[0] = L'\0';
    if (Path == NULL || Path[0] == L'\0') {
        return;
    }

    component = Path;
    cursor = Path;
    while (*cursor != L'\0') {
        if (*cursor == L'\\') {
            component = cursor + 1;
        }
        cursor++;
    }

    SysmonCopyWideString(Dst, DstChars, component);
}

static VOID
SysmonPopulateWmiUser(
    _Inout_ PSYSMON_WMI_CONTEXT Context)
{
    SYSMON_PROCESS_INFO *processInfo;

    if (KeGetCurrentIrql() != PASSIVE_LEVEL) {
        DbgPrintEx(
            DPFLTR_DEFAULT_ID,
            DPFLTR_WARNING_LEVEL,
            "[SysmonDrv] WMI user deferred: callback IRQL is not PASSIVE_LEVEL\n");
        return;
    }

    processInfo = (SYSMON_PROCESS_INFO *)SysmonAllocatePool(sizeof(SYSMON_PROCESS_INFO));
    if (processInfo == NULL) {
        return;
    }

    if (NT_SUCCESS(SysmonCollectProcessInfo(
            (HANDLE)(ULONG_PTR)Context->ProcessId,
            processInfo))) {
        /*
         * Kernel account-name resolution is deferred; User carries SID text
         * until user-mode enrichment is implemented.
         */
        SysmonCopyWideString(
            Context->User,
            RTL_NUMBER_OF(Context->User),
            processInfo->UserSid);
    }

    SysmonFreePool(processInfo);
}

/*
 * Check if a registry path is WMI-related.
 * Returns the appropriate Sysmon event ID, or 0 if not WMI.
 */
BOOLEAN
SysmonIsWmiRegistryPath(_In_ PCUNICODE_STRING KeyPath)
{
    if (KeyPath == NULL || KeyPath->Buffer == NULL || KeyPath->Length == 0) {
        return FALSE;
    }

    /* Check WBEM path */
    if (KeyPath->Length >= sizeof(g_WbemPath) - sizeof(WCHAR)) {
        if (_wcsnicmp(KeyPath->Buffer, g_WbemPath,
            (sizeof(g_WbemPath) - sizeof(WCHAR)) / sizeof(WCHAR)) == 0) {
            return TRUE;
        }
    }

    /* Check WMI control path */
    if (KeyPath->Length >= sizeof(g_WmiControlPath) - sizeof(WCHAR)) {
        if (_wcsnicmp(KeyPath->Buffer, g_WmiControlPath,
            (sizeof(g_WmiControlPath) - sizeof(WCHAR)) / sizeof(WCHAR)) == 0) {
            return TRUE;
        }
    }

    return FALSE;
}

/*
 * Classify WMI event type based on the registry path.
 */
static ULONG
SysmonClassifyWmiEvent(_In_ PCUNICODE_STRING KeyPath)
{
    WCHAR path[SYSMON_MAX_PATH];

    if (KeyPath == NULL || KeyPath->Buffer == NULL) return 0;

    SysmonCopyUnicodeString(path, RTL_NUMBER_OF(path), KeyPath);

    if (wcsstr(path, g_FilterToConsumerPath) != NULL) {
        return SysmonEventWmiConsumerToFilter;
    }
    if (wcsstr(path, g_EventFilterPath) != NULL) {
        return SysmonEventWmiFilter;
    }
    if (wcsstr(path, g_EventConsumerPath) != NULL) {
        return SysmonEventWmiConsumer;
    }

    return 0;
}

/*
 * Build a WMI event from registry callback data.
 */
NTSTATUS
SysmonBuildWmiEvent(
    _In_ ULONG EventId,
    _In_ ULONG ProcessId,
    _In_ PCUNICODE_STRING KeyPath,
    _In_opt_z_ PCWSTR Operation,
    _Out_ PVOID *EventData,
    _Out_ PULONG EventSize)
{
    PSYSMON_EVENT_UNION event = NULL;
    SYSMON_EVENT_PAYLOAD_BUILDER builder;
    SYSMON_WMI_CONTEXT context;

    *EventData = NULL;
    *EventSize = 0;

    RtlZeroMemory(&context, sizeof(context));
    context.EventId = EventId;
    context.ProcessId = ProcessId;
    SysmonCopyWideString(
        context.EventType,
        RTL_NUMBER_OF(context.EventType),
        SysmonWmiEventTypeName(EventId));
    if (!NT_SUCCESS(SysmonFormatTimestamp(SysmonGetCurrentTimestamp(), context.UtcTime))) {
        context.UtcTime[0] = L'\0';
    }
    SysmonCopyWideString(
        context.Operation,
        RTL_NUMBER_OF(context.Operation),
        (Operation != NULL) ? Operation : L"RegistryOperation");
    SysmonCopyUnicodeString(context.Path, RTL_NUMBER_OF(context.Path), KeyPath);
    SysmonCopyLastPathComponent(
        context.Name,
        RTL_NUMBER_OF(context.Name),
        context.Path);
    SysmonPopulateWmiUser(&context);

    event = SysmonAllocateEvent((SYSMON_EVENT_ID)EventId);
    if (event == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    /*
     * This module is still registry-backed instrumentation. It can identify
     * likely WMI subscription activity and the caller, but not full WMI object
     * properties such as real namespace/query/consumer bindings.
     */
    if (EventId == SysmonEventWmiFilter) {
        SYSMON_EVENT_WMI_FILTER_PAYLOAD *payload;

        SysmonBeginStringPayload(event, sizeof(*payload), &builder);
        payload = (SYSMON_EVENT_WMI_FILTER_PAYLOAD *)event->RawData;
        SysmonAddStringLiteralField(event, &builder, &payload->RuleName, L"-");
        SysmonAddWmiEventTypeField(event, &builder, &payload->EventType, context.EventId);
        SysmonAddFixedLengthStringField(
            event,
            &builder,
            &payload->UtcTime,
            context.UtcTime,
            SYSMON_TIMESTAMP_STRING_CHARS);
        SysmonAddWmiOperationField(event, &builder, &payload->Operation, context.Operation);
        SysmonAddStringField(event, &builder, &payload->User, context.User);
        SysmonAddStringField(event, &builder, &payload->EventNamespace, NULL);
        SysmonAddStringField(event, &builder, &payload->Name, context.Name);
        SysmonAddStringField(event, &builder, &payload->Query, NULL);
    } else if (EventId == SysmonEventWmiConsumer) {
        SYSMON_EVENT_WMI_CONSUMER_PAYLOAD *payload;

        SysmonBeginStringPayload(event, sizeof(*payload), &builder);
        payload = (SYSMON_EVENT_WMI_CONSUMER_PAYLOAD *)event->RawData;
        SysmonAddStringLiteralField(event, &builder, &payload->RuleName, L"-");
        SysmonAddWmiEventTypeField(event, &builder, &payload->EventType, context.EventId);
        SysmonAddFixedLengthStringField(
            event,
            &builder,
            &payload->UtcTime,
            context.UtcTime,
            SYSMON_TIMESTAMP_STRING_CHARS);
        SysmonAddWmiOperationField(event, &builder, &payload->Operation, context.Operation);
        SysmonAddStringField(event, &builder, &payload->User, context.User);
        SysmonAddStringField(event, &builder, &payload->Name, context.Name);
        SysmonAddStringField(event, &builder, &payload->Type, NULL);
        /*
         * Registry-backed WBEM detection does not expose the real consumer
         * destination (for example a command line or script target). Leave it
         * empty instead of logging the registry path as false data.
         */
        SysmonAddStringField(event, &builder, &payload->Destination, NULL);
    } else {
        SYSMON_EVENT_WMI_CONSUMER_TO_FILTER_PAYLOAD *payload;

        SysmonBeginStringPayload(event, sizeof(*payload), &builder);
        payload = (SYSMON_EVENT_WMI_CONSUMER_TO_FILTER_PAYLOAD *)event->RawData;
        SysmonAddStringLiteralField(event, &builder, &payload->RuleName, L"-");
        SysmonAddWmiEventTypeField(event, &builder, &payload->EventType, context.EventId);
        SysmonAddFixedLengthStringField(
            event,
            &builder,
            &payload->UtcTime,
            context.UtcTime,
            SYSMON_TIMESTAMP_STRING_CHARS);
        SysmonAddWmiOperationField(event, &builder, &payload->Operation, context.Operation);
        SysmonAddStringField(event, &builder, &payload->User, context.User);
        SysmonAddStringField(event, &builder, &payload->Consumer, NULL);
        SysmonAddStringField(event, &builder, &payload->Filter, NULL);
    }

    *EventData = event;
    *EventSize = event->Header.EventSize;
    return STATUS_SUCCESS;
}

/*
 * Process a registry operation for WMI events.
 * Called from the registry callback when a WMI path is detected.
 */
NTSTATUS
SysmonProcessWmiRegistryEvent(
    _In_ PCUNICODE_STRING KeyPath,
    _In_ ULONG ProcessId,
    _In_opt_z_ PCWSTR Operation)
{
    ULONG wmiEventId;
    PVOID eventData = NULL;
    ULONG eventSize = 0;
    PSYSMON_EVENT_UNION event = NULL;
    NTSTATUS status;

    wmiEventId = SysmonClassifyWmiEvent(KeyPath);
    if (wmiEventId == 0) return STATUS_SUCCESS;

    status = SysmonBuildWmiEvent(wmiEventId, ProcessId, KeyPath, Operation,
        &eventData, &eventSize);
    if (!NT_SUCCESS(status) || eventData == NULL) {
        return status;
    }

    event = (PSYSMON_EVENT_UNION)eventData;
    SysmonPublishEvent(event);
    SysmonFreeEvent(event);

    return STATUS_SUCCESS;
}

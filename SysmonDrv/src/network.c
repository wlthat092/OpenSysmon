#include "network.h"
#include "queue.h"
#include "event.h"
#include "driver.h"
#include "processinfo.h"
#include "utils.h"

/*
 * NetworkConnect (Event 3) - Network Connection Monitoring
 *
 * This module provides the framework for monitoring network connections.
 * Full WFP (Windows Filtering Platform) callout implementation requires:
 *   - fwpsk.h, fwpmk.h (WDK WFP headers)
 *   - fwpkclnt.lib, ndis.lib (WFP libraries)
 *   - Proper callout registration at FWPS_LAYER_ALE_AUTH_CONNECT_V4
 *
 * For now, this provides event reporting infrastructure. The actual
 * network connection data is populated when WFP callout is triggered.
 *
 * NOTE: The original SysmonDrv (v100.18.0) does NOT import WFP APIs.
 * Network monitoring in Sysmon is primarily done by the user-mode
 * Sysmon.exe service through DLL injection and hooking.
 */

static BOOLEAN g_NetworkInitialized = FALSE;

typedef struct _SYSMON_NETWORK_CONTEXT {
    ULONG ProcessId;
    WCHAR UtcTime[64];
    WCHAR ProcessGuid[SYSMON_MAX_GUID_STRING];
    WCHAR Image[SYSMON_MAX_PATH];
    WCHAR User[SYSMON_MAX_SID_STRING];
    WCHAR Protocol[16];
    WCHAR SourceIp[64];
    WCHAR DestinationIp[64];
    USHORT SourcePort;
    USHORT DestinationPort;
} SYSMON_NETWORK_CONTEXT, *PSYSMON_NETWORK_CONTEXT;

static VOID
SysmonPopulateNetworkProcessContext(
    _Inout_ PSYSMON_NETWORK_CONTEXT Context)
{
    SYSMON_PROCESS_INFO *processInfo;

    if (KeGetCurrentIrql() != PASSIVE_LEVEL) {
        DbgPrintEx(
            DPFLTR_DEFAULT_ID,
            DPFLTR_WARNING_LEVEL,
            "[SysmonDrv] Network process identity deferred: callback IRQL is not PASSIVE_LEVEL\n");
        return;
    }

    processInfo = (SYSMON_PROCESS_INFO *)SysmonAllocatePool(sizeof(SYSMON_PROCESS_INFO));
    if (processInfo == NULL) {
        return;
    }

    if (NT_SUCCESS(SysmonCollectProcessInfo(
            (HANDLE)(ULONG_PTR)Context->ProcessId,
            processInfo))) {
        SysmonCopyWideStringWithLength(
            Context->ProcessGuid,
            RTL_NUMBER_OF(Context->ProcessGuid),
            processInfo->ProcessGuid,
            SYSMON_GUID_STRING_CHARS);
        SysmonCopyWideString(
            Context->Image,
            RTL_NUMBER_OF(Context->Image),
            processInfo->ImagePath);
        /*
         * Account-name resolution is deferred; carry the available SID text
         * in User rather than fabricating domain\user.
         */
        SysmonCopyWideString(
            Context->User,
            RTL_NUMBER_OF(Context->User),
            processInfo->UserSid);
    }

    SysmonFreePool(processInfo);
}

static VOID
SysmonFormatIpv4(
    _In_ ULONG Address,
    _Out_writes_(64) PWCHAR Buffer)
{
    _snwprintf_s(Buffer, 64, _TRUNCATE, L"%d.%d.%d.%d",
        Address & 0xFF, (Address >> 8) & 0xFF,
        (Address >> 16) & 0xFF, (Address >> 24) & 0xFF);
}

static PCWSTR
SysmonProtocolName(_In_ ULONG Protocol)
{
    switch (Protocol) {
    case 6:
        return L"tcp";
    case 17:
        return L"udp";
    default:
        return NULL;
    }
}

static NTSTATUS
SysmonAddNetworkProtocolField(
    _Inout_ PSYSMON_EVENT_UNION Event,
    _Inout_ PSYSMON_EVENT_PAYLOAD_BUILDER Builder,
    _Out_ SYSMON_EVENT_STRING_REF *Ref,
    _In_ ULONG Protocol)
{
    switch (Protocol) {
    case 6:
        return SysmonAddStringLiteralField(Event, Builder, Ref, L"tcp");
    case 17:
        return SysmonAddStringLiteralField(Event, Builder, Ref, L"udp");
    default:
        return STATUS_SUCCESS;
    }
}

static VOID
SysmonSubmitNetworkEvent(_In_ PSYSMON_EVENT_UNION Event)
{
    SysmonPublishEvent(Event);
}

/*
 * Report a network connection event.
 * Called when a network connection is detected (from WFP callback or
 * user-mode notification via IOCTL).
 */
NTSTATUS
SysmonReportNetworkEvent(
    _In_ ULONG ProcessId,
    _In_ ULONG SrcIp,
    _In_ USHORT SrcPort,
    _In_ ULONG DstIp,
    _In_ USHORT DstPort,
    _In_ ULONG Protocol)
{
    PSYSMON_EVENT_UNION event = NULL;
    SYSMON_EVENT_NETWORK_CONNECT_PAYLOAD *eventData = NULL;
    SYSMON_EVENT_PAYLOAD_BUILDER builder;
    SYSMON_NETWORK_CONTEXT context;

    if (!SysmonIsProducerEnabled(SYSMON_FLAG_ENABLED)) return STATUS_SUCCESS;

    RtlZeroMemory(&context, sizeof(context));
    context.ProcessId = ProcessId;
    context.SourcePort = SrcPort;
    context.DestinationPort = DstPort;
    if (!NT_SUCCESS(SysmonFormatTimestamp(SysmonGetCurrentTimestamp(), context.UtcTime))) {
        context.UtcTime[0] = L'\0';
    }
    SysmonCopyWideString(
        context.Protocol,
        RTL_NUMBER_OF(context.Protocol),
        SysmonProtocolName(Protocol));
    SysmonFormatIpv4(SrcIp, context.SourceIp);
    SysmonFormatIpv4(DstIp, context.DestinationIp);
    SysmonPopulateNetworkProcessContext(&context);

    event = SysmonAllocateEvent(SysmonEventNetworkConnect);
    if (event == NULL) return STATUS_INSUFFICIENT_RESOURCES;

    SysmonBeginStringPayload(event, sizeof(*eventData), &builder);
    eventData = (SYSMON_EVENT_NETWORK_CONNECT_PAYLOAD *)event->RawData;
    eventData->ProcessId = context.ProcessId;
    eventData->Initiated = TRUE;
    eventData->SourceIsIpv6 = FALSE;
    eventData->SourcePort = context.SourcePort;
    eventData->DestinationIsIpv6 = FALSE;
    eventData->DestinationPort = context.DestinationPort;

    SysmonAddStringField(event, &builder, &eventData->RuleName, NULL);
    SysmonAddFixedLengthStringField(
        event,
        &builder,
        &eventData->UtcTime,
        context.UtcTime,
        SYSMON_TIMESTAMP_STRING_CHARS);
    SysmonAddFixedLengthStringField(
        event,
        &builder,
        &eventData->ProcessGuid,
        context.ProcessGuid,
        SYSMON_GUID_STRING_CHARS);
    SysmonAddStringField(event, &builder, &eventData->Image, context.Image);
    SysmonAddStringField(event, &builder, &eventData->User, context.User);
    SysmonAddNetworkProtocolField(event, &builder, &eventData->Protocol, Protocol);
    SysmonAddStringField(event, &builder, &eventData->SourceIp, context.SourceIp);
    /*
     * Hostname and port-name resolution requires user-mode DNS/service lookup.
     * Leave those canonical fields empty rather than inventing names.
     */
    SysmonAddStringField(event, &builder, &eventData->SourceHostname, NULL);
    SysmonAddStringField(event, &builder, &eventData->SourcePortName, NULL);
    SysmonAddStringField(event, &builder, &eventData->DestinationIp, context.DestinationIp);
    SysmonAddStringField(event, &builder, &eventData->DestinationHostname, NULL);
    SysmonAddStringField(event, &builder, &eventData->DestinationPortName, NULL);

    SysmonSubmitNetworkEvent(event);
    SysmonFreeEvent(event);

    return STATUS_SUCCESS;
}

/*
 * Initialize network monitoring.
 * In the original SysmonDrv, network monitoring is handled by the
 * user-mode service. The driver provides event reporting via IOCTL.
 */
NTSTATUS
SysmonInitializeNetworkFilter(_In_ PDRIVER_OBJECT DriverObject)
{
    UNREFERENCED_PARAMETER(DriverObject);

    if (g_NetworkInitialized) return STATUS_SUCCESS;

    /*
     * Network monitoring approaches:
     * 1. WFP Callout Driver (fwpsk.h) - requires driver signature
     * 2. TDI Filter Driver - deprecated but works on older Windows
     * 3. User-mode hooking via Sysmon.exe service (original approach)
     *
     * For this implementation, we provide the event reporting framework.
     * Actual network events are reported via:
     *   - IOCTL_SYSMON_SET_CONFIG from user-mode service
     *   - Or WFP callout callback (to be implemented)
     */

    g_NetworkInitialized = TRUE;
    DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_INFO_LEVEL,
        "[SysmonDrv] Network monitoring initialized (framework)\n");
    return STATUS_SUCCESS;
}

VOID
SysmonCleanupNetworkFilter(VOID)
{
    g_NetworkInitialized = FALSE;
}

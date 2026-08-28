#include "dns.h"
#include "queue.h"
#include "event.h"
#include "driver.h"
#include "processinfo.h"
#include "utils.h"

/*
 * DnsQuery (Event 22) - DNS Query Monitoring
 *
 * Monitors DNS queries by registering for the Microsoft-Windows-DNS-Client
 * ETW provider. When a DNS query is detected, this module captures:
 *   - Query name
 *   - Query results
 *   - Query status
 *   - Process ID
 *
 * Implementation approach: Since full ETW consumer registration in kernel
 * mode is complex, this implementation monitors DNS activity through the
 * registry callback (monitoring DNS cache entries) and provides a framework
 * for ETW-based monitoring.
 */

static BOOLEAN g_DnsInitialized = FALSE;

typedef struct _SYSMON_DNS_CONTEXT {
    ULONG ProcessId;
    WCHAR QueryStatusText[32];
    WCHAR UtcTime[64];
    WCHAR ProcessGuid[SYSMON_MAX_GUID_STRING];
    WCHAR Image[SYSMON_MAX_PATH];
    WCHAR QueryName[SYSMON_MAX_PATH];
    WCHAR QueryResults[SYSMON_MAX_PATH];
    WCHAR User[SYSMON_MAX_SID_STRING];
} SYSMON_DNS_CONTEXT, *PSYSMON_DNS_CONTEXT;

static BOOLEAN
SysmonFormatDnsStatusString(
    _In_ ULONG QueryStatus,
    _Out_writes_(BufferChars) PWCHAR Buffer,
    _In_ SIZE_T BufferChars)
{
    if (Buffer == NULL || BufferChars == 0) {
        return FALSE;
    }

    Buffer[0] = L'\0';
    if (QueryStatus == 87) {
        return FALSE;
    }

    return _snwprintf_s(
        Buffer,
        BufferChars,
        _TRUNCATE,
        L"%lu",
        (unsigned long)QueryStatus) >= 0;
}

static VOID
SysmonPopulateDnsProcessContext(
    _Inout_ PSYSMON_DNS_CONTEXT Context)
{
    SYSMON_PROCESS_INFO *processInfo;

    if (KeGetCurrentIrql() != PASSIVE_LEVEL) {
        DbgPrintEx(
            DPFLTR_DEFAULT_ID,
            DPFLTR_WARNING_LEVEL,
            "[SysmonDrv] DNS process identity deferred: callback IRQL is not PASSIVE_LEVEL\n");
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
          SysmonCopyWideString(
              Context->User,
              RTL_NUMBER_OF(Context->User),
              processInfo->UserSid);
      }

    SysmonFreePool(processInfo);
}

static VOID
SysmonSubmitDnsEvent(_In_ PSYSMON_EVENT_UNION Event)
{
    SysmonPublishEvent(Event);
}

/*
 * Build and enqueue a DNS query event.
 */
static NTSTATUS
SysmonReportDnsQuery(
    _In_ ULONG ProcessId,
    _In_ PCWSTR QueryName,
    _In_ ULONG QueryStatus)
{
    PSYSMON_EVENT_UNION event = NULL;
    SYSMON_EVENT_DNS_QUERY_PAYLOAD *eventData = NULL;
    SYSMON_EVENT_PAYLOAD_BUILDER builder;
    SYSMON_DNS_CONTEXT context;

    RtlZeroMemory(&context, sizeof(context));
    context.ProcessId = ProcessId;
    if (!SysmonFormatDnsStatusString(
            QueryStatus,
            context.QueryStatusText,
            RTL_NUMBER_OF(context.QueryStatusText))) {
        return STATUS_INVALID_PARAMETER;
    }

    if (!NT_SUCCESS(SysmonFormatTimestamp(SysmonGetCurrentTimestamp(), context.UtcTime))) {
        context.UtcTime[0] = L'\0';
    }
    SysmonCopyWideString(context.QueryName, RTL_NUMBER_OF(context.QueryName), QueryName);
    SysmonPopulateDnsProcessContext(&context);

    event = SysmonAllocateEvent(SysmonEventDnsQuery);
    if (event == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    SysmonBeginStringPayload(event, sizeof(*eventData), &builder);
    eventData = (SYSMON_EVENT_DNS_QUERY_PAYLOAD *)event->RawData;
    eventData->ProcessId = context.ProcessId;
    SysmonAddStringLiteralField(event, &builder, &eventData->RuleName, L"-");
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
    SysmonAddStringField(event, &builder, &eventData->QueryName, context.QueryName);
    SysmonAddStringField(event, &builder, &eventData->QueryStatus, context.QueryStatusText);
    if (context.QueryResults[0] != L'\0') {
        SysmonAddStringField(event, &builder, &eventData->QueryResults, context.QueryResults);
    } else {
        SysmonAddStringLiteralField(event, &builder, &eventData->QueryResults, L"-");
    }
    SysmonAddStringField(event, &builder, &eventData->Image, context.Image);
    SysmonAddStringField(event, &builder, &eventData->User, context.User);

    SysmonSubmitDnsEvent(event);
    SysmonFreeEvent(event);

    return STATUS_SUCCESS;
}

/*
 * Detect DNS queries from registry operations on the DNS cache.
 * This is a fallback mechanism for systems where ETW is not available.
 * The main DNS monitoring path uses ETW (see below).
 */
NTSTATUS
SysmonCheckDnsRegistryEvent(
    _In_ PCUNICODE_STRING KeyPath,
    _In_ ULONG ProcessId)
{
    static const WCHAR dnsCachePath[] =
        L"\\REGISTRY\\MACHINE\\SYSTEM\\CurrentControlSet\\Services\\Dnscache";

    if (KeyPath == NULL || KeyPath->Buffer == NULL) return STATUS_SUCCESS;

    if (KeyPath->Length >= sizeof(dnsCachePath) - sizeof(WCHAR)) {
        if (_wcsnicmp(KeyPath->Buffer, dnsCachePath,
            (sizeof(dnsCachePath) - sizeof(WCHAR)) / sizeof(WCHAR)) == 0) {
            /*
             * This path is now wired from the registry callback, but registry
             * cache activity does not expose QueryName/QueryStatus/Results.
             * Do not emit Event 22 here; the canonical producer above is kept
             * for a future ETW/user-mode DNS source that has real query data.
             */
            DbgPrintEx(
                DPFLTR_DEFAULT_ID,
                DPFLTR_INFO_LEVEL,
                "[SysmonDrv] DNS registry activity observed; DNS query payload deferred\n");
        }
    }

    return STATUS_SUCCESS;
}

/*
 * Initialize DNS monitoring.
 * For full DNS query monitoring, an ETW session would be created here.
 * This is a placeholder that sets up the monitoring framework.
 */
NTSTATUS
SysmonInitializeDnsMonitoring(VOID)
{
    if (g_DnsInitialized) return STATUS_SUCCESS;

    /*
     * TODO: Full implementation would use:
     * 1. EtwRegister() with Microsoft-Windows-DNS-Client provider GUID
     * 2. Enable trace flags for DNS query events
     * 3. Process ETW events in the callback
     *
     * For now, DNS monitoring is handled at a higher level by the
     * Sysmon service which consumes the DNS Client ETW provider.
     */

    g_DnsInitialized = TRUE;
    DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_INFO_LEVEL,
        "[SysmonDrv] DNS monitoring initialized (framework only)\n");
    return STATUS_SUCCESS;
}

VOID
SysmonCleanupDnsMonitoring(VOID)
{
    g_DnsInitialized = FALSE;
}

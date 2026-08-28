#include "clipboard.h"
#include "queue.h"
#include "event.h"
#include "driver.h"
#include "processinfo.h"
#include "utils.h"

/*
 * ClipboardChange (Event 24) - Clipboard Monitoring
 *
 * Monitors clipboard content changes. In the original Sysmon driver,
 * this is handled via a special queue (like event 4) that uses a
 * dedicated IOCTL for clipboard events.
 *
 * Implementation approach:
 * The driver monitors clipboard operations through the
 * minifilter by detecting IRP_MJ_WRITE operations on the clipboard
 * device, or through user-mode notification.
 *
 * NOTE: Full clipboard monitoring in kernel mode is complex and
 * typically requires cooperation with a user-mode component.
 * This implementation provides the framework.
 */

static BOOLEAN g_ClipboardInitialized = FALSE;

typedef struct _SYSMON_CLIPBOARD_CONTEXT {
    ULONG ProcessId;
    ULONG Session;
    WCHAR UtcTime[64];
    WCHAR ProcessGuid[SYSMON_MAX_GUID_STRING];
    WCHAR User[SYSMON_MAX_SID_STRING];
    WCHAR Image[SYSMON_MAX_PATH];
} SYSMON_CLIPBOARD_CONTEXT, *PSYSMON_CLIPBOARD_CONTEXT;

static VOID
SysmonPopulateClipboardProcessContext(
    _Inout_ PSYSMON_CLIPBOARD_CONTEXT Context)
{
    SYSMON_PROCESS_INFO *processInfo;

    if (KeGetCurrentIrql() != PASSIVE_LEVEL) {
        DbgPrintEx(
            DPFLTR_DEFAULT_ID,
            DPFLTR_WARNING_LEVEL,
            "[SysmonDrv] Clipboard process identity deferred: callback IRQL is not PASSIVE_LEVEL\n");
        return;
    }

    processInfo = (SYSMON_PROCESS_INFO *)SysmonAllocatePool(sizeof(SYSMON_PROCESS_INFO));
    if (processInfo == NULL) {
        return;
    }

    if (NT_SUCCESS(SysmonCollectProcessInfo(
            (HANDLE)(ULONG_PTR)Context->ProcessId,
            processInfo))) {
        Context->Session = processInfo->SessionId;
        SysmonCopyWideStringWithLength(
            Context->ProcessGuid,
            RTL_NUMBER_OF(Context->ProcessGuid),
            processInfo->ProcessGuid,
            SYSMON_GUID_STRING_CHARS);
        SysmonCopyWideString(
            Context->User,
            RTL_NUMBER_OF(Context->User),
            processInfo->UserSid);
        SysmonCopyWideString(
            Context->Image,
            RTL_NUMBER_OF(Context->Image),
            processInfo->ImagePath);
    }

    SysmonFreePool(processInfo);
}

static VOID
SysmonSubmitClipboardEvent(_In_ PSYSMON_EVENT_UNION Event)
{
    SysmonPublishEvent(Event);
}

/*
 * Build and enqueue a clipboard event.
 */
NTSTATUS
SysmonReportClipboardEvent(
    _In_ ULONG ProcessId,
    _In_opt_ PCWSTR ClipboardContent)
{
    PSYSMON_EVENT_UNION event = NULL;
    SYSMON_EVENT_CLIPBOARD_CHANGE_PAYLOAD *eventData = NULL;
    SYSMON_EVENT_PAYLOAD_BUILDER builder;
    SYSMON_CLIPBOARD_CONTEXT context;

    UNREFERENCED_PARAMETER(ClipboardContent);

    RtlZeroMemory(&context, sizeof(context));
    context.ProcessId = ProcessId;
    if (!NT_SUCCESS(SysmonFormatTimestamp(SysmonGetCurrentTimestamp(), context.UtcTime))) {
        context.UtcTime[0] = L'\0';
    }
    SysmonPopulateClipboardProcessContext(&context);

    event = SysmonAllocateEvent(SysmonEventClipboardChange);
    if (event == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    SysmonBeginStringPayload(event, sizeof(*eventData), &builder);
    eventData = (SYSMON_EVENT_CLIPBOARD_CHANGE_PAYLOAD *)event->RawData;
    eventData->ProcessId = context.ProcessId;
    eventData->Session = context.Session;
    /*
     * The current helper receives optional content but canonical Event 24 has
     * no raw-content field. Hash/archive/executable classification requires a
     * real clipboard archive path, so those fields remain honest defaults.
     */
    eventData->Archived = FALSE;
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
    SysmonAddStringField(event, &builder, &eventData->ClientInfo, NULL);
    SysmonAddStringField(event, &builder, &eventData->Hashes, NULL);
    SysmonAddStringField(event, &builder, &eventData->User, context.User);

    SysmonSubmitClipboardEvent(event);
    SysmonFreeEvent(event);

    return STATUS_SUCCESS;
}

/*
 * Initialize clipboard monitoring.
 */
NTSTATUS
SysmonInitializeClipboardMonitoring(VOID)
{
    if (g_ClipboardInitialized) return STATUS_SUCCESS;

    /*
     * Clipboard monitoring in the original Sysmon driver is done via:
     * 1. Monitoring user-mode window messages (WM_CLIPBOARDUPDATE)
     * 2. Or via a dedicated IOCTL channel with the Sysmon service
     *
     * Kernel-only capture remains a framework: no producer currently calls
     * SysmonReportClipboardEvent with trustworthy ClientInfo/archive data.
     */

    g_ClipboardInitialized = TRUE;
    DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_INFO_LEVEL,
        "[SysmonDrv] Clipboard monitoring initialized\n");
    return STATUS_SUCCESS;
}

VOID
SysmonCleanupClipboardMonitoring(VOID)
{
    g_ClipboardInitialized = FALSE;
}

#include "communication.h"
#include "queue.h"
#include "event.h"
#include "driver.h"
#include "process.h"
#include "processinfo.h"

typedef struct _SYSMON_PENDING_QUERY {
    LIST_ENTRY ListEntry;
    ULONG RequestId;
    KEVENT CompletionEvent;
    ULONG ResultCode;
    UCHAR HasExtendedBlob;
    BOOLEAN Completed;
    BOOLEAN Linked;
} SYSMON_PENDING_QUERY, *PSYSMON_PENDING_QUERY;

static volatile LONG g_GenericFilterEvaluatedCount = 0;
static volatile LONG g_GenericFilterDroppedCount = 0;
static volatile LONG g_LastEvaluatedEventId = 0;
static volatile LONG g_LastDroppedEventId = 0;
static FAST_MUTEX g_PendingQueryLock;
static LIST_ENTRY g_PendingQueryList;
static volatile LONG g_NextQueryRequestId = 0;

#define SYSMON_QUERY_WAIT_TIMEOUT_SECONDS 2

static PDEVICE_EXTENSION
SysmonGetActiveDeviceExtension(VOID)
{
    PDEVICE_OBJECT deviceObject;

    deviceObject = g_Context.DeviceObject;
    if (deviceObject == NULL) {
        return NULL;
    }

    return (PDEVICE_EXTENSION)deviceObject->DeviceExtension;
}

/* Atomically claim-or-check the single consumer file object for a queue. The
   first caller claims ownership; any subsequent caller from a different file
   object is rejected. Applies to both the synchronous dequeue path and the
   pending-IRP path so a second handle can never drain queued events/queries. */
static BOOLEAN
SysmonTryAcquireQueueConsumer(
    _In_ PKSPIN_LOCK Lock,
    _Inout_ PFILE_OBJECT *Consumer,
    _In_ PFILE_OBJECT FileObject)
{
    KIRQL oldIrql;
    BOOLEAN allowed;

    if (Lock == NULL || Consumer == NULL || FileObject == NULL) {
        return FALSE;
    }

    KeAcquireSpinLock(Lock, &oldIrql);
    if (*Consumer == NULL) {
        *Consumer = FileObject;
        allowed = TRUE;
    } else {
        allowed = (*Consumer == FileObject);
    }
    KeReleaseSpinLock(Lock, oldIrql);

    return allowed;
}

static VOID
SysmonCompleteRemovedIrp(
    _In_ PIRP Irp,
    _In_ NTSTATUS Status);

static VOID
SysmonCompleteRemovedIrp(
    _In_ PIRP Irp,
    _In_ NTSTATUS Status)
{
    if (Irp == NULL) {
        return;
    }

    Irp->IoStatus.Status = Status;
    Irp->IoStatus.Information = 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
}

static VOID
SysmonCancelPendingIrpsInternal(
    _In_opt_ PFILE_OBJECT FileObject,
    _In_ PSYSMON_IRP_CSQ_QUEUE Queue,
    _In_ NTSTATUS Status)
{
    PIRP pendingIrp;

    if (Queue == NULL) {
        return;
    }

    for (;;) {
        pendingIrp = IoCsqRemoveNextIrp(&Queue->Csq, FileObject);
        if (pendingIrp == NULL) {
            break;
        }

        SysmonCompleteRemovedIrp(pendingIrp, Status);
    }
}

NTSTATUS
SysmonPublishEventWithFilterState(
    _In_ PSYSMON_EVENT_UNION Event,
    _Out_opt_ PBOOLEAN FilteredOut)
{
    NTSTATUS status;
    PSYSMON_RULE_RUNTIME runtime = NULL;
    BOOLEAN shouldCapture = TRUE;
    BOOLEAN deferToUserMode = FALSE;

    if (FilteredOut != NULL) {
        *FilteredOut = FALSE;
    }

    if (Event == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    if (InterlockedCompareExchange(&g_Context.CapturePaused, 0, 0) != 0) {
        if (FilteredOut != NULL) {
            *FilteredOut = TRUE;
        }
        return STATUS_SUCCESS;
    }

    if (!SysmonAcquireDriverRundown()) {
        return STATUS_DELETE_PENDING;
    }

    runtime = SysmonAcquireRuleRuntimeSnapshot();
    deferToUserMode = SysmonEventFilterRequiresUserModeEnrichment(
        runtime,
        (SYSMON_EVENT_ID)Event->Header.EventId);
    if (!deferToUserMode) {
        InterlockedIncrement(&g_GenericFilterEvaluatedCount);
        InterlockedExchange(&g_LastEvaluatedEventId, (LONG)Event->Header.EventId);
        shouldCapture = SysmonShouldCaptureEvent(
            runtime,
            (SYSMON_EVENT_ID)Event->Header.EventId,
            Event);
    }
    SysmonReleaseRuleRuntimeSnapshot(runtime);
    if (!shouldCapture) {
        InterlockedIncrement(&g_GenericFilterDroppedCount);
        InterlockedExchange(&g_LastDroppedEventId, (LONG)Event->Header.EventId);
        if (FilteredOut != NULL) {
            *FilteredOut = TRUE;
        }
        SYSMON_HOTPATH_LOG(
            DPFLTR_INFO_LEVEL,
            "[SysmonDrv] Event %lu filtered before publish\n",
            Event->Header.EventId);
        SysmonReleaseDriverRundown();
        return STATUS_SUCCESS;
    }

    if (deferToUserMode) {
        SYSMON_HOTPATH_LOG(
            DPFLTR_INFO_LEVEL,
            "[SysmonDrv] Event %lu deferred to user-mode enrichment filter\n",
            Event->Header.EventId);
    }

    if (SysmonCompletePendingEventIrp(Event)) {
        status = STATUS_SUCCESS;
    } else {
        status = SysmonEnqueueEvent(Event);
    }

    SysmonReleaseDriverRundown();

    return status;
}

NTSTATUS
SysmonPublishEvent(_In_ PSYSMON_EVENT_UNION Event)
{
    return SysmonPublishEventWithFilterState(Event, NULL);
}

NTSTATUS
SysmonPendGetEventIrp(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ PIRP Irp)
{
    PDEVICE_EXTENSION ext;
    NTSTATUS status;
    PFILE_OBJECT fileObject;

    if (DeviceObject == NULL || Irp == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    if (!SysmonAcquireDriverRundown()) {
        return STATUS_DELETE_PENDING;
    }

    ext = (PDEVICE_EXTENSION)DeviceObject->DeviceExtension;
    if (ext == NULL) {
        status = STATUS_INVALID_DEVICE_STATE;
    } else {
        fileObject = IoGetCurrentIrpStackLocation(Irp)->FileObject;

        /* Enforce a single event consumer (K1): applies to the pending path and
           the synchronous dequeue path (SysmonHandleGetEvent) alike. Return only
           the error status: SysmonDeviceControl completes the IRP, so completing
           here would double-complete it. */
        if (!SysmonTryAcquireQueueConsumer(
                &ext->EventQueue.Lock,
                &ext->EventConsumerFileObject,
                fileObject)) {
            SysmonReleaseDriverRundown();
            return STATUS_ACCESS_DENIED;
        }

        IoMarkIrpPending(Irp);
        status = IoCsqInsertIrpEx(&ext->EventQueue.Csq, Irp, NULL, FALSE);
        if (NT_SUCCESS(status)) {
            status = STATUS_PENDING;
        }
    }

    SysmonReleaseDriverRundown();

    return status;
}

NTSTATUS
SysmonPendGetQueryIrp(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ PIRP Irp)
{
    PDEVICE_EXTENSION ext;
    NTSTATUS status;

    if (DeviceObject == NULL || Irp == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    if (!SysmonAcquireDriverRundown()) {
        return STATUS_DELETE_PENDING;
    }

    ext = (PDEVICE_EXTENSION)DeviceObject->DeviceExtension;
    if (ext == NULL) {
        status = STATUS_INVALID_DEVICE_STATE;
    } else {
        PFILE_OBJECT fileObject = IoGetCurrentIrpStackLocation(Irp)->FileObject;

        /* Enforce a single query consumer, mirroring the event queue. The
           service's query workers all share one handle, so this does not reject
           concurrent GET_QUERY IRPs from the same client. Return only the error
           status: SysmonDeviceControl completes the IRP. */
        if (!SysmonTryAcquireQueueConsumer(
                &ext->QueryQueue.Lock,
                &ext->QueryConsumerFileObject,
                fileObject)) {
            SysmonReleaseDriverRundown();
            return STATUS_ACCESS_DENIED;
        }

        IoMarkIrpPending(Irp);
        status = IoCsqInsertIrpEx(&ext->QueryQueue.Csq, Irp, NULL, TRUE);
        if (NT_SUCCESS(status)) {
            status = STATUS_PENDING;
        }
    }

    SysmonReleaseDriverRundown();

    return status;
}

VOID
SysmonCancelPendingIrpsForFileObject(
    _In_opt_ PFILE_OBJECT FileObject,
    _In_ NTSTATUS Status)
{
    PDEVICE_EXTENSION ext;

    if (!SysmonAcquireDriverRundown()) {
        return;
    }

    ext = SysmonGetActiveDeviceExtension();
    if (ext != NULL) {
        SysmonCancelPendingIrpsInternal(FileObject, &ext->EventQueue, Status);
        SysmonCancelPendingIrpsInternal(FileObject, &ext->QueryQueue, Status);

        if (FileObject != NULL && ext->EventConsumerFileObject == FileObject) {
            KIRQL oldIrql;

            KeAcquireSpinLock(&ext->EventQueue.Lock, &oldIrql);
            if (ext->EventConsumerFileObject == FileObject) {
                ext->EventConsumerFileObject = NULL;
            }
            KeReleaseSpinLock(&ext->EventQueue.Lock, oldIrql);
        }
        if (FileObject != NULL && ext->QueryConsumerFileObject == FileObject) {
            KIRQL oldIrql;

            KeAcquireSpinLock(&ext->QueryQueue.Lock, &oldIrql);
            if (ext->QueryConsumerFileObject == FileObject) {
                ext->QueryConsumerFileObject = NULL;
            }
            KeReleaseSpinLock(&ext->QueryQueue.Lock, oldIrql);
        }
    }
    SysmonReleaseDriverRundown();
}

VOID
SysmonDrainPendingEventIrps(_In_ NTSTATUS Status)
{
    PDEVICE_EXTENSION ext;

    ext = SysmonGetActiveDeviceExtension();
    if (ext != NULL) {
        KIRQL oldIrql;

        SysmonCancelPendingIrpsInternal(NULL, &ext->EventQueue, Status);
        KeAcquireSpinLock(&ext->EventQueue.Lock, &oldIrql);
        ext->EventConsumerFileObject = NULL;
        KeReleaseSpinLock(&ext->EventQueue.Lock, oldIrql);
    }
}

VOID
SysmonDrainPendingQueryIrps(_In_ NTSTATUS Status)
{
    PDEVICE_EXTENSION ext;

    ext = SysmonGetActiveDeviceExtension();
    if (ext != NULL) {
        KIRQL oldIrql;

        SysmonCancelPendingIrpsInternal(NULL, &ext->QueryQueue, Status);
        KeAcquireSpinLock(&ext->QueryQueue.Lock, &oldIrql);
        ext->QueryConsumerFileObject = NULL;
        KeReleaseSpinLock(&ext->QueryQueue.Lock, oldIrql);
    }
}

/* ========================================================================
 * CSQ Callbacks (unchanged)
 * ======================================================================== */

NTSTATUS NTAPI
SysmonCsqInsertIrp(
    _In_ PIO_CSQ Csq,
    _In_ PIRP Irp,
    _In_opt_ PVOID InsertContext)
{
    PSYSMON_IRP_CSQ_QUEUE queue = CONTAINING_RECORD(Csq, SYSMON_IRP_CSQ_QUEUE, Csq);
    UNREFERENCED_PARAMETER(InsertContext);
    InsertTailList(&queue->PendingIrpList, &Irp->Tail.Overlay.ListEntry);
    return STATUS_SUCCESS;
}

VOID NTAPI
SysmonCsqRemoveIrp(_In_ PIO_CSQ Csq, _In_ PIRP Irp)
{
    UNREFERENCED_PARAMETER(Csq);
    RemoveEntryList(&Irp->Tail.Overlay.ListEntry);
}

PIRP NTAPI
SysmonCsqPeekNextIrp(
    _In_ PIO_CSQ Csq,
    _In_opt_ PIRP Irp,
    _In_opt_ PVOID PeekContext)
{
    PSYSMON_IRP_CSQ_QUEUE queue = CONTAINING_RECORD(Csq, SYSMON_IRP_CSQ_QUEUE, Csq);
    PLIST_ENTRY entry;
    PIRP nextIrp = NULL;

    if (Irp == NULL) {
        entry = queue->PendingIrpList.Flink;
    } else {
        entry = Irp->Tail.Overlay.ListEntry.Flink;
    }

    while (entry != &queue->PendingIrpList) {
        nextIrp = CONTAINING_RECORD(entry, IRP, Tail.Overlay.ListEntry);
        if (PeekContext == NULL ||
            IoGetCurrentIrpStackLocation(nextIrp)->FileObject == (PFILE_OBJECT)PeekContext) {
            return nextIrp;
        }

        entry = nextIrp->Tail.Overlay.ListEntry.Flink;
    }

    return NULL;
}

VOID NTAPI
SysmonCsqAcquireLock(_In_ PIO_CSQ Csq, _Out_ PKIRQL Irql)
{
    PSYSMON_IRP_CSQ_QUEUE queue = CONTAINING_RECORD(Csq, SYSMON_IRP_CSQ_QUEUE, Csq);
    KeAcquireSpinLock(&queue->Lock, Irql);
}

VOID NTAPI
SysmonCsqReleaseLock(_In_ PIO_CSQ Csq, _In_ KIRQL Irql)
{
    PSYSMON_IRP_CSQ_QUEUE queue = CONTAINING_RECORD(Csq, SYSMON_IRP_CSQ_QUEUE, Csq);
    KeReleaseSpinLock(&queue->Lock, Irql);
}

VOID NTAPI
SysmonCsqCompleteCanceledIrp(_In_ PIO_CSQ Csq, _In_ PIRP Irp)
{
    UNREFERENCED_PARAMETER(Csq);
    Irp->IoStatus.Status = STATUS_CANCELLED;
    Irp->IoStatus.Information = 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
}

/* ========================================================================
 * CSQ Initialization
 * ======================================================================== */

NTSTATUS
SysmonInitializeCsq(_In_ PDEVICE_OBJECT DeviceObject)
{
    NTSTATUS status;
    PDEVICE_EXTENSION ext;
    PSYSMON_IRP_CSQ_QUEUE queue;

    if (DeviceObject == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    ext = (PDEVICE_EXTENSION)DeviceObject->DeviceExtension;
    if (ext == NULL) {
        return STATUS_INVALID_DEVICE_STATE;
    }

    RtlZeroMemory(ext, sizeof(*ext));
    ExInitializeFastMutex(&g_PendingQueryLock);
    InitializeListHead(&g_PendingQueryList);

    queue = &ext->EventQueue;
    InitializeListHead(&queue->PendingIrpList);
    KeInitializeSpinLock(&queue->Lock);
    status = IoCsqInitializeEx(
        &queue->Csq,
        SysmonCsqInsertIrp,
        SysmonCsqRemoveIrp,
        SysmonCsqPeekNextIrp,
        SysmonCsqAcquireLock,
        SysmonCsqReleaseLock,
        SysmonCsqCompleteCanceledIrp
    );
    if (!NT_SUCCESS(status)) {
        return status;
    }

    queue = &ext->QueryQueue;
    InitializeListHead(&queue->PendingIrpList);
    KeInitializeSpinLock(&queue->Lock);
    status = IoCsqInitializeEx(
        &queue->Csq,
        SysmonCsqInsertIrp,
        SysmonCsqRemoveIrp,
        SysmonCsqPeekNextIrp,
        SysmonCsqAcquireLock,
        SysmonCsqReleaseLock,
        SysmonCsqCompleteCanceledIrp
    );

    return status;
}

/* ========================================================================
 * IOCTL Handlers
 * ======================================================================== */

/*
 * SysmonHandleInit - INIT handshake (0x83400000)
 *
 * Original: user sends 4 bytes (version/mode) to driver
 *   Input: DWORD version/mode (e.g. 0x5f0)
 *   Output: None
 *
 * Stores the version info and returns success.
 */
NTSTATUS
SysmonHandleInit(_In_ PIRP Irp, _In_ ULONG InputLength, _In_opt_ PVOID InputBuffer)
{
    UNREFERENCED_PARAMETER(Irp);

    if (InputBuffer == NULL || InputLength < sizeof(ULONG)) {
        return STATUS_INVALID_PARAMETER;
    }

    InterlockedExchange(&g_Context.CapturePaused, 0);

    /* Store the version/mode from user-mode */
    {
        ULONG clientVersion = *(PULONG)InputBuffer;
        DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_INFO_LEVEL,
            "[SysmonDrv] Init handshake: client version=0x%08X\n", clientVersion);
    }

    return STATUS_SUCCESS;
}

/*
 * SysmonHandleGetEvent - GET EVENT (0x83400004)
 *
 * Inserted into CSQ for pended completion.
 * When an event is available, SysmonCompletePendingEventIrp completes it.
 */
NTSTATUS
SysmonHandleGetEvent(_In_ PIRP Irp)
{
    /* This is handled by CSQ insertion in SysmonDeviceControl */
    /* This function handles the case where we try synchronous completion */
    PSYSMON_EVENT_NODE node;
    PVOID outputBuffer;
    ULONG outputLength;
    PIO_STACK_LOCATION irpSp = IoGetCurrentIrpStackLocation(Irp);

    outputBuffer = Irp->AssociatedIrp.SystemBuffer;
    outputLength = irpSp->Parameters.DeviceIoControl.OutputBufferLength;

    /* Single-consumer check applies to the synchronous dequeue path too, so a
       non-owner handle cannot drain already-queued events. */
    {
        PDEVICE_EXTENSION ext = SysmonGetActiveDeviceExtension();

        if (ext == NULL ||
            !SysmonTryAcquireQueueConsumer(
                &ext->EventQueue.Lock,
                &ext->EventConsumerFileObject,
                irpSp->FileObject)) {
            return STATUS_ACCESS_DENIED;
        }
    }

    node = SysmonDequeueEvent();
    if (node == NULL) {
        return STATUS_NO_MORE_ENTRIES;
    }

    if (node->EventSize >= sizeof(SYSMON_EVENT_HEADER)) {
        PSYSMON_EVENT_UNION event = (PSYSMON_EVENT_UNION)SYSMON_EVENT_NODE_DATA(node);
        DbgPrintEx(
            DPFLTR_DEFAULT_ID,
            DPFLTR_INFO_LEVEL,
            "[SysmonDrv] GetEvent dequeued id=%lu nodeSize=%lu headerSize=%lu out=%lu\n",
            event->Header.EventId,
            node->EventSize,
            event->Header.EventSize,
            outputLength);
    }

    if (outputLength < node->EventSize) {
        SysmonFreeEventNode(node);
        return STATUS_BUFFER_TOO_SMALL;
    }

    RtlCopyMemory(outputBuffer, SYSMON_EVENT_NODE_DATA(node), node->EventSize);
    Irp->IoStatus.Information = node->EventSize;
    SysmonFreeEventNode(node);

    return STATUS_SUCCESS;
}

/*
 * SysmonHandleConfigNotify - CONFIG NOTIFY (0x83400008)
 *
 * Original: user sends empty IOCTL to notify driver of config change
 *   Input: None
 *   Output: None
 *
 * Driver should reload its configuration from registry.
 */
NTSTATUS
SysmonHandleConfigNotify(_In_ PIRP Irp)
{
    NTSTATUS status;

    UNREFERENCED_PARAMETER(Irp);

    DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_INFO_LEVEL,
        "[SysmonDrv] Config notify received\n");

    if (!SysmonAcquireDriverRundown()) {
        return STATUS_DELETE_PENDING;
    }

    /*
     * Live config updates can arrive from the CLI and the service-side
     * monitor at nearly the same time. Serializing load+sync keeps monitor
     * teardown/re-registration from double-touching shared work-item state.
     */
    ExAcquireFastMutex(&g_Context.RegistrationLock);
    status = SysmonLoadConfiguration();
    if (NT_SUCCESS(status)) {
        status = SysmonSyncMonitoringRegistration();
    }
    ExReleaseFastMutex(&g_Context.RegistrationLock);

    if (NT_SUCCESS(status)) {
        DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_INFO_LEVEL,
            "[SysmonDrv] Config reload succeeded\n");
    } else {
        DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_WARNING_LEVEL,
            "[SysmonDrv] Config reload failed or synced with errors: 0x%08X\n", status);
    }

    SysmonReleaseDriverRundown();

    return status;
}

/*
 * SysmonHandleProcessCache - PROCESS CACHE REQUEST (0x8340000c)
 *
 * Original: user sends 8 bytes, gets 0x4002 bytes of process cache data
 *   Input: 8 bytes (process query parameters)
 *   Output: up to 0x4002 bytes of process cache data
 */
NTSTATUS
SysmonHandleProcessCache(
    _In_ PIRP Irp,
    _In_ ULONG InputLength,
    _In_opt_ PVOID InputBuffer,
    _In_ ULONG OutputLength,
    _Out_opt_ PVOID OutputBuffer)
{
    ULONG processId;
    PSYSMON_PROCESS_CACHE_RESPONSE response;
    SYSMON_PROCESS_CACHE_METADATA cachedMetadata;
    SYSMON_PROCESS_INFO processInfo;

    UNREFERENCED_PARAMETER(Irp);

    if (InputBuffer == NULL || InputLength < 8) {
        return STATUS_INVALID_PARAMETER;
    }

    if (OutputBuffer == NULL || OutputLength < sizeof(SYSMON_PROCESS_CACHE_RESPONSE)) {
        return STATUS_BUFFER_TOO_SMALL;
    }

    processId = *(ULONG *)InputBuffer;
    response = (PSYSMON_PROCESS_CACHE_RESPONSE)OutputBuffer;

    RtlZeroMemory(OutputBuffer, min(OutputLength, 0x4002));
    response->Signature = SYSMON_PROCESS_CACHE_SIGNATURE;
    response->Version = SYSMON_PROCESS_CACHE_VERSION;
    response->ProcessId = processId;

    RtlZeroMemory(&cachedMetadata, sizeof(cachedMetadata));
    if (SysmonLookupCachedProcessMetadata(processId, &cachedMetadata)) {
        response->CreateTime = cachedMetadata.CreateTime;
        SysmonCopyWideStringWithLength(response->ProcessGuid, RTL_NUMBER_OF(response->ProcessGuid), cachedMetadata.ProcessGuid, SYSMON_GUID_STRING_CHARS);
        SysmonCopyWideString(response->Image, RTL_NUMBER_OF(response->Image), cachedMetadata.Image);
        SysmonCopyWideString(response->UserSid, RTL_NUMBER_OF(response->UserSid), cachedMetadata.UserSid);
        return STATUS_SUCCESS;
    }

    RtlZeroMemory(&processInfo, sizeof(processInfo));
    if (NT_SUCCESS(SysmonCollectProcessInfo((HANDLE)(ULONG_PTR)processId, &processInfo))) {
        response->CreateTime = processInfo.CreateTime;
        SysmonCopyWideStringWithLength(response->ProcessGuid, RTL_NUMBER_OF(response->ProcessGuid), processInfo.ProcessGuid, SYSMON_GUID_STRING_CHARS);
        SysmonCopyWideString(response->Image, RTL_NUMBER_OF(response->Image), processInfo.ImagePath);
        SysmonCopyWideString(response->UserSid, RTL_NUMBER_OF(response->UserSid), processInfo.UserSid);
    }

    return STATUS_SUCCESS;
}

/*
 * SysmonHandleQueryAnswer - QUERY ANSWER (0x83400010)
 *
 * Original: user sends 0x60 byte structure with field/rule matching data
 *   Input: 0x60 bytes (query answer structure)
 *   Output: None
 */
NTSTATUS
SysmonHandleQueryAnswer(
    _In_ PIRP Irp,
    _In_ ULONG InputLength,
    _In_opt_ PVOID InputBuffer)
{
    PSYSMON_QUERY_ANSWER answer;
    PLIST_ENTRY entry;

    UNREFERENCED_PARAMETER(Irp);

    if (InputBuffer == NULL || InputLength < sizeof(SYSMON_QUERY_ANSWER)) {
        return STATUS_INVALID_PARAMETER;
    }

    answer = (PSYSMON_QUERY_ANSWER)InputBuffer;

    ExAcquireFastMutex(&g_PendingQueryLock);
    for (entry = g_PendingQueryList.Flink; entry != &g_PendingQueryList; entry = entry->Flink) {
        PSYSMON_PENDING_QUERY pending = CONTAINING_RECORD(entry, SYSMON_PENDING_QUERY, ListEntry);
        if (pending->RequestId != answer->RequestId) {
            continue;
        }

        pending->ResultCode = answer->ResultCode;
        pending->HasExtendedBlob = answer->HasExtendedBlob;
        pending->Completed = TRUE;
        if (pending->Linked) {
            RemoveEntryList(&pending->ListEntry);
            pending->Linked = FALSE;
        }
        KeSetEvent(&pending->CompletionEvent, IO_NO_INCREMENT, FALSE);
        ExReleaseFastMutex(&g_PendingQueryLock);
        return STATUS_SUCCESS;
    }
    ExReleaseFastMutex(&g_PendingQueryLock);

    DbgPrintEx(
        DPFLTR_DEFAULT_ID,
        DPFLTR_WARNING_LEVEL,
        "[SysmonDrv] Query answer for unknown request id=%lu\n",
        answer->RequestId);
    return STATUS_NOT_FOUND;
}

NTSTATUS
SysmonHandleGetQueryEvent(_In_ PIRP Irp)
{
    PSYSMON_EVENT_NODE node;
    PVOID outputBuffer;
    ULONG outputLength;
    PIO_STACK_LOCATION irpSp = IoGetCurrentIrpStackLocation(Irp);

    outputBuffer = Irp->AssociatedIrp.SystemBuffer;
    outputLength = irpSp->Parameters.DeviceIoControl.OutputBufferLength;

    /* Single-consumer check applies to the synchronous dequeue path too. */
    {
        PDEVICE_EXTENSION ext = SysmonGetActiveDeviceExtension();

        if (ext == NULL ||
            !SysmonTryAcquireQueueConsumer(
                &ext->QueryQueue.Lock,
                &ext->QueryConsumerFileObject,
                irpSp->FileObject)) {
            return STATUS_ACCESS_DENIED;
        }
    }

    node = SysmonDequeueQueryRecord();
    if (node == NULL) {
        return STATUS_NO_MORE_ENTRIES;
    }

    if (outputLength < node->EventSize) {
        SysmonFreeEventNode(node);
        return STATUS_BUFFER_TOO_SMALL;
    }

    RtlCopyMemory(outputBuffer, SYSMON_EVENT_NODE_DATA(node), node->EventSize);
    Irp->IoStatus.Information = node->EventSize;
    SysmonFreeEventNode(node);

    return STATUS_SUCCESS;
}

/*
 * SysmonHandleStop - STOP (0x83400014)
 *
 * Original: user sends empty IOCTL to stop communication
 *   Input: None
 *   Output: None
 *
 * Cancels all pending IRPs for this file object.
 */
NTSTATUS
SysmonHandleStop(_In_ PIRP Irp)
{
    PIO_STACK_LOCATION irpSp = IoGetCurrentIrpStackLocation(Irp);

    DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_INFO_LEVEL,
        "[SysmonDrv] Stop command received\n");

    /*
     * Match original STOP semantics: first quiesce capture so producers stop
     * feeding queues while user mode is disconnecting, then cancel any
     * pended IRPs on the caller's file object.
     */
    InterlockedExchange(&g_Context.CapturePaused, 1);

    /* Cancel all pending IRPs for this file object */
    SysmonCancelPendingIrpsForFileObject(irpSp->FileObject, STATUS_CANCELLED);

    return STATUS_SUCCESS;
}

/*
 * SysmonHandleGetStats - GET DEBUG STATS (0x8340001c, clone-only)
 *
 * Returns driver statistics. Uses overlapped IO.
 */
NTSTATUS
SysmonHandleGetStats(
    _In_ PIRP Irp,
    _In_ ULONG OutputLength,
    _Out_opt_ PVOID OutputBuffer)
{
    UNREFERENCED_PARAMETER(Irp);

    if (OutputBuffer == NULL || OutputLength == 0) {
        return STATUS_BUFFER_TOO_SMALL;
    }

    /* Return debug stats with the original callback count at offset 0. */
    RtlZeroMemory(OutputBuffer, OutputLength);
    if (OutputLength >= sizeof(SYSMON_PROCESS_DEBUG_STATS)) {
        PSYSMON_PROCESS_DEBUG_STATS stats = (PSYSMON_PROCESS_DEBUG_STATS)OutputBuffer;
        PSYSMON_RULE_RUNTIME runtime;

        SysmonQueryProcessDebugStats(stats);
        SysmonQueryMinifilterDebugStats(stats);
        SysmonQueryObDebugStats(stats);
        SysmonQueryThreadDebugStats(stats);
        SysmonQueryImageDebugStats(stats);
        SysmonQueryTamperingDebugStats(stats);
        SysmonQueryQueueDebugStats(stats);
        stats->GenericFilterEvaluatedCount = (ULONG)g_GenericFilterEvaluatedCount;
        stats->GenericFilterDroppedCount = (ULONG)g_GenericFilterDroppedCount;
        stats->LastEvaluatedEventId = (ULONG)g_LastEvaluatedEventId;
        stats->LastDroppedEventId = (ULONG)g_LastDroppedEventId;
        stats->ReloadGeneration = g_Context.ReloadGeneration;

        runtime = SysmonAcquireRuleRuntimeSnapshot();
        stats->ContextEnabled = SysmonIsProducerEnabled(SYSMON_FLAG_ENABLED) ? 1u : 0u;
        stats->ContextProcessNotifyEnabled = SysmonIsProducerEnabled(SYSMON_FLAG_PROCESS_NOTIFY) ? 1u : 0u;
        stats->ContextThreadNotifyEnabled = SysmonIsProducerEnabled(SYSMON_FLAG_THREAD_NOTIFY) ? 1u : 0u;
        stats->ContextProcessAccessNotifyEnabled = SysmonIsProducerEnabled(SYSMON_FLAG_PROCESS_ACCESS_NOTIFY) ? 1u : 0u;
        stats->StatsStructSize = sizeof(*stats);
        stats->StatsVersion = SYSMON_PROCESS_DEBUG_STATS_VERSION;
        if (runtime != NULL && runtime->Header != NULL) {
            stats->RuntimeGroupCount = runtime->Header->GroupCount;
            stats->RuntimeEventRuleCount = runtime->Header->EventRuleCount;
            if (runtime->Header->EventRuleCount != 0) {
                stats->RuntimeFirstEventId = runtime->EventRules[0].EventId;
                stats->RuntimeFirstRuleCount = runtime->EventRules[0].RuleCount;
                stats->RuntimeFirstMatchType = runtime->EventRules[0].MatchType;
            }
            stats->RuntimeHasProcessAccessEvent =
                SysmonRuleRuntimeEventCanProduceLogs(runtime, SysmonEventProcessAccess) ? 1u : 0u;
        }
        SysmonReleaseRuleRuntimeSnapshot(runtime);
    } else if (OutputLength >= sizeof(ULONG)) {
        PSYSMON_PROCESS_DEBUG_STATS stats = (PSYSMON_PROCESS_DEBUG_STATS)OutputBuffer;
        SYSMON_PROCESS_DEBUG_STATS localStats;
        SysmonQueryProcessDebugStats(&localStats);
        stats->ProcessCallbackCount = localStats.ProcessCallbackCount;
    }

    return STATUS_SUCCESS;
}

/* ========================================================================
 * Event Completion via CSQ
 * ======================================================================== */

BOOLEAN
SysmonCompletePendingEventIrp(_In_ PSYSMON_EVENT_UNION Event)
{
    PIRP irp;
    PDEVICE_EXTENSION ext;

    if (Event == NULL) {
        return FALSE;
    }

    ext = SysmonGetActiveDeviceExtension();
    if (ext == NULL) {
        return FALSE;
    }

    irp = IoCsqRemoveNextIrp(&ext->EventQueue.Csq, NULL);
    if (irp == NULL) {
        return FALSE;
    }

    {
        PVOID outputBuffer = irp->AssociatedIrp.SystemBuffer;
        PIO_STACK_LOCATION irpSp = IoGetCurrentIrpStackLocation(irp);
        ULONG outputLength = irpSp->Parameters.DeviceIoControl.OutputBufferLength;

        DbgPrintEx(
            DPFLTR_DEFAULT_ID,
            DPFLTR_INFO_LEVEL,
            "[SysmonDrv] CompletePending id=%lu headerSize=%lu out=%lu\n",
            Event->Header.EventId,
            Event->Header.EventSize,
            outputLength);

        if (outputLength >= Event->Header.EventSize) {
            RtlCopyMemory(outputBuffer, Event, Event->Header.EventSize);
            irp->IoStatus.Information = Event->Header.EventSize;
            irp->IoStatus.Status = STATUS_SUCCESS;
        } else {
            irp->IoStatus.Information = 0;
            irp->IoStatus.Status = STATUS_BUFFER_TOO_SMALL;
        }
    }

    IoCompleteRequest(irp, IO_NO_INCREMENT);
    return TRUE;
}

BOOLEAN
SysmonCompletePendingQueryIrp(
    _In_reads_bytes_(RecordSize) PVOID QueryRecord,
    _In_ ULONG RecordSize)
{
    PIRP irp;
    PDEVICE_EXTENSION ext;

    if (QueryRecord == NULL || RecordSize == 0) {
        return FALSE;
    }

    ext = SysmonGetActiveDeviceExtension();
    if (ext == NULL) {
        return FALSE;
    }

    irp = IoCsqRemoveNextIrp(&ext->QueryQueue.Csq, NULL);
    if (irp == NULL) {
        return FALSE;
    }

    {
        PVOID outputBuffer = irp->AssociatedIrp.SystemBuffer;
        PIO_STACK_LOCATION irpSp = IoGetCurrentIrpStackLocation(irp);
        ULONG outputLength = irpSp->Parameters.DeviceIoControl.OutputBufferLength;

        if (outputLength >= RecordSize) {
            RtlCopyMemory(outputBuffer, QueryRecord, RecordSize);
            irp->IoStatus.Information = RecordSize;
            irp->IoStatus.Status = STATUS_SUCCESS;
        } else {
            irp->IoStatus.Information = 0;
            irp->IoStatus.Status = STATUS_BUFFER_TOO_SMALL;
        }
    }

    IoCompleteRequest(irp, IO_NO_INCREMENT);
    return TRUE;
}

NTSTATUS
SysmonSubmitQueryRecordAndWait(
    _Inout_ PSYSMON_QUERY_RECORD QueryRecord,
    _Out_ PULONG ResultCode)
{
    SYSMON_PENDING_QUERY pending;
    LARGE_INTEGER timeout;
    NTSTATUS status;

    if (QueryRecord == NULL || ResultCode == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    if (KeGetCurrentIrql() > PASSIVE_LEVEL) {
        return STATUS_INVALID_DEVICE_STATE;
    }

    if (InterlockedCompareExchange(&g_Context.CapturePaused, 0, 0) != 0) {
        *ResultCode = 0;
        return STATUS_DEVICE_NOT_READY;
    }

    RtlZeroMemory(&pending, sizeof(pending));
    pending.RequestId = (ULONG)InterlockedIncrement(&g_NextQueryRequestId);
    pending.ResultCode = 0;
    pending.Linked = TRUE;
    KeInitializeEvent(&pending.CompletionEvent, NotificationEvent, FALSE);

    QueryRecord->RecordSize = sizeof(*QueryRecord);
    QueryRecord->RequestId = pending.RequestId;

    ExAcquireFastMutex(&g_PendingQueryLock);
    InsertTailList(&g_PendingQueryList, &pending.ListEntry);
    ExReleaseFastMutex(&g_PendingQueryLock);

    if (SysmonCompletePendingQueryIrp(QueryRecord, QueryRecord->RecordSize)) {
        status = STATUS_SUCCESS;
    } else {
        status = SysmonEnqueueQueryRecord(QueryRecord, QueryRecord->RecordSize);
    }

    if (!NT_SUCCESS(status)) {
        ExAcquireFastMutex(&g_PendingQueryLock);
        if (pending.Linked) {
            RemoveEntryList(&pending.ListEntry);
            pending.Linked = FALSE;
        }
        ExReleaseFastMutex(&g_PendingQueryLock);
        return status;
    }

    timeout.QuadPart = -(SYSMON_QUERY_WAIT_TIMEOUT_SECONDS * 10LL * 1000LL * 1000LL);
    status = KeWaitForSingleObject(
        &pending.CompletionEvent,
        Executive,
        KernelMode,
        FALSE,
        &timeout);

    ExAcquireFastMutex(&g_PendingQueryLock);
    if (pending.Linked) {
        RemoveEntryList(&pending.ListEntry);
        pending.Linked = FALSE;
    }
    ExReleaseFastMutex(&g_PendingQueryLock);

    if (status == STATUS_TIMEOUT) {
        DbgPrintEx(
            DPFLTR_DEFAULT_ID,
            DPFLTR_WARNING_LEVEL,
            "[SysmonDrv] Query request %lu timed out\n",
            pending.RequestId);
        *ResultCode = 0;
        return STATUS_TIMEOUT;
    }

    *ResultCode = pending.ResultCode;
    return status;
}

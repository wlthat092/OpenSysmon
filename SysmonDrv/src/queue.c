#include "queue.h"
#include "driver.h"
#include "communication.h"
#include "process.h"

SYSMON_EVENT_QUEUE  g_EventQueue;
SYSMON_EVENT_QUEUE  g_QueryQueue;
static volatile LONG g_EventQueueDropCount = 0;
static volatile LONG g_QueryQueueDropCount = 0;
static volatile LONG g_LastEventQueueDropReason = 0;
static volatile LONG g_LastQueryQueueDropReason = 0;
static volatile LONG g_LastEventQueueDropEventId = 0;
static volatile LONG g_LastQueryQueueDropType = 0;

static VOID
SysmonInitializeEventQueue(
    _Out_ PSYSMON_EVENT_QUEUE Queue)
{
    RtlZeroMemory(Queue, sizeof(*Queue));
    ExInitializeFastMutex(&Queue->Lock);
    InitializeListHead(&Queue->Head);
    KeInitializeEvent(&Queue->EventAvailable, NotificationEvent, FALSE);
    Queue->MaxEvents = SYSMON_MAX_QUEUE_EVENTS;
    Queue->MaxTotalSize = SYSMON_MAX_QUEUE_SIZE;
}

static VOID
SysmonCleanupEventQueue(
    _Inout_ PSYSMON_EVENT_QUEUE Queue)
{
    PSYSMON_EVENT_NODE node;
    ExAcquireFastMutex(&Queue->Lock);
    while (!IsListEmpty(&Queue->Head)) {
        PLIST_ENTRY entry = RemoveHeadList(&Queue->Head);
        node = CONTAINING_RECORD(entry, SYSMON_EVENT_NODE, ListEntry);
        SysmonFreePool(node);
    }
    Queue->Count = 0;
    Queue->TotalSize = 0;
    ExReleaseFastMutex(&Queue->Lock);
}

NTSTATUS
SysmonInitializeQueue(VOID)
{
    InterlockedExchange(&g_EventQueueDropCount, 0);
    InterlockedExchange(&g_QueryQueueDropCount, 0);
    InterlockedExchange(&g_LastEventQueueDropReason, 0);
    InterlockedExchange(&g_LastQueryQueueDropReason, 0);
    InterlockedExchange(&g_LastEventQueueDropEventId, 0);
    InterlockedExchange(&g_LastQueryQueueDropType, 0);
    SysmonInitializeEventQueue(&g_EventQueue);
    SysmonInitializeEventQueue(&g_QueryQueue);
    return STATUS_SUCCESS;
}

VOID
SysmonCleanupQueue(VOID)
{
    SysmonCleanupEventQueue(&g_EventQueue);
    SysmonCleanupEventQueue(&g_QueryQueue);
}

static NTSTATUS
SysmonEnqueueBlob(
    _Inout_ PSYSMON_EVENT_QUEUE Queue,
    _In_reads_bytes_(BlobSize) PVOID Blob,
    _In_ ULONG BlobSize,
    _In_opt_z_ PCSTR DebugTag)
{
    PSYSMON_EVENT_NODE node;
    LIST_ENTRY evictedHead;
    SIZE_T totalSize;

    if (Blob == NULL || BlobSize == 0) {
        return STATUS_INVALID_PARAMETER;
    }

    if (BlobSize > Queue->MaxTotalSize) {
        return STATUS_INVALID_BUFFER_SIZE;
    }

    totalSize = sizeof(SYSMON_EVENT_NODE) + BlobSize;
    if (totalSize < BlobSize) {
        return STATUS_INTEGER_OVERFLOW;
    }

    node = (PSYSMON_EVENT_NODE)SysmonAllocatePool(totalSize);
    if (node == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    RtlCopyMemory(SYSMON_EVENT_NODE_DATA(node), Blob, BlobSize);
    node->Reserved = 0;
    node->EventSize = BlobSize;

    InitializeListHead(&evictedHead);
    ExAcquireFastMutex(&Queue->Lock);
    while (!IsListEmpty(&Queue->Head) &&
           (Queue->Count >= Queue->MaxEvents ||
            Queue->TotalSize + BlobSize > Queue->MaxTotalSize)) {
        PLIST_ENTRY oldEntry = RemoveHeadList(&Queue->Head);
        PSYSMON_EVENT_NODE oldNode = CONTAINING_RECORD(oldEntry, SYSMON_EVENT_NODE, ListEntry);

        Queue->Count--;
        Queue->TotalSize -= oldNode->EventSize;
        InsertTailList(&evictedHead, &oldNode->ListEntry);
    }

    if (Queue->Count >= Queue->MaxEvents ||
        Queue->TotalSize + BlobSize > Queue->MaxTotalSize) {
        ExReleaseFastMutex(&Queue->Lock);
        while (!IsListEmpty(&evictedHead)) {
            PLIST_ENTRY oldEntry = RemoveHeadList(&evictedHead);
            PSYSMON_EVENT_NODE oldNode = CONTAINING_RECORD(oldEntry, SYSMON_EVENT_NODE, ListEntry);

            SysmonFreeEventNode(oldNode);
        }
        SysmonFreeEventNode(node);
        return STATUS_QUOTA_EXCEEDED;
    }

    InsertTailList(&Queue->Head, &node->ListEntry);
    Queue->Count++;
    Queue->TotalSize += BlobSize;
    ExReleaseFastMutex(&Queue->Lock);

    while (!IsListEmpty(&evictedHead)) {
        PLIST_ENTRY oldEntry = RemoveHeadList(&evictedHead);
        PSYSMON_EVENT_NODE oldNode = CONTAINING_RECORD(oldEntry, SYSMON_EVENT_NODE, ListEntry);

        SysmonFreeEventNode(oldNode);
    }

    KeSetEvent(&Queue->EventAvailable, 0, FALSE);
    if (DebugTag != NULL) {
        SYSMON_HOTPATH_LOG(
            DPFLTR_INFO_LEVEL,
            "[SysmonDrv] %s enqueue size=%lu\n",
            DebugTag,
            BlobSize);
    }

    return STATUS_SUCCESS;
}

static SYSMON_QUEUE_DROP_REASON
SysmonMapQueueDropReason(
    _In_ NTSTATUS Status)
{
    switch (Status) {
    case STATUS_INVALID_PARAMETER:
        return SysmonQueueDropReasonInvalidParameter;

    case STATUS_INVALID_BUFFER_SIZE:
        return SysmonQueueDropReasonInvalidBufferSize;

    case STATUS_INTEGER_OVERFLOW:
        return SysmonQueueDropReasonIntegerOverflow;

    case STATUS_INSUFFICIENT_RESOURCES:
        return SysmonQueueDropReasonAllocationFailure;

    case STATUS_QUOTA_EXCEEDED:
        return SysmonQueueDropReasonQueueFull;

    default:
        return SysmonQueueDropReasonNone;
    }
}

static VOID
SysmonRecordQueueDrop(
    _In_ BOOLEAN IsQueryQueue,
    _In_ ULONG EventIdOrType,
    _In_ NTSTATUS Status)
{
    LONG reason;

    reason = (LONG)SysmonMapQueueDropReason(Status);
    if (reason == (LONG)SysmonQueueDropReasonNone) {
        return;
    }

    if (IsQueryQueue) {
        InterlockedIncrement(&g_QueryQueueDropCount);
        InterlockedExchange(&g_LastQueryQueueDropReason, reason);
        InterlockedExchange(&g_LastQueryQueueDropType, (LONG)EventIdOrType);
    } else {
        InterlockedIncrement(&g_EventQueueDropCount);
        InterlockedExchange(&g_LastEventQueueDropReason, reason);
        InterlockedExchange(&g_LastEventQueueDropEventId, (LONG)EventIdOrType);
    }
}

NTSTATUS
SysmonEnqueueEvent(_In_ PSYSMON_EVENT_UNION Event)
{
    ULONG eventSize;
    NTSTATUS status;

    if (Event == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    eventSize = Event->Header.EventSize;
    if (eventSize == 0) {
        eventSize = sizeof(*Event);
    } else if (eventSize < sizeof(SYSMON_EVENT_HEADER)) {
        DbgPrintEx(
            DPFLTR_DEFAULT_ID,
            DPFLTR_WARNING_LEVEL,
            "[SysmonDrv] Rejecting malformed event id=%lu size=%lu (smaller than header)\n",
            Event->Header.EventId,
            eventSize);
        return STATUS_INVALID_BUFFER_SIZE;
    } else if (eventSize > sizeof(*Event)) {
        DbgPrintEx(
            DPFLTR_DEFAULT_ID,
            DPFLTR_WARNING_LEVEL,
            "[SysmonDrv] Clamping oversized event id=%lu size=%lu to %zu bytes\n",
            Event->Header.EventId,
            eventSize,
            sizeof(*Event));
        eventSize = sizeof(*Event);
    }

    SYSMON_HOTPATH_LOG(
        DPFLTR_INFO_LEVEL,
        "[SysmonDrv] Queue enqueue id=%lu headerSize=%lu storedSize=%lu\n",
        Event->Header.EventId,
        Event->Header.EventSize,
        eventSize);

    status = SysmonEnqueueBlob(&g_EventQueue, Event, eventSize, "EventQueue");
    if (!NT_SUCCESS(status)) {
        SysmonRecordQueueDrop(FALSE, Event->Header.EventId, status);
    }

    return status;
}

NTSTATUS
SysmonEnqueueQueryRecord(
    _In_reads_bytes_(RecordSize) PVOID Record,
    _In_ ULONG RecordSize)
{
    NTSTATUS status;
    ULONG queryType;

    queryType = 0;
    if (Record != NULL && RecordSize >= sizeof(SYSMON_QUERY_RECORD)) {
        queryType = ((const SYSMON_QUERY_RECORD *)Record)->QueryType;
    }

    status = SysmonEnqueueBlob(&g_QueryQueue, Record, RecordSize, "QueryQueue");
    if (!NT_SUCCESS(status)) {
        SysmonRecordQueueDrop(TRUE, queryType, status);
    }

    return status;
}

static PSYSMON_EVENT_NODE
SysmonDequeueBlob(
    _Inout_ PSYSMON_EVENT_QUEUE Queue)
{
    PSYSMON_EVENT_NODE node = NULL;
    PLIST_ENTRY entry;

    ExAcquireFastMutex(&Queue->Lock);
    if (!IsListEmpty(&Queue->Head)) {
        entry = RemoveHeadList(&Queue->Head);
        node = CONTAINING_RECORD(entry, SYSMON_EVENT_NODE, ListEntry);
        Queue->Count--;
        Queue->TotalSize -= node->EventSize;
    }
    if (IsListEmpty(&Queue->Head)) {
        KeResetEvent(&Queue->EventAvailable);
    }
    ExReleaseFastMutex(&Queue->Lock);

    return node;
}

PSYSMON_EVENT_NODE
SysmonDequeueEvent(VOID)
{
    PSYSMON_EVENT_NODE node;

    node = SysmonDequeueBlob(&g_EventQueue);
    if (node != NULL) {
        PSYSMON_EVENT_UNION event = (PSYSMON_EVENT_UNION)SYSMON_EVENT_NODE_DATA(node);
        SYSMON_HOTPATH_LOG(
            DPFLTR_INFO_LEVEL,
            "[SysmonDrv] Queue dequeue id=%lu nodeSize=%lu headerSize=%lu\n",
            event->Header.EventId,
            node->EventSize,
            event->Header.EventSize);
    }
    return node;
}

PSYSMON_EVENT_NODE
SysmonDequeueQueryRecord(VOID)
{
    return SysmonDequeueBlob(&g_QueryQueue);
}

VOID
SysmonFreeEventNode(_In_opt_ PSYSMON_EVENT_NODE Node)
{
    if (Node == NULL) return;
    SysmonFreePool(Node);
}

VOID
SysmonQueryQueueDebugStats(
    _Out_ PSYSMON_PROCESS_DEBUG_STATS Stats)
{
    if (Stats == NULL) {
        return;
    }

    Stats->EventQueueDropCount = (ULONG)InterlockedCompareExchange(&g_EventQueueDropCount, 0, 0);
    Stats->QueryQueueDropCount = (ULONG)InterlockedCompareExchange(&g_QueryQueueDropCount, 0, 0);
    Stats->LastEventQueueDropReason = (ULONG)InterlockedCompareExchange(&g_LastEventQueueDropReason, 0, 0);
    Stats->LastQueryQueueDropReason = (ULONG)InterlockedCompareExchange(&g_LastQueryQueueDropReason, 0, 0);
    Stats->LastEventQueueDropEventId = (ULONG)InterlockedCompareExchange(&g_LastEventQueueDropEventId, 0, 0);
    Stats->LastQueryQueueDropType = (ULONG)InterlockedCompareExchange(&g_LastQueryQueueDropType, 0, 0);
}


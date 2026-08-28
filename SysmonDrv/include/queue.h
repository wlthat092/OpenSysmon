#pragma once
#include "common.h"
#include "event.h"

typedef struct _SYSMON_EVENT_NODE {
    LIST_ENTRY      ListEntry;
    ULONG           Reserved;
    ULONG           EventSize;
} SYSMON_EVENT_NODE, *PSYSMON_EVENT_NODE;

#define SYSMON_EVENT_NODE_DATA(_node) \
    ((PVOID)((PUCHAR)(_node) + sizeof(SYSMON_EVENT_NODE)))

typedef struct _SYSMON_EVENT_QUEUE {
    FAST_MUTEX      Lock;
    LIST_ENTRY      Head;
    ULONG           Count;
    ULONG           TotalSize;
    KEVENT          EventAvailable;
    ULONG           MaxEvents;
    ULONG           MaxTotalSize;
} SYSMON_EVENT_QUEUE, *PSYSMON_EVENT_QUEUE;

typedef enum _SYSMON_QUEUE_DROP_REASON {
    SysmonQueueDropReasonNone = 0,
    SysmonQueueDropReasonInvalidParameter = 1,
    SysmonQueueDropReasonInvalidBufferSize = 2,
    SysmonQueueDropReasonIntegerOverflow = 3,
    SysmonQueueDropReasonAllocationFailure = 4,
    SysmonQueueDropReasonQueueFull = 5
} SYSMON_QUEUE_DROP_REASON, *PSYSMON_QUEUE_DROP_REASON;

extern SYSMON_EVENT_QUEUE   g_EventQueue;
extern SYSMON_EVENT_QUEUE   g_QueryQueue;

NTSTATUS SysmonInitializeQueue(VOID);
VOID SysmonCleanupQueue(VOID);
NTSTATUS SysmonEnqueueEvent(_In_ PSYSMON_EVENT_UNION Event);
PSYSMON_EVENT_NODE SysmonDequeueEvent(VOID);
NTSTATUS SysmonEnqueueQueryRecord(
    _In_reads_bytes_(RecordSize) PVOID Record,
    _In_ ULONG RecordSize);
PSYSMON_EVENT_NODE SysmonDequeueQueryRecord(VOID);
VOID SysmonFreeEventNode(_In_opt_ PSYSMON_EVENT_NODE Node);
struct _SYSMON_PROCESS_DEBUG_STATS;
VOID SysmonQueryQueueDebugStats(_Out_ struct _SYSMON_PROCESS_DEBUG_STATS *Stats);

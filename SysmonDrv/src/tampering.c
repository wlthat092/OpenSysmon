#include "tampering.h"
#include "event.h"
#include "driver.h"
#include "process.h"
#include "processinfo.h"

#ifndef PROCESS_QUERY_LIMITED_INFORMATION
#define PROCESS_QUERY_LIMITED_INFORMATION 0x1000
#endif

#ifndef FILE_SEQUENTIAL_ONLY
#define FILE_SEQUENTIAL_ONLY 0x00000004
#endif

#ifndef FILE_SYNCHRONOUS_IO_ALERT
#define FILE_SYNCHRONOUS_IO_ALERT 0x00000010
#endif

#define SYSMON_PS_CREATE_PROCESS_NOTIFY_SUBSYSTEMS 0ul

#define SYSMON_TAMPER_IMAGE_LOCKED      1u
#define SYSMON_TAMPER_IMAGE_DELETED     2u
#define SYSMON_TAMPER_IMAGE_REPLACED    3u
#define SYSMON_TAMPER_IMAGE_HEADER_SIZE 0x108u
#define SYSMON_TAMPER_IMAGE_COMPARE_SIZE 0x88u
#define SYSMON_TAMPER_PROCESS_IMAGE_QUERY_BYTES 0x218u
#define SYSMON_MAX_TRACKED_PROCESSES    4096
#define SYSMON_TAMPER_PENDING_RETRY_BUDGET 4u
#define SYSMON_TAMPER_PENDING_RETRY_DELAY_100NS (-10LL * 1000LL * 50LL)
#define SYSMON_TAMPER_SETTLE_RETRY_ATTEMPTS 4u
#define SYSMON_TAMPER_SETTLE_RETRY_DELAY_100NS (-10LL * 1000LL * 10LL)

#define SYSMON_TAMPER_STAGE_IDLE             0u
#define SYSMON_TAMPER_STAGE_ENTER            1u
#define SYSMON_TAMPER_STAGE_PENDING_HIT      2u
#define SYSMON_TAMPER_STAGE_LOOKUP_PROCESS   3u
#define SYSMON_TAMPER_STAGE_OPEN_PROCESS     4u
#define SYSMON_TAMPER_STAGE_CAPTURE_STATE    5u
#define SYSMON_TAMPER_STAGE_QUERY_IMAGE      6u
#define SYSMON_TAMPER_STAGE_NORMALIZE_PATH   7u
#define SYSMON_TAMPER_STAGE_OPEN_IMAGE_FILE  8u
#define SYSMON_TAMPER_STAGE_READ_IMAGE_FILE  9u
#define SYSMON_TAMPER_STAGE_COMPLETE         10u

#define SYSMON_TAMPER_DECISION_NONE                  0u
#define SYSMON_TAMPER_DECISION_SKIPPED               1u
#define SYSMON_TAMPER_DECISION_PENDING_MISS          2u
#define SYSMON_TAMPER_DECISION_LOOKUP_PROCESS_FAIL   3u
#define SYSMON_TAMPER_DECISION_OPEN_PROCESS_FAIL     4u
#define SYSMON_TAMPER_DECISION_CAPTURE_FAIL          5u
#define SYSMON_TAMPER_DECISION_QUERY_IMAGE_FAIL      6u
#define SYSMON_TAMPER_DECISION_PATH_MISMATCH         7u
#define SYSMON_TAMPER_DECISION_OPEN_FILE_DELETED     8u
#define SYSMON_TAMPER_DECISION_OPEN_FILE_LOCKED      9u
#define SYSMON_TAMPER_DECISION_HEADER_MISMATCH       10u
#define SYSMON_TAMPER_DECISION_CLEAN                 11u

typedef struct _SYSMON_PROCESS_TRACK {
    LIST_ENTRY ListEntry;
    HANDLE ProcessId;
    ULONG RetryBudget;
} SYSMON_PROCESS_TRACK, *PSYSMON_PROCESS_TRACK;

typedef struct _SYSMON_UNICODE_STRING32 {
    USHORT Length;
    USHORT MaximumLength;
    ULONG Buffer;
} SYSMON_UNICODE_STRING32, *PSYSMON_UNICODE_STRING32;

/* Bound on the synchronous image-load wait: Event 25 keeps the original-style
   synchronous worker handoff so ghosting/doppelganging observe the post-create
   file state, but the wait must never hang the loader callback indefinitely
   (P0 in the 2026-08-04 review). On timeout the caller returns and the queued
   worker runs the check deferred. */
#define SYSMON_TAMPER_IMAGE_LOAD_WAIT_TIMEOUT_MS 500

typedef struct _SYSMON_TAMPER_WORK_ITEM {
    WORK_QUEUE_ITEM WorkItem;
    KEVENT CompletionEvent;
    HANDLE ProcessId;
    /* Reference count: 2 at queue time (one held by the worker, one by the
       synchronous waiter). Whoever's decrement reaches zero frees the item.
       The worker signals the event BEFORE releasing its reference, so the item
       is always alive while a thread may be blocked on CompletionEvent. */
    volatile LONG ReferenceCount;
} SYSMON_TAMPER_WORK_ITEM, *PSYSMON_TAMPER_WORK_ITEM;

typedef struct _SYSMON_TAMPER_RETRY_WORK_ITEM {
    WORK_QUEUE_ITEM WorkItem;
    HANDLE ProcessId;
} SYSMON_TAMPER_RETRY_WORK_ITEM, *PSYSMON_TAMPER_RETRY_WORK_ITEM;

typedef struct _SYSMON_RTL_USER_PROCESS_PARAMETERS64 {
    ULONG MaximumLength;
    ULONG Length;
    ULONG Flags;
    ULONG DebugFlags;
    HANDLE ConsoleHandle;
    ULONG ConsoleFlags;
    HANDLE StandardInput;
    HANDLE StandardOutput;
    HANDLE StandardError;
    UCHAR Reserved0[0x18];
    UNICODE_STRING DllPath;
    UNICODE_STRING ImagePathName;
    UNICODE_STRING CommandLine;
} SYSMON_RTL_USER_PROCESS_PARAMETERS64, *PSYSMON_RTL_USER_PROCESS_PARAMETERS64;

typedef struct _SYSMON_RTL_USER_PROCESS_PARAMETERS32 {
    ULONG MaximumLength;
    ULONG Length;
    ULONG Flags;
    ULONG DebugFlags;
    ULONG ConsoleHandle;
    ULONG ConsoleFlags;
    ULONG StandardInput;
    ULONG StandardOutput;
    ULONG StandardError;
    UCHAR Reserved0[0x0C];
    SYSMON_UNICODE_STRING32 DllPath;
    SYSMON_UNICODE_STRING32 ImagePathName;
    SYSMON_UNICODE_STRING32 CommandLine;
} SYSMON_RTL_USER_PROCESS_PARAMETERS32, *PSYSMON_RTL_USER_PROCESS_PARAMETERS32;

typedef struct _SYSMON_PEB64 {
    UCHAR Reserved1[2];
    UCHAR BeingDebugged;
    UCHAR Reserved2[1];
    PVOID Reserved3[2];
    PVOID Ldr;
    PSYSMON_RTL_USER_PROCESS_PARAMETERS64 ProcessParameters;
} SYSMON_PEB64, *PSYSMON_PEB64;

typedef struct _SYSMON_PEB32 {
    UCHAR Reserved1[2];
    UCHAR BeingDebugged;
    UCHAR Reserved2[1];
    ULONG Reserved3[2];
    ULONG Ldr;
    ULONG ProcessParameters;
} SYSMON_PEB32, *PSYSMON_PEB32;

C_ASSERT(FIELD_OFFSET(SYSMON_RTL_USER_PROCESS_PARAMETERS64, ImagePathName) == 0x60);
C_ASSERT(FIELD_OFFSET(SYSMON_RTL_USER_PROCESS_PARAMETERS32, ImagePathName) == 0x38);
C_ASSERT(FIELD_OFFSET(SYSMON_PEB64, ProcessParameters) == 0x20);
C_ASSERT(FIELD_OFFSET(SYSMON_PEB32, ProcessParameters) == 0x10);

static LIST_ENTRY g_ProcessTrackList;
static FAST_MUTEX g_ProcessTrackLock;
static volatile LONG g_TamperingSequence = 0;
static volatile LONG g_TrackedProcessCount = 0;
static PFN_PS_SET_CREATE_PROCESS_NOTIFY_ROUTINE_EX2 g_TamperingProcessNotifyRoutineEx2 = NULL;
static PFN_PS_SET_CREATE_PROCESS_NOTIFY_ROUTINE g_TamperingProcessNotifyRoutineLegacy = NULL;
static BOOLEAN g_TamperingInitialized = FALSE;
static BOOLEAN g_TamperingProcessNotifyRegisteredEx2 = FALSE;
static BOOLEAN g_TamperingProcessNotifyRegisteredLegacy = FALSE;
static volatile LONG g_TamperTrackProcessCount = 0;
static volatile LONG g_TamperCheckCallCount = 0;
static volatile LONG g_TamperPendingHitCount = 0;
static volatile LONG g_TamperUntrackMissCount = 0;
static volatile LONG g_TamperReportCount = 0;
static volatile LONG g_TamperLastProcessId = 0;
static volatile LONG g_TamperLastStage = 0;
static volatile LONG g_TamperLastDecision = 0;
static volatile LONG g_TamperLastOpenProcessStatus = 0;
static volatile LONG g_TamperLastCaptureStatus = 0;
static volatile LONG g_TamperLastQueryImageStatus = 0;
static volatile LONG g_TamperLastNormalizeStatus = 0;
static volatile LONG g_TamperLastOpenFileStatus = 0;
static volatile LONG g_TamperLastReadFileStatus = 0;
static volatile LONG g_TamperLookupProcessFailCount = 0;
static volatile LONG g_TamperOpenProcessFailCount = 0;
static volatile LONG g_TamperCaptureFailCount = 0;
static volatile LONG g_TamperQueryImageFailCount = 0;
static volatile LONG g_TamperLastQueryFailProcessId = 0;
static volatile LONG g_TamperLastQueryFailStatus = 0;
static volatile LONG g_TamperPathMismatchCount = 0;
static volatile LONG g_TamperOpenFileDeletedCount = 0;
static volatile LONG g_TamperOpenFileLockedCount = 0;
static volatile LONG g_TamperHeaderMismatchCount = 0;
static volatile LONG g_TamperCleanCount = 0;
static volatile LONG g_TamperRecentTrackPid[4] = { 0 };
static volatile LONG g_TamperRecentDecisionPid[4] = { 0 };
static volatile LONG g_TamperRecentDecisionCode[4] = { 0 };
static volatile LONG g_TamperRecentTrackCursor = -1;
static volatile LONG g_TamperRecentDecisionCursor = -1;

static VOID
SysmonTamperSetStage(_In_ ULONG Stage)
{
    InterlockedExchange(&g_TamperLastStage, (LONG)Stage);
}

static VOID
SysmonTamperSetDecision(_In_ ULONG Decision)
{
    InterlockedExchange(&g_TamperLastDecision, (LONG)Decision);
}

static VOID
SysmonTamperSetStatus(
    _Inout_ volatile LONG *Destination,
    _In_ NTSTATUS Status)
{
    InterlockedExchange(Destination, (LONG)Status);
}

static VOID
SysmonTamperRecordTrack(_In_ HANDLE ProcessId)
{
    LONG index;

    index = (InterlockedIncrement(&g_TamperRecentTrackCursor) - 1) & 3;
    InterlockedExchange(&g_TamperRecentTrackPid[index], (LONG)HandleToULong(ProcessId));
}

static VOID
SysmonTamperRecordFinalDecision(
    _In_ HANDLE ProcessId,
    _In_ ULONG Decision)
{
    LONG index;

    index = (InterlockedIncrement(&g_TamperRecentDecisionCursor) - 1) & 3;
    InterlockedExchange(&g_TamperRecentDecisionPid[index], (LONG)HandleToULong(ProcessId));
    InterlockedExchange(&g_TamperRecentDecisionCode[index], (LONG)Decision);
}

static VOID
SysmonTamperRecordQueryFail(
    _In_ HANDLE ProcessId,
    _In_ NTSTATUS Status)
{
    InterlockedExchange(
        &g_TamperLastQueryFailProcessId,
        (LONG)HandleToULong(ProcessId));
    SysmonTamperSetStatus(&g_TamperLastQueryFailStatus, Status);
}

static VOID
SysmonTamperDelayForSettle(VOID)
{
    LARGE_INTEGER interval;

    interval.QuadPart = SYSMON_TAMPER_SETTLE_RETRY_DELAY_100NS;
    (void)KeDelayExecutionThread(KernelMode, FALSE, &interval);
}

static VOID
SysmonTamperRetryWorkItemRoutine(
    _In_ PVOID Parameter)
{
    PSYSMON_TAMPER_RETRY_WORK_ITEM workItem;
    LARGE_INTEGER interval;

    workItem = (PSYSMON_TAMPER_RETRY_WORK_ITEM)Parameter;
    if (workItem == NULL) {
        return;
    }

    interval.QuadPart = SYSMON_TAMPER_PENDING_RETRY_DELAY_100NS;
    (void)KeDelayExecutionThread(KernelMode, FALSE, &interval);
    SysmonCheckProcessTamperingOnImageLoad(workItem->ProcessId);
    SysmonFreePool(workItem);
    /* The driver rundown was acquired before this item was queued; release it
       only after the worker is fully done so the driver cannot unload while a
       system work item is still executing driver code. */
    SysmonReleaseDriverRundown();
}

static VOID
SysmonQueueDelayedTamperRetry(_In_ HANDLE ProcessId)
{
    PSYSMON_TAMPER_RETRY_WORK_ITEM workItem;

    if (ProcessId == NULL) {
        return;
    }

    workItem = (PSYSMON_TAMPER_RETRY_WORK_ITEM)SysmonAllocatePool(sizeof(*workItem));
    if (workItem == NULL) {
        return;
    }

    RtlZeroMemory(workItem, sizeof(*workItem));
    workItem->ProcessId = ProcessId;

    /* Hold the driver rundown for the worker's lifetime. If the driver is
       already unloading, do not queue the item. */
    if (!SysmonAcquireDriverRundown()) {
        SysmonFreePool(workItem);
        return;
    }

    ExInitializeWorkItem(
        &workItem->WorkItem,
        SysmonTamperRetryWorkItemRoutine,
        workItem);
    ExQueueWorkItem(&workItem->WorkItem, DelayedWorkQueue);
}

static VOID
SysmonTamperWorkItemRoutine(
    _In_ PVOID Parameter)
{
    PSYSMON_TAMPER_WORK_ITEM workItem;

    workItem = (PSYSMON_TAMPER_WORK_ITEM)Parameter;
    if (workItem == NULL) {
        return;
    }

    SysmonCheckProcessTamperingOnImageLoad(workItem->ProcessId);
    /* Signal before releasing our reference: the waiter may be blocked on the
       event, and its own reference keeps the item alive until it wakes. */
    KeSetEvent(&workItem->CompletionEvent, IO_NO_INCREMENT, FALSE);
    if (InterlockedDecrement(&workItem->ReferenceCount) == 0) {
        SysmonFreePool(workItem);
    }
    /* The driver rundown was acquired before this item was queued; release it
       only after the worker is fully done so the driver cannot unload while a
       system work item is still executing driver code. */
    SysmonReleaseDriverRundown();
}

static PCWSTR
SysmonTamperTypeToCanonicalString(_In_ ULONG TamperType)
{
    switch (TamperType) {
    case SYSMON_TAMPER_IMAGE_LOCKED:
        return L"Image is locked for access";
    case SYSMON_TAMPER_IMAGE_DELETED:
        return L"Image is deleted";
    case SYSMON_TAMPER_IMAGE_REPLACED:
        return L"Image is replaced";
    default:
        return L"Unknown";
    }
}

static VOID
SysmonReportTampering(
    _In_ HANDLE ProcessId,
    _In_ ULONG TamperType,
    _In_opt_z_ PCWSTR ImagePath)
{
    PSYSMON_EVENT_UNION event;
    SYSMON_EVENT_PROCESS_TAMPERING_PAYLOAD *eventData;
    SYSMON_EVENT_PAYLOAD_BUILDER builder;
    SYSMON_PROCESS_INFO processInfo;
    PCWSTR image;

    RtlZeroMemory(&processInfo, sizeof(processInfo));
    (void)SysmonCollectProcessInfo(ProcessId, &processInfo);

    event = SysmonAllocateEvent(SysmonEventProcessTampering);
    if (event == NULL) {
        return;
    }

    eventData = (SYSMON_EVENT_PROCESS_TAMPERING_PAYLOAD *)event->RawData;
    SysmonBeginStringPayload(event, sizeof(*eventData), &builder);
    event->Header.Timestamp = SysmonGetCurrentTimestamp();
    event->Header.SequenceNumber = InterlockedIncrement(&g_TamperingSequence);

    image = ImagePath;
    if (image == NULL || image[0] == L'\0') {
        image = processInfo.ImagePath;
    }
    if (image == NULL || image[0] == L'\0') {
        image = L"<unknown process>";
    }

    SysmonAddStringField(event, &builder, &eventData->RuleName, L"-");
    SysmonAddCurrentUtcTimeField(event, &builder, &eventData->UtcTime);
    SysmonAddStringField(event, &builder, &eventData->ProcessGuid, processInfo.ProcessGuid);
    eventData->ProcessId = (ULONG)(ULONG_PTR)ProcessId;
    SysmonAddStringField(event, &builder, &eventData->Image, image);
    SysmonAddStringField(event, &builder, &eventData->Type, SysmonTamperTypeToCanonicalString(TamperType));
    SysmonAddStringField(event, &builder, &eventData->User, processInfo.UserSid);

    SysmonPublishEvent(event);
    SysmonFreeEvent(event);
    InterlockedIncrement(&g_TamperReportCount);

    DbgPrintEx(
        DPFLTR_DEFAULT_ID,
        DPFLTR_INFO_LEVEL,
        "[SysmonDrv] ProcessTampering: PID=%lu, Type=%u\n",
        (ULONG)(ULONG_PTR)ProcessId,
        TamperType);
}

static BOOLEAN
SysmonTrackProcessWithRetryBudget(
    _In_ HANDLE ProcessId,
    _In_ ULONG RetryBudget)
{
    PSYSMON_PROCESS_TRACK track;
    PLIST_ENTRY entry;

    if (InterlockedCompareExchange(&g_TrackedProcessCount, 0, 0) >=
        SYSMON_MAX_TRACKED_PROCESSES) {
        return FALSE;
    }

    track = (PSYSMON_PROCESS_TRACK)SysmonAllocatePool(sizeof(*track));
    if (track == NULL) {
        return FALSE;
    }

    RtlZeroMemory(track, sizeof(*track));
    track->ProcessId = ProcessId;
    track->RetryBudget = RetryBudget;

    ExAcquireFastMutex(&g_ProcessTrackLock);
    entry = g_ProcessTrackList.Flink;
    while (entry != &g_ProcessTrackList) {
        PSYSMON_PROCESS_TRACK currentTrack;

        currentTrack = CONTAINING_RECORD(entry, SYSMON_PROCESS_TRACK, ListEntry);
        if (currentTrack->ProcessId == ProcessId) {
            if (currentTrack->RetryBudget < RetryBudget) {
                currentTrack->RetryBudget = RetryBudget;
            }
            ExReleaseFastMutex(&g_ProcessTrackLock);
            SysmonFreePool(track);
            return TRUE;
        }
        entry = entry->Flink;
    }
    InsertHeadList(&g_ProcessTrackList, &track->ListEntry);
    ExReleaseFastMutex(&g_ProcessTrackLock);
    InterlockedIncrement(&g_TamperTrackProcessCount);
    SysmonTamperRecordTrack(ProcessId);
    InterlockedIncrement(&g_TrackedProcessCount);
    return TRUE;
}

static VOID
SysmonTrackProcess(_In_ HANDLE ProcessId)
{
    (void)SysmonTrackProcessWithRetryBudget(
        ProcessId,
        SYSMON_TAMPER_PENDING_RETRY_BUDGET);
}

static VOID
SysmonTrackProcessIfEnabled(_In_ HANDLE ProcessId)
{
    if (SysmonIsProducerEnabled(SYSMON_FLAG_ENABLED) && SysmonIsProducerEnabled(SYSMON_FLAG_TAMPERING_NOTIFY) && ProcessId != NULL) {
        SysmonTrackProcess(ProcessId);
    }
}

static BOOLEAN
SysmonUntrackProcess(
    _In_ HANDLE ProcessId,
    _Out_opt_ PULONG RetryBudget)
{
    PLIST_ENTRY entry;

    if (RetryBudget != NULL) {
        *RetryBudget = 0;
    }

    ExAcquireFastMutex(&g_ProcessTrackLock);
    entry = g_ProcessTrackList.Flink;
    while (entry != &g_ProcessTrackList) {
        PSYSMON_PROCESS_TRACK track;

        track = CONTAINING_RECORD(entry, SYSMON_PROCESS_TRACK, ListEntry);
        entry = entry->Flink;
        if (track->ProcessId == ProcessId) {
            RemoveEntryList(&track->ListEntry);
            ExReleaseFastMutex(&g_ProcessTrackLock);

            if (RetryBudget != NULL) {
                *RetryBudget = track->RetryBudget;
            }
            SysmonFreePool(track);
            InterlockedDecrement(&g_TrackedProcessCount);
            return TRUE;
        }
    }
    ExReleaseFastMutex(&g_ProcessTrackLock);
    return FALSE;
}

static NTSTATUS
SysmonCopyAttachedUnicodeString(
    _In_ PCUNICODE_STRING Source,
    _Out_writes_(DestinationChars) PWCHAR Destination,
    _In_ ULONG DestinationChars)
{
    ULONG copyChars;

    if (Destination == NULL || DestinationChars == 0) {
        return STATUS_INVALID_PARAMETER;
    }

    Destination[0] = L'\0';

    ProbeForRead(Source, sizeof(*Source), __alignof(WCHAR));
    if (Source->Buffer == NULL || Source->Length == 0) {
        return STATUS_NOT_FOUND;
    }

    copyChars = Source->Length / sizeof(WCHAR);
    if (copyChars >= DestinationChars) {
        copyChars = DestinationChars - 1;
    }

    ProbeForRead(Source->Buffer, copyChars * sizeof(WCHAR), sizeof(WCHAR));
    RtlCopyMemory(Destination, Source->Buffer, copyChars * sizeof(WCHAR));
    Destination[copyChars] = L'\0';
    return STATUS_SUCCESS;
}

static NTSTATUS
SysmonCopyProcessParametersUnicodeString64(
    _In_ const SYSMON_RTL_USER_PROCESS_PARAMETERS64 *ProcessParameters,
    _In_ ULONG Flags,
    _In_ PCUNICODE_STRING Source,
    _Out_writes_(DestinationChars) PWCHAR Destination,
    _In_ ULONG DestinationChars)
{
    ULONG copyChars;
    PWCHAR sourceBuffer;

    if (ProcessParameters == NULL ||
        Source == NULL ||
        Destination == NULL ||
        DestinationChars == 0) {
        return STATUS_INVALID_PARAMETER;
    }

    Destination[0] = L'\0';
    ProbeForRead(Source, sizeof(*Source), __alignof(WCHAR));
    if (Source->Buffer == NULL || Source->Length == 0) {
        return STATUS_NOT_FOUND;
    }

    if ((Flags & 1u) != 0) {
        sourceBuffer = Source->Buffer;
    } else {
        sourceBuffer = (PWCHAR)((PUCHAR)ProcessParameters + (ULONG_PTR)Source->Buffer);
    }

    copyChars = Source->Length / sizeof(WCHAR);
    if (copyChars >= DestinationChars) {
        copyChars = DestinationChars - 1;
    }

    ProbeForRead(sourceBuffer, copyChars * sizeof(WCHAR), sizeof(WCHAR));
    RtlCopyMemory(Destination, sourceBuffer, copyChars * sizeof(WCHAR));
    Destination[copyChars] = L'\0';
    return STATUS_SUCCESS;
}

static NTSTATUS
SysmonCopyAttachedUnicodeString32(
    _In_ const SYSMON_UNICODE_STRING32 *Source,
    _Out_writes_(DestinationChars) PWCHAR Destination,
    _In_ ULONG DestinationChars)
{
    ULONG copyChars;
    PWCHAR sourceBuffer;

    if (Destination == NULL || DestinationChars == 0) {
        return STATUS_INVALID_PARAMETER;
    }

    Destination[0] = L'\0';

    ProbeForRead(Source, sizeof(*Source), sizeof(USHORT));
    if (Source->Buffer == 0 || Source->Length == 0) {
        return STATUS_NOT_FOUND;
    }

    copyChars = Source->Length / sizeof(WCHAR);
    if (copyChars >= DestinationChars) {
        copyChars = DestinationChars - 1;
    }

    sourceBuffer = (PWCHAR)(ULONG_PTR)Source->Buffer;
    ProbeForRead(sourceBuffer, copyChars * sizeof(WCHAR), sizeof(WCHAR));
    RtlCopyMemory(Destination, sourceBuffer, copyChars * sizeof(WCHAR));
    Destination[copyChars] = L'\0';
    return STATUS_SUCCESS;
}

static NTSTATUS
SysmonCopyProcessParametersUnicodeString32(
    _In_ const SYSMON_RTL_USER_PROCESS_PARAMETERS32 *ProcessParameters,
    _In_ ULONG Flags,
    _In_ const SYSMON_UNICODE_STRING32 *Source,
    _Out_writes_(DestinationChars) PWCHAR Destination,
    _In_ ULONG DestinationChars)
{
    ULONG copyChars;
    PWCHAR sourceBuffer;

    if (ProcessParameters == NULL ||
        Source == NULL ||
        Destination == NULL ||
        DestinationChars == 0) {
        return STATUS_INVALID_PARAMETER;
    }

    Destination[0] = L'\0';
    ProbeForRead(Source, sizeof(*Source), sizeof(USHORT));
    if (Source->Buffer == 0 || Source->Length == 0) {
        return STATUS_NOT_FOUND;
    }

    if ((Flags & 1u) != 0) {
        sourceBuffer = (PWCHAR)(ULONG_PTR)Source->Buffer;
    } else {
        sourceBuffer = (PWCHAR)((PUCHAR)ProcessParameters + Source->Buffer);
    }

    copyChars = Source->Length / sizeof(WCHAR);
    if (copyChars >= DestinationChars) {
        copyChars = DestinationChars - 1;
    }

    ProbeForRead(sourceBuffer, copyChars * sizeof(WCHAR), sizeof(WCHAR));
    RtlCopyMemory(Destination, sourceBuffer, copyChars * sizeof(WCHAR));
    Destination[copyChars] = L'\0';
    return STATUS_SUCCESS;
}

static NTSTATUS
SysmonCaptureMainImageStateAttached64(
    _In_ const SYSMON_PEB64 *Peb,
    _Out_writes_(ImagePathChars) PWCHAR ImagePath,
    _In_ ULONG ImagePathChars,
    _Out_writes_bytes_(HeaderBytes) PUCHAR HeaderBuffer,
    _In_ ULONG HeaderBytes)
{
    const SYSMON_RTL_USER_PROCESS_PARAMETERS64 *processParameters;
    PVOID imageBase;
    NTSTATUS status;
    ULONG flags;

    ProbeForRead(Peb, sizeof(*Peb), sizeof(PVOID));
    if (Peb->ProcessParameters == NULL) {
        return STATUS_NOT_FOUND;
    }

    processParameters = Peb->ProcessParameters;
    ProbeForRead(processParameters, sizeof(*processParameters), sizeof(ULONG));
    flags = processParameters->Flags;
    status = SysmonCopyProcessParametersUnicodeString64(
        processParameters,
        flags,
        &processParameters->ImagePathName,
        ImagePath,
        ImagePathChars);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    if (HeaderBuffer != NULL && HeaderBytes != 0) {
        imageBase = Peb->Reserved3[1];
        if (imageBase == NULL) {
            return STATUS_NOT_FOUND;
        }

        ProbeForRead(imageBase, HeaderBytes, sizeof(UCHAR));
        RtlCopyMemory(HeaderBuffer, imageBase, HeaderBytes);
    }

    return STATUS_SUCCESS;
}

static NTSTATUS
SysmonCaptureMainImageStateAttached32(
    _In_ const SYSMON_PEB32 *Peb32,
    _Out_writes_(ImagePathChars) PWCHAR ImagePath,
    _In_ ULONG ImagePathChars,
    _Out_writes_bytes_(HeaderBytes) PUCHAR HeaderBuffer,
    _In_ ULONG HeaderBytes)
{
    const SYSMON_RTL_USER_PROCESS_PARAMETERS32 *processParameters;
    PVOID imageBase;
    NTSTATUS status;
    ULONG flags;

    ProbeForRead(Peb32, sizeof(*Peb32), sizeof(ULONG));
    if (Peb32->ProcessParameters == 0) {
        return STATUS_NOT_FOUND;
    }

    processParameters =
        (const SYSMON_RTL_USER_PROCESS_PARAMETERS32 *)(ULONG_PTR)Peb32->ProcessParameters;
    ProbeForRead(processParameters, sizeof(*processParameters), sizeof(ULONG));
    flags = processParameters->Flags;
    status = SysmonCopyProcessParametersUnicodeString32(
        processParameters,
        flags,
        &processParameters->ImagePathName,
        ImagePath,
        ImagePathChars);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    if (HeaderBuffer != NULL && HeaderBytes != 0) {
        imageBase = (PVOID)(ULONG_PTR)Peb32->Reserved3[1];
        if (imageBase == NULL) {
            return STATUS_NOT_FOUND;
        }

        ProbeForRead(imageBase, HeaderBytes, sizeof(UCHAR));
        RtlCopyMemory(HeaderBuffer, imageBase, HeaderBytes);
    }

    return STATUS_SUCCESS;
}

static NTSTATUS
SysmonCaptureMainImageStateForProcessHandle(
    _In_ HANDLE ProcessHandle,
    _Out_writes_(ImagePathChars) PWCHAR ImagePath,
    _In_ ULONG ImagePathChars,
    _Out_writes_bytes_(HeaderBytes) PUCHAR HeaderBuffer,
    _In_ ULONG HeaderBytes)
{
    KAPC_STATE apcState;
    PROCESS_BASIC_INFORMATION basicInfo;
    PVOID wow64Peb;
    PEPROCESS processObject;
    ULONG returnLength;
    NTSTATUS status;

    if (ProcessHandle == NULL ||
        ImagePath == NULL ||
        ImagePathChars == 0) {
        return STATUS_INVALID_PARAMETER;
    }

    ImagePath[0] = L'\0';
    if (HeaderBuffer != NULL && HeaderBytes != 0) {
        RtlZeroMemory(HeaderBuffer, HeaderBytes);
    }

    RtlZeroMemory(&basicInfo, sizeof(basicInfo));
    wow64Peb = NULL;
    processObject = NULL;
    returnLength = 0;

    status = ZwQueryInformationProcess(
        ProcessHandle,
        ProcessBasicInformation,
        &basicInfo,
        sizeof(basicInfo),
        &returnLength);
    if (!NT_SUCCESS(status) || basicInfo.PebBaseAddress == NULL) {
        return status;
    }

    (void)ZwQueryInformationProcess(
        ProcessHandle,
        ProcessWow64Information,
        &wow64Peb,
        sizeof(wow64Peb),
        &returnLength);

    status = ObReferenceObjectByHandle(
        ProcessHandle,
        0,
        NULL,
        KernelMode,
        (PVOID *)&processObject,
        NULL);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    KeStackAttachProcess(processObject, &apcState);
    __try {
        status = SysmonCaptureMainImageStateAttached64(
            (const SYSMON_PEB64 *)basicInfo.PebBaseAddress,
            ImagePath,
            ImagePathChars,
            HeaderBuffer,
            HeaderBytes);
        if (!NT_SUCCESS(status) &&
            wow64Peb != NULL &&
            (PVOID)(ULONG_PTR)wow64Peb <= MmHighestUserAddress) {
            status = SysmonCaptureMainImageStateAttached32(
                (const SYSMON_PEB32 *)(ULONG_PTR)wow64Peb,
                ImagePath,
                ImagePathChars,
                HeaderBuffer,
                HeaderBytes);
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        ImagePath[0] = L'\0';
        if (HeaderBuffer != NULL && HeaderBytes != 0) {
            RtlZeroMemory(HeaderBuffer, HeaderBytes);
        }
        status = GetExceptionCode();
    }
    KeUnstackDetachProcess(&apcState);
    ObDereferenceObject(processObject);

    return status;
}

static NTSTATUS
SysmonQueryProcessImagePathClass(
    _In_ HANDLE ProcessHandle,
    _In_ PROCESSINFOCLASS InformationClass,
    _Outptr_ PUNICODE_STRING *ImagePath)
{
    NTSTATUS status;
    ULONG returnLength;
    PUNICODE_STRING pathBuffer;

    if (ImagePath == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    *ImagePath = NULL;
    returnLength = SYSMON_TAMPER_PROCESS_IMAGE_QUERY_BYTES;
    pathBuffer = (PUNICODE_STRING)SysmonAllocatePool(returnLength);
    if (pathBuffer == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    RtlZeroMemory(pathBuffer, returnLength);
    status = ZwQueryInformationProcess(
        ProcessHandle,
        InformationClass,
        pathBuffer,
        returnLength,
        &returnLength);
    if (status == STATUS_INFO_LENGTH_MISMATCH ||
        status == STATUS_BUFFER_TOO_SMALL) {
        SysmonFreePool(pathBuffer);
        pathBuffer = (PUNICODE_STRING)SysmonAllocatePool(returnLength);
        if (pathBuffer == NULL) {
            return STATUS_INSUFFICIENT_RESOURCES;
        }

        RtlZeroMemory(pathBuffer, returnLength);
        status = ZwQueryInformationProcess(
            ProcessHandle,
            InformationClass,
            pathBuffer,
            returnLength,
            &returnLength);
    }
    if (!NT_SUCCESS(status)) {
        SysmonFreePool(pathBuffer);
        return status;
    }

    *ImagePath = pathBuffer;
    return STATUS_SUCCESS;
}

static NTSTATUS
SysmonQueryProcessImagePath(
    _In_ HANDLE ProcessHandle,
    _Outptr_ PUNICODE_STRING *ImagePath)
{
    NTSTATUS status;

    status = SysmonQueryProcessImagePathClass(
        ProcessHandle,
        ProcessImageFileName,
        ImagePath);
    if (status == STATUS_NOT_FOUND) {
        status = SysmonQueryProcessImagePathClass(
            ProcessHandle,
            ProcessImageFileNameWin32,
            ImagePath);
    }

    return status;
}

static NTSTATUS
SysmonNormalizeProcessImagePath(
    _In_ PCUNICODE_STRING NtImagePath,
    _Out_writes_(DosPathChars) PWCHAR DosPath,
    _In_ ULONG DosPathChars)
{
    NTSTATUS status;
    PFILE_OBJECT fileObject;
    PDEVICE_OBJECT deviceObject;
    POBJECT_NAME_INFORMATION dosNameInfo;
    ULONG copyChars;

    if (NtImagePath == NULL || DosPath == NULL || DosPathChars == 0) {
        return STATUS_INVALID_PARAMETER;
    }

    DosPath[0] = L'\0';
    if (NtImagePath->Buffer == NULL || NtImagePath->Length <= sizeof(WCHAR) * 2) {
        return STATUS_INVALID_PARAMETER;
    }

    if ((NtImagePath->Buffer[0] == L'\\' && NtImagePath->Buffer[1] == L'\\') ||
        NtImagePath->Buffer[1] == L':') {
        return STATUS_INVALID_PARAMETER;
    }

    fileObject = NULL;
    deviceObject = NULL;
    dosNameInfo = NULL;

    status = IoGetDeviceObjectPointer(
        (PUNICODE_STRING)NtImagePath,
        FILE_READ_ATTRIBUTES,
        &fileObject,
        &deviceObject);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    status = IoQueryFileDosDeviceName(fileObject, &dosNameInfo);
    ObDereferenceObject(fileObject);
    UNREFERENCED_PARAMETER(deviceObject);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    copyChars = dosNameInfo->Name.Length / sizeof(WCHAR);
    if (copyChars >= DosPathChars) {
        copyChars = DosPathChars - 1;
    }

    RtlCopyMemory(DosPath, dosNameInfo->Name.Buffer, copyChars * sizeof(WCHAR));
    DosPath[copyChars] = L'\0';
    ExFreePoolWithTag(dosNameInfo, 0);
    return STATUS_SUCCESS;
}

static PCWSTR
SysmonSkipImagePathPrefix(_In_opt_z_ PCWSTR ImagePath)
{
    if (ImagePath != NULL &&
        ImagePath[0] == L'\\' &&
        ImagePath[2] == L'?' &&
        ImagePath[3] == L'\\' &&
        (ImagePath[1] == L'?' || ImagePath[1] == L'\\')) {
        return ImagePath + 4;
    }

    return (ImagePath != NULL) ? ImagePath : L"";
}

static PCWSTR
SysmonSkipDriveLetterPrefix(_In_opt_z_ PCWSTR Path)
{
    if (Path != NULL &&
        Path[0] != L'\0' &&
        Path[1] == L':' &&
        Path[2] == L'\\') {
        return Path + 2;
    }

    return (Path != NULL) ? Path : L"";
}

static BOOLEAN
SysmonPathsEqualCaseInsensitive(
    _In_z_ PCWSTR Left,
    _In_z_ PCWSTR Right)
{
    SIZE_T leftLength;
    SIZE_T rightLength;
    PCWSTR normalizedLeft;
    PCWSTR normalizedRight;

    leftLength = wcslen(Left);
    rightLength = wcslen(Right);
    if (leftLength != rightLength) {
        normalizedLeft = Left;
        normalizedRight = Right;

        if (Left[0] == L'\\' &&
            Right[0] != L'\\') {
            normalizedRight = SysmonSkipDriveLetterPrefix(Right);
        } else if (Right[0] == L'\\' &&
                   Left[0] != L'\\') {
            normalizedLeft = SysmonSkipDriveLetterPrefix(Left);
        }

        if (normalizedLeft == Left &&
            normalizedRight == Right) {
            return FALSE;
        }

        leftLength = wcslen(normalizedLeft);
        rightLength = wcslen(normalizedRight);
        if (leftLength != rightLength) {
            return FALSE;
        }

        Left = normalizedLeft;
        Right = normalizedRight;
    }

    return (_wcsnicmp(Left, Right, leftLength) == 0);
}

static NTSTATUS
SysmonOpenProcessImageFile(
    _In_ PCUNICODE_STRING ImagePath,
    _Out_ PHANDLE FileHandle)
{
    static const WCHAR prefix[] = L"\\??\\";
    UNICODE_STRING openPath;
    UNICODE_STRING prefixedPath;
    OBJECT_ATTRIBUTES objectAttributes;
    IO_STATUS_BLOCK ioStatusBlock;
    NTSTATUS status;
    PWCHAR prefixedBuffer;

    if (ImagePath == NULL || FileHandle == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    *FileHandle = NULL;
    openPath = *ImagePath;
    RtlZeroMemory(&prefixedPath, sizeof(prefixedPath));
    prefixedBuffer = NULL;

    if (ImagePath->Buffer != NULL &&
        ImagePath->Length > sizeof(WCHAR) * 2 &&
        ImagePath->Buffer[1] == L':') {
        prefixedPath.MaximumLength = ImagePath->Length + sizeof(prefix);
        prefixedBuffer = (PWCHAR)SysmonAllocatePool(prefixedPath.MaximumLength);
        if (prefixedBuffer == NULL) {
            return STATUS_INSUFFICIENT_RESOURCES;
        }

        RtlZeroMemory(prefixedBuffer, prefixedPath.MaximumLength);
        prefixedPath.Buffer = prefixedBuffer;
        status = RtlAppendUnicodeToString(&prefixedPath, prefix);
        if (!NT_SUCCESS(status)) {
            SysmonFreePool(prefixedBuffer);
            return status;
        }

        status = RtlAppendUnicodeStringToString(&prefixedPath, ImagePath);
        if (!NT_SUCCESS(status)) {
            SysmonFreePool(prefixedBuffer);
            return status;
        }

        openPath = prefixedPath;
    }

    InitializeObjectAttributes(
        &objectAttributes,
        &openPath,
        OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE,
        NULL,
        NULL);
    status = ZwCreateFile(
        FileHandle,
        FILE_READ_DATA | FILE_READ_ATTRIBUTES | SYNCHRONIZE,
        &objectAttributes,
        &ioStatusBlock,
        NULL,
        FILE_ATTRIBUTE_NORMAL,
        FILE_SHARE_READ | FILE_SHARE_DELETE,
        FILE_OPEN,
        FILE_NON_DIRECTORY_FILE |
            FILE_SYNCHRONOUS_IO_ALERT |
            FILE_SEQUENTIAL_ONLY,
        NULL,
        0);

    if (prefixedBuffer != NULL) {
        SysmonFreePool(prefixedBuffer);
    }

    return status;
}

VOID
SysmonCheckProcessTamperingOnImageLoad(_In_ HANDLE ProcessId)
{
    UCHAR mappedImageHeader[SYSMON_TAMPER_IMAGE_HEADER_SIZE];
    UCHAR fileImageHeader[SYSMON_TAMPER_IMAGE_HEADER_SIZE];
    WCHAR processImagePath[SYSMON_MAX_PATH];
    WCHAR currentImageDosPath[SYSMON_MAX_PATH];
    HANDLE processHandle;
    HANDLE fileHandle;
    CLIENT_ID clientId;
    OBJECT_ATTRIBUTES objectAttributes;
    IO_STATUS_BLOCK ioStatusBlock;
    LARGE_INTEGER fileOffset;
    PUNICODE_STRING currentImagePath;
    NTSTATUS status;
    NTSTATUS queryFailureStatus;
    ULONG remainingRetryBudget;
    ULONG stateAttempt;
    BOOLEAN persistentPathMismatch;
    PCWSTR comparableProcessPath;

    if (!SysmonIsProducerEnabled(SYSMON_FLAG_ENABLED) ||
        !SysmonIsProducerEnabled(SYSMON_FLAG_TAMPERING_NOTIFY) ||
        ProcessId == NULL) {
        SysmonTamperSetDecision(SYSMON_TAMPER_DECISION_SKIPPED);
        return;
    }

    InterlockedIncrement(&g_TamperCheckCallCount);
    InterlockedExchange(&g_TamperLastProcessId, (LONG)HandleToULong(ProcessId));
    SysmonTamperSetStage(SYSMON_TAMPER_STAGE_ENTER);
    SysmonTamperSetDecision(SYSMON_TAMPER_DECISION_NONE);
    SysmonTamperSetStatus(&g_TamperLastOpenProcessStatus, STATUS_SUCCESS);
    SysmonTamperSetStatus(&g_TamperLastCaptureStatus, STATUS_SUCCESS);
    SysmonTamperSetStatus(&g_TamperLastQueryImageStatus, STATUS_SUCCESS);
    SysmonTamperSetStatus(&g_TamperLastNormalizeStatus, STATUS_SUCCESS);
    SysmonTamperSetStatus(&g_TamperLastOpenFileStatus, STATUS_SUCCESS);
    SysmonTamperSetStatus(&g_TamperLastReadFileStatus, STATUS_SUCCESS);
    remainingRetryBudget = 0;

    if (!SysmonUntrackProcess(ProcessId, &remainingRetryBudget)) {
        InterlockedIncrement(&g_TamperUntrackMissCount);
        SysmonTamperSetDecision(SYSMON_TAMPER_DECISION_PENDING_MISS);
        return;
    }
    InterlockedIncrement(&g_TamperPendingHitCount);
    SysmonTamperSetStage(SYSMON_TAMPER_STAGE_PENDING_HIT);

    processHandle = NULL;
    fileHandle = NULL;
    currentImagePath = NULL;
    processImagePath[0] = L'\0';
    currentImageDosPath[0] = L'\0';
    RtlZeroMemory(mappedImageHeader, sizeof(mappedImageHeader));
    RtlZeroMemory(fileImageHeader, sizeof(fileImageHeader));
    persistentPathMismatch = FALSE;

    InitializeObjectAttributes(&objectAttributes, NULL, OBJ_KERNEL_HANDLE, NULL, NULL);
    clientId.UniqueProcess = ProcessId;
    clientId.UniqueThread = NULL;

    status = ZwOpenProcess(
        &processHandle,
        0,
        &objectAttributes,
        &clientId);
    SysmonTamperSetStage(SYSMON_TAMPER_STAGE_OPEN_PROCESS);
    SysmonTamperSetStatus(&g_TamperLastOpenProcessStatus, status);
    if (!NT_SUCCESS(status)) {
        InterlockedIncrement(&g_TamperOpenProcessFailCount);
        SysmonTamperSetDecision(SYSMON_TAMPER_DECISION_OPEN_PROCESS_FAIL);
        SysmonTamperRecordFinalDecision(ProcessId, SYSMON_TAMPER_DECISION_OPEN_PROCESS_FAIL);
        goto Cleanup;
    }

    for (stateAttempt = 0;
         stateAttempt < SYSMON_TAMPER_SETTLE_RETRY_ATTEMPTS;
         stateAttempt++) {
        if (currentImagePath != NULL) {
            SysmonFreePool(currentImagePath);
            currentImagePath = NULL;
        }
        processImagePath[0] = L'\0';
        currentImageDosPath[0] = L'\0';
        RtlZeroMemory(mappedImageHeader, sizeof(mappedImageHeader));

        status = SysmonCaptureMainImageStateForProcessHandle(
            processHandle,
            processImagePath,
            RTL_NUMBER_OF(processImagePath),
            mappedImageHeader,
            sizeof(mappedImageHeader));
        SysmonTamperSetStage(SYSMON_TAMPER_STAGE_CAPTURE_STATE);
        SysmonTamperSetStatus(&g_TamperLastCaptureStatus, status);
        if (!NT_SUCCESS(status) || processImagePath[0] == L'\0') {
            if (status == STATUS_NOT_FOUND &&
                stateAttempt + 1 < SYSMON_TAMPER_SETTLE_RETRY_ATTEMPTS) {
                SysmonTamperDelayForSettle();
                continue;
            }

            InterlockedIncrement(&g_TamperCaptureFailCount);
            SysmonTamperSetDecision(SYSMON_TAMPER_DECISION_CAPTURE_FAIL);
            SysmonTamperRecordFinalDecision(ProcessId, SYSMON_TAMPER_DECISION_CAPTURE_FAIL);
            goto Cleanup;
        }

        status = SysmonQueryProcessImagePath(processHandle, &currentImagePath);
        SysmonTamperSetStage(SYSMON_TAMPER_STAGE_QUERY_IMAGE);
        SysmonTamperSetStatus(&g_TamperLastQueryImageStatus, status);
        if (!NT_SUCCESS(status) ||
            currentImagePath == NULL) {
            queryFailureStatus = status;
            if (NT_SUCCESS(queryFailureStatus)) {
                queryFailureStatus = STATUS_NOT_FOUND;
            }
            if (queryFailureStatus == STATUS_NOT_FOUND &&
                stateAttempt + 1 < SYSMON_TAMPER_SETTLE_RETRY_ATTEMPTS) {
                SysmonTamperDelayForSettle();
                continue;
            }

            InterlockedIncrement(&g_TamperQueryImageFailCount);
            SysmonTamperRecordQueryFail(ProcessId, queryFailureStatus);
            if (queryFailureStatus == STATUS_NOT_FOUND &&
                remainingRetryBudget != 0) {
                (void)SysmonTrackProcessWithRetryBudget(
                    ProcessId,
                    remainingRetryBudget - 1);
                SysmonQueueDelayedTamperRetry(ProcessId);
                SysmonTamperSetDecision(SYSMON_TAMPER_DECISION_PENDING_MISS);
                SysmonTamperRecordFinalDecision(
                    ProcessId,
                    SYSMON_TAMPER_DECISION_PENDING_MISS);
                goto Cleanup;
            }

            SysmonTamperSetDecision(SYSMON_TAMPER_DECISION_QUERY_IMAGE_FAIL);
            SysmonTamperRecordFinalDecision(ProcessId, SYSMON_TAMPER_DECISION_QUERY_IMAGE_FAIL);
            goto Cleanup;
        }

        status = SysmonNormalizeProcessImagePath(
            currentImagePath,
            currentImageDosPath,
            RTL_NUMBER_OF(currentImageDosPath));
        SysmonTamperSetStage(SYSMON_TAMPER_STAGE_NORMALIZE_PATH);
        SysmonTamperSetStatus(&g_TamperLastNormalizeStatus, status);
        if (NT_SUCCESS(status) && currentImageDosPath[0] != L'\0') {
            comparableProcessPath = SysmonSkipImagePathPrefix(processImagePath);
            if (!SysmonPathsEqualCaseInsensitive(currentImageDosPath, comparableProcessPath)) {
                if (stateAttempt + 1 < SYSMON_TAMPER_SETTLE_RETRY_ATTEMPTS) {
                    SysmonTamperDelayForSettle();
                    continue;
                }

                persistentPathMismatch = TRUE;
            }
        }

        break;
    }

    if (persistentPathMismatch) {
        InterlockedIncrement(&g_TamperPathMismatchCount);
        SysmonTamperSetDecision(SYSMON_TAMPER_DECISION_PATH_MISMATCH);
        SysmonTamperRecordFinalDecision(ProcessId, SYSMON_TAMPER_DECISION_PATH_MISMATCH);
        SysmonReportTampering(
            ProcessId,
            SYSMON_TAMPER_IMAGE_REPLACED,
            NULL);
        goto Cleanup;
    }

    status = SysmonOpenProcessImageFile(currentImagePath, &fileHandle);
    SysmonTamperSetStage(SYSMON_TAMPER_STAGE_OPEN_IMAGE_FILE);
    SysmonTamperSetStatus(&g_TamperLastOpenFileStatus, status);
    if (!NT_SUCCESS(status)) {
        if (status == STATUS_OBJECT_PATH_NOT_FOUND) {
            InterlockedIncrement(&g_TamperOpenFileDeletedCount);
            SysmonTamperRecordFinalDecision(ProcessId, SYSMON_TAMPER_DECISION_OPEN_FILE_DELETED);
        } else {
            InterlockedIncrement(&g_TamperOpenFileLockedCount);
            SysmonTamperRecordFinalDecision(ProcessId, SYSMON_TAMPER_DECISION_OPEN_FILE_LOCKED);
        }
        SysmonTamperSetDecision(
            (status == STATUS_OBJECT_PATH_NOT_FOUND)
                ? SYSMON_TAMPER_DECISION_OPEN_FILE_DELETED
                : SYSMON_TAMPER_DECISION_OPEN_FILE_LOCKED);
        SysmonReportTampering(
            ProcessId,
            (status == STATUS_OBJECT_PATH_NOT_FOUND)
                ? SYSMON_TAMPER_IMAGE_DELETED
                : SYSMON_TAMPER_IMAGE_LOCKED,
            NULL);
        goto Cleanup;
    }

    fileOffset.QuadPart = 0;
    status = ZwReadFile(
        fileHandle,
        NULL,
        NULL,
        NULL,
        &ioStatusBlock,
        fileImageHeader,
        sizeof(fileImageHeader),
        &fileOffset,
        NULL);
    SysmonTamperSetStage(SYSMON_TAMPER_STAGE_READ_IMAGE_FILE);
    SysmonTamperSetStatus(&g_TamperLastReadFileStatus, status);
    if (!NT_SUCCESS(status) ||
        RtlCompareMemory(
            mappedImageHeader,
            fileImageHeader,
            SYSMON_TAMPER_IMAGE_COMPARE_SIZE) !=
            SYSMON_TAMPER_IMAGE_COMPARE_SIZE) {
        InterlockedIncrement(&g_TamperHeaderMismatchCount);
        SysmonTamperSetDecision(SYSMON_TAMPER_DECISION_HEADER_MISMATCH);
        SysmonTamperRecordFinalDecision(ProcessId, SYSMON_TAMPER_DECISION_HEADER_MISMATCH);
        SysmonReportTampering(
            ProcessId,
            SYSMON_TAMPER_IMAGE_REPLACED,
            NULL);
    } else {
        InterlockedIncrement(&g_TamperCleanCount);
        SysmonTamperSetDecision(SYSMON_TAMPER_DECISION_CLEAN);
        SysmonTamperRecordFinalDecision(ProcessId, SYSMON_TAMPER_DECISION_CLEAN);
    }
    SysmonTamperSetStage(SYSMON_TAMPER_STAGE_COMPLETE);

Cleanup:
    if (fileHandle != NULL) {
        ZwClose(fileHandle);
    }
    if (currentImagePath != NULL) {
        SysmonFreePool(currentImagePath);
    }
    if (processHandle != NULL) {
        ZwClose(processHandle);
    }
}

VOID
SysmonCheckProcessTamperingOnImageLoadSynchronous(_In_ HANDLE ProcessId)
{
    PSYSMON_TAMPER_WORK_ITEM workItem;
    LARGE_INTEGER timeout;

    if (ProcessId == NULL) {
        return;
    }

    workItem = (PSYSMON_TAMPER_WORK_ITEM)SysmonAllocatePool(sizeof(*workItem));
    if (workItem == NULL) {
        DbgPrintEx(
            DPFLTR_DEFAULT_ID,
            DPFLTR_WARNING_LEVEL,
            "[SysmonDrv] Tampering: failed to allocate synchronous image-load work item for pid=%lu\n",
            HandleToULong(ProcessId));
        return;
    }

    RtlZeroMemory(workItem, sizeof(*workItem));
    workItem->ProcessId = ProcessId;
    workItem->ReferenceCount = 2; /* one for the worker, one for us (waiter) */

    /* Hold TWO driver rundown references: one for the worker's lifetime (so a
       timed-out waiter cannot let the driver unload while the system work item
       is still running driver code), and one for our own execution below (the
       worker releases the first, we release the second). If the driver is
       already unloading, skip the check. */
    if (!SysmonAcquireDriverRundown()) {
        SysmonFreePool(workItem);
        return;
    }
    if (!SysmonAcquireDriverRundown()) {
        SysmonReleaseDriverRundown();
        SysmonFreePool(workItem);
        return;
    }

    KeInitializeEvent(&workItem->CompletionEvent, NotificationEvent, FALSE);
    ExInitializeWorkItem(
        &workItem->WorkItem,
        SysmonTamperWorkItemRoutine,
        workItem);
    ExQueueWorkItem(&workItem->WorkItem, DelayedWorkQueue);

    /* The synchronous handoff is intentional (Event 25 must observe the
       post-create file state), but the wait is bounded so a starved worker can
       never hang the image-load callback indefinitely. On timeout the check is
       deferred for this load (the queued worker still runs it later). */
    timeout.QuadPart = -(SYSMON_TAMPER_IMAGE_LOAD_WAIT_TIMEOUT_MS * 10000);
    (void)KeWaitForSingleObject(
        &workItem->CompletionEvent,
        Executive,
        KernelMode,
        FALSE,
        &timeout);

    /* Release our reference; the worker holds its own until after it signals,
       so the item stays alive for the full wait. */
    if (InterlockedDecrement(&workItem->ReferenceCount) == 0) {
        SysmonFreePool(workItem);
    }

    /* Release our own rundown reference; the worker releases the one acquired
       for it. The driver stays loaded until both sides have fully finished. */
    SysmonReleaseDriverRundown();
}

VOID
SysmonQueryTamperingDebugStats(
    _Out_ PSYSMON_PROCESS_DEBUG_STATS Stats)
{
    if (Stats == NULL) {
        return;
    }

    Stats->TamperTrackProcessCount =
        (ULONG)InterlockedCompareExchange(&g_TamperTrackProcessCount, 0, 0);
    Stats->TamperCheckCallCount =
        (ULONG)InterlockedCompareExchange(&g_TamperCheckCallCount, 0, 0);
    Stats->TamperPendingHitCount =
        (ULONG)InterlockedCompareExchange(&g_TamperPendingHitCount, 0, 0);
    Stats->TamperUntrackMissCount =
        (ULONG)InterlockedCompareExchange(&g_TamperUntrackMissCount, 0, 0);
    Stats->TamperReportCount =
        (ULONG)InterlockedCompareExchange(&g_TamperReportCount, 0, 0);
    Stats->TamperLastProcessId =
        (ULONG)InterlockedCompareExchange(&g_TamperLastProcessId, 0, 0);
    Stats->TamperLastStage =
        (ULONG)InterlockedCompareExchange(&g_TamperLastStage, 0, 0);
    Stats->TamperLastDecision =
        (ULONG)InterlockedCompareExchange(&g_TamperLastDecision, 0, 0);
    Stats->TamperLastOpenProcessStatus =
        (ULONG)InterlockedCompareExchange(&g_TamperLastOpenProcessStatus, 0, 0);
    Stats->TamperLastCaptureStatus =
        (ULONG)InterlockedCompareExchange(&g_TamperLastCaptureStatus, 0, 0);
    Stats->TamperLastQueryImageStatus =
        (ULONG)InterlockedCompareExchange(&g_TamperLastQueryImageStatus, 0, 0);
    Stats->TamperLastNormalizeStatus =
        (ULONG)InterlockedCompareExchange(&g_TamperLastNormalizeStatus, 0, 0);
    Stats->TamperLastOpenFileStatus =
        (ULONG)InterlockedCompareExchange(&g_TamperLastOpenFileStatus, 0, 0);
    Stats->TamperLastReadFileStatus =
        (ULONG)InterlockedCompareExchange(&g_TamperLastReadFileStatus, 0, 0);
    Stats->TamperLookupProcessFailCount =
        (ULONG)InterlockedCompareExchange(&g_TamperLookupProcessFailCount, 0, 0);
    Stats->TamperOpenProcessFailCount =
        (ULONG)InterlockedCompareExchange(&g_TamperOpenProcessFailCount, 0, 0);
    Stats->TamperCaptureFailCount =
        (ULONG)InterlockedCompareExchange(&g_TamperCaptureFailCount, 0, 0);
    Stats->TamperQueryImageFailCount =
        (ULONG)InterlockedCompareExchange(&g_TamperQueryImageFailCount, 0, 0);
    Stats->TamperLastQueryFailProcessId =
        (ULONG)InterlockedCompareExchange(&g_TamperLastQueryFailProcessId, 0, 0);
    Stats->TamperLastQueryFailStatus =
        (ULONG)InterlockedCompareExchange(&g_TamperLastQueryFailStatus, 0, 0);
    Stats->TamperPathMismatchCount =
        (ULONG)InterlockedCompareExchange(&g_TamperPathMismatchCount, 0, 0);
    Stats->TamperOpenFileDeletedCount =
        (ULONG)InterlockedCompareExchange(&g_TamperOpenFileDeletedCount, 0, 0);
    Stats->TamperOpenFileLockedCount =
        (ULONG)InterlockedCompareExchange(&g_TamperOpenFileLockedCount, 0, 0);
    Stats->TamperHeaderMismatchCount =
        (ULONG)InterlockedCompareExchange(&g_TamperHeaderMismatchCount, 0, 0);
    Stats->TamperCleanCount =
        (ULONG)InterlockedCompareExchange(&g_TamperCleanCount, 0, 0);
    Stats->TamperRecentTrackPid0 =
        (ULONG)InterlockedCompareExchange(&g_TamperRecentTrackPid[0], 0, 0);
    Stats->TamperRecentTrackPid1 =
        (ULONG)InterlockedCompareExchange(&g_TamperRecentTrackPid[1], 0, 0);
    Stats->TamperRecentTrackPid2 =
        (ULONG)InterlockedCompareExchange(&g_TamperRecentTrackPid[2], 0, 0);
    Stats->TamperRecentTrackPid3 =
        (ULONG)InterlockedCompareExchange(&g_TamperRecentTrackPid[3], 0, 0);
    Stats->TamperRecentDecisionPid0 =
        (ULONG)InterlockedCompareExchange(&g_TamperRecentDecisionPid[0], 0, 0);
    Stats->TamperRecentDecisionPid1 =
        (ULONG)InterlockedCompareExchange(&g_TamperRecentDecisionPid[1], 0, 0);
    Stats->TamperRecentDecisionPid2 =
        (ULONG)InterlockedCompareExchange(&g_TamperRecentDecisionPid[2], 0, 0);
    Stats->TamperRecentDecisionPid3 =
        (ULONG)InterlockedCompareExchange(&g_TamperRecentDecisionPid[3], 0, 0);
    Stats->TamperRecentDecisionCode0 =
        (ULONG)InterlockedCompareExchange(&g_TamperRecentDecisionCode[0], 0, 0);
    Stats->TamperRecentDecisionCode1 =
        (ULONG)InterlockedCompareExchange(&g_TamperRecentDecisionCode[1], 0, 0);
    Stats->TamperRecentDecisionCode2 =
        (ULONG)InterlockedCompareExchange(&g_TamperRecentDecisionCode[2], 0, 0);
    Stats->TamperRecentDecisionCode3 =
        (ULONG)InterlockedCompareExchange(&g_TamperRecentDecisionCode[3], 0, 0);
}

static VOID
TamperingProcessNotifyCallback(
    _Inout_ PEPROCESS Process,
    _In_ HANDLE ProcessId,
    _Inout_opt_ PPS_CREATE_NOTIFY_INFO CreateInfo)
{
    UNREFERENCED_PARAMETER(Process);

    if (CreateInfo != NULL) {
        SysmonTrackProcessIfEnabled(ProcessId);
    }
}

static VOID
TamperingProcessNotifyCallbackLegacy(
    _In_ HANDLE ParentProcessId,
    _In_ HANDLE ProcessId,
    _In_ BOOLEAN Create)
{
    UNREFERENCED_PARAMETER(ParentProcessId);

    if (Create) {
        SysmonTrackProcessIfEnabled(ProcessId);
    }
}

NTSTATUS
SysmonRegisterTamperingDetection(_In_ PDRIVER_OBJECT DriverObject)
{
    NTSTATUS status;
    NTSTATUS ex2Status;
    NTSTATUS legacyStatus;
    UNICODE_STRING routineName;

    UNREFERENCED_PARAMETER(DriverObject);

    if (g_TamperingInitialized) {
        return STATUS_SUCCESS;
    }

    InitializeListHead(&g_ProcessTrackList);
    ExInitializeFastMutex(&g_ProcessTrackLock);
    g_TrackedProcessCount = 0;

    if (g_TamperingProcessNotifyRoutineEx2 == NULL) {
        RtlInitUnicodeString(&routineName, L"PsSetCreateProcessNotifyRoutineEx2");
        g_TamperingProcessNotifyRoutineEx2 =
            (PFN_PS_SET_CREATE_PROCESS_NOTIFY_ROUTINE_EX2)
                MmGetSystemRoutineAddress(&routineName);
    }

    if (g_TamperingProcessNotifyRoutineLegacy == NULL) {
        RtlInitUnicodeString(&routineName, L"PsSetCreateProcessNotifyRoutine");
        g_TamperingProcessNotifyRoutineLegacy =
            (PFN_PS_SET_CREATE_PROCESS_NOTIFY_ROUTINE)
                MmGetSystemRoutineAddress(&routineName);
    }

    status = STATUS_PROCEDURE_NOT_FOUND;
    ex2Status = STATUS_PROCEDURE_NOT_FOUND;
    legacyStatus = STATUS_PROCEDURE_NOT_FOUND;
    if (g_TamperingProcessNotifyRoutineEx2 != NULL) {
        ex2Status = g_TamperingProcessNotifyRoutineEx2(
            SYSMON_PS_CREATE_PROCESS_NOTIFY_SUBSYSTEMS,
            (PVOID)TamperingProcessNotifyCallback,
            FALSE);
        if (NT_SUCCESS(ex2Status)) {
            g_TamperingProcessNotifyRegisteredEx2 = TRUE;
            status = STATUS_SUCCESS;
        } else {
            DbgPrintEx(
                DPFLTR_DEFAULT_ID,
                DPFLTR_WARNING_LEVEL,
                "[SysmonDrv] Tampering: PsSetCreateProcessNotifyRoutineEx2 failed: 0x%08X\n",
                ex2Status);
        }
    }

    if (g_TamperingProcessNotifyRoutineLegacy != NULL) {
        legacyStatus = g_TamperingProcessNotifyRoutineLegacy(
            TamperingProcessNotifyCallbackLegacy,
            FALSE);
        if (NT_SUCCESS(legacyStatus)) {
            g_TamperingProcessNotifyRegisteredLegacy = TRUE;
            status = STATUS_SUCCESS;
        } else {
            DbgPrintEx(
                DPFLTR_DEFAULT_ID,
                DPFLTR_WARNING_LEVEL,
                "[SysmonDrv] Tampering: PsSetCreateProcessNotifyRoutine failed: 0x%08X\n",
                legacyStatus);
        }
    }

    if (!NT_SUCCESS(status)) {
        DbgPrintEx(
            DPFLTR_DEFAULT_ID,
            DPFLTR_WARNING_LEVEL,
            "[SysmonDrv] Tampering: no compatible process notify routine available (ex2=0x%08X legacy=0x%08X)\n",
            ex2Status,
            legacyStatus);
        return status;
    }

    if (!g_TamperingProcessNotifyRegisteredEx2 &&
        !g_TamperingProcessNotifyRegisteredLegacy) {
        DbgPrintEx(
            DPFLTR_DEFAULT_ID,
            DPFLTR_WARNING_LEVEL,
            "[SysmonDrv] Tampering: registration unexpectedly reported success without active callbacks\n",
            status);
        return status;
    }

    g_TamperingInitialized = TRUE;
    DbgPrintEx(
        DPFLTR_DEFAULT_ID,
        DPFLTR_INFO_LEVEL,
        "[SysmonDrv] ProcessTampering detection registered using %s%s callbacks\n",
        g_TamperingProcessNotifyRegisteredEx2 ? "Ex2" : "",
        g_TamperingProcessNotifyRegisteredLegacy ? (g_TamperingProcessNotifyRegisteredEx2 ? "+legacy" : "legacy") : "");
    return STATUS_SUCCESS;
}

VOID
SysmonUnregisterTamperingDetection(VOID)
{
    PLIST_ENTRY entry;

    if (!g_TamperingInitialized) {
        return;
    }

    if (g_TamperingProcessNotifyRegisteredEx2 &&
        g_TamperingProcessNotifyRoutineEx2 != NULL) {
        g_TamperingProcessNotifyRoutineEx2(
            SYSMON_PS_CREATE_PROCESS_NOTIFY_SUBSYSTEMS,
            (PVOID)TamperingProcessNotifyCallback,
            TRUE);
        g_TamperingProcessNotifyRegisteredEx2 = FALSE;
    }
    if (g_TamperingProcessNotifyRegisteredLegacy &&
        g_TamperingProcessNotifyRoutineLegacy != NULL) {
        g_TamperingProcessNotifyRoutineLegacy(
            TamperingProcessNotifyCallbackLegacy,
            TRUE);
        g_TamperingProcessNotifyRegisteredLegacy = FALSE;
    }

    ExAcquireFastMutex(&g_ProcessTrackLock);
    while (!IsListEmpty(&g_ProcessTrackList)) {
        entry = RemoveHeadList(&g_ProcessTrackList);
        SysmonFreePool(CONTAINING_RECORD(entry, SYSMON_PROCESS_TRACK, ListEntry));
    }
    ExReleaseFastMutex(&g_ProcessTrackLock);

    g_TrackedProcessCount = 0;
    g_TamperingInitialized = FALSE;
    DbgPrintEx(
        DPFLTR_DEFAULT_ID,
        DPFLTR_INFO_LEVEL,
        "[SysmonDrv] ProcessTampering detection unregistered\n");
}

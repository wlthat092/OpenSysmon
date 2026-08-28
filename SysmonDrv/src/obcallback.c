#include "obcallback.h"
#include "queue.h"
#include "event.h"
#include "driver.h"
#include "process.h"
#include "processinfo.h"
#include "rules.h"
#include "utils.h"

/*
 * ProcessAccess (Event 10) implementation via ObRegisterCallbacks
 *
 * Original SysmonDrv approach (from pseudo-code):
 *   1. Dynamically resolves ObRegisterCallbacks/ObUnRegisterCallbacks via
 *      MmGetSystemRoutineAddress (for OS compatibility)
 *   2. Also resolves PsAcquireProcessExitSynchronization /
 *      PsReleaseProcessExitSynchronization
 *   3. Registers OB_OPERATION_REGISTRATION for PsProcessType
 *   4. Pre-operation callback:
 *      - Checks OB_OPERATION_HANDLE_CREATE and OB_OPERATION_HANDLE_DUPLICATE
 *      - Filters cross-process access (source PID != target PID)
 *      - Copies operation info to work item, queues to IoWorkItem
 *      - Work item processes: generates event, enqueues
 *   5. Uses call stack capture for CallTrace field
 */

/* Dynamic function pointers (resolved at runtime) */
typedef NTSTATUS (*PFN_OB_REGISTER_CALLBACKS)(
    _In_ POB_CALLBACK_REGISTRATION CallbackRegistration,
    _Out_ PVOID *RegistrationHandle);

typedef VOID (*PFN_OB_UNREGISTER_CALLBACKS)(
    _In_ PVOID RegistrationHandle);

typedef NTSTATUS (*PFN_PS_ACQUIRE_PROCESS_EXIT_SYNCHRONIZATION)(
    _In_ PEPROCESS Process);

typedef VOID (*PFN_PS_RELEASE_PROCESS_EXIT_SYNCHRONIZATION)(
    _In_ PEPROCESS Process);

static PFN_OB_REGISTER_CALLBACKS g_ObRegisterCallbacks = NULL;
static PFN_OB_UNREGISTER_CALLBACKS g_ObUnRegisterCallbacks = NULL;
static PFN_PS_ACQUIRE_PROCESS_EXIT_SYNCHRONIZATION g_PsAcquireProcessExitSync = NULL;
static PFN_PS_RELEASE_PROCESS_EXIT_SYNCHRONIZATION g_PsReleaseProcessExitSync = NULL;

/* Registration state */
static PVOID g_ObRegistrationHandle = NULL;
static BOOLEAN g_ObCallbacksRegistered = FALSE;

/* OB object type (filled at registration time) */
static PVOID *g_PsProcessTypePtr = NULL;

/* Access filter configuration */
static SYSMON_ACCESS_FILTER g_AccessFilter;
static FAST_MUTEX g_AccessFilterLock;

/* Work item queue for deferred event generation */
typedef struct _SYSMON_OB_WORK_ITEM {
    LIST_ENTRY ListEntry;
    HANDLE SourcePid;
    HANDLE SourceTid;
    HANDLE TargetPid;
    ACCESS_MASK GrantedAccess;
    LONGLONG Timestamp;
    USHORT CallTraceFrameCount;
    PVOID CallTraceFrames[24];
} SYSMON_OB_WORK_ITEM, *PSYSMON_OB_WORK_ITEM;

static LIST_ENTRY g_ObWorkItemList;
static FAST_MUTEX g_ObWorkListLock;
static PIO_WORKITEM g_ObWorkItem = NULL;
static volatile LONG g_ObWorkItemCount = 0;
static volatile LONG g_ObWorkerQueued = 0;
static volatile LONG g_ObRegisterAttemptCount = 0;
static volatile LONG g_ObRegisterSuccessCount = 0;
static volatile LONG g_ObRegisterLastStatus = STATUS_SUCCESS;
static volatile LONG g_ObPostCallbackCount = 0;
static volatile LONG g_ObWorkItemQueuedCount = 0;
static volatile LONG g_ObWorkItemProcessedCount = 0;
static volatile LONG g_ObEventPublishedCount = 0;
static volatile LONG g_ObDropObjectTypeMismatchCount = 0;
static volatile LONG g_ObDropOperationMismatchCount = 0;
static volatile LONG g_ObDropKernelHandleCount = 0;
static volatile LONG g_ObDropSameProcessCount = 0;
static volatile LONG g_ObDropQueueLimitCount = 0;
static volatile LONG g_ObDropWorkerUnavailableCount = 0;
static volatile LONG g_ObDropAllocationFailureCount = 0;
static KEVENT g_ObWorkerIdleEvent;
static BOOLEAN g_ObWorkerInitialized = FALSE;
static BOOLEAN g_ObInfrastructureInitialized = FALSE;

extern PCHAR PsGetProcessImageFileName(_In_ PEPROCESS Process);

/*
 * Temporary stability gate:
 * Event 10 used to be force-disabled during BSOD isolation. The current
 * worker-based path is the supported implementation, so keep callbacks live.
 */
static const BOOLEAN g_ObCallbacksTemporarilyDisabled = FALSE;

static VOID
SysmonObWorkItemCallback(_In_ PDEVICE_OBJECT DeviceObject, _In_opt_ PVOID Context);

static VOID
SysmonPopulateProcessIdentity(
    _In_ HANDLE ProcessId,
    _Out_ PSYSMON_PROCESS_INFO Info)
{
    SYSMON_PROCESS_CACHE_METADATA cachedMetadata;
    PEPROCESS process;

    if (Info == NULL) {
        return;
    }

    RtlZeroMemory(Info, sizeof(*Info));
    Info->ProcessId = HandleToULong(ProcessId);

    RtlZeroMemory(&cachedMetadata, sizeof(cachedMetadata));
    if (SysmonLookupCachedProcessMetadata(HandleToULong(ProcessId), &cachedMetadata)) {
        Info->CreateTime = cachedMetadata.CreateTime;
        SysmonCopyWideStringWithLength(
            Info->ProcessGuid,
            RTL_NUMBER_OF(Info->ProcessGuid),
            cachedMetadata.ProcessGuid,
            SYSMON_GUID_STRING_CHARS);
        SysmonCopyWideString(
            Info->ImagePath,
            RTL_NUMBER_OF(Info->ImagePath),
            cachedMetadata.Image);
        SysmonCopyWideString(
            Info->UserSid,
            RTL_NUMBER_OF(Info->UserSid),
            cachedMetadata.UserSid);
    }

    if (Info->ImagePath[0] == L'\0' &&
        NT_SUCCESS(PsLookupProcessByProcessId(ProcessId, &process))) {
        /*
         * Event 10 runs under OB callbacks and is particularly sensitive during
         * logon and shutdown churn. Avoid reopening the process here; a stable
         * basename fallback is safer than another trip through object-manager
         * and token/query paths.
         */
        (void)SysmonAnsiToWide(
            PsGetProcessImageFileName(process),
            Info->ImagePath,
            RTL_NUMBER_OF(Info->ImagePath));
        ObDereferenceObject(process);
    }

    if (Info->CreateTime == 0) {
        Info->CreateTime = SysmonGetCurrentTimestamp();
    }
    if (Info->ProcessGuid[0] == L'\0') {
        SysmonGenerateProcessGuid(Info->ProcessId, Info->CreateTime, Info->ProcessGuid);
    }
}

static BOOLEAN
SysmonProcessAccessPathLooksComplete(
    _In_opt_z_ PCWSTR ImagePath)
{
    return ImagePath != NULL &&
        ImagePath[0] != L'\0' &&
        (_wcsicmp(ImagePath, L"System") == 0 ||
         wcschr(ImagePath, L'\\') != NULL ||
         wcschr(ImagePath, L':') != NULL);
}

static VOID
SysmonOverlayProcessAccessIdentityFromProcessInfo(
    _Inout_ PSYSMON_PROCESS_INFO Identity,
    _In_ const SYSMON_PROCESS_INFO *Info)
{
    if (Identity == NULL || Info == NULL) {
        return;
    }

    if (Identity->CreateTime == 0 && Info->CreateTime != 0) {
        Identity->CreateTime = Info->CreateTime;
    }
    if (Identity->ProcessGuid[0] == L'\0' && Info->ProcessGuid[0] != L'\0') {
        SysmonCopyWideStringWithLength(
            Identity->ProcessGuid,
            RTL_NUMBER_OF(Identity->ProcessGuid),
            Info->ProcessGuid,
            SYSMON_GUID_STRING_CHARS);
    }
    if (!SysmonProcessAccessPathLooksComplete(Identity->ImagePath) &&
        Info->ImagePath[0] != L'\0') {
        SysmonCopyWideString(
            Identity->ImagePath,
            RTL_NUMBER_OF(Identity->ImagePath),
            Info->ImagePath);
    }
    if (Identity->UserSid[0] == L'\0' && Info->UserSid[0] != L'\0') {
        SysmonCopyWideString(
            Identity->UserSid,
            RTL_NUMBER_OF(Identity->UserSid),
            Info->UserSid);
    }
    if (Identity->SessionId == 0 && Info->SessionId != 0) {
        Identity->SessionId = Info->SessionId;
    }
}

static VOID
SysmonEnrichProcessAccessIdentity(
    _In_ HANDLE ProcessId,
    _Inout_ PSYSMON_PROCESS_INFO Identity)
{
    PSYSMON_PROCESS_INFO processInfo;
    NTSTATUS status;
    BOOLEAN needsFullPath;
    BOOLEAN needsUser;

    if (Identity == NULL) {
        return;
    }

    needsFullPath = !SysmonProcessAccessPathLooksComplete(Identity->ImagePath);
    needsUser = Identity->UserSid[0] == L'\0';
    if (!needsFullPath &&
        !needsUser &&
        Identity->ProcessGuid[0] != L'\0' &&
        Identity->CreateTime != 0) {
        return;
    }

    (void)SysmonTryFinalizePendingProcessCreate(ProcessId);

    processInfo = (PSYSMON_PROCESS_INFO)SysmonAllocatePool(sizeof(*processInfo));
    if (processInfo == NULL) {
        goto FinalizeIdentity;
    }

    status = needsUser
        ? SysmonCollectProcessTokenIdentity(ProcessId, processInfo)
        : SysmonCollectProcessIdentity(ProcessId, processInfo);
    if (!NT_SUCCESS(status) && needsUser) {
        RtlZeroMemory(processInfo, sizeof(*processInfo));
        status = SysmonCollectProcessIdentity(ProcessId, processInfo);
    }

    if (NT_SUCCESS(status)) {
        SysmonOverlayProcessAccessIdentityFromProcessInfo(Identity, processInfo);
    }

    SysmonFreePool(processInfo);

FinalizeIdentity:
    if (Identity->CreateTime == 0) {
        Identity->CreateTime = SysmonGetCurrentTimestamp();
    }
    if (Identity->ProcessGuid[0] == L'\0') {
        SysmonGenerateProcessGuid(
            Identity->ProcessId,
            Identity->CreateTime,
            Identity->ProcessGuid);
    }
}

static VOID
SysmonFormatRawCallTrace(
    _In_reads_(FrameCount) PVOID *Frames,
    _In_ USHORT FrameCount,
    _Out_writes_(BufferChars) PWCHAR Buffer,
    _In_ ULONG BufferChars)
{
    USHORT index;
    PWCHAR cursor;
    SIZE_T usedChars;
    SIZE_T remainingChars;
    int written;

    if (Buffer == NULL || BufferChars == 0) {
        return;
    }

    Buffer[0] = L'\0';
    if (Frames == NULL || FrameCount == 0) {
        return;
    }

    cursor = Buffer;
    remainingChars = BufferChars;
    for (index = 0; index < FrameCount && remainingChars > 20; index++) {
        written = _snwprintf_s(
            cursor,
            remainingChars,
            _TRUNCATE,
            L"%p|",
            Frames[index]);
        if (written <= 0) {
            break;
        }

        usedChars = wcslen(cursor);
        cursor += usedChars;
        remainingChars -= usedChars;
    }

    if (cursor != Buffer && cursor[-1] == L'|') {
        cursor[-1] = L'\0';
    }
}

static VOID
SysmonObPostOperationCallback(
    _In_ PVOID RegistrationContext,
    _In_ POB_POST_OPERATION_INFORMATION OperationInformation);

static VOID
SysmonInitializeObInfrastructure(VOID)
{
    if (g_ObInfrastructureInitialized) {
        return;
    }

    ExInitializeFastMutex(&g_AccessFilterLock);
    ExInitializeFastMutex(&g_ObWorkListLock);
    InitializeListHead(&g_ObWorkItemList);
    KeInitializeEvent(&g_ObWorkerIdleEvent, NotificationEvent, TRUE);
    g_ObWorkerQueued = 0;
    g_ObWorkItemCount = 0;
    g_AccessFilter.Count = 0;
    g_ObInfrastructureInitialized = TRUE;
}

VOID
SysmonQueryObDebugStats(
    _Out_ PSYSMON_PROCESS_DEBUG_STATS Stats)
{
    if (Stats == NULL) {
        return;
    }

    Stats->ObRegisterAttemptCount = (ULONG)g_ObRegisterAttemptCount;
    Stats->ObRegisterSuccessCount = (ULONG)g_ObRegisterSuccessCount;
    Stats->ObRegisterLastStatus = (ULONG)g_ObRegisterLastStatus;
    Stats->ObPostCallbackCount = (ULONG)g_ObPostCallbackCount;
    Stats->ObWorkItemQueuedCount = (ULONG)g_ObWorkItemQueuedCount;
    Stats->ObWorkItemProcessedCount = (ULONG)g_ObWorkItemProcessedCount;
    Stats->ObEventPublishedCount = (ULONG)g_ObEventPublishedCount;
    Stats->ObDropObjectTypeMismatch = (ULONG)g_ObDropObjectTypeMismatchCount;
    Stats->ObDropOperationMismatch = (ULONG)g_ObDropOperationMismatchCount;
    Stats->ObDropKernelHandle = (ULONG)g_ObDropKernelHandleCount;
    Stats->ObDropSameProcess = (ULONG)g_ObDropSameProcessCount;
    Stats->ObDropQueueLimit = (ULONG)g_ObDropQueueLimitCount;
    Stats->ObDropWorkerUnavailable = (ULONG)g_ObDropWorkerUnavailableCount;
    Stats->ObDropAllocationFailure = (ULONG)g_ObDropAllocationFailureCount;
}

/*
 * SysmonSetAccessFilter - Update the access mask filter configuration
 */
VOID
SysmonSetAccessFilter(
    _In_ ULONG Count,
    _In_reads_(Count) ACCESS_MASK *Masks,
    _In_reads_(Count_opt) WCHAR *Names)
{
    ULONG i;

    SysmonInitializeObInfrastructure();

    ExAcquireFastMutex(&g_AccessFilterLock);

    RtlZeroMemory(&g_AccessFilter, sizeof(g_AccessFilter));
    g_AccessFilter.Count = min(Count, SYSMON_MAX_ACCESS_MASKS);
    for (i = 0; i < g_AccessFilter.Count; i++) {
        g_AccessFilter.Masks[i] = Masks[i];
        if (Names != NULL) {
            RtlCopyMemory(g_AccessFilter.Names[i],
                Names + (i * 64), 64 * sizeof(WCHAR));
        } else {
            g_AccessFilter.Names[i][0] = L'\0';
        }
    }

    ExReleaseFastMutex(&g_AccessFilterLock);
}

static BOOLEAN
SysmonExtractImageBaseName(
    _In_opt_z_ PCWSTR ImagePath,
    _Out_writes_(BufferChars) PWCHAR Buffer,
    _In_ ULONG BufferChars)
{
    PCWSTR baseName;
    PCWSTR cursor;
    SIZE_T copyChars;

    if (Buffer == NULL || BufferChars == 0) {
        return FALSE;
    }

    Buffer[0] = L'\0';
    if (ImagePath == NULL || ImagePath[0] == L'\0') {
        return FALSE;
    }

    baseName = ImagePath;
    for (cursor = ImagePath; *cursor != L'\0'; cursor++) {
        if (*cursor == L'\\') {
            baseName = cursor + 1;
        }
    }

    if (*baseName == L'\0') {
        return FALSE;
    }

    copyChars = wcslen(baseName);
    if (copyChars >= BufferChars) {
        copyChars = BufferChars - 1;
    }

    RtlCopyMemory(Buffer, baseName, copyChars * sizeof(WCHAR));
    Buffer[copyChars] = L'\0';
    return TRUE;
}

static BOOLEAN
SysmonShouldReportProcessAccess(
    _In_opt_z_ PCWSTR TargetImagePath,
    _In_ ACCESS_MASK GrantedAccess)
{
    WCHAR baseName[64];
    ULONG index;
    BOOLEAN allow;

    ExAcquireFastMutex(&g_AccessFilterLock);

    if (g_AccessFilter.Count == 0) {
        ExReleaseFastMutex(&g_AccessFilterLock);
        return TRUE;
    }

    if (!SysmonExtractImageBaseName(TargetImagePath, baseName, RTL_NUMBER_OF(baseName))) {
        ExReleaseFastMutex(&g_AccessFilterLock);
        return FALSE;
    }

    allow = FALSE;
    for (index = 0; index < g_AccessFilter.Count; index++) {
        if (g_AccessFilter.Names[index][0] == L'\0') {
            continue;
        }
        if (_wcsicmp(g_AccessFilter.Names[index], baseName) == 0 &&
            (GrantedAccess & g_AccessFilter.Masks[index]) != 0) {
            allow = TRUE;
            break;
        }
    }

    ExReleaseFastMutex(&g_AccessFilterLock);
    return allow;
}

static volatile LONG g_ProcessAccessSequence = 0;

static VOID
SysmonQueueObWorker(VOID)
{
    if (g_ObWorkItem == NULL) {
        return;
    }

    if (InterlockedCompareExchange(&g_ObWorkerQueued, 1, 0) == 0) {
        KeClearEvent(&g_ObWorkerIdleEvent);
        IoQueueWorkItem(g_ObWorkItem, SysmonObWorkItemCallback, DelayedWorkQueue, NULL);
    }
}

static VOID
SysmonCaptureCallTraceFrames(_Out_ PSYSMON_OB_WORK_ITEM WorkItem)
{
    ULONG frameCount;

    if (WorkItem == NULL) {
        return;
    }

    RtlZeroMemory(WorkItem->CallTraceFrames, sizeof(WorkItem->CallTraceFrames));
    frameCount = RtlWalkFrameChain(
        WorkItem->CallTraceFrames,
        RTL_NUMBER_OF(WorkItem->CallTraceFrames),
        1u);
    if (frameCount > RTL_NUMBER_OF(WorkItem->CallTraceFrames)) {
        frameCount = RTL_NUMBER_OF(WorkItem->CallTraceFrames);
    }
    WorkItem->CallTraceFrameCount = (USHORT)frameCount;
}

static VOID
SysmonFormatCallTrace(
    _In_ HANDLE ProcessId,
    _In_reads_(FrameCount) PVOID *Frames,
    _In_ USHORT FrameCount,
    _Out_writes_(BufferChars) PWCHAR Buffer,
    _In_ ULONG BufferChars)
{
    NTSTATUS status;

    if (Buffer == NULL || BufferChars == 0) {
        return;
    }

    Buffer[0] = L'\0';
    status = SysmonFormatCallTraceForProcess(
        ProcessId,
        Frames,
        FrameCount,
        Buffer,
        BufferChars);
    if (!NT_SUCCESS(status) || Buffer[0] == L'\0') {
        SysmonFormatRawCallTrace(
            Frames,
            FrameCount,
            Buffer,
            BufferChars);
    }
}

static VOID
SysmonRefreshProcessTokenIdentity(
    _In_ HANDLE ProcessId,
    _Inout_ PSYSMON_PROCESS_INFO Info)
{
    SYSMON_PROCESS_INFO tokenInfo;

    if (Info == NULL) {
        return;
    }

    RtlZeroMemory(&tokenInfo, sizeof(tokenInfo));
    if (NT_SUCCESS(SysmonCollectProcessTokenIdentity(ProcessId, &tokenInfo))) {
        RtlCopyMemory(Info, &tokenInfo, sizeof(tokenInfo));
    }
}

static PSYSMON_EVENT_UNION
SysmonAllocateScratchProcessAccessEvent(
    _In_ LONGLONG Timestamp)
{
    PSYSMON_EVENT_UNION event;

    event = (PSYSMON_EVENT_UNION)SysmonAllocatePool(sizeof(SYSMON_EVENT_UNION));
    if (event == NULL) {
        return NULL;
    }

    RtlZeroMemory(event, sizeof(*event));
    event->Header.EventId = SysmonEventProcessAccess;
    event->Header.EventSize = sizeof(*event);
    event->Header.Timestamp = Timestamp;
    return event;
}

static VOID
SysmonFreeScratchProcessAccessEvent(
    _In_opt_ PSYSMON_EVENT_UNION Event)
{
    SysmonFreePool(Event);
}

static VOID
SysmonBuildProcessAccessEventPayload(
    _Inout_ PSYSMON_EVENT_UNION Event,
    _In_ PSYSMON_OB_WORK_ITEM Item,
    _In_ const SYSMON_PROCESS_INFO *SourceInfo,
    _In_ const SYSMON_PROCESS_INFO *TargetInfo,
    _In_opt_z_ PCWSTR CallTrace,
    _In_ BOOLEAN IncludeUsers,
    _In_ BOOLEAN AssignFinalSequence)
{
    SYSMON_EVENT_PROCESS_ACCESS_PAYLOAD *eventData;
    SYSMON_EVENT_PAYLOAD_BUILDER builder;

    if (Event == NULL || Item == NULL || SourceInfo == NULL || TargetInfo == NULL) {
        return;
    }

    if (AssignFinalSequence) {
        Event->Header.SequenceNumber = (ULONG)InterlockedIncrement(&g_ProcessAccessSequence);
    } else {
        Event->Header.SequenceNumber = 0;
    }
    Event->Header.Timestamp = Item->Timestamp;

    eventData = (SYSMON_EVENT_PROCESS_ACCESS_PAYLOAD *)Event->RawData;
    SysmonBeginStringPayload(Event, sizeof(*eventData), &builder);
    (void)SysmonAddStringLiteralField(Event, &builder, &eventData->RuleName, L"-");
    (void)SysmonAddCurrentUtcTimeField(Event, &builder, &eventData->UtcTime);
    (void)SysmonAddFixedLengthStringField(
        Event,
        &builder,
        &eventData->SourceProcessGUID,
        SourceInfo->ProcessGuid,
        SYSMON_GUID_STRING_CHARS);
    eventData->SourceProcessId = (ULONG)(ULONG_PTR)Item->SourcePid;
    eventData->SourceThreadId = (ULONG)(ULONG_PTR)Item->SourceTid;
    (void)SysmonAddStringField(Event, &builder, &eventData->SourceImage, SourceInfo->ImagePath);
    (void)SysmonAddFixedLengthStringField(
        Event,
        &builder,
        &eventData->TargetProcessGUID,
        TargetInfo->ProcessGuid,
        SYSMON_GUID_STRING_CHARS);
    eventData->TargetProcessId = (ULONG)(ULONG_PTR)Item->TargetPid;
    (void)SysmonAddStringField(Event, &builder, &eventData->TargetImage, TargetInfo->ImagePath);
    eventData->GrantedAccess = (ULONG)Item->GrantedAccess;
    (void)SysmonAddStringField(Event, &builder, &eventData->CallTrace, CallTrace);
    (void)SysmonAddStringField(
        Event,
        &builder,
        &eventData->SourceUser,
        IncludeUsers ? SourceInfo->UserSid : NULL);
    (void)SysmonAddStringField(
        Event,
        &builder,
        &eventData->TargetUser,
        IncludeUsers ? TargetInfo->UserSid : NULL);
}

/*
 * Deferred work item callback - generates the ProcessAccess event
 * Runs at PASSIVE_LEVEL so we can call PsLookupProcessByProcessId etc.
 */
static VOID
SysmonObWorkItemCallback(_In_ PDEVICE_OBJECT DeviceObject, _In_opt_ PVOID Context)
{
    PSYSMON_OB_WORK_ITEM item;
    PLIST_ENTRY entry;
    PSYSMON_EVENT_UNION event;
    PSYSMON_EVENT_UNION probeEvent;
    PSYSMON_RULE_RUNTIME runtime;
    PSYSMON_PROCESS_INFO sourceInfo;
    PSYSMON_PROCESS_INFO targetInfo;
    ULONG ruleRequirements;
    BOOLEAN needsUserFields;
    BOOLEAN needsCallTraceForFilter;
    BOOLEAN earlyShouldCapture;
    PWCHAR callTrace;

    UNREFERENCED_PARAMETER(DeviceObject);
    UNREFERENCED_PARAMETER(Context);

    ExAcquireFastMutex(&g_ObWorkListLock);

    while (!IsListEmpty(&g_ObWorkItemList)) {
        entry = RemoveHeadList(&g_ObWorkItemList);
        item = CONTAINING_RECORD(entry, SYSMON_OB_WORK_ITEM, ListEntry);

        ExReleaseFastMutex(&g_ObWorkListLock);
        InterlockedIncrement(&g_ObWorkItemProcessedCount);

        event = NULL;
        sourceInfo = (PSYSMON_PROCESS_INFO)SysmonAllocatePool(sizeof(*sourceInfo));
        targetInfo = (PSYSMON_PROCESS_INFO)SysmonAllocatePool(sizeof(*targetInfo));
        callTrace = (PWCHAR)SysmonAllocatePool(sizeof(WCHAR) * 2048);
        runtime = NULL;
        probeEvent = NULL;
        ruleRequirements = SysmonProcessAccessRuleRequirementNone;
        needsUserFields = FALSE;
        needsCallTraceForFilter = FALSE;
        earlyShouldCapture = TRUE;
        if (sourceInfo == NULL || targetInfo == NULL || callTrace == NULL) {
            InterlockedIncrement(&g_ObDropAllocationFailureCount);
            goto NextWorkItem;
        }

        /*
         * Event 10 runs on a system worker thread and can be interrupted while
         * it is already inside object-manager and ETW paths. Keep the hot
         * identity and call-trace buffers off the kernel stack to avoid
         * double-faults from deep stack growth during handle-open enrichment.
         */
        RtlZeroMemory(sourceInfo, sizeof(*sourceInfo));
        RtlZeroMemory(targetInfo, sizeof(*targetInfo));
        RtlZeroMemory(callTrace, sizeof(WCHAR) * 2048);

        /*
         * Follow original layering: cheap target-image/access filtering
         * first, then only pay for heavier rule-required enrichment.
         */
        SysmonPopulateProcessIdentity(item->TargetPid, targetInfo);
        if (!SysmonShouldReportProcessAccess(
                targetInfo->ImagePath,
                item->GrantedAccess)) {
            goto NextWorkItem;
        }

        SysmonPopulateProcessIdentity(item->SourcePid, sourceInfo);
        SysmonEnrichProcessAccessIdentity(item->SourcePid, sourceInfo);
        SysmonEnrichProcessAccessIdentity(item->TargetPid, targetInfo);

        runtime = SysmonAcquireRuleRuntimeSnapshot();
        ruleRequirements = SysmonGetProcessAccessRuleRequirements(runtime);
        needsUserFields =
            (ruleRequirements &
             (SysmonProcessAccessRuleRequirementSourceUser |
              SysmonProcessAccessRuleRequirementTargetUser)) != 0;
        needsCallTraceForFilter =
            (ruleRequirements & SysmonProcessAccessRuleRequirementCallTrace) != 0;

        if (!needsCallTraceForFilter) {
            probeEvent = SysmonAllocateScratchProcessAccessEvent(item->Timestamp);
            if (probeEvent != NULL) {
                SysmonBuildProcessAccessEventPayload(
                    probeEvent,
                    item,
                    sourceInfo,
                    targetInfo,
                    NULL,
                    needsUserFields,
                    FALSE);
                earlyShouldCapture = SysmonShouldCaptureEvent(
                    runtime,
                    SysmonEventProcessAccess,
                    probeEvent);
                SysmonFreeScratchProcessAccessEvent(probeEvent);
                probeEvent = NULL;
            }
        }

        SysmonReleaseRuleRuntimeSnapshot(runtime);
        runtime = NULL;

        if (!earlyShouldCapture) {
            goto NextWorkItem;
        }

        SysmonFormatCallTrace(
            item->SourcePid,
            item->CallTraceFrames,
            item->CallTraceFrameCount,
            callTrace,
            2048);

        event = SysmonAllocateEvent(SysmonEventProcessAccess);
        if (event != NULL) {
            SysmonBuildProcessAccessEventPayload(
                event,
                item,
                sourceInfo,
                targetInfo,
                callTrace,
                TRUE,
                TRUE);

            /* Enqueue event */
            SysmonPublishEvent(event);
            InterlockedIncrement(&g_ObEventPublishedCount);
            SysmonFreeEvent(event);
        }

NextWorkItem:
        SysmonFreePool(callTrace);
        SysmonFreePool(targetInfo);
        SysmonFreePool(sourceInfo);
        SysmonFreePool(item);
        InterlockedDecrement(&g_ObWorkItemCount);

        ExAcquireFastMutex(&g_ObWorkListLock);
    }

    InterlockedExchange(&g_ObWorkerQueued, 0);
    if (IsListEmpty(&g_ObWorkItemList)) {
        KeSetEvent(&g_ObWorkerIdleEvent, IO_NO_INCREMENT, FALSE);
    } else {
        ExReleaseFastMutex(&g_ObWorkListLock);
        SysmonQueueObWorker();
        return;
    }

    ExReleaseFastMutex(&g_ObWorkListLock);
}

/*
 * Original Sysmon uses a stub pre-operation callback and captures Event 10
 * from post-operation so it can observe the final GrantedAccess.
 */
OB_PREOP_CALLBACK_STATUS
SysmonObPreOperationCallback(
    _In_ PVOID RegistrationContext,
    _Inout_ POB_PRE_OPERATION_INFORMATION OpInfo)
{
    UNREFERENCED_PARAMETER(RegistrationContext);
    UNREFERENCED_PARAMETER(OpInfo);
    return OB_PREOP_SUCCESS;
}

static VOID
SysmonObPostOperationCallback(
    _In_ PVOID RegistrationContext,
    _In_ POB_POST_OPERATION_INFORMATION OperationInformation)
{
    HANDLE sourcePid;
    HANDLE sourceTid;
    HANDLE targetPid;
    PEPROCESS targetProcess;
    ACCESS_MASK grantedAccess;
    PSYSMON_OB_WORK_ITEM workItem;

    UNREFERENCED_PARAMETER(RegistrationContext);

    if (!SysmonIsProducerEnabled(SYSMON_FLAG_ENABLED) || !SysmonIsProducerEnabled(SYSMON_FLAG_PROCESS_ACCESS_NOTIFY)) {
        return;
    }

    InterlockedIncrement(&g_ObPostCallbackCount);

    if (OperationInformation == NULL) {
        InterlockedIncrement(&g_ObDropObjectTypeMismatchCount);
        return;
    }

    if (g_PsProcessTypePtr != NULL &&
        OperationInformation->ObjectType != *g_PsProcessTypePtr) {
        InterlockedIncrement(&g_ObDropObjectTypeMismatchCount);
        return;
    }

    if (OperationInformation->Operation != OB_OPERATION_HANDLE_CREATE) {
        InterlockedIncrement(&g_ObDropOperationMismatchCount);
        return;
    }

    if (OperationInformation->KernelHandle) {
        InterlockedIncrement(&g_ObDropKernelHandleCount);
        return;
    }

    targetProcess = (PEPROCESS)OperationInformation->Object;
    targetPid = PsGetProcessId(targetProcess);
    sourcePid = PsGetCurrentProcessId();
    sourceTid = PsGetCurrentThreadId();
    if (sourcePid == targetPid) {
        InterlockedIncrement(&g_ObDropSameProcessCount);
        return;
    }

    grantedAccess = OperationInformation->Parameters->CreateHandleInformation.GrantedAccess;

    if (InterlockedCompareExchange(&g_ObWorkItemCount, 0, 0) >= 512) {
        InterlockedIncrement(&g_ObDropQueueLimitCount);
        return;
    }

    if (!g_ObWorkerInitialized || g_ObWorkItem == NULL) {
        InterlockedIncrement(&g_ObDropWorkerUnavailableCount);
        return;
    }

    workItem = (PSYSMON_OB_WORK_ITEM)SysmonAllocatePool(sizeof(SYSMON_OB_WORK_ITEM));
    if (workItem == NULL) {
        InterlockedIncrement(&g_ObDropAllocationFailureCount);
        return;
    }

    workItem->SourcePid = sourcePid;
    workItem->SourceTid = sourceTid;
    workItem->TargetPid = targetPid;
    workItem->GrantedAccess = grantedAccess;
    workItem->Timestamp = SysmonGetCurrentTimestamp();
    SysmonCaptureCallTraceFrames(workItem);

    InterlockedIncrement(&g_ObWorkItemCount);
    InterlockedIncrement(&g_ObWorkItemQueuedCount);

    ExAcquireFastMutex(&g_ObWorkListLock);
    InsertTailList(&g_ObWorkItemList, &workItem->ListEntry);
    ExReleaseFastMutex(&g_ObWorkListLock);

    SysmonQueueObWorker();
}

/*
 * SysmonRegisterObCallbacks - Register OB object callbacks
 *
 * Original Sysmon approach:
 *   1. Dynamically resolve ObRegisterCallbacks via MmGetSystemRoutineAddress
 *   2. Register callback for PsProcessType
 *   3. Use operation altitude "100000" (high priority)
 */
NTSTATUS
SysmonRegisterObCallbacks(_In_ PDEVICE_OBJECT DeviceObject)
{
    NTSTATUS status;
    UNICODE_STRING funcName;
    OB_CALLBACK_REGISTRATION callbackReg;
    OB_OPERATION_REGISTRATION opReg;

    /* Initialize synchronization primitives */
    SysmonInitializeObInfrastructure();
    InterlockedIncrement(&g_ObRegisterAttemptCount);

    if (g_ObCallbacksTemporarilyDisabled) {
        DbgPrintEx(
            DPFLTR_DEFAULT_ID,
            DPFLTR_WARNING_LEVEL,
            "[SysmonDrv] ProcessAccess callbacks temporarily disabled for crash isolation\n");
        InterlockedIncrement(&g_ObRegisterSuccessCount);
        InterlockedExchange(&g_ObRegisterLastStatus, STATUS_SUCCESS);
        UNREFERENCED_PARAMETER(DeviceObject);
        return STATUS_SUCCESS;
    }

    if (g_ObCallbacksRegistered) {
        InterlockedExchange(&g_ObRegisterLastStatus, STATUS_SUCCESS);
        return STATUS_SUCCESS;
    }

    /* Dynamically resolve ObRegisterCallbacks (original approach) */
    RtlInitUnicodeString(&funcName, L"ObRegisterCallbacks");
    g_ObRegisterCallbacks = (PFN_OB_REGISTER_CALLBACKS)
        MmGetSystemRoutineAddress(&funcName);
    if (g_ObRegisterCallbacks == NULL) {
        DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_WARNING_LEVEL,
            "[SysmonDrv] ObRegisterCallbacks not available\n");
        InterlockedExchange(&g_ObRegisterLastStatus, STATUS_PROCEDURE_NOT_FOUND);
        return STATUS_PROCEDURE_NOT_FOUND;
    }

    /* Resolve ObUnRegisterCallbacks */
    RtlInitUnicodeString(&funcName, L"ObUnRegisterCallbacks");
    g_ObUnRegisterCallbacks = (PFN_OB_UNREGISTER_CALLBACKS)
        MmGetSystemRoutineAddress(&funcName);

    /* Resolve PsAcquireProcessExitSynchronization */
    RtlInitUnicodeString(&funcName, L"PsAcquireProcessExitSynchronization");
    g_PsAcquireProcessExitSync = (PFN_PS_ACQUIRE_PROCESS_EXIT_SYNCHRONIZATION)
        MmGetSystemRoutineAddress(&funcName);

    /* Resolve PsReleaseProcessExitSynchronization */
    RtlInitUnicodeString(&funcName, L"PsReleaseProcessExitSynchronization");
    g_PsReleaseProcessExitSync = (PFN_PS_RELEASE_PROCESS_EXIT_SYNCHRONIZATION)
        MmGetSystemRoutineAddress(&funcName);

    if (g_ObUnRegisterCallbacks == NULL ||
        g_PsAcquireProcessExitSync == NULL ||
        g_PsReleaseProcessExitSync == NULL) {
        InterlockedExchange(&g_ObRegisterLastStatus, STATUS_PROCEDURE_NOT_FOUND);
        return STATUS_PROCEDURE_NOT_FOUND;
    }

    /* Store PsProcessType pointer */
    g_PsProcessTypePtr = (PVOID *)PsProcessType;

    /* Allocate IoWorkItem for deferred event processing */
    g_ObWorkItem = IoAllocateWorkItem(DeviceObject);
    if (g_ObWorkItem == NULL) {
        InterlockedExchange(&g_ObRegisterLastStatus, STATUS_INSUFFICIENT_RESOURCES);
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    g_ObWorkerInitialized = TRUE;

    /* Set up operation registration for process handles */
    RtlZeroMemory(&opReg, sizeof(opReg));
    opReg.ObjectType = PsProcessType;
    opReg.Operations = OB_OPERATION_HANDLE_CREATE;
    opReg.PreOperation = SysmonObPreOperationCallback;
    opReg.PostOperation = SysmonObPostOperationCallback;

    /* Set up callback registration */
    RtlZeroMemory(&callbackReg, sizeof(callbackReg));
    callbackReg.Version = OB_FLT_REGISTRATION_VERSION;
    callbackReg.OperationRegistrationCount = 1;
    /* Original reverse points at the literal altitude string "1000". */
    RtlInitUnicodeString(&callbackReg.Altitude, L"1000");
    callbackReg.RegistrationContext = NULL;
    callbackReg.OperationRegistration = &opReg;

    /* Register callbacks */
    status = g_ObRegisterCallbacks(&callbackReg, &g_ObRegistrationHandle);
    if (!NT_SUCCESS(status)) {
        InterlockedExchange(&g_ObRegisterLastStatus, status);
        DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL,
            "[SysmonDrv] ObRegisterCallbacks failed: 0x%08X\n", status);
        if (g_ObWorkItem != NULL) {
            IoFreeWorkItem(g_ObWorkItem);
            g_ObWorkItem = NULL;
        }
        g_ObWorkerInitialized = FALSE;
        return status;
    }

    g_ObCallbacksRegistered = TRUE;
    InterlockedIncrement(&g_ObRegisterSuccessCount);
    InterlockedExchange(&g_ObRegisterLastStatus, status);

    DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_INFO_LEVEL,
        "[SysmonDrv] OB callbacks registered for ProcessAccess monitoring\n");

    return STATUS_SUCCESS;
}

/*
 * SysmonUnregisterObCallbacks - Unregister OB callbacks and cleanup
 */
VOID
SysmonUnregisterObCallbacks(VOID)
{
    PLIST_ENTRY entry;

    if (g_ObCallbacksTemporarilyDisabled) {
        g_ObCallbacksRegistered = FALSE;
        g_ObRegistrationHandle = NULL;
        g_ObWorkerInitialized = FALSE;
        g_ObWorkItem = NULL;
        return;
    }

    if (!g_ObInfrastructureInitialized) {
        g_ObCallbacksRegistered = FALSE;
        g_ObRegistrationHandle = NULL;
        g_ObWorkerInitialized = FALSE;
        g_ObWorkItem = NULL;
        return;
    }

    if (g_ObCallbacksRegistered && g_ObUnRegisterCallbacks != NULL) {
        g_ObUnRegisterCallbacks(g_ObRegistrationHandle);
        g_ObCallbacksRegistered = FALSE;
        g_ObRegistrationHandle = NULL;
    }

    if (g_ObWorkerInitialized) {
        KeWaitForSingleObject(
            &g_ObWorkerIdleEvent,
            Executive,
            KernelMode,
            FALSE,
            NULL);
    }

    /* Drain any item that was never queued because shutdown won the race. */
    ExAcquireFastMutex(&g_ObWorkListLock);
    while (!IsListEmpty(&g_ObWorkItemList)) {
        entry = RemoveHeadList(&g_ObWorkItemList);
        SysmonFreePool(CONTAINING_RECORD(entry, SYSMON_OB_WORK_ITEM, ListEntry));
    }
    ExReleaseFastMutex(&g_ObWorkListLock);

    g_ObWorkerInitialized = FALSE;
    g_ObWorkerQueued = 0;
    g_ObWorkItemCount = 0;
    if (g_ObWorkItem != NULL) {
        IoFreeWorkItem(g_ObWorkItem);
        g_ObWorkItem = NULL;
    }

    DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_INFO_LEVEL,
        "[SysmonDrv] OB callbacks unregistered\n");
}

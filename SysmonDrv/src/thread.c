#include "process.h"
#include "queue.h"
#include "event.h"
#include "driver.h"
#include "processinfo.h"
#include "utils.h"

#ifndef THREAD_QUERY_INFORMATION
#define THREAD_QUERY_INFORMATION 0x0040
#endif

typedef NTSTATUS (NTAPI *PFN_PS_SET_CREATE_THREAD_NOTIFY_ROUTINE_EX)(
    ULONG NotifyType,
    PVOID NotifyInformation);

#define SYSMON_PS_CREATE_THREAD_NOTIFY_SUBSYSTEMS 1ul
#define SYSMON_THREAD_START_FUNCTION_CHARS 128u

static volatile LONG g_ThreadSequence = 0;
static BOOLEAN g_ThreadNotifyRegistered = FALSE;
static BOOLEAN g_ThreadNotifyRegisteredWithEx = FALSE;
static PFN_PS_SET_CREATE_THREAD_NOTIFY_ROUTINE_EX g_PsSetCreateThreadNotifyRoutineEx = NULL;
static volatile LONG g_ThreadCallbackCount = 0;
static volatile LONG g_ThreadCreateCallbackCount = 0;
static volatile LONG g_ThreadDropClaimedPendingCreateCount = 0;
static volatile LONG g_ThreadDropSystemProcessCount = 0;
static volatile LONG g_ThreadDropSystemThreadCount = 0;
static volatile LONG g_ThreadDropSelfTargetCount = 0;
static volatile LONG g_ThreadEventPublishedCount = 0;
static volatile LONG g_ThreadWorkItemCount = 0;
static volatile LONG g_ThreadWorkerQueued = 0;
static volatile LONG g_ThreadLastSourceProcessId = 0;
static volatile LONG g_ThreadLastTargetProcessId = 0;
static volatile LONG g_ThreadLastThreadId = 0;
static LIST_ENTRY g_ThreadWorkItemList;
static FAST_MUTEX g_ThreadWorkListLock;
static KEVENT g_ThreadWorkerIdleEvent;
static PIO_WORKITEM g_ThreadWorkItem = NULL;
static BOOLEAN g_ThreadInfrastructureInitialized = FALSE;
static BOOLEAN g_ThreadWorkerInitialized = FALSE;

extern PCHAR PsGetProcessImageFileName(_In_ PEPROCESS Process);
extern POBJECT_TYPE *PsThreadType;

typedef struct _SYSMON_THREAD_PROCESS_IDENTITY {
    ULONG ProcessId;
    LONGLONG CreateTime;
    WCHAR ProcessGuid[SYSMON_MAX_GUID_STRING];
    WCHAR ImagePath[SYSMON_MAX_PATH];
    WCHAR UserSid[SYSMON_MAX_SID_STRING];
} SYSMON_THREAD_PROCESS_IDENTITY, *PSYSMON_THREAD_PROCESS_IDENTITY;

typedef struct _SYSMON_THREAD_WORK_ITEM {
    LIST_ENTRY ListEntry;
    HANDLE SourceProcessId;
    HANDLE TargetProcessId;
    HANDLE ThreadId;
    ULONGLONG StartAddress;
    LONGLONG Timestamp;
    WCHAR StartModule[SYSMON_MAX_PATH];
    WCHAR StartFunction[SYSMON_THREAD_START_FUNCTION_CHARS];
    SYSMON_THREAD_PROCESS_IDENTITY SourceIdentity;
    SYSMON_THREAD_PROCESS_IDENTITY TargetIdentity;
} SYSMON_THREAD_WORK_ITEM, *PSYSMON_THREAD_WORK_ITEM;

static VOID
SysmonThreadWorkItemCallback(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_opt_ PVOID Context);

static VOID
SysmonPopulateThreadProcessIdentity(
    _In_ HANDLE ProcessId,
    _Out_ PSYSMON_THREAD_PROCESS_IDENTITY Identity)
{
    SYSMON_PROCESS_CACHE_METADATA cachedMetadata;
    PEPROCESS process;

    if (Identity == NULL) {
        return;
    }

    RtlZeroMemory(Identity, sizeof(*Identity));
    Identity->ProcessId = HandleToULong(ProcessId);

    RtlZeroMemory(&cachedMetadata, sizeof(cachedMetadata));
    if (SysmonLookupCachedProcessMetadata(Identity->ProcessId, &cachedMetadata)) {
        Identity->CreateTime = cachedMetadata.CreateTime;
        SysmonCopyWideStringWithLength(
            Identity->ProcessGuid,
            RTL_NUMBER_OF(Identity->ProcessGuid),
            cachedMetadata.ProcessGuid,
            SYSMON_GUID_STRING_CHARS);
        SysmonCopyWideString(
            Identity->ImagePath,
            RTL_NUMBER_OF(Identity->ImagePath),
            cachedMetadata.Image);
        SysmonCopyWideString(
            Identity->UserSid,
            RTL_NUMBER_OF(Identity->UserSid),
            cachedMetadata.UserSid);
    }

    if (Identity->ImagePath[0] == L'\0' &&
        NT_SUCCESS(PsLookupProcessByProcessId(ProcessId, &process))) {
        (void)SysmonAnsiToWide(
            PsGetProcessImageFileName(process),
            Identity->ImagePath,
            RTL_NUMBER_OF(Identity->ImagePath));
        ObDereferenceObject(process);
    }

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

static BOOLEAN
SysmonThreadPathLooksComplete(
    _In_opt_z_ PCWSTR ImagePath)
{
    return ImagePath != NULL &&
        ImagePath[0] != L'\0' &&
        (_wcsicmp(ImagePath, L"System") == 0 ||
         wcschr(ImagePath, L'\\') != NULL ||
         wcschr(ImagePath, L':') != NULL);
}

static VOID
SysmonOverlayThreadIdentityFromProcessInfo(
    _Inout_ PSYSMON_THREAD_PROCESS_IDENTITY Identity,
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
    if (!SysmonThreadPathLooksComplete(Identity->ImagePath) &&
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
}

static VOID
SysmonEnrichThreadProcessIdentity(
    _In_ HANDLE ProcessId,
    _Inout_ PSYSMON_THREAD_PROCESS_IDENTITY Identity)
{
    SYSMON_PROCESS_INFO processInfo;
    NTSTATUS status;
    BOOLEAN needsFullPath;
    BOOLEAN needsUser;

    if (Identity == NULL) {
        return;
    }

    needsFullPath = !SysmonThreadPathLooksComplete(Identity->ImagePath);
    needsUser = Identity->UserSid[0] == L'\0';
    if (!needsFullPath &&
        !needsUser &&
        Identity->ProcessGuid[0] != L'\0' &&
        Identity->CreateTime != 0) {
        return;
    }

    (void)SysmonTryFinalizePendingProcessCreate(ProcessId);

    RtlZeroMemory(&processInfo, sizeof(processInfo));
    status = needsUser
        ? SysmonCollectProcessTokenIdentity(ProcessId, &processInfo)
        : SysmonCollectProcessIdentity(ProcessId, &processInfo);
    if (!NT_SUCCESS(status) && needsUser) {
        RtlZeroMemory(&processInfo, sizeof(processInfo));
        status = SysmonCollectProcessIdentity(ProcessId, &processInfo);
    }

    if (NT_SUCCESS(status)) {
        SysmonOverlayThreadIdentityFromProcessInfo(Identity, &processInfo);
    }

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
SysmonInitializeThreadInfrastructure(VOID)
{
    if (g_ThreadInfrastructureInitialized) {
        return;
    }

    ExInitializeFastMutex(&g_ThreadWorkListLock);
    InitializeListHead(&g_ThreadWorkItemList);
    KeInitializeEvent(&g_ThreadWorkerIdleEvent, NotificationEvent, TRUE);
    g_ThreadWorkItemCount = 0;
    g_ThreadWorkerQueued = 0;
    g_ThreadInfrastructureInitialized = TRUE;
}

VOID
SysmonQueryThreadDebugStats(
    _Out_ PSYSMON_PROCESS_DEBUG_STATS Stats)
{
    if (Stats == NULL) {
        return;
    }

    Stats->ThreadCallbackCount = (ULONG)g_ThreadCallbackCount;
    Stats->ThreadCreateCallbackCount = (ULONG)g_ThreadCreateCallbackCount;
    Stats->ThreadDropClaimedPendingCreate = (ULONG)g_ThreadDropClaimedPendingCreateCount;
    Stats->ThreadDropSystemProcess = (ULONG)g_ThreadDropSystemProcessCount;
    Stats->ThreadDropSystemThread = (ULONG)g_ThreadDropSystemThreadCount;
    Stats->ThreadDropSelfTarget = (ULONG)g_ThreadDropSelfTargetCount;
    Stats->ThreadEventPublishedCount = (ULONG)g_ThreadEventPublishedCount;
    Stats->ThreadLastSourceProcessId = (ULONG)g_ThreadLastSourceProcessId;
    Stats->ThreadLastTargetProcessId = (ULONG)g_ThreadLastTargetProcessId;
    Stats->ThreadLastThreadId = (ULONG)g_ThreadLastThreadId;
}

static ULONGLONG
SysmonQueryThreadStartAddress(_In_ HANDLE ThreadId)
{
    PETHREAD threadObject;
    HANDLE threadHandle = NULL;
    PVOID startAddress = NULL;
    ULONG returnLength = 0;
    NTSTATUS status;

    threadObject = NULL;
    status = PsLookupThreadByThreadId(ThreadId, &threadObject);
    if (!NT_SUCCESS(status) || threadObject == NULL) {
        return 0;
    }

    status = ObOpenObjectByPointer(
        threadObject,
        OBJ_KERNEL_HANDLE,
        NULL,
        MAXIMUM_ALLOWED,
        (PsThreadType != NULL) ? *PsThreadType : NULL,
        KernelMode,
        &threadHandle);
    if (!NT_SUCCESS(status)) {
        ObDereferenceObject(threadObject);
        return 0;
    }

    status = ZwQueryInformationThread(
        threadHandle,
        (THREADINFOCLASS)9, /* ThreadQuerySetWin32StartAddress */
        &startAddress,
        sizeof(startAddress),
        &returnLength);

    ZwClose(threadHandle);
    ObDereferenceObject(threadObject);

    if (!NT_SUCCESS(status)) {
        return 0;
    }

    return (ULONGLONG)(ULONG_PTR)startAddress;
}

static VOID
SysmonResolveThreadStartContext(
    _Inout_ PSYSMON_THREAD_WORK_ITEM WorkItem)
{
    PEPROCESS process;

    if (WorkItem == NULL || WorkItem->StartAddress == 0) {
        return;
    }

    process = NULL;
    if (NT_SUCCESS(PsLookupProcessByProcessId(WorkItem->TargetProcessId, &process))) {
        (void)SysmonResolveUserStartContextForProcessObject(
            process,
            WorkItem->StartAddress,
            WorkItem->StartModule,
            RTL_NUMBER_OF(WorkItem->StartModule),
            WorkItem->StartFunction,
            RTL_NUMBER_OF(WorkItem->StartFunction));
        ObDereferenceObject(process);
    }
}

static VOID
SysmonPopulateCreateRemoteThreadEvent(
    _Inout_ PSYSMON_EVENT_UNION Event,
    _In_ const SYSMON_THREAD_WORK_ITEM *WorkItem)
{
    SYSMON_EVENT_CREATE_REMOTE_THREAD_PAYLOAD *eventData;
    SYSMON_EVENT_PAYLOAD_BUILDER builder;

    if (Event == NULL || WorkItem == NULL) {
        return;
    }

    eventData = (SYSMON_EVENT_CREATE_REMOTE_THREAD_PAYLOAD *)Event->RawData;
    SysmonBeginStringPayload(Event, sizeof(*eventData), &builder);
    Event->Header.Timestamp = WorkItem->Timestamp;
    Event->Header.SequenceNumber = (ULONG)InterlockedIncrement(&g_ThreadSequence);

    SysmonAddStringField(Event, &builder, &eventData->RuleName, L"-");
    SysmonAddCurrentUtcTimeField(Event, &builder, &eventData->UtcTime);
    SysmonAddStringField(
        Event,
        &builder,
        &eventData->SourceProcessGuid,
        WorkItem->SourceIdentity.ProcessGuid);
    SysmonWritePackedUlong(&eventData->SourceProcessId, (ULONG)(ULONG_PTR)WorkItem->SourceProcessId);
    SysmonAddStringField(
        Event,
        &builder,
        &eventData->SourceImage,
        WorkItem->SourceIdentity.ImagePath);
    SysmonAddStringField(
        Event,
        &builder,
        &eventData->TargetProcessGuid,
        WorkItem->TargetIdentity.ProcessGuid);
    SysmonWritePackedUlong(&eventData->TargetProcessId, (ULONG)(ULONG_PTR)WorkItem->TargetProcessId);
    SysmonAddStringField(
        Event,
        &builder,
        &eventData->TargetImage,
        WorkItem->TargetIdentity.ImagePath);
    SysmonWritePackedUlong(&eventData->NewThreadId, (ULONG)(ULONG_PTR)WorkItem->ThreadId);
    SysmonWritePackedUlongLong(&eventData->StartAddress, WorkItem->StartAddress);
    SysmonAddStringField(
        Event,
        &builder,
        &eventData->StartModule,
        WorkItem->StartModule);
    SysmonAddStringField(
        Event,
        &builder,
        &eventData->StartFunction,
        WorkItem->StartFunction);
    SysmonAddStringField(
        Event,
        &builder,
        &eventData->SourceUser,
        WorkItem->SourceIdentity.UserSid);
    SysmonAddStringField(
        Event,
        &builder,
        &eventData->TargetUser,
        WorkItem->TargetIdentity.UserSid);
    SYSMON_HOTPATH_LOG(
        DPFLTR_INFO_LEVEL,
        "[SysmonDrv] CreateRemoteThread built size=%lu srcPid=%lu dstPid=%lu tid=%lu\n",
        Event->Header.EventSize,
        eventData->SourceProcessId,
        eventData->TargetProcessId,
        eventData->NewThreadId);
}

static VOID
SysmonQueueThreadWorker(VOID)
{
    if (g_ThreadWorkItem == NULL) {
        return;
    }

    if (InterlockedCompareExchange(&g_ThreadWorkerQueued, 1, 0) == 0) {
        KeClearEvent(&g_ThreadWorkerIdleEvent);
        IoQueueWorkItem(
            g_ThreadWorkItem,
            SysmonThreadWorkItemCallback,
            DelayedWorkQueue,
            NULL);
    }
}

static VOID
SysmonThreadWorkItemCallback(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_opt_ PVOID Context)
{
    PSYSMON_THREAD_WORK_ITEM workItem;
    PSYSMON_EVENT_UNION event;
    PLIST_ENTRY listEntry;

    UNREFERENCED_PARAMETER(DeviceObject);
    UNREFERENCED_PARAMETER(Context);

    ExAcquireFastMutex(&g_ThreadWorkListLock);
    while (!IsListEmpty(&g_ThreadWorkItemList)) {
        listEntry = RemoveHeadList(&g_ThreadWorkItemList);
        workItem = CONTAINING_RECORD(
            listEntry,
            SYSMON_THREAD_WORK_ITEM,
            ListEntry);
        ExReleaseFastMutex(&g_ThreadWorkListLock);

        if (SysmonIsProducerEnabled(SYSMON_FLAG_ENABLED) &&
            SysmonIsProducerEnabled(SYSMON_FLAG_THREAD_NOTIFY) &&
            SysmonIsRuntimeEventConfigured(
                SysmonEventCreateThread,
                SysmonIsProducerEnabled(SYSMON_FLAG_THREAD_NOTIFY))) {
            SysmonEnrichThreadProcessIdentity(
                workItem->SourceProcessId,
                &workItem->SourceIdentity);
            SysmonEnrichThreadProcessIdentity(
                workItem->TargetProcessId,
                &workItem->TargetIdentity);

            event = SysmonAllocateEvent(SysmonEventCreateThread);
            if (event != NULL) {
                SysmonPopulateCreateRemoteThreadEvent(event, workItem);
                (void)SysmonPublishEvent(event);
                InterlockedIncrement(&g_ThreadEventPublishedCount);
                SysmonFreeEvent(event);
            }
        }

        SysmonFreePool(workItem);
        InterlockedDecrement(&g_ThreadWorkItemCount);
        ExAcquireFastMutex(&g_ThreadWorkListLock);
    }

    InterlockedExchange(&g_ThreadWorkerQueued, 0);
    if (IsListEmpty(&g_ThreadWorkItemList)) {
        KeSetEvent(&g_ThreadWorkerIdleEvent, IO_NO_INCREMENT, FALSE);
    } else {
        ExReleaseFastMutex(&g_ThreadWorkListLock);
        SysmonQueueThreadWorker();
        return;
    }

    ExReleaseFastMutex(&g_ThreadWorkListLock);
}

static VOID
ThreadNotifyCallback(
    _In_ HANDLE ProcessId,
    _In_ HANDLE ThreadId,
    _In_ BOOLEAN Create)
{
    PSYSMON_THREAD_WORK_ITEM workItem;
    HANDLE sourceProcessId;
    BOOLEAN claimedPendingCreate = FALSE;

    InterlockedIncrement(&g_ThreadCallbackCount);
    InterlockedExchange(&g_ThreadLastTargetProcessId, (LONG)HandleToULong(ProcessId));
    InterlockedExchange(&g_ThreadLastThreadId, (LONG)HandleToULong(ThreadId));

    if (!SysmonIsProducerEnabled(SYSMON_FLAG_ENABLED)) {
        return;
    }

    if (!Create) {
        return; /* Only monitor thread creation */
    }

    InterlockedIncrement(&g_ThreadCreateCallbackCount);

    if (SysmonIsProducerEnabled(SYSMON_FLAG_PROCESS_NOTIFY)) {
        /*
         * Original Sysmon finalizes Event 1 from the first thread-create path.
         * Doing the work directly here sharply reduces the window where a
         * short-lived process can exit before the deferred worker runs.
         */
        (void)SysmonTryFinalizePendingProcessCreateEx(ProcessId, &claimedPendingCreate);
        if (claimedPendingCreate) {
            InterlockedIncrement(&g_ThreadDropClaimedPendingCreateCount);
            return;
        }
    }

    if (!SysmonIsProducerEnabled(SYSMON_FLAG_THREAD_NOTIFY) ||
        !SysmonIsRuntimeEventConfigured(
            SysmonEventCreateThread,
            SysmonIsProducerEnabled(SYSMON_FLAG_THREAD_NOTIFY))) {
        return;
    }

    /*
     * The original Sysmon thread callback suppresses Event 8 when the notify
     * runs on a system thread or the target is the System process. Without
     * these gates PsGetCurrentProcessId() can resolve to PID 4 and produce
     * broad false positives.
     */
    if ((ULONG)(ULONG_PTR)ProcessId == 4) {
        InterlockedIncrement(&g_ThreadDropSystemProcessCount);
        return;
    }

    if (PsIsSystemThread(KeGetCurrentThread())) {
        InterlockedIncrement(&g_ThreadDropSystemThreadCount);
        return;
    }

    sourceProcessId = PsGetCurrentProcessId();
    InterlockedExchange(&g_ThreadLastSourceProcessId, (LONG)HandleToULong(sourceProcessId));
    if (sourceProcessId == ProcessId) {
        InterlockedIncrement(&g_ThreadDropSelfTargetCount);
        return; /* Event 8 is CreateRemoteThread, not ordinary in-process thread creation. */
    }

    if (InterlockedCompareExchange(&g_ThreadWorkItemCount, 0, 0) >= 512) {
        return;
    }

    if (!g_ThreadWorkerInitialized || g_ThreadWorkItem == NULL) {
        return;
    }

    workItem = (PSYSMON_THREAD_WORK_ITEM)SysmonAllocatePool(sizeof(*workItem));
    if (workItem == NULL) {
        return;
    }

    RtlZeroMemory(workItem, sizeof(*workItem));
    workItem->SourceProcessId = sourceProcessId;
    workItem->TargetProcessId = ProcessId;
    workItem->ThreadId = ThreadId;
    workItem->Timestamp = SysmonGetCurrentTimestamp();
    workItem->StartAddress = SysmonQueryThreadStartAddress(ThreadId);
    SysmonResolveThreadStartContext(workItem);
    SysmonPopulateThreadProcessIdentity(sourceProcessId, &workItem->SourceIdentity);
    SysmonPopulateThreadProcessIdentity(ProcessId, &workItem->TargetIdentity);

    InterlockedIncrement(&g_ThreadWorkItemCount);
    ExAcquireFastMutex(&g_ThreadWorkListLock);
    InsertTailList(&g_ThreadWorkItemList, &workItem->ListEntry);
    ExReleaseFastMutex(&g_ThreadWorkListLock);

    SysmonQueueThreadWorker();
}

NTSTATUS
SysmonRegisterThreadNotify(_In_ PDRIVER_OBJECT DriverObject)
{
    NTSTATUS status;
    UNICODE_STRING routineName;
    UNREFERENCED_PARAMETER(DriverObject);

    SysmonInitializeThreadInfrastructure();

    if (g_ThreadNotifyRegistered) {
        return STATUS_SUCCESS;
    }

    if (!g_ThreadWorkerInitialized) {
        g_ThreadWorkItem = IoAllocateWorkItem(g_Context.DeviceObject);
        if (g_ThreadWorkItem == NULL) {
            return STATUS_INSUFFICIENT_RESOURCES;
        }
        g_ThreadWorkerInitialized = TRUE;
    }

    if (g_PsSetCreateThreadNotifyRoutineEx == NULL) {
        RtlInitUnicodeString(&routineName, L"PsSetCreateThreadNotifyRoutineEx");
        g_PsSetCreateThreadNotifyRoutineEx =
            (PFN_PS_SET_CREATE_THREAD_NOTIFY_ROUTINE_EX)MmGetSystemRoutineAddress(&routineName);
    }

    status = STATUS_PROCEDURE_NOT_FOUND;
    if (g_PsSetCreateThreadNotifyRoutineEx != NULL) {
        status = g_PsSetCreateThreadNotifyRoutineEx(
            SYSMON_PS_CREATE_THREAD_NOTIFY_SUBSYSTEMS,
            (PVOID)ThreadNotifyCallback);
        if (NT_SUCCESS(status)) {
            g_ThreadNotifyRegistered = TRUE;
            g_ThreadNotifyRegisteredWithEx = TRUE;
            return STATUS_SUCCESS;
        }

        DbgPrintEx(
            DPFLTR_DEFAULT_ID,
            DPFLTR_WARNING_LEVEL,
            "[SysmonDrv] PsSetCreateThreadNotifyRoutineEx registration failed: 0x%08X\n",
            status);
    }

    status = PsSetCreateThreadNotifyRoutine(ThreadNotifyCallback);
    if (!NT_SUCCESS(status)) {
        DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_WARNING_LEVEL,
            "[SysmonDrv] PsSetCreateThreadNotifyRoutine failed: 0x%08X\n", status);
        return status;
    }

    g_ThreadNotifyRegistered = TRUE;
    g_ThreadNotifyRegisteredWithEx = FALSE;
    return STATUS_SUCCESS;
}

VOID
SysmonUnregisterThreadNotify(VOID)
{
    PLIST_ENTRY listEntry;

    if (!g_ThreadNotifyRegistered) {
        goto CleanupInfrastructure;
    }

    PsRemoveCreateThreadNotifyRoutine(ThreadNotifyCallback);
    g_ThreadNotifyRegistered = FALSE;
    g_ThreadNotifyRegisteredWithEx = FALSE;

CleanupInfrastructure:
    if (!g_ThreadInfrastructureInitialized) {
        return;
    }

    if (g_ThreadWorkerInitialized) {
        KeWaitForSingleObject(
            &g_ThreadWorkerIdleEvent,
            Executive,
            KernelMode,
            FALSE,
            NULL);
    }

    ExAcquireFastMutex(&g_ThreadWorkListLock);
    while (!IsListEmpty(&g_ThreadWorkItemList)) {
        listEntry = RemoveHeadList(&g_ThreadWorkItemList);
        SysmonFreePool(CONTAINING_RECORD(
            listEntry,
            SYSMON_THREAD_WORK_ITEM,
            ListEntry));
    }
    ExReleaseFastMutex(&g_ThreadWorkListLock);

    g_ThreadWorkerInitialized = FALSE;
    g_ThreadWorkerQueued = 0;
    g_ThreadWorkItemCount = 0;
    if (g_ThreadWorkItem != NULL) {
        IoFreeWorkItem(g_ThreadWorkItem);
        g_ThreadWorkItem = NULL;
    }
}

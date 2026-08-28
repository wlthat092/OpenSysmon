#include "process.h"
#include "queue.h"
#include "event.h"
#include "driver.h"
#include "fileinfo.h"
#include "hash.h"
#include "processinfo.h"
#include "rules.h"
#include "tampering.h"
#include "utils.h"

static volatile LONG g_ImageSequence = 0;
static BOOLEAN g_ImageNotifyRegistered = FALSE;
extern PCHAR PsGetProcessImageFileName(_In_ PEPROCESS Process);
extern HANDLE PsGetCurrentProcessId(VOID);

#define SYSMON_MAX_IMAGE_WORKERS 4
#define SYSMON_IMAGE_DROP_REASON_NONE               0u
#define SYSMON_IMAGE_DROP_REASON_WORKER_UNAVAILABLE 1u
#define SYSMON_IMAGE_DROP_REASON_QUEUE_FULL         2u
#define SYSMON_IMAGE_DROP_REASON_STOPPING           3u

typedef struct _SYSMON_IMAGE_WORK_CONTEXT {
    LIST_ENTRY ListEntry;
    HANDLE ProcessId;
    BOOLEAN DriverLoad;
    WCHAR ImageLoaded[SYSMON_MAX_PATH];
} SYSMON_IMAGE_WORK_CONTEXT, *PSYSMON_IMAGE_WORK_CONTEXT;

typedef struct _SYSMON_IMAGE_WORK_QUEUE {
    LIST_ENTRY WorkList;
    FAST_MUTEX Lock;
} SYSMON_IMAGE_WORK_QUEUE, *PSYSMON_IMAGE_WORK_QUEUE;

static SYSMON_IMAGE_WORK_QUEUE g_ImageWorkQueues[MAXIMUM_PROCESSORS];
static ULONG g_ImageWorkQueueCount = 0;
static PIO_WORKITEM g_ImageIoWorkItems[SYSMON_MAX_IMAGE_WORKERS];
static ULONG g_ImageWorkerCount = 0;
static volatile LONG g_ImageWorkItemCount = 0;
static volatile LONG g_ImageActiveWorkers = 0;
static volatile LONG g_ImageAcceptingWork = 0;
static volatile LONG g_ImageWorkerQueued[SYSMON_MAX_IMAGE_WORKERS];
static volatile LONG g_ImageQueueStealCursor = 0;
static KEVENT g_ImageWorkerIdleEvent;
static BOOLEAN g_ImageWorkerInitialized = FALSE;
static volatile LONG g_LastImageTargetEventId = 0;
static volatile LONG g_LastImageRuleRequirements = 0;
static volatile LONG g_LastImageFileInfoRequestMask = 0;
static volatile LONG g_LastImageCollectStatus = 0;
static volatile LONG g_LastImageHaveFileInfo = 0;
static volatile LONG g_LastImageHashValueState = 0;
static volatile LONG g_ImageQueueDropCount = 0;
static volatile LONG g_LastImageDropReason = 0;

typedef struct _SYSMON_IMAGE_PATH_PREFIX_ENTRY {
    BOOLEAN Valid;
    WCHAR DosPrefix[3];
    WCHAR NtPrefix[SYSMON_MAX_PATH];
} SYSMON_IMAGE_PATH_PREFIX_ENTRY, *PSYSMON_IMAGE_PATH_PREFIX_ENTRY;

static SYSMON_IMAGE_PATH_PREFIX_ENTRY g_ImagePathPrefixCache[26];
static FAST_MUTEX g_ImagePathPrefixCacheLock;
static volatile LONG g_ImagePathPrefixCacheInitState = 0; /* 0=uninitialized, 1=initializing, 2=ready */
static KEVENT g_ImagePathPrefixCacheInitEvent;
static volatile LONG g_ImagePathPrefixCacheInitEventState = 0;

static VOID
SysmonPopulateDriverLoadEvent(
    _Inout_ PSYSMON_EVENT_UNION Event,
    _In_z_ PCWSTR ImageLoaded,
    _In_opt_ const SYSMON_FILE_INFO *FileInfo,
    _In_ BOOLEAN HaveFileInfo);

static VOID
SysmonPopulateImageLoadEvent(
    _Inout_ PSYSMON_EVENT_UNION Event,
    _In_ HANDLE ProcessId,
    _In_z_ PCWSTR ImageLoaded,
    _In_ ULONG FileInfoRequestMask,
    _Inout_ PSYSMON_PROCESS_INFO ProcessInfo,
    _Inout_opt_ PSYSMON_FILE_INFO FileInfo);

static VOID
SysmonWriteImageLoadEvent(
    _Inout_ PSYSMON_EVENT_UNION Event,
    _In_ HANDLE ProcessId,
    _In_z_ PCWSTR ImageLoaded,
    _In_ const SYSMON_PROCESS_INFO *ProcessInfo,
    _In_opt_ const SYSMON_FILE_INFO *FileInfo,
    _In_ BOOLEAN HaveFileInfo);

static VOID
SysmonImageIoWorkItemCallback(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_opt_ PVOID Context);

static ULONG
SysmonGetImageQueueIndexForCurrentProcessor(VOID);

static BOOLEAN
SysmonTryDequeueImageWorkContext(
    _In_ ULONG StartQueueIndex,
    _Out_ PSYSMON_IMAGE_WORK_CONTEXT *WorkContext);

static ULONG
SysmonClaimImageWorkerSlot(VOID);

static ULONG
SysmonReserveImageWorkers(
    _Out_writes_(MaxWorkers) PIO_WORKITEM *Workers,
    _Out_writes_(MaxWorkers) PVOID *WorkerContexts,
    _In_ ULONG MaxWorkers);

static VOID
SysmonCleanupImageWorkers(VOID);

static BOOLEAN
SysmonIsKernelImageLoad(
    _In_ HANDLE ProcessId,
    _In_opt_ PIMAGE_INFO ImageInfo);

static VOID
SysmonRecordImageQueueDrop(
    _In_ ULONG Reason)
{
    InterlockedIncrement(&g_ImageQueueDropCount);
    InterlockedExchange(&g_LastImageDropReason, (LONG)Reason);
}

static VOID
SysmonEnsureImagePathPrefixCacheInitEventInitialized(VOID)
{
    if (InterlockedCompareExchange(&g_ImagePathPrefixCacheInitEventState, 1, 0) == 0) {
        KeInitializeEvent(&g_ImagePathPrefixCacheInitEvent, NotificationEvent, FALSE);
    }
}

static VOID
SysmonEnsureImagePathPrefixCacheInitialized(VOID)
{
    LONG state;

    SysmonEnsureImagePathPrefixCacheInitEventInitialized();
    for (;;) {
        state = InterlockedCompareExchange(&g_ImagePathPrefixCacheInitState, 2, 2);
        if (state == 2) {
            return;
        }

        if (state == 0 &&
            InterlockedCompareExchange(&g_ImagePathPrefixCacheInitState, 1, 0) == 0) {
            ULONG index;

            ExInitializeFastMutex(&g_ImagePathPrefixCacheLock);
            RtlZeroMemory(g_ImagePathPrefixCache, sizeof(g_ImagePathPrefixCache));
            for (index = 0; index < RTL_NUMBER_OF(g_ImagePathPrefixCache); index++) {
                HANDLE linkHandle = NULL;
                WCHAR linkBuffer[7];
                WCHAR targetBuffer[SYSMON_MAX_PATH];
                UNICODE_STRING linkName;
                UNICODE_STRING targetName;
                OBJECT_ATTRIBUTES objectAttributes;

                RtlZeroMemory(linkBuffer, sizeof(linkBuffer));
                RtlZeroMemory(targetBuffer, sizeof(targetBuffer));
                linkBuffer[0] = L'\\';
                linkBuffer[1] = L'?';
                linkBuffer[2] = L'?';
                linkBuffer[3] = L'\\';
                linkBuffer[4] = (WCHAR)(L'A' + index);
                linkBuffer[5] = L':';
                linkBuffer[6] = L'\0';

                RtlInitUnicodeString(&linkName, linkBuffer);
                InitializeObjectAttributes(
                    &objectAttributes,
                    &linkName,
                    OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
                    NULL,
                    NULL);

                if (!NT_SUCCESS(ZwOpenSymbolicLinkObject(
                        &linkHandle,
                        SYMBOLIC_LINK_QUERY,
                        &objectAttributes))) {
                    continue;
                }

                targetName.Buffer = targetBuffer;
                targetName.Length = 0;
                targetName.MaximumLength = sizeof(targetBuffer) - sizeof(WCHAR);
                if (NT_SUCCESS(ZwQuerySymbolicLinkObject(linkHandle, &targetName, NULL)) &&
                    targetName.Length != 0) {
                    ULONG targetChars = targetName.Length / sizeof(WCHAR);
                    if (targetChars >= RTL_NUMBER_OF(targetBuffer)) {
                        targetChars = RTL_NUMBER_OF(targetBuffer) - 1;
                    }
                    targetBuffer[targetChars] = L'\0';
                    g_ImagePathPrefixCache[index].Valid = TRUE;
                    g_ImagePathPrefixCache[index].DosPrefix[0] = (WCHAR)(L'A' + index);
                    g_ImagePathPrefixCache[index].DosPrefix[1] = L':';
                    g_ImagePathPrefixCache[index].DosPrefix[2] = L'\0';
                    SysmonCopyWideString(
                        g_ImagePathPrefixCache[index].NtPrefix,
                        RTL_NUMBER_OF(g_ImagePathPrefixCache[index].NtPrefix),
                        targetBuffer);
                }

                ZwClose(linkHandle);
            }

            InterlockedExchange(&g_ImagePathPrefixCacheInitState, 2);
            KeSetEvent(&g_ImagePathPrefixCacheInitEvent, IO_NO_INCREMENT, FALSE);
            return;
        }

        (void)KeWaitForSingleObject(
            &g_ImagePathPrefixCacheInitEvent,
            Executive,
            KernelMode,
            FALSE,
            NULL);
    }
}

static BOOLEAN
SysmonPathNeedsDosNormalization(
    _In_opt_z_ PCWSTR Path)
{
    if (Path == NULL || Path[0] == L'\0') {
        return FALSE;
    }

    if (((Path[0] >= L'A' && Path[0] <= L'Z') ||
         (Path[0] >= L'a' && Path[0] <= L'z')) &&
        Path[1] == L':') {
        return FALSE;
    }

    return Path[0] == L'\\';
}

static BOOLEAN
SysmonIsDosDrivePath(
    _In_opt_z_ PCWSTR Path)
{
    return Path != NULL &&
        (((Path[0] >= L'A' && Path[0] <= L'Z') ||
          (Path[0] >= L'a' && Path[0] <= L'z')) &&
         Path[1] == L':');
}

static BOOLEAN
SysmonTryConvertNtPathToDosPath(
    _In_z_ PCWSTR SourcePath,
    _Out_writes_(BufferChars) PWCHAR Buffer,
    _In_ ULONG BufferChars)
{
    ULONG bestIndex = RTL_NUMBER_OF(g_ImagePathPrefixCache);
    SIZE_T bestPrefixChars = 0;
    ULONG index;

    if (Buffer == NULL || BufferChars == 0) {
        return FALSE;
    }

    Buffer[0] = L'\0';
    if (SourcePath == NULL || SourcePath[0] == L'\0') {
        return FALSE;
    }

    if (SysmonIsDosDrivePath(SourcePath)) {
        SysmonCopyWideString(Buffer, BufferChars, SourcePath);
        return TRUE;
    }
    if (!SysmonPathNeedsDosNormalization(SourcePath)) {
        return FALSE;
    }

    SysmonEnsureImagePathPrefixCacheInitialized();

    ExAcquireFastMutex(&g_ImagePathPrefixCacheLock);
    for (index = 0; index < RTL_NUMBER_OF(g_ImagePathPrefixCache); index++) {
        SIZE_T prefixChars;

        if (!g_ImagePathPrefixCache[index].Valid ||
            g_ImagePathPrefixCache[index].NtPrefix[0] == L'\0') {
            continue;
        }

        prefixChars = wcslen(g_ImagePathPrefixCache[index].NtPrefix);
        if (prefixChars == 0 ||
            prefixChars <= bestPrefixChars) {
            continue;
        }

        if (_wcsnicmp(SourcePath, g_ImagePathPrefixCache[index].NtPrefix, prefixChars) == 0) {
            bestIndex = index;
            bestPrefixChars = prefixChars;
        }
    }
    ExReleaseFastMutex(&g_ImagePathPrefixCacheLock);

    if (bestIndex == RTL_NUMBER_OF(g_ImagePathPrefixCache)) {
        return FALSE;
    }

    if (_snwprintf_s(
            Buffer,
            BufferChars,
            _TRUNCATE,
            L"%ls%ls",
            g_ImagePathPrefixCache[bestIndex].DosPrefix,
            SourcePath + bestPrefixChars) < 0) {
        Buffer[0] = L'\0';
        return FALSE;
    }

    return TRUE;
}

static BOOLEAN
SysmonTryBuildRuleMatchPath(
    _In_opt_z_ PCWSTR SourcePath,
    _Out_writes_(BufferChars) PWCHAR Buffer,
    _In_ ULONG BufferChars)
{
    if (Buffer == NULL || BufferChars == 0) {
        return FALSE;
    }

    Buffer[0] = L'\0';
    if (SourcePath == NULL || SourcePath[0] == L'\0') {
        return FALSE;
    }

    if (SysmonIsDosDrivePath(SourcePath)) {
        SysmonCopyWideString(Buffer, BufferChars, SourcePath);
        return TRUE;
    }
    if (!SysmonPathNeedsDosNormalization(SourcePath)) {
        return FALSE;
    }

    return SysmonTryConvertNtPathToDosPath(SourcePath, Buffer, BufferChars);
}

static BOOLEAN
SysmonShouldSkipImageEventBeforeFileInfo(
    _Inout_ PSYSMON_EVENT_UNION Event,
    _In_ SYSMON_EVENT_ID EventId,
    _In_ HANDLE ProcessId,
    _In_z_ PCWSTR ImageLoaded,
    _In_ ULONG ImageRuleRequirements,
    _In_opt_ const SYSMON_PROCESS_INFO *ProcessInfo,
    _In_opt_ PSYSMON_RULE_RUNTIME Runtime)
{
    SYSMON_PROCESS_INFO filterProcessInfo;
    WCHAR normalizedImageLoaded[SYSMON_MAX_PATH];
    BOOLEAN shouldCapture;

    if (Event == NULL || Runtime == NULL || Runtime->Header == NULL) {
        return FALSE;
    }

    if (!SysmonRuleRuntimeEventCanProduceLogs(Runtime, EventId)) {
        return TRUE;
    }

    if (ImageRuleRequirements != SysmonImageRuleRequirementNone) {
        return FALSE;
    }

    if (!SysmonTryBuildRuleMatchPath(
            ImageLoaded,
            normalizedImageLoaded,
            RTL_NUMBER_OF(normalizedImageLoaded))) {
        return FALSE;
    }

    shouldCapture = TRUE;
    if (EventId == SysmonEventImageLoad) {
        WCHAR normalizedImage[SYSMON_MAX_PATH];

        if (ProcessInfo == NULL ||
            !SysmonTryBuildRuleMatchPath(
                ProcessInfo->ImagePath,
                normalizedImage,
                RTL_NUMBER_OF(normalizedImage))) {
            return FALSE;
        }

        filterProcessInfo = *ProcessInfo;
        SysmonCopyWideString(
            filterProcessInfo.ImagePath,
            RTL_NUMBER_OF(filterProcessInfo.ImagePath),
            normalizedImage);
        SysmonWriteImageLoadEvent(
            Event,
            ProcessId,
            normalizedImageLoaded,
            &filterProcessInfo,
            NULL,
            FALSE);
    } else {
        SysmonPopulateDriverLoadEvent(
            Event,
            normalizedImageLoaded,
            NULL,
            FALSE);
    }

    shouldCapture = SysmonShouldCaptureEvent(Runtime, EventId, Event);
    return !shouldCapture;
}

static ULONG
SysmonClassifyImageHashValueState(
    _In_ BOOLEAN HaveFileInfo,
    _In_opt_ const SYSMON_FILE_INFO *FileInfo)
{
    if (!HaveFileInfo || FileInfo == NULL) {
        return 1u;
    }

    if (FileInfo->Hashes[0] == L'\0') {
        return 2u;
    }

    if (FileInfo->Hashes[0] == L'-') {
        return 3u;
    }

    return 4u;
}

VOID
SysmonQueryImageDebugStats(
    _Out_ PSYSMON_PROCESS_DEBUG_STATS Stats)
{
    SYSMON_FILEINFO_DEBUG_SNAPSHOT fileInfoSnapshot;
    SYSMON_HASH_DEBUG_SNAPSHOT hashSnapshot;

    if (Stats == NULL) {
        return;
    }

    RtlZeroMemory(&fileInfoSnapshot, sizeof(fileInfoSnapshot));
    RtlZeroMemory(&hashSnapshot, sizeof(hashSnapshot));
    SysmonQueryFileInfoDebugSnapshot(&fileInfoSnapshot);
    SysmonQueryHashDebugSnapshot(&hashSnapshot);

    Stats->ContextImageNotifyEnabled = SysmonIsProducerEnabled(SYSMON_FLAG_IMAGE_NOTIFY) ? 1u : 0u;
    Stats->ContextImageLoadEventEnabled = SysmonIsProducerEnabled(SYSMON_FLAG_IMAGE_LOAD_EVENT) ? 1u : 0u;
    Stats->ContextHashingAlgorithm = g_Context.HashingAlgorithm;
    Stats->LastImageTargetEventId = (ULONG)InterlockedCompareExchange(&g_LastImageTargetEventId, 0, 0);
    Stats->LastImageRuleRequirements = (ULONG)InterlockedCompareExchange(&g_LastImageRuleRequirements, 0, 0);
    Stats->LastImageFileInfoRequestMask = (ULONG)InterlockedCompareExchange(&g_LastImageFileInfoRequestMask, 0, 0);
    Stats->LastImageCollectStatus = (ULONG)InterlockedCompareExchange(&g_LastImageCollectStatus, 0, 0);
    Stats->LastImageHaveFileInfo = (ULONG)InterlockedCompareExchange(&g_LastImageHaveFileInfo, 0, 0);
    Stats->LastImageHashValueState = (ULONG)InterlockedCompareExchange(&g_LastImageHashValueState, 0, 0);
    Stats->LastImageHashMaskUsed = fileInfoSnapshot.LastHashMaskUsed;
    Stats->LastImageHashStatus = fileInfoSnapshot.LastHashStatus;
    Stats->LastImageAvailableMask = fileInfoSnapshot.LastAvailableMask;
    Stats->LastImageFileContentMode = fileInfoSnapshot.LastFileContentMode;
    Stats->ImageQueueDropCount = (ULONG)InterlockedCompareExchange(&g_ImageQueueDropCount, 0, 0);
    Stats->LastImageDropReason = (ULONG)InterlockedCompareExchange(&g_LastImageDropReason, 0, 0);
    Stats->FileInfoCollectCallCount = fileInfoSnapshot.FileInfoCollectCallCount;
    Stats->FileInfoCacheLookupCount = fileInfoSnapshot.FileInfoCacheLookupCount;
    Stats->FileInfoCacheHitCount = fileInfoSnapshot.FileInfoCacheHitCount;
    Stats->FileInfoCacheStoreCount = fileInfoSnapshot.FileInfoCacheStoreCount;
    Stats->FileInfoMapAttemptCount = fileInfoSnapshot.FileInfoMapAttemptCount;
    Stats->FileInfoMapSuccessCount = fileInfoSnapshot.FileInfoMapSuccessCount;
    Stats->FileInfoReadFallbackCount = fileInfoSnapshot.FileInfoReadFallbackCount;
    Stats->FileInfoReadRetryCount = fileInfoSnapshot.FileInfoReadRetryCount;
    Stats->FileInfoHashComputeCount = fileInfoSnapshot.FileInfoHashComputeCount;
    Stats->FileInfoVersionParseCount = fileInfoSnapshot.FileInfoVersionParseCount;
    Stats->FileInfoMapUsecTotal = fileInfoSnapshot.FileInfoMapUsecTotal;
    Stats->FileInfoReadUsecTotal = fileInfoSnapshot.FileInfoReadUsecTotal;
    Stats->FileInfoHashUsecTotal = fileInfoSnapshot.FileInfoHashUsecTotal;
    Stats->FileInfoVersionUsecTotal = fileInfoSnapshot.FileInfoVersionUsecTotal;
    Stats->ImphashCallCount = hashSnapshot.ImphashCallCount;
    Stats->ImphashReadRvaCallCount = hashSnapshot.ImphashReadRvaCallCount;
    Stats->ImphashImportDescriptorCount = hashSnapshot.ImphashImportDescriptorCount;
    Stats->ImphashImportEntryCount = hashSnapshot.ImphashImportEntryCount;
    Stats->ImphashHashedImportCount = hashSnapshot.ImphashHashedImportCount;
    Stats->ImphashOrdinalImportCount = hashSnapshot.ImphashOrdinalImportCount;
    Stats->ImphashSectionCachePoolAllocCount = hashSnapshot.ImphashSectionCachePoolAllocCount;
    Stats->ImphashSectionCountTotal = hashSnapshot.ImphashSectionCountTotal;
}

static ULONG
SysmonDetermineImageWorkerCount(VOID)
{
    ULONG processorCount;

    processorCount = KeQueryActiveProcessorCount(NULL);
    if (processorCount >= 8) {
        return 4;
    }
    if (processorCount >= 4) {
        return 2;
    }

    return 1;
}

static ULONG
SysmonGetImageQueueIndexForCurrentProcessor(VOID)
{
    ULONG processorNumber;

    if (g_ImageWorkQueueCount <= 1) {
        return 0;
    }

    processorNumber = KeGetCurrentProcessorNumberEx(NULL);
    return processorNumber % g_ImageWorkQueueCount;
}

static BOOLEAN
SysmonTryDequeueImageWorkContext(
    _In_ ULONG StartQueueIndex,
    _Out_ PSYSMON_IMAGE_WORK_CONTEXT *WorkContext)
{
    ULONG offset;

    if (WorkContext == NULL || g_ImageWorkQueueCount == 0) {
        return FALSE;
    }

    *WorkContext = NULL;
    for (offset = 0; offset < g_ImageWorkQueueCount; offset++) {
        ULONG queueIndex;
        PSYSMON_IMAGE_WORK_QUEUE queue;

        queueIndex = (StartQueueIndex + offset) % g_ImageWorkQueueCount;
        queue = &g_ImageWorkQueues[queueIndex];
        ExAcquireFastMutex(&queue->Lock);
        if (!IsListEmpty(&queue->WorkList)) {
            PLIST_ENTRY listEntry = RemoveHeadList(&queue->WorkList);

            ExReleaseFastMutex(&queue->Lock);
            *WorkContext = CONTAINING_RECORD(
                listEntry,
                SYSMON_IMAGE_WORK_CONTEXT,
                ListEntry);
            return TRUE;
        }
        ExReleaseFastMutex(&queue->Lock);
    }

    return FALSE;
}

static VOID
SysmonDiscardPendingImageWork(VOID)
{
    ULONG queueIndex;

    for (queueIndex = 0; queueIndex < g_ImageWorkQueueCount; queueIndex++) {
        PSYSMON_IMAGE_WORK_QUEUE queue = &g_ImageWorkQueues[queueIndex];

        ExAcquireFastMutex(&queue->Lock);
        while (!IsListEmpty(&queue->WorkList)) {
            PLIST_ENTRY listEntry = RemoveHeadList(&queue->WorkList);
            PSYSMON_IMAGE_WORK_CONTEXT workContext = CONTAINING_RECORD(
                listEntry,
                SYSMON_IMAGE_WORK_CONTEXT,
                ListEntry);

            SysmonFreePool(workContext);
            InterlockedDecrement(&g_ImageWorkItemCount);
        }
        ExReleaseFastMutex(&queue->Lock);
    }
}

static ULONG
SysmonClaimImageWorkerSlot(VOID)
{
    ULONG workerIndex;

    for (workerIndex = 0; workerIndex < g_ImageWorkerCount; workerIndex++) {
        if (InterlockedCompareExchange(&g_ImageWorkerQueued[workerIndex], 1, 0) == 0) {
            return workerIndex;
        }
    }

    return g_ImageWorkerCount;
}

static BOOLEAN
SysmonIsKernelImageLoad(
    _In_ HANDLE ProcessId,
    _In_opt_ PIMAGE_INFO ImageInfo)
{
    if (ImageInfo != NULL && ImageInfo->SystemModeImage != 0) {
        return TRUE;
    }

    return (BOOLEAN)(((ULONG_PTR)ProcessId == 4) || (ProcessId == NULL));
}

static ULONG
SysmonReserveImageWorkers(
    _Out_writes_(MaxWorkers) PIO_WORKITEM *Workers,
    _Out_writes_(MaxWorkers) PVOID *WorkerContexts,
    _In_ ULONG MaxWorkers)
{
    ULONG reserved;

    if (Workers == NULL || WorkerContexts == NULL || MaxWorkers == 0) {
        return 0;
    }

    reserved = 0;
    while (reserved < MaxWorkers) {
        LONG activeWorkers;
        LONG pendingItems;
        ULONG workerIndex;

        pendingItems = InterlockedCompareExchange(&g_ImageWorkItemCount, 0, 0);
        activeWorkers = InterlockedCompareExchange(&g_ImageActiveWorkers, 0, 0);
        if (pendingItems <= activeWorkers ||
            activeWorkers >= (LONG)g_ImageWorkerCount) {
            break;
        }

        if (InterlockedCompareExchange(
                &g_ImageActiveWorkers,
                activeWorkers + 1,
                activeWorkers) != activeWorkers) {
            continue;
        }

        workerIndex = SysmonClaimImageWorkerSlot();
        if (workerIndex >= g_ImageWorkerCount) {
            (void)InterlockedDecrement(&g_ImageActiveWorkers);
            break;
        }

        Workers[reserved] = g_ImageIoWorkItems[workerIndex];
        WorkerContexts[reserved] = ULongToPtr(workerIndex);
        reserved += 1;
    }

    if (reserved != 0) {
        KeClearEvent(&g_ImageWorkerIdleEvent);
    }

    return reserved;
}

static VOID
SysmonPopulateImageProcessIdentity(
    _In_ HANDLE ProcessId,
    _Out_ PSYSMON_PROCESS_INFO ProcessInfo)
{
    SYSMON_PROCESS_CACHE_METADATA cachedMetadata;
    PEPROCESS process;

    if (ProcessInfo == NULL) {
        return;
    }

    RtlZeroMemory(ProcessInfo, sizeof(*ProcessInfo));
    ProcessInfo->ProcessId = HandleToULong(ProcessId);

    RtlZeroMemory(&cachedMetadata, sizeof(cachedMetadata));
    if (SysmonLookupCachedProcessMetadata(ProcessInfo->ProcessId, &cachedMetadata)) {
        ProcessInfo->CreateTime = cachedMetadata.CreateTime;
        SysmonCopyWideStringWithLength(
            ProcessInfo->ProcessGuid,
            RTL_NUMBER_OF(ProcessInfo->ProcessGuid),
            cachedMetadata.ProcessGuid,
            SYSMON_GUID_STRING_CHARS);
        SysmonCopyWideString(
            ProcessInfo->ImagePath,
            RTL_NUMBER_OF(ProcessInfo->ImagePath),
            cachedMetadata.Image);
        SysmonCopyWideString(
            ProcessInfo->UserSid,
            RTL_NUMBER_OF(ProcessInfo->UserSid),
            cachedMetadata.UserSid);
    }

    if (ProcessInfo->ImagePath[0] == L'\0' &&
        NT_SUCCESS(PsLookupProcessByProcessId(ProcessId, &process))) {
        /*
         * Image-load work items already run off the image notify path. Avoid
         * reopening the process or querying its token here; a stable basename
         * is safer than re-entering object-manager open paths.
         */
        (void)SysmonAnsiToWide(
            PsGetProcessImageFileName(process),
            ProcessInfo->ImagePath,
            RTL_NUMBER_OF(ProcessInfo->ImagePath));
        ObDereferenceObject(process);
    }

    if (ProcessInfo->CreateTime == 0) {
        ProcessInfo->CreateTime = SysmonGetCurrentTimestamp();
    }
    if (ProcessInfo->ProcessGuid[0] == L'\0') {
        SysmonGenerateProcessGuid(
            ProcessInfo->ProcessId,
            ProcessInfo->CreateTime,
            ProcessInfo->ProcessGuid);
    }
}

static VOID
SysmonProcessImageWorkContext(
    _In_ PSYSMON_IMAGE_WORK_CONTEXT context)
{
    PSYSMON_EVENT_UNION event;
    PSYSMON_RULE_RUNTIME runtime;
    SYSMON_EVENT_ID targetEventId;
    ULONG imageRuleRequirements;
    ULONG fileInfoRequestMask;
    ULONG hashMask;
    PSYSMON_PROCESS_INFO processInfo;
    PSYSMON_FILE_INFO fileInfo;
    BOOLEAN haveFileInfo;
    BOOLEAN shouldCollectVersionInfo;

    if (context == NULL) {
        return;
    }

    processInfo = NULL;
    fileInfo = NULL;
    haveFileInfo = FALSE;
    shouldCollectVersionInfo = FALSE;
    targetEventId = context->DriverLoad ? SysmonEventDriverLoad : SysmonEventImageLoad;
    InterlockedExchange(&g_LastImageTargetEventId, (LONG)targetEventId);
    InterlockedExchange(&g_LastImageCollectStatus, (LONG)STATUS_NOT_SUPPORTED);
    InterlockedExchange(&g_LastImageHaveFileInfo, 0);
    InterlockedExchange(&g_LastImageHashValueState, 0);

    if ((context->DriverLoad && !SysmonIsProducerEnabled(SYSMON_FLAG_DRIVER_LOAD_NOTIFY)) ||
        (!context->DriverLoad &&
         !SysmonIsProducerEnabled(SYSMON_FLAG_IMAGE_LOAD_EVENT) &&
         !SysmonIsProducerEnabled(SYSMON_FLAG_TAMPERING_NOTIFY))) {
        SysmonFreePool(context);
        return;
    }

    event = SysmonAllocateEvent(
        targetEventId);
    if (event != NULL) {
        runtime = SysmonAcquireRuleRuntimeSnapshot();
        imageRuleRequirements = SysmonGetImageRuleRequirements(
            runtime,
            targetEventId);
        InterlockedExchange(&g_LastImageRuleRequirements, (LONG)imageRuleRequirements);
        if (!context->DriverLoad) {
            processInfo = (PSYSMON_PROCESS_INFO)SysmonAllocatePool(sizeof(*processInfo));
            if (processInfo == NULL) {
                SysmonReleaseRuleRuntimeSnapshot(runtime);
                SysmonFreeEvent(event);
                SysmonFreePool(context);
                return;
            }

            SysmonPopulateImageProcessIdentity(context->ProcessId, processInfo);
        }
        if (SysmonShouldSkipImageEventBeforeFileInfo(
                event,
                targetEventId,
                context->ProcessId,
                context->ImageLoaded,
                imageRuleRequirements,
                processInfo,
                runtime)) {
            SysmonReleaseRuleRuntimeSnapshot(runtime);
            SysmonFreeEvent(event);
            SysmonFreePool(fileInfo);
            SysmonFreePool(processInfo);
            SysmonFreePool(context);
            return;
        }
        fileInfoRequestMask = 0;
        hashMask = g_Context.HashingAlgorithm;
        if ((hashMask != 0) ||
            ((imageRuleRequirements & SysmonImageRuleRequirementHashes) != 0)) {
            fileInfoRequestMask |= SYSMON_FILEINFO_REQUEST_HASHES;
        }
        InterlockedExchange(&g_LastImageFileInfoRequestMask, (LONG)fileInfoRequestMask);

        shouldCollectVersionInfo =
            (imageRuleRequirements & SysmonImageRuleRequirementVersionInfo) != 0;
        if (shouldCollectVersionInfo &&
            runtime != NULL &&
            processInfo != NULL) {
            SysmonWriteImageLoadEvent(
                event,
                context->ProcessId,
                context->ImageLoaded,
                processInfo,
                NULL,
                FALSE);
            shouldCollectVersionInfo = SysmonShouldCollectImageVersionInfoForEvent(
                runtime,
                targetEventId,
                event);
        }

        if (fileInfoRequestMask != 0 ||
            shouldCollectVersionInfo) {
            fileInfo = (PSYSMON_FILE_INFO)SysmonAllocatePool(sizeof(*fileInfo));
        }

        if (context->DriverLoad) {
            NTSTATUS fileInfoStatus;

            fileInfoStatus = STATUS_NOT_SUPPORTED;
            haveFileInfo =
                (fileInfo != NULL) &&
                (fileInfoRequestMask != 0) &&
                NT_SUCCESS(fileInfoStatus = SysmonCollectFileInfoByPathEx(
                    context->ImageLoaded,
                    fileInfoRequestMask,
                    fileInfo));
            InterlockedExchange(&g_LastImageCollectStatus, (LONG)fileInfoStatus);
            InterlockedExchange(&g_LastImageHaveFileInfo, haveFileInfo ? 1 : 0);
            InterlockedExchange(
                &g_LastImageHashValueState,
                (LONG)SysmonClassifyImageHashValueState(haveFileInfo, fileInfo));
            SysmonPopulateDriverLoadEvent(
                event,
                context->ImageLoaded,
                fileInfo,
                haveFileInfo);
        } else {
            SysmonPopulateImageLoadEvent(
                event,
                context->ProcessId,
                context->ImageLoaded,
                shouldCollectVersionInfo
                    ? (fileInfoRequestMask | SYSMON_FILEINFO_REQUEST_VERSION_INFO)
                    : fileInfoRequestMask,
                processInfo,
                fileInfo);
        }
        SysmonReleaseRuleRuntimeSnapshot(runtime);

        SysmonPublishEvent(event);
        SysmonFreeEvent(event);
    }

    SysmonFreePool(fileInfo);
    SysmonFreePool(processInfo);
    SysmonFreePool(context);
}

static BOOLEAN
SysmonQueueImageWorkContext(
    _In_ PSYSMON_IMAGE_WORK_CONTEXT Context)
{
    PIO_WORKITEM workersToQueue[SYSMON_MAX_IMAGE_WORKERS];
    PVOID workerContexts[SYSMON_MAX_IMAGE_WORKERS];
    ULONG workerCountToQueue;
    ULONG queueIndex;
    ULONG maxQueueDepth;
    ULONG workerIndex;
    PSYSMON_IMAGE_WORK_QUEUE queue;

    if (Context == NULL) {
        return FALSE;
    }

    if (!g_ImageWorkerInitialized || g_ImageWorkerCount == 0 || g_ImageWorkQueueCount == 0) {
        SysmonRecordImageQueueDrop(SYSMON_IMAGE_DROP_REASON_WORKER_UNAVAILABLE);
        return FALSE;
    }

    if (InterlockedCompareExchange(&g_ImageAcceptingWork, 0, 0) == 0) {
        SysmonRecordImageQueueDrop(SYSMON_IMAGE_DROP_REASON_STOPPING);
        return FALSE;
    }

    maxQueueDepth = g_Context.SigningQueueSize;
    if (maxQueueDepth == 0) {
        maxQueueDepth = 1000;
    }

    if ((ULONG)InterlockedCompareExchange(&g_ImageWorkItemCount, 0, 0) >= maxQueueDepth) {
        SysmonRecordImageQueueDrop(SYSMON_IMAGE_DROP_REASON_QUEUE_FULL);
        return FALSE;
    }

    queueIndex = SysmonGetImageQueueIndexForCurrentProcessor();
    queue = &g_ImageWorkQueues[queueIndex];
    ExAcquireFastMutex(&queue->Lock);
    if (!g_ImageWorkerInitialized || g_ImageWorkerCount == 0 || g_ImageWorkQueueCount == 0) {
        ExReleaseFastMutex(&queue->Lock);
        SysmonRecordImageQueueDrop(SYSMON_IMAGE_DROP_REASON_WORKER_UNAVAILABLE);
        return FALSE;
    }

    if (InterlockedCompareExchange(&g_ImageAcceptingWork, 0, 0) == 0) {
        ExReleaseFastMutex(&queue->Lock);
        SysmonRecordImageQueueDrop(SYSMON_IMAGE_DROP_REASON_STOPPING);
        return FALSE;
    }

    InsertTailList(&queue->WorkList, &Context->ListEntry);
    InterlockedIncrement(&g_ImageWorkItemCount);
    ExReleaseFastMutex(&queue->Lock);

    workerCountToQueue = SysmonReserveImageWorkers(
        workersToQueue,
        workerContexts,
        RTL_NUMBER_OF(workersToQueue));

    for (workerIndex = 0; workerIndex < workerCountToQueue; workerIndex++) {
        IoQueueWorkItem(
            workersToQueue[workerIndex],
            SysmonImageIoWorkItemCallback,
            DelayedWorkQueue,
            workerContexts[workerIndex]);
    }

    return TRUE;
}

static VOID
SysmonImageIoWorkItemCallback(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_opt_ PVOID Context)
{
    PSYSMON_IMAGE_WORK_CONTEXT workContext;
    PIO_WORKITEM workersToQueue[SYSMON_MAX_IMAGE_WORKERS];
    PVOID workerContexts[SYSMON_MAX_IMAGE_WORKERS];
    ULONG workerCountToQueue;
    ULONG workerIndex;
    ULONG startQueueIndex;
    ULONG imageWorkerIndex;
    BOOLEAN signalIdle;

    UNREFERENCED_PARAMETER(DeviceObject);

    imageWorkerIndex = PtrToUlong(Context);
    workContext = NULL;
    startQueueIndex = (ULONG)InterlockedIncrement(&g_ImageQueueStealCursor);

    for (;;) {
        if (!SysmonTryDequeueImageWorkContext(startQueueIndex, &workContext)) {
            break;
        }

        SysmonProcessImageWorkContext(workContext);
        InterlockedDecrement(&g_ImageWorkItemCount);
        startQueueIndex += 1;
    }

    workerCountToQueue = 0;
    signalIdle = FALSE;
    if (imageWorkerIndex < g_ImageWorkerCount) {
        if (InterlockedCompareExchange(&g_ImageWorkerQueued[imageWorkerIndex], 0, 1) == 1) {
            (void)InterlockedDecrement(&g_ImageActiveWorkers);
        }
    }
    if (InterlockedCompareExchange(&g_ImageAcceptingWork, 0, 0) != 0 &&
        InterlockedCompareExchange(&g_ImageWorkItemCount, 0, 0) != 0) {
        workerCountToQueue = SysmonReserveImageWorkers(
            workersToQueue,
            workerContexts,
            RTL_NUMBER_OF(workersToQueue));
    }

    /* Once image notifications are disabled, no new work can be admitted.
       A worker may nevertheless observe items left on another CPU queue after
       it releases its slot. Discard those items here so cleanup can wait for
       a real idle state without freeing a queued context behind a callback. */
    if (InterlockedCompareExchange(&g_ImageAcceptingWork, 0, 0) == 0) {
        SysmonDiscardPendingImageWork();
    }

    if (InterlockedCompareExchange(&g_ImageActiveWorkers, 0, 0) == 0 &&
        InterlockedCompareExchange(&g_ImageWorkItemCount, 0, 0) == 0) {
        signalIdle = TRUE;
    }

    if (signalIdle) {
        KeSetEvent(&g_ImageWorkerIdleEvent, IO_NO_INCREMENT, FALSE);
    }

    for (workerIndex = 0; workerIndex < workerCountToQueue; workerIndex++) {
        IoQueueWorkItem(
            workersToQueue[workerIndex],
            SysmonImageIoWorkItemCallback,
            DelayedWorkQueue,
            workerContexts[workerIndex]);
    }
}

static VOID
SysmonCleanupImageWorkers(VOID)
{
    ULONG queueIndex;

    if (!g_ImageWorkerInitialized || g_ImageWorkerCount == 0) {
        return;
    }

    if (InterlockedCompareExchange(&g_ImageActiveWorkers, 0, 0) != 0 ||
        InterlockedCompareExchange(&g_ImageWorkItemCount, 0, 0) != 0) {
        (void)KeWaitForSingleObject(
            &g_ImageWorkerIdleEvent,
            Executive,
            KernelMode,
            FALSE,
            NULL);
    }

    for (queueIndex = 0; queueIndex < g_ImageWorkQueueCount; queueIndex++) {
        PSYSMON_IMAGE_WORK_QUEUE queue = &g_ImageWorkQueues[queueIndex];

        ExAcquireFastMutex(&queue->Lock);
        while (!IsListEmpty(&queue->WorkList)) {
            PLIST_ENTRY listEntry = RemoveHeadList(&queue->WorkList);
            PSYSMON_IMAGE_WORK_CONTEXT workContext = CONTAINING_RECORD(
                listEntry,
                SYSMON_IMAGE_WORK_CONTEXT,
                ListEntry);

            SysmonFreePool(workContext);
        }
        ExReleaseFastMutex(&queue->Lock);
    }

    while (g_ImageWorkerCount > 0) {
        g_ImageWorkerCount -= 1;
        IoFreeWorkItem(g_ImageIoWorkItems[g_ImageWorkerCount]);
        g_ImageIoWorkItems[g_ImageWorkerCount] = NULL;
    }

    g_ImageWorkerInitialized = FALSE;
    g_ImageWorkQueueCount = 0;
    g_ImageWorkItemCount = 0;
    g_ImageActiveWorkers = 0;
    g_ImageQueueStealCursor = 0;
    RtlZeroMemory((PVOID)g_ImageWorkerQueued, sizeof(g_ImageWorkerQueued));
}

static VOID
SysmonPopulateDriverLoadEvent(
    _Inout_ PSYSMON_EVENT_UNION Event,
    _In_z_ PCWSTR ImageLoaded,
    _In_opt_ const SYSMON_FILE_INFO *FileInfo,
    _In_ BOOLEAN HaveFileInfo)
{
    SYSMON_EVENT_DRIVER_LOAD_PAYLOAD *eventData;
    SYSMON_EVENT_PAYLOAD_BUILDER builder;

      eventData = (SYSMON_EVENT_DRIVER_LOAD_PAYLOAD *)Event->RawData;
      SysmonBeginStringPayload(Event, sizeof(*eventData), &builder);
      Event->Header.Timestamp = SysmonGetCurrentTimestamp();
      Event->Header.SequenceNumber = (ULONG)InterlockedIncrement(&g_ImageSequence);

      SysmonAddStringLiteralField(Event, &builder, &eventData->RuleName, L"-");
      SysmonAddCurrentUtcTimeField(Event, &builder, &eventData->UtcTime);
      SysmonAddStringField(Event, &builder, &eventData->ImageLoaded, ImageLoaded);
      if (HaveFileInfo && FileInfo != NULL && FileInfo->Hashes[0] != L'\0' &&
          FileInfo->Hashes[0] != L'-') {
          SysmonAddStringField(Event, &builder, &eventData->Hashes, FileInfo->Hashes);
      } else {
          SysmonAddStringLiteralField(Event, &builder, &eventData->Hashes, L"-");
      }
    /* BOOLEAN has no unknown state; SignatureStatus carries the deferred state. */
    eventData->Signed = FALSE;
    SysmonAddStringLiteralField(Event, &builder, &eventData->Signature, L"Unavailable");
    SysmonAddStringLiteralField(Event, &builder, &eventData->SignatureStatus, L"Unavailable");
    SYSMON_HOTPATH_LOG(
        DPFLTR_INFO_LEVEL,
        "[SysmonDrv] DriverLoad built size=%lu image=%ws\n",
        Event->Header.EventSize,
        ImageLoaded);
}

static VOID
SysmonWriteImageLoadEvent(
    _Inout_ PSYSMON_EVENT_UNION Event,
    _In_ HANDLE ProcessId,
    _In_z_ PCWSTR ImageLoaded,
    _In_ const SYSMON_PROCESS_INFO *ProcessInfo,
    _In_opt_ const SYSMON_FILE_INFO *FileInfo,
    _In_ BOOLEAN HaveFileInfo)
{
    SYSMON_EVENT_IMAGE_LOAD_PAYLOAD *eventData;
    SYSMON_EVENT_PAYLOAD_BUILDER builder;

    eventData = (SYSMON_EVENT_IMAGE_LOAD_PAYLOAD *)Event->RawData;
    SysmonBeginStringPayload(Event, sizeof(*eventData), &builder);
    Event->Header.Timestamp = SysmonGetCurrentTimestamp();
    Event->Header.SequenceNumber = (ULONG)InterlockedIncrement(&g_ImageSequence);

    SysmonAddStringLiteralField(Event, &builder, &eventData->RuleName, L"-");
    SysmonAddCurrentUtcTimeField(Event, &builder, &eventData->UtcTime);
    SysmonAddFixedLengthStringField(
        Event,
        &builder,
        &eventData->ProcessGuid,
        ProcessInfo->ProcessGuid,
        SYSMON_GUID_STRING_CHARS);
    eventData->ProcessId = (ULONG)(ULONG_PTR)ProcessId;
    SysmonAddStringField(Event, &builder, &eventData->Image, ProcessInfo->ImagePath);
    SysmonAddStringField(Event, &builder, &eventData->ImageLoaded, ImageLoaded);
    if (HaveFileInfo && FileInfo != NULL && FileInfo->Hashes[0] != L'\0' &&
        FileInfo->Hashes[0] != L'-') {
        SysmonAddStringField(Event, &builder, &eventData->Hashes, FileInfo->Hashes);
    } else {
        SysmonAddStringLiteralField(Event, &builder, &eventData->Hashes, L"-");
    }
    eventData->Signed = FALSE;
    SysmonAddStringLiteralField(Event, &builder, &eventData->Signature, L"Unavailable");
    SysmonAddStringLiteralField(Event, &builder, &eventData->SignatureStatus, L"Unavailable");
    SysmonAddStringField(
        Event,
        &builder,
        &eventData->FileVersion,
        (HaveFileInfo && FileInfo != NULL && FileInfo->FileVersion[0] != L'\0') ? FileInfo->FileVersion : NULL);
    SysmonAddStringField(
        Event,
        &builder,
        &eventData->Description,
        (HaveFileInfo && FileInfo != NULL && FileInfo->FileDescription[0] != L'\0') ? FileInfo->FileDescription : NULL);
    SysmonAddStringField(
        Event,
        &builder,
        &eventData->Product,
        (HaveFileInfo && FileInfo != NULL && FileInfo->ProductName[0] != L'\0') ? FileInfo->ProductName : NULL);
    SysmonAddStringField(
        Event,
        &builder,
        &eventData->Company,
        (HaveFileInfo && FileInfo != NULL && FileInfo->CompanyName[0] != L'\0') ? FileInfo->CompanyName : NULL);
    SysmonAddStringField(
        Event,
        &builder,
        &eventData->OriginalFileName,
        (HaveFileInfo && FileInfo != NULL && FileInfo->OriginalFileName[0] != L'\0') ? FileInfo->OriginalFileName : NULL);
    SysmonAddStringField(Event, &builder, &eventData->User, ProcessInfo->UserSid);
}

static VOID
SysmonPopulateImageLoadEvent(
    _Inout_ PSYSMON_EVENT_UNION Event,
    _In_ HANDLE ProcessId,
    _In_z_ PCWSTR ImageLoaded,
    _In_ ULONG FileInfoRequestMask,
    _Inout_ PSYSMON_PROCESS_INFO ProcessInfo,
    _Inout_opt_ PSYSMON_FILE_INFO FileInfo)
{
    SYSMON_EVENT_IMAGE_LOAD_PAYLOAD *eventData;
    BOOLEAN haveFileInfo;
    BOOLEAN shouldCollectVersionInfo;
    BOOLEAN shouldCollectHashes;

    if (ProcessInfo == NULL) {
        return;
    }

    if (ProcessInfo->ProcessId == 0) {
        SysmonPopulateImageProcessIdentity(ProcessId, ProcessInfo);
    }
    shouldCollectVersionInfo =
        (FileInfoRequestMask & SYSMON_FILEINFO_REQUEST_VERSION_INFO) != 0;
    shouldCollectHashes =
        (FileInfoRequestMask & SYSMON_FILEINFO_REQUEST_HASHES) != 0;

    if (FileInfo != NULL && (shouldCollectHashes || shouldCollectVersionInfo)) {
        NTSTATUS fileInfoStatus = SysmonCollectFileInfoByPathEx(ImageLoaded, FileInfoRequestMask, FileInfo);
        haveFileInfo = NT_SUCCESS(fileInfoStatus);
        InterlockedExchange(&g_LastImageCollectStatus, (LONG)fileInfoStatus);
        if (!haveFileInfo &&
            shouldCollectHashes &&
            FileInfo != NULL) {
            if (_snwprintf_s(
                    FileInfo->Hashes,
                    RTL_NUMBER_OF(FileInfo->Hashes),
                    _TRUNCATE,
                    L"COLLECT=0x%08X",
                    fileInfoStatus) >= 0) {
                haveFileInfo = TRUE;
            }
        }
        SYSMON_HOTPATH_LOG(
            DPFLTR_INFO_LEVEL,
            "[SysmonDrv] CollectFileInfo path=%ws mask=0x%lx status=0x%lx hashes=%ws\n",
            ImageLoaded,
            FileInfoRequestMask,
            fileInfoStatus,
            haveFileInfo ? FileInfo->Hashes : L"(skipped)");
    } else {
        haveFileInfo = FALSE;
        InterlockedExchange(&g_LastImageCollectStatus, (LONG)STATUS_NOT_SUPPORTED);
        SYSMON_HOTPATH_LOG(
            DPFLTR_INFO_LEVEL,
            "[SysmonDrv] CollectFileInfo skipped path=%ws FileInfo=%p collectHashes=%d collectVer=%d\n",
            ImageLoaded,
            FileInfo,
            shouldCollectHashes,
            shouldCollectVersionInfo);
    }
    InterlockedExchange(&g_LastImageHaveFileInfo, haveFileInfo ? 1 : 0);
    InterlockedExchange(
        &g_LastImageHashValueState,
        (LONG)SysmonClassifyImageHashValueState(haveFileInfo, FileInfo));

    SysmonWriteImageLoadEvent(
        Event,
        ProcessId,
        ImageLoaded,
        ProcessInfo,
        FileInfo,
        haveFileInfo);

    eventData = (SYSMON_EVENT_IMAGE_LOAD_PAYLOAD *)Event->RawData;
    SYSMON_HOTPATH_LOG(
        DPFLTR_INFO_LEVEL,
        "[SysmonDrv] ImageLoad built size=%lu pid=%lu image=%ws loaded=%ws\n",
        Event->Header.EventSize,
        eventData->ProcessId,
        ProcessInfo->ImagePath,
        ImageLoaded);
}

static VOID
ImageNotifyCallback(
    _In_opt_ PUNICODE_STRING FullImageName,
    _In_ HANDLE ProcessId,
    _In_ PIMAGE_INFO ImageInfo)
{
    PSYSMON_IMAGE_WORK_CONTEXT context;
    BOOLEAN driverLoad;
    HANDLE effectiveProcessId;
    WCHAR imageLoaded[SYSMON_MAX_PATH];
    if (!SysmonIsProducerEnabled(SYSMON_FLAG_ENABLED) || !SysmonIsProducerEnabled(SYSMON_FLAG_IMAGE_NOTIFY)) {
        return;
    }

    SysmonCopyUnicodeString(imageLoaded, RTL_NUMBER_OF(imageLoaded), FullImageName);
    if (imageLoaded[0] == L'\0') {
        return;
    }

    driverLoad = FALSE;
    effectiveProcessId = ProcessId;
    if (effectiveProcessId == NULL) {
        effectiveProcessId = PsGetCurrentProcessId();
    }

    /*
     * DriverLoad (Event 6): Detect kernel driver loads.
     * Use IMAGE_INFO.SystemModeImage as the primary signal because
     * kernel-mode images are not limited to a .sys suffix.
     */
    if (SysmonIsKernelImageLoad(effectiveProcessId, ImageInfo)) {
        driverLoad = TRUE;
    }

    if ((driverLoad && !SysmonIsProducerEnabled(SYSMON_FLAG_DRIVER_LOAD_NOTIFY)) ||
        (!driverLoad &&
         !SysmonIsProducerEnabled(SYSMON_FLAG_IMAGE_LOAD_EVENT) &&
         !SysmonIsProducerEnabled(SYSMON_FLAG_TAMPERING_NOTIFY))) {
        return;
    }

    if (!driverLoad && SysmonIsProducerEnabled(SYSMON_FLAG_TAMPERING_NOTIFY)) {
        SysmonCheckProcessTamperingOnImageLoadSynchronous(effectiveProcessId);
    }

    context = (PSYSMON_IMAGE_WORK_CONTEXT)SysmonAllocatePool(sizeof(*context));
    if (context == NULL) {
        return;
    }

    RtlZeroMemory(context, sizeof(*context));
    context->ProcessId = effectiveProcessId;
    context->DriverLoad = driverLoad;
    SysmonCopyWideString(
        context->ImageLoaded,
        RTL_NUMBER_OF(context->ImageLoaded),
        imageLoaded);
    if (!SysmonQueueImageWorkContext(context)) {
        SysmonFreePool(context);
    }
}

NTSTATUS
SysmonRegisterImageNotify(_In_ PDRIVER_OBJECT DriverObject)
{
    NTSTATUS status;
    UNREFERENCED_PARAMETER(DriverObject);

    if (g_ImageNotifyRegistered) {
        return STATUS_SUCCESS;
    }

    if (!g_ImageWorkerInitialized) {
        ULONG processorCount;
        ULONG workerCount;
        ULONG workerIndex;

        if (g_Context.DeviceObject == NULL) {
            DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_WARNING_LEVEL,
                "[SysmonDrv] Image notify: device object not ready; image worker pool not initialized\n");
            return STATUS_INVALID_DEVICE_STATE;
        }

        processorCount = KeQueryActiveProcessorCount(NULL);
        if (processorCount == 0) {
            processorCount = 1;
        }
        if (processorCount > RTL_NUMBER_OF(g_ImageWorkQueues)) {
            processorCount = RTL_NUMBER_OF(g_ImageWorkQueues);
        }
        for (workerIndex = 0; workerIndex < processorCount; workerIndex++) {
            ExInitializeFastMutex(&g_ImageWorkQueues[workerIndex].Lock);
            InitializeListHead(&g_ImageWorkQueues[workerIndex].WorkList);
        }
        g_ImageWorkQueueCount = processorCount;
        KeInitializeEvent(&g_ImageWorkerIdleEvent, NotificationEvent, TRUE);
        g_ImageWorkItemCount = 0;
        g_ImageActiveWorkers = 0;
        g_ImageAcceptingWork = 0;
        g_ImageQueueStealCursor = 0;
        RtlZeroMemory(g_ImageIoWorkItems, sizeof(g_ImageIoWorkItems));
        RtlZeroMemory((PVOID)g_ImageWorkerQueued, sizeof(g_ImageWorkerQueued));
        workerCount = SysmonDetermineImageWorkerCount();
        if (workerCount == 0) {
            DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_WARNING_LEVEL,
                "[SysmonDrv] Image notify: unable to determine image worker count; image notify disabled\n");
            return STATUS_INSUFFICIENT_RESOURCES;
        }

        for (workerIndex = 0; workerIndex < workerCount; workerIndex++) {
            g_ImageIoWorkItems[workerIndex] = IoAllocateWorkItem(g_Context.DeviceObject);
            if (g_ImageIoWorkItems[workerIndex] == NULL) {
                while (workerIndex > 0) {
                    workerIndex -= 1;
                    IoFreeWorkItem(g_ImageIoWorkItems[workerIndex]);
                    g_ImageIoWorkItems[workerIndex] = NULL;
                }
                DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_WARNING_LEVEL,
                    "[SysmonDrv] Image notify: failed to allocate image work item %lu of %lu; image notify disabled\n",
                    workerIndex, workerCount);
                return STATUS_INSUFFICIENT_RESOURCES;
            }
        }

        g_ImageWorkerCount = workerCount;
        g_ImageWorkerInitialized = TRUE;
    }

    InterlockedExchange(&g_ImageAcceptingWork, 1);

    status = PsSetLoadImageNotifyRoutine(ImageNotifyCallback);
    if (!NT_SUCCESS(status)) {
        InterlockedExchange(&g_ImageAcceptingWork, 0);
        DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_WARNING_LEVEL,
            "[SysmonDrv] PsSetLoadImageNotifyRoutine failed: 0x%08X\n", status);
        return status;
    }

    g_ImageNotifyRegistered = TRUE;
    return STATUS_SUCCESS;
}

VOID
SysmonUnregisterImageNotify(VOID)
{
    if (!g_ImageNotifyRegistered) {
        InterlockedExchange(&g_ImageAcceptingWork, 0);
        SysmonCleanupImageWorkers();
        return;
    }

    PsRemoveLoadImageNotifyRoutine(ImageNotifyCallback);
    g_ImageNotifyRegistered = FALSE;
    InterlockedExchange(&g_ImageAcceptingWork, 0);
    SysmonCleanupImageWorkers();
}

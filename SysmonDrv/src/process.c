#include "process.h"
#include "queue.h"
#include "event.h"
#include "driver.h"
#include "processinfo.h"
#include "fileinfo.h"

#define SYSMON_PS_CREATE_PROCESS_NOTIFY_SUBSYSTEMS 0ul
#define SYSMON_PROCESS_CACHE_BUCKETS 64u
#define SYSMON_PROCESS_EVENT_CACHE_CAPACITY 1024u
#define SYSMON_PROCESS_EVENT_CACHE_ENTRIES_PER_BUCKET \
    (SYSMON_PROCESS_EVENT_CACHE_CAPACITY / SYSMON_PROCESS_CACHE_BUCKETS)
#define SYSMON_PROCESS_CREATE_FINALIZE_BUCKETS 64u

#if (SYSMON_PROCESS_EVENT_CACHE_CAPACITY % SYSMON_PROCESS_CACHE_BUCKETS) != 0
#error "SYSMON_PROCESS_EVENT_CACHE_CAPACITY must be divisible by SYSMON_PROCESS_CACHE_BUCKETS"
#endif

static volatile LONG g_ProcessSequence = 0;
volatile LONG g_ProcessCallbackCount = 0;
static volatile LONG g_ProcessCreateAttemptCount = 0;
static volatile LONG g_ProcessCreateCapturedCount = 0;
static volatile LONG g_ProcessCreateFilteredCount = 0;
static volatile LONG g_ProcessCreateDeliveryCount = 0;
static volatile LONG g_ProcessCreateFailureCount = 0;

static ULONG
SysmonGetProcessCacheBucketIndex(
    _In_ ULONG ProcessId)
{
    return ProcessId % SYSMON_PROCESS_CACHE_BUCKETS;
}

static ULONG
SysmonGetProcessCreateFinalizeBucketIndex(
    _In_ ULONG ProcessId)
{
    return ProcessId % SYSMON_PROCESS_CREATE_FINALIZE_BUCKETS;
}

VOID
SysmonQueryProcessDebugStats(
    _Out_ PSYSMON_PROCESS_DEBUG_STATS Stats)
{
    if (Stats == NULL) {
        return;
    }

    RtlZeroMemory(Stats, sizeof(*Stats));
    Stats->ProcessCallbackCount = (ULONG)g_ProcessCallbackCount;
    Stats->ProcessCreateAttemptCount = (ULONG)g_ProcessCreateAttemptCount;
    Stats->ProcessCreateCapturedCount = (ULONG)g_ProcessCreateCapturedCount;
    Stats->ProcessCreateFilteredCount = (ULONG)g_ProcessCreateFilteredCount;
    Stats->ProcessCreateDeliveryCount = (ULONG)g_ProcessCreateDeliveryCount;
    Stats->ProcessCreateFailureCount = (ULONG)g_ProcessCreateFailureCount;
}

typedef struct _SYSMON_PROCESS_EVENT_CACHE_ENTRY {
    LIST_ENTRY ListEntry;
    ULONG ProcessId;
    LONGLONG CreateTime;
    ULONGLONG LastAccessTick;
    WCHAR ProcessGuid[SYSMON_MAX_GUID_STRING];
    WCHAR Image[SYSMON_MAX_PATH];
    WCHAR UserSid[SYSMON_MAX_SID_STRING];
} SYSMON_PROCESS_EVENT_CACHE_ENTRY, *PSYSMON_PROCESS_EVENT_CACHE_ENTRY;

typedef struct _SYSMON_PENDING_PROCESS_CREATE_ENTRY {
    LIST_ENTRY ListEntry;
    ULONG ProcessId;
    ULONG ParentProcessId;
    BOOLEAN FinalizeInProgress;
    WCHAR Image[SYSMON_MAX_PATH];
    WCHAR CommandLine[SYSMON_MAX_CMDLINE];
} SYSMON_PENDING_PROCESS_CREATE_ENTRY, *PSYSMON_PENDING_PROCESS_CREATE_ENTRY;

typedef struct _SYSMON_PROCESS_CREATE_FINALIZE_WORK_ITEM {
    LIST_ENTRY QueueListEntry;
    LIST_ENTRY BucketListEntry;
    HANDLE ProcessId;
} SYSMON_PROCESS_CREATE_FINALIZE_WORK_ITEM, *PSYSMON_PROCESS_CREATE_FINALIZE_WORK_ITEM;

typedef struct _SYSMON_PROCESS_CREATE_EVENT_SCRATCH {
    SYSMON_PROCESS_INFO ProcessInfo;
    SYSMON_PROCESS_INFO ParentInfo;
    SYSMON_FILE_INFO ImageFileInfo;
} SYSMON_PROCESS_CREATE_EVENT_SCRATCH, *PSYSMON_PROCESS_CREATE_EVENT_SCRATCH;

static LIST_ENTRY g_ProcessEventCacheBuckets[SYSMON_PROCESS_CACHE_BUCKETS];
static FAST_MUTEX g_ProcessEventCacheBucketLocks[SYSMON_PROCESS_CACHE_BUCKETS];
static ULONG g_ProcessEventCacheBucketCounts[SYSMON_PROCESS_CACHE_BUCKETS];
static ULONGLONG g_ProcessEventCacheBucketClocks[SYSMON_PROCESS_CACHE_BUCKETS];
static BOOLEAN g_ProcessEventCacheInitialized = FALSE;
static LIST_ENTRY g_PendingProcessCreateCacheBuckets[SYSMON_PROCESS_CACHE_BUCKETS];
static FAST_MUTEX g_PendingProcessCreateCacheBucketLocks[SYSMON_PROCESS_CACHE_BUCKETS];
static BOOLEAN g_PendingProcessCreateCacheInitialized = FALSE;
static LIST_ENTRY g_ProcessCreateFinalizeWorkList;
static LIST_ENTRY g_ProcessCreateFinalizeWorkBuckets[SYSMON_PROCESS_CREATE_FINALIZE_BUCKETS];
static FAST_MUTEX g_ProcessCreateFinalizeWorkListLock;
static PIO_WORKITEM g_ProcessCreateFinalizeWorkItem = NULL;
static volatile LONG g_ProcessCreateFinalizeWorkCount = 0;
static volatile LONG g_ProcessCreateFinalizeWorkerQueued = 0;
static volatile LONG g_ProcessCreateFinalizeAcceptingWork = 0;
static KEVENT g_ProcessCreateFinalizeWorkerIdleEvent;
static BOOLEAN g_ProcessCreateFinalizeInfrastructureInitialized = FALSE;
static BOOLEAN g_ProcessCreateFinalizeWorkerInitialized = FALSE;
static BOOLEAN g_ProcessNotifyRegistered = FALSE;
static BOOLEAN g_ProcessNotifyRegisteredWithEx2 = FALSE;
static BOOLEAN g_ProcessNotifyRegisteredWithEx = FALSE;
static PFN_PS_SET_CREATE_PROCESS_NOTIFY_ROUTINE_EX2 g_PsSetCreateProcessNotifyRoutineEx2 = NULL;
static PFN_PS_SET_CREATE_PROCESS_NOTIFY_ROUTINE_EX g_PsSetCreateProcessNotifyRoutineEx = NULL;
static PFN_PS_SET_CREATE_PROCESS_NOTIFY_ROUTINE g_PsSetCreateProcessNotifyRoutineLegacy = NULL;

static ULONGLONG
SysmonAdvanceProcessEventCacheClock(
    _In_ ULONG BucketIndex)
{
    g_ProcessEventCacheBucketClocks[BucketIndex]++;
    return g_ProcessEventCacheBucketClocks[BucketIndex];
}

static VOID
SysmonProcessCreateFinalizeWorkItemCallback(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_opt_ PVOID Context);

static VOID
SysmonCacheProcessEventIdentity(
    _In_ PSYSMON_EVENT_UNION Event,
    _In_ PSYSMON_PROCESS_CREATE_EVENT_DATA EventData)
{
    PSYSMON_PROCESS_EVENT_CACHE_ENTRY entry;
    PSYSMON_PROCESS_EVENT_CACHE_ENTRY existingEntry = NULL;
    PSYSMON_PROCESS_EVENT_CACHE_ENTRY lruEntry = NULL;
    PSYSMON_PROCESS_EVENT_CACHE_ENTRY evictedEntry = NULL;
    WCHAR processGuid[SYSMON_MAX_GUID_STRING];
    WCHAR image[SYSMON_MAX_PATH];
    WCHAR userSid[SYSMON_MAX_SID_STRING];
    SYSMON_PROCESS_INFO processInfo;
    PLIST_ENTRY listEntry;
    ULONG bucketIndex;
    ULONG bucketCount;
    ULONG actualBucketCount;
    ULONGLONG oldestTick = ~0ULL;

    if (!g_ProcessEventCacheInitialized || Event == NULL || EventData == NULL) {
        return;
    }

    if (!SysmonCopyStringField(Event, EventData->ProcessGuid, processGuid, RTL_NUMBER_OF(processGuid))) {
        processGuid[0] = L'\0';
    }

    if (!SysmonCopyStringField(Event, EventData->Image, image, RTL_NUMBER_OF(image))) {
        image[0] = L'\0';
    }

    if (!SysmonCopyStringField(Event, EventData->User, userSid, RTL_NUMBER_OF(userSid))) {
        userSid[0] = L'\0';
    }

    entry = (PSYSMON_PROCESS_EVENT_CACHE_ENTRY)SysmonAllocatePool(sizeof(*entry));
    if (entry == NULL) {
        return;
    }

    RtlZeroMemory(entry, sizeof(*entry));
    entry->ProcessId = EventData->ProcessId;
    SysmonCopyWideStringWithLength(entry->ProcessGuid, RTL_NUMBER_OF(entry->ProcessGuid), processGuid, SYSMON_GUID_STRING_CHARS);
    SysmonCopyWideString(entry->Image, RTL_NUMBER_OF(entry->Image), image);
    SysmonCopyWideString(entry->UserSid, RTL_NUMBER_OF(entry->UserSid), userSid);
    entry->CreateTime = 0;

    RtlZeroMemory(&processInfo, sizeof(processInfo));
    if (NT_SUCCESS(SysmonCollectProcessInfoForCreateNotify((HANDLE)(ULONG_PTR)EventData->ProcessId, &processInfo))) {
        if (entry->ProcessGuid[0] == L'\0') {
            SysmonCopyWideStringWithLength(entry->ProcessGuid, RTL_NUMBER_OF(entry->ProcessGuid), processInfo.ProcessGuid, SYSMON_GUID_STRING_CHARS);
        }
        if (entry->Image[0] == L'\0') {
            SysmonCopyWideString(entry->Image, RTL_NUMBER_OF(entry->Image), processInfo.ImagePath);
        }
        if (entry->UserSid[0] == L'\0') {
            SysmonCopyWideString(entry->UserSid, RTL_NUMBER_OF(entry->UserSid), processInfo.UserSid);
        }
        entry->CreateTime = processInfo.CreateTime;
    }

    bucketIndex = SysmonGetProcessCacheBucketIndex(entry->ProcessId);
    ExAcquireFastMutex(&g_ProcessEventCacheBucketLocks[bucketIndex]);
    bucketCount = g_ProcessEventCacheBucketCounts[bucketIndex];
    actualBucketCount = 0;
    listEntry = g_ProcessEventCacheBuckets[bucketIndex].Flink;
    while (listEntry != &g_ProcessEventCacheBuckets[bucketIndex]) {
        PSYSMON_PROCESS_EVENT_CACHE_ENTRY currentEntry =
            CONTAINING_RECORD(listEntry, SYSMON_PROCESS_EVENT_CACHE_ENTRY, ListEntry);

        actualBucketCount += 1;
        if (currentEntry->ProcessId == entry->ProcessId) {
            existingEntry = currentEntry;
            break;
        }

        if (currentEntry->LastAccessTick < oldestTick) {
            oldestTick = currentEntry->LastAccessTick;
            lruEntry = currentEntry;
        }

        listEntry = listEntry->Flink;
    }
    if (existingEntry == NULL && actualBucketCount != bucketCount) {
        bucketCount = actualBucketCount;
        g_ProcessEventCacheBucketCounts[bucketIndex] = actualBucketCount;
    }

    if (existingEntry != NULL) {
        existingEntry->CreateTime = entry->CreateTime;
        existingEntry->LastAccessTick = SysmonAdvanceProcessEventCacheClock(bucketIndex);
        SysmonCopyWideStringWithLength(existingEntry->ProcessGuid, RTL_NUMBER_OF(existingEntry->ProcessGuid), entry->ProcessGuid, SYSMON_GUID_STRING_CHARS);
        SysmonCopyWideString(existingEntry->Image, RTL_NUMBER_OF(existingEntry->Image), entry->Image);
        SysmonCopyWideString(existingEntry->UserSid, RTL_NUMBER_OF(existingEntry->UserSid), entry->UserSid);
    } else {
        if (bucketCount >= SYSMON_PROCESS_EVENT_CACHE_ENTRIES_PER_BUCKET &&
            lruEntry != NULL) {
            RemoveEntryList(&lruEntry->ListEntry);
            evictedEntry = lruEntry;
        } else {
            g_ProcessEventCacheBucketCounts[bucketIndex] = bucketCount + 1;
        }

        entry->LastAccessTick = SysmonAdvanceProcessEventCacheClock(bucketIndex);
        InsertHeadList(&g_ProcessEventCacheBuckets[bucketIndex], &entry->ListEntry);
        entry = NULL;
    }
    ExReleaseFastMutex(&g_ProcessEventCacheBucketLocks[bucketIndex]);

    if (evictedEntry != NULL) {
        SysmonFreePool(evictedEntry);
    }
    if (entry != NULL) {
        SysmonFreePool(entry);
    }
}

BOOLEAN
SysmonLookupCachedProcessMetadata(
    _In_ ULONG ProcessId,
    _Out_ PSYSMON_PROCESS_CACHE_METADATA Metadata)
{
    ULONG bucketIndex;
    PLIST_ENTRY listEntry;
    PSYSMON_PROCESS_EVENT_CACHE_ENTRY entry;
    BOOLEAN found = FALSE;

    if (Metadata == NULL) {
        return FALSE;
    }

    RtlZeroMemory(Metadata, sizeof(*Metadata));
    Metadata->ProcessId = ProcessId;

    if (!g_ProcessEventCacheInitialized) {
        return FALSE;
    }

    bucketIndex = SysmonGetProcessCacheBucketIndex(ProcessId);
    ExAcquireFastMutex(&g_ProcessEventCacheBucketLocks[bucketIndex]);
    listEntry = g_ProcessEventCacheBuckets[bucketIndex].Flink;
    while (listEntry != &g_ProcessEventCacheBuckets[bucketIndex]) {
        entry = CONTAINING_RECORD(listEntry, SYSMON_PROCESS_EVENT_CACHE_ENTRY, ListEntry);
        listEntry = listEntry->Flink;
        if (entry->ProcessId == ProcessId) {
            Metadata->CreateTime = entry->CreateTime;
            entry->LastAccessTick = SysmonAdvanceProcessEventCacheClock(bucketIndex);
            SysmonCopyWideStringWithLength(Metadata->ProcessGuid, RTL_NUMBER_OF(Metadata->ProcessGuid), entry->ProcessGuid, SYSMON_GUID_STRING_CHARS);
            SysmonCopyWideString(Metadata->Image, RTL_NUMBER_OF(Metadata->Image), entry->Image);
            SysmonCopyWideString(Metadata->UserSid, RTL_NUMBER_OF(Metadata->UserSid), entry->UserSid);
            found = TRUE;
            break;
        }
    }
    ExReleaseFastMutex(&g_ProcessEventCacheBucketLocks[bucketIndex]);

    return found;
}

static BOOLEAN
SysmonRemoveCachedProcessEventIdentity(
    _In_ ULONG ProcessId,
    _Out_writes_(GuidChars) PWCHAR ProcessGuid,
    _In_ ULONG GuidChars,
    _Out_writes_(ImageChars) PWCHAR Image,
    _In_ ULONG ImageChars)
{
    ULONG bucketIndex;
    PLIST_ENTRY listEntry;
    PSYSMON_PROCESS_EVENT_CACHE_ENTRY entry;
    BOOLEAN found = FALSE;

    if (ProcessGuid != NULL && GuidChars != 0) {
        ProcessGuid[0] = L'\0';
    }
    if (Image != NULL && ImageChars != 0) {
        Image[0] = L'\0';
    }

    if (!g_ProcessEventCacheInitialized) {
        return FALSE;
    }

    bucketIndex = SysmonGetProcessCacheBucketIndex(ProcessId);
    ExAcquireFastMutex(&g_ProcessEventCacheBucketLocks[bucketIndex]);
    listEntry = g_ProcessEventCacheBuckets[bucketIndex].Flink;
    while (listEntry != &g_ProcessEventCacheBuckets[bucketIndex]) {
        entry = CONTAINING_RECORD(listEntry, SYSMON_PROCESS_EVENT_CACHE_ENTRY, ListEntry);
        listEntry = listEntry->Flink;
        if (entry->ProcessId == ProcessId) {
            if (ProcessGuid != NULL) {
                SysmonCopyWideStringWithLength(ProcessGuid, GuidChars, entry->ProcessGuid, SYSMON_GUID_STRING_CHARS);
            }
            if (Image != NULL) {
                SysmonCopyWideString(Image, ImageChars, entry->Image);
            }
            RemoveEntryList(&entry->ListEntry);
            if (g_ProcessEventCacheBucketCounts[bucketIndex] != 0) {
                g_ProcessEventCacheBucketCounts[bucketIndex]--;
            }
            SysmonFreePool(entry);
            found = TRUE;
            break;
        }
    }
    ExReleaseFastMutex(&g_ProcessEventCacheBucketLocks[bucketIndex]);

    return found;
}

static VOID
SysmonDrainProcessEventCache(VOID)
{
    ULONG bucketIndex;
    PLIST_ENTRY listEntry;

    if (!g_ProcessEventCacheInitialized) {
        return;
    }

    for (bucketIndex = 0; bucketIndex < SYSMON_PROCESS_CACHE_BUCKETS; bucketIndex++) {
        ExAcquireFastMutex(&g_ProcessEventCacheBucketLocks[bucketIndex]);
        while (!IsListEmpty(&g_ProcessEventCacheBuckets[bucketIndex])) {
            listEntry = RemoveHeadList(&g_ProcessEventCacheBuckets[bucketIndex]);
            SysmonFreePool(CONTAINING_RECORD(listEntry, SYSMON_PROCESS_EVENT_CACHE_ENTRY, ListEntry));
        }
        g_ProcessEventCacheBucketCounts[bucketIndex] = 0;
        g_ProcessEventCacheBucketClocks[bucketIndex] = 0;
        ExReleaseFastMutex(&g_ProcessEventCacheBucketLocks[bucketIndex]);
    }
}

static BOOLEAN
SysmonCachePendingProcessCreate(
    _In_ HANDLE ProcessId,
    _In_opt_ HANDLE ParentProcessId,
    _Inout_opt_ PPS_CREATE_NOTIFY_INFO CreateInfo)
{
    PSYSMON_PENDING_PROCESS_CREATE_ENTRY entry;
    PSYSMON_PENDING_PROCESS_CREATE_ENTRY existingEntry = NULL;
    ULONG bucketIndex;
    PLIST_ENTRY listEntry;

    if (!g_PendingProcessCreateCacheInitialized) {
        return FALSE;
    }

    entry = (PSYSMON_PENDING_PROCESS_CREATE_ENTRY)SysmonAllocatePool(sizeof(*entry));
    if (entry == NULL) {
        return FALSE;
    }

    RtlZeroMemory(entry, sizeof(*entry));
    entry->ProcessId = HandleToULong(ProcessId);
    if (ParentProcessId != NULL) {
        entry->ParentProcessId = HandleToULong(ParentProcessId);
    } else if (CreateInfo != NULL && CreateInfo->ParentProcessId != NULL) {
        entry->ParentProcessId = HandleToULong(CreateInfo->ParentProcessId);
    }

    if (CreateInfo != NULL) {
        /* CreateInfo buffers are only valid during the create callback. */
        SysmonCopyUnicodeString(
            entry->Image,
            RTL_NUMBER_OF(entry->Image),
            CreateInfo->ImageFileName);
        SysmonCopyUnicodeString(
            entry->CommandLine,
            RTL_NUMBER_OF(entry->CommandLine),
            CreateInfo->CommandLine);
    }

    bucketIndex = SysmonGetProcessCacheBucketIndex(entry->ProcessId);
    ExAcquireFastMutex(&g_PendingProcessCreateCacheBucketLocks[bucketIndex]);
    listEntry = g_PendingProcessCreateCacheBuckets[bucketIndex].Flink;
    while (listEntry != &g_PendingProcessCreateCacheBuckets[bucketIndex]) {
        PSYSMON_PENDING_PROCESS_CREATE_ENTRY currentEntry =
            CONTAINING_RECORD(listEntry, SYSMON_PENDING_PROCESS_CREATE_ENTRY, ListEntry);

        if (currentEntry->ProcessId == entry->ProcessId) {
            existingEntry = currentEntry;
            break;
        }

        listEntry = listEntry->Flink;
    }

    if (existingEntry != NULL) {
        existingEntry->ParentProcessId = entry->ParentProcessId;
        SysmonCopyWideString(existingEntry->Image, RTL_NUMBER_OF(existingEntry->Image), entry->Image);
        SysmonCopyWideString(existingEntry->CommandLine, RTL_NUMBER_OF(existingEntry->CommandLine), entry->CommandLine);
    } else {
        InsertHeadList(&g_PendingProcessCreateCacheBuckets[bucketIndex], &entry->ListEntry);
        entry = NULL;
    }
    ExReleaseFastMutex(&g_PendingProcessCreateCacheBucketLocks[bucketIndex]);

    if (entry != NULL) {
        SysmonFreePool(entry);
    }

    return TRUE;
}

static BOOLEAN
SysmonBeginPendingProcessCreateFinalize(
    _In_ ULONG ProcessId,
    _Out_ PSYSMON_PENDING_PROCESS_CREATE_ENTRY Snapshot)
{
    ULONG bucketIndex;
    PLIST_ENTRY listEntry;
    PSYSMON_PENDING_PROCESS_CREATE_ENTRY entry;
    BOOLEAN found = FALSE;

    if (Snapshot == NULL || !g_PendingProcessCreateCacheInitialized) {
        return FALSE;
    }

    RtlZeroMemory(Snapshot, sizeof(*Snapshot));

    bucketIndex = SysmonGetProcessCacheBucketIndex(ProcessId);
    ExAcquireFastMutex(&g_PendingProcessCreateCacheBucketLocks[bucketIndex]);
    listEntry = g_PendingProcessCreateCacheBuckets[bucketIndex].Flink;
    while (listEntry != &g_PendingProcessCreateCacheBuckets[bucketIndex]) {
        entry = CONTAINING_RECORD(listEntry, SYSMON_PENDING_PROCESS_CREATE_ENTRY, ListEntry);
        if (entry->ProcessId == ProcessId) {
            if (entry->FinalizeInProgress) {
                break;
            }

            RtlCopyMemory(Snapshot, entry, sizeof(*Snapshot));
            entry->FinalizeInProgress = TRUE;
            found = TRUE;
            break;
        }

        listEntry = listEntry->Flink;
    }
    ExReleaseFastMutex(&g_PendingProcessCreateCacheBucketLocks[bucketIndex]);

    return found;
}

static BOOLEAN
SysmonCompletePendingProcessCreateFinalize(
    _In_ ULONG ProcessId,
    _In_ BOOLEAN Consume)
{
    ULONG bucketIndex;
    PLIST_ENTRY listEntry;
    PSYSMON_PENDING_PROCESS_CREATE_ENTRY entry = NULL;
    BOOLEAN found = FALSE;

    if (!g_PendingProcessCreateCacheInitialized) {
        return FALSE;
    }

    bucketIndex = SysmonGetProcessCacheBucketIndex(ProcessId);
    ExAcquireFastMutex(&g_PendingProcessCreateCacheBucketLocks[bucketIndex]);
    listEntry = g_PendingProcessCreateCacheBuckets[bucketIndex].Flink;
    while (listEntry != &g_PendingProcessCreateCacheBuckets[bucketIndex]) {
        entry = CONTAINING_RECORD(listEntry, SYSMON_PENDING_PROCESS_CREATE_ENTRY, ListEntry);
        if (entry->ProcessId == ProcessId) {
            if (Consume) {
                RemoveEntryList(&entry->ListEntry);
            } else {
                entry->FinalizeInProgress = FALSE;
            }

            found = TRUE;
            break;
        }

        listEntry = listEntry->Flink;
    }
    ExReleaseFastMutex(&g_PendingProcessCreateCacheBucketLocks[bucketIndex]);

    if (Consume && found && entry != NULL) {
        SysmonFreePool(entry);
    }

    return found;
}

static BOOLEAN
SysmonConsumePendingProcessCreate(
    _In_ ULONG ProcessId)
{
    return SysmonCompletePendingProcessCreateFinalize(ProcessId, TRUE);
}

static VOID
SysmonDrainPendingProcessCreateCache(VOID)
{
    ULONG bucketIndex;
    PLIST_ENTRY listEntry;

    if (!g_PendingProcessCreateCacheInitialized) {
        return;
    }

    for (bucketIndex = 0; bucketIndex < SYSMON_PROCESS_CACHE_BUCKETS; bucketIndex++) {
        ExAcquireFastMutex(&g_PendingProcessCreateCacheBucketLocks[bucketIndex]);
        while (!IsListEmpty(&g_PendingProcessCreateCacheBuckets[bucketIndex])) {
            listEntry = RemoveHeadList(&g_PendingProcessCreateCacheBuckets[bucketIndex]);
            SysmonFreePool(CONTAINING_RECORD(listEntry, SYSMON_PENDING_PROCESS_CREATE_ENTRY, ListEntry));
        }
        ExReleaseFastMutex(&g_PendingProcessCreateCacheBucketLocks[bucketIndex]);
    }
}

static VOID
SysmonInitializeProcessCreateFinalizeInfrastructure(VOID)
{
    if (g_ProcessCreateFinalizeInfrastructureInitialized) {
        return;
    }

    ExInitializeFastMutex(&g_ProcessCreateFinalizeWorkListLock);
    InitializeListHead(&g_ProcessCreateFinalizeWorkList);
    {
        ULONG bucketIndex;

        for (bucketIndex = 0; bucketIndex < SYSMON_PROCESS_CREATE_FINALIZE_BUCKETS; bucketIndex++) {
            InitializeListHead(&g_ProcessCreateFinalizeWorkBuckets[bucketIndex]);
        }
    }
    KeInitializeEvent(&g_ProcessCreateFinalizeWorkerIdleEvent, NotificationEvent, TRUE);
    g_ProcessCreateFinalizeWorkCount = 0;
    g_ProcessCreateFinalizeWorkerQueued = 0;
    g_ProcessCreateFinalizeAcceptingWork = 0;
    g_ProcessCreateFinalizeInfrastructureInitialized = TRUE;
}

BOOLEAN
SysmonQueuePendingProcessCreateFinalize(
    _In_ HANDLE ProcessId)
{
    PSYSMON_PROCESS_CREATE_FINALIZE_WORK_ITEM workItem;
    PIO_WORKITEM workerToQueue = NULL;
    PLIST_ENTRY listEntry;
    ULONG bucketIndex;
    ULONG processId;

    processId = HandleToULong(ProcessId);
    if (!g_ProcessCreateFinalizeWorkerInitialized ||
        g_ProcessCreateFinalizeWorkItem == NULL ||
        InterlockedCompareExchange(&g_ProcessCreateFinalizeAcceptingWork, 0, 0) == 0) {
        return FALSE;
    }

    if (InterlockedCompareExchange(&g_ProcessCreateFinalizeWorkCount, 0, 0) >= 1024) {
        return FALSE;
    }

    workItem = (PSYSMON_PROCESS_CREATE_FINALIZE_WORK_ITEM)SysmonAllocatePool(sizeof(*workItem));
    if (workItem == NULL) {
        return FALSE;
    }

    RtlZeroMemory(workItem, sizeof(*workItem));
    workItem->ProcessId = ProcessId;
    bucketIndex = SysmonGetProcessCreateFinalizeBucketIndex(processId);

    ExAcquireFastMutex(&g_ProcessCreateFinalizeWorkListLock);
    if (!g_ProcessCreateFinalizeWorkerInitialized ||
        g_ProcessCreateFinalizeWorkItem == NULL ||
        InterlockedCompareExchange(&g_ProcessCreateFinalizeAcceptingWork, 0, 0) == 0) {
        ExReleaseFastMutex(&g_ProcessCreateFinalizeWorkListLock);
        SysmonFreePool(workItem);
        return FALSE;
    }

    listEntry = g_ProcessCreateFinalizeWorkBuckets[bucketIndex].Flink;
    while (listEntry != &g_ProcessCreateFinalizeWorkBuckets[bucketIndex]) {
        PSYSMON_PROCESS_CREATE_FINALIZE_WORK_ITEM currentItem =
            CONTAINING_RECORD(listEntry, SYSMON_PROCESS_CREATE_FINALIZE_WORK_ITEM, BucketListEntry);

        if (HandleToULong(currentItem->ProcessId) == processId) {
            ExReleaseFastMutex(&g_ProcessCreateFinalizeWorkListLock);
            SysmonFreePool(workItem);
            return TRUE;
        }

        listEntry = listEntry->Flink;
    }

    InsertTailList(&g_ProcessCreateFinalizeWorkList, &workItem->QueueListEntry);
    InsertTailList(&g_ProcessCreateFinalizeWorkBuckets[bucketIndex], &workItem->BucketListEntry);
    InterlockedIncrement(&g_ProcessCreateFinalizeWorkCount);
    if (InterlockedCompareExchange(&g_ProcessCreateFinalizeWorkerQueued, 0, 0) == 0) {
        g_ProcessCreateFinalizeWorkerQueued = 1;
        KeClearEvent(&g_ProcessCreateFinalizeWorkerIdleEvent);
        workerToQueue = g_ProcessCreateFinalizeWorkItem;
    }
    ExReleaseFastMutex(&g_ProcessCreateFinalizeWorkListLock);

    if (workerToQueue != NULL) {
        IoQueueWorkItem(
            workerToQueue,
            SysmonProcessCreateFinalizeWorkItemCallback,
            DelayedWorkQueue,
            NULL);
    }

    return TRUE;
}

static VOID
SysmonProcessCreateFinalizeWorkItemCallback(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_opt_ PVOID Context)
{
    PSYSMON_PROCESS_CREATE_FINALIZE_WORK_ITEM workItem;
    PLIST_ENTRY listEntry;

    UNREFERENCED_PARAMETER(DeviceObject);
    UNREFERENCED_PARAMETER(Context);

    ExAcquireFastMutex(&g_ProcessCreateFinalizeWorkListLock);
    while (!IsListEmpty(&g_ProcessCreateFinalizeWorkList)) {
        listEntry = RemoveHeadList(&g_ProcessCreateFinalizeWorkList);
        workItem = CONTAINING_RECORD(
            listEntry,
            SYSMON_PROCESS_CREATE_FINALIZE_WORK_ITEM,
            QueueListEntry);
        RemoveEntryList(&workItem->BucketListEntry);
        ExReleaseFastMutex(&g_ProcessCreateFinalizeWorkListLock);

        SysmonTryFinalizePendingProcessCreate(workItem->ProcessId);
        SysmonFreePool(workItem);
        InterlockedDecrement(&g_ProcessCreateFinalizeWorkCount);

        ExAcquireFastMutex(&g_ProcessCreateFinalizeWorkListLock);
    }

    g_ProcessCreateFinalizeWorkerQueued = 0;
    if (IsListEmpty(&g_ProcessCreateFinalizeWorkList)) {
        KeSetEvent(&g_ProcessCreateFinalizeWorkerIdleEvent, IO_NO_INCREMENT, FALSE);
    } else {
        g_ProcessCreateFinalizeWorkerQueued = 1;
        ExReleaseFastMutex(&g_ProcessCreateFinalizeWorkListLock);
        IoQueueWorkItem(
            g_ProcessCreateFinalizeWorkItem,
            SysmonProcessCreateFinalizeWorkItemCallback,
            DelayedWorkQueue,
            NULL);
        return;
    }

    ExReleaseFastMutex(&g_ProcessCreateFinalizeWorkListLock);
}

static VOID
SysmonCleanupProcessCreateFinalizeInfrastructure(VOID)
{
    PLIST_ENTRY listEntry;

    if (!g_ProcessCreateFinalizeInfrastructureInitialized) {
        g_ProcessCreateFinalizeWorkerInitialized = FALSE;
        g_ProcessCreateFinalizeWorkItem = NULL;
        return;
    }

    InterlockedExchange(&g_ProcessCreateFinalizeAcceptingWork, 0);
    ExAcquireFastMutex(&g_ProcessCreateFinalizeWorkListLock);
    ExReleaseFastMutex(&g_ProcessCreateFinalizeWorkListLock);

    if (g_ProcessCreateFinalizeWorkerInitialized) {
        KeWaitForSingleObject(
            &g_ProcessCreateFinalizeWorkerIdleEvent,
            Executive,
            KernelMode,
            FALSE,
            NULL);
    }

    ExAcquireFastMutex(&g_ProcessCreateFinalizeWorkListLock);
    while (!IsListEmpty(&g_ProcessCreateFinalizeWorkList)) {
        listEntry = RemoveHeadList(&g_ProcessCreateFinalizeWorkList);
        RemoveEntryList(&CONTAINING_RECORD(
            listEntry,
            SYSMON_PROCESS_CREATE_FINALIZE_WORK_ITEM,
            QueueListEntry)->BucketListEntry);
        SysmonFreePool(CONTAINING_RECORD(
            listEntry,
            SYSMON_PROCESS_CREATE_FINALIZE_WORK_ITEM,
            QueueListEntry));
    }
    ExReleaseFastMutex(&g_ProcessCreateFinalizeWorkListLock);

    g_ProcessCreateFinalizeWorkerInitialized = FALSE;
    g_ProcessCreateFinalizeWorkerQueued = 0;
    g_ProcessCreateFinalizeWorkCount = 0;
    g_ProcessCreateFinalizeAcceptingWork = 0;
    if (g_ProcessCreateFinalizeWorkItem != NULL) {
        IoFreeWorkItem(g_ProcessCreateFinalizeWorkItem);
        g_ProcessCreateFinalizeWorkItem = NULL;
    }
    g_ProcessCreateFinalizeInfrastructureInitialized = FALSE;
}

static NTSTATUS
SysmonPopulateProcessCreateEvent(
    _In_ PSYSMON_EVENT_UNION Event,
    _In_ HANDLE ProcessId,
    _In_opt_ HANDLE ParentProcessId,
    _In_opt_z_ PCWSTR CachedImagePath,
    _In_opt_z_ PCWSTR CachedCommandLine)
{
    PSYSMON_PROCESS_CREATE_EVENT_DATA eventData;
    PSYSMON_PROCESS_CREATE_EVENT_SCRATCH scratch;
    PSYSMON_PROCESS_INFO processInfo;
    PSYSMON_PROCESS_INFO parentInfo;
    PSYSMON_FILE_INFO imageFileInfo;
    SYSMON_EVENT_PAYLOAD_BUILDER builder;
    PCWSTR imagePath;
    PCWSTR commandLine;
    NTSTATUS status;

    if (Event == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    scratch = (PSYSMON_PROCESS_CREATE_EVENT_SCRATCH)SysmonAllocatePool(sizeof(*scratch));
    if (scratch == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    processInfo = &scratch->ProcessInfo;
    parentInfo = &scratch->ParentInfo;
    imageFileInfo = &scratch->ImageFileInfo;

    eventData = (PSYSMON_PROCESS_CREATE_EVENT_DATA)Event->RawData;
    SysmonBeginStringPayload(Event, sizeof(*eventData), &builder);

    Event->Header.Timestamp = SysmonGetCurrentTimestamp();
    Event->Header.SequenceNumber = (ULONG)InterlockedIncrement(&g_ProcessSequence);

    SysmonWritePackedUlong(&eventData->ProcessId, HandleToULong(ProcessId));
    SysmonWritePackedUlong(&eventData->ParentProcessId, 0);
    if (ParentProcessId != NULL) {
        SysmonWritePackedUlong(&eventData->ParentProcessId, HandleToULong(ParentProcessId));
    }

    imagePath = ((CachedImagePath != NULL && CachedImagePath[0] != L'\0') ? CachedImagePath : L"");
    commandLine = ((CachedCommandLine != NULL && CachedCommandLine[0] != L'\0') ? CachedCommandLine : L"");

    /*
     * Event 1 is finalized on the first thread-create callback, but the new
     * process can still be too early for command-line/current-directory
     * probing. Always start with the create-notify-safe collector here and
     * rely on the cached create-time strings for Image/CommandLine.
     *
     * SysmonCollectProcessInfoForCreateNotify internally calls
     * PsLookupProcessByProcessId + ZwOpenProcess.  If either fails the
     * process is gone or inaccessible — a fallback SysmonCollectProcessIdentity
     * would retry the same operations and fail identically, so skip the
     * redundant second lookup.
     */
    status = SysmonCollectProcessInfoForCreateNotify(ProcessId, processInfo);
    if (!NT_SUCCESS(status)) {
        SysmonFreePool(scratch);
        return status;
    }

    if (SysmonReadPackedUlong(&eventData->ParentProcessId) == 0) {
        SysmonWritePackedUlong(&eventData->ParentProcessId, processInfo->ParentProcessId);
    }
    if (imagePath[0] == L'\0' && processInfo->ImagePath[0] != L'\0') {
        imagePath = processInfo->ImagePath;
    }

    if (commandLine[0] == L'\0' && processInfo->CommandLine[0] != L'\0') {
        commandLine = processInfo->CommandLine;
    }

    if (SysmonReadPackedUlong(&eventData->ParentProcessId) != 0) {
        /*
         * Parent process info is best-effort.  SysmonCollectProcessInfoForCreateNotify
         * already collects the full identity subset (image path, GUID, SID) that the
         * old SysmonCollectProcessIdentity fallback would retry — skip the redundant
         * second PsLookupProcessByProcessId + ZwOpenProcess.
         */
        (void)SysmonCollectProcessInfoForCreateNotify(
            (HANDLE)(ULONG_PTR)SysmonReadPackedUlong(&eventData->ParentProcessId),
            parentInfo);
    }

    if (imagePath[0] != L'\0') {
        (void)SysmonCollectFileInfoByPath(imagePath, imageFileInfo);
    }

    SysmonAddStringLiteralField(Event, &builder, &eventData->RuleName, L"-");
    SysmonAddCurrentUtcTimeField(Event, &builder, &eventData->UtcTime);
    SysmonAddFixedLengthStringField(
        Event,
        &builder,
        &eventData->ProcessGuid,
        processInfo->ProcessGuid,
        SYSMON_GUID_STRING_CHARS);
    SysmonAddStringField(Event, &builder, &eventData->Image, imagePath);
    SysmonAddStringField(Event, &builder, &eventData->FileVersion, imageFileInfo->FileVersion);
    SysmonAddStringField(Event, &builder, &eventData->Description, imageFileInfo->FileDescription);
    SysmonAddStringField(Event, &builder, &eventData->Product, imageFileInfo->ProductName);
    SysmonAddStringField(Event, &builder, &eventData->Company, imageFileInfo->CompanyName);
    SysmonAddStringField(Event, &builder, &eventData->OriginalFileName, imageFileInfo->OriginalFileName);
    SysmonAddStringField(Event, &builder, &eventData->CommandLine, commandLine);
    SysmonAddStringField(Event, &builder, &eventData->CurrentDirectory, processInfo->CurrentDirectory);
    /* Account-name resolution is deferred; canonical User currently carries SID text. */
    SysmonAddStringField(Event, &builder, &eventData->User, processInfo->UserSid);
    SysmonAddFixedLengthStringField(
        Event,
        &builder,
        &eventData->LogonGuid,
        processInfo->LogonGuid,
        SYSMON_GUID_STRING_CHARS);
    SysmonWritePackedUlongLong(&eventData->LogonId, processInfo->LogonId);
    SysmonWritePackedUlong(&eventData->TerminalSessionId, processInfo->SessionId);
    SysmonAddStringField(Event, &builder, &eventData->IntegrityLevel, processInfo->IntegrityLevel);
    SysmonAddStringField(Event, &builder, &eventData->Hashes, imageFileInfo->Hashes);
    SysmonAddFixedLengthStringField(
        Event,
        &builder,
        &eventData->ParentProcessGuid,
        parentInfo->ProcessGuid,
        SYSMON_GUID_STRING_CHARS);
    SysmonAddStringField(Event, &builder, &eventData->ParentImage, parentInfo->ImagePath);
    SysmonAddStringField(Event, &builder, &eventData->ParentCommandLine, parentInfo->CommandLine);
    /* Account-name resolution is deferred; canonical ParentUser currently carries SID text. */
    SysmonAddStringField(Event, &builder, &eventData->ParentUser, parentInfo->UserSid);

    SysmonFreePool(scratch);
    return STATUS_SUCCESS;
}

BOOLEAN
SysmonTryFinalizePendingProcessCreateEx(
    _In_ HANDLE ProcessId,
    _Out_opt_ PBOOLEAN ClaimedPendingCreate)
{
    PSYSMON_EVENT_UNION event = NULL;
    PSYSMON_PROCESS_CREATE_EVENT_DATA eventData = NULL;
    SYSMON_PENDING_PROCESS_CREATE_ENTRY pendingEntrySnapshot;
    PCWSTR imageForLog;
    NTSTATUS status;
    ULONG processId;
    BOOLEAN consumed;
    BOOLEAN filteredOut;

    if (ClaimedPendingCreate != NULL) {
        *ClaimedPendingCreate = FALSE;
    }

    processId = HandleToULong(ProcessId);

    if (!SysmonBeginPendingProcessCreateFinalize(processId, &pendingEntrySnapshot)) {
        return FALSE;
    }

    if (ClaimedPendingCreate != NULL) {
        *ClaimedPendingCreate = TRUE;
    }

    event = SysmonAllocateEvent(SysmonEventProcessCreate);
    if (event == NULL) {
        InterlockedIncrement(&g_ProcessCreateFailureCount);
        DbgPrintEx(
            DPFLTR_DEFAULT_ID,
            DPFLTR_ERROR_LEVEL,
            "[SysmonDrv] ProcessCreate allocation failed pid=%lu failures=%ld\n",
            processId,
            g_ProcessCreateFailureCount);
        SysmonCompletePendingProcessCreateFinalize(processId, FALSE);
        return TRUE;
    }

    status = SysmonPopulateProcessCreateEvent(
        event,
        ProcessId,
        (pendingEntrySnapshot.ParentProcessId != 0) ? (HANDLE)(ULONG_PTR)pendingEntrySnapshot.ParentProcessId : NULL,
        pendingEntrySnapshot.Image,
        pendingEntrySnapshot.CommandLine);
    if (!NT_SUCCESS(status)) {
        InterlockedIncrement(&g_ProcessCreateFailureCount);
        DbgPrintEx(
            DPFLTR_DEFAULT_ID,
            DPFLTR_ERROR_LEVEL,
            "[SysmonDrv] ProcessCreate populate failed pid=%lu status=0x%08X failures=%ld\n",
            processId,
            status,
            g_ProcessCreateFailureCount);
        SysmonFreeEvent(event);
        SysmonCompletePendingProcessCreateFinalize(processId, FALSE);
        return TRUE;
    }

    eventData = SysmonGetProcessCreateEventData(event);
    if (eventData == NULL) {
        InterlockedIncrement(&g_ProcessCreateFailureCount);
        DbgPrintEx(
            DPFLTR_DEFAULT_ID,
            DPFLTR_ERROR_LEVEL,
            "[SysmonDrv] ProcessCreate payload validation failed pid=%lu failures=%ld\n",
            processId,
            g_ProcessCreateFailureCount);
        SysmonFreeEvent(event);
        SysmonCompletePendingProcessCreateFinalize(processId, FALSE);
        return TRUE;
    }

    /*
     * Keep driver-side process metadata available even when Event 1 is not
     * configured or is filtered out. Original Sysmon later reuses this cache
     * to enrich other event types such as network and DNS activity.
     */
    SysmonCacheProcessEventIdentity(event, eventData);

    filteredOut = FALSE;
    status = SysmonPublishEventWithFilterState(event, &filteredOut);
    if (!NT_SUCCESS(status)) {
        InterlockedIncrement(&g_ProcessCreateFailureCount);
        DbgPrintEx(
            DPFLTR_DEFAULT_ID,
            DPFLTR_ERROR_LEVEL,
            "[SysmonDrv] ProcessCreate publish failed pid=%lu status=0x%08X failures=%ld\n",
            processId,
            status,
            g_ProcessCreateFailureCount);
        SysmonFreeEvent(event);
        SysmonCompletePendingProcessCreateFinalize(processId, FALSE);
        return TRUE;
    }

    if (filteredOut) {
        consumed = SysmonCompletePendingProcessCreateFinalize(processId, TRUE);
        imageForLog = pendingEntrySnapshot.Image;
        InterlockedIncrement(&g_ProcessCreateFilteredCount);
        SYSMON_HOTPATH_LOG(
            DPFLTR_INFO_LEVEL,
            "[SysmonDrv] ProcessCreate drop pid=%lu image=%ws consumed=%lu\n",
            eventData->ProcessId,
            imageForLog,
            consumed ? 1UL : 0UL);
        SysmonFreeEvent(event);
        return TRUE;
    }

    consumed = SysmonCompletePendingProcessCreateFinalize(processId, TRUE);
    if (!consumed) {
        DbgPrintEx(
            DPFLTR_DEFAULT_ID,
            DPFLTR_WARNING_LEVEL,
            "[SysmonDrv] ProcessCreate published pid=%lu but pending entry was already gone\n",
            processId);
    }

    InterlockedIncrement(&g_ProcessCreateCapturedCount);
    imageForLog = pendingEntrySnapshot.Image;
    SYSMON_HOTPATH_LOG(
        DPFLTR_INFO_LEVEL,
        "[SysmonDrv] ProcessCreate capture pid=%lu parentPid=%lu image=%ws captured=%ld\n",
        eventData->ProcessId,
        eventData->ParentProcessId,
        imageForLog,
        g_ProcessCreateCapturedCount);

    InterlockedIncrement(&g_ProcessCreateDeliveryCount);

    SYSMON_HOTPATH_LOG(
        DPFLTR_INFO_LEVEL,
        "[SysmonDrv] ProcessCreate delivered pid=%lu deliveries=%ld\n",
        processId,
        g_ProcessCreateDeliveryCount);

    SysmonFreeEvent(event);
    return TRUE;
}

BOOLEAN
SysmonTryFinalizePendingProcessCreate(
    _In_ HANDLE ProcessId)
{
    return SysmonTryFinalizePendingProcessCreateEx(ProcessId, NULL);
}

static VOID
SysmonPopulateProcessTerminateEvent(
    _In_ PSYSMON_EVENT_UNION Event,
    _In_ HANDLE ProcessId)
{
    PSYSMON_PROCESS_TERMINATE_EVENT_DATA eventData;
    SYSMON_EVENT_PAYLOAD_BUILDER builder;
    SYSMON_PROCESS_INFO processInfo;
    WCHAR processGuid[SYSMON_MAX_GUID_STRING];
    WCHAR image[SYSMON_MAX_PATH];
    WCHAR user[SYSMON_MAX_SID_STRING];
    ULONG pid;

    if (Event == NULL) {
        return;
    }

    eventData = (PSYSMON_PROCESS_TERMINATE_EVENT_DATA)Event->RawData;
    SysmonBeginStringPayload(Event, sizeof(*eventData), &builder);
    Event->Header.Timestamp = SysmonGetCurrentTimestamp();
    Event->Header.SequenceNumber = (ULONG)InterlockedIncrement(&g_ProcessSequence);

    pid = HandleToULong(ProcessId);
    eventData->ProcessId = pid;
    processGuid[0] = L'\0';
    image[0] = L'\0';
    user[0] = L'\0';
    RtlZeroMemory(&processInfo, sizeof(processInfo));

      SysmonRemoveCachedProcessEventIdentity(
          pid,
        processGuid,
        RTL_NUMBER_OF(processGuid),
        image,
        RTL_NUMBER_OF(image));

      if (image[0] == L'\0' || processGuid[0] == L'\0') {
          if (NT_SUCCESS(SysmonCollectProcessInfo(ProcessId, &processInfo))) {
              if (processGuid[0] == L'\0') {
                  SysmonCopyWideStringWithLength(processGuid, RTL_NUMBER_OF(processGuid), processInfo.ProcessGuid, SYSMON_GUID_STRING_CHARS);
              }
              if (image[0] == L'\0') {
                  SysmonCopyWideString(image, RTL_NUMBER_OF(image), processInfo.ImagePath);
              }
              if (processInfo.UserSid[0] != L'\0') {
                  SysmonCopyWideString(user, RTL_NUMBER_OF(user), processInfo.UserSid);
              }
          }
      } else if (NT_SUCCESS(SysmonCollectProcessInfo(ProcessId, &processInfo)) &&
                 processInfo.UserSid[0] != L'\0') {
          SysmonCopyWideString(user, RTL_NUMBER_OF(user), processInfo.UserSid);
      }

      SysmonAddStringLiteralField(Event, &builder, &eventData->RuleName, L"-");
      SysmonAddCurrentUtcTimeField(Event, &builder, &eventData->UtcTime);
      SysmonAddFixedLengthStringField(
          Event,
          &builder,
          &eventData->ProcessGuid,
          processGuid,
          SYSMON_GUID_STRING_CHARS);
      SysmonAddStringField(Event, &builder, &eventData->Image, image);
      SysmonAddStringField(Event, &builder, &eventData->User, user);
  }

static VOID
SysmonHandleProcessNotifyEvent(
    _In_ HANDLE ProcessId,
    _In_opt_ HANDLE ParentProcessId,
    _In_ BOOLEAN Create,
    _Inout_opt_ PPS_CREATE_NOTIFY_INFO CreateInfo)
{
    PSYSMON_EVENT_UNION event = NULL;
    WCHAR imageForLog[SYSMON_MAX_PATH];

    if (!SysmonIsProducerEnabled(SYSMON_FLAG_ENABLED) || !SysmonIsProducerEnabled(SYSMON_FLAG_PROCESS_NOTIFY)) {
        return;
    }

    InterlockedIncrement(&g_ProcessCallbackCount);
    SYSMON_HOTPATH_LOG(
        DPFLTR_INFO_LEVEL,
        "[SysmonDrv] Process callback create=%lu pid=%lu callbacks=%ld\n",
        Create ? 1UL : 0UL,
        HandleToULong(ProcessId),
        g_ProcessCallbackCount);

    if (Create) {
        InterlockedIncrement(&g_ProcessCreateAttemptCount);
        if (!SysmonCachePendingProcessCreate(ProcessId, ParentProcessId, CreateInfo)) {
            InterlockedIncrement(&g_ProcessCreateFailureCount);
            DbgPrintEx(
                DPFLTR_DEFAULT_ID,
                DPFLTR_ERROR_LEVEL,
                "[SysmonDrv] ProcessCreate cache failed pid=%lu failures=%ld\n",
                HandleToULong(ProcessId),
                g_ProcessCreateFailureCount);
            return;
        }

        imageForLog[0] = L'\0';
        if (CreateInfo != NULL) {
            SysmonCopyUnicodeString(
                imageForLog,
                RTL_NUMBER_OF(imageForLog),
                CreateInfo->ImageFileName);
        }
        SYSMON_HOTPATH_LOG(
            DPFLTR_INFO_LEVEL,
            "[SysmonDrv] ProcessCreate deferred pid=%lu parentPid=%lu image=%ws attempts=%ld\n",
            HandleToULong(ProcessId),
            (CreateInfo != NULL && CreateInfo->ParentProcessId != NULL)
                ? HandleToULong(CreateInfo->ParentProcessId)
                : HandleToULong(ParentProcessId),
            imageForLog,
            g_ProcessCreateAttemptCount);

        /*
         * Keep an asynchronous retry in flight even before the first thread
         * callback. This mirrors the original driver's deferred finalize path
         * and reduces misses for very short-lived processes.
         */
        (void)SysmonQueuePendingProcessCreateFinalize(ProcessId);

        return;
    } else {
        /*
         * Give Event 1 one last chance to materialize before the process tears
         * down, then drop any orphaned pending entry so failed finalizations do
         * not leak indefinitely.
        */
        (void)SysmonTryFinalizePendingProcessCreate(ProcessId);
        (void)SysmonConsumePendingProcessCreate(HandleToULong(ProcessId));

        if (!SysmonIsRuntimeEventConfigured(
                SysmonEventProcessTerminate,
                SysmonIsProducerEnabled(SYSMON_FLAG_PROCESS_NOTIFY))) {
            return;
        }

        event = SysmonAllocateEvent(SysmonEventProcessTerminate);
        if (event == NULL) {
            return;
        }

        SysmonPopulateProcessTerminateEvent(event, ProcessId);

        DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_TRACE_LEVEL,
            "[SysmonDrv] ProcessTerminate: PID=%lu\n", HandleToULong(ProcessId));
    }

    SysmonPublishEvent(event);
    SysmonFreeEvent(event);
}

static VOID
ProcessNotifyCallbackEx(
    _Inout_ PEPROCESS Process,
    _In_ HANDLE ProcessId,
    _Inout_opt_ PPS_CREATE_NOTIFY_INFO CreateInfo)
{
    UNREFERENCED_PARAMETER(Process);

    SysmonHandleProcessNotifyEvent(
        ProcessId,
        NULL,
        (CreateInfo != NULL),
        CreateInfo);
}

static VOID
ProcessNotifyCallbackLegacy(
    _In_ HANDLE ParentProcessId,
    _In_ HANDLE ProcessId,
    _In_ BOOLEAN Create)
{
    SysmonHandleProcessNotifyEvent(ProcessId, ParentProcessId, Create, NULL);
}

NTSTATUS
SysmonRegisterProcessNotify(_In_ PDRIVER_OBJECT DriverObject)
{
    NTSTATUS status;
    NTSTATUS threadStatus;
    UNICODE_STRING routineName;
    UNREFERENCED_PARAMETER(DriverObject);

    if (g_ProcessNotifyRegistered) {
        threadStatus = SysmonRegisterThreadNotify(DriverObject);
        if (!NT_SUCCESS(threadStatus)) {
            DbgPrintEx(
                DPFLTR_DEFAULT_ID,
                DPFLTR_WARNING_LEVEL,
                "[SysmonDrv] Existing process notify kept although thread notify restore failed: 0x%08X\n",
                threadStatus);
        }
        return STATUS_SUCCESS;
    }

    if (!g_ProcessEventCacheInitialized) {
        ULONG bucketIndex;

        for (bucketIndex = 0; bucketIndex < SYSMON_PROCESS_CACHE_BUCKETS; bucketIndex++) {
            InitializeListHead(&g_ProcessEventCacheBuckets[bucketIndex]);
            ExInitializeFastMutex(&g_ProcessEventCacheBucketLocks[bucketIndex]);
            g_ProcessEventCacheBucketCounts[bucketIndex] = 0;
            g_ProcessEventCacheBucketClocks[bucketIndex] = 0;
        }
        g_ProcessEventCacheInitialized = TRUE;
    }

    if (!g_PendingProcessCreateCacheInitialized) {
        ULONG bucketIndex;

        for (bucketIndex = 0; bucketIndex < SYSMON_PROCESS_CACHE_BUCKETS; bucketIndex++) {
            InitializeListHead(&g_PendingProcessCreateCacheBuckets[bucketIndex]);
            ExInitializeFastMutex(&g_PendingProcessCreateCacheBucketLocks[bucketIndex]);
        }
        g_PendingProcessCreateCacheInitialized = TRUE;
    }

    SysmonInitializeProcessCreateFinalizeInfrastructure();
    if (!g_ProcessCreateFinalizeWorkerInitialized) {
        if (g_Context.DeviceObject == NULL) {
            return STATUS_INVALID_DEVICE_STATE;
        }

        g_ProcessCreateFinalizeWorkItem = IoAllocateWorkItem(g_Context.DeviceObject);
        if (g_ProcessCreateFinalizeWorkItem == NULL) {
            return STATUS_INSUFFICIENT_RESOURCES;
        }

        g_ProcessCreateFinalizeWorkerInitialized = TRUE;
    }
    InterlockedExchange(&g_ProcessCreateFinalizeAcceptingWork, 1);

    g_ProcessNotifyRegisteredWithEx2 = FALSE;
    g_ProcessNotifyRegisteredWithEx = FALSE;

    if (g_PsSetCreateProcessNotifyRoutineEx2 == NULL) {
        RtlInitUnicodeString(&routineName, L"PsSetCreateProcessNotifyRoutineEx2");
        g_PsSetCreateProcessNotifyRoutineEx2 =
            (PFN_PS_SET_CREATE_PROCESS_NOTIFY_ROUTINE_EX2)MmGetSystemRoutineAddress(&routineName);
    }

    if (g_PsSetCreateProcessNotifyRoutineEx == NULL) {
        RtlInitUnicodeString(&routineName, L"PsSetCreateProcessNotifyRoutineEx");
        g_PsSetCreateProcessNotifyRoutineEx =
            (PFN_PS_SET_CREATE_PROCESS_NOTIFY_ROUTINE_EX)MmGetSystemRoutineAddress(&routineName);
    }

    if (g_PsSetCreateProcessNotifyRoutineLegacy == NULL) {
        RtlInitUnicodeString(&routineName, L"PsSetCreateProcessNotifyRoutine");
        g_PsSetCreateProcessNotifyRoutineLegacy =
            (PFN_PS_SET_CREATE_PROCESS_NOTIFY_ROUTINE)MmGetSystemRoutineAddress(&routineName);
    }

    /*
     * Event 1 finalization depends on the first thread-create callback, so
     * bring thread notifications online before process notifications to avoid
     * a startup window where pending creates can never be retried.
     */
    threadStatus = SysmonRegisterThreadNotify(DriverObject);
    if (!NT_SUCCESS(threadStatus)) {
        DbgPrintEx(
            DPFLTR_DEFAULT_ID,
            DPFLTR_WARNING_LEVEL,
            "[SysmonDrv] Thread notify registration unavailable; Event 1 will rely on deferred/exit finalize paths: 0x%08X\n",
            threadStatus);
    }

    status = STATUS_PROCEDURE_NOT_FOUND;
    if (g_PsSetCreateProcessNotifyRoutineEx2 != NULL) {
        status = g_PsSetCreateProcessNotifyRoutineEx2(
            SYSMON_PS_CREATE_PROCESS_NOTIFY_SUBSYSTEMS,
            (PVOID)ProcessNotifyCallbackEx,
            FALSE);
        if (NT_SUCCESS(status)) {
            g_ProcessNotifyRegistered = TRUE;
            g_ProcessNotifyRegisteredWithEx2 = TRUE;
            g_ProcessNotifyRegisteredWithEx = FALSE;
        } else {
            DbgPrintEx(
                DPFLTR_DEFAULT_ID,
                DPFLTR_ERROR_LEVEL,
                "[SysmonDrv] PsSetCreateProcessNotifyRoutineEx2 registration failed: 0x%08X\n",
                status);
        }
    }

    if (!NT_SUCCESS(status) && g_PsSetCreateProcessNotifyRoutineEx != NULL) {
        status = g_PsSetCreateProcessNotifyRoutineEx(ProcessNotifyCallbackEx, FALSE);
        if (NT_SUCCESS(status)) {
            g_ProcessNotifyRegistered = TRUE;
            g_ProcessNotifyRegisteredWithEx2 = FALSE;
            g_ProcessNotifyRegisteredWithEx = TRUE;
        } else {
            DbgPrintEx(
                DPFLTR_DEFAULT_ID,
                DPFLTR_ERROR_LEVEL,
                "[SysmonDrv] PsSetCreateProcessNotifyRoutineEx registration failed: 0x%08X\n",
                status);
        }
    }

    if (!NT_SUCCESS(status) && g_PsSetCreateProcessNotifyRoutineLegacy != NULL) {
        status = g_PsSetCreateProcessNotifyRoutineLegacy(ProcessNotifyCallbackLegacy, FALSE);
        if (NT_SUCCESS(status)) {
            g_ProcessNotifyRegistered = TRUE;
            g_ProcessNotifyRegisteredWithEx2 = FALSE;
            g_ProcessNotifyRegisteredWithEx = FALSE;
            DbgPrintEx(
                DPFLTR_DEFAULT_ID,
                DPFLTR_WARNING_LEVEL,
                "[SysmonDrv] Using legacy PsSetCreateProcessNotifyRoutine because Ex routine is unavailable\n");
        }
    }

    if (!NT_SUCCESS(status)) {
        DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL,
            "[SysmonDrv] Process notify registration failed: 0x%08X\n", status);
        SysmonUnregisterThreadNotify();
        SysmonCleanupProcessCreateFinalizeInfrastructure();
    } else {
        DbgPrintEx(
            DPFLTR_DEFAULT_ID,
            DPFLTR_INFO_LEVEL,
            "[SysmonDrv] Process notify registered using %s callback\n",
            g_ProcessNotifyRegisteredWithEx2 ? "Ex2" :
            (g_ProcessNotifyRegisteredWithEx ? "Ex" : "legacy"));
    }
    return status;
}

VOID
SysmonUnregisterProcessNotify(VOID)
{
    if (!g_ProcessNotifyRegistered) {
        SysmonCleanupProcessCreateFinalizeInfrastructure();
        if (g_ProcessEventCacheInitialized) {
            SysmonDrainProcessEventCache();
            g_ProcessEventCacheInitialized = FALSE;
        }
        if (g_PendingProcessCreateCacheInitialized) {
            SysmonDrainPendingProcessCreateCache();
            g_PendingProcessCreateCacheInitialized = FALSE;
        }
        return;
    }

    if (g_ProcessNotifyRegisteredWithEx2 && g_PsSetCreateProcessNotifyRoutineEx2 != NULL) {
        g_PsSetCreateProcessNotifyRoutineEx2(
            SYSMON_PS_CREATE_PROCESS_NOTIFY_SUBSYSTEMS,
            (PVOID)ProcessNotifyCallbackEx,
            TRUE);
    } else if (g_ProcessNotifyRegisteredWithEx && g_PsSetCreateProcessNotifyRoutineEx != NULL) {
        g_PsSetCreateProcessNotifyRoutineEx(ProcessNotifyCallbackEx, TRUE);
    } else if (!g_ProcessNotifyRegisteredWithEx &&
               g_PsSetCreateProcessNotifyRoutineLegacy != NULL) {
        g_PsSetCreateProcessNotifyRoutineLegacy(ProcessNotifyCallbackLegacy, TRUE);
    }
    g_ProcessNotifyRegistered = FALSE;
    g_ProcessNotifyRegisteredWithEx2 = FALSE;
    g_ProcessNotifyRegisteredWithEx = FALSE;
    SysmonCleanupProcessCreateFinalizeInfrastructure();
    SysmonDrainProcessEventCache();
    SysmonDrainPendingProcessCreateCache();
    g_ProcessEventCacheInitialized = FALSE;
    g_PendingProcessCreateCacheInitialized = FALSE;
}

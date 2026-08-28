#include "../include/process_store.h"

#include <psapi.h>
#include <tlhelp32.h>

#ifndef PROCESS_QUERY_LIMITED_INFORMATION
#define PROCESS_QUERY_LIMITED_INFORMATION 0x1000
#endif

#define SYSMON_PROCESS_STORE_BUCKET_COUNT 8
#define SYSMON_PROCESS_STORE_STALE_WINDOW 600000000ull
#define SYSMON_DNS_DEDUP_PER_PROCESS_LIMIT 1000

typedef struct _SYSMON_DNS_DEDUP_ENTRY {
    PWCHAR QueryName;
    PWCHAR QueryStatus;
    PWCHAR QueryResults;
    struct _SYSMON_DNS_DEDUP_ENTRY *Next;
} SYSMON_DNS_DEDUP_ENTRY, *PSYSMON_DNS_DEDUP_ENTRY;

typedef struct _SYSMON_PROCESS_INSTANCE {
    ULONGLONG LastSeenTime;
    ULONGLONG LowerTimeBound;
    ULONGLONG UpperTimeBound;
    SYSMON_PROCESS_CACHE_RESPONSE Snapshot;
    PSYSMON_DNS_DEDUP_ENTRY DnsHead;
    PSYSMON_DNS_DEDUP_ENTRY DnsTail;
    DWORD DnsEntryCount;
    struct _SYSMON_PROCESS_INSTANCE *Prev;
    struct _SYSMON_PROCESS_INSTANCE *Next;
} SYSMON_PROCESS_INSTANCE, *PSYSMON_PROCESS_INSTANCE;

typedef struct _SYSMON_PROCESS_NODE {
    DWORD ProcessId;
    DWORD InstanceCount;
    ULONGLONG LastActivityTime;
    struct _SYSMON_PROCESS_NODE *NextInBucket;
    struct _SYSMON_PROCESS_NODE *PrevGlobal;
    struct _SYSMON_PROCESS_NODE *NextGlobal;
    PSYSMON_PROCESS_INSTANCE InstanceHead;
    PSYSMON_PROCESS_INSTANCE InstanceTail;
} SYSMON_PROCESS_NODE, *PSYSMON_PROCESS_NODE;

typedef struct _SYSMON_PROCESS_ACTIVITY_ENTRY {
    ULONGLONG Timestamp;
    DWORD ProcessId;
} SYSMON_PROCESS_ACTIVITY_ENTRY, *PSYSMON_PROCESS_ACTIVITY_ENTRY;

typedef struct _SYSMON_PROCESS_STORE {
    CRITICAL_SECTION Lock;
    PSYSMON_PROCESS_NODE Buckets[SYSMON_PROCESS_STORE_BUCKET_COUNT];
    PSYSMON_PROCESS_NODE GlobalHead;
    PSYSMON_PROCESS_NODE GlobalTail;
    PSYSMON_PROCESS_ACTIVITY_ENTRY ActivityHeapBase;
    PSYSMON_PROCESS_ACTIVITY_ENTRY ActivityHeapCurrent;
    PSYSMON_PROCESS_ACTIVITY_ENTRY ActivityHeapEnd;
} SYSMON_PROCESS_STORE, *PSYSMON_PROCESS_STORE;

static SYSMON_PROCESS_STORE g_ProcessStore;
static INIT_ONCE g_ProcessStoreInitOnce = INIT_ONCE_STATIC_INIT;
static volatile LONG g_ProcessStoreInitialized = 0;

static ULONGLONG
SysmonProcessStoreCurrentTime(void)
{
    FILETIME now;
    ULARGE_INTEGER value;

    GetSystemTimeAsFileTime(&now);
    value.LowPart = now.dwLowDateTime;
    value.HighPart = now.dwHighDateTime;
    return value.QuadPart;
}

static void
SysmonProcessStoreCopyWideOrEmpty(
    _Out_writes_(BufferChars) PWCHAR Buffer,
    _In_ size_t BufferChars,
    _In_opt_z_ PCWSTR Text)
{
    if (Buffer == NULL || BufferChars == 0) {
        return;
    }

    if (Text == NULL || Text[0] == L'\0') {
        Buffer[0] = L'\0';
        return;
    }

    wcscpy_s(Buffer, BufferChars, Text);
}

static PWCHAR
SysmonProcessStoreDuplicateWideText(
    _In_z_ PCWSTR Text)
{
    SIZE_T charCount;
    SIZE_T byteCount;
    PWCHAR copy;

    if (Text == NULL) {
        return NULL;
    }

    charCount = wcslen(Text) + 1;
    byteCount = charCount * sizeof(WCHAR);
    copy = (PWCHAR)SYSMON_ALLOC(byteCount);
    if (copy == NULL) {
        return NULL;
    }

    memcpy(copy, Text, byteCount);
    return copy;
}

static DWORD
SysmonProcessStoreSelectBucket(
    _In_ DWORD ProcessId)
{
    return ProcessId & (SYSMON_PROCESS_STORE_BUCKET_COUNT - 1);
}

static size_t
SysmonProcessStoreActivityCountLocked(void)
{
    if (g_ProcessStore.ActivityHeapBase == NULL ||
        g_ProcessStore.ActivityHeapCurrent == NULL ||
        g_ProcessStore.ActivityHeapCurrent < g_ProcessStore.ActivityHeapBase) {
        return 0;
    }

    return (size_t)(g_ProcessStore.ActivityHeapCurrent - g_ProcessStore.ActivityHeapBase);
}

static BOOL
SysmonProcessStoreEnsureActivityCapacityLocked(void)
{
    size_t oldCapacity;
    size_t oldCount;
    size_t minCapacity;
    size_t grownCapacity;
    size_t newCapacity;
    SIZE_T newSize;
    PSYSMON_PROCESS_ACTIVITY_ENTRY newBuffer;

    if (g_ProcessStore.ActivityHeapBase != NULL &&
        g_ProcessStore.ActivityHeapCurrent < g_ProcessStore.ActivityHeapEnd) {
        return TRUE;
    }

    oldCount = SysmonProcessStoreActivityCountLocked();
    oldCapacity = g_ProcessStore.ActivityHeapBase != NULL
        ? (size_t)(g_ProcessStore.ActivityHeapEnd - g_ProcessStore.ActivityHeapBase)
        : 0;

    minCapacity = oldCount + 1;
    if (oldCapacity == 0) {
        newCapacity = minCapacity;
    } else {
        grownCapacity = oldCapacity + (oldCapacity >> 1);
        newCapacity = grownCapacity >= minCapacity ? grownCapacity : minCapacity;
    }

    newSize = newCapacity * sizeof(*newBuffer);
    newBuffer = (PSYSMON_PROCESS_ACTIVITY_ENTRY)SYSMON_ALLOC(newSize);
    if (newBuffer == NULL) {
        return FALSE;
    }

    if (oldCount != 0) {
        memcpy(newBuffer, g_ProcessStore.ActivityHeapBase, oldCount * sizeof(*newBuffer));
    }

    SYSMON_FREE(g_ProcessStore.ActivityHeapBase);
    g_ProcessStore.ActivityHeapBase = newBuffer;
    g_ProcessStore.ActivityHeapCurrent = newBuffer + oldCount;
    g_ProcessStore.ActivityHeapEnd = newBuffer + newCapacity;
    return TRUE;
}

static void
SysmonProcessStoreSwapActivityEntriesLocked(
    _In_ size_t Left,
    _In_ size_t Right)
{
    SYSMON_PROCESS_ACTIVITY_ENTRY temp;

    temp = g_ProcessStore.ActivityHeapBase[Left];
    g_ProcessStore.ActivityHeapBase[Left] = g_ProcessStore.ActivityHeapBase[Right];
    g_ProcessStore.ActivityHeapBase[Right] = temp;
}

static void
SysmonProcessStoreHeapifyUpLocked(
    _In_ size_t Index)
{
    while (Index > 0) {
        size_t parent = (Index - 1) / 2;

        if (g_ProcessStore.ActivityHeapBase[parent].Timestamp <=
            g_ProcessStore.ActivityHeapBase[Index].Timestamp) {
            break;
        }

        SysmonProcessStoreSwapActivityEntriesLocked(parent, Index);
        Index = parent;
    }
}

static void
SysmonProcessStoreHeapifyDownLocked(
    _In_ size_t Index)
{
    size_t count = SysmonProcessStoreActivityCountLocked();

    for (;;) {
        size_t left = (Index * 2) + 1;
        size_t right = left + 1;
        size_t smallest = Index;

        if (left < count &&
            g_ProcessStore.ActivityHeapBase[left].Timestamp <
                g_ProcessStore.ActivityHeapBase[smallest].Timestamp) {
            smallest = left;
        }

        if (right < count &&
            g_ProcessStore.ActivityHeapBase[right].Timestamp <
                g_ProcessStore.ActivityHeapBase[smallest].Timestamp) {
            smallest = right;
        }

        if (smallest == Index) {
            break;
        }

        SysmonProcessStoreSwapActivityEntriesLocked(Index, smallest);
        Index = smallest;
    }
}

static BOOL
SysmonProcessStorePopOldestActivityLocked(
    _Out_ PSYSMON_PROCESS_ACTIVITY_ENTRY Entry)
{
    size_t count = SysmonProcessStoreActivityCountLocked();

    if (Entry == NULL || count == 0) {
        return FALSE;
    }

    *Entry = g_ProcessStore.ActivityHeapBase[0];
    count -= 1;
    g_ProcessStore.ActivityHeapCurrent = g_ProcessStore.ActivityHeapBase + count;
    if (count != 0) {
        g_ProcessStore.ActivityHeapBase[0] = g_ProcessStore.ActivityHeapBase[count];
        SysmonProcessStoreHeapifyDownLocked(0);
    }

    return TRUE;
}

static void
SysmonProcessStoreFreeDnsEntriesLocked(
    _Inout_opt_ PSYSMON_DNS_DEDUP_ENTRY Entry)
{
    while (Entry != NULL) {
        PSYSMON_DNS_DEDUP_ENTRY nextEntry = Entry->Next;
        SYSMON_FREE(Entry->QueryName);
        SYSMON_FREE(Entry->QueryStatus);
        SYSMON_FREE(Entry->QueryResults);
        SYSMON_FREE(Entry);
        Entry = nextEntry;
    }
}

static PSYSMON_PROCESS_NODE
SysmonProcessStoreFindNodeLocked(
    _In_ DWORD ProcessId)
{
    PSYSMON_PROCESS_NODE node;

    node = g_ProcessStore.Buckets[SysmonProcessStoreSelectBucket(ProcessId)];
    while (node != NULL) {
        if (node->ProcessId == ProcessId) {
            return node;
        }

        node = node->NextInBucket;
    }

    return NULL;
}

static void
SysmonProcessStoreRemoveNodeFromIndexesLocked(
    _Inout_ PSYSMON_PROCESS_NODE Node)
{
    PSYSMON_PROCESS_NODE *bucketLink;

    if (Node == NULL) {
        return;
    }

    if (Node->PrevGlobal != NULL) {
        Node->PrevGlobal->NextGlobal = Node->NextGlobal;
    } else {
        g_ProcessStore.GlobalHead = Node->NextGlobal;
    }

    if (Node->NextGlobal != NULL) {
        Node->NextGlobal->PrevGlobal = Node->PrevGlobal;
    } else {
        g_ProcessStore.GlobalTail = Node->PrevGlobal;
    }

    bucketLink = &g_ProcessStore.Buckets[SysmonProcessStoreSelectBucket(Node->ProcessId)];
    while (*bucketLink != NULL && *bucketLink != Node) {
        bucketLink = &(*bucketLink)->NextInBucket;
    }

    if (*bucketLink == Node) {
        *bucketLink = Node->NextInBucket;
    }

    Node->PrevGlobal = NULL;
    Node->NextGlobal = NULL;
    Node->NextInBucket = NULL;
}

static void
SysmonProcessStoreFreeNodeLocked(
    _Inout_ PSYSMON_PROCESS_NODE Node)
{
    PSYSMON_PROCESS_INSTANCE instance;

    if (Node == NULL) {
        return;
    }

    SysmonProcessStoreRemoveNodeFromIndexesLocked(Node);

    instance = Node->InstanceHead;
    while (instance != NULL) {
        PSYSMON_PROCESS_INSTANCE nextInstance = instance->Next;
        SysmonProcessStoreFreeDnsEntriesLocked(instance->DnsHead);
        SYSMON_FREE(instance);
        instance = nextInstance;
    }

    SYSMON_FREE(Node);
}

static void
SysmonProcessStoreRecordActivityLocked(
    _In_ DWORD ProcessId,
    _In_ ULONGLONG Timestamp)
{
    size_t index;

    if (!SysmonProcessStoreEnsureActivityCapacityLocked()) {
        return;
    }

    index = SysmonProcessStoreActivityCountLocked();
    g_ProcessStore.ActivityHeapBase[index].Timestamp = Timestamp;
    g_ProcessStore.ActivityHeapBase[index].ProcessId = ProcessId;
    g_ProcessStore.ActivityHeapCurrent = g_ProcessStore.ActivityHeapBase + index + 1;
    SysmonProcessStoreHeapifyUpLocked(index);
}

static void
SysmonProcessStoreTouchNodeLocked(
    _Inout_ PSYSMON_PROCESS_NODE Node,
    _In_ ULONGLONG Timestamp)
{
    PSYSMON_PROCESS_INSTANCE instance;

    if (Node == NULL) {
        return;
    }

    Node->LastActivityTime = Timestamp;
    for (instance = Node->InstanceHead; instance != NULL; instance = instance->Next) {
        instance->LastSeenTime = Timestamp;
    }

    SysmonProcessStoreRecordActivityLocked(Node->ProcessId, Timestamp);
}

static void
SysmonProcessStoreEvictStaleNodesLocked(
    _In_ ULONGLONG Now)
{
    SYSMON_PROCESS_ACTIVITY_ENTRY entry;
    PSYSMON_PROCESS_NODE node;

    while (SysmonProcessStoreActivityCountLocked() != 0) {
        if (g_ProcessStore.ActivityHeapBase[0].Timestamp + SYSMON_PROCESS_STORE_STALE_WINDOW >= Now) {
            break;
        }

        if (!SysmonProcessStorePopOldestActivityLocked(&entry)) {
            break;
        }

        node = SysmonProcessStoreFindNodeLocked(entry.ProcessId);
        if (node == NULL) {
            continue;
        }

        if (node->LastActivityTime != entry.Timestamp) {
            continue;
        }

        SysmonProcessStoreFreeNodeLocked(node);
    }
}

static PSYSMON_PROCESS_NODE
SysmonProcessStoreFindOrCreateNodeLocked(
    _In_ DWORD ProcessId,
    _Out_opt_ PBOOL CreatedNew)
{
    DWORD bucket;
    PSYSMON_PROCESS_NODE node;

    if (CreatedNew != NULL) {
        *CreatedNew = FALSE;
    }

    node = SysmonProcessStoreFindNodeLocked(ProcessId);
    if (node != NULL) {
        return node;
    }

    node = (PSYSMON_PROCESS_NODE)SYSMON_ALLOC(sizeof(*node));
    if (node == NULL) {
        return NULL;
    }

    ZeroMemory(node, sizeof(*node));
    node->ProcessId = ProcessId;

    bucket = SysmonProcessStoreSelectBucket(ProcessId);
    node->NextInBucket = g_ProcessStore.Buckets[bucket];
    g_ProcessStore.Buckets[bucket] = node;

    node->NextGlobal = g_ProcessStore.GlobalHead;
    if (g_ProcessStore.GlobalHead != NULL) {
        g_ProcessStore.GlobalHead->PrevGlobal = node;
    } else {
        g_ProcessStore.GlobalTail = node;
    }
    g_ProcessStore.GlobalHead = node;

    if (CreatedNew != NULL) {
        *CreatedNew = TRUE;
    }

    return node;
}

static PSYSMON_PROCESS_INSTANCE
SysmonProcessStoreSelectInstanceLocked(
    _In_opt_ PSYSMON_PROCESS_NODE Node,
    _In_opt_ const ULONGLONG *Timestamp)
{
    PSYSMON_PROCESS_INSTANCE instance;

    if (Node == NULL) {
        return NULL;
    }

    if (Timestamp == NULL) {
        return Node->InstanceHead;
    }

    for (instance = Node->InstanceHead; instance != NULL; instance = instance->Next) {
        if (*Timestamp >= instance->LowerTimeBound &&
            (instance->UpperTimeBound == 0 || *Timestamp <= instance->UpperTimeBound)) {
            return instance;
        }
    }

    return NULL;
}

static BOOL
SysmonDnsDedupEntryMatches(
    _In_ const SYSMON_DNS_DEDUP_ENTRY *Entry,
    _In_z_ PCWSTR QueryName,
    _In_z_ PCWSTR QueryStatus,
    _In_z_ PCWSTR QueryResults)
{
    if (Entry == NULL ||
        Entry->QueryName == NULL ||
        Entry->QueryStatus == NULL ||
        Entry->QueryResults == NULL) {
        return FALSE;
    }

    return _wcsicmp(Entry->QueryName, QueryName) == 0 &&
           _wcsicmp(Entry->QueryStatus, QueryStatus) == 0 &&
           _wcsicmp(Entry->QueryResults, QueryResults) == 0;
}

static BOOL
SysmonProcessStoreRememberDnsEventLocked(
    _Inout_ PSYSMON_PROCESS_INSTANCE Instance,
    _In_z_ PCWSTR QueryName,
    _In_z_ PCWSTR QueryStatus,
    _In_z_ PCWSTR QueryResults)
{
    PSYSMON_DNS_DEDUP_ENTRY entry;
    PSYSMON_DNS_DEDUP_ENTRY newEntry;

    for (entry = Instance->DnsHead; entry != NULL; entry = entry->Next) {
        if (SysmonDnsDedupEntryMatches(entry, QueryName, QueryStatus, QueryResults)) {
            return FALSE;
        }
    }

    if (Instance->DnsEntryCount >= SYSMON_DNS_DEDUP_PER_PROCESS_LIMIT &&
        Instance->DnsHead != NULL) {
        entry = Instance->DnsHead;
        Instance->DnsHead = entry->Next;
        if (Instance->DnsHead == NULL) {
            Instance->DnsTail = NULL;
        }
        Instance->DnsEntryCount -= 1;
        entry->Next = NULL;
        SysmonProcessStoreFreeDnsEntriesLocked(entry);
    }

    newEntry = (PSYSMON_DNS_DEDUP_ENTRY)SYSMON_ALLOC(sizeof(*newEntry));
    if (newEntry == NULL) {
        return TRUE;
    }

    ZeroMemory(newEntry, sizeof(*newEntry));
    newEntry->QueryName = SysmonProcessStoreDuplicateWideText(QueryName);
    newEntry->QueryStatus = SysmonProcessStoreDuplicateWideText(QueryStatus);
    newEntry->QueryResults = SysmonProcessStoreDuplicateWideText(QueryResults);
    if (newEntry->QueryName == NULL ||
        newEntry->QueryStatus == NULL ||
        newEntry->QueryResults == NULL) {
        SysmonProcessStoreFreeDnsEntriesLocked(newEntry);
        return TRUE;
    }

    if (Instance->DnsTail != NULL) {
        Instance->DnsTail->Next = newEntry;
    } else {
        Instance->DnsHead = newEntry;
    }
    Instance->DnsTail = newEntry;
    Instance->DnsEntryCount += 1;
    return TRUE;
}

static BOOL CALLBACK
SysmonProcessStoreInitOnceCallback(
    PINIT_ONCE InitOnce,
    PVOID Parameter,
    PVOID *Context)
{
    UNREFERENCED_PARAMETER(InitOnce);
    UNREFERENCED_PARAMETER(Parameter);
    UNREFERENCED_PARAMETER(Context);

    ZeroMemory(&g_ProcessStore, sizeof(g_ProcessStore));
    InitializeCriticalSection(&g_ProcessStore.Lock);
    InterlockedExchange(&g_ProcessStoreInitialized, 1);
    return TRUE;
}

BOOL
SysmonProcessStoreEnsureInitialized(void)
{
    return InitOnceExecuteOnce(
        &g_ProcessStoreInitOnce,
        SysmonProcessStoreInitOnceCallback,
        NULL,
        NULL);
}

void
SysmonProcessStoreCleanup(void)
{
    if (InterlockedCompareExchange(&g_ProcessStoreInitialized, 0, 0) == 0) {
        return;
    }

    EnterCriticalSection(&g_ProcessStore.Lock);
    while (g_ProcessStore.GlobalHead != NULL) {
        SysmonProcessStoreFreeNodeLocked(g_ProcessStore.GlobalHead);
    }
    ZeroMemory(g_ProcessStore.Buckets, sizeof(g_ProcessStore.Buckets));
    LeaveCriticalSection(&g_ProcessStore.Lock);

    SYSMON_FREE(g_ProcessStore.ActivityHeapBase);
    g_ProcessStore.ActivityHeapBase = NULL;
    g_ProcessStore.ActivityHeapCurrent = NULL;
    g_ProcessStore.ActivityHeapEnd = NULL;
    DeleteCriticalSection(&g_ProcessStore.Lock);
    ZeroMemory(&g_ProcessStore, sizeof(g_ProcessStore));
    InterlockedExchange(&g_ProcessStoreInitialized, 0);
}

BOOL
SysmonProcessStoreLookupProcessByPidAndTime(
    _In_ DWORD ProcessId,
    _In_opt_ const ULONGLONG *Timestamp,
    _Out_ PSYSMON_PROCESS_CACHE_RESPONSE Response)
{
    PSYSMON_PROCESS_NODE node;
    PSYSMON_PROCESS_INSTANCE instance;

    if (Response == NULL || !SysmonProcessStoreEnsureInitialized()) {
        return FALSE;
    }

    ZeroMemory(Response, sizeof(*Response));

    EnterCriticalSection(&g_ProcessStore.Lock);
    node = SysmonProcessStoreFindNodeLocked(ProcessId);
    instance = SysmonProcessStoreSelectInstanceLocked(node, Timestamp);
    if (instance != NULL) {
        *Response = instance->Snapshot;
        SysmonProcessStoreRecordActivityLocked(ProcessId, instance->LastSeenTime);
    }
    LeaveCriticalSection(&g_ProcessStore.Lock);

    return instance != NULL;
}

BOOL
SysmonProcessStoreInsertProcessCacheResponse(
    _In_ DWORD ProcessId,
    _In_ const SYSMON_PROCESS_CACHE_RESPONSE *Response)
{
    BOOL createdNew = FALSE;
    ULONGLONG now;
    PSYSMON_PROCESS_NODE node;
    PSYSMON_PROCESS_INSTANCE current;
    PSYSMON_PROCESS_INSTANCE previous;
    PSYSMON_PROCESS_INSTANCE instance;

    if (Response == NULL || !SysmonProcessStoreEnsureInitialized()) {
        return FALSE;
    }

    now = SysmonProcessStoreCurrentTime();

    EnterCriticalSection(&g_ProcessStore.Lock);

    node = SysmonProcessStoreFindOrCreateNodeLocked(ProcessId, &createdNew);
    if (node == NULL) {
        LeaveCriticalSection(&g_ProcessStore.Lock);
        return FALSE;
    }

    previous = NULL;
    current = node->InstanceHead;
    while (current != NULL && current->LowerTimeBound > Response->CreateTime) {
        previous = current;
        current = current->Next;
    }

    if (current != NULL && current->LowerTimeBound == Response->CreateTime) {
        current->Snapshot = *Response;
        current->LastSeenTime = now;
        SysmonProcessStoreTouchNodeLocked(node, now);
        SysmonProcessStoreEvictStaleNodesLocked(now);
        LeaveCriticalSection(&g_ProcessStore.Lock);
        return TRUE;
    }

    instance = (PSYSMON_PROCESS_INSTANCE)SYSMON_ALLOC(sizeof(*instance));
    if (instance == NULL) {
        if (createdNew && node->InstanceCount == 0) {
            SysmonProcessStoreFreeNodeLocked(node);
        }
        LeaveCriticalSection(&g_ProcessStore.Lock);
        return FALSE;
    }

    ZeroMemory(instance, sizeof(*instance));
    instance->Snapshot = *Response;
    instance->LastSeenTime = now;
    instance->LowerTimeBound = Response->CreateTime;
    instance->UpperTimeBound = previous != NULL ? previous->LowerTimeBound : 0;

    instance->Prev = previous;
    instance->Next = current;
    if (previous != NULL) {
        previous->Next = instance;
    } else {
        node->InstanceHead = instance;
    }

    if (current != NULL) {
        current->Prev = instance;
        current->UpperTimeBound = instance->LowerTimeBound;
    } else {
        node->InstanceTail = instance;
    }

    if (node->InstanceTail == NULL) {
        node->InstanceTail = instance;
    }

    node->InstanceCount += 1;
    SysmonProcessStoreTouchNodeLocked(node, now);
    SysmonProcessStoreEvictStaleNodesLocked(now);
    LeaveCriticalSection(&g_ProcessStore.Lock);
    return TRUE;
}

void
SysmonProcessStoreTouch(
    _In_ DWORD ProcessId,
    _In_opt_ const ULONGLONG *Timestamp)
{
    ULONGLONG now;
    PSYSMON_PROCESS_NODE node;

    if (!SysmonProcessStoreEnsureInitialized()) {
        return;
    }

    now = Timestamp != NULL ? *Timestamp : SysmonProcessStoreCurrentTime();

    EnterCriticalSection(&g_ProcessStore.Lock);
    node = SysmonProcessStoreFindNodeLocked(ProcessId);
    if (node != NULL) {
        SysmonProcessStoreTouchNodeLocked(node, now);
        SysmonProcessStoreEvictStaleNodesLocked(now);
    }
    LeaveCriticalSection(&g_ProcessStore.Lock);
}

BOOL
SysmonProcessStoreRememberDnsEvent(
    _In_ DWORD ProcessId,
    _In_opt_ const ULONGLONG *Timestamp,
    _In_z_ PCWSTR QueryName,
    _In_z_ PCWSTR QueryStatus,
    _In_z_ PCWSTR QueryResults)
{
    ULONGLONG now;
    PSYSMON_PROCESS_NODE node;
    PSYSMON_PROCESS_INSTANCE instance;

    if (QueryName == NULL ||
        QueryStatus == NULL ||
        QueryResults == NULL ||
        !SysmonProcessStoreEnsureInitialized()) {
        return TRUE;
    }

    now = Timestamp != NULL ? *Timestamp : SysmonProcessStoreCurrentTime();

    EnterCriticalSection(&g_ProcessStore.Lock);
    node = SysmonProcessStoreFindNodeLocked(ProcessId);
    instance = SysmonProcessStoreSelectInstanceLocked(node, Timestamp);
    if (instance == NULL) {
        LeaveCriticalSection(&g_ProcessStore.Lock);
        return TRUE;
    }

    if (SysmonProcessStoreRememberDnsEventLocked(instance, QueryName, QueryStatus, QueryResults)) {
        instance->LastSeenTime = now;
        if (node != NULL) {
            node->LastActivityTime = now;
            SysmonProcessStoreRecordActivityLocked(ProcessId, now);
            SysmonProcessStoreEvictStaleNodesLocked(now);
        }
        LeaveCriticalSection(&g_ProcessStore.Lock);
        return TRUE;
    }

    LeaveCriticalSection(&g_ProcessStore.Lock);
    return FALSE;
}

BOOL
SysmonProcessStoreResolveImage(
    _In_ DWORD ProcessId,
    _In_opt_ const ULONGLONG *Timestamp,
    _Out_writes_(BufferChars) PWCHAR Buffer,
    _In_ size_t BufferChars)
{
    SYSMON_PROCESS_CACHE_RESPONSE response;
    HANDLE processHandle;
    DWORD imageChars;
    HANDLE snapshot;
    MODULEENTRY32W moduleEntry;

    if (Buffer == NULL || BufferChars == 0) {
        return FALSE;
    }

    Buffer[0] = L'\0';
    ZeroMemory(&response, sizeof(response));
    if (SysmonProcessStoreLookupProcessByPidAndTime(ProcessId, Timestamp, &response) &&
        !SysmonIsPlaceholderString(response.Image)) {
        SysmonProcessStoreCopyWideOrEmpty(Buffer, BufferChars, response.Image);
        return Buffer[0] != L'\0';
    }

    processHandle = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, ProcessId);
    if (processHandle == NULL) {
        processHandle = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, ProcessId);
    }

    if (processHandle != NULL) {
        imageChars = (DWORD)BufferChars;
        if (QueryFullProcessImageNameW(processHandle, 0, Buffer, &imageChars)) {
            CloseHandle(processHandle);
            return TRUE;
        }

        imageChars = (DWORD)BufferChars;
        if (GetProcessImageFileNameW(processHandle, Buffer, imageChars) != 0) {
            CloseHandle(processHandle);
            return TRUE;
        }

        CloseHandle(processHandle);
    }

    snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, ProcessId);
    if (snapshot == INVALID_HANDLE_VALUE) {
        return FALSE;
    }

    ZeroMemory(&moduleEntry, sizeof(moduleEntry));
    moduleEntry.dwSize = sizeof(moduleEntry);
    if (Module32FirstW(snapshot, &moduleEntry)) {
        SysmonProcessStoreCopyWideOrEmpty(Buffer, BufferChars, moduleEntry.szExePath);
        CloseHandle(snapshot);
        return Buffer[0] != L'\0';
    }

    CloseHandle(snapshot);
    return FALSE;
}

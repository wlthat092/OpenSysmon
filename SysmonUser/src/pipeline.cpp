/*
 * pipeline.c - Event unpacking, enrichment, and final dispatch
 *
 * Receives raw events from the driver, validates their headers, enriches
 * Event 6/7 signature fields in user mode, applies a final user-mode rule
 * pass for those enriched events, then forwards the resulting payload to
 * the output layer.
 */

#include "../include/pipeline.h"
#include "../include/output.h"
#include "../include/common.h"
#include "../include/hash_compat.h"
#include "../include/path_cache.h"
#include "../include/packed_read.hpp"
#include "../include/runtime.hpp"
#include "../include/service.h"
#include "../include/rules.h"

#include <wintrust.h>
#include <softpub.h>
#include <mscat.h>

/* Event handler table indexed by EventId */
static SYSMON_EVENT_HANDLER g_EventHandlers[256] = { 0 };
static const GUID g_GenericVerifyV2Action = WINTRUST_ACTION_GENERIC_VERIFY_V2;
static const GUID g_DriverVerifyAction = DRIVER_ACTION_VERIFY;
static const GUID g_ConfigCiVerifyAction = CONFIG_CI_ACTION_VERIFY;

#define SYSMON_SIGNATURE_CACHE_CAPACITY   4096
#define SYSMON_SIGNATURE_CACHE_BUCKET_COUNT 8192
#define SYSMON_IMAGE_ENRICHMENT_CACHE_CAPACITY 8192
#define SYSMON_IMAGE_ENRICHMENT_CACHE_BUCKET_COUNT 16384
#define SYSMON_MAX_SIGNATURE_PATH_CHARS   1024
#define SYSMON_MAX_SIGNER_NAME_CHARS      256
#define SYSMON_MAX_SIGNATURE_STATUS_CHARS 64
#define SYSMON_ENRICHED_EVENT_BUFFER_SIZE 32768
#define SYSMON_MAX_SIGNING_WORKERS        8
#define SYSMON_DEFAULT_SIGNING_WORKERS    2
#define SYSMON_MAX_PENDING_ENRICHMENT_EVENTS_PER_WORK_ITEM 256
#define SYSMON_MAX_PENDING_ENRICHMENT_EVENTS 16384

typedef LONG (WINAPI *PFN_WINVERIFYTRUST)(
    HWND hwnd,
    GUID *pgActionID,
    LPVOID pWVTData);

typedef CRYPT_PROVIDER_DATA *(WINAPI *PFN_WTHELPPERPROVDATAFROMSTATEDATA)(
    HANDLE hStateData);

typedef CRYPT_PROVIDER_SGNR *(WINAPI *PFN_WTHELPPERGETPROVSIGNERFROMCHAIN)(
    CRYPT_PROVIDER_DATA *pProvData,
    DWORD idxSigner,
    BOOL fCounterSigner,
    DWORD idxCounterSigner);

typedef BOOL (WINAPI *PFN_CRYPTCATADMINACQUIRECONTEXT)(
    HCATADMIN *phCatAdmin,
    const GUID *pgSubsystem,
    DWORD dwFlags);

typedef HCATINFO (WINAPI *PFN_CRYPTCATADMINENUMCATALOGFROMHASH)(
    HCATADMIN hCatAdmin,
    BYTE *pbHash,
    DWORD cbHash,
    DWORD dwFlags,
    HCATINFO *phPrevCatInfo);

typedef BOOL (WINAPI *PFN_CRYPTCATADMINCALCHASHFROMFILEHANDLE)(
    HANDLE hFile,
    DWORD *pcbHash,
    BYTE *pbHash,
    DWORD dwFlags);

typedef BOOL (WINAPI *PFN_CRYPTCATCATALOGINFOFROMCONTEXT)(
    HCATINFO hCatInfo,
    CATALOG_INFO *psCatInfo,
    DWORD dwFlags);

typedef BOOL (WINAPI *PFN_CRYPTCATADMINRELEASECATALOGCONTEXT)(
    HCATADMIN hCatAdmin,
    HCATINFO hCatInfo,
    DWORD dwFlags);

typedef BOOL (WINAPI *PFN_CRYPTCATADMINRELEASECONTEXT)(
    HCATADMIN hCatAdmin,
    DWORD dwFlags);

typedef DWORD (WINAPI *PFN_CERTGETNAMESTRINGW)(
    PCCERT_CONTEXT pCertContext,
    DWORD dwType,
    DWORD dwFlags,
    void *pvTypePara,
    LPWSTR pszNameString,
    DWORD cchNameString);

typedef DWORD (WINAPI *PFN_CERTNAMETOSTRW)(
    DWORD dwCertEncodingType,
    PCERT_NAME_BLOB pName,
    DWORD dwStrType,
    LPWSTR psz,
    DWORD csz);

typedef struct _SYSMON_SIGNATURE_APIS {
    BOOL Initialized;
    BOOL Available;
    HMODULE WintrustModule;
    HMODULE Crypt32Module;
    PFN_WINVERIFYTRUST WinVerifyTrust;
    PFN_WTHELPPERPROVDATAFROMSTATEDATA WTHelperProvDataFromStateData;
    PFN_WTHELPPERGETPROVSIGNERFROMCHAIN WTHelperGetProvSignerFromChain;
    PFN_CRYPTCATADMINACQUIRECONTEXT CryptCATAdminAcquireContext;
    PFN_CRYPTCATADMINENUMCATALOGFROMHASH CryptCATAdminEnumCatalogFromHash;
    PFN_CRYPTCATADMINCALCHASHFROMFILEHANDLE CryptCATAdminCalcHashFromFileHandle;
    PFN_CRYPTCATCATALOGINFOFROMCONTEXT CryptCATCatalogInfoFromContext;
    PFN_CRYPTCATADMINRELEASECATALOGCONTEXT CryptCATAdminReleaseCatalogContext;
    PFN_CRYPTCATADMINRELEASECONTEXT CryptCATAdminReleaseContext;
    PFN_CERTGETNAMESTRINGW CertGetNameStringW;
    PFN_CERTNAMETOSTRW CertNameToStrW;
} SYSMON_SIGNATURE_APIS, *PSYSMON_SIGNATURE_APIS;

typedef struct _SYSMON_SIGNATURE_RESULT {
    BOOLEAN Signed;
    WCHAR Signature[SYSMON_MAX_SIGNER_NAME_CHARS];
    WCHAR SignatureStatus[SYSMON_MAX_SIGNATURE_STATUS_CHARS];
    WCHAR ResolvedPath[SYSMON_MAX_SIGNATURE_PATH_CHARS];
} SYSMON_SIGNATURE_RESULT, *PSYSMON_SIGNATURE_RESULT;

typedef struct _SYSMON_SIGNATURE_CACHE_ENTRY {
    BOOL InUse;
    BOOL CheckRevocation;
    DWORD ActionKind;
    DWORD PathHash;
    DWORD PathLength;
    LONG NextInBucket;
    WCHAR Path[SYSMON_MAX_SIGNATURE_PATH_CHARS];
    SYSMON_SIGNATURE_RESULT Result;
} SYSMON_SIGNATURE_CACHE_ENTRY, *PSYSMON_SIGNATURE_CACHE_ENTRY;

typedef struct _SYSMON_IMAGE_ENRICHMENT_CACHE_ENTRY {
    BOOL InUse;
    BOOL CheckRevocation;
    DWORD ActionKind;
    DWORD HashMask;
    DWORD PathHash;
    DWORD PathLength;
    LONG NextInBucket;
    WCHAR Path[SYSMON_MAX_SIGNATURE_PATH_CHARS];
    SYSMON_SIGNATURE_RESULT SignatureResult;
    WCHAR Hashes[512];
} SYSMON_IMAGE_ENRICHMENT_CACHE_ENTRY, *PSYSMON_IMAGE_ENRICHMENT_CACHE_ENTRY;

typedef struct _SYSMON_PENDING_ENRICHMENT_EVENT {
    LIST_ENTRY ListEntry;
    BYTE *EventData;
    DWORD EventSize;
    SYSMON_EVENT_ID EventId;
} SYSMON_PENDING_ENRICHMENT_EVENT, *PSYSMON_PENDING_ENRICHMENT_EVENT;

typedef struct _SYSMON_ENRICHMENT_WORK_ITEM {
    LIST_ENTRY ListEntry;
    LIST_ENTRY PendingEvents;
    DWORD PendingEventCount;
    BOOL CheckRevocation;
    DWORD HashMask;
    WCHAR RawPath[SYSMON_MAX_SIGNATURE_PATH_CHARS];
    WCHAR KeyPath[SYSMON_MAX_SIGNATURE_PATH_CHARS];
} SYSMON_ENRICHMENT_WORK_ITEM, *PSYSMON_ENRICHMENT_WORK_ITEM;

static SYSMON_SIGNATURE_APIS g_SignatureApis = { 0 };
static INIT_ONCE g_SignatureApisInitOnce = INIT_ONCE_STATIC_INIT;
static SYSMON_SIGNATURE_CACHE_ENTRY g_SignatureCache[SYSMON_SIGNATURE_CACHE_CAPACITY];
static DWORD g_SignatureCacheVictim = 0;
static LONG g_SignatureCacheBuckets[SYSMON_SIGNATURE_CACHE_BUCKET_COUNT];
static CRITICAL_SECTION g_SignatureCacheLock;
static SYSMON_IMAGE_ENRICHMENT_CACHE_ENTRY g_ImageEnrichmentCache[SYSMON_IMAGE_ENRICHMENT_CACHE_CAPACITY];
static DWORD g_ImageEnrichmentCacheVictim = 0;
static LONG g_ImageEnrichmentCacheBuckets[SYSMON_IMAGE_ENRICHMENT_CACHE_BUCKET_COUNT];
static CRITICAL_SECTION g_ImageEnrichmentCacheLock;
static CRITICAL_SECTION g_SigningQueueLock;
static HANDLE g_SigningQueueEvent = NULL;
static HANDLE g_SigningWorkerThreads[SYSMON_MAX_SIGNING_WORKERS];
static DWORD g_SigningWorkerThreadCount = 0;
static LIST_ENTRY g_SigningQueueList;
static LIST_ENTRY g_SigningActiveList;
static volatile LONG g_SigningQueueDepth = 0;
static volatile LONG g_SigningPendingEventDepth = 0;
static volatile LONG g_SigningWorkerRunning = 0;
static volatile LONG g_SigningPipelineInitialized = 0;

static VOID
SysmonInitializeListHead(
    _Out_ PLIST_ENTRY ListHead)
{
    ListHead->Flink = ListHead;
    ListHead->Blink = ListHead;
}

static BOOL
SysmonIsListEmpty(
    _In_ const LIST_ENTRY *ListHead)
{
    return ListHead->Flink == ListHead;
}

static VOID
SysmonInsertTailList(
    _Inout_ PLIST_ENTRY ListHead,
    _Inout_ PLIST_ENTRY Entry)
{
    PLIST_ENTRY blink;

    blink = ListHead->Blink;
    Entry->Flink = ListHead;
    Entry->Blink = blink;
    blink->Flink = Entry;
    ListHead->Blink = Entry;
}

static PLIST_ENTRY
SysmonRemoveHeadList(
    _Inout_ PLIST_ENTRY ListHead)
{
    PLIST_ENTRY entry;
    PLIST_ENTRY next;

    entry = ListHead->Flink;
    next = entry->Flink;
    ListHead->Flink = next;
    next->Blink = ListHead;
    entry->Flink = entry;
    entry->Blink = entry;
    return entry;
}

static VOID
SysmonRemoveEntryList(
    _Inout_ PLIST_ENTRY Entry)
{
    PLIST_ENTRY blink;
    PLIST_ENTRY flink;

    blink = Entry->Blink;
    flink = Entry->Flink;
    blink->Flink = flink;
    flink->Blink = blink;
    Entry->Flink = Entry;
    Entry->Blink = Entry;
}

static DWORD
SysmonComputeCachePathHash(
    _In_z_ PCWSTR FilePath,
    _Out_opt_ DWORD *PathLength)
{
    return SysmonComputeInsensitiveWideHash(FilePath, PathLength);
}

static BOOL
SysmonCachedPathMatches(
    _In_ DWORD CachedPathHash,
    _In_ DWORD CachedPathLength,
    _In_z_ PCWSTR CachedPath,
    _In_ DWORD PathHash,
    _In_ DWORD PathLength,
    _In_z_ PCWSTR FilePath)
{
    return SysmonInsensitiveWideTextMatches(
        CachedPathHash,
        CachedPathLength,
        CachedPath,
        PathHash,
        PathLength,
        FilePath);
}

static DWORD
SysmonSelectSignatureCacheBucket(
    _In_ DWORD PathHash)
{
    return PathHash % SYSMON_SIGNATURE_CACHE_BUCKET_COUNT;
}

static DWORD
SysmonSelectImageEnrichmentCacheBucket(
    _In_ DWORD PathHash)
{
    return PathHash % SYSMON_IMAGE_ENRICHMENT_CACHE_BUCKET_COUNT;
}

static VOID
SysmonUnlinkSignatureCacheSlot(
    _In_ DWORD Slot)
{
    DWORD bucket;
    LONG current;
    LONG previous;

    if (Slot >= SYSMON_SIGNATURE_CACHE_CAPACITY ||
        !g_SignatureCache[Slot].InUse) {
        return;
    }

    bucket = SysmonSelectSignatureCacheBucket(g_SignatureCache[Slot].PathHash);
    current = g_SignatureCacheBuckets[bucket];
    previous = -1;
    while (current >= 0) {
        if ((DWORD)current == Slot) {
            if (previous < 0) {
                g_SignatureCacheBuckets[bucket] = g_SignatureCache[Slot].NextInBucket;
            } else {
                g_SignatureCache[previous].NextInBucket = g_SignatureCache[Slot].NextInBucket;
            }
            break;
        }

        previous = current;
        current = g_SignatureCache[current].NextInBucket;
    }

    g_SignatureCache[Slot].NextInBucket = -1;
}

static VOID
SysmonLinkSignatureCacheSlot(
    _In_ DWORD Slot)
{
    DWORD bucket;

    if (Slot >= SYSMON_SIGNATURE_CACHE_CAPACITY ||
        !g_SignatureCache[Slot].InUse) {
        return;
    }

    bucket = SysmonSelectSignatureCacheBucket(g_SignatureCache[Slot].PathHash);
    g_SignatureCache[Slot].NextInBucket = g_SignatureCacheBuckets[bucket];
    g_SignatureCacheBuckets[bucket] = (LONG)Slot;
}

static VOID
SysmonUnlinkImageEnrichmentCacheSlot(
    _In_ DWORD Slot)
{
    DWORD bucket;
    LONG current;
    LONG previous;

    if (Slot >= SYSMON_IMAGE_ENRICHMENT_CACHE_CAPACITY ||
        !g_ImageEnrichmentCache[Slot].InUse) {
        return;
    }

    bucket = SysmonSelectImageEnrichmentCacheBucket(g_ImageEnrichmentCache[Slot].PathHash);
    current = g_ImageEnrichmentCacheBuckets[bucket];
    previous = -1;
    while (current >= 0) {
        if ((DWORD)current == Slot) {
            if (previous < 0) {
                g_ImageEnrichmentCacheBuckets[bucket] = g_ImageEnrichmentCache[Slot].NextInBucket;
            } else {
                g_ImageEnrichmentCache[previous].NextInBucket = g_ImageEnrichmentCache[Slot].NextInBucket;
            }
            break;
        }

        previous = current;
        current = g_ImageEnrichmentCache[current].NextInBucket;
    }

    g_ImageEnrichmentCache[Slot].NextInBucket = -1;
}

static VOID
SysmonLinkImageEnrichmentCacheSlot(
    _In_ DWORD Slot)
{
    DWORD bucket;

    if (Slot >= SYSMON_IMAGE_ENRICHMENT_CACHE_CAPACITY ||
        !g_ImageEnrichmentCache[Slot].InUse) {
        return;
    }

    bucket = SysmonSelectImageEnrichmentCacheBucket(g_ImageEnrichmentCache[Slot].PathHash);
    g_ImageEnrichmentCache[Slot].NextInBucket = g_ImageEnrichmentCacheBuckets[bucket];
    g_ImageEnrichmentCacheBuckets[bucket] = (LONG)Slot;
}

/*
 * Default event handler - just forwards to output.
 */
static void DefaultEventHandler(
    PUCHAR EventData,
    DWORD EventSize,
    SYSMON_EVENT_ID EventId)
{
    SysmonOutputEvent(EventData, EventSize, EventId);
}

static DWORD WINAPI SysmonSigningWorkerThreadMain(_In_opt_ LPVOID Parameter);

static DWORD
SysmonGetSignatureActionKind(
    _In_ const GUID *ActionGuid)
{
    if (ActionGuid == &g_DriverVerifyAction) {
        return 1;
    }
    if (ActionGuid == &g_ConfigCiVerifyAction) {
        return 2;
    }

    return 0;
}

static const GUID *
SysmonGetSignatureVerifyActionForEvent(
    _In_ SYSMON_EVENT_ID EventId)
{
    if (EventId == SysmonEventDriverLoad) {
        return &g_DriverVerifyAction;
    }

    return &g_GenericVerifyV2Action;
}

static DWORD
SysmonDetermineSigningWorkerCount(VOID)
{
    SYSTEM_INFO systemInfo;
    DWORD workerCount;

    GetSystemInfo(&systemInfo);
    workerCount = systemInfo.dwNumberOfProcessors;
    if (workerCount == 0) {
        workerCount = 1;
    }

    /*
     * Signature verification is still the heaviest remaining user-mode ImageLoad
     * step. Keep small VMs on a single background worker so task-manager CPU
     * does not jump from one saturated core to two, and only allow limited
     * parallelism on larger machines.
     */
    if (workerCount < 8) {
        workerCount = 1;
    } else if (workerCount > SYSMON_DEFAULT_SIGNING_WORKERS) {
        workerCount = SYSMON_DEFAULT_SIGNING_WORKERS;
    }
    if (workerCount > SYSMON_MAX_SIGNING_WORKERS) {
        workerCount = SYSMON_MAX_SIGNING_WORKERS;
    }
    if (workerCount == 0) {
        workerCount = 1;
    }

    return workerCount;
}

static VOID
SysmonFreePendingEnrichmentEvent(
    _Inout_opt_ PSYSMON_PENDING_ENRICHMENT_EVENT PendingEvent)
{
    if (PendingEvent == NULL) {
        return;
    }

    SYSMON_FREE(PendingEvent->EventData);
    SYSMON_FREE(PendingEvent);
}

static DWORD
SysmonGetConfiguredHashMask(VOID)
{
    DWORD hashMask;

    {
        CriticalSectionGuard configLock(&g_ServiceCtx.ConfigLock);

        hashMask = g_ServiceCtx.Config.HashingAlgorithm;
    }

    /* HashingAlgorithm == 0 means "no hashing" (None). Keep it 0 so ImageLoad
       enrichment is consistent with ProcessCreate / output enrichment, instead
       of silently defaulting to MD5|SHA1 here. See U5 in the 2026-08-04 review. */
    return hashMask;
}

static DWORD
SysmonGetConfiguredSigningQueueSize(VOID)
{
    DWORD queueSize;

    {
        CriticalSectionGuard configLock(&g_ServiceCtx.ConfigLock);

        queueSize = g_ServiceCtx.Config.SigningQueueSize;
    }

    if (queueSize == 0) {
        queueSize = 1000;
    }

    return queueSize;
}

static BYTE *
SysmonGetEnrichedEventBuffer(
    _Inout_ BYTE **EnrichedEvent)
{
    if (EnrichedEvent == NULL) {
        return NULL;
    }

    if (*EnrichedEvent == NULL) {
        *EnrichedEvent = (BYTE *)SYSMON_ALLOC(SYSMON_ENRICHED_EVENT_BUFFER_SIZE);
    }

    return *EnrichedEvent;
}

static DWORD
SysmonGetConfiguredSigningWorkerCount(VOID)
{
    DWORD workerCount;

    {
        CriticalSectionGuard configLock(&g_ServiceCtx.ConfigLock);

        workerCount = g_ServiceCtx.Config.SigningWorkerCount;
    }

    if (workerCount == 0) {
        return SysmonDetermineSigningWorkerCount();
    }

    if (workerCount > SYSMON_MAX_SIGNING_WORKERS) {
        workerCount = SYSMON_MAX_SIGNING_WORKERS;
    }

    return (workerCount < 1) ? 1 : workerCount;
}

static BOOL
SysmonExtractImageSignatureInputs(
    _In_reads_bytes_(EventSize) const BYTE *EventData,
    _In_ DWORD EventSize,
    _In_ SYSMON_EVENT_ID EventId,
    _Out_writes_(ImageLoadedChars) PWCHAR ImageLoaded,
    _In_ size_t ImageLoadedChars,
    _Out_writes_opt_(ExistingHashesChars) PWCHAR ExistingHashes,
    _In_ size_t ExistingHashesChars)
{
    const BYTE *payloadBase;

    if (EventData == NULL || ImageLoaded == NULL || ImageLoadedChars == 0) {
        return FALSE;
    }

    ImageLoaded[0] = L'\0';
    if (ExistingHashes != NULL && ExistingHashesChars != 0) {
        ExistingHashes[0] = L'\0';
    }

    payloadBase = EventData + SYSMON_EVENT_HEADER_SIZE;
    if (EventId == SysmonEventDriverLoad) {
        const SYSMON_EVENT_DRIVER_LOAD_PAYLOAD *payload;

        if (EventSize < SYSMON_EVENT_CONTRACT_SIZE(SYSMON_EVENT_DRIVER_LOAD_PAYLOAD)) {
            return FALSE;
        }

        payload = (const SYSMON_EVENT_DRIVER_LOAD_PAYLOAD *)payloadBase;
        (void)SysmonCopyStringField(
            EventData,
            EventSize,
            payload->ImageLoaded,
            ImageLoaded,
            ImageLoadedChars);
        if (ExistingHashes != NULL && ExistingHashesChars != 0) {
            (void)SysmonCopyStringField(
                EventData,
                EventSize,
                payload->Hashes,
                ExistingHashes,
                ExistingHashesChars);
        }
        return TRUE;
    }

    if (EventId == SysmonEventImageLoad) {
        const SYSMON_EVENT_IMAGE_LOAD_PAYLOAD *payload;

        if (EventSize < SYSMON_EVENT_CONTRACT_SIZE(SYSMON_EVENT_IMAGE_LOAD_PAYLOAD)) {
            return FALSE;
        }

        payload = (const SYSMON_EVENT_IMAGE_LOAD_PAYLOAD *)payloadBase;
        (void)SysmonCopyStringField(
            EventData,
            EventSize,
            payload->ImageLoaded,
            ImageLoaded,
            ImageLoadedChars);
        if (ExistingHashes != NULL && ExistingHashesChars != 0) {
            (void)SysmonCopyStringField(
                EventData,
                EventSize,
                payload->Hashes,
                ExistingHashes,
                ExistingHashesChars);
        }
        return TRUE;
    }

    return FALSE;
}

static BOOL
SysmonIsSelfImageLoadEvent(
    _In_reads_bytes_(EventSize) const BYTE *EventData,
    _In_ DWORD EventSize)
{
    const BYTE *payloadBase;
    const SYSMON_EVENT_IMAGE_LOAD_PAYLOAD *payload;

    if (EventData == NULL ||
        EventSize < SYSMON_EVENT_CONTRACT_SIZE(SYSMON_EVENT_IMAGE_LOAD_PAYLOAD)) {
        return FALSE;
    }

    payloadBase = EventData + SYSMON_EVENT_HEADER_SIZE;
    payload = (const SYSMON_EVENT_IMAGE_LOAD_PAYLOAD *)payloadBase;
    return SysmonReadPackedValue<DWORD>(&payload->ProcessId) == GetCurrentProcessId();
}

static BOOL
SysmonInitializeSignatureApis(
    PINIT_ONCE InitOnce,
    PVOID Parameter,
    PVOID *Context)
{
    UNREFERENCED_PARAMETER(InitOnce);
    UNREFERENCED_PARAMETER(Parameter);
    UNREFERENCED_PARAMETER(Context);

    ZeroMemory(&g_SignatureApis, sizeof(g_SignatureApis));
    g_SignatureApis.Initialized = TRUE;

    g_SignatureApis.WintrustModule = LoadLibraryW(L"wintrust.dll");
    g_SignatureApis.Crypt32Module = LoadLibraryW(L"crypt32.dll");
    if (g_SignatureApis.WintrustModule == NULL || g_SignatureApis.Crypt32Module == NULL) {
        return FALSE;
    }

    g_SignatureApis.WinVerifyTrust = (PFN_WINVERIFYTRUST)GetProcAddress(
        g_SignatureApis.WintrustModule,
        "WinVerifyTrust");
    g_SignatureApis.WTHelperProvDataFromStateData = (PFN_WTHELPPERPROVDATAFROMSTATEDATA)GetProcAddress(
        g_SignatureApis.WintrustModule,
        "WTHelperProvDataFromStateData");
    g_SignatureApis.WTHelperGetProvSignerFromChain = (PFN_WTHELPPERGETPROVSIGNERFROMCHAIN)GetProcAddress(
        g_SignatureApis.WintrustModule,
        "WTHelperGetProvSignerFromChain");
    g_SignatureApis.CryptCATAdminAcquireContext = (PFN_CRYPTCATADMINACQUIRECONTEXT)GetProcAddress(
        g_SignatureApis.WintrustModule,
        "CryptCATAdminAcquireContext");
    g_SignatureApis.CryptCATAdminEnumCatalogFromHash = (PFN_CRYPTCATADMINENUMCATALOGFROMHASH)GetProcAddress(
        g_SignatureApis.WintrustModule,
        "CryptCATAdminEnumCatalogFromHash");
    g_SignatureApis.CryptCATAdminCalcHashFromFileHandle = (PFN_CRYPTCATADMINCALCHASHFROMFILEHANDLE)GetProcAddress(
        g_SignatureApis.WintrustModule,
        "CryptCATAdminCalcHashFromFileHandle");
    g_SignatureApis.CryptCATCatalogInfoFromContext = (PFN_CRYPTCATCATALOGINFOFROMCONTEXT)GetProcAddress(
        g_SignatureApis.WintrustModule,
        "CryptCATCatalogInfoFromContext");
    g_SignatureApis.CryptCATAdminReleaseCatalogContext = (PFN_CRYPTCATADMINRELEASECATALOGCONTEXT)GetProcAddress(
        g_SignatureApis.WintrustModule,
        "CryptCATAdminReleaseCatalogContext");
    g_SignatureApis.CryptCATAdminReleaseContext = (PFN_CRYPTCATADMINRELEASECONTEXT)GetProcAddress(
        g_SignatureApis.WintrustModule,
        "CryptCATAdminReleaseContext");
    g_SignatureApis.CertGetNameStringW = (PFN_CERTGETNAMESTRINGW)GetProcAddress(
        g_SignatureApis.Crypt32Module,
        "CertGetNameStringW");
    g_SignatureApis.CertNameToStrW = (PFN_CERTNAMETOSTRW)GetProcAddress(
        g_SignatureApis.Crypt32Module,
        "CertNameToStrW");

    g_SignatureApis.Available =
        g_SignatureApis.WinVerifyTrust != NULL &&
        g_SignatureApis.WTHelperProvDataFromStateData != NULL &&
        g_SignatureApis.WTHelperGetProvSignerFromChain != NULL &&
        g_SignatureApis.CryptCATAdminAcquireContext != NULL &&
        g_SignatureApis.CryptCATAdminEnumCatalogFromHash != NULL &&
        g_SignatureApis.CryptCATAdminCalcHashFromFileHandle != NULL &&
        g_SignatureApis.CryptCATCatalogInfoFromContext != NULL &&
        g_SignatureApis.CryptCATAdminReleaseCatalogContext != NULL &&
        g_SignatureApis.CryptCATAdminReleaseContext != NULL &&
        g_SignatureApis.CertGetNameStringW != NULL;

    return TRUE;
}

static BOOL
SysmonInitSignatureApis(VOID)
{
    if (!InitOnceExecuteOnce(
            &g_SignatureApisInitOnce,
            SysmonInitializeSignatureApis,
            NULL,
            NULL)) {
        return FALSE;
    }

    return g_SignatureApis.Available;
}

static BOOL
SysmonExtractSignerLabel(
    _Inout_updates_(BufferChars) PWCHAR SubjectName,
    _In_ size_t BufferChars,
    _Out_writes_(OutputChars) PWCHAR Output,
    _In_ size_t OutputChars)
{
    PWCHAR candidate;
    PWCHAR nextOu;
    PWCHAR end;

    if (SubjectName == NULL || Output == NULL || OutputChars == 0) {
        return FALSE;
    }

    Output[0] = L'\0';
    candidate = wcsstr(SubjectName, L"CN=");
    if (candidate != NULL) {
        candidate += 3;
    } else {
        candidate = wcsstr(SubjectName, L"OU=");
        if (candidate != NULL) {
            nextOu = wcsstr(candidate + 3, L"OU=");
            while (nextOu != NULL) {
                candidate = nextOu;
                nextOu = wcsstr(candidate + 3, L"OU=");
            }
            candidate += 3;
        } else {
            candidate = SubjectName;
        }
    }

    while (*candidate == L' ' || *candidate == L'\t') {
        candidate++;
    }

    if (*candidate == L'"') {
        candidate += 1;
        end = wcschr(candidate, L'"');
    } else {
        end = candidate;
        while (*end != L'\0' && *end != L',' && *end != L';') {
            end++;
        }
    }

    if (end == NULL) {
        end = candidate + wcslen(candidate);
    }

    while (end > candidate &&
           (end[-1] == L' ' || end[-1] == L'\t')) {
        end--;
    }

    if (end <= candidate) {
        return FALSE;
    }

    *end = L'\0';
    if (SysmonIsPlaceholderString(candidate)) {
        return FALSE;
    }

    return SysmonCopyWideText(Output, OutputChars, candidate);
}

static BOOL
SysmonExtractSignerNameFromCert(
    _In_ PCCERT_CONTEXT CertContext,
    _Out_writes_(BufferChars) PWCHAR Buffer,
    _In_ size_t BufferChars)
{
    WCHAR subjectName[1024];

    if (CertContext == NULL || Buffer == NULL || BufferChars == 0) {
        return FALSE;
    }

    subjectName[0] = L'\0';
    if (g_SignatureApis.CertGetNameStringW(
            CertContext,
            CERT_NAME_FRIENDLY_DISPLAY_TYPE,
            0,
            NULL,
            subjectName,
            RTL_NUMBER_OF(subjectName)) > 1 &&
        SysmonExtractSignerLabel(
            subjectName,
            RTL_NUMBER_OF(subjectName),
            Buffer,
            BufferChars)) {
        return TRUE;
    }

    subjectName[0] = L'\0';
    if (g_SignatureApis.CertNameToStrW != NULL &&
        CertContext->pCertInfo != NULL &&
        g_SignatureApis.CertNameToStrW(
            X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
            &CertContext->pCertInfo->Subject,
            CERT_X500_NAME_STR | CERT_NAME_STR_COMMA_FLAG,
            subjectName,
            RTL_NUMBER_OF(subjectName)) > 1 &&
        SysmonExtractSignerLabel(
            subjectName,
            RTL_NUMBER_OF(subjectName),
            Buffer,
            BufferChars)) {
        return TRUE;
    }

    subjectName[0] = L'\0';
    if (g_SignatureApis.CertGetNameStringW(
            CertContext,
            CERT_NAME_SIMPLE_DISPLAY_TYPE,
            0,
            NULL,
            subjectName,
            RTL_NUMBER_OF(subjectName)) > 1 &&
        !SysmonIsPlaceholderString(subjectName) &&
        SysmonCopyWideText(Buffer, BufferChars, subjectName)) {
        return TRUE;
    }

    return FALSE;
}

static BOOL
SysmonExtractSignerName(
    _In_opt_ HANDLE StateData,
    _Out_writes_(BufferChars) PWCHAR Buffer,
    _In_ size_t BufferChars)
{
    CRYPT_PROVIDER_DATA *providerData;
    CRYPT_PROVIDER_SGNR *providerSigner;
    DWORD chainIndex;

    if (Buffer == NULL || BufferChars == 0) {
        return FALSE;
    }

    Buffer[0] = L'\0';
    if (!SysmonInitSignatureApis() || StateData == NULL) {
        return FALSE;
    }

    providerData = g_SignatureApis.WTHelperProvDataFromStateData(StateData);
    if (providerData == NULL) {
        return FALSE;
    }

    providerSigner = g_SignatureApis.WTHelperGetProvSignerFromChain(providerData, 0, FALSE, 0);
    if (providerSigner == NULL ||
        providerSigner->csCertChain == 0 ||
        providerSigner->pasCertChain == NULL) {
        return FALSE;
    }

    for (chainIndex = 0; chainIndex < providerSigner->csCertChain; chainIndex++) {
        PCCERT_CONTEXT certContext;

        certContext = providerSigner->pasCertChain[chainIndex].pCert;
        if (certContext == NULL) {
            continue;
        }

        if (SysmonExtractSignerNameFromCert(
                certContext,
                Buffer,
                BufferChars)) {
            return TRUE;
        }
    }

    return FALSE;
}

static VOID
SysmonCloseTrustState(
    _In_ const GUID *ActionGuid,
    _Inout_ PWINTRUST_DATA TrustData)
{
    if (!SysmonInitSignatureApis() ||
        ActionGuid == NULL ||
        TrustData == NULL ||
        TrustData->hWVTStateData == NULL) {
        return;
    }

    TrustData->dwStateAction = WTD_STATEACTION_CLOSE;
    (void)g_SignatureApis.WinVerifyTrust(
        NULL,
        (GUID *)ActionGuid,
        TrustData);
    TrustData->hWVTStateData = NULL;
}

static VOID
SysmonMapSignatureStatus(
    _In_ LONG VerifyStatus,
    _In_ BOOL Signed,
    _Out_ PSYSMON_SIGNATURE_RESULT Result)
{
    PCWSTR statusText;

    if (Result == NULL) {
        return;
    }

    Result->Signed = Signed ? TRUE : FALSE;
    if (Signed) {
        statusText = L"Valid";
    } else if (VerifyStatus == CERT_E_EXPIRED) {
        statusText = L"Expired";
    } else if (VerifyStatus == CERT_E_REVOKED) {
        statusText = L"Revoked";
    } else {
        statusText = L"Unavailable";
    }

    (void)SysmonCopyWideText(
        Result->SignatureStatus,
        RTL_NUMBER_OF(Result->SignatureStatus),
        statusText);
}

static BOOL
SysmonFileHasEmbeddedSignatureHint(
    _In_z_ PCWSTR FilePath)
{
    HANDLE fileHandle;
    BYTE header[4096];
    DWORD bytesRead;
    ULONG peOffset;
    USHORT optHdrMagic;
    ULONG securityDirOffset;
    ULONG securityDirAddress;
    ULONG securityDirSize;

    if (FilePath == NULL || FilePath[0] == L'\0') {
        return TRUE;
    }

    fileHandle = CreateFileW(
        FilePath,
        GENERIC_READ,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        NULL,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL | FILE_FLAG_SEQUENTIAL_SCAN,
        NULL);
    if (fileHandle == INVALID_HANDLE_VALUE) {
        return TRUE;
    }

    bytesRead = 0;
    ZeroMemory(header, sizeof(header));
    if (!ReadFile(fileHandle, header, sizeof(header), &bytesRead, NULL) ||
        bytesRead < 0x100) {
        CloseHandle(fileHandle);
        return TRUE;
    }
    CloseHandle(fileHandle);

    if (header[0] != 'M' || header[1] != 'Z') {
        return TRUE;
    }

    peOffset = *(const ULONG *)(header + 0x3C);
    if (peOffset > (bytesRead - 0x18) ||
        peOffset + 0x18 > bytesRead ||
        peOffset + 4 > bytesRead ||
        memcmp(header + peOffset, "PE\0\0", 4) != 0) {
        return TRUE;
    }

    optHdrMagic = *(const USHORT *)(header + peOffset + 0x18);
    if (optHdrMagic == 0x20b) {
        securityDirOffset = peOffset + 0xA0;
    } else if (optHdrMagic == 0x10b) {
        securityDirOffset = peOffset + 0x90;
    } else {
        return TRUE;
    }

    if (securityDirOffset > (bytesRead - 8)) {
        return TRUE;
    }

    securityDirAddress = *(const ULONG *)(header + securityDirOffset);
    securityDirSize = *(const ULONG *)(header + securityDirOffset + 4);
    return securityDirAddress != 0 && securityDirSize != 0;
}

static LONG
SysmonVerifyEmbeddedSignature(
    _In_z_ PCWSTR FilePath,
    _In_ const GUID *ActionGuid,
    _In_ BOOL CheckRevocation,
    _Out_ PSYSMON_SIGNATURE_RESULT Result)
{
    WINTRUST_FILE_INFO fileInfo;
    WINTRUST_DATA trustData;
    LONG status;

    if (Result == NULL || ActionGuid == NULL || !SysmonInitSignatureApis()) {
        return TRUST_E_PROVIDER_UNKNOWN;
    }

    ZeroMemory(&fileInfo, sizeof(fileInfo));
    ZeroMemory(&trustData, sizeof(trustData));

    fileInfo.cbStruct = sizeof(fileInfo);
    fileInfo.pcwszFilePath = FilePath;

    trustData.cbStruct = sizeof(trustData);
    trustData.dwUIChoice = WTD_UI_NONE;
    trustData.fdwRevocationChecks = CheckRevocation ? WTD_REVOKE_WHOLECHAIN : WTD_REVOKE_NONE;
    trustData.dwUnionChoice = WTD_CHOICE_FILE;
    trustData.pFile = &fileInfo;
    trustData.dwStateAction = WTD_STATEACTION_VERIFY;
    trustData.dwProvFlags = CheckRevocation ? 0 : WTD_CACHE_ONLY_URL_RETRIEVAL;

    status = g_SignatureApis.WinVerifyTrust(
        NULL,
        (GUID *)ActionGuid,
        &trustData);

    (void)SysmonExtractSignerName(
        trustData.hWVTStateData,
        Result->Signature,
        RTL_NUMBER_OF(Result->Signature));
    SysmonCloseTrustState(ActionGuid, &trustData);
    return status;
}

static LONG
SysmonVerifyCatalogSignature(
    _In_z_ PCWSTR FilePath,
    _In_ const GUID *ActionGuid,
    _In_ BOOL CheckRevocation,
    _Out_ PSYSMON_SIGNATURE_RESULT Result)
{
    HANDLE fileHandle;
    HCATADMIN catAdmin;
    HCATINFO catInfo;
    CATALOG_INFO catalogInfo;
    WINTRUST_CATALOG_INFO trustCatalogInfo;
    WINTRUST_DATA trustData;
    BYTE *hashBuffer;
    DWORD hashBytes;
    WCHAR *memberTag;
    LONG status;
    DWORD index;

    if (Result == NULL || ActionGuid == NULL || !SysmonInitSignatureApis()) {
        return TRUST_E_PROVIDER_UNKNOWN;
    }

    fileHandle = CreateFileW(
        FilePath,
        GENERIC_READ,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        NULL,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        NULL);
    if (fileHandle == INVALID_HANDLE_VALUE) {
        return HRESULT_FROM_WIN32(GetLastError());
    }

    catAdmin = NULL;
    catInfo = NULL;
    hashBuffer = NULL;
    memberTag = NULL;
    status = TRUST_E_NOSIGNATURE;
    hashBytes = 0;

    if (!g_SignatureApis.CryptCATAdminAcquireContext(&catAdmin, NULL, 0)) {
        status = HRESULT_FROM_WIN32(GetLastError());
        goto cleanup;
    }

    if (!g_SignatureApis.CryptCATAdminCalcHashFromFileHandle(fileHandle, &hashBytes, NULL, 0) ||
        hashBytes == 0) {
        status = HRESULT_FROM_WIN32(GetLastError());
        goto cleanup;
    }

    hashBuffer = (BYTE *)SYSMON_ALLOC(hashBytes);
    memberTag = (WCHAR *)SYSMON_ALLOC((hashBytes * 2 + 1) * sizeof(WCHAR));
    if (hashBuffer == NULL || memberTag == NULL) {
        status = ERROR_NOT_ENOUGH_MEMORY;
        goto cleanup;
    }

    if (!g_SignatureApis.CryptCATAdminCalcHashFromFileHandle(fileHandle, &hashBytes, hashBuffer, 0)) {
        status = HRESULT_FROM_WIN32(GetLastError());
        goto cleanup;
    }

    for (index = 0; index < hashBytes; index++) {
        (void)_snwprintf_s(
            memberTag + (index * 2),
            (hashBytes * 2 + 1) - (index * 2),
            _TRUNCATE,
            L"%02X",
            hashBuffer[index]);
    }

    catInfo = g_SignatureApis.CryptCATAdminEnumCatalogFromHash(
        catAdmin,
        hashBuffer,
        hashBytes,
        0,
        NULL);
    if (catInfo == NULL) {
        status = TRUST_E_NOSIGNATURE;
        goto cleanup;
    }

    ZeroMemory(&catalogInfo, sizeof(catalogInfo));
    catalogInfo.cbStruct = sizeof(catalogInfo);
    if (!g_SignatureApis.CryptCATCatalogInfoFromContext(catInfo, &catalogInfo, 0)) {
        status = HRESULT_FROM_WIN32(GetLastError());
        goto cleanup;
    }

    ZeroMemory(&trustCatalogInfo, sizeof(trustCatalogInfo));
    ZeroMemory(&trustData, sizeof(trustData));

    trustCatalogInfo.cbStruct = sizeof(trustCatalogInfo);
    trustCatalogInfo.pcwszCatalogFilePath = catalogInfo.wszCatalogFile;
    trustCatalogInfo.pcwszMemberTag = memberTag;
    trustCatalogInfo.pcwszMemberFilePath = FilePath;
    /*
     * Original Sysmon passes the precomputed member hash into the catalog
     * verification path instead of relying on the member file handle alone.
     * This is required for some catalog-signed inbox binaries to expose the
     * signer chain consistently.
     */
    trustCatalogInfo.pbCalculatedFileHash = hashBuffer;
    trustCatalogInfo.cbCalculatedFileHash = hashBytes;

    trustData.cbStruct = sizeof(trustData);
    trustData.dwUIChoice = WTD_UI_NONE;
    trustData.fdwRevocationChecks = CheckRevocation ? WTD_REVOKE_WHOLECHAIN : WTD_REVOKE_NONE;
    trustData.dwUnionChoice = WTD_CHOICE_CATALOG;
    trustData.dwStateAction = WTD_STATEACTION_VERIFY;
    trustData.pCatalog = &trustCatalogInfo;
    trustData.dwProvFlags = CheckRevocation ? 0 : WTD_CACHE_ONLY_URL_RETRIEVAL;

    status = g_SignatureApis.WinVerifyTrust(
        NULL,
        (GUID *)ActionGuid,
        &trustData);

    (void)SysmonExtractSignerName(
        trustData.hWVTStateData,
        Result->Signature,
        RTL_NUMBER_OF(Result->Signature));
    SysmonCloseTrustState(ActionGuid, &trustData);

cleanup:
    if (catInfo != NULL && catAdmin != NULL) {
        g_SignatureApis.CryptCATAdminReleaseCatalogContext(catAdmin, catInfo, 0);
    }
    if (catAdmin != NULL) {
        g_SignatureApis.CryptCATAdminReleaseContext(catAdmin, 0);
    }
    SYSMON_FREE(memberTag);
    SYSMON_FREE(hashBuffer);
    CloseHandle(fileHandle);
    return status;
}

static BOOL
SysmonShouldTryCatalogVerification(
    _In_ LONG Status)
{
    return Status == TRUST_E_NOSIGNATURE ||
        Status == TRUST_E_SUBJECT_FORM_UNKNOWN ||
        Status == TRUST_E_PROVIDER_UNKNOWN ||
        Status == TRUST_E_BAD_DIGEST;
}

static BOOL
SysmonLookupSignatureCache(
    _In_z_ PCWSTR FilePath,
    _In_ BOOL CheckRevocation,
    _In_ DWORD ActionKind,
    _Out_ PSYSMON_SIGNATURE_RESULT Result)
{
    DWORD bucket;
    DWORD pathHash;
    DWORD pathLength;
    LONG index;

    if (FilePath == NULL || Result == NULL || FilePath[0] == L'\0') {
        return FALSE;
    }

    pathHash = SysmonComputeCachePathHash(FilePath, &pathLength);
    CriticalSectionGuard cacheLock(&g_SignatureCacheLock);

    bucket = SysmonSelectSignatureCacheBucket(pathHash);
    for (index = g_SignatureCacheBuckets[bucket];
         index >= 0;
         index = g_SignatureCache[index].NextInBucket) {
        if (g_SignatureCache[index].CheckRevocation != CheckRevocation) {
            continue;
        }

        if (g_SignatureCache[index].ActionKind != ActionKind) {
            continue;
        }

        if (!SysmonCachedPathMatches(
                g_SignatureCache[index].PathHash,
                g_SignatureCache[index].PathLength,
                g_SignatureCache[index].Path,
                pathHash,
                pathLength,
                FilePath)) {
            continue;
        }

        *Result = g_SignatureCache[index].Result;
        return TRUE;
    }

    return FALSE;
}

static VOID
SysmonStoreSignatureCache(
    _In_z_ PCWSTR FilePath,
    _In_ BOOL CheckRevocation,
    _In_ DWORD ActionKind,
    _In_ const SYSMON_SIGNATURE_RESULT *Result)
{
    DWORD slot;
    DWORD bucket;
    DWORD pathHash;
    DWORD pathLength;
    LONG index;

    if (FilePath == NULL || Result == NULL || FilePath[0] == L'\0') {
        return;
    }

    pathHash = SysmonComputeCachePathHash(FilePath, &pathLength);
    CriticalSectionGuard cacheLock(&g_SignatureCacheLock);

    bucket = SysmonSelectSignatureCacheBucket(pathHash);
    for (index = g_SignatureCacheBuckets[bucket];
         index >= 0;
         index = g_SignatureCache[index].NextInBucket) {
        if (g_SignatureCache[index].CheckRevocation == CheckRevocation &&
            g_SignatureCache[index].ActionKind == ActionKind &&
            SysmonCachedPathMatches(
                g_SignatureCache[index].PathHash,
                g_SignatureCache[index].PathLength,
                g_SignatureCache[index].Path,
                pathHash,
                pathLength,
                FilePath)) {
            g_SignatureCache[index].Result = *Result;
            return;
        }
    }

    slot = g_SignatureCacheVictim++ % SYSMON_SIGNATURE_CACHE_CAPACITY;
    SysmonUnlinkSignatureCacheSlot(slot);
    ZeroMemory(&g_SignatureCache[slot], sizeof(g_SignatureCache[slot]));
    g_SignatureCache[slot].InUse = TRUE;
    g_SignatureCache[slot].CheckRevocation = CheckRevocation;
    g_SignatureCache[slot].ActionKind = ActionKind;
    g_SignatureCache[slot].PathHash = pathHash;
    g_SignatureCache[slot].PathLength = pathLength;
    g_SignatureCache[slot].NextInBucket = -1;
    (void)SysmonCopyWideText(
        g_SignatureCache[slot].Path,
        RTL_NUMBER_OF(g_SignatureCache[slot].Path),
        FilePath);
    g_SignatureCache[slot].Result = *Result;
    SysmonLinkSignatureCacheSlot(slot);
}

static BOOL
SysmonLookupImageEnrichmentCache(
    _In_z_ PCWSTR FilePath,
    _In_ BOOL CheckRevocation,
    _In_ DWORD ActionKind,
    _In_ DWORD HashMask,
    _Out_opt_ PSYSMON_SIGNATURE_RESULT SignatureResult,
    _Out_writes_opt_(HashesChars) PWCHAR Hashes,
    _In_ size_t HashesChars)
{
    DWORD bucket;
    DWORD pathHash;
    DWORD pathLength;
    LONG index;

    if (FilePath == NULL || FilePath[0] == L'\0') {
        return FALSE;
    }

    pathHash = SysmonComputeCachePathHash(FilePath, &pathLength);
    CriticalSectionGuard cacheLock(&g_ImageEnrichmentCacheLock);

    bucket = SysmonSelectImageEnrichmentCacheBucket(pathHash);
    for (index = g_ImageEnrichmentCacheBuckets[bucket];
         index >= 0;
         index = g_ImageEnrichmentCache[index].NextInBucket) {
        if (g_ImageEnrichmentCache[index].CheckRevocation != CheckRevocation ||
            g_ImageEnrichmentCache[index].ActionKind != ActionKind ||
            g_ImageEnrichmentCache[index].HashMask != HashMask ||
            !SysmonCachedPathMatches(
                g_ImageEnrichmentCache[index].PathHash,
                g_ImageEnrichmentCache[index].PathLength,
                g_ImageEnrichmentCache[index].Path,
                pathHash,
                pathLength,
                FilePath)) {
            continue;
        }

        if (SignatureResult != NULL) {
            *SignatureResult = g_ImageEnrichmentCache[index].SignatureResult;
        }
        if (Hashes != NULL && HashesChars != 0) {
            (void)SysmonCopyWideText(
                Hashes,
                HashesChars,
                g_ImageEnrichmentCache[index].Hashes);
        }
        return TRUE;
    }

    return FALSE;
}

static VOID
SysmonStoreImageEnrichmentCache(
    _In_z_ PCWSTR FilePath,
    _In_ BOOL CheckRevocation,
    _In_ DWORD ActionKind,
    _In_ DWORD HashMask,
    _In_ const SYSMON_SIGNATURE_RESULT *SignatureResult,
    _In_opt_z_ PCWSTR Hashes)
{
    DWORD slot;
    DWORD bucket;
    DWORD pathHash;
    DWORD pathLength;
    LONG index;

    if (FilePath == NULL || FilePath[0] == L'\0' || SignatureResult == NULL) {
        return;
    }

    pathHash = SysmonComputeCachePathHash(FilePath, &pathLength);
    CriticalSectionGuard cacheLock(&g_ImageEnrichmentCacheLock);

    bucket = SysmonSelectImageEnrichmentCacheBucket(pathHash);
    for (index = g_ImageEnrichmentCacheBuckets[bucket];
         index >= 0;
         index = g_ImageEnrichmentCache[index].NextInBucket) {
        if (g_ImageEnrichmentCache[index].CheckRevocation == CheckRevocation &&
            g_ImageEnrichmentCache[index].ActionKind == ActionKind &&
            g_ImageEnrichmentCache[index].HashMask == HashMask &&
            SysmonCachedPathMatches(
                g_ImageEnrichmentCache[index].PathHash,
                g_ImageEnrichmentCache[index].PathLength,
                g_ImageEnrichmentCache[index].Path,
                pathHash,
                pathLength,
                FilePath)) {
            g_ImageEnrichmentCache[index].SignatureResult = *SignatureResult;
            if (!SysmonIsPlaceholderString(Hashes)) {
                (void)SysmonCopyWideText(
                    g_ImageEnrichmentCache[index].Hashes,
                    RTL_NUMBER_OF(g_ImageEnrichmentCache[index].Hashes),
                    Hashes);
            }
            return;
        }
    }

    slot = g_ImageEnrichmentCacheVictim++ % SYSMON_IMAGE_ENRICHMENT_CACHE_CAPACITY;
    SysmonUnlinkImageEnrichmentCacheSlot(slot);
    ZeroMemory(&g_ImageEnrichmentCache[slot], sizeof(g_ImageEnrichmentCache[slot]));
    g_ImageEnrichmentCache[slot].InUse = TRUE;
    g_ImageEnrichmentCache[slot].CheckRevocation = CheckRevocation;
    g_ImageEnrichmentCache[slot].ActionKind = ActionKind;
    g_ImageEnrichmentCache[slot].HashMask = HashMask;
    g_ImageEnrichmentCache[slot].PathHash = pathHash;
    g_ImageEnrichmentCache[slot].PathLength = pathLength;
    g_ImageEnrichmentCache[slot].NextInBucket = -1;
    (void)SysmonCopyWideText(
        g_ImageEnrichmentCache[slot].Path,
        RTL_NUMBER_OF(g_ImageEnrichmentCache[slot].Path),
        FilePath);
    g_ImageEnrichmentCache[slot].SignatureResult = *SignatureResult;
    if (!SysmonIsPlaceholderString(Hashes)) {
        (void)SysmonCopyWideText(
            g_ImageEnrichmentCache[slot].Hashes,
            RTL_NUMBER_OF(g_ImageEnrichmentCache[slot].Hashes),
            Hashes);
    }
    SysmonLinkImageEnrichmentCacheSlot(slot);
}

static BOOL
SysmonResolveSignatureResult(
    _In_z_ PCWSTR RawPath,
    _In_ const GUID *ActionGuid,
    _In_ BOOL CheckRevocation,
    _Out_ PSYSMON_SIGNATURE_RESULT Result)
{
    LONG verifyStatus;
    DWORD actionKind;

    if (Result == NULL) {
        return FALSE;
    }

    ZeroMemory(Result, sizeof(*Result));
    (void)SysmonCopyWideText(
        Result->SignatureStatus,
        RTL_NUMBER_OF(Result->SignatureStatus),
        L"Unavailable");

    if (RawPath == NULL || RawPath[0] == L'\0') {
        return FALSE;
    }

    if (!SysmonConvertNtPathToWin32Path(
            RawPath,
            Result->ResolvedPath,
            RTL_NUMBER_OF(Result->ResolvedPath))) {
        (void)SysmonCopyWideText(
            Result->ResolvedPath,
            RTL_NUMBER_OF(Result->ResolvedPath),
            RawPath);
    }

    actionKind = SysmonGetSignatureActionKind(ActionGuid);
    if (SysmonLookupSignatureCache(Result->ResolvedPath, CheckRevocation, actionKind, Result)) {
        return TRUE;
    }

    if (SysmonFileHasEmbeddedSignatureHint(Result->ResolvedPath)) {
        verifyStatus = SysmonVerifyEmbeddedSignature(
            Result->ResolvedPath,
            ActionGuid,
            CheckRevocation,
            Result);
    } else {
        verifyStatus = TRUST_E_NOSIGNATURE;
    }

    if ((verifyStatus != ERROR_SUCCESS && SysmonShouldTryCatalogVerification(verifyStatus)) ||
        (verifyStatus == ERROR_SUCCESS && SysmonIsPlaceholderString(Result->Signature))) {
        SYSMON_SIGNATURE_RESULT catalogResult;
        LONG catalogStatus;

        ZeroMemory(&catalogResult, sizeof(catalogResult));
        (void)SysmonCopyWideText(
            catalogResult.ResolvedPath,
            RTL_NUMBER_OF(catalogResult.ResolvedPath),
            Result->ResolvedPath);

        catalogStatus = SysmonVerifyCatalogSignature(Result->ResolvedPath, ActionGuid, CheckRevocation, &catalogResult);
        if (catalogStatus == ERROR_SUCCESS &&
            (!SysmonIsPlaceholderString(catalogResult.Signature) || verifyStatus != ERROR_SUCCESS)) {
            *Result = catalogResult;
            verifyStatus = catalogStatus;
        }
    }

    if (verifyStatus == ERROR_SUCCESS &&
        SysmonIsPlaceholderString(Result->Signature) &&
        ActionGuid != &g_GenericVerifyV2Action) {
        SYSMON_SIGNATURE_RESULT genericResult;
        LONG genericStatus;

        ZeroMemory(&genericResult, sizeof(genericResult));
        (void)SysmonCopyWideText(
            genericResult.ResolvedPath,
            RTL_NUMBER_OF(genericResult.ResolvedPath),
            Result->ResolvedPath);

        genericStatus = SysmonVerifyEmbeddedSignature(
            Result->ResolvedPath,
            &g_GenericVerifyV2Action,
            CheckRevocation,
            &genericResult);
        if ((genericStatus != ERROR_SUCCESS && SysmonShouldTryCatalogVerification(genericStatus)) ||
            (genericStatus == ERROR_SUCCESS && SysmonIsPlaceholderString(genericResult.Signature))) {
            SYSMON_SIGNATURE_RESULT genericCatalogResult;
            LONG genericCatalogStatus;

            ZeroMemory(&genericCatalogResult, sizeof(genericCatalogResult));
            (void)SysmonCopyWideText(
                genericCatalogResult.ResolvedPath,
                RTL_NUMBER_OF(genericCatalogResult.ResolvedPath),
                Result->ResolvedPath);

            genericCatalogStatus = SysmonVerifyCatalogSignature(
                Result->ResolvedPath,
                &g_GenericVerifyV2Action,
                CheckRevocation,
                &genericCatalogResult);
            if (genericCatalogStatus == ERROR_SUCCESS &&
                (!SysmonIsPlaceholderString(genericCatalogResult.Signature) ||
                 genericStatus != ERROR_SUCCESS)) {
                genericResult = genericCatalogResult;
                genericStatus = genericCatalogStatus;
            }
        }

        if (genericStatus == ERROR_SUCCESS &&
            !SysmonIsPlaceholderString(genericResult.Signature)) {
            *Result = genericResult;
            verifyStatus = genericStatus;
        }
    }

    SysmonMapSignatureStatus(verifyStatus, verifyStatus == ERROR_SUCCESS, Result);
    SysmonStoreSignatureCache(Result->ResolvedPath, CheckRevocation, actionKind, Result);
    return TRUE;
}

static BOOL
SysmonAddNormalizedPathField(
    _Inout_updates_bytes_(EventBufferSize) PBYTE EventBuffer,
    _In_ DWORD EventBufferSize,
    _Inout_ PSYSMON_EVENT_PAYLOAD_BUILDER Builder,
    _Out_ SYSMON_EVENT_STRING_REF *FieldRef,
    _In_opt_z_ PCWSTR RawPath)
{
    WCHAR normalizedPath[SYSMON_MAX_SIGNATURE_PATH_CHARS];

    if (FieldRef == NULL) {
        return FALSE;
    }

    normalizedPath[0] = L'\0';
    if (RawPath != NULL && RawPath[0] != L'\0') {
        if (!SysmonConvertNtPathToWin32Path(
                RawPath,
                normalizedPath,
                RTL_NUMBER_OF(normalizedPath))) {
            (void)SysmonCopyWideText(
                normalizedPath,
                RTL_NUMBER_OF(normalizedPath),
                RawPath);
        }
    }

    return SysmonAddStringField(
        EventBuffer,
        EventBufferSize,
        Builder,
        FieldRef,
        normalizedPath[0] != L'\0' ? normalizedPath : RawPath) == SYSMON_SUCCESS;
}

static VOID
SysmonResolveEventHashes(
    _In_z_ PCWSTR RawPath,
    _In_opt_z_ PCWSTR ExistingHashes,
    _In_opt_z_ PCWSTR PreferredResolvedPath,
    _In_ DWORD HashMask,
    _Out_writes_(BufferChars) PWCHAR Buffer,
    _In_ size_t BufferChars)
{
    WCHAR resolvedPath[SYSMON_MAX_SIGNATURE_PATH_CHARS];

    if (Buffer == NULL || BufferChars == 0) {
        return;
    }

    Buffer[0] = L'\0';
    if (!SysmonIsPlaceholderString(ExistingHashes)) {
        (void)SysmonCopyWideText(Buffer, BufferChars, ExistingHashes);
        return;
    }

    if (RawPath == NULL || RawPath[0] == L'\0') {
        return;
    }

    resolvedPath[0] = L'\0';
    if (!SysmonIsPlaceholderString(PreferredResolvedPath)) {
        (void)SysmonCopyWideText(
            resolvedPath,
            RTL_NUMBER_OF(resolvedPath),
            PreferredResolvedPath);
    } else if (!SysmonConvertNtPathToWin32Path(
                   RawPath,
                   resolvedPath,
                   RTL_NUMBER_OF(resolvedPath))) {
        (void)SysmonCopyWideText(
            resolvedPath,
            RTL_NUMBER_OF(resolvedPath),
            RawPath);
    }

    /* HashMask == 0 means "no hashing" (None). Do not fall back to MD5|SHA1:
       SysmonComputeFileHashes already handles a 0 mask by returning "-".
       See U5 in the 2026-08-04 review. */

    if (resolvedPath[0] != L'\0') {
        (void)SysmonComputeFileHashes(
            resolvedPath,
            HashMask,
            Buffer,
            (ULONG)BufferChars);
    }
}

static BOOL
SysmonResolveImageEnrichmentBundle(
    _In_z_ PCWSTR RawPath,
    _In_ SYSMON_EVENT_ID EventId,
    _In_opt_z_ PCWSTR ExistingHashes,
    _In_ BOOL CheckRevocation,
    _In_ const GUID *ActionGuid,
    _In_ DWORD HashMask,
    _Out_ PSYSMON_SIGNATURE_RESULT SignatureResult,
    _Out_writes_(HashesChars) PWCHAR Hashes,
    _In_ size_t HashesChars)
{
    WCHAR cachePath[SYSMON_MAX_SIGNATURE_PATH_CHARS];
    DWORD actionKind;

    if (SignatureResult == NULL || Hashes == NULL || HashesChars == 0) {
        return FALSE;
    }

    ZeroMemory(SignatureResult, sizeof(*SignatureResult));
    Hashes[0] = L'\0';
    cachePath[0] = L'\0';

    if (RawPath == NULL || RawPath[0] == L'\0') {
        return FALSE;
    }

    if (!SysmonConvertNtPathToWin32Path(
            RawPath,
            cachePath,
            RTL_NUMBER_OF(cachePath))) {
        (void)SysmonCopyWideText(
            cachePath,
            RTL_NUMBER_OF(cachePath),
            RawPath);
    }

    actionKind = SysmonGetSignatureActionKind(ActionGuid);
    if (SysmonLookupImageEnrichmentCache(
            cachePath,
            CheckRevocation,
            actionKind,
            HashMask,
            SignatureResult,
            Hashes,
            HashesChars)) {
        if (!SysmonIsPlaceholderString(ExistingHashes) &&
            SysmonIsPlaceholderString(Hashes)) {
            (void)SysmonCopyWideText(Hashes, HashesChars, ExistingHashes);
        }
        return TRUE;
    }

    (void)SysmonResolveSignatureResult(
        RawPath,
        ActionGuid,
        CheckRevocation,
        SignatureResult);
    if (EventId == SysmonEventDriverLoad) {
        SysmonResolveEventHashes(
            RawPath,
            ExistingHashes,
            SignatureResult->ResolvedPath,
            HashMask,
            Hashes,
            HashesChars);
    } else if (!SysmonIsPlaceholderString(ExistingHashes)) {
        (void)SysmonCopyWideText(Hashes, HashesChars, ExistingHashes);
    }

    SysmonStoreImageEnrichmentCache(
        !SysmonIsPlaceholderString(SignatureResult->ResolvedPath)
            ? SignatureResult->ResolvedPath
            : cachePath,
        CheckRevocation,
        actionKind,
        HashMask,
        SignatureResult,
        Hashes);
    return TRUE;
}

static BOOL
SysmonBeginRebuildImageEvent(
    _Out_writes_bytes_(BufferSize) BYTE *Buffer,
    _In_ DWORD BufferSize,
    _In_ SYSMON_EVENT_ID EventId,
    _In_ DWORD PayloadSize,
    _In_ ULONGLONG Timestamp,
    _Out_ PSYSMON_EVENT_HEADER *Header,
    _Out_ PSYSMON_EVENT_PAYLOAD_BUILDER Builder)
{
    if (Buffer == NULL || Header == NULL || Builder == NULL) {
        return FALSE;
    }

    SysmonInitializeEventBuffer(
        Buffer,
        BufferSize,
        EventId,
        PayloadSize,
        Builder,
        Timestamp);

    *Header = (PSYSMON_EVENT_HEADER)Buffer;
    return TRUE;
}

typedef struct _SYSMON_DRIVER_LOAD_REBUILD_FIELDS {
    WCHAR RuleName[256];
    WCHAR UtcTime[64];
    WCHAR ImageLoaded[SYSMON_MAX_SIGNATURE_PATH_CHARS];
    WCHAR Hashes[512];
    WCHAR Signature[256];
    WCHAR SignatureStatus[256];
    BOOLEAN Signed;
} SYSMON_DRIVER_LOAD_REBUILD_FIELDS, *PSYSMON_DRIVER_LOAD_REBUILD_FIELDS;

typedef struct _SYSMON_IMAGE_LOAD_REBUILD_FIELDS {
    WCHAR RuleName[256];
    WCHAR UtcTime[64];
    WCHAR ProcessGuid[128];
    WCHAR Image[SYSMON_MAX_SIGNATURE_PATH_CHARS];
    WCHAR ImageLoaded[SYSMON_MAX_SIGNATURE_PATH_CHARS];
    WCHAR Hashes[512];
    WCHAR Signature[256];
    WCHAR SignatureStatus[256];
    WCHAR FileVersion[256];
    WCHAR Description[256];
    WCHAR Product[256];
    WCHAR Company[256];
    WCHAR OriginalFileName[256];
    WCHAR User[256];
    DWORD ProcessId;
    BOOLEAN Signed;
} SYSMON_IMAGE_LOAD_REBUILD_FIELDS, *PSYSMON_IMAGE_LOAD_REBUILD_FIELDS;

static BOOL
SysmonExtractDriverLoadRebuildFields(
    _In_reads_bytes_(EventSize) const BYTE *EventData,
    _In_ DWORD EventSize,
    _Out_ const SYSMON_EVENT_HEADER **SourceHeader,
    _Out_ SYSMON_DRIVER_LOAD_REBUILD_FIELDS *Fields)
{
    const SYSMON_EVENT_DRIVER_LOAD_PAYLOAD *sourcePayload;

    if (EventData == NULL || SourceHeader == NULL || Fields == NULL) {
        return FALSE;
    }

    if (EventSize < SYSMON_EVENT_CONTRACT_SIZE(SYSMON_EVENT_DRIVER_LOAD_PAYLOAD)) {
        return FALSE;
    }

    *SourceHeader = (const SYSMON_EVENT_HEADER *)EventData;
    sourcePayload = (const SYSMON_EVENT_DRIVER_LOAD_PAYLOAD *)(EventData + SYSMON_EVENT_HEADER_SIZE);

    ZeroMemory(Fields, sizeof(*Fields));
    (void)SysmonCopyStringField(EventData, EventSize, sourcePayload->RuleName, Fields->RuleName, RTL_NUMBER_OF(Fields->RuleName));
    (void)SysmonCopyStringField(EventData, EventSize, sourcePayload->UtcTime, Fields->UtcTime, RTL_NUMBER_OF(Fields->UtcTime));
    (void)SysmonCopyStringField(EventData, EventSize, sourcePayload->ImageLoaded, Fields->ImageLoaded, RTL_NUMBER_OF(Fields->ImageLoaded));
    (void)SysmonCopyStringField(EventData, EventSize, sourcePayload->Hashes, Fields->Hashes, RTL_NUMBER_OF(Fields->Hashes));
    (void)SysmonCopyStringField(EventData, EventSize, sourcePayload->Signature, Fields->Signature, RTL_NUMBER_OF(Fields->Signature));
    (void)SysmonCopyStringField(EventData, EventSize, sourcePayload->SignatureStatus, Fields->SignatureStatus, RTL_NUMBER_OF(Fields->SignatureStatus));
    Fields->Signed = SysmonReadPackedValue<BOOLEAN>(&sourcePayload->Signed);
    return TRUE;
}

static BOOL
SysmonWriteDriverLoadRebuildEvent(
    _In_ const SYSMON_EVENT_HEADER *SourceHeader,
    _In_ const SYSMON_DRIVER_LOAD_REBUILD_FIELDS *Fields,
    _In_ BOOL IncludeRuleName,
    _Out_writes_bytes_(BufferSize) BYTE *Buffer,
    _In_ DWORD BufferSize,
    _Out_ PDWORD RebuiltSize)
{
    PSYSMON_EVENT_HEADER targetHeader;
    SYSMON_EVENT_DRIVER_LOAD_PAYLOAD *targetPayload;
    SYSMON_EVENT_PAYLOAD_BUILDER builder;

    if (SourceHeader == NULL || Fields == NULL || Buffer == NULL || RebuiltSize == NULL) {
        return FALSE;
    }

    if (!SysmonBeginRebuildImageEvent(
            Buffer,
            BufferSize,
            SysmonEventDriverLoad,
            sizeof(*targetPayload),
            (ULONGLONG)SourceHeader->Timestamp,
            &targetHeader,
            &builder)) {
        return FALSE;
    }

    targetPayload = (SYSMON_EVENT_DRIVER_LOAD_PAYLOAD *)(Buffer + SYSMON_EVENT_HEADER_SIZE);
    targetHeader->SequenceNumber = SourceHeader->SequenceNumber;

    if ((IncludeRuleName &&
         SysmonAddStringField(Buffer, BufferSize, &builder, &targetPayload->RuleName, Fields->RuleName) != SYSMON_SUCCESS) ||
        SysmonAddStringField(Buffer, BufferSize, &builder, &targetPayload->UtcTime, Fields->UtcTime) != SYSMON_SUCCESS ||
        !SysmonAddNormalizedPathField(Buffer, BufferSize, &builder, &targetPayload->ImageLoaded, Fields->ImageLoaded) ||
        SysmonAddStringField(Buffer, BufferSize, &builder, &targetPayload->Hashes, Fields->Hashes) != SYSMON_SUCCESS ||
        SysmonAddStringField(Buffer, BufferSize, &builder, &targetPayload->Signature, Fields->Signature) != SYSMON_SUCCESS ||
        SysmonAddStringField(Buffer, BufferSize, &builder, &targetPayload->SignatureStatus, Fields->SignatureStatus) != SYSMON_SUCCESS) {
        return FALSE;
    }

    SysmonWritePackedValue<BOOLEAN>(&targetPayload->Signed, Fields->Signed);
    *RebuiltSize = targetHeader->EventSize;
    return TRUE;
}

static VOID
SysmonPopulateMissingImageLoadVersionInfo(
    _Inout_ SYSMON_IMAGE_LOAD_REBUILD_FIELDS *Fields,
    _In_ const SYSMON_SIGNATURE_RESULT *SignatureResult)
{
    SYSMON_IMAGE_VERSION_INFO versionInfo;

    if (Fields == NULL || SignatureResult == NULL ||
        SysmonIsPlaceholderString(SignatureResult->ResolvedPath)) {
        return;
    }

    if (!SysmonIsPlaceholderString(Fields->FileVersion) &&
        !SysmonIsPlaceholderString(Fields->Description) &&
        !SysmonIsPlaceholderString(Fields->Product) &&
        !SysmonIsPlaceholderString(Fields->Company) &&
        !SysmonIsPlaceholderString(Fields->OriginalFileName)) {
        return;
    }

    ZeroMemory(&versionInfo, sizeof(versionInfo));
    SysmonResolveImageVersionInfo(SignatureResult->ResolvedPath, &versionInfo);

    if (SysmonIsPlaceholderString(Fields->FileVersion) && !SysmonIsPlaceholderString(versionInfo.FileVersion)) {
        (void)SysmonCopyWideText(Fields->FileVersion, RTL_NUMBER_OF(Fields->FileVersion), versionInfo.FileVersion);
    }
    if (SysmonIsPlaceholderString(Fields->Description) && !SysmonIsPlaceholderString(versionInfo.Description)) {
        (void)SysmonCopyWideText(Fields->Description, RTL_NUMBER_OF(Fields->Description), versionInfo.Description);
    }
    if (SysmonIsPlaceholderString(Fields->Product) && !SysmonIsPlaceholderString(versionInfo.Product)) {
        (void)SysmonCopyWideText(Fields->Product, RTL_NUMBER_OF(Fields->Product), versionInfo.Product);
    }
    if (SysmonIsPlaceholderString(Fields->Company) && !SysmonIsPlaceholderString(versionInfo.Company)) {
        (void)SysmonCopyWideText(Fields->Company, RTL_NUMBER_OF(Fields->Company), versionInfo.Company);
    }
    if (SysmonIsPlaceholderString(Fields->OriginalFileName) && !SysmonIsPlaceholderString(versionInfo.OriginalFileName)) {
        (void)SysmonCopyWideText(
            Fields->OriginalFileName,
            RTL_NUMBER_OF(Fields->OriginalFileName),
            versionInfo.OriginalFileName);
    }
}

static BOOL
SysmonExtractImageLoadRebuildFields(
    _In_reads_bytes_(EventSize) const BYTE *EventData,
    _In_ DWORD EventSize,
    _Out_ const SYSMON_EVENT_HEADER **SourceHeader,
    _Out_ SYSMON_IMAGE_LOAD_REBUILD_FIELDS *Fields)
{
    const SYSMON_EVENT_IMAGE_LOAD_PAYLOAD *sourcePayload;

    if (EventData == NULL || SourceHeader == NULL || Fields == NULL) {
        return FALSE;
    }

    if (EventSize < SYSMON_EVENT_CONTRACT_SIZE(SYSMON_EVENT_IMAGE_LOAD_PAYLOAD)) {
        return FALSE;
    }

    *SourceHeader = (const SYSMON_EVENT_HEADER *)EventData;
    sourcePayload = (const SYSMON_EVENT_IMAGE_LOAD_PAYLOAD *)(EventData + SYSMON_EVENT_HEADER_SIZE);

    ZeroMemory(Fields, sizeof(*Fields));
    (void)SysmonCopyStringField(EventData, EventSize, sourcePayload->RuleName, Fields->RuleName, RTL_NUMBER_OF(Fields->RuleName));
    (void)SysmonCopyStringField(EventData, EventSize, sourcePayload->UtcTime, Fields->UtcTime, RTL_NUMBER_OF(Fields->UtcTime));
    (void)SysmonCopyStringField(EventData, EventSize, sourcePayload->ProcessGuid, Fields->ProcessGuid, RTL_NUMBER_OF(Fields->ProcessGuid));
    (void)SysmonCopyStringField(EventData, EventSize, sourcePayload->Image, Fields->Image, RTL_NUMBER_OF(Fields->Image));
    (void)SysmonCopyStringField(EventData, EventSize, sourcePayload->ImageLoaded, Fields->ImageLoaded, RTL_NUMBER_OF(Fields->ImageLoaded));
    (void)SysmonCopyStringField(EventData, EventSize, sourcePayload->Hashes, Fields->Hashes, RTL_NUMBER_OF(Fields->Hashes));
    (void)SysmonCopyStringField(EventData, EventSize, sourcePayload->Signature, Fields->Signature, RTL_NUMBER_OF(Fields->Signature));
    (void)SysmonCopyStringField(EventData, EventSize, sourcePayload->SignatureStatus, Fields->SignatureStatus, RTL_NUMBER_OF(Fields->SignatureStatus));
    (void)SysmonCopyStringField(EventData, EventSize, sourcePayload->FileVersion, Fields->FileVersion, RTL_NUMBER_OF(Fields->FileVersion));
    (void)SysmonCopyStringField(EventData, EventSize, sourcePayload->Description, Fields->Description, RTL_NUMBER_OF(Fields->Description));
    (void)SysmonCopyStringField(EventData, EventSize, sourcePayload->Product, Fields->Product, RTL_NUMBER_OF(Fields->Product));
    (void)SysmonCopyStringField(EventData, EventSize, sourcePayload->Company, Fields->Company, RTL_NUMBER_OF(Fields->Company));
    (void)SysmonCopyStringField(EventData, EventSize, sourcePayload->OriginalFileName, Fields->OriginalFileName, RTL_NUMBER_OF(Fields->OriginalFileName));
    (void)SysmonCopyStringField(EventData, EventSize, sourcePayload->User, Fields->User, RTL_NUMBER_OF(Fields->User));
    Fields->ProcessId = SysmonReadPackedValue<DWORD>(&sourcePayload->ProcessId);
    Fields->Signed = SysmonReadPackedValue<BOOLEAN>(&sourcePayload->Signed);
    return TRUE;
}

static BOOL
SysmonWriteImageLoadRebuildEvent(
    _In_ const SYSMON_EVENT_HEADER *SourceHeader,
    _In_ const SYSMON_IMAGE_LOAD_REBUILD_FIELDS *Fields,
    _In_ BOOL IncludeRuleName,
    _Out_writes_bytes_(BufferSize) BYTE *Buffer,
    _In_ DWORD BufferSize,
    _Out_ PDWORD RebuiltSize)
{
    PSYSMON_EVENT_HEADER targetHeader;
    SYSMON_EVENT_IMAGE_LOAD_PAYLOAD *targetPayload;
    SYSMON_EVENT_PAYLOAD_BUILDER builder;

    if (SourceHeader == NULL || Fields == NULL || Buffer == NULL || RebuiltSize == NULL) {
        return FALSE;
    }

    if (!SysmonBeginRebuildImageEvent(
            Buffer,
            BufferSize,
            SysmonEventImageLoad,
            sizeof(*targetPayload),
            (ULONGLONG)SourceHeader->Timestamp,
            &targetHeader,
            &builder)) {
        return FALSE;
    }

    targetPayload = (SYSMON_EVENT_IMAGE_LOAD_PAYLOAD *)(Buffer + SYSMON_EVENT_HEADER_SIZE);
    targetHeader->SequenceNumber = SourceHeader->SequenceNumber;

    if ((IncludeRuleName &&
         SysmonAddStringField(Buffer, BufferSize, &builder, &targetPayload->RuleName, Fields->RuleName) != SYSMON_SUCCESS) ||
        SysmonAddStringField(Buffer, BufferSize, &builder, &targetPayload->UtcTime, Fields->UtcTime) != SYSMON_SUCCESS ||
        SysmonAddStringField(Buffer, BufferSize, &builder, &targetPayload->ProcessGuid, Fields->ProcessGuid) != SYSMON_SUCCESS ||
        !SysmonAddNormalizedPathField(Buffer, BufferSize, &builder, &targetPayload->Image, Fields->Image) ||
        !SysmonAddNormalizedPathField(Buffer, BufferSize, &builder, &targetPayload->ImageLoaded, Fields->ImageLoaded) ||
        SysmonAddStringField(Buffer, BufferSize, &builder, &targetPayload->Hashes, Fields->Hashes) != SYSMON_SUCCESS ||
        SysmonAddStringField(Buffer, BufferSize, &builder, &targetPayload->Signature, Fields->Signature) != SYSMON_SUCCESS ||
        SysmonAddStringField(Buffer, BufferSize, &builder, &targetPayload->SignatureStatus, Fields->SignatureStatus) != SYSMON_SUCCESS ||
        SysmonAddStringField(Buffer, BufferSize, &builder, &targetPayload->FileVersion, Fields->FileVersion) != SYSMON_SUCCESS ||
        SysmonAddStringField(Buffer, BufferSize, &builder, &targetPayload->Description, Fields->Description) != SYSMON_SUCCESS ||
        SysmonAddStringField(Buffer, BufferSize, &builder, &targetPayload->Product, Fields->Product) != SYSMON_SUCCESS ||
        SysmonAddStringField(Buffer, BufferSize, &builder, &targetPayload->Company, Fields->Company) != SYSMON_SUCCESS ||
        SysmonAddStringField(Buffer, BufferSize, &builder, &targetPayload->OriginalFileName, Fields->OriginalFileName) != SYSMON_SUCCESS ||
        SysmonAddStringField(Buffer, BufferSize, &builder, &targetPayload->User, Fields->User) != SYSMON_SUCCESS) {
        return FALSE;
    }

    SysmonWritePackedValue<DWORD>(&targetPayload->ProcessId, Fields->ProcessId);
    SysmonWritePackedValue<BOOLEAN>(&targetPayload->Signed, Fields->Signed);
    *RebuiltSize = targetHeader->EventSize;
    return TRUE;
}

static BOOL
SysmonTryRebuildDriverLoadEvent(
    _In_reads_bytes_(EventSize) const BYTE *EventData,
    _In_ DWORD EventSize,
    _In_ const SYSMON_SIGNATURE_RESULT *SignatureResult,
    _In_opt_z_ PCWSTR HashesValue,
    _Out_writes_bytes_(BufferSize) BYTE *Buffer,
    _In_ DWORD BufferSize,
    _Out_ PDWORD RebuiltSize)
{
    const SYSMON_EVENT_HEADER *sourceHeader;
    SYSMON_DRIVER_LOAD_REBUILD_FIELDS fields;

    if (EventData == NULL || SignatureResult == NULL || Buffer == NULL || RebuiltSize == NULL) {
        return FALSE;
    }

    if (!SysmonExtractDriverLoadRebuildFields(EventData, EventSize, &sourceHeader, &fields)) {
        return FALSE;
    }

    (void)SysmonCopyWideText(fields.Hashes, RTL_NUMBER_OF(fields.Hashes), HashesValue);
    (void)SysmonCopyWideText(fields.Signature, RTL_NUMBER_OF(fields.Signature), SignatureResult->Signature);
    (void)SysmonCopyWideText(fields.SignatureStatus, RTL_NUMBER_OF(fields.SignatureStatus), SignatureResult->SignatureStatus);
    fields.Signed = SignatureResult->Signed;

    return SysmonWriteDriverLoadRebuildEvent(
        sourceHeader,
        &fields,
        TRUE,
        Buffer,
        BufferSize,
        RebuiltSize);
}

static BOOL
SysmonTryRebuildImageLoadEvent(
    _In_reads_bytes_(EventSize) const BYTE *EventData,
    _In_ DWORD EventSize,
    _In_ const SYSMON_SIGNATURE_RESULT *SignatureResult,
    _In_opt_z_ PCWSTR HashesValue,
    _Out_writes_bytes_(BufferSize) BYTE *Buffer,
    _In_ DWORD BufferSize,
    _Out_ PDWORD RebuiltSize)
{
    const SYSMON_EVENT_HEADER *sourceHeader;
    SYSMON_IMAGE_LOAD_REBUILD_FIELDS fields;

    if (EventData == NULL || SignatureResult == NULL || Buffer == NULL || RebuiltSize == NULL) {
        return FALSE;
    }

    if (!SysmonExtractImageLoadRebuildFields(EventData, EventSize, &sourceHeader, &fields)) {
        return FALSE;
    }

    if (SysmonIsPlaceholderString(HashesValue) &&
        !SysmonIsPlaceholderString(fields.Hashes)) {
        /* Keep the event's existing hash string. */
    } else {
        (void)SysmonCopyWideText(fields.Hashes, RTL_NUMBER_OF(fields.Hashes), HashesValue);
    }

    SysmonPopulateMissingImageLoadVersionInfo(&fields, SignatureResult);
    (void)SysmonCopyWideText(fields.Signature, RTL_NUMBER_OF(fields.Signature), SignatureResult->Signature);
    (void)SysmonCopyWideText(fields.SignatureStatus, RTL_NUMBER_OF(fields.SignatureStatus), SignatureResult->SignatureStatus);
    fields.Signed = SignatureResult->Signed;

    return SysmonWriteImageLoadRebuildEvent(
        sourceHeader,
        &fields,
        TRUE,
        Buffer,
        BufferSize,
        RebuiltSize);
}

static BOOL
SysmonTryNormalizeImageSignaturePathsForFiltering(
    _In_reads_bytes_(EventSize) const BYTE *EventData,
    _In_ DWORD EventSize,
    _In_ SYSMON_EVENT_ID EventId,
    _Out_writes_bytes_(BufferSize) BYTE *Buffer,
    _In_ DWORD BufferSize,
    _Out_ PDWORD RebuiltSize)
{
    if (EventData == NULL || Buffer == NULL || RebuiltSize == NULL) {
        return FALSE;
    }

    if (EventId == SysmonEventDriverLoad) {
        const SYSMON_EVENT_HEADER *sourceHeader;
        SYSMON_DRIVER_LOAD_REBUILD_FIELDS fields;

        if (!SysmonExtractDriverLoadRebuildFields(EventData, EventSize, &sourceHeader, &fields)) {
            return FALSE;
        }

        return SysmonWriteDriverLoadRebuildEvent(
            sourceHeader,
            &fields,
            FALSE,
            Buffer,
            BufferSize,
            RebuiltSize);
    }

    if (EventId == SysmonEventImageLoad) {
        const SYSMON_EVENT_HEADER *sourceHeader;
        SYSMON_IMAGE_LOAD_REBUILD_FIELDS fields;

        if (!SysmonExtractImageLoadRebuildFields(EventData, EventSize, &sourceHeader, &fields)) {
            return FALSE;
        }

        return SysmonWriteImageLoadRebuildEvent(
            sourceHeader,
            &fields,
            FALSE,
            Buffer,
            BufferSize,
            RebuiltSize);
    }

    return FALSE;
}

static BOOL
SysmonTryRebuildEnrichedImageSignatureEvent(
    _In_reads_bytes_(EventSize) const BYTE *EventData,
    _In_ DWORD EventSize,
    _In_ SYSMON_EVENT_ID EventId,
    _In_ const SYSMON_SIGNATURE_RESULT *SignatureResult,
    _In_opt_z_ PCWSTR HashesValue,
    _Out_writes_bytes_(BufferSize) BYTE *Buffer,
    _In_ DWORD BufferSize,
    _Out_ PDWORD RebuiltSize)
{
    if (EventId == SysmonEventDriverLoad) {
        return SysmonTryRebuildDriverLoadEvent(
            EventData,
            EventSize,
            SignatureResult,
            HashesValue,
            Buffer,
            BufferSize,
            RebuiltSize);
    }

    if (EventId == SysmonEventImageLoad) {
        return SysmonTryRebuildImageLoadEvent(
            EventData,
            EventSize,
            SignatureResult,
            HashesValue,
            Buffer,
            BufferSize,
            RebuiltSize);
    }

    return FALSE;
}

static VOID
SysmonDispatchPreparedEvent(
    _In_reads_bytes_(EventSize) const BYTE *EventData,
    _In_ DWORD EventSize,
    _In_ SYSMON_EVENT_ID EventId)
{
    SYSMON_EVENT_HANDLER handler;
    PSYSMON_RULE_RUNTIME runtime = NULL;

    {
        CriticalSectionGuard configLock(&g_ServiceCtx.ConfigLock);

        runtime = g_ServiceCtx.RuleRuntime;
        if (runtime != NULL &&
            !SysmonShouldCaptureEvent(runtime, EventId, EventData, EventSize)) {
            return;
        }
    }

    handler = g_EventHandlers[EventId];
    if (handler != NULL) {
        handler((PUCHAR)EventData, EventSize, EventId);
    }
}

static VOID
SysmonFreeEnrichmentWorkItem(
    _Inout_opt_ PSYSMON_ENRICHMENT_WORK_ITEM WorkItem)
{
    DWORD drained = 0;

    while (WorkItem != NULL && !SysmonIsListEmpty(&WorkItem->PendingEvents)) {
        PLIST_ENTRY entry;

        entry = SysmonRemoveHeadList(&WorkItem->PendingEvents);
        SysmonFreePendingEnrichmentEvent(
            CONTAINING_RECORD(entry, SYSMON_PENDING_ENRICHMENT_EVENT, ListEntry));
        drained++;
    }

    if (drained != 0) {
        InterlockedAdd(&g_SigningPendingEventDepth, -(LONG)drained);
    }

    SYSMON_FREE(WorkItem);
}

static PSYSMON_ENRICHMENT_WORK_ITEM
SysmonFindEnrichmentWorkItemInListLocked(
    _In_ const LIST_ENTRY *ListHead,
    _In_z_ PCWSTR KeyPath,
    _In_ BOOL CheckRevocation,
    _In_ DWORD HashMask)
{
    PLIST_ENTRY entry;

    for (entry = ListHead->Flink;
         entry != ListHead;
         entry = entry->Flink) {
        PSYSMON_ENRICHMENT_WORK_ITEM workItem;

        workItem = CONTAINING_RECORD(entry, SYSMON_ENRICHMENT_WORK_ITEM, ListEntry);
        if (workItem->CheckRevocation != CheckRevocation ||
            workItem->HashMask != HashMask) {
            continue;
        }

        if (_wcsicmp(workItem->KeyPath, KeyPath) == 0) {
            return workItem;
        }
    }

    return NULL;
}

static PSYSMON_ENRICHMENT_WORK_ITEM
SysmonFindEnrichmentWorkItemLocked(
    _In_z_ PCWSTR KeyPath,
    _In_ BOOL CheckRevocation,
    _In_ DWORD HashMask)
{
    PSYSMON_ENRICHMENT_WORK_ITEM workItem;

    workItem = SysmonFindEnrichmentWorkItemInListLocked(
        &g_SigningQueueList,
        KeyPath,
        CheckRevocation,
        HashMask);
    if (workItem != NULL) {
        return workItem;
    }

    return SysmonFindEnrichmentWorkItemInListLocked(
        &g_SigningActiveList,
        KeyPath,
        CheckRevocation,
        HashMask);
}

static BOOL
SysmonQueueImageSignatureEnrichment(
    _In_reads_bytes_(EventSize) const BYTE *EventData,
    _In_ DWORD EventSize,
    _In_ SYSMON_EVENT_ID EventId,
    _In_ BOOL CheckRevocation,
    _In_ DWORD HashMask)
{
    PSYSMON_PENDING_ENRICHMENT_EVENT pendingEvent;
    PSYSMON_ENRICHMENT_WORK_ITEM workItem;
    WCHAR rawPath[SYSMON_MAX_SIGNATURE_PATH_CHARS];
    WCHAR keyPath[SYSMON_MAX_SIGNATURE_PATH_CHARS];
    DWORD queueLimit;

    if (InterlockedCompareExchange(&g_SigningWorkerRunning, 0, 0) == 0 ||
        g_SigningQueueEvent == NULL) {
        return FALSE;
    }

    rawPath[0] = L'\0';
    keyPath[0] = L'\0';
    if (!SysmonExtractImageSignatureInputs(
            EventData,
            EventSize,
            EventId,
            rawPath,
            RTL_NUMBER_OF(rawPath),
            NULL,
            0) ||
        rawPath[0] == L'\0') {
        return FALSE;
    }

    if (!SysmonConvertNtPathToWin32Path(rawPath, keyPath, RTL_NUMBER_OF(keyPath))) {
        (void)SysmonCopyWideText(keyPath, RTL_NUMBER_OF(keyPath), rawPath);
    }

    pendingEvent = (PSYSMON_PENDING_ENRICHMENT_EVENT)SYSMON_ALLOC(sizeof(*pendingEvent));
    workItem = NULL;
    if (pendingEvent == NULL) {
        SysmonFreePendingEnrichmentEvent(pendingEvent);
        return FALSE;
    }

    ZeroMemory(pendingEvent, sizeof(*pendingEvent));
    pendingEvent->EventData = (BYTE *)SYSMON_ALLOC(EventSize);
    if (pendingEvent->EventData == NULL) {
        SysmonFreePendingEnrichmentEvent(pendingEvent);
        return FALSE;
    }

    CopyMemory(pendingEvent->EventData, EventData, EventSize);
    pendingEvent->EventSize = EventSize;
    pendingEvent->EventId = EventId;
    SysmonInitializeListHead(&pendingEvent->ListEntry);

    queueLimit = SysmonGetConfiguredSigningQueueSize();

    EnterCriticalSection(&g_SigningQueueLock);
    if (InterlockedCompareExchange(&g_SigningWorkerRunning, 0, 0) == 0) {
        LeaveCriticalSection(&g_SigningQueueLock);
        SysmonFreePendingEnrichmentEvent(pendingEvent);
        SysmonFreeEnrichmentWorkItem(workItem);
        return FALSE;
    }

    {
        PSYSMON_ENRICHMENT_WORK_ITEM existingItem;

        existingItem = SysmonFindEnrichmentWorkItemLocked(
            keyPath,
            CheckRevocation,
            HashMask);
        if (existingItem != NULL) {
            if (existingItem->PendingEventCount >=
                SYSMON_MAX_PENDING_ENRICHMENT_EVENTS_PER_WORK_ITEM ||
                (DWORD)InterlockedCompareExchange(&g_SigningPendingEventDepth, 0, 0) >=
                    SYSMON_MAX_PENDING_ENRICHMENT_EVENTS) {
                /* Bound both the per-work-item list and the global pending-event
                   count so an ImageLoad burst cannot exhaust memory (U2 in the
                   2026-08-04 review). Drop the excess event: the caller dispatches
                   the raw driver event (still logged, just unenriched). */
                LeaveCriticalSection(&g_SigningQueueLock);
                SysmonFreePendingEnrichmentEvent(pendingEvent);
                SysmonLogWarning(
                    SYSMON_COMPONENT_PIPELINE,
                    "Signing enrichment queue is full (%lu work items, %lu pending); dropping enrichment for event %u",
                    (unsigned long)InterlockedCompareExchange(&g_SigningQueueDepth, 0, 0),
                    (unsigned long)InterlockedCompareExchange(&g_SigningPendingEventDepth, 0, 0),
                    (unsigned)EventId);
                return FALSE;
            }

            SysmonInsertTailList(&existingItem->PendingEvents, &pendingEvent->ListEntry);
            existingItem->PendingEventCount += 1;
            InterlockedIncrement(&g_SigningPendingEventDepth);
            LeaveCriticalSection(&g_SigningQueueLock);
            SetEvent(g_SigningQueueEvent);
            return TRUE;
        }
    }

    if ((DWORD)InterlockedCompareExchange(&g_SigningQueueDepth, 0, 0) >= queueLimit ||
        (DWORD)InterlockedCompareExchange(&g_SigningPendingEventDepth, 0, 0) >=
            SYSMON_MAX_PENDING_ENRICHMENT_EVENTS) {
        LeaveCriticalSection(&g_SigningQueueLock);
        SysmonFreePendingEnrichmentEvent(pendingEvent);
        SysmonFreeEnrichmentWorkItem(workItem);
        SysmonLogWarning(
            SYSMON_COMPONENT_PIPELINE,
            "Signing queue is full (%lu work items, %lu pending)",
            (unsigned long)queueLimit,
            (unsigned long)InterlockedCompareExchange(&g_SigningPendingEventDepth, 0, 0));
        return FALSE;
    }

    workItem = (PSYSMON_ENRICHMENT_WORK_ITEM)SYSMON_ALLOC(sizeof(*workItem));
    if (workItem == NULL) {
        LeaveCriticalSection(&g_SigningQueueLock);
        SysmonFreePendingEnrichmentEvent(pendingEvent);
        return FALSE;
    }

    ZeroMemory(workItem, sizeof(*workItem));
    SysmonInitializeListHead(&workItem->ListEntry);
    SysmonInitializeListHead(&workItem->PendingEvents);
    workItem->CheckRevocation = CheckRevocation;
    workItem->HashMask = HashMask;
    (void)SysmonCopyWideText(workItem->RawPath, RTL_NUMBER_OF(workItem->RawPath), rawPath);
    (void)SysmonCopyWideText(workItem->KeyPath, RTL_NUMBER_OF(workItem->KeyPath), keyPath);

    SysmonInsertTailList(&workItem->PendingEvents, &pendingEvent->ListEntry);
    workItem->PendingEventCount = 1;
    InterlockedIncrement(&g_SigningPendingEventDepth);
    SysmonInsertTailList(&g_SigningQueueList, &workItem->ListEntry);
    InterlockedIncrement(&g_SigningQueueDepth);
    LeaveCriticalSection(&g_SigningQueueLock);

    SetEvent(g_SigningQueueEvent);
    return TRUE;
}

static BOOL
SysmonPopQueuedEnrichmentWorkItem(
    _Out_ PSYSMON_ENRICHMENT_WORK_ITEM *WorkItem)
{
    PLIST_ENTRY entry;

    if (WorkItem == NULL) {
        return FALSE;
    }

    *WorkItem = NULL;
    EnterCriticalSection(&g_SigningQueueLock);
    if (SysmonIsListEmpty(&g_SigningQueueList)) {
        ResetEvent(g_SigningQueueEvent);
        LeaveCriticalSection(&g_SigningQueueLock);
        return FALSE;
    }

    entry = SysmonRemoveHeadList(&g_SigningQueueList);
    SysmonInsertTailList(&g_SigningActiveList, entry);
    if (SysmonIsListEmpty(&g_SigningQueueList)) {
        ResetEvent(g_SigningQueueEvent);
    }
    InterlockedDecrement(&g_SigningQueueDepth);
    LeaveCriticalSection(&g_SigningQueueLock);

    *WorkItem = CONTAINING_RECORD(entry, SYSMON_ENRICHMENT_WORK_ITEM, ListEntry);
    return TRUE;
}

static VOID
SysmonDetachPendingEventsLocked(
    _Inout_ PSYSMON_ENRICHMENT_WORK_ITEM WorkItem,
    _Out_ PLIST_ENTRY PendingList)
{
    DWORD detachedCount = WorkItem->PendingEventCount;

    *PendingList = WorkItem->PendingEvents;
    PendingList->Flink->Blink = PendingList;
    PendingList->Blink->Flink = PendingList;
    SysmonInitializeListHead(&WorkItem->PendingEvents);
    WorkItem->PendingEventCount = 0;
    if (detachedCount != 0) {
        InterlockedAdd(&g_SigningPendingEventDepth, -(LONG)detachedCount);
    }
}

static VOID
SysmonProcessQueuedEnrichmentWorkItem(
    _Inout_ PSYSMON_ENRICHMENT_WORK_ITEM WorkItem)
{
    BYTE *enrichedEvent;
    WCHAR resolvedHashes[512];
    LIST_ENTRY pendingList;

    if (WorkItem == NULL) {
        return;
    }

    enrichedEvent = (BYTE *)SYSMON_ALLOC(SYSMON_ENRICHED_EVENT_BUFFER_SIZE);
    resolvedHashes[0] = L'\0';

    SysmonInitializeListHead(&pendingList);
    for (;;) {
        EnterCriticalSection(&g_SigningQueueLock);
        if (SysmonIsListEmpty(&WorkItem->PendingEvents)) {
            SysmonRemoveEntryList(&WorkItem->ListEntry);
            SysmonInitializeListHead(&WorkItem->ListEntry);
            LeaveCriticalSection(&g_SigningQueueLock);
            break;
        }
        SysmonDetachPendingEventsLocked(WorkItem, &pendingList);
        LeaveCriticalSection(&g_SigningQueueLock);

        while (!SysmonIsListEmpty(&pendingList)) {
            PLIST_ENTRY entry;
            PSYSMON_PENDING_ENRICHMENT_EVENT pendingEvent;
            const BYTE *eventToDispatch;
            DWORD dispatchSize;
            WCHAR existingHashes[512];
            SYSMON_SIGNATURE_RESULT signatureResult;
            PCWSTR hashesToUse;
            const GUID *actionGuid;

            entry = SysmonRemoveHeadList(&pendingList);
            pendingEvent = CONTAINING_RECORD(entry, SYSMON_PENDING_ENRICHMENT_EVENT, ListEntry);
            eventToDispatch = pendingEvent->EventData;
            dispatchSize = pendingEvent->EventSize;
            existingHashes[0] = L'\0';
            ZeroMemory(&signatureResult, sizeof(signatureResult));
            hashesToUse = resolvedHashes;
            actionGuid = SysmonGetSignatureVerifyActionForEvent(pendingEvent->EventId);

            if (!SysmonExtractImageSignatureInputs(
                    pendingEvent->EventData,
                    pendingEvent->EventSize,
                    pendingEvent->EventId,
                    NULL,
                    0,
                    existingHashes,
                    RTL_NUMBER_OF(existingHashes))) {
                existingHashes[0] = L'\0';
            }

            if (!SysmonResolveImageEnrichmentBundle(
                    WorkItem->RawPath,
                    pendingEvent->EventId,
                    existingHashes,
                    WorkItem->CheckRevocation,
                    actionGuid,
                    WorkItem->HashMask,
                    &signatureResult,
                    resolvedHashes,
                    RTL_NUMBER_OF(resolvedHashes))) {
                hashesToUse = existingHashes;
            }

            if (enrichedEvent != NULL &&
                SysmonTryRebuildEnrichedImageSignatureEvent(
                    pendingEvent->EventData,
                    pendingEvent->EventSize,
                    pendingEvent->EventId,
                    &signatureResult,
                    hashesToUse,
                    enrichedEvent,
                    SYSMON_ENRICHED_EVENT_BUFFER_SIZE,
                    &dispatchSize)) {
                eventToDispatch = enrichedEvent;
            }

            if (InterlockedCompareExchange(&g_SigningWorkerRunning, 0, 0) == 0) {
                /* Service is stopping: free the event without dispatching it so a
                   slow worker never touches output/rules/config after teardown. */
                SysmonFreePendingEnrichmentEvent(pendingEvent);
                continue;
            }

            SysmonDispatchPreparedEvent(eventToDispatch, dispatchSize, pendingEvent->EventId);
            SysmonFreePendingEnrichmentEvent(pendingEvent);
        }
    }

    SYSMON_FREE(enrichedEvent);
}

static DWORD WINAPI
SysmonSigningWorkerThreadMain(
    _In_opt_ LPVOID Parameter)
{
    HANDLE waitHandles[2];
    DWORD waitCount;
    BOOL backgroundModeEnabled;

    UNREFERENCED_PARAMETER(Parameter);

    backgroundModeEnabled =
        SetThreadPriority(GetCurrentThread(), THREAD_MODE_BACKGROUND_BEGIN) != 0;
    waitHandles[0] = g_SigningQueueEvent;
    waitCount = 1;
    if (g_ServiceCtx.StopEvent != NULL) {
        waitHandles[waitCount++] = g_ServiceCtx.StopEvent;
    }

    while (InterlockedCompareExchange(&g_SigningWorkerRunning, 0, 0) != 0) {
        DWORD waitResult;
        PSYSMON_ENRICHMENT_WORK_ITEM workItem;

        waitResult = WaitForMultipleObjects(waitCount, waitHandles, FALSE, INFINITE);
        if (waitResult == WAIT_OBJECT_0 + 1) {
            break;
        }
        if (waitResult != WAIT_OBJECT_0) {
            continue;
        }

        while (SysmonPopQueuedEnrichmentWorkItem(&workItem)) {
            SysmonProcessQueuedEnrichmentWorkItem(workItem);
            SysmonFreeEnrichmentWorkItem(workItem);
            if (InterlockedCompareExchange(&g_SigningWorkerRunning, 0, 0) == 0) {
                break;
            }

            /*
             * ImageLoad cold-start bursts can enqueue hundreds of first-seen
             * DLLs. Yield between batches so the background signing worker
             * does not monopolize a core while foreground apps are still
             * starting up.
             */
            Sleep(1);
        }
    }

    if (backgroundModeEnabled) {
        (void)SetThreadPriority(GetCurrentThread(), THREAD_MODE_BACKGROUND_END);
    }

    return 0;
}

static BOOL
SysmonTryEnrichImageSignatureEvent(
    _In_reads_bytes_(EventSize) const BYTE *EventData,
    _In_ DWORD EventSize,
    _In_ SYSMON_EVENT_ID EventId,
    _In_ BOOL CheckRevocation,
    _Out_writes_bytes_(BufferSize) BYTE *Buffer,
    _In_ DWORD BufferSize,
    _Out_ PDWORD EnrichedSize)
{
    WCHAR imageLoaded[SYSMON_MAX_SIGNATURE_PATH_CHARS];
    WCHAR existingHashes[512];
    WCHAR resolvedHashes[512];
    SYSMON_SIGNATURE_RESULT signatureResult;
    DWORD hashMask;
    const GUID *actionGuid;

    if (EventData == NULL || Buffer == NULL || EnrichedSize == NULL) {
        return FALSE;
    }

    if (EventId != SysmonEventDriverLoad && EventId != SysmonEventImageLoad) {
        return FALSE;
    }

    imageLoaded[0] = L'\0';
    existingHashes[0] = L'\0';
    resolvedHashes[0] = L'\0';
    ZeroMemory(&signatureResult, sizeof(signatureResult));
    if (!SysmonExtractImageSignatureInputs(
            EventData,
            EventSize,
            EventId,
            imageLoaded,
            RTL_NUMBER_OF(imageLoaded),
            existingHashes,
            RTL_NUMBER_OF(existingHashes))) {
        return FALSE;
    }

    hashMask = SysmonGetConfiguredHashMask();
    actionGuid = SysmonGetSignatureVerifyActionForEvent(EventId);
    if (!SysmonResolveImageEnrichmentBundle(
            imageLoaded,
            EventId,
            existingHashes,
            CheckRevocation,
            actionGuid,
            hashMask,
            &signatureResult,
            resolvedHashes,
            RTL_NUMBER_OF(resolvedHashes))) {
        (void)SysmonResolveSignatureResult(
            imageLoaded,
            actionGuid,
            CheckRevocation,
            &signatureResult);

        if (EventId == SysmonEventDriverLoad) {
            SysmonResolveEventHashes(
                imageLoaded,
                existingHashes,
                signatureResult.ResolvedPath,
                hashMask,
                resolvedHashes,
                RTL_NUMBER_OF(resolvedHashes));
        } else {
            (void)SysmonCopyWideText(
                resolvedHashes,
                RTL_NUMBER_OF(resolvedHashes),
                existingHashes);
        }
    }

    return SysmonTryRebuildEnrichedImageSignatureEvent(
        EventData,
        EventSize,
        EventId,
        &signatureResult,
        resolvedHashes,
        Buffer,
        BufferSize,
        EnrichedSize);
}

/*
 * SysmonPipelineInit - Initialize the event pipeline.
 */
SYSMON_STATUS SysmonPipelineInit(void)
{
    int i;
    DWORD workerIndex;
    DWORD workerCount;

    if (InterlockedCompareExchange(&g_SigningPipelineInitialized, 0, 0) != 0) {
        return ERROR_ALREADY_INITIALIZED;
    }

    for (i = 0; i < 256; i++) {
        g_EventHandlers[i] = DefaultEventHandler;
    }

    ZeroMemory(g_SignatureCache, sizeof(g_SignatureCache));
    g_SignatureCacheVictim = 0;
    SysmonInitializeBucketHeads(g_SignatureCacheBuckets, RTL_NUMBER_OF(g_SignatureCacheBuckets));
    ZeroMemory(g_ImageEnrichmentCache, sizeof(g_ImageEnrichmentCache));
    g_ImageEnrichmentCacheVictim = 0;
    SysmonInitializeBucketHeads(g_ImageEnrichmentCacheBuckets, RTL_NUMBER_OF(g_ImageEnrichmentCacheBuckets));
    ZeroMemory(g_SigningWorkerThreads, sizeof(g_SigningWorkerThreads));
    g_SigningWorkerThreadCount = 0;
    InitializeCriticalSection(&g_SignatureCacheLock);
    InitializeCriticalSection(&g_ImageEnrichmentCacheLock);
    InitializeCriticalSection(&g_SigningQueueLock);
    SysmonInitializeListHead(&g_SigningQueueList);
    SysmonInitializeListHead(&g_SigningActiveList);
    g_SigningQueueEvent = CreateEventW(NULL, TRUE, FALSE, NULL);
    if (g_SigningQueueEvent == NULL) {
        InterlockedExchange(&g_SigningWorkerRunning, 0);
        InterlockedExchange(&g_SigningQueueDepth, 0);
        InterlockedExchange(&g_SigningPendingEventDepth, 0);
        DeleteCriticalSection(&g_SigningQueueLock);
        DeleteCriticalSection(&g_ImageEnrichmentCacheLock);
        DeleteCriticalSection(&g_SignatureCacheLock);
        return GetLastError();
    }

    InterlockedExchange(&g_SigningQueueDepth, 0);
    InterlockedExchange(&g_SigningWorkerRunning, 1);
    workerCount = SysmonGetConfiguredSigningWorkerCount();
    for (workerIndex = 0; workerIndex < workerCount; workerIndex++) {
        g_SigningWorkerThreads[workerIndex] = CreateThread(
            NULL,
            0,
            SysmonSigningWorkerThreadMain,
            NULL,
            0,
            NULL);
        if (g_SigningWorkerThreads[workerIndex] == NULL) {
            DWORD status = GetLastError();
            DWORD cleanupIndex;

            InterlockedExchange(&g_SigningWorkerRunning, 0);
            if (g_SigningQueueEvent != NULL) {
                SetEvent(g_SigningQueueEvent);
            }

            /* Wait for the workers that were created to fully exit before closing
               the event and deleting the locks they use (same exit confirmation as
               the normal cleanup path, P1 in the review). */
            for (cleanupIndex = 0; cleanupIndex < workerIndex; cleanupIndex++) {
                if (g_SigningWorkerThreads[cleanupIndex] != NULL) {
                    WaitForSingleObject(g_SigningWorkerThreads[cleanupIndex], INFINITE);
                    CloseHandle(g_SigningWorkerThreads[cleanupIndex]);
                    g_SigningWorkerThreads[cleanupIndex] = NULL;
                }
            }

            CloseHandle(g_SigningQueueEvent);
            g_SigningQueueEvent = NULL;
            DeleteCriticalSection(&g_SigningQueueLock);
            DeleteCriticalSection(&g_ImageEnrichmentCacheLock);
            DeleteCriticalSection(&g_SignatureCacheLock);
            InterlockedExchange(&g_SigningWorkerRunning, 0);
            InterlockedExchange(&g_SigningQueueDepth, 0);
            InterlockedExchange(&g_SigningPendingEventDepth, 0);
            return status;
        }

        g_SigningWorkerThreadCount += 1;
    }

    InterlockedExchange(&g_SigningPipelineInitialized, 1);
    return SYSMON_SUCCESS;
}

/*
 * SysmonPipelineCleanup - Free pipeline resources.
 */
void SysmonPipelineCleanup(void)
{
    DWORD workerIndex;

    if (InterlockedCompareExchange(&g_SigningPipelineInitialized, 0, 0) == 0) {
        return;
    }
    InterlockedExchange(&g_SigningPipelineInitialized, 0);

    InterlockedExchange(&g_SigningWorkerRunning, 0);
    if (g_SigningQueueEvent != NULL) {
        SetEvent(g_SigningQueueEvent);
    }
    for (workerIndex = 0; workerIndex < g_SigningWorkerThreadCount; workerIndex++) {
        if (g_SigningWorkerThreads[workerIndex] != NULL) {
            /* Wait indefinitely: a worker still inside a slow signature/revocation
               check finishes it (and any dispatch it already started), then
               observes g_SigningWorkerRunning == 0 and exits. Returning before
               every worker has exited would let the caller tear down
               output/rules/config that a still-running worker's dispatch touches
               (P1 in the review). */
            WaitForSingleObject(g_SigningWorkerThreads[workerIndex], INFINITE);
            CloseHandle(g_SigningWorkerThreads[workerIndex]);
            g_SigningWorkerThreads[workerIndex] = NULL;
        }
    }

    g_SigningWorkerThreadCount = 0;

    EnterCriticalSection(&g_SigningQueueLock);
    while (!SysmonIsListEmpty(&g_SigningQueueList)) {
        PLIST_ENTRY entry;
        PSYSMON_ENRICHMENT_WORK_ITEM workItem;

        entry = SysmonRemoveHeadList(&g_SigningQueueList);
        workItem = CONTAINING_RECORD(entry, SYSMON_ENRICHMENT_WORK_ITEM, ListEntry);
        LeaveCriticalSection(&g_SigningQueueLock);
        SysmonFreeEnrichmentWorkItem(workItem);
        EnterCriticalSection(&g_SigningQueueLock);
    }
    while (!SysmonIsListEmpty(&g_SigningActiveList)) {
        PLIST_ENTRY entry;
        PSYSMON_ENRICHMENT_WORK_ITEM workItem;

        entry = SysmonRemoveHeadList(&g_SigningActiveList);
        workItem = CONTAINING_RECORD(entry, SYSMON_ENRICHMENT_WORK_ITEM, ListEntry);
        LeaveCriticalSection(&g_SigningQueueLock);
        SysmonFreeEnrichmentWorkItem(workItem);
        EnterCriticalSection(&g_SigningQueueLock);
    }
    LeaveCriticalSection(&g_SigningQueueLock);

    if (g_SigningQueueEvent != NULL) {
        CloseHandle(g_SigningQueueEvent);
        g_SigningQueueEvent = NULL;
    }
    DeleteCriticalSection(&g_SigningQueueLock);
    DeleteCriticalSection(&g_SignatureCacheLock);
    DeleteCriticalSection(&g_ImageEnrichmentCacheLock);

    ZeroMemory(g_EventHandlers, sizeof(g_EventHandlers));
    ZeroMemory(g_SignatureCache, sizeof(g_SignatureCache));
    SysmonInitializeBucketHeads(g_SignatureCacheBuckets, RTL_NUMBER_OF(g_SignatureCacheBuckets));
    ZeroMemory(g_ImageEnrichmentCache, sizeof(g_ImageEnrichmentCache));
    SysmonInitializeBucketHeads(g_ImageEnrichmentCacheBuckets, RTL_NUMBER_OF(g_ImageEnrichmentCacheBuckets));
    ZeroMemory(g_SigningWorkerThreads, sizeof(g_SigningWorkerThreads));
    g_SignatureCacheVictim = 0;
    g_ImageEnrichmentCacheVictim = 0;
    InterlockedExchange(&g_SigningQueueDepth, 0);
    InterlockedExchange(&g_SigningPendingEventDepth, 0);
}

/*
 * SysmonPipelineDispatch - Process a raw event from driver.
 */
SYSMON_STATUS SysmonPipelineDispatch(PUCHAR EventData, DWORD BufferSize)
{
    SYSMON_STATUS status;
    SYSMON_EVENT_ID eventId;
    SYSMON_EVENT_HANDLER handler;
    PSYSMON_EVENT_HEADER header;
    const BYTE *eventToDispatch;
    DWORD eventSize;
    DWORD dispatchSize;
    BYTE *enrichedEvent = NULL;

    if (!EventData || BufferSize < SYSMON_EVENT_HEADER_SIZE) {
        return SYSMON_ERROR_INVALID_PARAM;
    }

    status = SYSMON_SUCCESS;

    header = (PSYSMON_EVENT_HEADER)EventData;
    eventId = (SYSMON_EVENT_ID)header->EventId;
    eventSize = header->EventSize;

    if (eventSize < SYSMON_EVENT_HEADER_SIZE) {
        return SYSMON_ERROR_INVALID_PARAM;
    }

    if (eventSize > BufferSize) {
        eventSize = BufferSize;
    }

    if ((unsigned)eventId >= _countof(g_EventHandlers)) {
        eventId = SysmonEventNone;
    }

    eventToDispatch = EventData;
    dispatchSize = eventSize;

    if (eventId == SysmonEventDriverLoad || eventId == SysmonEventImageLoad) {
        BOOL checkRevocation;
        DWORD hashMask;
        BOOL runtimeHasEvent;
        BOOL filterNeedsUserModeEnrichment;
        PSYSMON_RULE_RUNTIME runtime;
        DWORD imageRuleRequirements;
        const BYTE *filterEventData;
        DWORD filterEventSize;

        if (eventId == SysmonEventImageLoad &&
            SysmonIsSelfImageLoadEvent(EventData, eventSize)) {
            return SYSMON_SUCCESS;
        }

        {
            CriticalSectionGuard configLock(&g_ServiceCtx.ConfigLock);

            checkRevocation = g_ServiceCtx.Config.CheckRevocation;
            hashMask = g_ServiceCtx.Config.HashingAlgorithm;
            runtime = g_ServiceCtx.RuleRuntime;
            runtimeHasEvent = (runtime != NULL) &&
                SysmonRuleRuntimeEventCanProduceLogs(runtime, eventId);
            imageRuleRequirements = runtimeHasEvent
                ? SysmonGetImageRuleRequirements(runtime, eventId)
                : SysmonImageRuleRequirementNone;
            filterNeedsUserModeEnrichment =
                (imageRuleRequirements & SysmonImageRuleRequirementUserModeFields) != 0;
            filterEventData = EventData;
            filterEventSize = eventSize;

            if (runtime != NULL && !runtimeHasEvent) {
                goto cleanup;
            }

            if (runtimeHasEvent &&
                SysmonGetEnrichedEventBuffer(&enrichedEvent) != NULL &&
                SysmonTryNormalizeImageSignaturePathsForFiltering(
                    EventData,
                    eventSize,
                    eventId,
                    enrichedEvent,
                    SYSMON_ENRICHED_EVENT_BUFFER_SIZE,
                    &filterEventSize)) {
                filterEventData = enrichedEvent;
            }

            /*
             * Most ImageLoad rules in real-world configs only inspect raw fields such
             * as Image/ImageLoaded. If the current rule set does not depend on
             * user-mode-only signature fields, evaluate the filter before running
             * expensive enrichment so excluded events do not pay the full
             * signature-verification cost.
             */
            if (runtimeHasEvent &&
                !filterNeedsUserModeEnrichment) {
                if (!SysmonShouldCaptureEvent(runtime, eventId, filterEventData, filterEventSize)) {
                    goto cleanup;
                }
            } else if (runtimeHasEvent &&
                       filterNeedsUserModeEnrichment) {
                /*
                 * Mixed raw/enriched ImageLoad rules can still often be rejected
                 * from raw Image/ImageLoaded fields alone. If the raw-field subset
                 * already proves the event can never match any final include path,
                 * drop it before queuing signature work.
                 */
                if (SysmonCanEarlyRejectImageEvent(runtime, eventId, filterEventData, filterEventSize)) {
                    goto cleanup;
                }
            }
        }

        /*
         * Filtering can often be decided from raw Image/ImageLoaded fields alone,
         * but the final event payload can still need user-mode signature and
         * version enrichment before emission.
         */
        if (SysmonQueueImageSignatureEnrichment(
                EventData,
                eventSize,
                eventId,
                checkRevocation,
                hashMask)) {
            goto cleanup;
        }

        /*
         * Official Sysmon appears to prefer staged asynchronous ImageLoad
         * enrichment and limit/queue pressure rather than dragging the full
         * signing/hash path back onto the dispatch thread. Keep DriverLoad on
         * the synchronous fallback because it is relatively rare and more
         * correctness-sensitive, but let bursty ImageLoad traffic flow through
         * with the driver's already-populated fields when the enrichment queue
         * is unavailable or saturated.
         */
        if (eventId == SysmonEventImageLoad) {
            eventToDispatch = EventData;
            dispatchSize = eventSize;
        } else
        if (SysmonGetEnrichedEventBuffer(&enrichedEvent) != NULL &&
            SysmonTryEnrichImageSignatureEvent(
                EventData,
                eventSize,
                eventId,
                checkRevocation,
                enrichedEvent,
                SYSMON_ENRICHED_EVENT_BUFFER_SIZE,
                &dispatchSize)) {
            eventToDispatch = enrichedEvent;
        }
    }

    handler = g_EventHandlers[eventId];
    if (eventId == SysmonEventDriverLoad || eventId == SysmonEventImageLoad) {
        UNREFERENCED_PARAMETER(handler);
        SysmonDispatchPreparedEvent(eventToDispatch, dispatchSize, eventId);
        goto cleanup;
    }

    if (handler != NULL) {
        handler((PUCHAR)eventToDispatch, dispatchSize, eventId);
    }

cleanup:
    SYSMON_FREE(enrichedEvent);
    return status;
}

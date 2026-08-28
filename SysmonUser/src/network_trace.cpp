#include "../include/network_trace.h"

#include "../include/config.h"
#include "../include/event.h"
#include "../include/packed_read.hpp"
#include "../include/pipeline.h"
#include "../include/rules.h"
#include "../include/runtime.hpp"
#include "../include/service.h"
#include "../include/source_common.h"

#include <evntrace.h>
#include <evntcons.h>
#include <tdh.h>
#include <psapi.h>
#include <sddl.h>
#include <wincrypt.h>
#include <winsock2.h>
#include <ws2tcpip.h>

#define SYSMON_NETWORK_TRACE_SESSION_NAME L"SYSMON TRACE"
#define SYSMON_NETWORK_TRACE_BUFFER_SIZE  8192
#define SYSMON_NETWORK_DEDUP_CAPACITY     1100
#define SYSMON_NETWORK_DEDUP_WINDOW       9000000000ULL
#define SYSMON_NETWORK_NAME_CACHE_CAPACITY 256
#define SYSMON_NETWORK_NAME_WORK_LIMIT     64
#define SYSMON_NETWORK_NAME_POSITIVE_TTL  900000ULL
#define SYSMON_NETWORK_NAME_NEGATIVE_TTL  300000ULL

static const GUID SYSMON_KERNEL_NETWORK_PROVIDER = {
    0x7dd42a49, 0x5329, 0x4832, { 0x8d, 0xfd, 0x43, 0xd9, 0x79, 0x15, 0x3a, 0x88 }
};

typedef struct _SYSMON_TRACE_PROPERTIES_BUFFER {
    EVENT_TRACE_PROPERTIES Properties;
    WCHAR SessionName[64];
} SYSMON_TRACE_PROPERTIES_BUFFER, *PSYSMON_TRACE_PROPERTIES_BUFFER;

typedef struct _SYSMON_NETWORK_EVENT_DATA {
    DWORD ProcessId;
    ULONGLONG Timestamp;
    BOOL Initiated;
    BOOL SourceIsIpv6;
    BOOL DestinationIsIpv6;
    DWORD SourcePort;
    DWORD DestinationPort;
    WCHAR Protocol[8];
    WCHAR SourceIp[64];
    WCHAR DestinationIp[64];
} SYSMON_NETWORK_EVENT_DATA, *PSYSMON_NETWORK_EVENT_DATA;

typedef struct _SYSMON_NETWORK_DEDUP_ENTRY {
    DWORD ProcessId;
    DWORD SourcePort;
    DWORD DestinationPort;
    BOOL Initiated;
    WCHAR Protocol[8];
    WCHAR SourceIp[64];
    WCHAR DestinationIp[64];
    ULONGLONG LastSeen;
} SYSMON_NETWORK_DEDUP_ENTRY, *PSYSMON_NETWORK_DEDUP_ENTRY;

typedef struct _SYSMON_NETWORK_NAME_CACHE_ENTRY {
    BOOL InUse;
    BOOL Pending;
    BOOL Negative;
    ULONGLONG ExpireTick;
    WCHAR Key[128];
    WCHAR Value[256];
} SYSMON_NETWORK_NAME_CACHE_ENTRY, *PSYSMON_NETWORK_NAME_CACHE_ENTRY;

typedef struct _SYSMON_NETWORK_NAME_REQUEST {
    BOOL ServiceLookup;
    BOOL IsIpv6;
    DWORD Port;
    WCHAR Key[128];
    WCHAR Address[64];
    CHAR Protocol[8];
} SYSMON_NETWORK_NAME_REQUEST, *PSYSMON_NETWORK_NAME_REQUEST;

static SRWLOCK g_NetworkNameCacheLock = SRWLOCK_INIT;
static SYSMON_NETWORK_NAME_CACHE_ENTRY g_NetworkNameCache[SYSMON_NETWORK_NAME_CACHE_CAPACITY];
static volatile LONG g_NetworkNameWorkCount = 0;
static INIT_ONCE g_NetworkWsaOnce = INIT_ONCE_STATIC_INIT;

static BOOL CALLBACK
SysmonInitializeNetworkWsa(
    PINIT_ONCE InitOnce,
    PVOID Parameter,
    PVOID *Context)
{
    WSADATA wsaData;

    UNREFERENCED_PARAMETER(InitOnce);
    UNREFERENCED_PARAMETER(Parameter);
    UNREFERENCED_PARAMETER(Context);
    return WSAStartup(MAKEWORD(2, 2), &wsaData) == 0;
}

static BOOL
SysmonNetworkNameCacheLookup(
    _In_z_ PCWSTR Key,
    _Out_writes_(ValueChars) PWCHAR Value,
    _In_ size_t ValueChars)
{
    ULONGLONG now = (ULONGLONG)GetTickCount64();
    LONG index;
    BOOL found = FALSE;

    if (Key == NULL || Value == NULL || ValueChars == 0) {
        return FALSE;
    }
    Value[0] = L'\0';
    AcquireSRWLockExclusive(&g_NetworkNameCacheLock);
    for (index = 0; index < SYSMON_NETWORK_NAME_CACHE_CAPACITY; index++) {
        PSYSMON_NETWORK_NAME_CACHE_ENTRY entry = &g_NetworkNameCache[index];
        if (!entry->InUse || _wcsicmp(entry->Key, Key) != 0) {
            continue;
        }
        if (entry->ExpireTick <= now) {
            ZeroMemory(entry, sizeof(*entry));
        } else if (!entry->Pending && !entry->Negative) {
            wcscpy_s(Value, ValueChars, entry->Value);
            found = TRUE;
        }
        break;
    }
    ReleaseSRWLockExclusive(&g_NetworkNameCacheLock);
    return found;
}

static BOOL
SysmonNetworkNameCacheReserve(_In_z_ PCWSTR Key)
{
    ULONGLONG now = (ULONGLONG)GetTickCount64();
    LONG index;
    LONG slot = -1;
    ULONGLONG oldest = ~(ULONGLONG)0;

    AcquireSRWLockExclusive(&g_NetworkNameCacheLock);
    for (index = 0; index < SYSMON_NETWORK_NAME_CACHE_CAPACITY; index++) {
        PSYSMON_NETWORK_NAME_CACHE_ENTRY entry = &g_NetworkNameCache[index];
        if (entry->InUse && _wcsicmp(entry->Key, Key) == 0) {
            if (entry->ExpireTick > now) {
                ReleaseSRWLockExclusive(&g_NetworkNameCacheLock);
                return FALSE;
            }
            slot = index;
            break;
        }
        if (!entry->InUse) {
            if (slot < 0) {
                slot = index;
            }
            continue;
        }
        if (entry->ExpireTick < oldest) {
            oldest = entry->ExpireTick;
            slot = index;
        }
    }
    if (slot >= 0) {
        PSYSMON_NETWORK_NAME_CACHE_ENTRY entry = &g_NetworkNameCache[slot];
        ZeroMemory(entry, sizeof(*entry));
        entry->InUse = TRUE;
        entry->Pending = TRUE;
        entry->ExpireTick = now + 10000;
        wcscpy_s(entry->Key, _countof(entry->Key), Key);
    }
    ReleaseSRWLockExclusive(&g_NetworkNameCacheLock);
    return slot >= 0;
}

static void
SysmonNetworkNameCacheStore(
    _In_z_ PCWSTR Key,
    _In_opt_z_ PCWSTR Value)
{
    ULONGLONG now = (ULONGLONG)GetTickCount64();
    LONG index;

    AcquireSRWLockExclusive(&g_NetworkNameCacheLock);
    for (index = 0; index < SYSMON_NETWORK_NAME_CACHE_CAPACITY; index++) {
        PSYSMON_NETWORK_NAME_CACHE_ENTRY entry = &g_NetworkNameCache[index];
        if (!entry->InUse || _wcsicmp(entry->Key, Key) != 0) {
            continue;
        }
        entry->Pending = FALSE;
        entry->Negative = Value == NULL || Value[0] == L'\0';
        entry->ExpireTick = now + (entry->Negative
            ? SYSMON_NETWORK_NAME_NEGATIVE_TTL
            : SYSMON_NETWORK_NAME_POSITIVE_TTL);
        if (!entry->Negative) {
            wcscpy_s(entry->Value, _countof(entry->Value), Value);
        }
        break;
    }
    ReleaseSRWLockExclusive(&g_NetworkNameCacheLock);
}

static DWORD WINAPI
SysmonNetworkNameWorker(_In_ LPVOID Parameter)
{
    PSYSMON_NETWORK_NAME_REQUEST request = (PSYSMON_NETWORK_NAME_REQUEST)Parameter;
    WCHAR value[256];
    sockaddr_storage address;
    int addressLength;
    servent *service;

    if (request == NULL) {
        return 0;
    }
    value[0] = L'\0';
    if (request->ServiceLookup) {
        service = getservbyport(htons((u_short)request->Port), request->Protocol);
        if (service != NULL) {
            MultiByteToWideChar(CP_ACP, 0, service->s_name, -1, value, _countof(value));
        }
    } else {
        ZeroMemory(&address, sizeof(address));
        addressLength = request->IsIpv6 ? sizeof(sockaddr_in6) : sizeof(sockaddr_in);
        if (request->IsIpv6) {
            sockaddr_in6 *ipv6 = (sockaddr_in6 *)&address;
            ipv6->sin6_family = AF_INET6;
            InetPtonW(AF_INET6, request->Address, &ipv6->sin6_addr);
        } else {
            sockaddr_in *ipv4 = (sockaddr_in *)&address;
            ipv4->sin_family = AF_INET;
            InetPtonW(AF_INET, request->Address, &ipv4->sin_addr);
        }
        if (GetNameInfoW(
                (sockaddr *)&address,
                (socklen_t)addressLength,
                value,
                _countof(value),
                NULL,
                0,
                NI_NAMEREQD) != 0) {
            value[0] = L'\0';
        }
    }
    SysmonNetworkNameCacheStore(request->Key, value[0] != L'\0' ? value : NULL);
    InterlockedDecrement(&g_NetworkNameWorkCount);
    SYSMON_FREE(request);
    return 0;
}

static void
SysmonQueueNetworkNameLookup(
    _In_z_ PCWSTR Key,
    _In_opt_z_ PCWSTR Address,
    _In_ BOOL IsIpv6,
    _In_ BOOL ServiceLookup,
    _In_ DWORD Port,
    _In_z_ PCSTR Protocol)
{
    PSYSMON_NETWORK_NAME_REQUEST request;

    if (InterlockedIncrement(&g_NetworkNameWorkCount) > SYSMON_NETWORK_NAME_WORK_LIMIT) {
        InterlockedDecrement(&g_NetworkNameWorkCount);
        return;
    }
    if (!SysmonNetworkNameCacheReserve(Key)) {
        InterlockedDecrement(&g_NetworkNameWorkCount);
        return;
    }
    request = (PSYSMON_NETWORK_NAME_REQUEST)SYSMON_ALLOC(sizeof(*request));
    if (request == NULL) {
        SysmonNetworkNameCacheStore(Key, NULL);
        InterlockedDecrement(&g_NetworkNameWorkCount);
        return;
    }
    ZeroMemory(request, sizeof(*request));
    request->ServiceLookup = ServiceLookup;
    request->IsIpv6 = IsIpv6;
    request->Port = Port;
    wcscpy_s(request->Key, _countof(request->Key), Key);
    if (Address != NULL) {
        wcscpy_s(request->Address, _countof(request->Address), Address);
    }
    strncpy_s(request->Protocol, _countof(request->Protocol), Protocol, _TRUNCATE);
    if (!QueueUserWorkItem(SysmonNetworkNameWorker, request, WT_EXECUTEDEFAULT)) {
        SysmonNetworkNameCacheStore(Key, NULL);
        InterlockedDecrement(&g_NetworkNameWorkCount);
        SYSMON_FREE(request);
    }
}

struct _SYSMON_NETWORK_TRACE_CONTEXT {
    PSYSMON_SERVICE_CONTEXT ServiceContext;
    HANDLE ThreadHandle;
    TRACEHANDLE SessionHandle;
    TRACEHANDLE ConsumerHandle;
    SYSMON_TRACE_PROPERTIES_BUFFER Properties;
    PSYSMON_RULE_RUNTIME RuleRuntime;
    const BYTE *RuleSourceBlob;
    DWORD RuleSourceBlobSize;
    WCHAR LocalHostname[256];
    BOOL WsaStarted;
    BOOL OwnsSession;
    DWORD NetworkDedupCount;
    SYSMON_NETWORK_DEDUP_ENTRY NetworkDedup[SYSMON_NETWORK_DEDUP_CAPACITY];
    volatile LONG StopRequested;
};

static ULONGLONG
SysmonNetworkCurrentFileTime(void)
{
    FILETIME fileTime;
    ULARGE_INTEGER value;

    GetSystemTimeAsFileTime(&fileTime);
    value.LowPart = fileTime.dwLowDateTime;
    value.HighPart = fileTime.dwHighDateTime;
    return value.QuadPart;
}

static BOOL
SysmonNetworkEventIsDuplicate(
    _Inout_ PSYSMON_NETWORK_TRACE_CONTEXT Context,
    _In_ const SYSMON_NETWORK_EVENT_DATA *NetworkData)
{
    ULONGLONG now;
    DWORD index;
    DWORD oldestIndex = 0;
    ULONGLONG oldestTime = ~(ULONGLONG)0;

    if (Context == NULL || NetworkData == NULL) {
        return TRUE;
    }

    now = SysmonNetworkCurrentFileTime();
    for (index = 0; index < Context->NetworkDedupCount; index++) {
        PSYSMON_NETWORK_DEDUP_ENTRY entry = &Context->NetworkDedup[index];

        if (now >= entry->LastSeen && now - entry->LastSeen > SYSMON_NETWORK_DEDUP_WINDOW) {
            *entry = Context->NetworkDedup[Context->NetworkDedupCount - 1];
            Context->NetworkDedupCount -= 1;
            index -= 1;
            continue;
        }

        if (entry->LastSeen < oldestTime) {
            oldestTime = entry->LastSeen;
            oldestIndex = index;
        }

        if (entry->ProcessId == NetworkData->ProcessId &&
            entry->SourcePort == NetworkData->SourcePort &&
            entry->DestinationPort == NetworkData->DestinationPort &&
            entry->Initiated == NetworkData->Initiated &&
            _wcsicmp(entry->Protocol, NetworkData->Protocol) == 0 &&
            _wcsicmp(entry->SourceIp, NetworkData->SourceIp) == 0 &&
            _wcsicmp(entry->DestinationIp, NetworkData->DestinationIp) == 0) {
            entry->LastSeen = now;
            return TRUE;
        }
    }

    if (Context->NetworkDedupCount < SYSMON_NETWORK_DEDUP_CAPACITY) {
        oldestIndex = Context->NetworkDedupCount++;
    }

    {
        PSYSMON_NETWORK_DEDUP_ENTRY entry = &Context->NetworkDedup[oldestIndex];
        ZeroMemory(entry, sizeof(*entry));
        entry->ProcessId = NetworkData->ProcessId;
        entry->SourcePort = NetworkData->SourcePort;
        entry->DestinationPort = NetworkData->DestinationPort;
        entry->Initiated = NetworkData->Initiated;
        wcscpy_s(entry->Protocol, _countof(entry->Protocol), NetworkData->Protocol);
        wcscpy_s(entry->SourceIp, _countof(entry->SourceIp), NetworkData->SourceIp);
        wcscpy_s(entry->DestinationIp, _countof(entry->DestinationIp), NetworkData->DestinationIp);
        entry->LastSeen = now;
    }

    return FALSE;
}

static void
SysmonLookupNetworkNames(
    _In_ const SYSMON_NETWORK_EVENT_DATA *NetworkData,
    _In_ BOOL DnsLookup,
    _Out_writes_(SourceHostnameChars) PWCHAR SourceHostname,
    _In_ size_t SourceHostnameChars,
    _Out_writes_(DestinationHostnameChars) PWCHAR DestinationHostname,
    _In_ size_t DestinationHostnameChars,
    _Out_writes_(SourcePortNameChars) PWCHAR SourcePortName,
    _In_ size_t SourcePortNameChars,
    _Out_writes_(DestinationPortNameChars) PWCHAR DestinationPortName,
    _In_ size_t DestinationPortNameChars)
{
    PCSTR protocol;
    WCHAR key[128];
    WCHAR cached[256];

    SysmonCopyOrPlaceholder(SourceHostname, SourceHostnameChars, L"-");
    SysmonCopyOrPlaceholder(DestinationHostname, DestinationHostnameChars, L"-");
    SysmonCopyOrPlaceholder(SourcePortName, SourcePortNameChars, L"-");
    SysmonCopyOrPlaceholder(DestinationPortName, DestinationPortNameChars, L"-");

    if (NetworkData == NULL) {
        return;
    }

    if (!DnsLookup) {
        return;
    }

    protocol = _wcsicmp(NetworkData->Protocol, L"udp") == 0 ? "udp" : "tcp";

    _snwprintf_s(key, _countof(key), _TRUNCATE, L"svc:%hs:%lu", protocol, (unsigned long)NetworkData->SourcePort);
    if (SysmonNetworkNameCacheLookup(key, cached, _countof(cached))) {
        SysmonCopyOrPlaceholder(SourcePortName, SourcePortNameChars, cached);
    } else {
        SysmonQueueNetworkNameLookup(key, NULL, FALSE, TRUE, NetworkData->SourcePort, protocol);
    }

    _snwprintf_s(key, _countof(key), _TRUNCATE, L"svc:%hs:%lu", protocol, (unsigned long)NetworkData->DestinationPort);
    if (SysmonNetworkNameCacheLookup(key, cached, _countof(cached))) {
        SysmonCopyOrPlaceholder(DestinationPortName, DestinationPortNameChars, cached);
    } else {
        SysmonQueueNetworkNameLookup(key, NULL, FALSE, TRUE, NetworkData->DestinationPort, protocol);
    }

    _snwprintf_s(key, _countof(key), _TRUNCATE, L"host:%ls", NetworkData->SourceIp);
    if (SysmonNetworkNameCacheLookup(key, cached, _countof(cached))) {
        SysmonCopyOrPlaceholder(SourceHostname, SourceHostnameChars, cached);
    } else {
        SysmonQueueNetworkNameLookup(key, NetworkData->SourceIp, NetworkData->SourceIsIpv6, FALSE, 0, protocol);
    }

    _snwprintf_s(key, _countof(key), _TRUNCATE, L"host:%ls", NetworkData->DestinationIp);
    if (SysmonNetworkNameCacheLookup(key, cached, _countof(cached))) {
        SysmonCopyOrPlaceholder(DestinationHostname, DestinationHostnameChars, cached);
    } else {
        SysmonQueueNetworkNameLookup(key, NetworkData->DestinationIp, NetworkData->DestinationIsIpv6, FALSE, 0, protocol);
    }
}

/* The Microsoft-Windows-Kernel-Network provider payload layouts below mirror the
   MOF event definitions and have been stable since Windows Vista (Wireshark and
   other decoders use the same fixed layouts). They are NOT version-negotiated:
   if a future Windows release changes a payload, the size-mismatch check in
   SysmonValidateNetworkEventPayloadSize logs a diagnostic instead of silently
   producing wrong network events (U3 in the 2026-08-04 review). */
#pragma pack(push, 1)
typedef struct _SYSMON_ETW_TCP_IPV4_EVENT {
    ULONG Pid;
    ULONG Size;
    ULONG DestinationAddress;
    ULONG SourceAddress;
    USHORT DestinationPort;
    USHORT SourcePort;
    USHORT Mss;
    USHORT SackOpt;
    USHORT TsOpt;
    USHORT WsOpt;
    ULONG ReceiveWindow;
    USHORT ReceiveWindowScale;
    USHORT SendWindowScale;
    ULONG SequenceNumber;
    ULONG ConnectionId;
} SYSMON_ETW_TCP_IPV4_EVENT, *PSYSMON_ETW_TCP_IPV4_EVENT;

typedef struct _SYSMON_ETW_TCP_IPV6_EVENT {
    ULONG Pid;
    ULONG Size;
    BYTE DestinationAddress[16];
    BYTE SourceAddress[16];
    USHORT DestinationPort;
    USHORT SourcePort;
    USHORT Mss;
    USHORT SackOpt;
    USHORT TsOpt;
    USHORT WsOpt;
    ULONG ReceiveWindow;
    USHORT ReceiveWindowScale;
    USHORT SendWindowScale;
    ULONG SequenceNumber;
    ULONG ConnectionId;
} SYSMON_ETW_TCP_IPV6_EVENT, *PSYSMON_ETW_TCP_IPV6_EVENT;

typedef struct _SYSMON_ETW_UDP_IPV4_EVENT {
    ULONG Pid;
    ULONG Size;
    ULONG DestinationAddress;
    ULONG SourceAddress;
    USHORT DestinationPort;
    USHORT SourcePort;
    ULONG SequenceNumber;
    ULONG ConnectionId;
} SYSMON_ETW_UDP_IPV4_EVENT, *PSYSMON_ETW_UDP_IPV4_EVENT;

typedef struct _SYSMON_ETW_UDP_IPV6_EVENT {
    ULONG Pid;
    ULONG Size;
    BYTE DestinationAddress[16];
    BYTE SourceAddress[16];
    USHORT DestinationPort;
    USHORT SourcePort;
    ULONG SequenceNumber;
    ULONG ConnectionId;
} SYSMON_ETW_UDP_IPV6_EVENT, *PSYSMON_ETW_UDP_IPV6_EVENT;
#pragma pack(pop)

static BOOL
SysmonIsSupportedNetworkEventId(
    _In_ USHORT EventId)
{
    switch (EventId) {
    case 12:
    case 15:
    case 28:
    case 31:
    case 42:
    case 43:
    case 58:
    case 59:
        return TRUE;
    default:
        return FALSE;
    }
}

static void
SysmonFormatUtcTimestamp(
    _In_ ULONGLONG RawTimestamp,
    _Out_writes_(BufferChars) PWCHAR Buffer,
    _In_ size_t BufferChars,
    _Out_opt_ PULONGLONG Timestamp)
{
    (void)SysmonFormatSyntheticUtcTimestamp(RawTimestamp, Buffer, BufferChars, Timestamp);
}

static void
SysmonFormatIpv4Address(
    _In_ ULONG Address,
    _Out_writes_(BufferChars) PWCHAR Buffer,
    _In_ size_t BufferChars)
{
    IN_ADDR addr;

    if (Buffer == NULL || BufferChars == 0) {
        return;
    }

    addr.S_un.S_addr = Address;
    if (InetNtopW(AF_INET, &addr, Buffer, (DWORD)BufferChars) == NULL) {
        SysmonCopyOrPlaceholder(Buffer, BufferChars, L"-");
    }
}

static void
SysmonFormatIpv6Address(
    _In_reads_(16) const BYTE *Address,
    _Out_writes_(BufferChars) PWCHAR Buffer,
    _In_ size_t BufferChars)
{
    if (Buffer == NULL || BufferChars == 0) {
        return;
    }

    if (Address == NULL || InetNtopW(AF_INET6, (PVOID)Address, Buffer, (DWORD)BufferChars) == NULL) {
        SysmonCopyOrPlaceholder(Buffer, BufferChars, L"-");
    }
}

/* Layout-drift warnings are logged at most once per (event id, payload length)
   so a Windows release that appends a field does not spam the log on the network
   hot path (P2 in the review). The network trace callback runs on a single
   ProcessTrace thread, so no lock is needed. */
#define SYSMON_NETWORK_LAYOUT_WARN_CAPACITY 16
struct SysmonNetworkLayoutWarnEntry {
    USHORT EventId;
    ULONG Length;
};
static SysmonNetworkLayoutWarnEntry g_networkLayoutWarnings[SYSMON_NETWORK_LAYOUT_WARN_CAPACITY];
static LONG g_networkLayoutWarnCursor = 0;

static BOOL
SysmonNoteNetworkLayoutWarning(
    _In_ USHORT EventId,
    _In_ ULONG UserDataLength)
{
    LONG i;

    for (i = 0; i < SYSMON_NETWORK_LAYOUT_WARN_CAPACITY; i++) {
        if (g_networkLayoutWarnings[i].EventId == EventId &&
            g_networkLayoutWarnings[i].Length == UserDataLength) {
            return FALSE; /* already reported */
        }
    }

    {
        LONG slot = InterlockedIncrement(&g_networkLayoutWarnCursor) - 1;
        LONG index = slot % SYSMON_NETWORK_LAYOUT_WARN_CAPACITY;

        g_networkLayoutWarnings[index].EventId = EventId;
        g_networkLayoutWarnings[index].Length = UserDataLength;
    }

    return TRUE;
}

static BOOL
SysmonValidateNetworkEventPayloadSize(
    _In_ USHORT EventId,
    _In_ ULONG UserDataLength,
    _In_ ULONG ExpectedSize)
{
    /* The provider may append fields or add alignment padding on a newer
       Windows build. The fields consumed here are a stable prefix, so reject
       only truncated records and keep a once-per-layout diagnostic for longer
       records instead of silently dropping valid Event 3 connections. */
    if (UserDataLength < ExpectedSize) {
        return FALSE;
    }
    if (UserDataLength != ExpectedSize) {
        /* Any size mismatch is treated as an unknown layout. Parsing a prefix
           would silently reinterpret fields when a provider changes offsets or
           inserts data, which is worse than dropping one event. */
        if (SysmonNoteNetworkLayoutWarning(EventId, UserDataLength)) {
            SysmonLogWarning(
                SYSMON_COMPONENT_SERVICE,
                "Kernel network event %u payload size %lu exceeds known prefix %lu; event layout may have appended fields",
                (unsigned)EventId,
                (unsigned long)UserDataLength,
                (unsigned long)ExpectedSize);
        }
        return FALSE;
    }

    return TRUE;
}

static BOOL
SysmonNetworkGetPropertySize(
    _In_ const EVENT_RECORD *EventRecord,
    _In_z_ PCWSTR PropertyName,
    _Out_ PULONG PropertySize)
{
    PROPERTY_DATA_DESCRIPTOR descriptor;

    if (EventRecord == NULL || PropertyName == NULL || PropertySize == NULL) {
        return FALSE;
    }
    ZeroMemory(&descriptor, sizeof(descriptor));
    descriptor.PropertyName = (ULONGLONG)(ULONG_PTR)PropertyName;
    descriptor.ArrayIndex = ULONG_MAX;
    return TdhGetPropertySize(
        (PEVENT_RECORD)EventRecord,
        0,
        NULL,
        1,
        &descriptor,
        PropertySize) == ERROR_SUCCESS;
}

static BOOL
SysmonNetworkGetUInt32Property(
    _In_ const EVENT_RECORD *EventRecord,
    _In_z_ PCWSTR PropertyName,
    _Out_ PDWORD Value)
{
    PROPERTY_DATA_DESCRIPTOR descriptor;
    ULONG propertySize = 0;
    BYTE raw[sizeof(ULONGLONG)] = { 0 };
    WCHAR text[64];

    if (Value == NULL || !SysmonNetworkGetPropertySize(EventRecord, PropertyName, &propertySize)) {
        return FALSE;
    }
    ZeroMemory(&descriptor, sizeof(descriptor));
    descriptor.PropertyName = (ULONGLONG)(ULONG_PTR)PropertyName;
    descriptor.ArrayIndex = ULONG_MAX;
    if (propertySize <= sizeof(raw) &&
        TdhGetProperty(
            (PEVENT_RECORD)EventRecord,
            0,
            NULL,
            1,
            &descriptor,
            propertySize,
            raw) == ERROR_SUCCESS) {
        switch (propertySize) {
        case sizeof(BYTE):
            *Value = raw[0];
            return TRUE;
        case sizeof(USHORT):
            *Value = *(const USHORT *)raw;
            return TRUE;
        case sizeof(ULONG):
            *Value = *(const ULONG *)raw;
            return TRUE;
        default:
            break;
        }
    }
    ZeroMemory(text, sizeof(text));
    if (propertySize >= sizeof(WCHAR) && propertySize <= sizeof(text) &&
        TdhGetProperty(
            (PEVENT_RECORD)EventRecord,
            0,
            NULL,
            1,
            &descriptor,
            sizeof(text) - sizeof(WCHAR),
            (PBYTE)text) == ERROR_SUCCESS) {
        *Value = wcstoul(text, NULL, 0);
        return TRUE;
    }
    return FALSE;
}

static BOOL
SysmonNetworkGetStringProperty(
    _In_ const EVENT_RECORD *EventRecord,
    _In_z_ PCWSTR PropertyName,
    _Out_writes_(BufferChars) PWCHAR Buffer,
    _In_ size_t BufferChars)
{
    PROPERTY_DATA_DESCRIPTOR descriptor;
    ULONG propertySize = 0;
    ULONG copyBytes;

    if (Buffer == NULL || BufferChars == 0 ||
        !SysmonNetworkGetPropertySize(EventRecord, PropertyName, &propertySize) ||
        propertySize == 0) {
        return FALSE;
    }
    ZeroMemory(&descriptor, sizeof(descriptor));
    descriptor.PropertyName = (ULONGLONG)(ULONG_PTR)PropertyName;
    descriptor.ArrayIndex = ULONG_MAX;
    copyBytes = (ULONG)((BufferChars - 1) * sizeof(WCHAR));
    if (TdhGetProperty(
            (PEVENT_RECORD)EventRecord,
            0,
            NULL,
            1,
            &descriptor,
            copyBytes,
            (PBYTE)Buffer) != ERROR_SUCCESS) {
        return FALSE;
    }
    Buffer[BufferChars - 1] = L'\0';
    return Buffer[0] != L'\0';
}

static BOOL
SysmonParseNetworkEventRecordByTdh(
    _In_ const EVENT_RECORD *EventRecord,
    _Out_ PSYSMON_NETWORK_EVENT_DATA NetworkData)
{
    USHORT eventId;
    DWORD pid;
    DWORD sourcePort;
    DWORD destinationPort;

    if (EventRecord == NULL || NetworkData == NULL || EventRecord->UserData == NULL) {
        return FALSE;
    }
    eventId = EventRecord->EventHeader.EventDescriptor.Id;
    if (!SysmonIsSupportedNetworkEventId(eventId) ||
        !SysmonNetworkGetUInt32Property(EventRecord, L"PID", &pid) ||
        !SysmonNetworkGetUInt32Property(EventRecord, L"sport", &sourcePort) ||
        !SysmonNetworkGetUInt32Property(EventRecord, L"dport", &destinationPort) ||
        !SysmonNetworkGetStringProperty(EventRecord, L"saddr", NetworkData->SourceIp, _countof(NetworkData->SourceIp)) ||
        !SysmonNetworkGetStringProperty(EventRecord, L"daddr", NetworkData->DestinationIp, _countof(NetworkData->DestinationIp))) {
        return FALSE;
    }

    NetworkData->ProcessId = pid;
    NetworkData->Timestamp = (ULONGLONG)EventRecord->EventHeader.TimeStamp.QuadPart;
    NetworkData->Initiated = eventId == 12 || eventId == 28 || eventId == 42 || eventId == 58;
    NetworkData->SourceIsIpv6 = eventId == 28 || eventId == 31 || eventId == 58 || eventId == 59;
    NetworkData->DestinationIsIpv6 = NetworkData->SourceIsIpv6;
    NetworkData->SourcePort = sourcePort;
    NetworkData->DestinationPort = destinationPort;
    wcscpy_s(
        NetworkData->Protocol,
        _countof(NetworkData->Protocol),
        eventId == 42 || eventId == 43 || eventId == 58 || eventId == 59 ? L"udp" : L"tcp");
    return TRUE;
}

static BOOL
SysmonParseNetworkEventRecord(
    _In_ const EVENT_RECORD *EventRecord,
    _Out_ PSYSMON_NETWORK_EVENT_DATA NetworkData)
{
    USHORT eventId;

    if (EventRecord == NULL || NetworkData == NULL) {
        return FALSE;
    }

    ZeroMemory(NetworkData, sizeof(*NetworkData));
    if (EventRecord->UserData == NULL ||
        EventRecord->EventHeader.EventDescriptor.Version != 0) {
        return FALSE;
    }
    eventId = EventRecord->EventHeader.EventDescriptor.Id;
    NetworkData->Timestamp = (ULONGLONG)EventRecord->EventHeader.TimeStamp.QuadPart;

    switch (eventId) {
    case 12:
    case 15:
    {
        const SYSMON_ETW_TCP_IPV4_EVENT *record = (const SYSMON_ETW_TCP_IPV4_EVENT *)EventRecord->UserData;

        if (!SysmonValidateNetworkEventPayloadSize(eventId, EventRecord->UserDataLength, (ULONG)sizeof(*record))) {
            return FALSE;
        }

        NetworkData->ProcessId = record->Pid;
        NetworkData->Initiated = (eventId == 12);
        NetworkData->SourceIsIpv6 = FALSE;
        NetworkData->DestinationIsIpv6 = FALSE;
        NetworkData->SourcePort = ntohs(record->SourcePort);
        NetworkData->DestinationPort = ntohs(record->DestinationPort);
        wcscpy_s(NetworkData->Protocol, _countof(NetworkData->Protocol), L"tcp");
        SysmonFormatIpv4Address(record->SourceAddress, NetworkData->SourceIp, _countof(NetworkData->SourceIp));
        SysmonFormatIpv4Address(record->DestinationAddress, NetworkData->DestinationIp, _countof(NetworkData->DestinationIp));
        return TRUE;
    }

    case 28:
    case 31:
    {
        const SYSMON_ETW_TCP_IPV6_EVENT *record = (const SYSMON_ETW_TCP_IPV6_EVENT *)EventRecord->UserData;

        if (!SysmonValidateNetworkEventPayloadSize(eventId, EventRecord->UserDataLength, (ULONG)sizeof(*record))) {
            return FALSE;
        }

        NetworkData->ProcessId = record->Pid;
        NetworkData->Initiated = (eventId == 28);
        NetworkData->SourceIsIpv6 = TRUE;
        NetworkData->DestinationIsIpv6 = TRUE;
        NetworkData->SourcePort = ntohs(record->SourcePort);
        NetworkData->DestinationPort = ntohs(record->DestinationPort);
        wcscpy_s(NetworkData->Protocol, _countof(NetworkData->Protocol), L"tcp");
        SysmonFormatIpv6Address(record->SourceAddress, NetworkData->SourceIp, _countof(NetworkData->SourceIp));
        SysmonFormatIpv6Address(record->DestinationAddress, NetworkData->DestinationIp, _countof(NetworkData->DestinationIp));
        return TRUE;
    }

    case 42:
    case 43:
    {
        const SYSMON_ETW_UDP_IPV4_EVENT *record = (const SYSMON_ETW_UDP_IPV4_EVENT *)EventRecord->UserData;

        if (!SysmonValidateNetworkEventPayloadSize(eventId, EventRecord->UserDataLength, (ULONG)sizeof(*record))) {
            return FALSE;
        }

        NetworkData->ProcessId = record->Pid;
        NetworkData->Initiated = (eventId == 42);
        NetworkData->SourceIsIpv6 = FALSE;
        NetworkData->DestinationIsIpv6 = FALSE;
        NetworkData->SourcePort = ntohs(record->SourcePort);
        NetworkData->DestinationPort = ntohs(record->DestinationPort);
        wcscpy_s(NetworkData->Protocol, _countof(NetworkData->Protocol), L"udp");
        SysmonFormatIpv4Address(record->SourceAddress, NetworkData->SourceIp, _countof(NetworkData->SourceIp));
        SysmonFormatIpv4Address(record->DestinationAddress, NetworkData->DestinationIp, _countof(NetworkData->DestinationIp));
        return TRUE;
    }

    case 58:
    case 59:
    {
        const SYSMON_ETW_UDP_IPV6_EVENT *record = (const SYSMON_ETW_UDP_IPV6_EVENT *)EventRecord->UserData;

        if (!SysmonValidateNetworkEventPayloadSize(eventId, EventRecord->UserDataLength, (ULONG)sizeof(*record))) {
            return FALSE;
        }

        NetworkData->ProcessId = record->Pid;
        NetworkData->Initiated = (eventId == 58);
        NetworkData->SourceIsIpv6 = TRUE;
        NetworkData->DestinationIsIpv6 = TRUE;
        NetworkData->SourcePort = ntohs(record->SourcePort);
        NetworkData->DestinationPort = ntohs(record->DestinationPort);
        wcscpy_s(NetworkData->Protocol, _countof(NetworkData->Protocol), L"udp");
        SysmonFormatIpv6Address(record->SourceAddress, NetworkData->SourceIp, _countof(NetworkData->SourceIp));
        SysmonFormatIpv6Address(record->DestinationAddress, NetworkData->DestinationIp, _countof(NetworkData->DestinationIp));
        return TRUE;
    }
    }

    return FALSE;
}

static void
SysmonRefreshRuleRuntime(
    _Inout_ PSYSMON_NETWORK_TRACE_CONTEXT Context,
    _Out_ PBOOL NetworkEnabled)
{
    BOOL enabled;

    if (Context == NULL || Context->ServiceContext == NULL || NetworkEnabled == NULL) {
        return;
    }

    {
        CriticalSectionGuard configLock(&Context->ServiceContext->ConfigLock);

        enabled = (Context->ServiceContext->Config.Options & SYSMON_OPTION_NETWORK_CONNECT) != 0;
    }

    SysmonRefreshSourceRuleRuntime(
        Context->ServiceContext,
        &Context->RuleRuntime,
        &Context->RuleSourceBlob,
        &Context->RuleSourceBlobSize,
        SYSMON_SOURCE_RULE_REFRESH_KEEP_OLD_ON_FAILURE,
        "user-mode network");

    *NetworkEnabled = enabled;
}

static void
SysmonDispatchNetworkEvent(
    _Inout_ PSYSMON_NETWORK_TRACE_CONTEXT Context,
    _In_ const SYSMON_NETWORK_EVENT_DATA *NetworkData)
{
    BYTE eventBuffer[SYSMON_NETWORK_TRACE_BUFFER_SIZE];
    SYSMON_EVENT_PAYLOAD_BUILDER builder;
    PSYSMON_EVENT_HEADER header;
    SYSMON_EVENT_NETWORK_CONNECT_PAYLOAD *payload;
    SYSMON_PROCESS_METADATA metadata;
    WCHAR utcTime[64];
    WCHAR sourceHostname[256];
    WCHAR destinationHostname[256];
    WCHAR sourcePortName[64];
    WCHAR destinationPortName[64];
    BOOL networkEnabled = FALSE;
    BOOL dnsLookup = FALSE;
    ULONGLONG timestamp = 0;

    if (Context == NULL || NetworkData == NULL) {
        return;
    }

    SysmonRefreshRuleRuntime(Context, &networkEnabled);
    if (!networkEnabled) {
        return;
    }

    if (Context->RuleRuntime != NULL &&
        !SysmonRuleRuntimeEventCanProduceLogs(Context->RuleRuntime, SysmonEventNetworkConnect)) {
        return;
    }

    {
        CriticalSectionGuard configLock(&Context->ServiceContext->ConfigLock);
        dnsLookup = Context->ServiceContext->Config.DnsLookup;
    }

    if (SysmonNetworkEventIsDuplicate(Context, NetworkData)) {
        return;
    }

    ZeroMemory(&metadata, sizeof(metadata));

    SysmonFormatUtcTimestamp(NetworkData->Timestamp, utcTime, _countof(utcTime), &timestamp);
    SysmonCollectProcessMetadataAtTime(
        Context->ServiceContext,
        NetworkData->ProcessId,
        &timestamp,
        &metadata);
    SysmonLookupNetworkNames(
        NetworkData,
        dnsLookup,
        sourceHostname,
        _countof(sourceHostname),
        destinationHostname,
        _countof(destinationHostname),
        sourcePortName,
        _countof(sourcePortName),
        destinationPortName,
        _countof(destinationPortName));
    if (NetworkData->Initiated) {
        SysmonCopyOrPlaceholder(sourceHostname, _countof(sourceHostname), Context->LocalHostname);
    } else {
        SysmonCopyOrPlaceholder(destinationHostname, _countof(destinationHostname), Context->LocalHostname);
    }

    SysmonInitializeEventBuffer(
        eventBuffer,
        sizeof(eventBuffer),
        SysmonEventNetworkConnect,
        sizeof(*payload),
        &builder,
        timestamp);

    header = (PSYSMON_EVENT_HEADER)eventBuffer;
    if (header->EventSize == 0) {
        return;
    }

    payload = (SYSMON_EVENT_NETWORK_CONNECT_PAYLOAD *)(eventBuffer + SYSMON_EVENT_HEADER_SIZE);
    ZeroMemory(payload, sizeof(*payload));

    SysmonWritePackedValue<DWORD>(&payload->ProcessId, NetworkData->ProcessId);
    payload->Initiated = NetworkData->Initiated ? TRUE : FALSE;
    payload->SourceIsIpv6 = NetworkData->SourceIsIpv6 ? TRUE : FALSE;
    payload->SourcePort = NetworkData->SourcePort;
    payload->DestinationIsIpv6 = NetworkData->DestinationIsIpv6 ? TRUE : FALSE;
    payload->DestinationPort = NetworkData->DestinationPort;

    if (SysmonAddStringField(eventBuffer, sizeof(eventBuffer), &builder, &payload->RuleName, L"-") != SYSMON_SUCCESS ||
        SysmonAddStringField(eventBuffer, sizeof(eventBuffer), &builder, &payload->UtcTime, utcTime) != SYSMON_SUCCESS ||
        SysmonAddStringField(eventBuffer, sizeof(eventBuffer), &builder, &payload->ProcessGuid, metadata.ProcessGuid) != SYSMON_SUCCESS ||
        SysmonAddStringField(eventBuffer, sizeof(eventBuffer), &builder, &payload->Image, metadata.Image) != SYSMON_SUCCESS ||
        SysmonAddStringField(eventBuffer, sizeof(eventBuffer), &builder, &payload->User, metadata.UserName) != SYSMON_SUCCESS ||
        SysmonAddStringField(eventBuffer, sizeof(eventBuffer), &builder, &payload->Protocol, NetworkData->Protocol) != SYSMON_SUCCESS ||
        SysmonAddStringField(eventBuffer, sizeof(eventBuffer), &builder, &payload->SourceIp, NetworkData->SourceIp) != SYSMON_SUCCESS ||
        SysmonAddStringField(eventBuffer, sizeof(eventBuffer), &builder, &payload->SourceHostname, sourceHostname) != SYSMON_SUCCESS ||
        SysmonAddStringField(eventBuffer, sizeof(eventBuffer), &builder, &payload->SourcePortName, sourcePortName) != SYSMON_SUCCESS ||
        SysmonAddStringField(eventBuffer, sizeof(eventBuffer), &builder, &payload->DestinationIp, NetworkData->DestinationIp) != SYSMON_SUCCESS ||
        SysmonAddStringField(eventBuffer, sizeof(eventBuffer), &builder, &payload->DestinationHostname, destinationHostname) != SYSMON_SUCCESS ||
        SysmonAddStringField(eventBuffer, sizeof(eventBuffer), &builder, &payload->DestinationPortName, destinationPortName) != SYSMON_SUCCESS) {
        return;
    }

    if (Context->RuleRuntime == NULL ||
        SysmonShouldCaptureEvent(
            Context->RuleRuntime,
            SysmonEventNetworkConnect,
            eventBuffer,
            ((PSYSMON_EVENT_HEADER)eventBuffer)->EventSize)) {
        SysmonPipelineDispatch(eventBuffer, ((PSYSMON_EVENT_HEADER)eventBuffer)->EventSize);
    } else {
    }
}

static VOID WINAPI
SysmonNetworkTraceRecordCallback(
    _In_ PEVENT_RECORD EventRecord)
{
    PSYSMON_NETWORK_TRACE_CONTEXT context;
    SYSMON_NETWORK_EVENT_DATA networkData;

    if (EventRecord == NULL) {
        return;
    }

    context = (PSYSMON_NETWORK_TRACE_CONTEXT)EventRecord->UserContext;
    if (context == NULL || InterlockedCompareExchange(&context->StopRequested, 0, 0) != 0) {
        return;
    }

    {
        BOOL packedParsed;
        BOOL tdhParsed;

        if (!IsEqualGUID(EventRecord->EventHeader.ProviderId, SYSMON_KERNEL_NETWORK_PROVIDER) ||
            !SysmonIsSupportedNetworkEventId(EventRecord->EventHeader.EventDescriptor.Id)) {
            return;
        }
        packedParsed = SysmonParseNetworkEventRecord(EventRecord, &networkData);
        tdhParsed = packedParsed || SysmonParseNetworkEventRecordByTdh(EventRecord, &networkData);
        if (!tdhParsed) {
            return;
        }
    }

    SysmonDispatchNetworkEvent(context, &networkData);
}

static DWORD WINAPI
SysmonNetworkTraceThread(
    _In_ LPVOID Parameter)
{
    PSYSMON_NETWORK_TRACE_CONTEXT context = (PSYSMON_NETWORK_TRACE_CONTEXT)Parameter;
    TRACEHANDLE handles[1];
    ULONG status;

    if (context == NULL || context->ConsumerHandle == INVALID_PROCESSTRACE_HANDLE) {
        return ERROR_INVALID_HANDLE;
    }

    handles[0] = context->ConsumerHandle;
    status = ProcessTrace(handles, 1, NULL, NULL);
    if (InterlockedCompareExchange(&context->StopRequested, 0, 0) == 0) {
        /* An external ETW stop may make ProcessTrace return success. The
           source is nevertheless gone, so mark it faulted for reconstruction
           by the service health loop. */
        InterlockedExchange(&context->ServiceContext->NetworkTraceFaulted, 1);
        SysmonLogWarning(
            SYSMON_COMPONENT_SERVICE,
            "ProcessTrace for network session ended with status %lu while the source was active",
            (unsigned long)status);
    }

    return status;
}

SYSMON_STATUS
SysmonNetworkTraceStart(
    PSYSMON_SERVICE_CONTEXT ServiceContext,
    PSYSMON_NETWORK_TRACE_CONTEXT *Context)
{
    EVENT_TRACE_LOGFILEW logfile;
    PSYSMON_NETWORK_TRACE_CONTEXT context;
    ULONG status;
    DWORD hostnameChars;

    if (ServiceContext == NULL || Context == NULL) {
        return SYSMON_ERROR_INVALID_PARAM;
    }

    *Context = NULL;
    context = (PSYSMON_NETWORK_TRACE_CONTEXT)SYSMON_ALLOC(sizeof(*context));
    if (context == NULL) {
        return SYSMON_ERROR_OUT_OF_MEMORY;
    }

    ZeroMemory(context, sizeof(*context));
    context->ServiceContext = ServiceContext;
    context->ConsumerHandle = INVALID_PROCESSTRACE_HANDLE;
    wcscpy_s(context->Properties.SessionName, _countof(context->Properties.SessionName), SYSMON_NETWORK_TRACE_SESSION_NAME);
    context->Properties.Properties.Wnode.BufferSize = sizeof(context->Properties);
    /* The event timestamp is consumed as a FILETIME below and by the
       process-store lifetime lookup. Request the ETW system-time clock rather
       than QPC, which would be a different epoch and cannot be compared with
       process creation/exit FILETIMEs. */
    context->Properties.Properties.Wnode.ClientContext = 2;
    context->Properties.Properties.Wnode.Flags = WNODE_FLAG_TRACED_GUID;
    context->Properties.Properties.LogFileMode = EVENT_TRACE_REAL_TIME_MODE;
    context->Properties.Properties.LoggerNameOffset = offsetof(SYSMON_TRACE_PROPERTIES_BUFFER, SessionName);
    context->Properties.Properties.FlushTimer = 1;

    hostnameChars = (DWORD)_countof(context->LocalHostname);
    if (GetComputerNameExW(
            ComputerNameDnsFullyQualified,
            context->LocalHostname,
            &hostnameChars) == 0) {
        SysmonCopyOrPlaceholder(context->LocalHostname, _countof(context->LocalHostname), L"-");
    }

    if (!InitOnceExecuteOnce(&g_NetworkWsaOnce, SysmonInitializeNetworkWsa, NULL, NULL)) {
        SysmonNetworkTraceStop(context);
        return WSASYSNOTREADY;
    }
    context->WsaStarted = TRUE;

    status = StartTraceW(
        &context->SessionHandle,
        context->Properties.SessionName,
        &context->Properties.Properties);
    if (status == ERROR_ALREADY_EXISTS) {
        SysmonLogWarning(
            SYSMON_COMPONENT_SERVICE,
            "Network ETW session '%ls' is already owned by another producer",
            context->Properties.SessionName);
    }
    if (status != ERROR_SUCCESS) {
        SysmonNetworkTraceStop(context);
        return status;
    }
    context->OwnsSession = TRUE;

    status = EnableTraceEx2(
        context->SessionHandle,
        &SYSMON_KERNEL_NETWORK_PROVIDER,
        EVENT_CONTROL_CODE_ENABLE_PROVIDER,
        TRACE_LEVEL_VERBOSE,
        0,
        0,
        0,
        NULL);
    if (status != ERROR_SUCCESS) {
        SysmonNetworkTraceStop(context);
        return status;
    }

    ZeroMemory(&logfile, sizeof(logfile));
    logfile.LoggerName = context->Properties.SessionName;
    logfile.ProcessTraceMode = PROCESS_TRACE_MODE_REAL_TIME | PROCESS_TRACE_MODE_EVENT_RECORD;
    logfile.EventRecordCallback = SysmonNetworkTraceRecordCallback;
    logfile.Context = context;

    context->ConsumerHandle = OpenTraceW(&logfile);
    if (context->ConsumerHandle == INVALID_PROCESSTRACE_HANDLE) {
        status = GetLastError();
        SysmonNetworkTraceStop(context);
        return status;
    }

    context->ThreadHandle = CreateThread(NULL, 0, SysmonNetworkTraceThread, context, 0, NULL);
    if (context->ThreadHandle == NULL) {
        status = GetLastError();
        SysmonNetworkTraceStop(context);
        return status;
    }

    *Context = context;
    return SYSMON_SUCCESS;
}

void
SysmonNetworkTraceStop(
    PSYSMON_NETWORK_TRACE_CONTEXT Context)
{
    if (Context == NULL) {
        return;
    }

    InterlockedExchange(&Context->StopRequested, 1);

    if (Context->ConsumerHandle != INVALID_PROCESSTRACE_HANDLE) {
        CloseTrace(Context->ConsumerHandle);
        Context->ConsumerHandle = INVALID_PROCESSTRACE_HANDLE;
    }

    if (Context->OwnsSession && Context->SessionHandle != 0) {
        ControlTraceW(
            Context->SessionHandle,
            Context->Properties.SessionName,
            &Context->Properties.Properties,
            EVENT_TRACE_CONTROL_STOP);
        Context->SessionHandle = 0;
    }
    Context->OwnsSession = FALSE;

    if (Context->ThreadHandle != NULL) {
        WaitForSingleObject(Context->ThreadHandle, INFINITE);
        CloseHandle(Context->ThreadHandle);
        Context->ThreadHandle = NULL;
    }

    SysmonFreeRuleRuntime(Context->RuleRuntime);
    Context->RuleRuntime = NULL;

    /* Winsock is initialized once for the process because asynchronous name
       workers can outlive an individual ETW source context. Releasing it here
       would race workers that are still resolving names. */
    Context->WsaStarted = FALSE;

    SYSMON_FREE(Context);
}

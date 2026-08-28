/*
 * output.c - Console/file/ETW output channels
 *
 * Console output: human-readable structured event fields
 * File output: raw append fallback to ArchiveDirectory
 * ETW: Provider Microsoft-Windows-Sysmon (TODO)
 */

#include "../include/output.h"
#include "../include/output_enrichment.h"
#include "../include/config.h"
#include "../include/hash_compat.h"
#include "../include/path_cache.h"
#include "../include/packed_read.hpp"
#include "../include/service.h"
#include "../include/runtime.hpp"

#include <stddef.h>
#include <evntprov.h>
#include <sddl.h>
#include <winver.h>

/* Output state */
static DWORD g_OutputChannels = 0;
static HANDLE g_OutputFile = INVALID_HANDLE_VALUE;
static HANDLE g_EtwDiagnosticsFile = INVALID_HANDLE_VALUE;
static CRITICAL_SECTION g_OutputSinkLock;
static CRITICAL_SECTION g_OutputEtwLock;
static SRWLOCK g_OutputStateLock = SRWLOCK_INIT;
static BOOL g_OutputInitialized = FALSE;
static REGHANDLE g_EtwProviderHandle = 0;
static BOOL g_EtwProviderRegistered = FALSE;
static PWCHAR g_EtwStringStorage = NULL;
static SIZE_T g_EtwStringStorageBytes = 0;

static const GUID SYSMON_PROVIDER_GUID = {
    0x5770385f, 0xc22a, 0x43e0, { 0xbf, 0x4c, 0x06, 0xf5, 0x69, 0x8f, 0xfb, 0xd9 }
};

#define SYSMON_ETW_DESCRIPTOR_CAPACITY 32u
#define SYSMON_ETW_STRING_STORAGE_CHARS 2048u

static void RenderEventConsole(
    _In_reads_bytes_(EventSize) const UCHAR *EventData,
    _In_ DWORD EventSize,
    _In_ SYSMON_EVENT_ID EventId);

class SharedSrwLockGuard {
public:
    explicit SharedSrwLockGuard(_Inout_ SRWLOCK* lock) noexcept
        : lock_(lock)
    {
        if (lock_ != NULL) {
            AcquireSRWLockShared(lock_);
        }
    }

    ~SharedSrwLockGuard() noexcept
    {
        if (lock_ != NULL) {
            ReleaseSRWLockShared(lock_);
        }
    }

    SharedSrwLockGuard(const SharedSrwLockGuard&) = delete;
    SharedSrwLockGuard& operator=(const SharedSrwLockGuard&) = delete;

private:
    SRWLOCK* lock_;
};

class ExclusiveSrwLockGuard {
public:
    explicit ExclusiveSrwLockGuard(_Inout_ SRWLOCK* lock) noexcept
        : lock_(lock)
    {
        if (lock_ != NULL) {
            AcquireSRWLockExclusive(lock_);
        }
    }

    ~ExclusiveSrwLockGuard() noexcept
    {
        if (lock_ != NULL) {
            ReleaseSRWLockExclusive(lock_);
        }
    }

    ExclusiveSrwLockGuard(const ExclusiveSrwLockGuard&) = delete;
    ExclusiveSrwLockGuard& operator=(const ExclusiveSrwLockGuard&) = delete;

private:
    SRWLOCK* lock_;
};

/*
 * Caller must hold g_OutputEtwLock whenever shared ETW string storage is used.
 */
static PWCHAR
SysmonEnsureEtwStringStorageCapacity(
    _In_ SIZE_T RequiredBytes)
{
    PWCHAR storage;

    if (RequiredBytes == 0) {
        return NULL;
    }

    if (g_EtwStringStorage != NULL &&
        g_EtwStringStorageBytes >= RequiredBytes) {
        return g_EtwStringStorage;
    }

    storage = (PWCHAR)SYSMON_ALLOC(RequiredBytes);
    if (storage == NULL) {
        return NULL;
    }

    SYSMON_FREE(g_EtwStringStorage);
    g_EtwStringStorage = storage;
    g_EtwStringStorageBytes = RequiredBytes;
    return g_EtwStringStorage;
}

static VOID
SysmonResetEtwStringStorage(VOID)
{
    SYSMON_FREE(g_EtwStringStorage);
    g_EtwStringStorage = NULL;
    g_EtwStringStorageBytes = 0;
}

void
SysmonFormatProductVersion(
    _Out_writes_(BufferChars) PWCHAR Buffer,
    _In_ size_t BufferChars)
{
    if (Buffer == NULL || BufferChars == 0) {
        return;
    }

    _snwprintf_s(
        Buffer,
        BufferChars,
        _TRUNCATE,
        L"%u.%u.%u",
        (unsigned)SYSMON_VERSION_MAJOR,
        (unsigned)SYSMON_VERSION_MINOR,
        (unsigned)SYSMON_VERSION_BUILD);
}

/* Event ID to name mapping */
static const struct {
    SYSMON_EVENT_ID Id;
    const char *Name;
} g_EventNames[] = {
    { SysmonEventProcessCreate,         "Process Create" },
    { SysmonEventFileCreateTime,        "File Creation Time" },
    { SysmonEventNetworkConnect,        "Network Connection" },
    { SysmonEventServiceState,          "Service State Change" },
    { SysmonEventProcessTerminate,      "Process Terminate" },
    { SysmonEventDriverLoad,            "Driver Load" },
    { SysmonEventImageLoad,             "Image Load" },
    { SysmonEventCreateRemoteThread,    "Create Remote Thread" },
    { SysmonEventRawAccessRead,         "Raw Access Read" },
    { SysmonEventProcessAccess,         "Process Access" },
    { SysmonEventFileCreate,            "File Create" },
    { SysmonEventRegistryEvent,         "Registry Event (Key)" },
    { SysmonEventRegistryValueSet,      "Registry Value Set" },
    { SysmonEventRegistryRename,        "Registry Rename" },
    { SysmonEventFileCreateStreamHash,  "File Stream Create" },
    { SysmonEventConfigChange,          "Config Change" },
    { SysmonEventPipeCreated,           "Pipe Created" },
    { SysmonEventPipeConnected,         "Pipe Connected" },
    { SysmonEventWmiFilter,             "WMI Filter" },
    { SysmonEventWmiConsumer,           "WMI Consumer" },
    { SysmonEventWmiConsumerToFilter,   "WMI Binding" },
    { SysmonEventDnsQuery,              "DNS Query" },
    { SysmonEventFileDelete,            "File Delete" },
    { SysmonEventClipboardChange,       "Clipboard Change" },
    { SysmonEventProcessTampering,      "Process Tampering" },
    { SysmonEventFileDeleteDetected,    "File Delete Detected" },
    { SysmonEventFileBlockExecutable,   "File Block Executable" },
    { SysmonEventFileBlockShredding,    "File Block Shredding" },
    { SysmonEventFileExecutableDetected,"File Executable Detected" },
    { SysmonEventDropped,               "Events Dropped" },
    { SysmonEventError,                 "Error" },
};

static const char* GetEventName(SYSMON_EVENT_ID EventId)
{
    int i;
    for (i = 0; i < _countof(g_EventNames); i++) {
        if (g_EventNames[i].Id == EventId) {
            return g_EventNames[i].Name;
        }
    }
    return "Unknown";
}

BOOL HasPayloadBytes(DWORD PayloadSize, size_t Offset, size_t Size)
{
    return Offset <= PayloadSize && Size <= (size_t)(PayloadSize - Offset);
}

static int
SysmonHexDigitValue(
    _In_ WCHAR Ch)
{
    if (Ch >= L'0' && Ch <= L'9') {
        return Ch - L'0';
    }

    if (Ch >= L'a' && Ch <= L'f') {
        return Ch - L'a' + 10;
    }

    if (Ch >= L'A' && Ch <= L'F') {
        return Ch - L'A' + 10;
    }

    return -1;
}

static BOOL
SysmonParseGuidHex(
    _In_reads_(DigitCount) LPCWSTR Text,
    _In_ size_t DigitCount,
    _Out_ ULONG *Value)
{
    ULONG parsed;
    size_t index;

    if (Text == NULL || Value == NULL || DigitCount == 0 || DigitCount > 8) {
        return FALSE;
    }

    parsed = 0;
    for (index = 0; index < DigitCount; index++) {
        int digit = SysmonHexDigitValue(Text[index]);
        if (digit < 0) {
            return FALSE;
        }

        parsed = (parsed << 4) | (ULONG)digit;
    }

    *Value = parsed;
    return TRUE;
}

static BOOL
SysmonParseGuidByte(
    _In_reads_(2) LPCWSTR Text,
    _Out_ UCHAR *Value)
{
    ULONG parsed;

    if (Value == NULL || !SysmonParseGuidHex(Text, 2, &parsed) || parsed > 0xFF) {
        return FALSE;
    }

    *Value = (UCHAR)parsed;
    return TRUE;
}

static BOOL
SysmonTryParseGuidString(
    _In_z_ LPCWSTR Text,
    _Out_ GUID *Guid)
{
    ULONG data1;
    ULONG data2;
    ULONG data3;
    size_t length;
    LPCWSTR value;

    if (Text == NULL || Guid == NULL) {
        return FALSE;
    }

    ZeroMemory(Guid, sizeof(*Guid));

    length = wcslen(Text);
    value = Text;
    if (length == 38 && Text[0] == L'{' && Text[37] == L'}') {
        value = Text + 1;
        length = 36;
    }

    if (length != 36 ||
        value[8] != L'-' ||
        value[13] != L'-' ||
        value[18] != L'-' ||
        value[23] != L'-') {
        return FALSE;
    }

    if (!SysmonParseGuidHex(value, 8, &data1) ||
        !SysmonParseGuidHex(value + 9, 4, &data2) ||
        !SysmonParseGuidHex(value + 14, 4, &data3)) {
        return FALSE;
    }

    Guid->Data1 = data1;
    Guid->Data2 = (USHORT)data2;
    Guid->Data3 = (USHORT)data3;
    return SysmonParseGuidByte(value + 19, &Guid->Data4[0]) &&
        SysmonParseGuidByte(value + 21, &Guid->Data4[1]) &&
        SysmonParseGuidByte(value + 24, &Guid->Data4[2]) &&
        SysmonParseGuidByte(value + 26, &Guid->Data4[3]) &&
        SysmonParseGuidByte(value + 28, &Guid->Data4[4]) &&
        SysmonParseGuidByte(value + 30, &Guid->Data4[5]) &&
        SysmonParseGuidByte(value + 32, &Guid->Data4[6]) &&
        SysmonParseGuidByte(value + 34, &Guid->Data4[7]);
}

static BOOL
SysmonEtwFieldUsesGuidType(
    _In_ SYSMON_EVENT_ID EventId,
    _In_ const SYSMON_EVENT_FIELD_DESCRIPTOR *Field)
{
    UNREFERENCED_PARAMETER(EventId);

    if (Field == NULL || Field->Name == NULL ||
        (_wcsicmp(Field->Name, EVT_FIELD_PROCESS_GUID) != 0 &&
         _wcsicmp(Field->Name, EVT_FIELD_LOGON_GUID) != 0 &&
         _wcsicmp(Field->Name, EVT_FIELD_PARENT_PROCESS_GUID) != 0 &&
         _wcsicmp(Field->Name, EVT_FIELD_SOURCE_PROCESS_GUID) != 0 &&
         _wcsicmp(Field->Name, EVT_FIELD_TARGET_PROCESS_GUID) != 0 &&
         _wcsicmp(Field->Name, EVT_FIELD_SOURCE_PROCESS_GUID_CAPS) != 0 &&
         _wcsicmp(Field->Name, EVT_FIELD_TARGET_PROCESS_GUID_CAPS) != 0)) {
        return FALSE;
    }

    /*
     * The original Sysmon ETW schema publishes process GUID fields as win:GUID
     * while the driver/user contract stores them as canonical strings for rule
     * matching and console output.
     */
    return TRUE;
}

static BOOL
SysmonEtwFieldUsesUInt16Type(
    _In_ SYSMON_EVENT_ID EventId,
    _In_ const SYSMON_EVENT_FIELD_DESCRIPTOR *Field)
{
    if (EventId != SysmonEventNetworkConnect ||
        Field == NULL ||
        Field->Name == NULL) {
        return FALSE;
    }

    return _wcsicmp(Field->Name, EVT_FIELD_SOURCE_PORT) == 0 ||
        _wcsicmp(Field->Name, EVT_FIELD_DESTINATION_PORT) == 0;
}

static BOOL
SysmonEtwFieldUsesUnicodeStringType(
    _In_ SYSMON_EVENT_ID EventId,
    _In_ const SYSMON_EVENT_FIELD_DESCRIPTOR *Field)
{
    if (Field == NULL || Field->Name == NULL) {
        return FALSE;
    }

    if ((EventId == SysmonEventDriverLoad || EventId == SysmonEventImageLoad) &&
        _wcsicmp(Field->Name, EVT_FIELD_SIGNED) == 0) {
        return TRUE;
    }

    if (EventId == SysmonEventCreateRemoteThread &&
        _wcsicmp(Field->Name, EVT_FIELD_START_ADDRESS) == 0) {
        return TRUE;
    }

    if ((EventId == SysmonEventFileDelete || EventId == SysmonEventClipboardChange) &&
        _wcsicmp(Field->Name, EVT_FIELD_ARCHIVED) == 0) {
        return TRUE;
    }

    return FALSE;
}

BOOL CopyStringRefValue(
    _In_reads_bytes_(PayloadSize) const UCHAR *PayloadBase,
    _In_ DWORD PayloadSize,
    _In_ const SYSMON_EVENT_STRING_REF *StringRefAddress,
    _Out_writes_(BufferChars) PWCHAR Buffer,
    _In_ size_t BufferChars)
{
    SYSMON_EVENT_STRING_REF stringRef;
    size_t copyBytes;

    if (PayloadBase == NULL || StringRefAddress == NULL || Buffer == NULL || BufferChars == 0) {
        return FALSE;
    }

    Buffer[0] = L'\0';

    stringRef = SysmonReadPackedValue<SYSMON_EVENT_STRING_REF>(StringRefAddress);
    if (stringRef.LengthBytes == 0) {
        return TRUE;
    }

    if ((stringRef.LengthBytes % sizeof(WCHAR)) != 0 ||
        !HasPayloadBytes(PayloadSize, stringRef.Offset, stringRef.LengthBytes)) {
        return FALSE;
    }

    copyBytes = stringRef.LengthBytes;
    if (copyBytes >= BufferChars * sizeof(WCHAR)) {
        copyBytes = (BufferChars - 1) * sizeof(WCHAR);
    }

    CopyMemory(Buffer, PayloadBase + stringRef.Offset, copyBytes);
    Buffer[copyBytes / sizeof(WCHAR)] = L'\0';
    return TRUE;
}

BOOL
SysmonGetStringRefValueView(
    _In_reads_bytes_(PayloadSize) const UCHAR *PayloadBase,
    _In_ DWORD PayloadSize,
    _In_ const SYSMON_EVENT_STRING_REF *StringRefAddress,
    _Outptr_result_z_ const WCHAR **Value,
    _Out_ ULONG *ValueSizeBytes)
{
    SYSMON_EVENT_STRING_REF stringRef;
    const WCHAR *text;
    size_t terminatorOffset;

    if (PayloadBase == NULL || StringRefAddress == NULL || Value == NULL || ValueSizeBytes == NULL) {
        return FALSE;
    }

    stringRef = SysmonReadPackedValue<SYSMON_EVENT_STRING_REF>(StringRefAddress);
    if (stringRef.LengthBytes == 0) {
        static const WCHAR s_EmptyEtwString[] = L"";

        *Value = s_EmptyEtwString;
        *ValueSizeBytes = sizeof(s_EmptyEtwString);
        return TRUE;
    }

    if ((stringRef.LengthBytes % sizeof(WCHAR)) != 0 ||
        !HasPayloadBytes(PayloadSize, stringRef.Offset, stringRef.LengthBytes + sizeof(WCHAR))) {
        return FALSE;
    }

    text = (const WCHAR *)(PayloadBase + stringRef.Offset);
    terminatorOffset = stringRef.LengthBytes / sizeof(WCHAR);
    if (text[terminatorOffset] != L'\0') {
        return FALSE;
    }

    *Value = text;
    *ValueSizeBytes = stringRef.LengthBytes + sizeof(WCHAR);
    return TRUE;
}

BOOL
FormatFieldValue(
    _In_reads_bytes_(PayloadSize) const UCHAR *PayloadBase,
    _In_ DWORD PayloadSize,
    _In_ const SYSMON_EVENT_FIELD_DESCRIPTOR *Field,
    _Out_writes_(BufferChars) PWCHAR Buffer,
    _In_ size_t BufferChars)
{
    const void *fieldPtr;
    SYSMON_EVENT_STRING_REF stringRef;
    DWORD value32;
    ULONGLONG value64;
    BOOLEAN boolValue;

    if (PayloadBase == NULL || Field == NULL || Buffer == NULL || BufferChars == 0) {
        return FALSE;
    }

    Buffer[0] = L'\0';
    fieldPtr = PayloadBase + Field->Offset;

    switch (Field->Kind) {
    case SysmonRenderStringRef:
        if (!HasPayloadBytes(PayloadSize, Field->Offset, sizeof(stringRef))) {
            return FALSE;
        }
        stringRef = SysmonReadPackedValue<SYSMON_EVENT_STRING_REF>(fieldPtr);
        return CopyStringRefValue(PayloadBase, PayloadSize, &stringRef, Buffer, BufferChars);

    case SysmonRenderUInt32:
        if (!HasPayloadBytes(PayloadSize, Field->Offset, sizeof(value32))) {
            return FALSE;
        }
        value32 = SysmonReadPackedValue<DWORD>(fieldPtr);
        return SUCCEEDED(_snwprintf_s(Buffer, BufferChars, _TRUNCATE, L"%lu", (unsigned long)value32));

    case SysmonRenderUInt32Hex:
        if (!HasPayloadBytes(PayloadSize, Field->Offset, sizeof(value32))) {
            return FALSE;
        }
        value32 = SysmonReadPackedValue<DWORD>(fieldPtr);
        return SUCCEEDED(_snwprintf_s(Buffer, BufferChars, _TRUNCATE, L"0x%lx", (unsigned long)value32));

    case SysmonRenderUInt64:
        if (!HasPayloadBytes(PayloadSize, Field->Offset, sizeof(value64))) {
            return FALSE;
        }
        value64 = SysmonReadPackedValue<ULONGLONG>(fieldPtr);
        return SUCCEEDED(_snwprintf_s(Buffer, BufferChars, _TRUNCATE, L"%llu", value64));

    case SysmonRenderUInt64Hex:
        if (!HasPayloadBytes(PayloadSize, Field->Offset, sizeof(value64))) {
            return FALSE;
        }
        value64 = SysmonReadPackedValue<ULONGLONG>(fieldPtr);
        return SUCCEEDED(_snwprintf_s(Buffer, BufferChars, _TRUNCATE, L"0x%llx", value64));

    case SysmonRenderBool:
        if (!HasPayloadBytes(PayloadSize, Field->Offset, sizeof(boolValue))) {
            return FALSE;
        }
        boolValue = SysmonReadPackedValue<BOOLEAN>(fieldPtr);
        return SUCCEEDED(_snwprintf_s(
            Buffer,
            BufferChars,
            _TRUNCATE,
            L"%ls",
            (boolValue != FALSE) ? L"true" : L"false"));

    case SysmonRenderProcessTerminatePid:
        if (HasPayloadBytes(PayloadSize, Field->Offset, sizeof(value32))) {
            value32 = SysmonReadPackedValue<DWORD>(fieldPtr);
        } else if (PayloadSize == sizeof(value32) &&
                   HasPayloadBytes(PayloadSize, 0, sizeof(value32))) {
            /* Only accept the legacy PID-only layout when the payload is exactly that shape. */
            value32 = SysmonReadPackedValue<DWORD>(PayloadBase);
        } else {
            return FALSE;
        }
        return SUCCEEDED(_snwprintf_s(Buffer, BufferChars, _TRUNCATE, L"%lu", (unsigned long)value32));
    }

    return FALSE;
}

BOOL
ShouldPreserveEmptyEtwString(
    _In_ SYSMON_EVENT_ID EventId,
    _In_ const SYSMON_EVENT_FIELD_DESCRIPTOR *Field)
{
    if (Field == NULL || Field->Name == NULL) {
        return FALSE;
    }

    if (EventId == SysmonEventConfigChange &&
        wcscmp(Field->Name, EVT_FIELD_CONFIGURATION_FILE_HASH) == 0) {
        return TRUE;
    }

    return FALSE;
}

/*
 * These descriptors must match the manifest metadata exactly:
 * { Id, Version, Channel, Level, Opcode, Task, Keyword }.
 * The Operational channel maps to 0x10.
 */
static const EVENT_DESCRIPTOR g_EtwProcessCreateDescriptor = {
    1, 5, 0x10, 4, 0, 1, 0x8000000000000000ULL
};

static const EVENT_DESCRIPTOR g_EtwFileCreateTimeDescriptor = {
    2, 5, 0x10, 4, 0, 2, 0x8000000000000000ULL
};

static const EVENT_DESCRIPTOR g_EtwNetworkConnectDescriptor = {
    3, 5, 0x10, 4, 0, 3, 0x8000000000000000ULL
};

static const EVENT_DESCRIPTOR g_EtwServiceStateDescriptor = {
    4, 3, 0x10, 4, 0, 4, 0x8000000000000000ULL
};

static const EVENT_DESCRIPTOR g_EtwProcessTerminateDescriptor = {
    5, 3, 0x10, 4, 0, 5, 0x8000000000000000ULL
};

static const EVENT_DESCRIPTOR g_EtwDriverLoadDescriptor = {
    6, 4, 0x10, 4, 0, 6, 0x8000000000000000ULL
};

static const EVENT_DESCRIPTOR g_EtwImageLoadDescriptor = {
    7, 3, 0x10, 4, 0, 7, 0x8000000000000000ULL
};

static const EVENT_DESCRIPTOR g_EtwCreateRemoteThreadDescriptor = {
    8, 2, 0x10, 4, 0, 8, 0x8000000000000000ULL
};

static const EVENT_DESCRIPTOR g_EtwRawAccessReadDescriptor = {
    9, 2, 0x10, 4, 0, 9, 0x8000000000000000ULL
};

static const EVENT_DESCRIPTOR g_EtwProcessAccessDescriptor = {
    10, 3, 0x10, 4, 0, 10, 0x8000000000000000ULL
};

static const EVENT_DESCRIPTOR g_EtwFileCreateDescriptor = {
    11, 2, 0x10, 4, 0, 11, 0x8000000000000000ULL
};

static const EVENT_DESCRIPTOR g_EtwRegistryEventDescriptor = {
    12, 2, 0x10, 4, 0, 12, 0x8000000000000000ULL
};

static const EVENT_DESCRIPTOR g_EtwRegistryValueSetDescriptor = {
    13, 2, 0x10, 4, 0, 13, 0x8000000000000000ULL
};

static const EVENT_DESCRIPTOR g_EtwRegistryRenameDescriptor = {
    14, 2, 0x10, 4, 0, 14, 0x8000000000000000ULL
};

static const EVENT_DESCRIPTOR g_EtwFileCreateStreamHashDescriptor = {
    15, 2, 0x10, 4, 0, 15, 0x8000000000000000ULL
};

static const EVENT_DESCRIPTOR g_EtwConfigChangeDescriptor = {
    16, 3, 0x10, 4, 0, 16, 0x8000000000000000ULL
};

static const EVENT_DESCRIPTOR g_EtwPipeCreatedDescriptor = {
    17, 1, 0x10, 4, 0, 17, 0x8000000000000000ULL
};

static const EVENT_DESCRIPTOR g_EtwPipeConnectedDescriptor = {
    18, 1, 0x10, 4, 0, 18, 0x8000000000000000ULL
};

static const EVENT_DESCRIPTOR g_EtwWmiFilterDescriptor = {
    19, 3, 0x10, 4, 0, 19, 0x8000000000000000ULL
};

static const EVENT_DESCRIPTOR g_EtwWmiConsumerDescriptor = {
    20, 3, 0x10, 4, 0, 20, 0x8000000000000000ULL
};

static const EVENT_DESCRIPTOR g_EtwWmiConsumerToFilterDescriptor = {
    21, 3, 0x10, 4, 0, 21, 0x8000000000000000ULL
};

static const EVENT_DESCRIPTOR g_EtwDnsQueryDescriptor = {
    22, 5, 0x10, 4, 0, 22, 0x8000000000000000ULL
};

static const EVENT_DESCRIPTOR g_EtwFileDeleteDescriptor = {
    23, 5, 0x10, 4, 0, 23, 0x8000000000000000ULL
};

static const EVENT_DESCRIPTOR g_EtwClipboardChangeDescriptor = {
    24, 5, 0x10, 4, 0, 24, 0x8000000000000000ULL
};

static const EVENT_DESCRIPTOR g_EtwProcessTamperingDescriptor = {
    25, 5, 0x10, 4, 0, 25, 0x8000000000000000ULL
};

static const EVENT_DESCRIPTOR g_EtwFileDeleteDetectedDescriptor = {
    26, 5, 0x10, 4, 0, 26, 0x8000000000000000ULL
};

static const EVENT_DESCRIPTOR g_EtwFileBlockExecutableDescriptor = {
    27, 5, 0x10, 4, 0, 27, 0x8000000000000000ULL
};

static const EVENT_DESCRIPTOR g_EtwFileBlockShreddingDescriptor = {
    28, 5, 0x10, 4, 0, 28, 0x8000000000000000ULL
};

static const EVENT_DESCRIPTOR g_EtwFileExecutableDetectedDescriptor = {
    29, 5, 0x10, 4, 0, 29, 0x8000000000000000ULL
};

static const EVENT_DESCRIPTOR *
GetEtwEventDescriptor(
    _In_ SYSMON_EVENT_ID EventId)
{
    switch (EventId) {
    case SysmonEventProcessCreate:
        return &g_EtwProcessCreateDescriptor;
    case SysmonEventFileCreateTime:
        return &g_EtwFileCreateTimeDescriptor;
    case SysmonEventNetworkConnect:
        return &g_EtwNetworkConnectDescriptor;
    case SysmonEventServiceState:
        return &g_EtwServiceStateDescriptor;
    case SysmonEventProcessTerminate:
        return &g_EtwProcessTerminateDescriptor;
    case SysmonEventDriverLoad:
        return &g_EtwDriverLoadDescriptor;
    case SysmonEventImageLoad:
        return &g_EtwImageLoadDescriptor;
    case SysmonEventCreateRemoteThread:
        return &g_EtwCreateRemoteThreadDescriptor;
    case SysmonEventRawAccessRead:
        return &g_EtwRawAccessReadDescriptor;
    case SysmonEventProcessAccess:
        return &g_EtwProcessAccessDescriptor;
    case SysmonEventFileCreate:
        return &g_EtwFileCreateDescriptor;
    case SysmonEventRegistryEvent:
        return &g_EtwRegistryEventDescriptor;
    case SysmonEventRegistryValueSet:
        return &g_EtwRegistryValueSetDescriptor;
    case SysmonEventRegistryRename:
        return &g_EtwRegistryRenameDescriptor;
    case SysmonEventFileCreateStreamHash:
        return &g_EtwFileCreateStreamHashDescriptor;
    case SysmonEventConfigChange:
        return &g_EtwConfigChangeDescriptor;
    case SysmonEventPipeCreated:
        return &g_EtwPipeCreatedDescriptor;
    case SysmonEventPipeConnected:
        return &g_EtwPipeConnectedDescriptor;
    case SysmonEventWmiFilter:
        return &g_EtwWmiFilterDescriptor;
    case SysmonEventWmiConsumer:
        return &g_EtwWmiConsumerDescriptor;
    case SysmonEventWmiConsumerToFilter:
        return &g_EtwWmiConsumerToFilterDescriptor;
    case SysmonEventDnsQuery:
        return &g_EtwDnsQueryDescriptor;
    case SysmonEventFileDelete:
        return &g_EtwFileDeleteDescriptor;
    case SysmonEventClipboardChange:
        return &g_EtwClipboardChangeDescriptor;
    case SysmonEventProcessTampering:
        return &g_EtwProcessTamperingDescriptor;
    case SysmonEventFileDeleteDetected:
        return &g_EtwFileDeleteDetectedDescriptor;
    case SysmonEventFileBlockExecutable:
        return &g_EtwFileBlockExecutableDescriptor;
    case SysmonEventFileBlockShredding:
        return &g_EtwFileBlockShreddingDescriptor;
    case SysmonEventFileExecutableDetected:
        return &g_EtwFileExecutableDetectedDescriptor;
    default:
        return NULL;
    }
}

static VOID
CloseEtwDiagnosticsFile(VOID)
{
    if (g_EtwDiagnosticsFile != INVALID_HANDLE_VALUE) {
        FlushFileBuffers(g_EtwDiagnosticsFile);
        CloseHandle(g_EtwDiagnosticsFile);
        g_EtwDiagnosticsFile = INVALID_HANDLE_VALUE;
    }
}

static VOID
InitializeEtwDiagnosticsLog(
    _In_opt_ LPCWSTR ArchiveDirectory)
{
    WCHAR logPath[MAX_PATH];
    DWORD pathLength;
    BOOL useArchivePath;

    g_EtwDiagnosticsFile = INVALID_HANDLE_VALUE;
    useArchivePath = (ArchiveDirectory != NULL && ArchiveDirectory[0] != L'\0');

    if (useArchivePath) {
        CreateDirectoryW(ArchiveDirectory, NULL);
        _snwprintf_s(
            logPath,
            _countof(logPath),
            _TRUNCATE,
            L"%s\\Sysmon_ETW_Diagnostics.log",
            ArchiveDirectory);
    } else {
fallback_to_temp:
        pathLength = GetTempPathW(_countof(logPath), logPath);
        if (pathLength == 0 || pathLength >= _countof(logPath)) {
            return;
        }

        if (wcscat_s(logPath, _countof(logPath), L"Sysmon_ETW_Diagnostics.log") != 0) {
            return;
        }
    }

    g_EtwDiagnosticsFile = CreateFileW(
        logPath,
        FILE_APPEND_DATA,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        NULL,
        OPEN_ALWAYS,
        FILE_ATTRIBUTE_NORMAL,
        NULL);

    if (g_EtwDiagnosticsFile == INVALID_HANDLE_VALUE && useArchivePath) {
        useArchivePath = FALSE;
        goto fallback_to_temp;
    }
}

static VOID
LogEtwDiagnostic(
    _In_ SYSMON_EVENT_ID EventId,
    _In_z_ const char *Stage,
    _In_ ULONG Status,
    _In_opt_z_ const char *Reason)
{
    SYSTEMTIME st;
    char line[512];
    int lineLength;
    DWORD bytesWritten;

    if (g_EtwDiagnosticsFile == INVALID_HANDLE_VALUE || Stage == NULL) {
        return;
    }

    GetLocalTime(&st);
    lineLength = _snprintf_s(
        line,
        sizeof(line),
        _TRUNCATE,
        "%04u-%02u-%02u %02u:%02u:%02u.%03u event=%u stage=%s status=%lu (0x%08lX)%s%s\r\n",
        (unsigned)st.wYear,
        (unsigned)st.wMonth,
        (unsigned)st.wDay,
        (unsigned)st.wHour,
        (unsigned)st.wMinute,
        (unsigned)st.wSecond,
        (unsigned)st.wMilliseconds,
        (unsigned)EventId,
        Stage,
        (unsigned long)Status,
        (unsigned long)Status,
        (Reason != NULL && Reason[0] != '\0') ? " reason=" : "",
        (Reason != NULL) ? Reason : "");

    if (lineLength <= 0) {
        return;
    }

    WriteFile(
        g_EtwDiagnosticsFile,
        line,
        (DWORD)lineLength,
        &bytesWritten,
        NULL);
}

static ULONG
WriteEventEtwWithHandle(
    _In_ REGHANDLE ProviderHandle,
    _In_reads_bytes_(EventSize) const UCHAR *EventData,
    _In_ DWORD EventSize,
    _In_ SYSMON_EVENT_ID EventId);

static ULONG
WriteEventEtwWithTransientStorage(
    _In_ REGHANDLE ProviderHandle,
    _In_reads_bytes_(EventSize) const UCHAR *EventData,
    _In_ DWORD EventSize,
    _In_ SYSMON_EVENT_ID EventId);

static PWCHAR
SysmonGetEtwStringStorageSlot(
    _In_ PWCHAR StringStorage,
    _In_ size_t SlotChars,
    _In_ ULONG SlotIndex)
{
    return StringStorage + ((size_t)SlotIndex * SlotChars);
}

static ULONG
BuildEtwEventDataDescriptors(
    _In_ SYSMON_EVENT_ID EventId,
    _In_reads_bytes_(PayloadSize) const UCHAR *PayloadBase,
    _In_ DWORD PayloadSize,
    _In_ const SYSMON_EVENT_SCHEMA *Schema,
    _In_opt_ const SYSMON_PROCESS_CREATE_ENRICHMENT *ProcessCreateEnrichment,
    _Inout_opt_ SYSMON_PROCESS_CREATE_ENRICHMENT *ImageLoadEnrichment,
    _Out_writes_(DescriptorCapacity) EVENT_DATA_DESCRIPTOR *Descriptors,
    _Out_writes_(DescriptorCapacity * StringStorageSlotChars) PWCHAR StringStorage,
    _In_ size_t StringStorageSlotChars,
    _In_ ULONG DescriptorCapacity,
    _Out_opt_ ULONG *FailureStatus,
    _Outptr_opt_result_z_ const char **FailureReason)
{
    DWORD fieldIndex;

    if (FailureStatus != NULL) {
        *FailureStatus = ERROR_SUCCESS;
    }

    if (FailureReason != NULL) {
        *FailureReason = NULL;
    }

    if (PayloadBase == NULL || Schema == NULL || Descriptors == NULL ||
        StringStorage == NULL || StringStorageSlotChars == 0) {
        if (FailureStatus != NULL) {
            *FailureStatus = ERROR_INVALID_PARAMETER;
        }
        if (FailureReason != NULL) {
            *FailureReason = "missing ETW descriptor inputs";
        }
        return 0;
    }

    if (Schema->FieldCount > DescriptorCapacity) {
        if (FailureStatus != NULL) {
            *FailureStatus = ERROR_INSUFFICIENT_BUFFER;
        }
        if (FailureReason != NULL) {
            *FailureReason = "schema field count exceeds descriptor capacity";
        }
        return 0;
    }

    for (fieldIndex = 0; fieldIndex < Schema->FieldCount; fieldIndex++) {
        const SYSMON_EVENT_FIELD_DESCRIPTOR *field;
        PWCHAR fieldStringStorage;
        const void *fieldPtr;
        DWORD value32;
        USHORT value16;
        ULONGLONG value64;

        field = &Schema->Fields[fieldIndex];
        fieldStringStorage = SysmonGetEtwStringStorageSlot(
            StringStorage,
            StringStorageSlotChars,
            fieldIndex);
        fieldPtr = PayloadBase + field->Offset;

        switch (field->Kind) {
        case SysmonRenderStringRef:
        {
            SYSMON_EVENT_STRING_REF stringRef;
            const WCHAR *directValue;
            ULONG directValueSize;
            BOOL useDirectStringRef;

            if (!HasPayloadBytes(PayloadSize, field->Offset, sizeof(stringRef))) {
                if (FailureStatus != NULL) {
                    *FailureStatus = ERROR_INVALID_DATA;
                }
                if (FailureReason != NULL) {
                    *FailureReason = "missing string ref field bytes";
                }
                return 0;
            }

            stringRef = SysmonReadPackedValue<SYSMON_EVENT_STRING_REF>(fieldPtr);
            useDirectStringRef = FALSE;
            if (SysmonEtwFieldUsesGuidType(EventId, field)) {
                GUID *guidStorage = (GUID *)fieldStringStorage;

                ZeroMemory(guidStorage, sizeof(*guidStorage));
                if (!SysmonGetStringRefValueView(
                         PayloadBase,
                         PayloadSize,
                         &stringRef,
                         &directValue,
                         &directValueSize)) {
                    if (FailureStatus != NULL) {
                        *FailureStatus = ERROR_INVALID_DATA;
                    }
                    if (FailureReason != NULL) {
                        *FailureReason = "missing GUID string field";
                    }
                    /* Emit a zero GUID instead of dropping the entire event
                       (U7 in the 2026-08-04 review). */
                } else if (!SysmonTryParseGuidString(directValue, guidStorage)) {
                    if (FailureStatus != NULL) {
                        *FailureStatus = ERROR_INVALID_DATA;
                    }
                    if (FailureReason != NULL) {
                        *FailureReason = "invalid GUID string field";
                    }
                    /* Emit a zero GUID instead of dropping the entire event
                       (U7 in the 2026-08-04 review). */
                }

                EventDataDescCreate(
                    &Descriptors[fieldIndex],
                    guidStorage,
                    sizeof(*guidStorage));
                break;
            }

            if (SysmonGetStringRefValueView(
                    PayloadBase,
                    PayloadSize,
                    &stringRef,
                    &directValue,
                    &directValueSize) &&
                !(directValue[0] == L'\0' && !ShouldPreserveEmptyEtwString(EventId, field)) &&
                SysmonCanUseDirectEtwStringRef(
                    EventId,
                    field,
                    directValue,
                    ProcessCreateEnrichment,
                    ImageLoadEnrichment) &&
                !SysmonHasConfiguredFieldSize(field->Name)) {
                EventDataDescCreate(
                    &Descriptors[fieldIndex],
                    directValue,
                    directValueSize);
                useDirectStringRef = TRUE;
            }

            if (useDirectStringRef) {
                break;
            }

            fieldStringStorage[0] = L'\0';
            if (!FormatFieldValueForEvent(
                    EventId,
                    PayloadBase,
                    PayloadSize,
                    field,
                    ProcessCreateEnrichment,
                    ImageLoadEnrichment,
                    fieldStringStorage,
                    StringStorageSlotChars)) {
                wcscpy_s(fieldStringStorage, StringStorageSlotChars, L"-");
            } else if (fieldStringStorage[0] == L'\0' &&
                       !ShouldPreserveEmptyEtwString(EventId, field)) {
                wcscpy_s(fieldStringStorage, StringStorageSlotChars, L"-");
            }

            EventDataDescCreate(
                &Descriptors[fieldIndex],
                fieldStringStorage,
                ((ULONG)wcslen(fieldStringStorage) + 1) * sizeof(WCHAR));
            break;
        }

        case SysmonRenderUInt32:
        case SysmonRenderUInt32Hex:
            if (!HasPayloadBytes(PayloadSize, field->Offset, sizeof(DWORD))) {
                if (FailureStatus != NULL) {
                    *FailureStatus = ERROR_INVALID_DATA;
                }
                if (FailureReason != NULL) {
                    *FailureReason = "missing 32-bit field bytes";
                }
                return 0;
            }

            value32 = SysmonReadPackedValue<DWORD>(fieldPtr);
            if (SysmonEtwFieldUsesUnicodeStringType(EventId, field)) {
                if (!FormatFieldValueForEvent(
                        EventId,
                        PayloadBase,
                        PayloadSize,
                        field,
                        ProcessCreateEnrichment,
                        ImageLoadEnrichment,
                        fieldStringStorage,
                        StringStorageSlotChars)) {
                    wcscpy_s(fieldStringStorage, StringStorageSlotChars, L"-");
                }

                EventDataDescCreate(
                    &Descriptors[fieldIndex],
                    fieldStringStorage,
                    ((ULONG)wcslen(fieldStringStorage) + 1) * sizeof(WCHAR));
                break;
            }

            if (SysmonEtwFieldUsesUInt16Type(EventId, field)) {
                value16 = (USHORT)value32;
                CopyMemory(fieldStringStorage, &value16, sizeof(value16));
                EventDataDescCreate(
                    &Descriptors[fieldIndex],
                    fieldStringStorage,
                    sizeof(value16));
                break;
            }

            CopyMemory(fieldStringStorage, &value32, sizeof(value32));
            EventDataDescCreate(
                &Descriptors[fieldIndex],
                fieldStringStorage,
                sizeof(value32));
            break;

        case SysmonRenderUInt64:
        case SysmonRenderUInt64Hex:
            if (!HasPayloadBytes(PayloadSize, field->Offset, sizeof(ULONGLONG))) {
                if (FailureStatus != NULL) {
                    *FailureStatus = ERROR_INVALID_DATA;
                }
                if (FailureReason != NULL) {
                    *FailureReason = "missing 64-bit field bytes";
                }
                return 0;
            }

            value64 = SysmonReadPackedValue<ULONGLONG>(fieldPtr);
            if (SysmonEtwFieldUsesUnicodeStringType(EventId, field)) {
                if (!FormatFieldValueForEvent(
                        EventId,
                        PayloadBase,
                        PayloadSize,
                        field,
                        ProcessCreateEnrichment,
                        ImageLoadEnrichment,
                        fieldStringStorage,
                        StringStorageSlotChars)) {
                    wcscpy_s(fieldStringStorage, StringStorageSlotChars, L"-");
                }

                EventDataDescCreate(
                    &Descriptors[fieldIndex],
                    fieldStringStorage,
                    ((ULONG)wcslen(fieldStringStorage) + 1) * sizeof(WCHAR));
                break;
            }

            CopyMemory(fieldStringStorage, &value64, sizeof(value64));
            EventDataDescCreate(
                &Descriptors[fieldIndex],
                fieldStringStorage,
                sizeof(value64));
            break;

        case SysmonRenderBool: {
            ULONG boolValue;

            if (!HasPayloadBytes(PayloadSize, field->Offset, sizeof(BOOLEAN))) {
                if (FailureStatus != NULL) {
                    *FailureStatus = ERROR_INVALID_DATA;
                }
                if (FailureReason != NULL) {
                    *FailureReason = "missing boolean field bytes";
                }
                return 0;
            }

            boolValue = (SysmonReadPackedValue<BOOLEAN>(fieldPtr) != FALSE) ? 1UL : 0UL;
            if (SysmonEtwFieldUsesUnicodeStringType(EventId, field)) {
                if (!FormatFieldValueForEvent(
                        EventId,
                        PayloadBase,
                        PayloadSize,
                        field,
                        ProcessCreateEnrichment,
                        ImageLoadEnrichment,
                        fieldStringStorage,
                        StringStorageSlotChars)) {
                    wcscpy_s(fieldStringStorage, StringStorageSlotChars, L"-");
                }

                EventDataDescCreate(
                    &Descriptors[fieldIndex],
                    fieldStringStorage,
                    ((ULONG)wcslen(fieldStringStorage) + 1) * sizeof(WCHAR));
                break;
            }

            CopyMemory(fieldStringStorage, &boolValue, sizeof(boolValue));
            EventDataDescCreate(
                &Descriptors[fieldIndex],
                fieldStringStorage,
                sizeof(boolValue));
            break;
        }

        case SysmonRenderProcessTerminatePid:
            if (HasPayloadBytes(PayloadSize, field->Offset, sizeof(DWORD))) {
                value32 = SysmonReadPackedValue<DWORD>(fieldPtr);
            } else if (PayloadSize == sizeof(DWORD) &&
                       HasPayloadBytes(PayloadSize, 0, sizeof(DWORD))) {
                value32 = SysmonReadPackedValue<DWORD>(PayloadBase);
            } else {
                if (FailureStatus != NULL) {
                    *FailureStatus = ERROR_INVALID_DATA;
                }
                if (FailureReason != NULL) {
                    *FailureReason = "missing process terminate PID bytes";
                }
                return 0;
            }

            CopyMemory(fieldStringStorage, &value32, sizeof(value32));
            EventDataDescCreate(
                &Descriptors[fieldIndex],
                fieldStringStorage,
                sizeof(value32));
            break;

        default:
            if (FailureStatus != NULL) {
                *FailureStatus = ERROR_INVALID_DATA;
            }
            if (FailureReason != NULL) {
                *FailureReason = "unsupported ETW field render kind";
            }
            return 0;
        }
    }

    return Schema->FieldCount;
}

static ULONG
WriteEventEtwWithStorageMode(
    _In_ REGHANDLE ProviderHandle,
    _In_reads_bytes_(EventSize) const UCHAR *EventData,
    _In_ DWORD EventSize,
    _In_ SYSMON_EVENT_ID EventId,
    _In_ BOOL UseSharedStringStorage)
{
    const SYSMON_EVENT_HEADER *header;
    const EVENT_DESCRIPTOR *descriptor;
    SYSMON_OUTPUT_EVENT_CONTEXT context;
    EVENT_DATA_DESCRIPTOR eventDataDescriptors[SYSMON_ETW_DESCRIPTOR_CAPACITY];
    PWCHAR stringStorage;
    SIZE_T stringStorageBytes;
    ULONG descriptorCount;
    ULONG buildStatus;
    ULONG status;
    const char *buildFailureReason;

    stringStorage = NULL;
    if (ProviderHandle == 0 || EventData == NULL || EventSize < SYSMON_EVENT_HEADER_SIZE) {
        return ERROR_INVALID_PARAMETER;
    }

    descriptor = GetEtwEventDescriptor(EventId);
    if (descriptor == NULL) {
        return ERROR_NOT_SUPPORTED;
    }

    header = (const SYSMON_EVENT_HEADER *)EventData;
    if (header->EventSize < SYSMON_EVENT_HEADER_SIZE) {
        return ERROR_INVALID_DATA;
    }

    ZeroMemory(eventDataDescriptors, sizeof(eventDataDescriptors));
    SysmonPrepareOutputEventContext(
        EventId,
        EventData + SYSMON_EVENT_HEADER_SIZE,
        EventSize - SYSMON_EVENT_HEADER_SIZE,
        &context);

    if (context.Schema == NULL || context.Schema->Fields == NULL || context.Schema->FieldCount == 0) {
        return ERROR_NOT_SUPPORTED;
    }

    stringStorageBytes =
        (SIZE_T)context.Schema->FieldCount *
        (SIZE_T)SYSMON_ETW_STRING_STORAGE_CHARS *
        sizeof(WCHAR);
    if (UseSharedStringStorage) {
        stringStorage = SysmonEnsureEtwStringStorageCapacity(stringStorageBytes);
    } else {
        stringStorage = (PWCHAR)SYSMON_ALLOC(stringStorageBytes);
    }
    if (stringStorage == NULL) {
        return ERROR_NOT_ENOUGH_MEMORY;
    }

    descriptorCount = BuildEtwEventDataDescriptors(
        EventId,
        context.PayloadBase,
        context.PayloadSize,
        context.Schema,
        context.ProcessCreateEnrichment,
        context.ImageLoadEnrichment,
        eventDataDescriptors,
        stringStorage,
        SYSMON_ETW_STRING_STORAGE_CHARS,
        RTL_NUMBER_OF(eventDataDescriptors),
        &buildStatus,
        &buildFailureReason);
    if (descriptorCount == 0) {
        status = buildStatus;
        LogEtwDiagnostic(EventId, "build", buildStatus, buildFailureReason);
        goto Cleanup;
    }

    if (buildStatus != ERROR_SUCCESS) {
        /* A field could not be fully rendered (e.g. an invalid GUID string) and
           was emitted with a zero/placeholder value rather than dropping the
           event (U7). Log the diagnostic but still write the event. */
        LogEtwDiagnostic(EventId, "build-partial", buildStatus, buildFailureReason);
    }

    status = EventWrite(ProviderHandle, descriptor, descriptorCount, eventDataDescriptors);
    if (status != ERROR_SUCCESS) {
        LogEtwDiagnostic(EventId, "write", status, NULL);
        SysmonLogWarning(
            SYSMON_COMPONENT_OUTPUT,
            "EventWrite failed for event %u with status %lu",
            (unsigned)EventId,
            (unsigned long)status);
    }

Cleanup:
    if (!UseSharedStringStorage) {
        SYSMON_FREE(stringStorage);
    }

    return status;
}

static ULONG
WriteEventEtwWithHandle(
    _In_ REGHANDLE ProviderHandle,
    _In_reads_bytes_(EventSize) const UCHAR *EventData,
    _In_ DWORD EventSize,
    _In_ SYSMON_EVENT_ID EventId)
{
    return WriteEventEtwWithStorageMode(
        ProviderHandle,
        EventData,
        EventSize,
        EventId,
        TRUE);
}

static ULONG
WriteEventEtwWithTransientStorage(
    _In_ REGHANDLE ProviderHandle,
    _In_reads_bytes_(EventSize) const UCHAR *EventData,
    _In_ DWORD EventSize,
    _In_ SYSMON_EVENT_ID EventId)
{
    return WriteEventEtwWithStorageMode(
        ProviderHandle,
        EventData,
        EventSize,
        EventId,
        FALSE);
}

static ULONG
WriteOutputEventEtw(
    _In_reads_bytes_(EventSize) const UCHAR *EventData,
    _In_ DWORD EventSize,
    _In_ SYSMON_EVENT_ID EventId,
    _Out_opt_ BOOL *EtwEnabled)
{
    if (EtwEnabled != NULL) {
        *EtwEnabled = FALSE;
    }

    if ((g_OutputChannels & SYSMON_OUTPUT_ETW) == 0) {
        return ERROR_SUCCESS;
    }

    if (EtwEnabled != NULL) {
        *EtwEnabled = TRUE;
    }

    {
        CriticalSectionGuard etwLock(&g_OutputEtwLock);

        if (!g_EtwProviderRegistered) {
            return ERROR_INVALID_HANDLE;
        }

        return WriteEventEtwWithHandle(g_EtwProviderHandle, EventData, EventSize, EventId);
    }
}

static VOID
WriteOutputEventConsoleAndFile(
    _In_reads_bytes_(EventSize) const UCHAR *EventData,
    _In_ DWORD EventSize,
    _In_ SYSMON_EVENT_ID EventId)
{
    DWORD written;

    if ((g_OutputChannels & (SYSMON_OUTPUT_CONSOLE | SYSMON_OUTPUT_FILE)) == 0) {
        return;
    }

    written = 0;
    {
        CriticalSectionGuard sinkLock(&g_OutputSinkLock);

        if (g_OutputChannels & SYSMON_OUTPUT_CONSOLE) {
            RenderEventConsole(EventData, EventSize, EventId);
        }

        if ((g_OutputChannels & SYSMON_OUTPUT_FILE) && g_OutputFile != INVALID_HANDLE_VALUE) {
            if (!WriteFile(g_OutputFile, EventData, EventSize, &written, NULL) || written != EventSize) {
                SysmonLogWarning(SYSMON_COMPONENT_OUTPUT,
                    "Raw event append failed for event %u (wanted=%lu wrote=%lu)",
                    (unsigned)EventId,
                    (unsigned long)EventSize,
                    (unsigned long)written);
            }
        }
    }
}

static ULONG
WriteOutputEventUnlocked(
    _In_reads_bytes_(EventSize) const UCHAR *EventData,
    _In_ DWORD EventSize,
    _In_ SYSMON_EVENT_ID EventId,
    _Out_opt_ BOOL *EtwEnabled)
{
    WriteOutputEventConsoleAndFile(EventData, EventSize, EventId);
    return WriteOutputEventEtw(EventData, EventSize, EventId, EtwEnabled);
}

static ULONG
WriteOutputEventLocked(
    _In_reads_bytes_(EventSize) const UCHAR *EventData,
    _In_ DWORD EventSize,
    _In_ SYSMON_EVENT_ID EventId,
    _Out_opt_ BOOL *EtwEnabled)
{
    SharedSrwLockGuard outputStateLock(&g_OutputStateLock);

    if (!g_OutputInitialized) {
        if (EtwEnabled != NULL) {
            *EtwEnabled = FALSE;
        }
        return ERROR_SUCCESS;
    }

    return WriteOutputEventUnlocked(EventData, EventSize, EventId, EtwEnabled);
}

static VOID
SysmonWaitForTransientEtwEnable(
    _In_ REGHANDLE ProviderHandle,
    _In_ DWORD TimeoutMs)
{
    DWORD elapsed;

    if (ProviderHandle == 0) {
        return;
    }

    for (elapsed = 0; elapsed < TimeoutMs; elapsed += 10) {
        if (EventProviderEnabled(ProviderHandle, 0, 0)) {
            break;
        }

        Sleep(10);
    }
}

static void RenderEventConsole(
    _In_reads_bytes_(EventSize) const UCHAR *EventData,
    _In_ DWORD EventSize,
    _In_ SYSMON_EVENT_ID EventId)
{
    const char *eventName;
    const SYSMON_EVENT_HEADER *header;
    SYSMON_OUTPUT_EVENT_CONTEXT context;
    DWORD i;

    eventName = GetEventName(EventId);
    if (EventSize < SYSMON_EVENT_HEADER_SIZE) {
        wprintf(L"[Event %u] %hs (size=%lu)\n",
            (unsigned)EventId,
            eventName,
            (unsigned long)EventSize);
        wprintf(L"  ParseError: event smaller than header\n\n");
        return;
    }

    header = (const SYSMON_EVENT_HEADER *)EventData;
    if (header->EventSize != EventSize) {
        wprintf(L"[Event %u] %hs (size=%lu header=%lu)\n",
            (unsigned)EventId,
            eventName,
            (unsigned long)EventSize,
            (unsigned long)header->EventSize);
    } else {
        wprintf(L"[Event %u] %hs (size=%lu)\n",
            (unsigned)EventId,
            eventName,
            (unsigned long)EventSize);
    }

    SysmonPrepareOutputEventContext(
        EventId,
        EventData + SYSMON_EVENT_HEADER_SIZE,
        EventSize - SYSMON_EVENT_HEADER_SIZE,
        &context);

    if (context.Schema == NULL || context.Schema->Fields == NULL || context.Schema->FieldCount == 0) {
        wprintf(L"  Payload: raw/unparsed\n\n");
        return;
    }

    for (i = 0; i < context.Schema->FieldCount; i++) {
        WCHAR valueBuffer[2048];
        const WCHAR *valueText;

        valueText = L"-";
        if (FormatFieldValueForEvent(
                EventId,
                context.PayloadBase,
                context.PayloadSize,
                &context.Schema->Fields[i],
                context.ProcessCreateEnrichment,
                context.ImageLoadEnrichment,
                valueBuffer,
                _countof(valueBuffer))) {
            if (valueBuffer[0] != L'\0') {
                valueText = valueBuffer;
            }
        }

        wprintf(L"  %ls: %ls\n", context.Schema->Fields[i].Name, valueText);
    }

    wprintf(L"\n");
}

/*
 * SysmonOutputInit - Initialize output subsystem
 */
SYSMON_STATUS SysmonOutputInit(DWORD OutputChannels, LPCWSTR ArchiveDirectory)
{
    ULONG status;
    ExclusiveSrwLockGuard outputStateLock(&g_OutputStateLock);

    g_OutputChannels = OutputChannels;
    g_OutputFile = INVALID_HANDLE_VALUE;
    g_EtwDiagnosticsFile = INVALID_HANDLE_VALUE;
    g_EtwProviderHandle = 0;
    g_EtwProviderRegistered = FALSE;
    SysmonResetEtwStringStorage();
    SysmonInitializeOutputEnrichmentCaches();
    InitializeCriticalSection(&g_OutputSinkLock);
    InitializeCriticalSection(&g_OutputEtwLock);
    g_OutputInitialized = TRUE;

    if (OutputChannels & SYSMON_OUTPUT_ETW) {
        InitializeEtwDiagnosticsLog(ArchiveDirectory);
    }

    /* Open file output if requested */
    if ((OutputChannels & SYSMON_OUTPUT_FILE) && ArchiveDirectory) {
        WCHAR filePath[MAX_PATH];
        SYSTEMTIME st;
        GetLocalTime(&st);

        _snwprintf_s(filePath, _countof(filePath), _TRUNCATE,
            L"%s\\Sysmon_%04d%02d%02d.bin",
            ArchiveDirectory, st.wYear, st.wMonth, st.wDay);

        /* Create directory if needed */
        CreateDirectoryW(ArchiveDirectory, NULL);

        g_OutputFile = CreateFileW(filePath,
            GENERIC_WRITE, FILE_SHARE_READ, NULL,
            OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);

        if (g_OutputFile == INVALID_HANDLE_VALUE) {
            SysmonLogWarning(SYSMON_COMPONENT_OUTPUT,
                "Failed to open output file: %ls", filePath);
        } else {
            /* Seek to end for append */
            SetFilePointer(g_OutputFile, 0, NULL, FILE_END);
            SysmonLogInfo(SYSMON_COMPONENT_OUTPUT,
                "Event logging to: %ls", filePath);
        }
    }

    if (OutputChannels & SYSMON_OUTPUT_ETW) {
        status = EventRegister(&SYSMON_PROVIDER_GUID, NULL, NULL, &g_EtwProviderHandle);
        LogEtwDiagnostic((SYSMON_EVENT_ID)0, "register", status, NULL);
        if (status != ERROR_SUCCESS) {
            SysmonLogWarning(
                SYSMON_COMPONENT_OUTPUT,
                "EventRegister failed with status %lu",
                (unsigned long)status);
            g_EtwProviderHandle = 0;
        } else {
            g_EtwProviderRegistered = TRUE;
        }
    }

    return SYSMON_SUCCESS;
}

/*
 * SysmonOutputCleanup - Flush and close output handles
 */
void SysmonOutputCleanup(void)
{
    ExclusiveSrwLockGuard outputStateLock(&g_OutputStateLock);

    if (!g_OutputInitialized) return;

    g_OutputInitialized = FALSE;

    {
        CriticalSectionGuard sinkLock(&g_OutputSinkLock);

        if (g_OutputFile != INVALID_HANDLE_VALUE) {
            FlushFileBuffers(g_OutputFile);
            CloseHandle(g_OutputFile);
            g_OutputFile = INVALID_HANDLE_VALUE;
        }
    }

    {
        CriticalSectionGuard etwLock(&g_OutputEtwLock);

        CloseEtwDiagnosticsFile();

        if (g_EtwProviderRegistered) {
            EventUnregister(g_EtwProviderHandle);
            g_EtwProviderHandle = 0;
            g_EtwProviderRegistered = FALSE;
        }

        SysmonResetEtwStringStorage();
    }

    SysmonCleanupOutputEnrichmentCaches();
    DeleteCriticalSection(&g_OutputEtwLock);
    DeleteCriticalSection(&g_OutputSinkLock);
}

/*
 * SysmonOutputEvent - Write event to all active output channels
 *
 * Console: schema-ordered human-readable fields
 * File: raw event data append fallback
 */
void SysmonOutputEvent(PUCHAR EventData, DWORD EventSize, SYSMON_EVENT_ID EventId)
{
    if (EventData == NULL || EventSize == 0) return;

    (void)WriteOutputEventLocked(EventData, EventSize, EventId, NULL);
}

static SYSMON_STATUS
SysmonEmitBuiltInternalEventEx(
    _In_reads_bytes_(EventSize) const UCHAR *EventData,
    _In_ DWORD EventSize,
    _In_ SYSMON_EVENT_ID EventId,
    _In_ BOOL ForceTransientEtw)
{
    REGHANDLE providerHandle;
    ULONG status;

    if (EventData == NULL || EventSize < SYSMON_EVENT_HEADER_SIZE) {
        return SYSMON_ERROR_INVALID_PARAM;
    }

    if (!ForceTransientEtw) {
        BOOL etwEnabled;

        status = WriteOutputEventLocked(EventData, EventSize, EventId, &etwEnabled);

        if (etwEnabled && status != ERROR_SUCCESS) {
            return status;
        }

        return SYSMON_SUCCESS;
    }

    providerHandle = 0;
    status = EventRegister(&SYSMON_PROVIDER_GUID, NULL, NULL, &providerHandle);
    if (status != ERROR_SUCCESS) {
        SysmonLogWarning(
            SYSMON_COMPONENT_OUTPUT,
            "Transient EventRegister failed for internal event %u with status %lu",
            (unsigned)EventId,
            (unsigned long)status);
        return status;
    }

    SysmonWaitForTransientEtwEnable(providerHandle, 250);
    {
        SharedSrwLockGuard outputStateLock(&g_OutputStateLock);

        if (g_OutputInitialized) {
            CriticalSectionGuard etwLock(&g_OutputEtwLock);

            status = WriteEventEtwWithHandle(providerHandle, EventData, EventSize, EventId);
        } else {
            status = WriteEventEtwWithTransientStorage(
                providerHandle,
                EventData,
                EventSize,
                EventId);
        }
    }
    EventUnregister(providerHandle);
    return status;
}

static SYSMON_STATUS
SysmonEmitBuiltInternalEvent(
    _In_reads_bytes_(EventSize) const UCHAR *EventData,
    _In_ DWORD EventSize,
    _In_ SYSMON_EVENT_ID EventId)
{
    return SysmonEmitBuiltInternalEventEx(EventData, EventSize, EventId, FALSE);
}

static SYSMON_STATUS
SysmonBuildServiceStateEvent(
    _In_z_ LPCWSTR State,
    _Out_writes_bytes_(EventBufferSize) PBYTE EventBuffer,
    _In_ DWORD EventBufferSize,
    _Out_ PDWORD EventSize)
{
    SYSMON_EVENT_PAYLOAD_BUILDER builder;
    SYSMON_EVENT_SERVICE_STATE_PAYLOAD *payload;
    WCHAR utcTime[64];
    WCHAR version[32];
    ULONGLONG timestamp;
    SYSMON_STATUS status;

    if (State == NULL || EventBuffer == NULL || EventSize == NULL) {
        return SYSMON_ERROR_INVALID_PARAM;
    }

    timestamp = 0;
    if (!SysmonFormatSyntheticUtcTimestamp(0, utcTime, _countof(utcTime), &timestamp)) {
        return ERROR_INVALID_DATA;
    }

    SysmonInitializeEventBuffer(
        EventBuffer,
        EventBufferSize,
        SysmonEventServiceState,
        sizeof(*payload),
        &builder,
        timestamp);
    payload = (SYSMON_EVENT_SERVICE_STATE_PAYLOAD *)(EventBuffer + SYSMON_EVENT_HEADER_SIZE);

    SysmonResolveCurrentModuleFileVersion(version, _countof(version));

    status = SysmonAddStringField(EventBuffer, EventBufferSize, &builder, &payload->UtcTime, utcTime);
    if (status != SYSMON_SUCCESS) return status;
    status = SysmonAddStringField(EventBuffer, EventBufferSize, &builder, &payload->State, State);
    if (status != SYSMON_SUCCESS) return status;
    status = SysmonAddStringField(EventBuffer, EventBufferSize, &builder, &payload->Version, version);
    if (status != SYSMON_SUCCESS) return status;
    status = SysmonAddStringField(EventBuffer, EventBufferSize, &builder, &payload->SchemaVersion, SYSMON_SCHEMA_VERSION);
    if (status != SYSMON_SUCCESS) return status;

    *EventSize = ((const SYSMON_EVENT_HEADER *)EventBuffer)->EventSize;
    return SYSMON_SUCCESS;
}

static SYSMON_STATUS
SysmonBuildConfigChangeEvent(
    _In_opt_z_ LPCWSTR Configuration,
    _In_opt_z_ LPCWSTR ConfigurationFileHash,
    _Out_writes_bytes_(EventBufferSize) PBYTE EventBuffer,
    _In_ DWORD EventBufferSize,
    _Out_ PDWORD EventSize)
{
    SYSMON_EVENT_PAYLOAD_BUILDER builder;
    SYSMON_EVENT_CONFIG_CHANGE_PAYLOAD *payload;
    WCHAR utcTime[64];
    ULONGLONG timestamp;
    SYSMON_STATUS status;

    if (EventBuffer == NULL || EventSize == NULL) {
        return SYSMON_ERROR_INVALID_PARAM;
    }

    timestamp = 0;
    if (!SysmonFormatSyntheticUtcTimestamp(0, utcTime, _countof(utcTime), &timestamp)) {
        return ERROR_INVALID_DATA;
    }

    SysmonInitializeEventBuffer(
        EventBuffer,
        EventBufferSize,
        SysmonEventConfigChange,
        sizeof(*payload),
        &builder,
        timestamp);
    payload = (SYSMON_EVENT_CONFIG_CHANGE_PAYLOAD *)(EventBuffer + SYSMON_EVENT_HEADER_SIZE);

    status = SysmonAddStringField(EventBuffer, EventBufferSize, &builder, &payload->UtcTime, utcTime);
    if (status != SYSMON_SUCCESS) return status;
    status = SysmonAddStringField(EventBuffer, EventBufferSize, &builder, &payload->Configuration, Configuration);
    if (status != SYSMON_SUCCESS) return status;
    status = SysmonAddStringField(EventBuffer, EventBufferSize, &builder, &payload->ConfigurationFileHash, ConfigurationFileHash);
    if (status != SYSMON_SUCCESS) return status;

    *EventSize = ((const SYSMON_EVENT_HEADER *)EventBuffer)->EventSize;
    return SYSMON_SUCCESS;
}

SYSMON_STATUS
SysmonEmitServiceStateEvent(
    _In_z_ LPCWSTR State)
{
    BYTE eventBuffer[512];
    DWORD eventSize;
    SYSMON_STATUS status;

    status = SysmonBuildServiceStateEvent(State, eventBuffer, sizeof(eventBuffer), &eventSize);
    if (status != SYSMON_SUCCESS) {
        return status;
    }

    return SysmonEmitBuiltInternalEvent(eventBuffer, eventSize, SysmonEventServiceState);
}

SYSMON_STATUS
SysmonEmitServiceStateEventTransient(
    _In_z_ LPCWSTR State)
{
    BYTE eventBuffer[512];
    DWORD eventSize;
    SYSMON_STATUS status;

    status = SysmonBuildServiceStateEvent(State, eventBuffer, sizeof(eventBuffer), &eventSize);
    if (status != SYSMON_SUCCESS) {
        return status;
    }

    return SysmonEmitBuiltInternalEventEx(eventBuffer, eventSize, SysmonEventServiceState, TRUE);
}

SYSMON_STATUS
SysmonEmitConfigChangeEvent(
    _In_opt_z_ LPCWSTR Configuration,
    _In_opt_z_ LPCWSTR ConfigurationFileHash)
{
    BYTE eventBuffer[2048];
    DWORD eventSize;
    SYSMON_STATUS status;

    status = SysmonBuildConfigChangeEvent(
        Configuration,
        ConfigurationFileHash,
        eventBuffer,
        sizeof(eventBuffer),
        &eventSize);
    if (status != SYSMON_SUCCESS) {
        return status;
    }

    return SysmonEmitBuiltInternalEvent(eventBuffer, eventSize, SysmonEventConfigChange);
}

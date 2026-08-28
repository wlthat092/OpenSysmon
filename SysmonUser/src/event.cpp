/*
 * event.c - Event helpers for synthetic user-mode events and rule matching
 */

#include "../include/event.h"
#include "../include/event_schema.h"
#include "../include/packed_read.hpp"

#define SYSMON_INTERNAL_EVENT_MIN_SIZE ((DWORD)SYSMON_EVENT_HEADER_SIZE)
#define SYSMON_UNKNOWN_EVENT_MIN_SIZE ((DWORD)-1)

static volatile LONG g_SyntheticSequenceNumber = 0;

static const struct {
    SYSMON_EVENT_ID Id;
    DWORD MinSize;
} g_EventMinSizes[] = {
    { SysmonEventProcessCreate,          SYSMON_EVENT_CONTRACT_SIZE(SYSMON_EVENT_PROCESS_CREATE_PAYLOAD) },
    { SysmonEventFileCreateTime,         SYSMON_EVENT_CONTRACT_SIZE(SYSMON_EVENT_FILE_CREATE_TIME_PAYLOAD) },
    { SysmonEventNetworkConnect,         SYSMON_EVENT_CONTRACT_SIZE(SYSMON_EVENT_NETWORK_CONNECT_PAYLOAD) },
    { SysmonEventServiceState,           SYSMON_EVENT_CONTRACT_SIZE(SYSMON_EVENT_SERVICE_STATE_PAYLOAD) },
    { SysmonEventProcessTerminate,       SYSMON_EVENT_CONTRACT_SIZE(SYSMON_EVENT_PROCESS_TERMINATE_PAYLOAD) },
    { SysmonEventDriverLoad,             SYSMON_EVENT_CONTRACT_SIZE(SYSMON_EVENT_DRIVER_LOAD_PAYLOAD) },
    { SysmonEventImageLoad,              SYSMON_EVENT_CONTRACT_SIZE(SYSMON_EVENT_IMAGE_LOAD_PAYLOAD) },
    { SysmonEventCreateRemoteThread,     SYSMON_EVENT_CONTRACT_SIZE(SYSMON_EVENT_CREATE_REMOTE_THREAD_PAYLOAD) },
    { SysmonEventRawAccessRead,          SYSMON_EVENT_CONTRACT_SIZE(SYSMON_EVENT_RAW_ACCESS_READ_PAYLOAD) },
    { SysmonEventProcessAccess,          SYSMON_EVENT_CONTRACT_SIZE(SYSMON_EVENT_PROCESS_ACCESS_PAYLOAD) },
    { SysmonEventFileCreate,             SYSMON_EVENT_CONTRACT_SIZE(SYSMON_EVENT_FILE_CREATE_PAYLOAD) },
    { SysmonEventRegistryEvent,          SYSMON_EVENT_CONTRACT_SIZE(SYSMON_EVENT_REGISTRY_EVENT_PAYLOAD) },
    { SysmonEventRegistryValueSet,       SYSMON_EVENT_CONTRACT_SIZE(SYSMON_EVENT_REGISTRY_VALUE_SET_PAYLOAD) },
    { SysmonEventRegistryRename,         SYSMON_EVENT_CONTRACT_SIZE(SYSMON_EVENT_REGISTRY_RENAME_PAYLOAD) },
    { SysmonEventFileCreateStreamHash,   SYSMON_EVENT_CONTRACT_SIZE(SYSMON_EVENT_FILE_CREATE_STREAM_HASH_PAYLOAD) },
    { SysmonEventConfigChange,           SYSMON_EVENT_CONTRACT_SIZE(SYSMON_EVENT_CONFIG_CHANGE_PAYLOAD) },
    { SysmonEventPipeCreated,            SYSMON_EVENT_CONTRACT_SIZE(SYSMON_EVENT_PIPE_CREATED_PAYLOAD) },
    { SysmonEventPipeConnected,          SYSMON_EVENT_CONTRACT_SIZE(SYSMON_EVENT_PIPE_PAYLOAD) },
    { SysmonEventWmiFilter,              SYSMON_EVENT_CONTRACT_SIZE(SYSMON_EVENT_WMI_FILTER_PAYLOAD) },
    { SysmonEventWmiConsumer,            SYSMON_EVENT_CONTRACT_SIZE(SYSMON_EVENT_WMI_CONSUMER_PAYLOAD) },
    { SysmonEventWmiConsumerToFilter,    SYSMON_EVENT_CONTRACT_SIZE(SYSMON_EVENT_WMI_CONSUMER_TO_FILTER_PAYLOAD) },
    { SysmonEventDnsQuery,               SYSMON_EVENT_CONTRACT_SIZE(SYSMON_EVENT_DNS_QUERY_PAYLOAD) },
    { SysmonEventFileDelete,             SYSMON_EVENT_CONTRACT_SIZE(SYSMON_EVENT_FILE_DELETE_PAYLOAD) },
    { SysmonEventClipboardChange,        SYSMON_EVENT_CONTRACT_SIZE(SYSMON_EVENT_CLIPBOARD_CHANGE_PAYLOAD) },
    { SysmonEventProcessTampering,       SYSMON_EVENT_CONTRACT_SIZE(SYSMON_EVENT_PROCESS_TAMPERING_PAYLOAD) },
    { SysmonEventFileDeleteDetected,     SYSMON_EVENT_CONTRACT_SIZE(SYSMON_EVENT_FILE_BLOCK_PAYLOAD) },
    { SysmonEventFileBlockExecutable,    SYSMON_EVENT_CONTRACT_SIZE(SYSMON_EVENT_FILE_HASH_PAYLOAD) },
    { SysmonEventFileBlockShredding,     SYSMON_EVENT_CONTRACT_SIZE(SYSMON_EVENT_FILE_BLOCK_PAYLOAD) },
    { SysmonEventFileExecutableDetected, SYSMON_EVENT_CONTRACT_SIZE(SYSMON_EVENT_FILE_HASH_PAYLOAD) },
    { SysmonEventDropped,                SYSMON_INTERNAL_EVENT_MIN_SIZE },
    { SysmonEventError,                  SYSMON_INTERNAL_EVENT_MIN_SIZE },
};


static ULONGLONG
SysmonGetCurrentTimestamp(void)
{
    FILETIME fileTime;
    ULARGE_INTEGER stamp;

    GetSystemTimeAsFileTime(&fileTime);
    stamp.LowPart = fileTime.dwLowDateTime;
    stamp.HighPart = fileTime.dwHighDateTime;
    return stamp.QuadPart;
}

BOOL
SysmonFormatSyntheticUtcTimestamp(
    _In_ ULONGLONG RawTimestamp,
    _Out_writes_(BufferChars) PWCHAR Buffer,
    _In_ size_t BufferChars,
    _Out_opt_ PULONGLONG Timestamp)
{
    FILETIME fileTime;
    SYSTEMTIME systemTime;
    ULARGE_INTEGER timeValue;

    if (Buffer == NULL || BufferChars == 0) {
        return FALSE;
    }

    if (RawTimestamp == 0) {
        GetSystemTimeAsFileTime(&fileTime);
        timeValue.LowPart = fileTime.dwLowDateTime;
        timeValue.HighPart = fileTime.dwHighDateTime;
    } else {
        timeValue.QuadPart = RawTimestamp;
        fileTime.dwLowDateTime = timeValue.LowPart;
        fileTime.dwHighDateTime = timeValue.HighPart;
    }

    if (!FileTimeToSystemTime(&fileTime, &systemTime)) {
        Buffer[0] = L'\0';
        return FALSE;
    }

    if (Timestamp != NULL) {
        *Timestamp = timeValue.QuadPart;
    }

    return SUCCEEDED(_snwprintf_s(
        Buffer,
        BufferChars,
        _TRUNCATE,
        L"%04u-%02u-%02u %02u:%02u:%02u.%03u",
        (unsigned)systemTime.wYear,
        (unsigned)systemTime.wMonth,
        (unsigned)systemTime.wDay,
        (unsigned)systemTime.wHour,
        (unsigned)systemTime.wMinute,
        (unsigned)systemTime.wSecond,
        (unsigned)systemTime.wMilliseconds));
}

static BOOL
SysmonHasPayloadBytes(
    _In_ DWORD PayloadSize,
    _In_ size_t Offset,
    _In_ size_t Size)
{
    return Offset <= PayloadSize && Size <= (size_t)(PayloadSize - Offset);
}

static BOOL
SysmonCopyLiteralString(
    _Out_writes_(BufferChars) PWCHAR Buffer,
    _In_ size_t BufferChars,
    _In_z_ PCWSTR Value)
{
    return Buffer != NULL &&
        BufferChars != 0 &&
        Value != NULL &&
        wcscpy_s(Buffer, BufferChars, Value) == 0;
}

static BOOL
SysmonFormatUInt32(
    _In_ DWORD Value,
    _Out_writes_(BufferChars) PWCHAR Buffer,
    _In_ size_t BufferChars,
    _In_ BOOL Hex)
{
    if (Buffer == NULL || BufferChars == 0) {
        return FALSE;
    }

    if (Hex) {
        return SUCCEEDED(_snwprintf_s(Buffer, BufferChars, _TRUNCATE, L"0x%lx", (unsigned long)Value));
    }

    return SUCCEEDED(_snwprintf_s(Buffer, BufferChars, _TRUNCATE, L"%lu", (unsigned long)Value));
}

static BOOL
SysmonFormatUInt64Hex(
    _In_ ULONGLONG Value,
    _Out_writes_(BufferChars) PWCHAR Buffer,
    _In_ size_t BufferChars)
{
    if (Buffer == NULL || BufferChars == 0) {
        return FALSE;
    }

    return SUCCEEDED(_snwprintf_s(Buffer, BufferChars, _TRUNCATE, L"0x%llx", Value));
}

static BOOL
SysmonFormatUInt64(
    _In_ ULONGLONG Value,
    _Out_writes_(BufferChars) PWCHAR Buffer,
    _In_ size_t BufferChars)
{
    if (Buffer == NULL || BufferChars == 0) {
        return FALSE;
    }

    return SUCCEEDED(_snwprintf_s(Buffer, BufferChars, _TRUNCATE, L"%llu", Value));
}

static BOOL
SysmonFormatBoolean(
    _In_ BOOLEAN Value,
    _Out_writes_(BufferChars) PWCHAR Buffer,
    _In_ size_t BufferChars)
{
    return SysmonCopyLiteralString(Buffer, BufferChars, Value ? L"true" : L"false");
}

static LPCWSTR
SysmonNormalizeFieldName(
    _In_opt_ LPCWSTR FieldName)
{
    if (FieldName == NULL) {
        return NULL;
    }

    if (_wcsicmp(FieldName, EVT_FIELD_UTCTIME) == 0) {
        return EVT_FIELD_UTC_TIME;
    }
    if (_wcsicmp(FieldName, EVT_FIELD_DEST_IP) == 0) {
        return EVT_FIELD_DESTINATION_IP;
    }
    if (_wcsicmp(FieldName, EVT_FIELD_DEST_PORT) == 0) {
        return EVT_FIELD_DESTINATION_PORT;
    }
    if (_wcsicmp(FieldName, EVT_FIELD_DEST_HOSTNAME) == 0) {
        return EVT_FIELD_DESTINATION_HOSTNAME;
    }
    if (_wcsicmp(FieldName, EVT_FIELD_USER_SID) == 0) {
        return EVT_FIELD_USER;
    }
    if (_wcsicmp(FieldName, EVT_FIELD_QUERY_RESULT_STR) == 0) {
        return EVT_FIELD_QUERY_RESULTS;
    }
    if (_wcsicmp(FieldName, EVT_FIELD_CONNECTED) == 0) {
        return EVT_FIELD_INITIATED;
    }
    return FieldName;
}

static BOOL
SysmonIsRegistryRuleField(
    _In_ SYSMON_EVENT_ID EventId,
    _In_opt_ LPCWSTR FieldName)
{
    if (FieldName == NULL) {
        return FALSE;
    }

    if (EventId != SysmonEventRegistryEvent &&
        EventId != SysmonEventRegistryValueSet &&
        EventId != SysmonEventRegistryRename) {
        return FALSE;
    }

    return _wcsicmp(FieldName, EVT_FIELD_TARGET_OBJECT) == 0 ||
        _wcsicmp(FieldName, EVT_FIELD_NEW_NAME) == 0;
}

static BOOL
SysmonQueryCurrentControlSetName(
    _Out_writes_(BufferChars) PWCHAR Buffer,
    _In_ size_t BufferChars)
{
    HKEY key = NULL;
    DWORD current = 0;
    DWORD type = REG_DWORD;
    DWORD size = sizeof(current);
    LONG result;

    if (Buffer == NULL || BufferChars < 16) {
        return FALSE;
    }

    Buffer[0] = L'\0';
    result = RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"SYSTEM\\Select", 0, KEY_QUERY_VALUE, &key);
    if (result != ERROR_SUCCESS) {
        return FALSE;
    }

    result = RegQueryValueExW(key, L"Current", NULL, &type, (LPBYTE)&current, &size);
    RegCloseKey(key);
    if (result != ERROR_SUCCESS || type != REG_DWORD) {
        return FALSE;
    }

    return SUCCEEDED(_snwprintf_s(Buffer, BufferChars, _TRUNCATE, L"ControlSet%03lu", (unsigned long)current));
}

static VOID
SysmonNormalizeRegistryFieldForMatching(
    _Inout_updates_(BufferChars) PWCHAR Buffer,
    _In_ size_t BufferChars)
{
    static const WCHAR g_NativePrefix[] = L"\\REGISTRY\\";
    static const WCHAR g_Hklm[] = L"HKLM";
    static const WCHAR g_HkeyLocalMachine[] = L"HKEY_LOCAL_MACHINE";
    static const WCHAR g_Hku[] = L"HKU";
    static const WCHAR g_HkeyUsers[] = L"HKEY_USERS";
    static const WCHAR g_Hkcr[] = L"HKCR";
    static const WCHAR g_HkeyClassesRoot[] = L"HKEY_CLASSES_ROOT";
    static const WCHAR g_MachineRoot[] = L"\\REGISTRY\\MACHINE";
    static const WCHAR g_UserRoot[] = L"\\REGISTRY\\USER";
    static const WCHAR g_ClassesRoot[] = L"\\REGISTRY\\MACHINE\\SOFTWARE\\Classes";
    static const WCHAR g_CurrentControlSetPrefix[] =
        L"\\REGISTRY\\MACHINE\\SYSTEM\\CurrentControlSet";
    static const WCHAR g_HardwareProfilesPrefix[] =
        L"\\REGISTRY\\MACHINE\\SYSTEM\\CurrentControlSet\\Hardware Profiles\\Current";
    WCHAR normalized[1024];
    WCHAR controlSetName[16];
    LPCWSTR source;
    LPCWSTR nativeRoot;
    LPCWSTR suffix;
    size_t nativeRootChars;
    size_t suffixChars;

    if (Buffer == NULL || BufferChars == 0 || Buffer[0] == L'\0') {
        return;
    }

    source = Buffer;
    nativeRoot = NULL;
    suffix = NULL;
    normalized[0] = L'\0';

    if (_wcsnicmp(source, g_NativePrefix, _countof(g_NativePrefix) - 1) == 0) {
        (void)SysmonCopyLiteralString(normalized, _countof(normalized), source);
    } else if (_wcsnicmp(source, g_HkeyLocalMachine, _countof(g_HkeyLocalMachine) - 1) == 0 &&
               (source[_countof(g_HkeyLocalMachine) - 1] == L'\0' ||
                source[_countof(g_HkeyLocalMachine) - 1] == L'\\')) {
        nativeRoot = g_MachineRoot;
        suffix = source + _countof(g_HkeyLocalMachine) - 1;
    } else if (_wcsnicmp(source, g_Hklm, _countof(g_Hklm) - 1) == 0 &&
               (source[_countof(g_Hklm) - 1] == L'\0' ||
                source[_countof(g_Hklm) - 1] == L'\\')) {
        nativeRoot = g_MachineRoot;
        suffix = source + _countof(g_Hklm) - 1;
    } else if (_wcsnicmp(source, g_HkeyUsers, _countof(g_HkeyUsers) - 1) == 0 &&
               (source[_countof(g_HkeyUsers) - 1] == L'\0' ||
                source[_countof(g_HkeyUsers) - 1] == L'\\')) {
        nativeRoot = g_UserRoot;
        suffix = source + _countof(g_HkeyUsers) - 1;
    } else if (_wcsnicmp(source, g_Hku, _countof(g_Hku) - 1) == 0 &&
               (source[_countof(g_Hku) - 1] == L'\0' ||
                source[_countof(g_Hku) - 1] == L'\\')) {
        nativeRoot = g_UserRoot;
        suffix = source + _countof(g_Hku) - 1;
    } else if (_wcsnicmp(source, g_HkeyClassesRoot, _countof(g_HkeyClassesRoot) - 1) == 0 &&
               (source[_countof(g_HkeyClassesRoot) - 1] == L'\0' ||
                source[_countof(g_HkeyClassesRoot) - 1] == L'\\')) {
        nativeRoot = g_ClassesRoot;
        suffix = source + _countof(g_HkeyClassesRoot) - 1;
    } else if (_wcsnicmp(source, g_Hkcr, _countof(g_Hkcr) - 1) == 0 &&
               (source[_countof(g_Hkcr) - 1] == L'\0' ||
                source[_countof(g_Hkcr) - 1] == L'\\')) {
        nativeRoot = g_ClassesRoot;
        suffix = source + _countof(g_Hkcr) - 1;
    }

    if (nativeRoot != NULL && suffix != NULL) {
        nativeRootChars = wcslen(nativeRoot);
        suffixChars = wcslen(suffix);
        if (nativeRootChars + suffixChars >= _countof(normalized)) {
            suffixChars = _countof(normalized) - nativeRootChars - 1;
        }

        CopyMemory(normalized, nativeRoot, nativeRootChars * sizeof(WCHAR));
        CopyMemory(normalized + nativeRootChars, suffix, suffixChars * sizeof(WCHAR));
        normalized[nativeRootChars + suffixChars] = L'\0';
    }

    if (normalized[0] == L'\0') {
        return;
    }

    if (_wcsnicmp(
            normalized,
            g_CurrentControlSetPrefix,
            _countof(g_CurrentControlSetPrefix) - 1) == 0 &&
        _wcsnicmp(
            normalized,
            g_HardwareProfilesPrefix,
            _countof(g_HardwareProfilesPrefix) - 1) != 0 &&
        SysmonQueryCurrentControlSetName(controlSetName, _countof(controlSetName))) {
        suffix = normalized + _countof(g_CurrentControlSetPrefix) - 1;
        (void)_snwprintf_s(
            Buffer,
            BufferChars,
            _TRUNCATE,
            L"\\REGISTRY\\MACHINE\\SYSTEM\\%ls%ls",
            controlSetName,
            suffix);
        return;
    }

    (void)SysmonCopyLiteralString(Buffer, BufferChars, normalized);
}

DWORD
SysmonGetEventMinSize(
    _In_ SYSMON_EVENT_ID EventId)
{
    int index;

    for (index = 0; index < _countof(g_EventMinSizes); index++) {
        if (g_EventMinSizes[index].Id == EventId) {
            return g_EventMinSizes[index].MinSize;
        }
    }

    return SYSMON_UNKNOWN_EVENT_MIN_SIZE;
}

void
SysmonInitializeEventBuffer(
    PBYTE EventBuffer,
    DWORD EventBufferSize,
    SYSMON_EVENT_ID EventId,
    DWORD PayloadSize,
    PSYSMON_EVENT_PAYLOAD_BUILDER Builder,
    ULONGLONG Timestamp)
{
    PSYSMON_EVENT_HEADER header;

    if (EventBuffer == NULL || Builder == NULL) {
        return;
    }

    ZeroMemory(Builder, sizeof(*Builder));
    ZeroMemory(EventBuffer, EventBufferSize);

    if (EventBufferSize < SYSMON_EVENT_HEADER_SIZE + PayloadSize) {
        return;
    }

    header = (PSYSMON_EVENT_HEADER)EventBuffer;
    header->EventId = (ULONG)EventId;
    header->EventSize = (ULONG)(SYSMON_EVENT_HEADER_SIZE + PayloadSize);
    header->SequenceNumber = (ULONG)InterlockedIncrement(&g_SyntheticSequenceNumber);
    header->Padding = 0;
    header->Timestamp = Timestamp != 0 ? (LONGLONG)Timestamp : (LONGLONG)SysmonGetCurrentTimestamp();

    Builder->PayloadSize = PayloadSize;
    Builder->Cursor = PayloadSize;
    Builder->Capacity = EventBufferSize - SYSMON_EVENT_HEADER_SIZE;
}

SYSMON_STATUS
SysmonAddStringField(
    PBYTE EventBuffer,
    DWORD EventBufferSize,
    PSYSMON_EVENT_PAYLOAD_BUILDER Builder,
    SYSMON_EVENT_STRING_REF *Ref,
    PCWSTR Source)
{
    size_t sourceChars;
    DWORD bytes;
    DWORD bytesWithTerminator;
    PBYTE payloadBase;
    PBYTE destination;

    if (EventBuffer == NULL || Builder == NULL || Ref == NULL) {
        return SYSMON_ERROR_INVALID_PARAM;
    }

    Ref->Offset = 0;
    Ref->LengthBytes = 0;

    if (Source == NULL || Source[0] == L'\0') {
        return SYSMON_SUCCESS;
    }

    if (EventBufferSize < SYSMON_EVENT_HEADER_SIZE || Builder->Capacity > EventBufferSize - SYSMON_EVENT_HEADER_SIZE) {
        return ERROR_INVALID_DATA;
    }

    sourceChars = wcslen(Source);
    bytes = (DWORD)(sourceChars * sizeof(WCHAR));
    bytesWithTerminator = bytes + sizeof(WCHAR);
    if (Builder->Cursor > Builder->Capacity || bytesWithTerminator > Builder->Capacity - Builder->Cursor) {
        return ERROR_BUFFER_OVERFLOW;
    }

    payloadBase = EventBuffer + SYSMON_EVENT_HEADER_SIZE;
    destination = payloadBase + Builder->Cursor;
    CopyMemory(destination, Source, bytes);
    ZeroMemory(destination + bytes, sizeof(WCHAR));

    Ref->Offset = Builder->Cursor;
    Ref->LengthBytes = bytes;
    Builder->Cursor += bytesWithTerminator;
    ((PSYSMON_EVENT_HEADER)EventBuffer)->EventSize = (ULONG)(SYSMON_EVENT_HEADER_SIZE + Builder->Cursor);
    return SYSMON_SUCCESS;
}

BOOL
SysmonCopyStringField(
    const BYTE *EventData,
    DWORD EventSize,
    SYSMON_EVENT_STRING_REF Ref,
    PWCHAR Buffer,
    size_t BufferChars)
{
    const BYTE *payloadBase;
    DWORD payloadSize;
    size_t copyBytes;

    if (EventData == NULL || Buffer == NULL || BufferChars == 0 || EventSize < SYSMON_EVENT_HEADER_SIZE) {
        return FALSE;
    }

    Buffer[0] = L'\0';
    payloadBase = EventData + SYSMON_EVENT_HEADER_SIZE;
    payloadSize = EventSize - SYSMON_EVENT_HEADER_SIZE;

    if (Ref.LengthBytes == 0) {
        return TRUE;
    }

    if ((Ref.LengthBytes % sizeof(WCHAR)) != 0 ||
        !SysmonHasPayloadBytes(payloadSize, Ref.Offset, Ref.LengthBytes)) {
        return FALSE;
    }

    copyBytes = Ref.LengthBytes;
    if (copyBytes >= BufferChars * sizeof(WCHAR)) {
        copyBytes = (BufferChars - 1) * sizeof(WCHAR);
    }

    CopyMemory(Buffer, payloadBase + Ref.Offset, copyBytes);
    Buffer[copyBytes / sizeof(WCHAR)] = L'\0';
    return TRUE;
}

BOOL
SysmonExtractEventField(
    const BYTE *EventData,
    DWORD EventSize,
    SYSMON_EVENT_ID EventId,
    LPCWSTR FieldName,
    PWCHAR Buffer,
    size_t BufferChars)
{
    const SYSMON_EVENT_SCHEMA *schema;
    const BYTE *payloadBase;
    DWORD payloadSize;
    DWORD fieldIndex;
    SYSMON_EVENT_ID lookupEventId;
    LPCWSTR normalizedFieldName;

    if (EventData == NULL || FieldName == NULL || Buffer == NULL || BufferChars == 0) {
        return FALSE;
    }

    Buffer[0] = L'\0';
    if (EventSize < SYSMON_EVENT_HEADER_SIZE) {
        return FALSE;
    }

    lookupEventId = EventId;
    schema = GetEventSchema(lookupEventId);
    if (schema == NULL || EventSize < SysmonGetEventMinSize(lookupEventId)) {
        return FALSE;
    }

    normalizedFieldName = SysmonNormalizeFieldName(FieldName);
    payloadBase = EventData + SYSMON_EVENT_HEADER_SIZE;
    payloadSize = EventSize - SYSMON_EVENT_HEADER_SIZE;

    for (fieldIndex = 0; fieldIndex < schema->FieldCount; fieldIndex++) {
        const SYSMON_EVENT_FIELD_DESCRIPTOR *field = &schema->Fields[fieldIndex];
        const void *fieldPtr;

        if (_wcsicmp(normalizedFieldName, field->Name) != 0) {
            if (lookupEventId != SysmonEventProcessAccess) {
                continue;
            }

            if (!((_wcsicmp(normalizedFieldName, L"SourceProcessGuid") == 0 ||
                   _wcsicmp(normalizedFieldName, L"SourceProcessGUID") == 0) &&
                  _wcsicmp(field->Name, L"SourceProcessGUID") == 0) &&
                !((_wcsicmp(normalizedFieldName, L"TargetProcessGuid") == 0 ||
                   _wcsicmp(normalizedFieldName, L"TargetProcessGUID") == 0) &&
                  _wcsicmp(field->Name, L"TargetProcessGUID") == 0)) {
                continue;
            }
        }

        if (!SysmonHasPayloadBytes(payloadSize, field->Offset,
                (field->Kind == SysmonRenderStringRef) ? sizeof(SYSMON_EVENT_STRING_REF) :
                ((field->Kind == SysmonRenderUInt64) || (field->Kind == SysmonRenderUInt64Hex)) ? sizeof(ULONGLONG) :
                (field->Kind == SysmonRenderBool) ? sizeof(BOOLEAN) :
                sizeof(DWORD))) {
            return FALSE;
        }

        fieldPtr = payloadBase + field->Offset;
        switch (field->Kind) {
        case SysmonRenderStringRef:
        {
            SYSMON_EVENT_STRING_REF stringRef;

            stringRef = SysmonReadPackedValue<SYSMON_EVENT_STRING_REF>(fieldPtr);
            BOOL copied = SysmonCopyStringField(
                EventData,
                EventSize,
                stringRef,
                Buffer,
                BufferChars);
            if (copied && SysmonIsRegistryRuleField(lookupEventId, field->Name)) {
                SysmonNormalizeRegistryFieldForMatching(Buffer, BufferChars);
            }
            return copied;
        }

        case SysmonRenderUInt32:
            return SysmonFormatUInt32(
                SysmonReadPackedValue<DWORD>(fieldPtr),
                Buffer,
                BufferChars,
                FALSE);

        case SysmonRenderUInt32Hex:
            return SysmonFormatUInt32(
                SysmonReadPackedValue<DWORD>(fieldPtr),
                Buffer,
                BufferChars,
                TRUE);

        case SysmonRenderUInt64:
            return SysmonFormatUInt64(
                SysmonReadPackedValue<ULONGLONG>(fieldPtr),
                Buffer,
                BufferChars);

        case SysmonRenderUInt64Hex:
            return SysmonFormatUInt64Hex(
                SysmonReadPackedValue<ULONGLONG>(fieldPtr),
                Buffer,
                BufferChars);

        case SysmonRenderBool:
            return SysmonFormatBoolean(
                SysmonReadPackedValue<BOOLEAN>(fieldPtr),
                Buffer,
                BufferChars);

        case SysmonRenderProcessTerminatePid:
            return SysmonFormatUInt32(
                SysmonReadPackedValue<DWORD>(fieldPtr),
                Buffer,
                BufferChars,
                FALSE);
        }

        return FALSE;
    }

    return FALSE;
}

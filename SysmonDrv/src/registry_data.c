#include "common.h"
#include "driver.h"
#include "obcallback.h"
#include "utils.h"

/* Registry configuration key paths */
static const WCHAR g_ConfigKeyPath[] =
    L"\\Registry\\Machine\\System\\CurrentControlSet\\Services\\Sysmon\\Parameters";
static const WCHAR g_LegacyConfigKeyPath[] =
    L"\\Registry\\Machine\\System\\CurrentControlSet\\Services\\SysmonDrv\\Parameters";

/* Default hash algorithms bitmask */
/* HashingAlgorithm=0 is the shared "None" value. User mode and the driver
   must agree here so an omitted registry value does not silently enable MD5
   and SHA1 hashing in the kernel. */
#define SYSMON_DEFAULT_HASH_ALG  0

typedef struct _SYSMON_REGISTRY_CONFIG {
    BOOLEAN Enabled;
    BOOLEAN ProcessNotifyEnabled;
    BOOLEAN ThreadNotifyEnabled;
    BOOLEAN ImageNotifyEnabled;
    BOOLEAN DriverLoadNotifyEnabled;
    BOOLEAN ImageLoadEventEnabled;
    BOOLEAN RegistryNotifyEnabled;
    BOOLEAN FileNotifyEnabled;
    BOOLEAN NetworkNotifyEnabled;
    BOOLEAN ProcessAccessNotifyEnabled;
    BOOLEAN DnsQueryNotifyEnabled;
    BOOLEAN ClipboardNotifyEnabled;
    BOOLEAN TamperingNotifyEnabled;
    ULONG Options;
    ULONG HashingAlgorithm;
    BOOLEAN CheckRevocation;
    BOOLEAN DnsLookup;
    ULONG DriverQueueSize;
    ULONG SigningQueueSize;
    BOOLEAN CopyOnDeletePE;
    PWCHAR ArchiveDirectory;
    PWCHAR CopyOnDeleteSIDs;
    PWCHAR CopyOnDeleteExtensions;
    PWCHAR CopyOnDeleteProcesses;
} SYSMON_REGISTRY_CONFIG, *PSYSMON_REGISTRY_CONFIG;

/*
 * Read a ULONG value from the driver's configuration registry key.
 */
static NTSTATUS
SysmonReadRegDword(
    _In_ HANDLE KeyHandle,
    _In_ PCWSTR ValueName,
    _Out_ PULONG Value)
{
    NTSTATUS status;
    UNICODE_STRING valueNameStr;
    ULONG resultLength;
    UCHAR buffer[sizeof(KEY_VALUE_PARTIAL_INFORMATION) + sizeof(ULONG)];
    PKEY_VALUE_PARTIAL_INFORMATION info = (PKEY_VALUE_PARTIAL_INFORMATION)buffer;

    RtlInitUnicodeString(&valueNameStr, ValueName);

    status = ZwQueryValueKey(KeyHandle,
        &valueNameStr,
        KeyValuePartialInformation,
        buffer,
        sizeof(buffer),
        &resultLength);

    if (NT_SUCCESS(status) && info->Type == REG_DWORD && info->DataLength >= sizeof(ULONG)) {
        *Value = *(ULONG *)info->Data;
    }

    return status;
}

/*
 * Read a string value from the driver's configuration registry key.
 */
static NTSTATUS
SysmonReadRegString(
    _In_ HANDLE KeyHandle,
    _In_ PCWSTR ValueName,
    _Out_writes_(MaxChars) WCHAR *Buffer,
    _In_ ULONG MaxChars)
{
    NTSTATUS status;
    UNICODE_STRING valueNameStr;
    ULONG resultLength;
    ULONG bufSize;
    PKEY_VALUE_PARTIAL_INFORMATION info;

    RtlInitUnicodeString(&valueNameStr, ValueName);

    bufSize = sizeof(KEY_VALUE_PARTIAL_INFORMATION) + MaxChars * sizeof(WCHAR);
    info = (PKEY_VALUE_PARTIAL_INFORMATION)SysmonAllocatePool(bufSize);
    if (info == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    status = ZwQueryValueKey(KeyHandle,
        &valueNameStr,
        KeyValuePartialInformation,
        info,
        bufSize,
        &resultLength);

    if (NT_SUCCESS(status) && info->Type == REG_SZ && info->DataLength > 0) {
        ULONG copyLen = info->DataLength / sizeof(WCHAR);
        if (copyLen >= MaxChars) copyLen = MaxChars - 1;
        RtlCopyMemory(Buffer, info->Data, copyLen * sizeof(WCHAR));
        Buffer[copyLen] = L'\0';
    }

    SysmonFreePool(info);
    return status;
}

static NTSTATUS
SysmonReadRegAllocatedString(
    _In_ HANDLE KeyHandle,
    _In_ PCWSTR ValueName,
    _Outptr_result_z_ PWCHAR *Value)
{
    NTSTATUS status;
    UNICODE_STRING valueNameStr;
    ULONG resultLength = 0;
    ULONG valueChars;
    PKEY_VALUE_PARTIAL_INFORMATION info = NULL;
    PWCHAR data = NULL;

    if (Value == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    *Value = NULL;

    RtlInitUnicodeString(&valueNameStr, ValueName);

    status = ZwQueryValueKey(
        KeyHandle,
        &valueNameStr,
        KeyValuePartialInformation,
        NULL,
        0,
        &resultLength);
    if (status != STATUS_BUFFER_TOO_SMALL && status != STATUS_BUFFER_OVERFLOW) {
        return status;
    }

    info = (PKEY_VALUE_PARTIAL_INFORMATION)SysmonAllocatePool(resultLength);
    if (info == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    status = ZwQueryValueKey(
        KeyHandle,
        &valueNameStr,
        KeyValuePartialInformation,
        info,
        resultLength,
        &resultLength);
    if (!NT_SUCCESS(status)) {
        goto cleanup;
    }

    if (info->Type != REG_SZ) {
        status = STATUS_OBJECT_TYPE_MISMATCH;
        goto cleanup;
    }

    if ((info->DataLength % sizeof(WCHAR)) != 0) {
        status = STATUS_INVALID_BUFFER_SIZE;
        goto cleanup;
    }

    valueChars = info->DataLength / sizeof(WCHAR);
    data = (PWCHAR)SysmonAllocatePool(((SIZE_T)valueChars + 1) * sizeof(WCHAR));
    if (data == NULL) {
        status = STATUS_INSUFFICIENT_RESOURCES;
        goto cleanup;
    }

    if (valueChars != 0) {
        RtlCopyMemory(data, info->Data, valueChars * sizeof(WCHAR));
    }
    data[valueChars] = L'\0';

    *Value = data;
    data = NULL;
    status = STATUS_SUCCESS;

cleanup:
    SysmonFreePool(data);
    SysmonFreePool(info);
    return status;
}

static NTSTATUS
SysmonReadRegBool(
    _In_ HANDLE KeyHandle,
    _In_ PCWSTR ValueName,
    _Out_ PBOOLEAN Value)
{
    NTSTATUS status;
    UNICODE_STRING valueNameStr;
    ULONG resultLength;
    UCHAR buffer[sizeof(KEY_VALUE_PARTIAL_INFORMATION) + sizeof(UCHAR)];
    PKEY_VALUE_PARTIAL_INFORMATION info = (PKEY_VALUE_PARTIAL_INFORMATION)buffer;

    RtlInitUnicodeString(&valueNameStr, ValueName);

    status = ZwQueryValueKey(KeyHandle,
        &valueNameStr,
        KeyValuePartialInformation,
        buffer,
        sizeof(buffer),
        &resultLength);

    if (NT_SUCCESS(status) &&
        info->Type == REG_BINARY &&
        info->DataLength >= sizeof(UCHAR)) {
        *Value = (BOOLEAN)(info->Data[0] != 0);
    }

    return status;
}

static NTSTATUS
SysmonReadRegBinary(
    _In_ HANDLE KeyHandle,
    _In_ PCWSTR ValueName,
    _Outptr_result_bytebuffer_(*ValueSize) PUCHAR *Value,
    _Out_ PULONG ValueSize)
{
    NTSTATUS status;
    UNICODE_STRING valueNameStr;
    ULONG resultLength = 0;
    PKEY_VALUE_PARTIAL_INFORMATION info = NULL;
    PUCHAR data = NULL;

    *Value = NULL;
    *ValueSize = 0;

    RtlInitUnicodeString(&valueNameStr, ValueName);

    status = ZwQueryValueKey(KeyHandle,
        &valueNameStr,
        KeyValuePartialInformation,
        NULL,
        0,
        &resultLength);

    if (status != STATUS_BUFFER_TOO_SMALL && status != STATUS_BUFFER_OVERFLOW) {
        return status;
    }

    info = (PKEY_VALUE_PARTIAL_INFORMATION)SysmonAllocatePool(resultLength);
    if (info == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    status = ZwQueryValueKey(KeyHandle,
        &valueNameStr,
        KeyValuePartialInformation,
        info,
        resultLength,
        &resultLength);
    if (!NT_SUCCESS(status)) {
        goto cleanup;
    }

    if (info->Type != REG_BINARY || info->DataLength == 0) {
        status = STATUS_OBJECT_TYPE_MISMATCH;
        goto cleanup;
    }

    data = (PUCHAR)SysmonAllocatePool(info->DataLength);
    if (data == NULL) {
        status = STATUS_INSUFFICIENT_RESOURCES;
        goto cleanup;
    }

    RtlCopyMemory(data, info->Data, info->DataLength);
    *Value = data;
    *ValueSize = info->DataLength;
    data = NULL;

cleanup:
    SysmonFreePool(data);
    SysmonFreePool(info);
    return status;
}

static NTSTATUS
SysmonReadRegMultiSz(
    _In_ HANDLE KeyHandle,
    _In_ PCWSTR ValueName,
    _Outptr_result_bytebuffer_(*ValueSize) PWCHAR *Value,
    _Out_ PULONG ValueSize)
{
    NTSTATUS status;
    UNICODE_STRING valueNameStr;
    ULONG resultLength = 0;
    PKEY_VALUE_PARTIAL_INFORMATION info = NULL;
    PWCHAR data = NULL;

    *Value = NULL;
    *ValueSize = 0;

    RtlInitUnicodeString(&valueNameStr, ValueName);

    status = ZwQueryValueKey(
        KeyHandle,
        &valueNameStr,
        KeyValuePartialInformation,
        NULL,
        0,
        &resultLength);
    if (status != STATUS_BUFFER_TOO_SMALL && status != STATUS_BUFFER_OVERFLOW) {
        return status;
    }

    info = (PKEY_VALUE_PARTIAL_INFORMATION)SysmonAllocatePool(resultLength);
    if (info == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    status = ZwQueryValueKey(
        KeyHandle,
        &valueNameStr,
        KeyValuePartialInformation,
        info,
        resultLength,
        &resultLength);
    if (!NT_SUCCESS(status)) {
        goto cleanup;
    }

    if (info->Type != REG_MULTI_SZ || info->DataLength < (2 * sizeof(WCHAR))) {
        status = STATUS_OBJECT_TYPE_MISMATCH;
        goto cleanup;
    }

    data = (PWCHAR)SysmonAllocatePool(info->DataLength);
    if (data == NULL) {
        status = STATUS_INSUFFICIENT_RESOURCES;
        goto cleanup;
    }

    RtlCopyMemory(data, info->Data, info->DataLength);
    *Value = data;
    *ValueSize = info->DataLength;
    data = NULL;

cleanup:
    SysmonFreePool(data);
    SysmonFreePool(info);
    return status;
}

static BOOLEAN
SysmonIsCsvWhitespace(
    _In_ WCHAR Character)
{
    return Character == L' ' ||
        Character == L'\t' ||
        Character == L'\r' ||
        Character == L'\n';
}

static VOID
SysmonTrimCsvSpan(
    _In_reads_(Length) PCWSTR Text,
    _Inout_ PSIZE_T Start,
    _Inout_ PSIZE_T Length)
{
    SIZE_T start;
    SIZE_T length;

    if (Text == NULL || Start == NULL || Length == NULL) {
        return;
    }

    start = *Start;
    length = *Length;

    while (length != 0 && SysmonIsCsvWhitespace(Text[start])) {
        start++;
        length--;
    }

    while (length != 0 && SysmonIsCsvWhitespace(Text[start + length - 1])) {
        length--;
    }

    *Start = start;
    *Length = length;
}

static BOOLEAN
SysmonArchiveDirectoryIsSinglePathComponent(
    _In_opt_z_ PCWSTR Value)
{
    SIZE_T length;

    if (Value == NULL || Value[0] == L'\0') {
        return FALSE;
    }

    if (wcscmp(Value, L".") == 0 || wcscmp(Value, L"..") == 0) {
        return FALSE;
    }

    length = wcslen(Value);
    if (length != 0 &&
        (Value[length - 1] == L'.' || Value[length - 1] == L' ')) {
        return FALSE;
    }

    return wcschr(Value, L'\\') == NULL &&
        wcschr(Value, L'/') == NULL &&
        wcschr(Value, L':') == NULL;
}

static NTSTATUS
SysmonNormalizeArchiveDirectoryComponent(
    _In_opt_z_ PCWSTR Input,
    _Out_ PUNICODE_STRING Component)
{
    SIZE_T lengthChars;
    PWCHAR buffer;

    if (Component == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    RtlInitUnicodeString(Component, NULL);

    if (Input == NULL || Input[0] == L'\0') {
        return STATUS_SUCCESS;
    }

    if (!SysmonArchiveDirectoryIsSinglePathComponent(Input)) {
        return STATUS_INVALID_PARAMETER;
    }

    lengthChars = wcslen(Input);
    if (lengthChars > ((MAXUSHORT / sizeof(WCHAR)) - 3)) {
        return STATUS_NAME_TOO_LONG;
    }

    buffer = (PWCHAR)SysmonAllocatePool((lengthChars + 3) * sizeof(WCHAR));
    if (buffer == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    buffer[0] = L'\\';
    RtlCopyMemory(buffer + 1, Input, lengthChars * sizeof(WCHAR));
    buffer[lengthChars + 1] = L'\\';
    buffer[lengthChars + 2] = L'\0';

    Component->Buffer = buffer;
    Component->Length = (USHORT)((lengthChars + 2) * sizeof(WCHAR));
    Component->MaximumLength = (USHORT)((lengthChars + 3) * sizeof(WCHAR));
    return STATUS_SUCCESS;
}

static NTSTATUS
SysmonSplitCsvToMultiSzLower(
    _In_opt_z_ PCWSTR Input,
    _Outptr_result_bytebuffer_(*OutputBytes) PWCHAR *Output,
    _Out_ PULONG OutputBytes)
{
    PCWSTR cursor;
    ULONG totalChars = 1;
    ULONG tokenCount = 0;
    PWCHAR buffer = NULL;
    PWCHAR destination;

    if (Output == NULL || OutputBytes == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    *Output = NULL;
    *OutputBytes = 0;

    /* NULL input is normalized to an empty MULTI_SZ. */
    cursor = (Input != NULL) ? Input : L"";
    while (TRUE) {
        SIZE_T tokenStart = 0;
        SIZE_T rawLength = 0;
        SIZE_T tokenLength;

        while (cursor[rawLength] != L',' && cursor[rawLength] != L'\0') {
            rawLength++;
        }

        tokenLength = rawLength;
        SysmonTrimCsvSpan(cursor, &tokenStart, &tokenLength);
        if (tokenLength != 0) {
            if (tokenLength > (SIZE_T)(MAXULONG - totalChars - 1)) {
                return STATUS_INTEGER_OVERFLOW;
            }

            totalChars += (ULONG)tokenLength + 1;
            tokenCount += 1;
        }

        if (cursor[rawLength] == L'\0') {
            break;
        }

        cursor += rawLength + 1;
    }

    if (tokenCount == 0) {
        buffer = (PWCHAR)SysmonAllocatePool(2 * sizeof(WCHAR));
        if (buffer == NULL) {
            return STATUS_INSUFFICIENT_RESOURCES;
        }

        buffer[0] = L'\0';
        buffer[1] = L'\0';
        *Output = buffer;
        *OutputBytes = 2 * sizeof(WCHAR);
        return STATUS_SUCCESS;
    }

    buffer = (PWCHAR)SysmonAllocatePool((SIZE_T)totalChars * sizeof(WCHAR));
    if (buffer == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    destination = buffer;
    cursor = (Input != NULL) ? Input : L"";
    while (TRUE) {
        SIZE_T tokenStart = 0;
        SIZE_T rawLength = 0;
        SIZE_T tokenLength;
        SIZE_T index;

        while (cursor[rawLength] != L',' && cursor[rawLength] != L'\0') {
            rawLength++;
        }

        tokenLength = rawLength;
        SysmonTrimCsvSpan(cursor, &tokenStart, &tokenLength);
        if (tokenLength != 0) {
            for (index = 0; index < tokenLength; index++) {
                destination[index] = RtlDowncaseUnicodeChar(cursor[tokenStart + index]);
            }

            destination += tokenLength;
            *destination++ = L'\0';
        }

        if (cursor[rawLength] == L'\0') {
            break;
        }

        cursor += rawLength + 1;
    }

    *destination = L'\0';

    *Output = buffer;
    *OutputBytes = totalChars * sizeof(WCHAR);
    return STATUS_SUCCESS;
}

static VOID
SysmonFreeRegistryConfigStrings(
    _Inout_ PSYSMON_REGISTRY_CONFIG Config)
{
    if (Config == NULL) {
        return;
    }

    SysmonFreePool(Config->ArchiveDirectory);
    SysmonFreePool(Config->CopyOnDeleteSIDs);
    SysmonFreePool(Config->CopyOnDeleteExtensions);
    SysmonFreePool(Config->CopyOnDeleteProcesses);
    Config->ArchiveDirectory = NULL;
    Config->CopyOnDeleteSIDs = NULL;
    Config->CopyOnDeleteExtensions = NULL;
    Config->CopyOnDeleteProcesses = NULL;
}

static VOID
SysmonApplyProcessAccessFilter(
    _In_reads_bytes_opt_(NamesSize) PWCHAR Names,
    _In_ ULONG NamesSize,
    _In_reads_bytes_opt_(MasksSize) PUCHAR Masks,
    _In_ ULONG MasksSize)
{
    ACCESS_MASK parsedMasks[SYSMON_MAX_ACCESS_MASKS];
    WCHAR parsedNames[SYSMON_MAX_ACCESS_MASKS][64];
    ULONG nameCount = 0;
    ULONG maskCount = 0;
    ULONG count;

    RtlZeroMemory(parsedMasks, sizeof(parsedMasks));
    RtlZeroMemory(parsedNames, sizeof(parsedNames));

    if (Names != NULL && NamesSize >= (2 * sizeof(WCHAR))) {
        PWCHAR cursor = Names;
        ULONG remainingChars = NamesSize / sizeof(WCHAR);

        while (nameCount < SYSMON_MAX_ACCESS_MASKS &&
               remainingChars > 1 &&
               *cursor != L'\0') {
            ULONG entryChars = 0;
            ULONG copyChars;

            while (entryChars < remainingChars && cursor[entryChars] != L'\0') {
                entryChars++;
            }

            if (entryChars == 0 || entryChars >= remainingChars) {
                break;
            }

            copyChars = min(entryChars, RTL_NUMBER_OF(parsedNames[0]) - 1);
            RtlCopyMemory(
                parsedNames[nameCount],
                cursor,
                copyChars * sizeof(WCHAR));
            parsedNames[nameCount][copyChars] = L'\0';
            nameCount += 1;

            cursor += entryChars + 1;
            remainingChars -= entryChars + 1;
        }
    }

    if (Masks != NULL && MasksSize >= sizeof(ACCESS_MASK)) {
        maskCount = min(MasksSize / sizeof(ACCESS_MASK), SYSMON_MAX_ACCESS_MASKS);
        RtlCopyMemory(parsedMasks, Masks, maskCount * sizeof(ACCESS_MASK));
    }

    count = min(nameCount, maskCount);
    if (count == 0) {
        SysmonSetAccessFilter(0, NULL, NULL);
        return;
    }

    SysmonSetAccessFilter(count, parsedMasks, (WCHAR *)parsedNames);
}

static VOID
SysmonSetConfigDefaults(
    _Out_ PSYSMON_REGISTRY_CONFIG Config)
{
    RtlZeroMemory(Config, sizeof(*Config));
    Config->Enabled = TRUE;
    Config->ProcessNotifyEnabled = FALSE;
    Config->ThreadNotifyEnabled = FALSE;
    Config->ImageNotifyEnabled = FALSE;
    Config->DriverLoadNotifyEnabled = FALSE;
    Config->ImageLoadEventEnabled = FALSE;
    Config->RegistryNotifyEnabled = FALSE;
    Config->FileNotifyEnabled = FALSE;
    Config->NetworkNotifyEnabled = FALSE;
    Config->ProcessAccessNotifyEnabled = FALSE;
    Config->DnsQueryNotifyEnabled = FALSE;
    Config->ClipboardNotifyEnabled = FALSE;
    Config->TamperingNotifyEnabled = FALSE;
    Config->HashingAlgorithm = SYSMON_DEFAULT_HASH_ALG;
    Config->CheckRevocation = TRUE;
    Config->DnsLookup = TRUE;
    Config->SigningQueueSize = 1000;
}

static BOOLEAN
SysmonRuleRuntimeHasAnyLoggableEvent(
    _In_opt_ PSYSMON_RULE_RUNTIME Runtime,
    _In_reads_(EventIdCount) const SYSMON_EVENT_ID *EventIds,
    _In_ ULONG EventIdCount)
{
    ULONG index;

    if (EventIds == NULL || EventIdCount == 0) {
        return FALSE;
    }

    for (index = 0; index < EventIdCount; index++) {
        if (SysmonRuleRuntimeEventCanProduceLogs(Runtime, EventIds[index])) {
            return TRUE;
        }
    }

    return FALSE;
}

static VOID
SysmonDeriveConfigFromRules(
    _Inout_ PSYSMON_REGISTRY_CONFIG Config,
    _In_ BOOLEAN ProcessNotifySpecified,
    _In_ BOOLEAN ThreadNotifySpecified,
    _In_ BOOLEAN ImageNotifySpecified,
    _In_ BOOLEAN RegistryNotifySpecified,
    _In_ BOOLEAN FileNotifySpecified,
    _In_opt_ PSYSMON_RULE_RUNTIME Runtime)
{
    static const SYSMON_EVENT_ID g_ProcessNotifyEvents[] = {
        SysmonEventProcessCreate,
        SysmonEventNetworkConnect,
        SysmonEventRawAccessRead,
        SysmonEventProcessTerminate,
        SysmonEventImageLoad,
        SysmonEventPipeCreated,
        SysmonEventPipeConnected,
        SysmonEventDnsQuery,
        SysmonEventFileDelete,
        SysmonEventClipboardChange,
        SysmonEventFileDeleteDetected,
        SysmonEventFileBlockExecutable,
        SysmonEventFileBlockShredding,
        SysmonEventFileExecutableDetected
    };
    static const SYSMON_EVENT_ID g_ThreadNotifyEvents[] = {
        SysmonEventProcessCreate,
        SysmonEventCreateThread
    };
    static const SYSMON_EVENT_ID g_ImageNotifyEvents[] = {
        SysmonEventDriverLoad,
        SysmonEventImageLoad
    };
    static const SYSMON_EVENT_ID g_RegistryNotifyEvents[] = {
        SysmonEventRegistryEvent,
        SysmonEventRegistryValueSet,
        SysmonEventRegistryRename
    };
    static const SYSMON_EVENT_ID g_MinifilterEvents[] = {
        SysmonEventFileCreateTime,
        SysmonEventRawAccessRead,
        SysmonEventFileCreate,
        SysmonEventFileCreateStreamHash,
        SysmonEventPipeCreated,
        SysmonEventPipeConnected,
        SysmonEventFileDelete,
        SysmonEventFileDeleteDetected,
        SysmonEventFileBlockExecutable,
        SysmonEventFileBlockShredding,
        SysmonEventFileExecutableDetected
    };
    static const SYSMON_EVENT_ID g_NetworkEvents[] = {
        SysmonEventNetworkConnect
    };
    static const SYSMON_EVENT_ID g_ProcessAccessEvents[] = {
        SysmonEventProcessAccess
    };
    static const SYSMON_EVENT_ID g_DnsEvents[] = {
        SysmonEventDnsQuery
    };
    static const SYSMON_EVENT_ID g_ClipboardEvents[] = {
        SysmonEventClipboardChange
    };
    static const SYSMON_EVENT_ID g_TamperingEvents[] = {
        SysmonEventProcessTampering
    };

    Config->DriverLoadNotifyEnabled = Config->ImageNotifyEnabled;
    Config->ImageLoadEventEnabled = Config->ImageNotifyEnabled;

    if (Runtime == NULL || Runtime->Header == NULL || Runtime->Header->EventRuleCount == 0) {
        return;
    }

    if (!ProcessNotifySpecified) {
        Config->ProcessNotifyEnabled = SysmonRuleRuntimeHasAnyLoggableEvent(
            Runtime,
            g_ProcessNotifyEvents,
            RTL_NUMBER_OF(g_ProcessNotifyEvents));
    }

    if (!ThreadNotifySpecified) {
        Config->ThreadNotifyEnabled = SysmonRuleRuntimeHasAnyLoggableEvent(
            Runtime,
            g_ThreadNotifyEvents,
            RTL_NUMBER_OF(g_ThreadNotifyEvents));
    }

    if (!ImageNotifySpecified) {
        Config->DriverLoadNotifyEnabled = SysmonRuleRuntimeEventCanProduceLogs(
            Runtime,
            SysmonEventDriverLoad);
        Config->ImageLoadEventEnabled = SysmonRuleRuntimeEventCanProduceLogs(
            Runtime,
            SysmonEventImageLoad);
        Config->ImageNotifyEnabled = SysmonRuleRuntimeHasAnyLoggableEvent(
            Runtime,
            g_ImageNotifyEvents,
            RTL_NUMBER_OF(g_ImageNotifyEvents));
    }

    if (!RegistryNotifySpecified) {
        Config->RegistryNotifyEnabled = SysmonRuleRuntimeHasAnyLoggableEvent(
            Runtime,
            g_RegistryNotifyEvents,
            RTL_NUMBER_OF(g_RegistryNotifyEvents));
    }

    if (!FileNotifySpecified) {
        Config->FileNotifyEnabled = SysmonRuleRuntimeHasAnyLoggableEvent(
            Runtime,
            g_MinifilterEvents,
            RTL_NUMBER_OF(g_MinifilterEvents));
    }

    Config->NetworkNotifyEnabled = SysmonRuleRuntimeHasAnyLoggableEvent(
        Runtime,
        g_NetworkEvents,
        RTL_NUMBER_OF(g_NetworkEvents));
    Config->ProcessAccessNotifyEnabled = SysmonRuleRuntimeHasAnyLoggableEvent(
        Runtime,
        g_ProcessAccessEvents,
        RTL_NUMBER_OF(g_ProcessAccessEvents));
    Config->DnsQueryNotifyEnabled = SysmonRuleRuntimeHasAnyLoggableEvent(
        Runtime,
        g_DnsEvents,
        RTL_NUMBER_OF(g_DnsEvents));
    Config->ClipboardNotifyEnabled = SysmonRuleRuntimeHasAnyLoggableEvent(
        Runtime,
        g_ClipboardEvents,
        RTL_NUMBER_OF(g_ClipboardEvents));
    Config->TamperingNotifyEnabled = SysmonRuleRuntimeHasAnyLoggableEvent(
        Runtime,
        g_TamperingEvents,
        RTL_NUMBER_OF(g_TamperingEvents));

    if (Config->TamperingNotifyEnabled) {
        Config->ImageNotifyEnabled = TRUE;
    }
}

/*
 * Load driver configuration from registry.
 * Called during DriverEntry after device creation.
 *
 * Registry values (all under Parameters key):
 *   Enabled         (DWORD) - 1 to enable monitoring, 0 to disable
 *   HashingAlgorithm (DWORD) - bitmask of hash algorithms
 *   ProcessNotify   (DWORD) - 1 to enable process monitoring
 *   ThreadNotify    (DWORD) - 1 to enable thread monitoring
 *   ImageNotify     (DWORD) - 1 to enable image load monitoring
 *   RegistryNotify  (DWORD) - 1 to enable registry monitoring
 *   FileNotify      (DWORD) - 1 to enable file monitoring
 */
NTSTATUS
SysmonLoadConfiguration(VOID)
{
    NTSTATUS status;
    OBJECT_ATTRIBUTES objAttr;
    UNICODE_STRING keyPath;
    HANDLE keyHandle = NULL;
    ULONG dwordValue;
    SYSMON_REGISTRY_CONFIG config;
    PUCHAR rulesBlob = NULL;
    ULONG rulesBlobSize = 0;
    PWCHAR processAccessNames = NULL;
    ULONG processAccessNamesSize = 0;
    PUCHAR processAccessMasks = NULL;
    ULONG processAccessMasksSize = 0;
    PSYSMON_RULE_RUNTIME newRuntime = NULL;
    PSYSMON_RULE_RUNTIME oldRuntime = NULL;
    BOOLEAN boolValue;
    BOOLEAN rulesBlobPresent = FALSE;
    BOOLEAN processNotifySpecified = FALSE;
    BOOLEAN threadNotifySpecified = FALSE;
    BOOLEAN imageNotifySpecified = FALSE;
    BOOLEAN registryNotifySpecified = FALSE;
    BOOLEAN fileNotifySpecified = FALSE;

    SysmonSetConfigDefaults(&config);

    status = SysmonCreateEmptyRuleRuntime(&newRuntime);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    RtlInitUnicodeString(&keyPath, g_ConfigKeyPath);
    InitializeObjectAttributes(&objAttr, &keyPath,
        OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);

    status = ZwOpenKey(&keyHandle, KEY_READ, &objAttr);
    if ((status == STATUS_OBJECT_NAME_NOT_FOUND || status == STATUS_OBJECT_PATH_NOT_FOUND)) {
        RtlInitUnicodeString(&keyPath, g_LegacyConfigKeyPath);
        InitializeObjectAttributes(&objAttr, &keyPath,
            OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);
        status = ZwOpenKey(&keyHandle, KEY_READ, &objAttr);
    }
    if (!NT_SUCCESS(status)) {
        if (status == STATUS_OBJECT_NAME_NOT_FOUND || status == STATUS_OBJECT_PATH_NOT_FOUND) {
            status = STATUS_SUCCESS;
            goto apply_config;
        }

        goto cleanup;
    }

    /* Read Enabled flag */
    if (NT_SUCCESS(SysmonReadRegDword(keyHandle, L"Enabled", &dwordValue))) {
        config.Enabled = (BOOLEAN)(dwordValue != 0);
    }

    /* Read ProcessNotify flag */
    if (NT_SUCCESS(SysmonReadRegDword(keyHandle, L"ProcessNotify", &dwordValue))) {
        config.ProcessNotifyEnabled = (BOOLEAN)(dwordValue != 0);
        processNotifySpecified = TRUE;
    }

    /* Read ThreadNotify flag */
    if (NT_SUCCESS(SysmonReadRegDword(keyHandle, L"ThreadNotify", &dwordValue))) {
        config.ThreadNotifyEnabled = (BOOLEAN)(dwordValue != 0);
        threadNotifySpecified = TRUE;
    }

    /* Read ImageNotify flag */
    if (NT_SUCCESS(SysmonReadRegDword(keyHandle, L"ImageNotify", &dwordValue))) {
        config.ImageNotifyEnabled = (BOOLEAN)(dwordValue != 0);
        imageNotifySpecified = TRUE;
    }

    /* Read RegistryNotify flag */
    if (NT_SUCCESS(SysmonReadRegDword(keyHandle, L"RegistryNotify", &dwordValue))) {
        config.RegistryNotifyEnabled = (BOOLEAN)(dwordValue != 0);
        registryNotifySpecified = TRUE;
    }

    /* Read FileNotify flag */
    if (NT_SUCCESS(SysmonReadRegDword(keyHandle, L"FileNotify", &dwordValue))) {
        config.FileNotifyEnabled = (BOOLEAN)(dwordValue != 0);
        fileNotifySpecified = TRUE;
    }

    if (NT_SUCCESS(SysmonReadRegDword(keyHandle, L"Options", &dwordValue))) {
        config.Options = dwordValue;
    }

    if (NT_SUCCESS(SysmonReadRegDword(keyHandle, L"HashingAlgorithm", &dwordValue)) &&
        dwordValue != 0) {
        config.HashingAlgorithm = dwordValue;
    }

    if (NT_SUCCESS(SysmonReadRegBool(keyHandle, L"CheckRevocation", &config.CheckRevocation))) {
        /* Already copied into config by helper. */
    }

    if (NT_SUCCESS(SysmonReadRegBool(keyHandle, L"DnsLookup", &config.DnsLookup))) {
        /* Already copied into config by helper. */
    }

    if (NT_SUCCESS(SysmonReadRegDword(keyHandle, L"DriverQueueSize", &dwordValue))) {
        config.DriverQueueSize = dwordValue;
    }

    if (NT_SUCCESS(SysmonReadRegDword(keyHandle, L"SigningQueueSize", &dwordValue))) {
        config.SigningQueueSize = dwordValue;
    }

    if (NT_SUCCESS(SysmonReadRegBool(keyHandle, L"CopyOnDeletePE", &boolValue))) {
        config.CopyOnDeletePE = boolValue;
    }

    status = SysmonReadRegAllocatedString(
        keyHandle,
        L"ArchiveDirectory",
        &config.ArchiveDirectory);
    if (!NT_SUCCESS(status) &&
        status != STATUS_OBJECT_NAME_NOT_FOUND &&
        status != STATUS_OBJECT_PATH_NOT_FOUND &&
        status != STATUS_OBJECT_TYPE_MISMATCH) {
        goto cleanup;
    }

    status = SysmonReadRegAllocatedString(
        keyHandle,
        L"CopyOnDeleteSIDs",
        &config.CopyOnDeleteSIDs);
    if (!NT_SUCCESS(status) &&
        status != STATUS_OBJECT_NAME_NOT_FOUND &&
        status != STATUS_OBJECT_PATH_NOT_FOUND &&
        status != STATUS_OBJECT_TYPE_MISMATCH) {
        goto cleanup;
    }

    status = SysmonReadRegAllocatedString(
        keyHandle,
        L"CopyOnDeleteExtensions",
        &config.CopyOnDeleteExtensions);
    if (!NT_SUCCESS(status) &&
        status != STATUS_OBJECT_NAME_NOT_FOUND &&
        status != STATUS_OBJECT_PATH_NOT_FOUND &&
        status != STATUS_OBJECT_TYPE_MISMATCH) {
        goto cleanup;
    }

    status = SysmonReadRegAllocatedString(
        keyHandle,
        L"CopyOnDeleteProcesses",
        &config.CopyOnDeleteProcesses);
    if (!NT_SUCCESS(status) &&
        status != STATUS_OBJECT_NAME_NOT_FOUND &&
        status != STATUS_OBJECT_PATH_NOT_FOUND &&
        status != STATUS_OBJECT_TYPE_MISMATCH) {
        goto cleanup;
    }

    status = SysmonReadRegMultiSz(
        keyHandle,
        L"ProcessAccessNames",
        &processAccessNames,
        &processAccessNamesSize);
    if (!NT_SUCCESS(status) &&
        status != STATUS_OBJECT_NAME_NOT_FOUND &&
        status != STATUS_OBJECT_PATH_NOT_FOUND &&
        status != STATUS_OBJECT_TYPE_MISMATCH) {
        goto cleanup;
    }

    status = SysmonReadRegBinary(
        keyHandle,
        L"ProcessAccessMasks",
        &processAccessMasks,
        &processAccessMasksSize);
    if (!NT_SUCCESS(status) &&
        status != STATUS_OBJECT_NAME_NOT_FOUND &&
        status != STATUS_OBJECT_PATH_NOT_FOUND &&
        status != STATUS_OBJECT_TYPE_MISMATCH) {
        goto cleanup;
    }

    status = SysmonReadRegBinary(keyHandle, L"Rules", &rulesBlob, &rulesBlobSize);
    if (NT_SUCCESS(status)) {
        PSYSMON_RULE_RUNTIME decodedRuntime = NULL;

        status = SysmonLoadRuleRuntime(rulesBlob, rulesBlobSize, &decodedRuntime);
        if (!NT_SUCCESS(status)) {
            goto cleanup;
        }

        SysmonFreeRuleRuntime(newRuntime);
        newRuntime = decodedRuntime;
        rulesBlobPresent = TRUE;
    } else if (status == STATUS_OBJECT_NAME_NOT_FOUND || status == STATUS_OBJECT_PATH_NOT_FOUND) {
        status = STATUS_SUCCESS;
    } else {
        goto cleanup;
    }

apply_config:
    if (newRuntime != NULL) {
        newRuntime->Options = config.Options;
        newRuntime->HashingAlgorithm = config.HashingAlgorithm;
        newRuntime->CheckRevocation = config.CheckRevocation;
        newRuntime->DnsLookup = config.DnsLookup;
        newRuntime->DriverQueueSize = config.DriverQueueSize;
        newRuntime->SigningQueueSize = config.SigningQueueSize;
        newRuntime->CopyOnDeletePE = config.CopyOnDeletePE;

        status = SysmonNormalizeArchiveDirectoryComponent(
            config.ArchiveDirectory,
            &newRuntime->ArchiveDirectoryComponent);
        if (status == STATUS_INVALID_PARAMETER) {
            DbgPrintEx(
                DPFLTR_DEFAULT_ID,
                DPFLTR_WARNING_LEVEL,
                "[SysmonDrv] Ignoring invalid registry value 'ArchiveDirectory': '%ws'\n",
                config.ArchiveDirectory);
            SysmonFreePool(config.ArchiveDirectory);
            config.ArchiveDirectory = NULL;
            status = STATUS_SUCCESS;
        } else if (!NT_SUCCESS(status)) {
            goto cleanup;
        }

        status = SysmonSplitCsvToMultiSzLower(
            config.CopyOnDeleteSIDs,
            &newRuntime->CopyOnDeleteSIDsMultiSz,
            &newRuntime->CopyOnDeleteSIDsBytes);
        if (!NT_SUCCESS(status)) {
            goto cleanup;
        }

        status = SysmonSplitCsvToMultiSzLower(
            config.CopyOnDeleteExtensions,
            &newRuntime->CopyOnDeleteExtensionsMultiSz,
            &newRuntime->CopyOnDeleteExtensionsBytes);
        if (!NT_SUCCESS(status)) {
            goto cleanup;
        }

        status = SysmonSplitCsvToMultiSzLower(
            config.CopyOnDeleteProcesses,
            &newRuntime->CopyOnDeleteProcessesMultiSz,
            &newRuntime->CopyOnDeleteProcessesBytes);
        if (!NT_SUCCESS(status)) {
            goto cleanup;
        }
    }

    if (rulesBlobPresent) {
        /*
         * The Rules blob is authoritative for feature enablement. Legacy
         * per-feature DWORDs are only a fallback when no Rules blob exists.
         */
        processNotifySpecified = FALSE;
        threadNotifySpecified = FALSE;
        imageNotifySpecified = FALSE;
        registryNotifySpecified = FALSE;
        fileNotifySpecified = FALSE;
    }

    SysmonDeriveConfigFromRules(
        &config,
        processNotifySpecified,
        threadNotifySpecified,
        imageNotifySpecified,
        registryNotifySpecified,
        fileNotifySpecified,
        newRuntime);

    ExAcquireFastMutex(&g_Context.RuleLock);
    oldRuntime = g_Context.RuleRuntime;
    g_Context.RuleRuntime = newRuntime;
    {
        LONG newProducerFlags =
            (config.Enabled ? SYSMON_FLAG_ENABLED : 0) |
            (config.ProcessNotifyEnabled ? SYSMON_FLAG_PROCESS_NOTIFY : 0) |
            (config.ThreadNotifyEnabled ? SYSMON_FLAG_THREAD_NOTIFY : 0) |
            (config.ImageNotifyEnabled ? SYSMON_FLAG_IMAGE_NOTIFY : 0) |
            (config.DriverLoadNotifyEnabled ? SYSMON_FLAG_DRIVER_LOAD_NOTIFY : 0) |
            (config.ImageLoadEventEnabled ? SYSMON_FLAG_IMAGE_LOAD_EVENT : 0) |
            (config.RegistryNotifyEnabled ? SYSMON_FLAG_REGISTRY_NOTIFY : 0) |
            (config.FileNotifyEnabled ? SYSMON_FLAG_FILE_NOTIFY : 0) |
            (config.NetworkNotifyEnabled ? SYSMON_FLAG_NETWORK_NOTIFY : 0) |
            (config.ProcessAccessNotifyEnabled ? SYSMON_FLAG_PROCESS_ACCESS_NOTIFY : 0) |
            (config.DnsQueryNotifyEnabled ? SYSMON_FLAG_DNS_QUERY_NOTIFY : 0) |
            (config.ClipboardNotifyEnabled ? SYSMON_FLAG_CLIPBOARD_NOTIFY : 0) |
            (config.TamperingNotifyEnabled ? SYSMON_FLAG_TAMPERING_NOTIFY : 0);

        /* Publish all producer flags as one atomic snapshot so a hot producer can
           never observe a cross-generation mix of the individual flags (K2 in the
           2026-08-04 review). */
        InterlockedExchange(&g_Context.ProducerFlags, newProducerFlags);
    }
    g_Context.Options = config.Options;
    g_Context.HashingAlgorithm = config.HashingAlgorithm;
    g_Context.CheckRevocation = config.CheckRevocation;
    g_Context.DnsLookup = config.DnsLookup;
    g_Context.DriverQueueSize = config.DriverQueueSize;
    g_Context.SigningQueueSize = config.SigningQueueSize;
    g_Context.CopyOnDeletePE = newRuntime->CopyOnDeletePE;
    g_Context.ArchiveDirectoryConfigured =
        (BOOLEAN)(newRuntime->ArchiveDirectoryComponent.Buffer != NULL);
    g_Context.ReloadGeneration += 1;
    ExReleaseFastMutex(&g_Context.RuleLock);
    newRuntime = NULL;

    SysmonApplyProcessAccessFilter(
        processAccessNames,
        processAccessNamesSize,
        processAccessMasks,
        processAccessMasksSize);

    DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_INFO_LEVEL,
        "[SysmonDrv] Config loaded: Enabled=%d Proc=%d Thread=%d Image=%d Reg=%d File=%d Net=%d Ob=%d Dns=%d Clip=%d Tamp=%d Rules=%lu Gen=%lu\n",
        SysmonIsProducerEnabled(SYSMON_FLAG_ENABLED),
        SysmonIsProducerEnabled(SYSMON_FLAG_PROCESS_NOTIFY),
        SysmonIsProducerEnabled(SYSMON_FLAG_THREAD_NOTIFY),
        SysmonIsProducerEnabled(SYSMON_FLAG_IMAGE_NOTIFY),
        SysmonIsProducerEnabled(SYSMON_FLAG_REGISTRY_NOTIFY),
        SysmonIsProducerEnabled(SYSMON_FLAG_FILE_NOTIFY),
        SysmonIsProducerEnabled(SYSMON_FLAG_NETWORK_NOTIFY),
        SysmonIsProducerEnabled(SYSMON_FLAG_PROCESS_ACCESS_NOTIFY),
        SysmonIsProducerEnabled(SYSMON_FLAG_DNS_QUERY_NOTIFY),
        SysmonIsProducerEnabled(SYSMON_FLAG_CLIPBOARD_NOTIFY),
        SysmonIsProducerEnabled(SYSMON_FLAG_TAMPERING_NOTIFY),
        (g_Context.RuleRuntime != NULL && g_Context.RuleRuntime->Header != NULL),
        g_Context.ReloadGeneration);

    if (oldRuntime != NULL) {
        ExWaitForRundownProtectionRelease(&oldRuntime->RundownRef);
    }
    SysmonFreeRuleRuntime(oldRuntime);

cleanup:
    SysmonFreeRuleRuntime(newRuntime);
    SysmonFreePool(rulesBlob);
    SysmonFreePool(processAccessNames);
    SysmonFreePool(processAccessMasks);
    SysmonFreeRegistryConfigStrings(&config);
    if (keyHandle != NULL) {
        ZwClose(keyHandle);
    }
    return status;
}

#include "registry.h"
#include "queue.h"
#include "event.h"
#include "driver.h"
#include "processinfo.h"
#include "utils.h"
#include "dns.h"
#include "wmi.h"

static LARGE_INTEGER g_RegistryCookie = { 0 };

typedef struct _SYSMON_REGISTRY_CONTEXT {
    ULONG ProcessId;
    ULONG EventType;
    ULONG EventId;
    WCHAR EventTypeName[32];
    WCHAR UtcTime[64];
    WCHAR ProcessGuid[SYSMON_MAX_GUID_STRING];
    WCHAR Image[SYSMON_MAX_PATH];
    WCHAR User[SYSMON_MAX_SID_STRING];
    WCHAR TargetObject[SYSMON_MAX_PATH];
    WCHAR ValueName[SYSMON_MAX_PATH];
    WCHAR Details[SYSMON_MAX_PATH];
    WCHAR NewName[SYSMON_MAX_PATH];
} SYSMON_REGISTRY_CONTEXT, *PSYSMON_REGISTRY_CONTEXT;

static BOOLEAN
SysmonRegistryPathHasPrefix(
    _In_z_ PCWSTR Path,
    _In_z_ PCWSTR Prefix)
{
    SIZE_T prefixChars;

    if (Path == NULL || Prefix == NULL) {
        return FALSE;
    }

    prefixChars = wcslen(Prefix);
    if (_wcsnicmp(Path, Prefix, prefixChars) != 0) {
        return FALSE;
    }

    return Path[prefixChars] == L'\0' || Path[prefixChars] == L'\\';
}

static VOID
SysmonFormatRegistryPathForDisplay(
    _Inout_updates_(PathChars) PWCHAR Path,
    _In_ ULONG PathChars)
{
    static const WCHAR g_ClassesPrefix[] =
        L"\\REGISTRY\\MACHINE\\SOFTWARE\\Classes";
    static const WCHAR g_MachinePrefix[] =
        L"\\REGISTRY\\MACHINE";
    static const WCHAR g_UserPrefix[] =
        L"\\REGISTRY\\USER";
    static const WCHAR g_ControlSetPrefix[] =
        L"\\REGISTRY\\MACHINE\\SYSTEM\\ControlSet";
    WCHAR formatted[SYSMON_MAX_PATH];
    PCWSTR suffix = NULL;

    if (Path == NULL || PathChars == 0 || Path[0] == L'\0') {
        return;
    }

    formatted[0] = L'\0';
    if (SysmonRegistryPathHasPrefix(Path, g_ClassesPrefix)) {
        suffix = Path + wcslen(g_ClassesPrefix);
        _snwprintf_s(formatted, RTL_NUMBER_OF(formatted), _TRUNCATE, L"HKCR%ls", suffix);
    } else if (_wcsnicmp(Path, g_ControlSetPrefix, wcslen(g_ControlSetPrefix)) == 0 &&
               iswdigit(Path[wcslen(g_ControlSetPrefix)]) &&
               iswdigit(Path[wcslen(g_ControlSetPrefix) + 1]) &&
               iswdigit(Path[wcslen(g_ControlSetPrefix) + 2])) {
        suffix = Path + wcslen(g_ControlSetPrefix) + 3;
        _snwprintf_s(
            formatted,
            RTL_NUMBER_OF(formatted),
            _TRUNCATE,
            L"HKLM\\System\\CurrentControlSet%ls",
            suffix);
    } else if (SysmonRegistryPathHasPrefix(Path, g_MachinePrefix)) {
        suffix = Path + wcslen(g_MachinePrefix);
        _snwprintf_s(formatted, RTL_NUMBER_OF(formatted), _TRUNCATE, L"HKLM%ls", suffix);
    } else if (SysmonRegistryPathHasPrefix(Path, g_UserPrefix)) {
        suffix = Path + wcslen(g_UserPrefix);
        _snwprintf_s(formatted, RTL_NUMBER_OF(formatted), _TRUNCATE, L"HKU%ls", suffix);
    }

    if (formatted[0] != L'\0') {
        SysmonCopyWideString(Path, PathChars, formatted);
    }
}

static BOOLEAN
SysmonBuildCreateTargetObject(
    _In_ PREG_CREATE_KEY_INFORMATION_V1 CreateInfo,
    _Out_writes_(TargetChars) PWCHAR TargetObject,
    _In_ ULONG TargetChars,
    _Out_opt_ PUNICODE_STRING CanonicalPath)
{
    PUNICODE_STRING rootKeyName = NULL;
    ULONG prefixChars;
    ULONG relativeChars;

    if (TargetObject == NULL || TargetChars == 0) {
        return FALSE;
    }

    TargetObject[0] = L'\0';
    if (CanonicalPath != NULL) {
        CanonicalPath->Buffer = TargetObject;
        CanonicalPath->Length = 0;
        CanonicalPath->MaximumLength = (USHORT)(TargetChars * sizeof(WCHAR));
    }

    if (CreateInfo == NULL ||
        CreateInfo->CompleteName == NULL ||
        CreateInfo->CompleteName->Buffer == NULL ||
        CreateInfo->CompleteName->Length == 0) {
        return FALSE;
    }

    if (CreateInfo->CompleteName->Buffer[0] == L'\\') {
        SysmonCopyUnicodeString(TargetObject, TargetChars, CreateInfo->CompleteName);
    } else {
        if (CreateInfo->RootObject == NULL) {
            return FALSE;
        }

        if (!NT_SUCCESS(CmCallbackGetKeyObjectID(
                &g_RegistryCookie,
                CreateInfo->RootObject,
                NULL,
                &rootKeyName)) ||
            rootKeyName == NULL ||
            rootKeyName->Buffer == NULL ||
            rootKeyName->Length == 0) {
            return FALSE;
        }

        prefixChars = rootKeyName->Length / sizeof(WCHAR);
        if (prefixChars >= TargetChars) {
            return FALSE;
        }

        RtlCopyMemory(TargetObject, rootKeyName->Buffer, prefixChars * sizeof(WCHAR));
        TargetObject[prefixChars] = L'\0';

        if (TargetObject[prefixChars - 1] != L'\\') {
            if (prefixChars + 1 >= TargetChars) {
                return FALSE;
            }
            TargetObject[prefixChars++] = L'\\';
            TargetObject[prefixChars] = L'\0';
        }

        relativeChars = CreateInfo->CompleteName->Length / sizeof(WCHAR);
        if (prefixChars + relativeChars >= TargetChars) {
            relativeChars = TargetChars - prefixChars - 1;
        }

        if (relativeChars == 0) {
            return FALSE;
        }

        RtlCopyMemory(
            TargetObject + prefixChars,
            CreateInfo->CompleteName->Buffer,
            relativeChars * sizeof(WCHAR));
        TargetObject[prefixChars + relativeChars] = L'\0';
    }

    if (CanonicalPath != NULL) {
        CanonicalPath->Length = (USHORT)(wcslen(TargetObject) * sizeof(WCHAR));
    }

    return (TargetObject[0] != L'\0');
}

static PCWSTR
SysmonRegistryEventTypeName(_In_ ULONG EventType)
{
    switch (EventType) {
    case SysmonRegCreateKey:
        return L"CreateKey";
    case SysmonRegDeleteKey:
        return L"DeleteKey";
    case SysmonRegRenameKey:
        return L"RenameKey";
    case SysmonRegCreateValue:
        return L"CreateValue";
    case SysmonRegDeleteValue:
        return L"DeleteValue";
    case SysmonRegRenameValue:
        return L"RenameValue";
    case SysmonRegSetValue:
        return L"SetValue";
    default:
        return L"Unknown";
    }
}

static NTSTATUS
SysmonAddRegistryEventTypeField(
    _Inout_ PSYSMON_EVENT_UNION Event,
    _Inout_ PSYSMON_EVENT_PAYLOAD_BUILDER Builder,
    _Out_ SYSMON_EVENT_STRING_REF *Ref,
    _In_ ULONG EventType)
{
    switch (EventType) {
    case SysmonRegCreateKey:
        return SysmonAddStringLiteralField(Event, Builder, Ref, L"CreateKey");
    case SysmonRegDeleteKey:
        return SysmonAddStringLiteralField(Event, Builder, Ref, L"DeleteKey");
    case SysmonRegRenameKey:
        return SysmonAddStringLiteralField(Event, Builder, Ref, L"RenameKey");
    case SysmonRegCreateValue:
        return SysmonAddStringLiteralField(Event, Builder, Ref, L"CreateValue");
    case SysmonRegDeleteValue:
        return SysmonAddStringLiteralField(Event, Builder, Ref, L"DeleteValue");
    case SysmonRegRenameValue:
        return SysmonAddStringLiteralField(Event, Builder, Ref, L"RenameValue");
    case SysmonRegSetValue:
        return SysmonAddStringLiteralField(Event, Builder, Ref, L"SetValue");
    default:
        return SysmonAddStringLiteralField(Event, Builder, Ref, L"Unknown");
    }
}

static PCWSTR
SysmonRegistryOperationName(_In_ REG_NOTIFY_CLASS NotifyClass)
{
    switch (NotifyClass) {
    case RegNtPostCreateKey:
    case RegNtPostCreateKeyEx:
        return L"Created";
    case RegNtPostDeleteKey:
    case RegNtPostDeleteValueKey:
        return L"Deleted";
    case RegNtPostRenameKey:
        return L"Renamed";
    case RegNtPostSetValueKey:
    case RegNtPostSetInformationKey:
        return L"Modified";
    default:
        return L"RegistryOperation";
    }
}

static POBJECT_NAME_INFORMATION
SysmonAllocateRegistryObjectNameInfo(
    _In_ PCUNICODE_STRING Name)
{
    POBJECT_NAME_INFORMATION nameInfo;
    SIZE_T totalBytes;
    PWCHAR nameBuffer;

    if (Name == NULL || Name->Buffer == NULL || Name->Length == 0) {
        return NULL;
    }

    totalBytes = sizeof(*nameInfo) + Name->Length + sizeof(WCHAR);
    nameInfo = (POBJECT_NAME_INFORMATION)SysmonAllocatePool(totalBytes);
    if (nameInfo == NULL) {
        return NULL;
    }

    RtlZeroMemory(nameInfo, totalBytes);
    nameBuffer = (PWCHAR)((PUCHAR)nameInfo + sizeof(*nameInfo));
    RtlCopyMemory(nameBuffer, Name->Buffer, Name->Length);
    nameBuffer[Name->Length / sizeof(WCHAR)] = L'\0';

    nameInfo->Name.Buffer = nameBuffer;
    nameInfo->Name.Length = Name->Length;
    nameInfo->Name.MaximumLength = (USHORT)(Name->Length + sizeof(WCHAR));
    return nameInfo;
}

static POBJECT_NAME_INFORMATION
SysmonQueryRegistryObjectName(
    _In_opt_ PVOID Object)
{
    PCUNICODE_STRING canonicalName = NULL;
    POBJECT_NAME_INFORMATION nameInfo = NULL;
    ULONG returnLength = 0;
    NTSTATUS status;

    if (Object == NULL) {
        return NULL;
    }

    if (g_RegistryCookie.QuadPart != 0 &&
        NT_SUCCESS(CmCallbackGetKeyObjectID(
            &g_RegistryCookie,
            Object,
            NULL,
            &canonicalName)) &&
        canonicalName != NULL &&
        canonicalName->Buffer != NULL &&
        canonicalName->Length != 0) {
        nameInfo = SysmonAllocateRegistryObjectNameInfo(canonicalName);
        if (nameInfo != NULL) {
            return nameInfo;
        }
    }

    status = ObQueryNameString(Object, NULL, 0, &returnLength);
    if (status != STATUS_INFO_LENGTH_MISMATCH &&
        status != STATUS_BUFFER_OVERFLOW &&
        status != STATUS_BUFFER_TOO_SMALL) {
        return NULL;
    }

    nameInfo = (POBJECT_NAME_INFORMATION)SysmonAllocatePool(returnLength);
    if (nameInfo == NULL) {
        return NULL;
    }

    RtlZeroMemory(nameInfo, returnLength);
    status = ObQueryNameString(Object, nameInfo, returnLength, &returnLength);
    if (!NT_SUCCESS(status) ||
        nameInfo->Name.Buffer == NULL ||
        nameInfo->Name.Length == 0) {
        SysmonFreePool(nameInfo);
        return NULL;
    }

    return nameInfo;
}

static VOID
SysmonFreeRegistryObjectName(
    _In_opt_ POBJECT_NAME_INFORMATION NameInfo)
{
    SysmonFreePool(NameInfo);
}

static NTSTATUS
SysmonCaptureRegistryObjectContext(
    _In_opt_ PVOID Object)
{
    POBJECT_NAME_INFORMATION nameInfo;
    PVOID oldContext = NULL;
    NTSTATUS status;

    if (Object == NULL || g_RegistryCookie.QuadPart == 0) {
        return STATUS_INVALID_PARAMETER;
    }

    nameInfo = SysmonQueryRegistryObjectName(Object);
    if (nameInfo == NULL) {
        return STATUS_UNSUCCESSFUL;
    }

    status = CmSetCallbackObjectContext(
        Object,
        &g_RegistryCookie,
        nameInfo,
        &oldContext);
    if (!NT_SUCCESS(status)) {
        SysmonFreeRegistryObjectName(nameInfo);
        return status;
    }

    if (oldContext != NULL && oldContext != nameInfo) {
        SysmonFreeRegistryObjectName((POBJECT_NAME_INFORMATION)oldContext);
    }

    return STATUS_SUCCESS;
}

static VOID
SysmonPopulateRegistryProcessContext(
    _Inout_ PSYSMON_REGISTRY_CONTEXT Context)
{
    SYSMON_PROCESS_INFO *processInfo;

    if (KeGetCurrentIrql() != PASSIVE_LEVEL) {
        DbgPrintEx(
            DPFLTR_DEFAULT_ID,
            DPFLTR_WARNING_LEVEL,
            "[SysmonDrv] Registry process identity deferred: callback IRQL is not PASSIVE_LEVEL\n");
        return;
    }

    processInfo = (SYSMON_PROCESS_INFO *)SysmonAllocatePool(sizeof(SYSMON_PROCESS_INFO));
    if (processInfo == NULL) {
        return;
    }

    if (NT_SUCCESS(SysmonCollectProcessTokenIdentity(
            (HANDLE)(ULONG_PTR)Context->ProcessId,
            processInfo))) {
        SysmonCopyWideStringWithLength(
            Context->ProcessGuid,
            RTL_NUMBER_OF(Context->ProcessGuid),
            processInfo->ProcessGuid,
            SYSMON_GUID_STRING_CHARS);
        SysmonCopyWideString(
            Context->Image,
            RTL_NUMBER_OF(Context->Image),
            processInfo->ImagePath);
        SysmonCopyWideString(
            Context->User,
            RTL_NUMBER_OF(Context->User),
            processInfo->UserSid);
    }

    SysmonFreePool(processInfo);
}

static VOID
SysmonAppendRegistryValueName(
    _Inout_updates_(TargetChars) PWCHAR TargetObject,
    _In_ ULONG TargetChars,
    _In_z_ PCWSTR ValueName)
{
    SIZE_T targetChars;
    SIZE_T valueChars;
    PCWSTR sourceValue;

    if (TargetObject == NULL || TargetChars == 0 ||
        ValueName == NULL || ValueName[0] == L'\0') {
        return;
    }

    targetChars = wcslen(TargetObject);
    sourceValue = ValueName;
    while (*sourceValue == L'\\') {
        sourceValue += 1;
    }

    valueChars = wcslen(sourceValue);
    if (targetChars + 2 >= TargetChars) {
        return;
    }

    if (targetChars + 1 + valueChars >= TargetChars) {
        valueChars = TargetChars - targetChars - 2;
    }

    if (valueChars == 0) {
        return;
    }

    TargetObject[targetChars++] = L'\\';
    RtlCopyMemory(TargetObject + targetChars, sourceValue, valueChars * sizeof(WCHAR));
    TargetObject[targetChars + valueChars] = L'\0';
}

static VOID
SysmonBuildRegistryRenameName(
    _Inout_updates_(DstChars) PWCHAR Dst,
    _In_ ULONG DstChars,
    _In_z_ PCWSTR TargetObject,
    _In_z_ PCWSTR NewName)
{
    LONG index;
    ULONG prefixChars;
    ULONG newNameChars;

    if (Dst == NULL || DstChars == 0) {
        return;
    }

    Dst[0] = L'\0';
    if (NewName == NULL || NewName[0] == L'\0') {
        return;
    }

    if (NewName[0] == L'\\') {
        SysmonCopyWideString(Dst, DstChars, NewName);
        return;
    }

    if (TargetObject == NULL || TargetObject[0] == L'\0') {
        SysmonCopyWideString(Dst, DstChars, NewName);
        return;
    }

    index = (LONG)wcslen(TargetObject) - 1;
    while (index >= 0 && TargetObject[index] != L'\\') {
        index--;
    }

    if (index < 0) {
        SysmonCopyWideString(Dst, DstChars, NewName);
        return;
    }

    prefixChars = (ULONG)index + 1;
    if (prefixChars >= DstChars) {
        return;
    }

    RtlCopyMemory(Dst, TargetObject, prefixChars * sizeof(WCHAR));
    newNameChars = (ULONG)wcslen(NewName);
    if (prefixChars + newNameChars >= DstChars) {
        newNameChars = DstChars - prefixChars - 1;
    }

    RtlCopyMemory(Dst + prefixChars, NewName, newNameChars * sizeof(WCHAR));
    Dst[prefixChars + newNameChars] = L'\0';
}

static VOID
SysmonFormatRegistryDetails(
    _In_ ULONG Type,
    _In_reads_bytes_opt_(DataSize) PVOID Data,
    _In_ ULONG DataSize,
    _Out_writes_(BufferChars) PWCHAR Buffer,
    _In_ ULONG BufferChars)
{
    ULONG copyChars;
    ULONGLONG qwordValue;
    ULONG dwordValue;

    if (Buffer == NULL || BufferChars == 0) {
        return;
    }

    Buffer[0] = L'\0';
    if (Data == NULL || DataSize == 0) {
        return;
    }

    switch (Type) {
    case REG_SZ:
    case REG_EXPAND_SZ:
        copyChars = DataSize / sizeof(WCHAR);
        if (copyChars > 0 && ((PWCHAR)Data)[copyChars - 1] == L'\0') {
            copyChars--;
        }
        if (copyChars >= BufferChars) {
            copyChars = BufferChars - 1;
        }
        RtlCopyMemory(Buffer, Data, copyChars * sizeof(WCHAR));
        Buffer[copyChars] = L'\0';
        break;
    case REG_DWORD:
        if (DataSize >= sizeof(ULONG)) {
            RtlCopyMemory(&dwordValue, Data, sizeof(dwordValue));
            _snwprintf_s(
                Buffer,
                BufferChars,
                _TRUNCATE,
                L"DWORD (0x%08X)",
                dwordValue);
        }
        break;
    case REG_QWORD:
        if (DataSize >= sizeof(ULONGLONG)) {
            RtlCopyMemory(&qwordValue, Data, sizeof(qwordValue));
            _snwprintf_s(
                Buffer,
                BufferChars,
                _TRUNCATE,
                L"QWORD (0x%08X-0x%08X)",
                (ULONG)(qwordValue >> 32),
                (ULONG)qwordValue);
        }
        break;
    case REG_MULTI_SZ:
        copyChars = DataSize / sizeof(WCHAR);
        if (copyChars >= BufferChars) {
            copyChars = BufferChars - 1;
        }
        RtlCopyMemory(Buffer, Data, copyChars * sizeof(WCHAR));
        Buffer[copyChars] = L'\0';
        break;
    default:
        _snwprintf_s(
            Buffer,
            BufferChars,
            _TRUNCATE,
            L"Type %lu (%lu bytes)",
            Type,
            DataSize);
        break;
    }
}

static VOID
SysmonSubmitRegistryEvent(_In_ PSYSMON_EVENT_UNION Event)
{
    if (Event != NULL) {
        DbgPrintEx(
            DPFLTR_DEFAULT_ID,
            DPFLTR_INFO_LEVEL,
            "[SysmonDrv] Registry submit id=%lu size=%lu\n",
            Event->Header.EventId,
            Event->Header.EventSize);
    }

    SysmonPublishEvent(Event);
}

/* Map registry operation class to Sysmon event type */
static ULONG
SysmonMapRegistryClass(
    _In_ REG_NOTIFY_CLASS NotifyClass,
    _Out_ PULONG SysmonEventId,
    _Out_ PULONG SysmonEventType)
{
    switch (NotifyClass) {
    case RegNtPostCreateKey:
    case RegNtPostCreateKeyEx:
        *SysmonEventId = SysmonEventRegistryEvent;
        *SysmonEventType = SysmonRegCreateKey;
        return TRUE;
    case RegNtPostDeleteKey:
        *SysmonEventId = SysmonEventRegistryEvent;
        *SysmonEventType = SysmonRegDeleteKey;
        return TRUE;
    case RegNtPostRenameKey:
        *SysmonEventId = SysmonEventRegistryRename;
        *SysmonEventType = SysmonRegRenameKey;
        return TRUE;
    case RegNtPostSetValueKey:
        *SysmonEventId = SysmonEventRegistrySetValue;
        *SysmonEventType = SysmonRegSetValue;
        return TRUE;
    case RegNtPostDeleteValueKey:
        *SysmonEventId = SysmonEventRegistryEvent;
        *SysmonEventType = SysmonRegDeleteValue;
        return TRUE;
    default:
        *SysmonEventId = SysmonEventNull;
        *SysmonEventType = 0;
        return FALSE;
    }
}

static NTSTATUS
RegistryCallback(
    _In_ PVOID CallbackContext,
    _In_opt_ PVOID Argument1,
    _In_opt_ PVOID Argument2)
{
    REG_NOTIFY_CLASS notifyClass;
    ULONG sysmonEventType = 0;
    ULONG sysmonEventId = SysmonEventNull;
    NTSTATUS status = STATUS_SUCCESS;
    PSYSMON_EVENT_UNION event = NULL;
    POBJECT_NAME_INFORMATION objectNameInfo = NULL;
    POBJECT_NAME_INFORMATION oldNameInfo = NULL;
    POBJECT_NAME_INFORMATION callContextNameInfo = NULL;
    PCUNICODE_STRING keyName = NULL;
    PSYSMON_REGISTRY_CONTEXT context = NULL;
    SYSMON_EVENT_PAYLOAD_BUILDER builder;
    WCHAR baseTargetObject[SYSMON_MAX_PATH];
    PREG_POST_OPERATION_INFORMATION postInfo;
    PREG_POST_CREATE_KEY_INFORMATION postCreateInfo;
    UNICODE_STRING baseKeyName;

    UNREFERENCED_PARAMETER(CallbackContext);

    notifyClass = (REG_NOTIFY_CLASS)(ULONG_PTR)Argument1;

    if (notifyClass == RegNtCallbackObjectContextCleanup) {
        PREG_CALLBACK_CONTEXT_CLEANUP_INFORMATION cleanupInfo =
            (PREG_CALLBACK_CONTEXT_CLEANUP_INFORMATION)Argument2;

        if (cleanupInfo != NULL && cleanupInfo->ObjectContext != NULL) {
            SysmonFreeRegistryObjectName(
                (POBJECT_NAME_INFORMATION)cleanupInfo->ObjectContext);
        }
        return STATUS_SUCCESS;
    }

    if (!SysmonIsProducerEnabled(SYSMON_FLAG_ENABLED) || !SysmonIsProducerEnabled(SYSMON_FLAG_REGISTRY_NOTIFY)) {
        return STATUS_SUCCESS;
    }

    if (notifyClass == RegNtPreDeleteKey) {
        PREG_DELETE_KEY_INFORMATION deleteInfo =
            (PREG_DELETE_KEY_INFORMATION)Argument2;

        if (deleteInfo != NULL && deleteInfo->Object != NULL) {
            if (deleteInfo->CallContext == NULL) {
                deleteInfo->CallContext = SysmonQueryRegistryObjectName(deleteInfo->Object);
            }
            SysmonCaptureRegistryObjectContext(deleteInfo->Object);
        }
        return STATUS_SUCCESS;
    }

    if (notifyClass == RegNtPreRenameKey) {
        PREG_RENAME_KEY_INFORMATION renameInfo =
            (PREG_RENAME_KEY_INFORMATION)Argument2;

        if (renameInfo != NULL && renameInfo->Object != NULL) {
            if (renameInfo->CallContext == NULL) {
                renameInfo->CallContext = SysmonQueryRegistryObjectName(renameInfo->Object);
            }
            SysmonCaptureRegistryObjectContext(renameInfo->Object);
        }
        return STATUS_SUCCESS;
    }

    if (!SysmonMapRegistryClass(notifyClass, &sysmonEventId, &sysmonEventType)) {
        return STATUS_SUCCESS;
    }

    context = (PSYSMON_REGISTRY_CONTEXT)SysmonAllocatePool(sizeof(*context));
    if (context == NULL) {
        return STATUS_SUCCESS;
    }

    RtlZeroMemory(context, sizeof(*context));
    context->EventId = sysmonEventId;
    context->EventType = sysmonEventType;
    context->ProcessId = (ULONG)(ULONG_PTR)PsGetCurrentProcessId();
    SysmonCopyWideString(
        context->EventTypeName,
        RTL_NUMBER_OF(context->EventTypeName),
        SysmonRegistryEventTypeName(sysmonEventType));
    status = SysmonFormatTimestamp(SysmonGetCurrentTimestamp(), context->UtcTime);
    if (!NT_SUCCESS(status)) {
        goto Cleanup;
    }
    RtlZeroMemory(baseTargetObject, sizeof(baseTargetObject));

    if (notifyClass == RegNtPostCreateKey) {
        postCreateInfo = (PREG_POST_CREATE_KEY_INFORMATION)Argument2;
        if (postCreateInfo == NULL ||
            !NT_SUCCESS(postCreateInfo->Status) ||
            postCreateInfo->Object == NULL) {
            goto Cleanup;
        }

        objectNameInfo = SysmonQueryRegistryObjectName(postCreateInfo->Object);
    } else {
        postInfo = (PREG_POST_OPERATION_INFORMATION)Argument2;
        if (postInfo == NULL ||
            !NT_SUCCESS(postInfo->Status) ||
            (postInfo->Object == NULL && notifyClass != RegNtPostRenameKey)) {
            goto Cleanup;
        }

        switch (notifyClass) {
        case RegNtPostCreateKeyEx:
            objectNameInfo = SysmonQueryRegistryObjectName(postInfo->Object);
            break;

        case RegNtPostDeleteKey:
            callContextNameInfo = (POBJECT_NAME_INFORMATION)postInfo->CallContext;
            oldNameInfo = callContextNameInfo;
            if (oldNameInfo == NULL) {
                oldNameInfo = (POBJECT_NAME_INFORMATION)postInfo->ObjectContext;
            }
            if (oldNameInfo == NULL) {
                objectNameInfo = SysmonQueryRegistryObjectName(postInfo->Object);
            }
            break;

        case RegNtPostSetValueKey:
        {
            PREG_SET_VALUE_KEY_INFORMATION setInfo =
                (PREG_SET_VALUE_KEY_INFORMATION)postInfo->PreInformation;

            objectNameInfo = SysmonQueryRegistryObjectName(postInfo->Object);
            if (setInfo != NULL) {
                if (setInfo->ValueName != NULL) {
                    SysmonCopyUnicodeString(
                        context->ValueName,
                        RTL_NUMBER_OF(context->ValueName),
                        setInfo->ValueName);
                }
                SysmonFormatRegistryDetails(
                    setInfo->Type,
                    setInfo->Data,
                    setInfo->DataSize,
                    context->Details,
                    RTL_NUMBER_OF(context->Details));
            }
            break;
        }

        case RegNtPostDeleteValueKey:
        {
            PREG_DELETE_VALUE_KEY_INFORMATION deleteValueInfo =
                (PREG_DELETE_VALUE_KEY_INFORMATION)postInfo->PreInformation;

            objectNameInfo = SysmonQueryRegistryObjectName(postInfo->Object);
            if (deleteValueInfo != NULL && deleteValueInfo->ValueName != NULL) {
                SysmonCopyUnicodeString(
                    context->ValueName,
                    RTL_NUMBER_OF(context->ValueName),
                    deleteValueInfo->ValueName);
            }
            break;
        }

        case RegNtPostRenameKey:
        {
            PREG_RENAME_KEY_INFORMATION renameInfo =
                (PREG_RENAME_KEY_INFORMATION)postInfo->PreInformation;
            WCHAR renameBuffer[SYSMON_MAX_PATH];

            callContextNameInfo = (POBJECT_NAME_INFORMATION)postInfo->CallContext;
            oldNameInfo = callContextNameInfo;
            if (oldNameInfo == NULL) {
                oldNameInfo = (POBJECT_NAME_INFORMATION)postInfo->ObjectContext;
            }
            if (postInfo->Object != NULL) {
                objectNameInfo = SysmonQueryRegistryObjectName(postInfo->Object);
            }
            if (objectNameInfo != NULL) {
                SysmonCopyUnicodeString(
                    context->NewName,
                    RTL_NUMBER_OF(context->NewName),
                    &objectNameInfo->Name);
            }

            if (context->NewName[0] == L'\0' &&
                renameInfo != NULL &&
                renameInfo->NewName != NULL) {
                RtlZeroMemory(renameBuffer, sizeof(renameBuffer));
                SysmonCopyUnicodeString(
                    renameBuffer,
                    RTL_NUMBER_OF(renameBuffer),
                    renameInfo->NewName);
                SysmonBuildRegistryRenameName(
                    context->NewName,
                    RTL_NUMBER_OF(context->NewName),
                    (oldNameInfo != NULL &&
                     oldNameInfo->Name.Buffer != NULL &&
                     oldNameInfo->Name.Length != 0) ?
                        oldNameInfo->Name.Buffer : NULL,
                    renameBuffer);
            }
            break;
        }

        default:
            break;
        }
    }

    if (oldNameInfo != NULL &&
        oldNameInfo->Name.Buffer != NULL &&
        oldNameInfo->Name.Length != 0) {
        keyName = &oldNameInfo->Name;
    } else if (objectNameInfo != NULL &&
               objectNameInfo->Name.Buffer != NULL &&
               objectNameInfo->Name.Length != 0) {
        keyName = &objectNameInfo->Name;
    }

    if (keyName == NULL) {
        goto Cleanup;
    }

    SysmonCopyUnicodeString(
        context->TargetObject,
        RTL_NUMBER_OF(context->TargetObject),
        keyName);
    if (context->TargetObject[0] == L'\0') {
        goto Cleanup;
    }

    SysmonCopyWideString(
        baseTargetObject,
        RTL_NUMBER_OF(baseTargetObject),
        context->TargetObject);

    if (context->ValueName[0] != L'\0') {
        SysmonAppendRegistryValueName(
            context->TargetObject,
            RTL_NUMBER_OF(context->TargetObject),
            context->ValueName);
    }

    baseKeyName.Buffer = baseTargetObject;
    baseKeyName.Length = (USHORT)(wcslen(baseTargetObject) * sizeof(WCHAR));
    baseKeyName.MaximumLength = (USHORT)sizeof(baseTargetObject);

    /* WMI Event 19/20/21 are produced by the user-mode ROOT\\Subscription
       watcher. Registry callbacks cannot recover the WMI object fields and
       must not emit placeholder duplicates. */
    SysmonCheckDnsRegistryEvent(&baseKeyName, context->ProcessId);

    SysmonPopulateRegistryProcessContext(context);
    SysmonFormatRegistryPathForDisplay(
        context->TargetObject,
        RTL_NUMBER_OF(context->TargetObject));
    SysmonFormatRegistryPathForDisplay(
        context->NewName,
        RTL_NUMBER_OF(context->NewName));

    event = SysmonAllocateEvent((SYSMON_EVENT_ID)sysmonEventId);
    if (event == NULL) {
        goto Cleanup;
    }

    if (sysmonEventId == SysmonEventRegistryValueSet) {
        SYSMON_EVENT_REGISTRY_VALUE_SET_PAYLOAD *payload;

        SysmonBeginStringPayload(event, sizeof(*payload), &builder);
        payload = (SYSMON_EVENT_REGISTRY_VALUE_SET_PAYLOAD *)event->RawData;
        payload->ProcessId = context->ProcessId;
        SysmonAddStringLiteralField(event, &builder, &payload->RuleName, L"-");
        SysmonAddRegistryEventTypeField(event, &builder, &payload->EventType, context->EventType);
        SysmonAddFixedLengthStringField(
            event,
            &builder,
            &payload->UtcTime,
            context->UtcTime,
            SYSMON_TIMESTAMP_STRING_CHARS);
        SysmonAddFixedLengthStringField(
            event,
            &builder,
            &payload->ProcessGuid,
            context->ProcessGuid,
            SYSMON_GUID_STRING_CHARS);
        SysmonAddStringField(event, &builder, &payload->Image, context->Image);
        SysmonAddStringField(event, &builder, &payload->TargetObject, context->TargetObject);
        SysmonAddStringField(event, &builder, &payload->Details, context->Details);
        SysmonAddStringField(event, &builder, &payload->User, context->User);
    } else if (sysmonEventId == SysmonEventRegistryRename) {
        SYSMON_EVENT_REGISTRY_RENAME_PAYLOAD *payload;

        SysmonBeginStringPayload(event, sizeof(*payload), &builder);
        payload = (SYSMON_EVENT_REGISTRY_RENAME_PAYLOAD *)event->RawData;
        payload->ProcessId = context->ProcessId;
        SysmonAddStringLiteralField(event, &builder, &payload->RuleName, L"-");
        SysmonAddRegistryEventTypeField(event, &builder, &payload->EventType, context->EventType);
        SysmonAddFixedLengthStringField(
            event,
            &builder,
            &payload->UtcTime,
            context->UtcTime,
            SYSMON_TIMESTAMP_STRING_CHARS);
        SysmonAddFixedLengthStringField(
            event,
            &builder,
            &payload->ProcessGuid,
            context->ProcessGuid,
            SYSMON_GUID_STRING_CHARS);
        SysmonAddStringField(event, &builder, &payload->Image, context->Image);
        SysmonAddStringField(event, &builder, &payload->TargetObject, context->TargetObject);
        SysmonAddStringField(event, &builder, &payload->NewName, context->NewName);
        SysmonAddStringField(event, &builder, &payload->User, context->User);
    } else {
        SYSMON_EVENT_REGISTRY_EVENT_PAYLOAD *payload;

        SysmonBeginStringPayload(event, sizeof(*payload), &builder);
        payload = (SYSMON_EVENT_REGISTRY_EVENT_PAYLOAD *)event->RawData;
        payload->ProcessId = context->ProcessId;
        SysmonAddStringLiteralField(event, &builder, &payload->RuleName, L"-");
        SysmonAddRegistryEventTypeField(event, &builder, &payload->EventType, context->EventType);
        SysmonAddFixedLengthStringField(
            event,
            &builder,
            &payload->UtcTime,
            context->UtcTime,
            SYSMON_TIMESTAMP_STRING_CHARS);
        SysmonAddFixedLengthStringField(
            event,
            &builder,
            &payload->ProcessGuid,
            context->ProcessGuid,
            SYSMON_GUID_STRING_CHARS);
        SysmonAddStringField(event, &builder, &payload->Image, context->Image);
        SysmonAddStringField(event, &builder, &payload->TargetObject, context->TargetObject);
        SysmonAddStringField(event, &builder, &payload->User, context->User);
    }

    DbgPrintEx(
        DPFLTR_DEFAULT_ID,
        DPFLTR_INFO_LEVEL,
        "[SysmonDrv] Registry built id=%lu size=%lu target=%ws\n",
        event->Header.EventId,
        event->Header.EventSize,
        context->TargetObject);

    /* Enqueue and try to complete pending IRP */
    SysmonSubmitRegistryEvent(event);
    SysmonFreeEvent(event);
    event = NULL;

Cleanup:
    SysmonFreeRegistryObjectName(callContextNameInfo);
    SysmonFreeRegistryObjectName(objectNameInfo);
    SysmonFreeEvent(event);
    SysmonFreePool(context);
    return STATUS_SUCCESS;
}

NTSTATUS
SysmonRegisterRegistryCallback(VOID)
{
    NTSTATUS status;

    if (g_RegistryCookie.QuadPart != 0) {
        return STATUS_SUCCESS;
    }

    status = CmRegisterCallback(RegistryCallback, NULL, &g_RegistryCookie);
    if (!NT_SUCCESS(status)) {
        DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_WARNING_LEVEL,
            "[SysmonDrv] CmRegisterCallback failed: 0x%08X\n", status);
    }
    return status;
}

VOID
SysmonUnregisterRegistryCallback(VOID)
{
    if (g_RegistryCookie.QuadPart != 0) {
        CmUnRegisterCallback(g_RegistryCookie);
        g_RegistryCookie.QuadPart = 0;
    }
}

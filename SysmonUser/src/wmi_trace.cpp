#define COBJMACROS

#include "../include/wmi_trace.h"

#include "../include/event.h"
#include "../include/pipeline.h"
#include "../include/rules.h"
#include "../include/service.h"
#include "../include/source_common.h"

#include <objbase.h>
#include <oleauto.h>
#include <sddl.h>
#include <wbemidl.h>

#define SYSMON_WMI_QUERY_LANGUAGE     L"WQL"
#define SYSMON_WMI_QUERY_TEXT         L"SELECT * FROM __InstanceOperationEvent WITHIN 5 WHERE TargetInstance ISA '__EventConsumer' OR TargetInstance ISA '__EventFilter' OR TargetInstance ISA '__FilterToConsumerBinding'"
#define SYSMON_WMI_NAMESPACE          L"ROOT\\Subscription"
#define SYSMON_WMI_EVENT_BUFFER_SIZE  16384

typedef struct _SYSMON_WMI_EVENT_INFO {
    SYSMON_EVENT_ID EventId;
    WCHAR EventType[32];
    WCHAR UtcTime[64];
    WCHAR Operation[16];
    WCHAR User[256];
    WCHAR EventNamespace[512];
    WCHAR Name[512];
    WCHAR Query[2048];
    WCHAR Type[64];
    WCHAR Destination[2048];
    WCHAR Consumer[1024];
    WCHAR Filter[1024];
    ULONGLONG Timestamp;
} SYSMON_WMI_EVENT_INFO, *PSYSMON_WMI_EVENT_INFO;

struct _SYSMON_WMI_TRACE_CONTEXT {
    PSYSMON_SERVICE_CONTEXT ServiceContext;
    HANDLE ThreadHandle;
    PSYSMON_RULE_RUNTIME RuleRuntime;
    const BYTE *RuleSourceBlob;
    DWORD RuleSourceBlobSize;
    volatile LONG StopRequested;
};

static BOOL
SysmonTryAddEventString(
    _Inout_updates_bytes_(EventBufferSize) PBYTE EventBuffer,
    _In_ DWORD EventBufferSize,
    _Inout_ PSYSMON_EVENT_PAYLOAD_BUILDER Builder,
    _Out_ SYSMON_EVENT_STRING_REF *Field,
    _In_opt_z_ PCWSTR Value)
{
    return SysmonAddStringField(
               EventBuffer,
               EventBufferSize,
               Builder,
               Field,
               Value) == SYSMON_SUCCESS;
}

static BOOL
SysmonExtractStringValue(
    _In_ IWbemClassObject *Object,
    _In_z_ LPCWSTR PropertyName,
    _Out_writes_(BufferChars) PWCHAR Buffer,
    _In_ size_t BufferChars)
{
    VARIANT value;
    VARIANT converted;
    HRESULT hr;
    BOOL success = FALSE;

    if (Object == NULL || PropertyName == NULL || Buffer == NULL || BufferChars == 0) {
        return FALSE;
    }

    Buffer[0] = L'\0';
    VariantInit(&value);
    VariantInit(&converted);

    hr = Object->Get(PropertyName, 0, &value, NULL, NULL);
    if (FAILED(hr) || value.vt == VT_NULL || value.vt == VT_EMPTY) {
        goto cleanup;
    }

    if (value.vt == VT_BSTR) {
        SysmonCopyOrPlaceholder(Buffer, BufferChars, value.bstrVal);
        success = TRUE;
        goto cleanup;
    }

    hr = VariantChangeType(&converted, &value, 0, VT_BSTR);
    if (SUCCEEDED(hr) && converted.vt == VT_BSTR) {
        SysmonCopyOrPlaceholder(Buffer, BufferChars, converted.bstrVal);
        success = TRUE;
    }

cleanup:
    VariantClear(&converted);
    VariantClear(&value);
    return success;
}

static BOOL
SysmonExtractCreatorSid(
    _In_ IWbemClassObject *Object,
    _Out_writes_(BufferChars) PWCHAR Buffer,
    _In_ size_t BufferChars)
{
    VARIANT value;
    HRESULT hr;
    BOOL success = FALSE;

    if (Object == NULL || Buffer == NULL || BufferChars == 0) {
        return FALSE;
    }

    SysmonCopyOrPlaceholder(Buffer, BufferChars, L"-");
    VariantInit(&value);

    hr = Object->Get(L"CreatorSID", 0, &value, NULL, NULL);
    if (FAILED(hr) || value.vt == VT_NULL || value.vt == VT_EMPTY) {
        goto cleanup;
    }

    if (value.vt == VT_BSTR) {
        PSID sid = NULL;

        if (ConvertStringSidToSidW(value.bstrVal, &sid)) {
            SysmonResolveAccountName(sid, Buffer, BufferChars);
            LocalFree(sid);
        } else {
            SysmonCopyOrPlaceholder(Buffer, BufferChars, value.bstrVal);
        }

        success = TRUE;
        goto cleanup;
    }

    if ((value.vt & VT_ARRAY) != 0 && (value.vt & VT_TYPEMASK) == VT_UI1 && value.parray != NULL) {
        BYTE *data = NULL;
        LONG lower = 0;
        LONG upper = -1;

        if (SUCCEEDED(SafeArrayGetLBound(value.parray, 1, &lower)) &&
            SUCCEEDED(SafeArrayGetUBound(value.parray, 1, &upper)) &&
            upper >= lower &&
            SUCCEEDED(SafeArrayAccessData(value.parray, (void **)&data))) {
            ULONG sidBytes = (ULONG)(upper - lower + 1);

            if (sidBytes >= SECURITY_MAX_SID_SIZE) {
                sidBytes = SECURITY_MAX_SID_SIZE;
            }

            if (data != NULL && IsValidSid(data)) {
                SysmonResolveAccountName((PSID)data, Buffer, BufferChars);
                success = TRUE;
            }

            SafeArrayUnaccessData(value.parray);
        }
    }

cleanup:
    VariantClear(&value);
    return success;
}

static BOOL
SysmonGetTargetInstance(
    _In_ IWbemClassObject *EventObject,
    _Outptr_ IWbemClassObject **TargetInstance)
{
    VARIANT value;
    HRESULT hr;
    BOOL success = FALSE;

    if (EventObject == NULL || TargetInstance == NULL) {
        return FALSE;
    }

    *TargetInstance = NULL;
    VariantInit(&value);

    hr = EventObject->Get(L"TargetInstance", 0, &value, NULL, NULL);
    if (FAILED(hr)) {
        goto cleanup;
    }

    if (value.vt == VT_UNKNOWN && value.punkVal != NULL) {
        hr = value.punkVal->QueryInterface(IID_IWbemClassObject, reinterpret_cast<void **>(TargetInstance));
        success = SUCCEEDED(hr) && *TargetInstance != NULL;
    }

cleanup:
    VariantClear(&value);
    return success;
}

static void
SysmonWrapQuotedValue(
    _Out_writes_(BufferChars) PWCHAR Buffer,
    _In_ size_t BufferChars,
    _In_opt_z_ PCWSTR Value)
{
    size_t valueLength;
    size_t writeOffset;
    const WCHAR *cursor;

    if (Buffer == NULL || BufferChars == 0) {
        return;
    }

    if (Value == NULL || Value[0] == L'\0' || (Value[0] == L'-' && Value[1] == L'\0')) {
        wcscpy_s(Buffer, BufferChars, L"-");
        return;
    }

    valueLength = wcslen(Value);
    if (valueLength >= 2 && Value[0] == L'"' && Value[valueLength - 1] == L'"') {
        wcscpy_s(Buffer, BufferChars, Value);
        return;
    }

    Buffer[0] = L'"';
    writeOffset = 1;
    for (cursor = Value; *cursor != L'\0' && writeOffset + 2 < BufferChars; cursor++) {
        if (*cursor == L'"') {
            Buffer[writeOffset++] = L'\\';
        }
        Buffer[writeOffset++] = *cursor;
    }

    if (writeOffset + 1 >= BufferChars) {
        Buffer[0] = L'-';
        Buffer[1] = L'\0';
        return;
    }

    Buffer[writeOffset++] = L'"';
    Buffer[writeOffset] = L'\0';
}

static void
SysmonMapOperation(
    _In_z_ LPCWSTR EventClass,
    _Out_writes_(BufferChars) PWCHAR Buffer,
    _In_ size_t BufferChars)
{
    if (Buffer == NULL || BufferChars == 0) {
        return;
    }

    if (EventClass == NULL) {
        wcscpy_s(Buffer, BufferChars, L"Unknown");
    } else if (wcsstr(EventClass, L"Deletion") != NULL) {
        wcscpy_s(Buffer, BufferChars, L"Deleted");
    } else if (wcsstr(EventClass, L"Creation") != NULL) {
        wcscpy_s(Buffer, BufferChars, L"Created");
    } else if (wcsstr(EventClass, L"Modification") != NULL) {
        wcscpy_s(Buffer, BufferChars, L"Modified");
    } else {
        wcscpy_s(Buffer, BufferChars, L"Unknown");
    }
}

static SYSMON_EVENT_ID
SysmonClassToEventId(
    _In_z_ LPCWSTR ClassName)
{
    if (ClassName == NULL) {
        return SysmonEventNone;
    }

    if (_wcsicmp(ClassName, L"__EventFilter") == 0) {
        return SysmonEventWmiFilter;
    }

    if (_wcsicmp(ClassName, L"__FilterToConsumerBinding") == 0) {
        return SysmonEventWmiConsumerToFilter;
    }

    return SysmonEventWmiConsumer;
}

static void
SysmonDetectConsumerDetails(
    _In_ IWbemClassObject *TargetInstance,
    _Out_writes_(TypeChars) PWCHAR TypeBuffer,
    _In_ size_t TypeChars,
    _Out_writes_(DestinationChars) PWCHAR DestinationBuffer,
    _In_ size_t DestinationChars)
{
    WCHAR value[2048];

    SysmonCopyOrPlaceholder(TypeBuffer, TypeChars, L"Unknown");
    SysmonCopyOrPlaceholder(DestinationBuffer, DestinationChars, L"-");

    if (SysmonExtractStringValue(TargetInstance, L"ScriptFilename", value, _countof(value)) && value[0] != L'\0') {
        wcscpy_s(TypeBuffer, TypeChars, L"Script");
        SysmonWrapQuotedValue(DestinationBuffer, DestinationChars, value);
        return;
    }

    if (SysmonExtractStringValue(TargetInstance, L"ScriptText", value, _countof(value)) && value[0] != L'\0') {
        wcscpy_s(TypeBuffer, TypeChars, L"Script");
        SysmonWrapQuotedValue(DestinationBuffer, DestinationChars, value);
        return;
    }

    if (SysmonExtractStringValue(TargetInstance, L"ExecutablePath", value, _countof(value)) && value[0] != L'\0') {
        wcscpy_s(TypeBuffer, TypeChars, L"Command Line");
        SysmonWrapQuotedValue(DestinationBuffer, DestinationChars, value);
        return;
    }

    if (SysmonExtractStringValue(TargetInstance, L"CommandLineTemplate", value, _countof(value)) && value[0] != L'\0') {
        wcscpy_s(TypeBuffer, TypeChars, L"Command Line");
        SysmonWrapQuotedValue(DestinationBuffer, DestinationChars, value);
        return;
    }

    if (SysmonExtractStringValue(TargetInstance, L"Filename", value, _countof(value)) && value[0] != L'\0') {
        wcscpy_s(TypeBuffer, TypeChars, L"Log File");
        SysmonWrapQuotedValue(DestinationBuffer, DestinationChars, value);
        return;
    }

    if (SysmonExtractStringValue(TargetInstance, L"SourceName", value, _countof(value)) && value[0] != L'\0') {
        wcscpy_s(TypeBuffer, TypeChars, L"Event Log");
        SysmonWrapQuotedValue(DestinationBuffer, DestinationChars, value);
        return;
    }

    if (SysmonExtractStringValue(TargetInstance, L"ToLine", value, _countof(value)) && value[0] != L'\0') {
        wcscpy_s(TypeBuffer, TypeChars, L"SMTP");
        SysmonWrapQuotedValue(DestinationBuffer, DestinationChars, value);
    }
}

static void
SysmonRefreshRuleRuntime(
    _Inout_ PSYSMON_WMI_TRACE_CONTEXT Context)
{
    if (Context == NULL || Context->ServiceContext == NULL) {
        return;
    }

    SysmonRefreshSourceRuleRuntime(
        Context->ServiceContext,
        &Context->RuleRuntime,
        &Context->RuleSourceBlob,
        &Context->RuleSourceBlobSize,
        0,
        NULL);
}

static BOOL
SysmonParseWmiEventObject(
    _In_ IWbemClassObject *EventObject,
    _Out_ PSYSMON_WMI_EVENT_INFO Info)
{
    IWbemClassObject *targetInstance = NULL;
    WCHAR eventClass[128];
    WCHAR targetClass[128];

    if (EventObject == NULL || Info == NULL) {
        return FALSE;
    }

    ZeroMemory(Info, sizeof(*Info));
    SysmonCopyOrPlaceholder(Info->User, _countof(Info->User), L"-");
    SysmonCopyOrPlaceholder(Info->EventNamespace, _countof(Info->EventNamespace), L"-");
    SysmonCopyOrPlaceholder(Info->Name, _countof(Info->Name), L"-");
    SysmonCopyOrPlaceholder(Info->Query, _countof(Info->Query), L"-");
    SysmonCopyOrPlaceholder(Info->Type, _countof(Info->Type), L"-");
    SysmonCopyOrPlaceholder(Info->Destination, _countof(Info->Destination), L"-");
    SysmonCopyOrPlaceholder(Info->Consumer, _countof(Info->Consumer), L"-");
    SysmonCopyOrPlaceholder(Info->Filter, _countof(Info->Filter), L"-");

    if (!SysmonExtractStringValue(EventObject, L"__CLASS", eventClass, _countof(eventClass))) {
        wcscpy_s(eventClass, _countof(eventClass), L"Unknown");
    }

    if (!SysmonGetTargetInstance(EventObject, &targetInstance)) {
        return FALSE;
    }

    if (!SysmonExtractStringValue(targetInstance, L"__CLASS", targetClass, _countof(targetClass))) {
        targetInstance->Release();
        return FALSE;
    }

    Info->EventId = SysmonClassToEventId(targetClass);
    if (Info->EventId == SysmonEventNone) {
        targetInstance->Release();
        return FALSE;
    }

    switch (Info->EventId) {
    case SysmonEventWmiFilter:
        wcscpy_s(Info->EventType, _countof(Info->EventType), L"WmiFilterEvent");
        break;
    case SysmonEventWmiConsumer:
        wcscpy_s(Info->EventType, _countof(Info->EventType), L"WmiConsumerEvent");
        break;
    case SysmonEventWmiConsumerToFilter:
        wcscpy_s(Info->EventType, _countof(Info->EventType), L"WmiBindingEvent");
        break;
    default:
        targetInstance->Release();
        return FALSE;
    }

    SysmonMapOperation(eventClass, Info->Operation, _countof(Info->Operation));
    SysmonFormatCurrentUtcTime(Info->UtcTime, _countof(Info->UtcTime), &Info->Timestamp);
    SysmonExtractCreatorSid(targetInstance, Info->User, _countof(Info->User));

    if (Info->EventId == SysmonEventWmiFilter) {
        WCHAR value[2048];

        if (SysmonExtractStringValue(targetInstance, L"EventNamespace", value, _countof(value))) {
            SysmonWrapQuotedValue(Info->EventNamespace, _countof(Info->EventNamespace), value);
        }
        if (SysmonExtractStringValue(targetInstance, L"Name", value, _countof(value))) {
            SysmonWrapQuotedValue(Info->Name, _countof(Info->Name), value);
        }
        if (SysmonExtractStringValue(targetInstance, L"Query", value, _countof(value))) {
            SysmonWrapQuotedValue(Info->Query, _countof(Info->Query), value);
        }
    } else if (Info->EventId == SysmonEventWmiConsumer) {
        WCHAR value[2048];

        if (SysmonExtractStringValue(targetInstance, L"Name", value, _countof(value))) {
            SysmonWrapQuotedValue(Info->Name, _countof(Info->Name), value);
        }
        SysmonDetectConsumerDetails(
            targetInstance,
            Info->Type,
            _countof(Info->Type),
            Info->Destination,
            _countof(Info->Destination));
    } else if (Info->EventId == SysmonEventWmiConsumerToFilter) {
        WCHAR value[2048];

        if (SysmonExtractStringValue(targetInstance, L"Consumer", value, _countof(value))) {
            SysmonWrapQuotedValue(Info->Consumer, _countof(Info->Consumer), value);
        }
        if (SysmonExtractStringValue(targetInstance, L"Filter", value, _countof(value))) {
            SysmonWrapQuotedValue(Info->Filter, _countof(Info->Filter), value);
        }
    }

    targetInstance->Release();
    return TRUE;
}

static void
SysmonDispatchWmiEvent(
    _Inout_ PSYSMON_WMI_TRACE_CONTEXT Context,
    _In_ const SYSMON_WMI_EVENT_INFO *Info)
{
    BYTE eventBuffer[SYSMON_WMI_EVENT_BUFFER_SIZE];
    SYSMON_EVENT_PAYLOAD_BUILDER builder;
    PSYSMON_EVENT_HEADER header;

    if (Context == NULL || Info == NULL) {
        return;
    }

    SysmonRefreshRuleRuntime(Context);
    if (Context->RuleRuntime != NULL &&
        !SysmonRuleRuntimeEventCanProduceLogs(Context->RuleRuntime, Info->EventId)) {
        return;
    }

    if (Info->EventId == SysmonEventWmiFilter) {
        SYSMON_EVENT_WMI_FILTER_PAYLOAD *payload;

        SysmonInitializeEventBuffer(
            eventBuffer,
            sizeof(eventBuffer),
            SysmonEventWmiFilter,
            sizeof(*payload),
            &builder,
            Info->Timestamp);

        header = (PSYSMON_EVENT_HEADER)eventBuffer;
        if (header->EventSize == 0) {
            return;
        }

        payload = (SYSMON_EVENT_WMI_FILTER_PAYLOAD *)(eventBuffer + SYSMON_EVENT_HEADER_SIZE);
        ZeroMemory(payload, sizeof(*payload));

        if (!SysmonTryAddEventString(eventBuffer, sizeof(eventBuffer), &builder, &payload->RuleName, L"-") ||
            !SysmonTryAddEventString(eventBuffer, sizeof(eventBuffer), &builder, &payload->EventType, Info->EventType) ||
            !SysmonTryAddEventString(eventBuffer, sizeof(eventBuffer), &builder, &payload->UtcTime, Info->UtcTime) ||
            !SysmonTryAddEventString(eventBuffer, sizeof(eventBuffer), &builder, &payload->Operation, Info->Operation) ||
            !SysmonTryAddEventString(eventBuffer, sizeof(eventBuffer), &builder, &payload->User, Info->User) ||
            !SysmonTryAddEventString(eventBuffer, sizeof(eventBuffer), &builder, &payload->EventNamespace, Info->EventNamespace) ||
            !SysmonTryAddEventString(eventBuffer, sizeof(eventBuffer), &builder, &payload->Name, Info->Name) ||
            !SysmonTryAddEventString(eventBuffer, sizeof(eventBuffer), &builder, &payload->Query, Info->Query)) {
            return;
        }
    } else if (Info->EventId == SysmonEventWmiConsumer) {
        SYSMON_EVENT_WMI_CONSUMER_PAYLOAD *payload;

        SysmonInitializeEventBuffer(
            eventBuffer,
            sizeof(eventBuffer),
            SysmonEventWmiConsumer,
            sizeof(*payload),
            &builder,
            Info->Timestamp);

        header = (PSYSMON_EVENT_HEADER)eventBuffer;
        if (header->EventSize == 0) {
            return;
        }

        payload = (SYSMON_EVENT_WMI_CONSUMER_PAYLOAD *)(eventBuffer + SYSMON_EVENT_HEADER_SIZE);
        ZeroMemory(payload, sizeof(*payload));

        if (!SysmonTryAddEventString(eventBuffer, sizeof(eventBuffer), &builder, &payload->RuleName, L"-") ||
            !SysmonTryAddEventString(eventBuffer, sizeof(eventBuffer), &builder, &payload->EventType, Info->EventType) ||
            !SysmonTryAddEventString(eventBuffer, sizeof(eventBuffer), &builder, &payload->UtcTime, Info->UtcTime) ||
            !SysmonTryAddEventString(eventBuffer, sizeof(eventBuffer), &builder, &payload->Operation, Info->Operation) ||
            !SysmonTryAddEventString(eventBuffer, sizeof(eventBuffer), &builder, &payload->User, Info->User) ||
            !SysmonTryAddEventString(eventBuffer, sizeof(eventBuffer), &builder, &payload->Name, Info->Name) ||
            !SysmonTryAddEventString(eventBuffer, sizeof(eventBuffer), &builder, &payload->Type, Info->Type) ||
            !SysmonTryAddEventString(eventBuffer, sizeof(eventBuffer), &builder, &payload->Destination, Info->Destination)) {
            return;
        }
    } else if (Info->EventId == SysmonEventWmiConsumerToFilter) {
        SYSMON_EVENT_WMI_CONSUMER_TO_FILTER_PAYLOAD *payload;

        SysmonInitializeEventBuffer(
            eventBuffer,
            sizeof(eventBuffer),
            SysmonEventWmiConsumerToFilter,
            sizeof(*payload),
            &builder,
            Info->Timestamp);

        header = (PSYSMON_EVENT_HEADER)eventBuffer;
        if (header->EventSize == 0) {
            return;
        }

        payload = (SYSMON_EVENT_WMI_CONSUMER_TO_FILTER_PAYLOAD *)(eventBuffer + SYSMON_EVENT_HEADER_SIZE);
        ZeroMemory(payload, sizeof(*payload));

        if (!SysmonTryAddEventString(eventBuffer, sizeof(eventBuffer), &builder, &payload->RuleName, L"-") ||
            !SysmonTryAddEventString(eventBuffer, sizeof(eventBuffer), &builder, &payload->EventType, Info->EventType) ||
            !SysmonTryAddEventString(eventBuffer, sizeof(eventBuffer), &builder, &payload->UtcTime, Info->UtcTime) ||
            !SysmonTryAddEventString(eventBuffer, sizeof(eventBuffer), &builder, &payload->Operation, Info->Operation) ||
            !SysmonTryAddEventString(eventBuffer, sizeof(eventBuffer), &builder, &payload->User, Info->User) ||
            !SysmonTryAddEventString(eventBuffer, sizeof(eventBuffer), &builder, &payload->Consumer, Info->Consumer) ||
            !SysmonTryAddEventString(eventBuffer, sizeof(eventBuffer), &builder, &payload->Filter, Info->Filter)) {
            return;
        }
    } else {
        return;
    }

    if (Context->RuleRuntime == NULL ||
        SysmonShouldCaptureEvent(
            Context->RuleRuntime,
            Info->EventId,
            eventBuffer,
            ((PSYSMON_EVENT_HEADER)eventBuffer)->EventSize)) {
        SysmonPipelineDispatch(eventBuffer, ((PSYSMON_EVENT_HEADER)eventBuffer)->EventSize);
    }
}

static DWORD WINAPI
SysmonWmiTraceThread(
    _In_ LPVOID Parameter)
{
    PSYSMON_WMI_TRACE_CONTEXT context = (PSYSMON_WMI_TRACE_CONTEXT)Parameter;

    while (context != NULL && InterlockedCompareExchange(&context->StopRequested, 0, 0) == 0) {
        IWbemLocator *locator = NULL;
        IWbemServices *services = NULL;
        IEnumWbemClassObject *enumerator = NULL;
        BSTR namespaceName = NULL;
        BSTR queryLanguage = NULL;
        BSTR queryText = NULL;
        HRESULT hr;
        BOOL comInitialized = FALSE;

        hr = CoInitializeEx(NULL, COINIT_MULTITHREADED);
        if (FAILED(hr) && hr != RPC_E_CHANGED_MODE) {
            Sleep(1000);
            continue;
        }
        comInitialized = SUCCEEDED(hr);

        hr = CoInitializeSecurity(
            NULL,
            -1,
            NULL,
            NULL,
            RPC_C_AUTHN_LEVEL_DEFAULT,
            RPC_C_IMP_LEVEL_IMPERSONATE,
            NULL,
            EOAC_NONE,
            NULL);
        if (FAILED(hr) && hr != RPC_E_TOO_LATE) {
            if (comInitialized) {
                CoUninitialize();
            }
            Sleep(1000);
            continue;
        }

        hr = CoCreateInstance(
            CLSID_WbemLocator,
            NULL,
            CLSCTX_INPROC_SERVER,
            IID_IWbemLocator,
            reinterpret_cast<LPVOID *>(&locator));
        if (FAILED(hr) || locator == NULL) {
            if (comInitialized) {
                CoUninitialize();
            }
            Sleep(1000);
            continue;
        }

        namespaceName = SysAllocString(SYSMON_WMI_NAMESPACE);
        queryLanguage = SysAllocString(SYSMON_WMI_QUERY_LANGUAGE);
        queryText = SysAllocString(SYSMON_WMI_QUERY_TEXT);
        if (namespaceName == NULL || queryLanguage == NULL || queryText == NULL) {
            goto reconnect;
        }

        hr = locator->ConnectServer(
            namespaceName,
            NULL,
            NULL,
            0,
            0,
            NULL,
            NULL,
            &services);
        if (FAILED(hr) || services == NULL) {
            goto reconnect;
        }

        hr = CoSetProxyBlanket(
            (IUnknown *)services,
            RPC_C_AUTHN_WINNT,
            RPC_C_AUTHZ_NONE,
            NULL,
            RPC_C_AUTHN_LEVEL_CALL,
            RPC_C_IMP_LEVEL_IMPERSONATE,
            NULL,
            EOAC_NONE);
        if (FAILED(hr)) {
            goto reconnect;
        }

        hr = services->ExecNotificationQuery(
            queryLanguage,
            queryText,
            WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY,
            NULL,
            &enumerator);
        if (FAILED(hr) || enumerator == NULL) {
            goto reconnect;
        }

        while (InterlockedCompareExchange(&context->StopRequested, 0, 0) == 0) {
            IWbemClassObject *eventObject = NULL;
            ULONG returned = 0;
            SYSMON_WMI_EVENT_INFO info;

            hr = enumerator->Next(1000, 1, &eventObject, &returned);
            if (hr == WBEM_S_TIMEDOUT || returned == 0) {
                continue;
            }

            if (FAILED(hr)) {
                break;
            }

            if (SysmonParseWmiEventObject(eventObject, &info)) {
                SysmonDispatchWmiEvent(context, &info);
            }

            eventObject->Release();
        }

reconnect:
        if (enumerator != NULL) {
            enumerator->Release();
        }
        if (services != NULL) {
            services->Release();
        }
        if (locator != NULL) {
            locator->Release();
        }
        if (queryText != NULL) {
            SysFreeString(queryText);
        }
        if (queryLanguage != NULL) {
            SysFreeString(queryLanguage);
        }
        if (namespaceName != NULL) {
            SysFreeString(namespaceName);
        }

        if (comInitialized) {
            CoUninitialize();
        }

        if (InterlockedCompareExchange(&context->StopRequested, 0, 0) == 0) {
            Sleep(1000);
        }
    }

    return 0;
}

SYSMON_STATUS
SysmonWmiTraceStart(
    _Inout_ PSYSMON_SERVICE_CONTEXT ServiceContext,
    _Outptr_result_maybenull_ PSYSMON_WMI_TRACE_CONTEXT *Context)
{
    PSYSMON_WMI_TRACE_CONTEXT context;

    if (Context == NULL) {
        return SYSMON_ERROR_INVALID_PARAM;
    }

    *Context = NULL;

    if (ServiceContext == NULL) {
        return SYSMON_ERROR_INVALID_PARAM;
    }

    context = (PSYSMON_WMI_TRACE_CONTEXT)SYSMON_ALLOC(sizeof(*context));
    if (context == NULL) {
        return SYSMON_ERROR_OUT_OF_MEMORY;
    }

    ZeroMemory(context, sizeof(*context));
    context->ServiceContext = ServiceContext;
    context->ThreadHandle = CreateThread(NULL, 0, SysmonWmiTraceThread, context, 0, NULL);
    if (context->ThreadHandle == NULL) {
        SYSMON_FREE(context);
        return GetLastError();
    }

    *Context = context;
    return SYSMON_SUCCESS;
}

void
SysmonWmiTraceStop(
    _Inout_opt_ PSYSMON_WMI_TRACE_CONTEXT Context)
{
    DWORD waitResult;

    if (Context == NULL) {
        return;
    }

    InterlockedExchange(&Context->StopRequested, 1);

    if (Context->ThreadHandle != NULL) {
        waitResult = WaitForSingleObject(Context->ThreadHandle, 10000);
        if (waitResult == WAIT_TIMEOUT) {
            SysmonLogWarning(
                SYSMON_COMPONENT_SERVICE,
                "WMI trace thread did not stop within timeout; waiting for cooperative shutdown");
            waitResult = WaitForSingleObject(Context->ThreadHandle, INFINITE);
        }

        CloseHandle(Context->ThreadHandle);
        Context->ThreadHandle = NULL;
    }

    if (Context->RuleRuntime != NULL) {
        SysmonFreeRuleRuntime(Context->RuleRuntime);
        Context->RuleRuntime = NULL;
    }

    SYSMON_FREE(Context);
}

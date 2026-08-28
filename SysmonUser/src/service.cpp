/*
 * service.c - service_main, RegisterServiceCtrlHandlerExW, state transitions
 *
 * Original flow (from pseudo-code sub_140088xxx):
 *   1. RegisterServiceCtrlHandlerExW(svcName, handler, NULL)
 *   2. Report SERVICE_START_PENDING (3000ms wait hint)
 *   3. Enable SeDebugPrivilege
 *   4. Initialize rule engine
 *   5. Create stop event (data_1401b8dc0, manual-reset)
 *   6. Start worker threads:
 *      - ServiceThread (sub_14008a570) - event pull loop
 *      - ConfigMonitorThread (sub_14008a9f0) - registry monitoring
 *   7. Report SERVICE_RUNNING
 *   8. WaitForSingleObject(stopEvent, INFINITE)
 *   9. Cleanup: send 0x83400014, report SERVICE_STOPPED
 */

#include "../include/service.h"
#include "../include/protocol.h"
#include "../include/config.h"
#include "../include/event.h"
#include "../include/packed_read.hpp"
#include "../include/pipeline.h"
#include "../include/output.h"
#include "../include/process_store.h"
#include "../include/source_common.h"

#include "../include/runtime.hpp"

/* Global service context */
SYSMON_SERVICE_CONTEXT g_ServiceCtx;

#define SYSMON_QUERY_WORKER_COUNT 4

/* Forward declarations */
static DWORD WINAPI ServiceWorkerThread(LPVOID Param);
static DWORD WINAPI QueryWorkerThread(LPVOID Param);
static void ServiceReportStatus(DWORD State, DWORD ExitCode, DWORD WaitHint);
static BOOL WINAPI SysmonConsoleCtrlHandler(DWORD CtrlType);

static BOOL
SysmonRuleRuntimeHasAnyLoggableEvent(
    _In_opt_ PSYSMON_RULE_RUNTIME Runtime,
    _In_reads_(EventIdCount) const SYSMON_EVENT_ID *EventIds,
    _In_ DWORD EventIdCount)
{
    DWORD index;

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

UCHAR
SysmonComputeOptionalSourceMask(
    _In_opt_ const SYSMON_CONFIG *Config,
    _In_opt_ PSYSMON_RULE_RUNTIME RuleRuntime)
{
    static const SYSMON_EVENT_ID wmiEventIds[] = {
        SysmonEventWmiFilter,
        SysmonEventWmiConsumer,
        SysmonEventWmiConsumerToFilter
    };
    PSYSMON_RULE_RUNTIME fallbackRuntime;
    UCHAR optionalSourceMask = SysmonOptionalSourceNone;

    fallbackRuntime = NULL;
    if (RuleRuntime == NULL) {
        if (Config == NULL ||
            Config->Rules == NULL ||
            Config->RulesSize == 0 ||
            SysmonLoadRuleRuntime(
                Config->Rules,
                Config->RulesSize,
                &fallbackRuntime) != SYSMON_SUCCESS) {
            return SysmonOptionalSourceNone;
        }

        RuleRuntime = fallbackRuntime;
    }

    if (Config != NULL &&
        (Config->Options & SYSMON_OPTION_NETWORK_CONNECT) != 0 &&
        SysmonRuleRuntimeEventCanProduceLogs(RuleRuntime, SysmonEventNetworkConnect)) {
        optionalSourceMask |= SysmonOptionalSourceNetwork;
    }

    if (SysmonRuleRuntimeEventCanProduceLogs(RuleRuntime, SysmonEventDnsQuery)) {
        optionalSourceMask |= SysmonOptionalSourceDns;
    }

    if (SysmonRuleRuntimeHasAnyLoggableEvent(
            RuleRuntime,
            wmiEventIds,
            ARRAYSIZE(wmiEventIds))) {
        optionalSourceMask |= SysmonOptionalSourceWmi;
    }

    if (SysmonRuleRuntimeEventCanProduceLogs(RuleRuntime, SysmonEventClipboardChange)) {
        optionalSourceMask |= SysmonOptionalSourceClipboard;
    }

    SysmonFreeRuleRuntime(fallbackRuntime);
    return optionalSourceMask;
}

void
SysmonApplyOptionalSourceMask(
    _Inout_ PSYSMON_SERVICE_CONTEXT ServiceContext,
    _In_ UCHAR OptionalSourceMask)
{
    SYSMON_STATUS status;
    BOOL stopping;
    ULONGLONG nowTick;

    if (ServiceContext == NULL) {
        return;
    }

    EnterCriticalSection(&ServiceContext->OptionalSourceLock);
    stopping = (!ServiceContext->Running) ||
        (ServiceContext->StopEvent != NULL &&
            WaitForSingleObject(ServiceContext->StopEvent, 0) == WAIT_OBJECT_0);
    if (stopping) {
        OptionalSourceMask = SysmonOptionalSourceNone;
    }

    nowTick = (ULONGLONG)GetTickCount64();

    if ((OptionalSourceMask & SysmonOptionalSourceNetwork) != 0) {
        if (InterlockedExchange(&ServiceContext->NetworkTraceFaulted, 0) != 0 &&
            ServiceContext->NetworkTrace != NULL) {
            SysmonNetworkTraceStop(ServiceContext->NetworkTrace);
            ServiceContext->NetworkTrace = NULL;
        }
        if (ServiceContext->NetworkTrace == NULL &&
            (ServiceContext->NetworkTraceRetryAfterTick == 0 ||
             nowTick >= ServiceContext->NetworkTraceRetryAfterTick)) {
            status = SysmonNetworkTraceStart(ServiceContext, &ServiceContext->NetworkTrace);
            if (status != SYSMON_SUCCESS) {
                SysmonLogWarning(
                    SYSMON_COMPONENT_SERVICE,
                    "Network trace startup failed with status %lu",
                    (unsigned long)status);
                ServiceContext->NetworkTrace = NULL;
                ServiceContext->NetworkTraceRetryAfterTick = nowTick + 1000;
            } else {
                ServiceContext->NetworkTraceRetryAfterTick = 0;
            }
        }
    } else if (ServiceContext->NetworkTrace != NULL) {
        SysmonNetworkTraceStop(ServiceContext->NetworkTrace);
        ServiceContext->NetworkTrace = NULL;
        ServiceContext->NetworkTraceRetryAfterTick = 0;
    }

    if ((OptionalSourceMask & SysmonOptionalSourceDns) != 0) {
        if (InterlockedExchange(&ServiceContext->DnsTraceFaulted, 0) != 0 &&
            ServiceContext->DnsTrace != NULL) {
            SysmonDnsTraceStop(ServiceContext->DnsTrace);
            ServiceContext->DnsTrace = NULL;
        }
        if (ServiceContext->DnsTrace == NULL &&
            (ServiceContext->DnsTraceRetryAfterTick == 0 ||
             nowTick >= ServiceContext->DnsTraceRetryAfterTick)) {
            status = SysmonDnsTraceStart(ServiceContext, &ServiceContext->DnsTrace);
            if (status != SYSMON_SUCCESS) {
                SysmonLogWarning(
                    SYSMON_COMPONENT_SERVICE,
                    "DNS trace startup failed with status %lu",
                    (unsigned long)status);
                ServiceContext->DnsTrace = NULL;
                ServiceContext->DnsTraceRetryAfterTick = nowTick + 1000;
            } else {
                ServiceContext->DnsTraceRetryAfterTick = 0;
            }
        }
    } else if (ServiceContext->DnsTrace != NULL) {
        SysmonDnsTraceStop(ServiceContext->DnsTrace);
        ServiceContext->DnsTrace = NULL;
        ServiceContext->DnsTraceRetryAfterTick = 0;
    }

    if ((OptionalSourceMask & SysmonOptionalSourceWmi) != 0) {
        if (ServiceContext->WmiTrace == NULL) {
            status = SysmonWmiTraceStart(ServiceContext, &ServiceContext->WmiTrace);
            if (status != SYSMON_SUCCESS) {
                SysmonLogWarning(
                    SYSMON_COMPONENT_SERVICE,
                    "WMI trace startup failed with status %lu",
                    (unsigned long)status);
                ServiceContext->WmiTrace = NULL;
            }
        }
    } else if (ServiceContext->WmiTrace != NULL) {
        SysmonWmiTraceStop(ServiceContext->WmiTrace);
        ServiceContext->WmiTrace = NULL;
    }

    if ((OptionalSourceMask & SysmonOptionalSourceClipboard) != 0) {
        if (ServiceContext->ClipboardMonitor == NULL) {
            status = SysmonClipboardMonitorStart(
                ServiceContext,
                &ServiceContext->ClipboardMonitor);
            if (status != SYSMON_SUCCESS) {
                SysmonLogWarning(
                    SYSMON_COMPONENT_SERVICE,
                    "Clipboard monitor startup failed with status %lu",
                    (unsigned long)status);
                ServiceContext->ClipboardMonitor = NULL;
            }
        }
    } else if (ServiceContext->ClipboardMonitor != NULL) {
        SysmonClipboardMonitorStop(ServiceContext->ClipboardMonitor);
        ServiceContext->ClipboardMonitor = NULL;
    }

    LeaveCriticalSection(&ServiceContext->OptionalSourceLock);
}

void
SysmonServiceApplyReloadedConfig(
    _Inout_ PSYSMON_SERVICE_CONTEXT ServiceContext,
    _Inout_ PSYSMON_CONFIG NewConfig,
    _In_opt_ PSYSMON_RULE_RUNTIME NewRuleRuntime)
{
    SYSMON_CONFIG oldConfig;
    PSYSMON_RULE_RUNTIME oldRuntime;
    UCHAR desiredOptionalSources;

    if (ServiceContext == NULL || NewConfig == NULL) {
        return;
    }

    ZeroMemory(&oldConfig, sizeof(oldConfig));
    oldRuntime = NULL;

    EnterCriticalSection(&ServiceContext->ConfigLock);
    oldConfig = ServiceContext->Config;
    oldRuntime = ServiceContext->RuleRuntime;

    ServiceContext->Config = *NewConfig;
    ServiceContext->RuleRuntime = NewRuleRuntime;
    desiredOptionalSources = SysmonComputeOptionalSourceMask(
        &ServiceContext->Config,
        ServiceContext->RuleRuntime);

    /* Free the swapped-out objects while still holding ConfigLock: every reader
       of Config/RuleRuntime uses them under this lock, so freeing under the lock
       guarantees no reader can ever touch the freed pointers (U1 in the
       2026-08-04 review). */
    ZeroMemory(NewConfig, sizeof(*NewConfig));
    SysmonConfigFree(&oldConfig);
    SysmonFreeRuleRuntime(oldRuntime);

    LeaveCriticalSection(&ServiceContext->ConfigLock);

    if (!ServiceContext->Running ||
        (ServiceContext->StopEvent != NULL &&
            WaitForSingleObject(ServiceContext->StopEvent, 0) == WAIT_OBJECT_0)) {
        return;
    }

    SysmonApplyOptionalSourceMask(ServiceContext, desiredOptionalSources);
}

void
SysmonStopOptionalSources(
    _Inout_ PSYSMON_SERVICE_CONTEXT ServiceContext)
{
    if (ServiceContext == NULL) {
        return;
    }

    InterlockedExchange(&ServiceContext->NetworkTraceFaulted, 0);
    InterlockedExchange(&ServiceContext->DnsTraceFaulted, 0);
    ServiceContext->NetworkTraceRetryAfterTick = 0;
    ServiceContext->DnsTraceRetryAfterTick = 0;

    EnterCriticalSection(&ServiceContext->OptionalSourceLock);
    SysmonClipboardMonitorStop(ServiceContext->ClipboardMonitor);
    ServiceContext->ClipboardMonitor = NULL;
    SysmonWmiTraceStop(ServiceContext->WmiTrace);
    ServiceContext->WmiTrace = NULL;
    SysmonDnsTraceStop(ServiceContext->DnsTrace);
    ServiceContext->DnsTrace = NULL;
    SysmonNetworkTraceStop(ServiceContext->NetworkTrace);
    ServiceContext->NetworkTrace = NULL;
    LeaveCriticalSection(&ServiceContext->OptionalSourceLock);
}

void
SysmonRefreshOptionalSourceHealth(
    _Inout_ PSYSMON_SERVICE_CONTEXT ServiceContext)
{
    UCHAR desiredSources;

    if (ServiceContext == NULL || !ServiceContext->Running) {
        return;
    }

    EnterCriticalSection(&ServiceContext->ConfigLock);
    desiredSources = SysmonComputeOptionalSourceMask(
        &ServiceContext->Config,
        ServiceContext->RuleRuntime);
    LeaveCriticalSection(&ServiceContext->ConfigLock);
    SysmonApplyOptionalSourceMask(ServiceContext, desiredSources);
}

static DWORD
SysmonEvaluateFileDeleteQuery(
    _In_ const SYSMON_QUERY_RECORD *QueryRecord)
{
    BYTE eventBuffer[4096];
    SYSMON_EVENT_PAYLOAD_BUILDER builder;
    SYSMON_EVENT_FILE_DELETE_PAYLOAD *payload;
    PSYSMON_EVENT_HEADER header;
    WCHAR utcTime[64];
    DWORD resultCode;

    if (QueryRecord == NULL) {
        return 0;
    }

    ZeroMemory(eventBuffer, sizeof(eventBuffer));
    ZeroMemory(&builder, sizeof(builder));
    ZeroMemory(utcTime, sizeof(utcTime));

    SysmonInitializeEventBuffer(
        eventBuffer,
        sizeof(eventBuffer),
        SysmonEventFileDelete,
        sizeof(*payload),
        &builder,
        (ULONGLONG)QueryRecord->Timestamp);

    payload = (SYSMON_EVENT_FILE_DELETE_PAYLOAD *)(eventBuffer + SYSMON_EVENT_HEADER_SIZE);
    SysmonWritePackedValue<DWORD>(&payload->ProcessId, QueryRecord->ProcessId);
    payload->IsExecutable = (QueryRecord->Flags & SYSMON_QUERY_FLAG_IS_EXECUTABLE) != 0;
    payload->Archived = FALSE;

    if (!SysmonFormatSyntheticUtcTimestamp(
            (ULONGLONG)QueryRecord->Timestamp,
            utcTime,
            _countof(utcTime),
            NULL)) {
        utcTime[0] = L'\0';
    }

    (void)SysmonAddStringField(eventBuffer, sizeof(eventBuffer), &builder, &payload->RuleName, NULL);
    (void)SysmonAddStringField(eventBuffer, sizeof(eventBuffer), &builder, &payload->UtcTime, utcTime);
    (void)SysmonAddStringField(eventBuffer, sizeof(eventBuffer), &builder, &payload->ProcessGuid, QueryRecord->ProcessGuid);
    (void)SysmonAddStringField(eventBuffer, sizeof(eventBuffer), &builder, &payload->User, QueryRecord->User);
    (void)SysmonAddStringField(eventBuffer, sizeof(eventBuffer), &builder, &payload->Image, QueryRecord->Image);
    (void)SysmonAddStringField(eventBuffer, sizeof(eventBuffer), &builder, &payload->TargetFilename, QueryRecord->TargetFilename);
    (void)SysmonAddStringField(eventBuffer, sizeof(eventBuffer), &builder, &payload->Hashes, QueryRecord->Hashes);

    header = (PSYSMON_EVENT_HEADER)eventBuffer;

    {
        CriticalSectionGuard configLock(&g_ServiceCtx.ConfigLock);
        resultCode = SysmonShouldCaptureEvent(
            g_ServiceCtx.RuleRuntime,
            SysmonEventFileDelete,
            eventBuffer,
            header->EventSize) ? 1u : 0u;
    }

    return resultCode;
}

static void
SysmonAnswerQueryRecord(
    _In_ const SYSMON_QUERY_RECORD *QueryRecord)
{
    SYSMON_QUERY_ANSWER answer;
    DWORD resultCode = 0;
    SYSMON_STATUS status;

    if (QueryRecord == NULL) {
        return;
    }

    ZeroMemory(&answer, sizeof(answer));
    answer.RequestId = QueryRecord->RequestId;

    switch (QueryRecord->QueryType) {
    case SYSMON_QUERY_TYPE_FILE_DELETE:
        resultCode = SysmonEvaluateFileDeleteQuery(QueryRecord);
        break;

    default:
        SysmonLogWarning(
            SYSMON_COMPONENT_DRIVER_COMM,
            "Unknown query event type %lu",
            (unsigned long)QueryRecord->QueryType);
        resultCode = 0;
        break;
    }

    answer.ResultCode = resultCode;
    answer.HasExtendedBlob = 0;

    status = SysmonSendQueryAnswer(&g_ServiceCtx.Transport, &answer);
    if (status != SYSMON_SUCCESS) {
        SysmonLogWarning(
            SYSMON_COMPONENT_DRIVER_COMM,
            "Failed to send query answer for request %lu: %lu",
            (unsigned long)QueryRecord->RequestId,
            (unsigned long)status);
    }
}

static DWORD WINAPI
QueryWorkerThread(LPVOID Param)
{
    OVERLAPPED overlapped;
    HANDLE waitHandles[2];
    ScopedHandle queryEvent;
    PUCHAR queryBuffer = NULL;

    UNREFERENCED_PARAMETER(Param);

    queryEvent.reset(CreateEventW(NULL, FALSE, FALSE, NULL));
    if (!queryEvent.valid()) {
        SysmonLogWarning(
            SYSMON_COMPONENT_DRIVER_COMM,
            "Failed to create query worker event: %lu",
            (unsigned long)GetLastError());
        return 0;
    }

    queryBuffer = (PUCHAR)SYSMON_ALLOC(SYSMON_EVENT_BUFFER_SIZE);
    if (queryBuffer == NULL) {
        SysmonLogWarning(SYSMON_COMPONENT_DRIVER_COMM, "Failed to allocate query buffer");
        return 0;
    }

    waitHandles[0] = queryEvent.get();
    waitHandles[1] = g_ServiceCtx.StopEvent;

    while (g_ServiceCtx.Running) {
        DWORD bytesReturned = 0;
        BOOL success;

        ZeroMemory(&overlapped, sizeof(overlapped));
        overlapped.hEvent = queryEvent.get();

        success = DeviceIoControl(
            g_ServiceCtx.Transport.DeviceHandle,
            SYSMON_IOCTL_GET_QUERY,
            NULL,
            0,
            queryBuffer,
            SYSMON_EVENT_BUFFER_SIZE,
            &bytesReturned,
            &overlapped);

        if (!success) {
            DWORD err = GetLastError();

            if (err == ERROR_IO_PENDING) {
                DWORD waitResult = WaitForMultipleObjects(2, waitHandles, FALSE, INFINITE);
                if (waitResult == WAIT_OBJECT_0 + 1) {
                    CancelIo(g_ServiceCtx.Transport.DeviceHandle);
                    break;
                }

                if (!GetOverlappedResult(
                        g_ServiceCtx.Transport.DeviceHandle,
                        &overlapped,
                        &bytesReturned,
                        FALSE)) {
                    err = GetLastError();
                } else {
                    err = ERROR_SUCCESS;
                }
            }

            if (err == ERROR_SUCCESS) {
                /* handled below */
            } else if (err == ERROR_INVALID_HANDLE ||
                       err == ERROR_ACCESS_DENIED ||
                       err == ERROR_OPERATION_ABORTED) {
                break;
            } else {
                Sleep(250);
                continue;
            }
        }

        if (bytesReturned < sizeof(SYSMON_QUERY_RECORD)) {
            SysmonLogWarning(
                SYSMON_COMPONENT_DRIVER_COMM,
                "Incorrect query event size %lu",
                (unsigned long)bytesReturned);
            continue;
        }

        SysmonAnswerQueryRecord((const SYSMON_QUERY_RECORD *)queryBuffer);
    }

    SYSMON_FREE(queryBuffer);
    return 0;
}

/*
 * SysmonServiceCtrlHandler - SCM control handler
 *
 * Original: handles STOP (1) and SHUTDOWN
 *   - Sets stop event (data_1401b8dc0)
 *   - Reports SERVICE_STOP_PENDING
 */
DWORD WINAPI SysmonServiceCtrlHandler(
    DWORD dwControl,
    DWORD dwEventType,
    LPVOID lpEventData,
    LPVOID lpContext)
{
    UNREFERENCED_PARAMETER(dwEventType);
    UNREFERENCED_PARAMETER(lpEventData);
    UNREFERENCED_PARAMETER(lpContext);

    switch (dwControl) {
    case SERVICE_CONTROL_STOP:
    case SERVICE_CONTROL_SHUTDOWN:
        /* Report stop pending */
        ServiceReportStatus(SERVICE_STOP_PENDING, NO_ERROR, 3000);

        /* Signal all threads to stop */
        g_ServiceCtx.Running = FALSE;
        SetEvent(g_ServiceCtx.StopEvent);
        return NO_ERROR;

    default:
        break;
    }
    return ERROR_CALL_NOT_IMPLEMENTED;
}

static BOOL WINAPI
SysmonConsoleCtrlHandler(DWORD CtrlType)
{
    switch (CtrlType) {
    case CTRL_C_EVENT:
    case CTRL_BREAK_EVENT:
    case CTRL_CLOSE_EVENT:
    case CTRL_LOGOFF_EVENT:
    case CTRL_SHUTDOWN_EVENT:
        g_ServiceCtx.Running = FALSE;
        if (g_ServiceCtx.StopEvent != NULL) {
            SetEvent(g_ServiceCtx.StopEvent);
        }
        return TRUE;

    default:
        return FALSE;
    }
}

/*
 * ServiceReportStatus - Report service status to SCM
 */
static void ServiceReportStatus(DWORD State, DWORD ExitCode, DWORD WaitHint)
{
    static LONG checkPoint = 0;

    g_ServiceCtx.ServiceStatus.dwCurrentState = State;
    g_ServiceCtx.ServiceStatus.dwWin32ExitCode = ExitCode;
    g_ServiceCtx.ServiceStatus.dwWaitHint = WaitHint;

    if (State == SERVICE_START_PENDING || State == SERVICE_STOP_PENDING) {
        g_ServiceCtx.ServiceStatus.dwControlsAccepted = 0;
    } else {
        g_ServiceCtx.ServiceStatus.dwControlsAccepted =
            SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN;
    }

    if (State == SERVICE_RUNNING || State == SERVICE_STOPPED) {
        g_ServiceCtx.ServiceStatus.dwCheckPoint = 0;
        InterlockedExchange(&checkPoint, 0);
    } else {
        g_ServiceCtx.ServiceStatus.dwCheckPoint = (DWORD)InterlockedIncrement(&checkPoint);
    }

    SetServiceStatus(g_ServiceCtx.StatusHandle, &g_ServiceCtx.ServiceStatus);
}

/*
 * ServiceWorkerThread - Main service work
 *
 * Original (sub_14008a570):
 *   1. Allocate 0x40000 event buffer
 *   2. Initialize critical sections
 *   3. Create driver event for overlapped
 *   4. Initialize rule engine, signature verification
 *   5. Refresh process cache (EnumProcesses)
 *   6. Connect to driver (sub_140089a70)
 *   7. Start stats thread (sub_14008a210)
 *   8. Event loop: DeviceIoControl(0x04) + WaitForMultipleObjects
 *   9. Validate event size >= 0x358, dispatch
 *   10. Reconnect on ERROR_INVALID_HANDLE (10 retries, 500ms)
 */
static DWORD WINAPI ServiceWorkerThread(LPVOID Param)
{
    SYSMON_STATUS status;
    PUCHAR eventBuffer = NULL;
    UCHAR desiredOptionalSources = SysmonOptionalSourceNone;
    DWORD bytesReturned;
    DWORD minimumEventSize;
    PSYSMON_EVENT_HEADER header;
    BOOL reportedRunning = FALSE;
    BOOL emittedStarted = FALSE;
    BOOL transportInitialized = FALSE;
    HANDLE queryThreads[SYSMON_QUERY_WORKER_COUNT];
    DWORD queryWorkerIndex;

    UNREFERENCED_PARAMETER(Param);

    ZeroMemory(queryThreads, sizeof(queryThreads));

    /* Load configuration */
    status = SysmonConfigLoad(&g_ServiceCtx.Config, SYSMON_SERVICE_NAME);
    if (status != SYSMON_SUCCESS) {
        SysmonLogError(SYSMON_COMPONENT_SERVICE, status, "Failed to load configuration");
    } else if (g_ServiceCtx.Config.Rules != NULL && g_ServiceCtx.Config.RulesSize != 0) {
        status = SysmonLoadRuleRuntime(
            g_ServiceCtx.Config.Rules,
            g_ServiceCtx.Config.RulesSize,
            &g_ServiceCtx.RuleRuntime);
        if (status != SYSMON_SUCCESS) {
            SysmonLogError(
                SYSMON_COMPONENT_SERVICE,
                status,
                "Failed to initialize user-mode rule runtime");
            g_ServiceCtx.Running = FALSE;
            SysmonConfigFree(&g_ServiceCtx.Config);
            if (g_ServiceCtx.StopEvent != NULL) {
                SetEvent(g_ServiceCtx.StopEvent);
            }
            if (!g_ServiceCtx.DebugMode) {
                ServiceReportStatus(SERVICE_STOPPED, status, 0);
            }
            return status;
        }
    }

    /* Initialize transport */
    status = SysmonTransportInit(&g_ServiceCtx.Transport, g_ServiceCtx.StopEvent);
    if (status != SYSMON_SUCCESS) {
        SysmonReportError(SYSMON_COMPONENT_SERVICE, status, "Failed to initialize transport");
        g_ServiceCtx.Running = FALSE;
        SetEvent(g_ServiceCtx.StopEvent);
        goto cleanup;
    }
    transportInitialized = TRUE;

    /* Connect to driver */
    status = SysmonTransportConnect(&g_ServiceCtx.Transport);
    if (status != SYSMON_SUCCESS) {
        SysmonLogError(SYSMON_COMPONENT_SERVICE, status,
            "Failed to connect to driver during service startup");
        SetEvent(g_ServiceCtx.StopEvent);
        goto cleanup;
    }

    /* Send initial config notify */
    if (g_ServiceCtx.Transport.Connected) {
        SysmonSendConfigNotify(&g_ServiceCtx.Transport);
    }

    for (queryWorkerIndex = 0;
         queryWorkerIndex < SYSMON_QUERY_WORKER_COUNT;
         queryWorkerIndex++) {
        queryThreads[queryWorkerIndex] = CreateThread(
            NULL,
            0,
            QueryWorkerThread,
            NULL,
            0,
            NULL);
        if (queryThreads[queryWorkerIndex] == NULL) {
            SysmonLogWarning(
                SYSMON_COMPONENT_SERVICE,
                "Failed to start query worker thread %lu: %lu",
                (unsigned long)queryWorkerIndex,
                (unsigned long)GetLastError());
            break;
        }
    }

    /* Initialize pipeline */
    status = SysmonPipelineInit();
    if (status != SYSMON_SUCCESS) {
        SysmonLogError(SYSMON_COMPONENT_SERVICE, status, "Failed to initialize pipeline");
        g_ServiceCtx.Running = FALSE;
        SetEvent(g_ServiceCtx.StopEvent);
        goto cleanup;
    }

    /* Initialize output */
    {
        DWORD channels = SYSMON_OUTPUT_ETW;
        if (g_ServiceCtx.DebugMode) {
            channels |= SYSMON_OUTPUT_CONSOLE;
        }
        {
            CriticalSectionGuard configLock(&g_ServiceCtx.ConfigLock);
            if (g_ServiceCtx.Config.ArchiveDirectory) {
                channels |= SYSMON_OUTPUT_FILE;
            }
            SysmonOutputInit(channels, g_ServiceCtx.Config.ArchiveDirectory);
        }
    }

    {
        CriticalSectionGuard configLock(&g_ServiceCtx.ConfigLock);
        desiredOptionalSources = SysmonComputeOptionalSourceMask(
            &g_ServiceCtx.Config,
            g_ServiceCtx.RuleRuntime);
    }
    SysmonApplyOptionalSourceMask(&g_ServiceCtx, desiredOptionalSources);

    /* Allocate event buffer (0x40000 = 256KB, matching original) */
    eventBuffer = (PUCHAR)SYSMON_ALLOC(SYSMON_EVENT_BUFFER_SIZE);
    if (eventBuffer == NULL) {
        SysmonReportError(SYSMON_COMPONENT_SERVICE, ERROR_NOT_ENOUGH_MEMORY,
            "Failed to allocate %x bytes", SYSMON_EVENT_BUFFER_SIZE);
        status = ERROR_NOT_ENOUGH_MEMORY;
        g_ServiceCtx.Running = FALSE;
        SetEvent(g_ServiceCtx.StopEvent);
        goto cleanup;
    }

    /* Report running */
    if (!g_ServiceCtx.DebugMode) {
        SysmonTryFlushPendingConfigChangeEvent(SYSMON_SERVICE_NAME);
        status = SysmonEmitServiceStateEvent(L"Started");
        if (status != SYSMON_SUCCESS) {
            SysmonLogWarning(
                SYSMON_COMPONENT_SERVICE,
                "Failed to emit service started event: %lu",
                (unsigned long)status);
        } else {
            emittedStarted = TRUE;
        }

        ServiceReportStatus(SERVICE_RUNNING, NO_ERROR, 0);
        reportedRunning = TRUE;
    }
    SysmonLogInfo(SYSMON_COMPONENT_SERVICE, "Service started, reading events...");

    /* Main event loop */
    while (g_ServiceCtx.Running) {
        /* A source can fault while the driver is continuously producing
           events, so do not rely solely on the one-second pending-IO health
           tick below to notice and rebuild it. */
        SysmonRefreshOptionalSourceHealth(&g_ServiceCtx);
        status = SysmonRecvEvent(
            &g_ServiceCtx.Transport,
            eventBuffer,
            SYSMON_EVENT_BUFFER_SIZE,
            &bytesReturned);

        if (status == ERROR_TIMEOUT) {
            /* Stop event signaled */
            break;
        }

        if (status == ERROR_RETRY) {
            SysmonRefreshOptionalSourceHealth(&g_ServiceCtx);
            continue;
        }

        if (status != SYSMON_SUCCESS) {
            SysmonLogError(SYSMON_COMPONENT_DRIVER_COMM, status,
                "Failed to retrieve events");
            if (status == ERROR_CONNECTION_UNAVAIL ||
                status == ERROR_INVALID_HANDLE ||
                status == ERROR_ACCESS_DENIED) {
                SetEvent(g_ServiceCtx.StopEvent);
                break;
            }
            continue;
        }

        if (bytesReturned < SYSMON_EVENT_HEADER_SIZE) {
            SysmonLogWarning(SYSMON_COMPONENT_DRIVER_COMM,
                "Incorrect event size %u (minimum header %u)",
                bytesReturned, SYSMON_EVENT_HEADER_SIZE);
            continue;
        }

        header = (PSYSMON_EVENT_HEADER)eventBuffer;
        minimumEventSize = SysmonGetEventMinSize((SYSMON_EVENT_ID)header->EventId);
        if (bytesReturned < minimumEventSize) {
            SysmonLogWarning(SYSMON_COMPONENT_DRIVER_COMM,
                "Incorrect event size %u for event %u (minimum %u)",
                bytesReturned,
                header->EventId,
                minimumEventSize);
            continue;
        }

        if (header->EventSize > bytesReturned) {
            SysmonLogWarning(
                SYSMON_COMPONENT_DRIVER_COMM,
                "Driver event %u declared size %u but returned %u bytes",
                header->EventId,
                header->EventSize,
                bytesReturned);
        }

        /* Dispatch event through pipeline */
        SysmonPipelineDispatch(eventBuffer, bytesReturned);
    }

cleanup:
    /* Cleanup */
    for (queryWorkerIndex = 0;
         queryWorkerIndex < SYSMON_QUERY_WORKER_COUNT;
         queryWorkerIndex++) {
        if (queryThreads[queryWorkerIndex] != NULL) {
            WaitForSingleObject(queryThreads[queryWorkerIndex], INFINITE);
            CloseHandle(queryThreads[queryWorkerIndex]);
            queryThreads[queryWorkerIndex] = NULL;
        }
    }
    SYSMON_FREE(eventBuffer);
    SysmonStopOptionalSources(&g_ServiceCtx);
    if (!g_ServiceCtx.DebugMode && emittedStarted) {
        status = SysmonEmitServiceStateEventTransient(L"Stopped");
        if (status != SYSMON_SUCCESS) {
            SysmonLogWarning(
                SYSMON_COMPONENT_SERVICE,
                "Failed to emit service stopped event: %lu",
                (unsigned long)status);
        }
    }
    SysmonPipelineCleanup();
    SysmonOutputCleanup();
    if (transportInitialized) {
        SysmonTransportDisconnect(&g_ServiceCtx.Transport);
        SysmonTransportCleanup(&g_ServiceCtx.Transport);
    }
    SysmonProcessStoreCleanup();
    SysmonFreeRuleRuntime(g_ServiceCtx.RuleRuntime);
    g_ServiceCtx.RuleRuntime = NULL;
    SysmonConfigFree(&g_ServiceCtx.Config);
    if (g_ServiceCtx.StopEvent != NULL) {
        SetEvent(g_ServiceCtx.StopEvent);
    }

    if (!g_ServiceCtx.DebugMode) {
        ServiceReportStatus(SERVICE_STOPPED, reportedRunning ? NO_ERROR : status, 0);
    }
    SysmonLogInfo(SYSMON_COMPONENT_SERVICE, "Service stopped");

    return status;
}

/*
 * SysmonServiceMain - SCM entry point
 *
 * Original (sub_140088xxx service_main):
 *   1. RegisterServiceCtrlHandlerExW
 *   2. Report START_PENDING (3000ms hint)
 *   3. Enable SeDebugPrivilege
 *   4. Initialize rule engine
 *   5. Set thread priority
 *   6. Create stop event (manual-reset)
 *   7. Start ServiceThread + ConfigMonitorThread
 *   8. Report RUNNING
 *   9. WaitForSingleObject(stopEvent)
 */
void WINAPI SysmonServiceMain(DWORD Argc, LPWSTR *Argv)
{
    HANDLE hWorkerThread = NULL;
    HANDLE hConfigThread = NULL;
    DWORD threadId;
    DWORD waitResult;
    BOOL allThreadsExited = TRUE;

    UNREFERENCED_PARAMETER(Argc);
    UNREFERENCED_PARAMETER(Argv);

    /* Initialize context */
    ZeroMemory(&g_ServiceCtx, sizeof(g_ServiceCtx));
    g_ServiceCtx.DebugMode = FALSE;
    g_ServiceCtx.Running = TRUE;
    InitializeCriticalSection(&g_ServiceCtx.ConfigLock);
    InitializeCriticalSection(&g_ServiceCtx.OptionalSourceLock);

    /* Register service control handler */
    g_ServiceCtx.StatusHandle = RegisterServiceCtrlHandlerExW(
        SYSMON_SERVICE_NAME,
        SysmonServiceCtrlHandler,
        NULL);

    if (g_ServiceCtx.StatusHandle == 0) {
        SysmonReportError(SYSMON_COMPONENT_SERVICE, GetLastError(),
            "RegisterServiceCtrlHandlerExW failed");
        return;
    }

    /* Initialize service status */
    g_ServiceCtx.ServiceStatus.dwServiceType = SERVICE_WIN32_OWN_PROCESS;
    g_ServiceCtx.ServiceStatus.dwCurrentState = SERVICE_START_PENDING;
    g_ServiceCtx.ServiceStatus.dwControlsAccepted = 0;
    g_ServiceCtx.ServiceStatus.dwWin32ExitCode = NO_ERROR;
    g_ServiceCtx.ServiceStatus.dwServiceSpecificExitCode = 0;
    g_ServiceCtx.ServiceStatus.dwCheckPoint = 0;
    g_ServiceCtx.ServiceStatus.dwWaitHint = 3000;

    /* Report start pending */
    ServiceReportStatus(SERVICE_START_PENDING, NO_ERROR, 3000);

    /* Enable SeDebugPrivilege */
    SysmonEnableDebugPrivilege();

    /* Set thread priority (original: THREAD_PRIORITY_NORMAL - 1 = -1) */
    SetThreadPriority(GetCurrentThread(), THREAD_PRIORITY_NORMAL - 1);

    /* Create stop event (manual-reset, initially non-signaled) */
    g_ServiceCtx.StopEvent = CreateEventW(NULL, TRUE, FALSE, NULL);
    if (g_ServiceCtx.StopEvent == NULL) {
        SysmonReportError(SYSMON_COMPONENT_SERVICE, GetLastError(),
            "Failed to create stop event");
        ServiceReportStatus(SERVICE_STOPPED, GetLastError(), 0);
        return;
    }

    /* Start worker thread */
    hWorkerThread = CreateThread(NULL, 0, ServiceWorkerThread, NULL, 0, &threadId);
    if (hWorkerThread == NULL) {
        SysmonReportError(SYSMON_COMPONENT_SERVICE, GetLastError(),
            "Failed to create worker thread");
        ServiceReportStatus(SERVICE_STOPPED, GetLastError(), 0);
        CloseHandle(g_ServiceCtx.StopEvent);
        return;
    }

    /* Start config monitor thread */
    hConfigThread = CreateThread(NULL, 0, SysmonConfigMonitorThread, NULL, 0, &threadId);
    if (hConfigThread == NULL) {
        SysmonLogWarning(SYSMON_COMPONENT_SERVICE,
            "Failed to create config monitor thread");
    }

    /* Wait for stop signal */
    WaitForSingleObject(g_ServiceCtx.StopEvent, INFINITE);

    /* Signal running flag */
    g_ServiceCtx.Running = FALSE;

    /* Wait for threads to exit */
    if (hWorkerThread != NULL) {
        waitResult = WaitForSingleObject(hWorkerThread, INFINITE);
        if (waitResult == WAIT_OBJECT_0) {
            CloseHandle(hWorkerThread);
            hWorkerThread = NULL;
        } else {
            DWORD waitError = GetLastError();
            allThreadsExited = FALSE;
            SysmonLogError(
                SYSMON_COMPONENT_SERVICE,
                waitError,
                "Failed to confirm service worker exit");
        }
    }
    if (hConfigThread != NULL) {
        waitResult = WaitForSingleObject(hConfigThread, INFINITE);
        if (waitResult == WAIT_OBJECT_0) {
            CloseHandle(hConfigThread);
            hConfigThread = NULL;
        } else {
            DWORD waitError = GetLastError();
            allThreadsExited = FALSE;
            SysmonLogError(
                SYSMON_COMPONENT_SERVICE,
                waitError,
                "Failed to confirm config monitor exit");
        }
    }

    /* Cleanup */
    if (!allThreadsExited) {
        return;
    }
    CloseHandle(g_ServiceCtx.StopEvent);
    DeleteCriticalSection(&g_ServiceCtx.OptionalSourceLock);
    DeleteCriticalSection(&g_ServiceCtx.ConfigLock);
}

/*
 * SysmonServiceRunDirect - Foreground debug mode (-d)
 *
 * Runs the same logic as the service, but without SCM registration.
 * Output goes to console directly.
 */
SYSMON_STATUS SysmonServiceRunDirect(void)
{
    HANDLE hWorkerThread = NULL;
    HANDLE hConfigThread = NULL;
    DWORD threadId;
    SYSMON_STATUS status;
    BOOL consoleHandlerRegistered = FALSE;
    DWORD waitResult;
    BOOL allThreadsExited = TRUE;

    /* Initialize context */
    ZeroMemory(&g_ServiceCtx, sizeof(g_ServiceCtx));
    g_ServiceCtx.DebugMode = TRUE;
    g_ServiceCtx.Running = TRUE;
    InitializeCriticalSection(&g_ServiceCtx.ConfigLock);
    InitializeCriticalSection(&g_ServiceCtx.OptionalSourceLock);

    SysmonLogInfo(SYSMON_COMPONENT_SERVICE, "Running in debug mode");

    /* Enable SeDebugPrivilege */
    SysmonEnableDebugPrivilege();

    /* Create stop event */
    g_ServiceCtx.StopEvent = CreateEventW(NULL, TRUE, FALSE, NULL);
    if (g_ServiceCtx.StopEvent == NULL) {
        return GetLastError();
    }

    /* Set console control handler for Ctrl+C */
    if (SetConsoleCtrlHandler(SysmonConsoleCtrlHandler, TRUE)) {
        consoleHandlerRegistered = TRUE;
    } else {
        SysmonLogWarning(
            SYSMON_COMPONENT_SERVICE,
            "Failed to register Ctrl+C handler: %lu",
            (unsigned long)GetLastError());
    }

    /* Start worker thread */
    hWorkerThread = CreateThread(NULL, 0, ServiceWorkerThread, NULL, 0, &threadId);
    if (hWorkerThread == NULL) {
        status = GetLastError();
        if (consoleHandlerRegistered) {
            SetConsoleCtrlHandler(SysmonConsoleCtrlHandler, FALSE);
        }
        CloseHandle(g_ServiceCtx.StopEvent);
        return status;
    }

    /* Start config monitor thread */
    hConfigThread = CreateThread(NULL, 0, SysmonConfigMonitorThread, NULL, 0, &threadId);

    /* Wait for stop */
    WaitForSingleObject(g_ServiceCtx.StopEvent, INFINITE);
    g_ServiceCtx.Running = FALSE;

    /* Wait for threads */
    if (hWorkerThread) {
        waitResult = WaitForSingleObject(hWorkerThread, INFINITE);
        if (waitResult == WAIT_OBJECT_0) {
            CloseHandle(hWorkerThread);
            hWorkerThread = NULL;
        } else {
            status = GetLastError();
            allThreadsExited = FALSE;
            SysmonLogError(
                SYSMON_COMPONENT_SERVICE,
                status,
                "Failed to confirm service worker exit");
        }
    }
    if (hConfigThread) {
        waitResult = WaitForSingleObject(hConfigThread, INFINITE);
        if (waitResult == WAIT_OBJECT_0) {
            CloseHandle(hConfigThread);
            hConfigThread = NULL;
        } else {
            status = GetLastError();
            allThreadsExited = FALSE;
            SysmonLogError(
                SYSMON_COMPONENT_SERVICE,
                status,
                "Failed to confirm config monitor exit");
        }
    }

    if (!allThreadsExited) {
        if (consoleHandlerRegistered) {
            SetConsoleCtrlHandler(SysmonConsoleCtrlHandler, FALSE);
        }
        return status;
    }

    CloseHandle(g_ServiceCtx.StopEvent);
    if (consoleHandlerRegistered) {
        SetConsoleCtrlHandler(SysmonConsoleCtrlHandler, FALSE);
    }
    DeleteCriticalSection(&g_ServiceCtx.OptionalSourceLock);
    DeleteCriticalSection(&g_ServiceCtx.ConfigLock);

    return SYSMON_SUCCESS;
}

/*
 * SysmonEnableDebugPrivilege - Enable SeDebugPrivilege
 * Original: sub_1400868c0("SeDebugPrivilege")
 */
BOOL SysmonEnableDebugPrivilege(void)
{
    HANDLE hToken = NULL;
    TOKEN_PRIVILEGES tp;
    LUID luid;

    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken)) {
        return FALSE;
    }

    if (!LookupPrivilegeValueW(NULL, L"SeDebugPrivilege", &luid)) {
        CloseHandle(hToken);
        return FALSE;
    }

    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

    BOOL result = AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(tp), NULL, NULL);
    CloseHandle(hToken);

    return result;
}


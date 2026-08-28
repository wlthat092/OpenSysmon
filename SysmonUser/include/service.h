#pragma once
/*
 * service.h - Service entry, SCM state machine, control handler
 */

#include "common.h"
#include "protocol.h"
#include "config.h"
#include "network_trace.h"
#include "dns_trace.h"
#include "clipboard_monitor.h"
#include "wmi_trace.h"

/* Service state context passed between threads */
typedef struct _SYSMON_SERVICE_CONTEXT {
    SERVICE_STATUS_HANDLE StatusHandle;
    SERVICE_STATUS ServiceStatus;
    HANDLE StopEvent;               /* Manual-reset, signaled to stop */
    SYSMON_TRANSPORT Transport;
    SYSMON_CONFIG Config;
    PSYSMON_RULE_RUNTIME RuleRuntime;
    PSYSMON_NETWORK_TRACE_CONTEXT NetworkTrace;
    PSYSMON_DNS_TRACE_CONTEXT DnsTrace;
    PSYSMON_CLIPBOARD_MONITOR_CONTEXT ClipboardMonitor;
    PSYSMON_WMI_TRACE_CONTEXT WmiTrace;
    volatile BOOL Running;
    volatile BOOL DebugMode;        /* -d: foreground mode */
    volatile LONG NetworkTraceFaulted;
    volatile LONG DnsTraceFaulted;
    ULONGLONG NetworkTraceRetryAfterTick;
    ULONGLONG DnsTraceRetryAfterTick;
    CRITICAL_SECTION ConfigLock;
    CRITICAL_SECTION OptionalSourceLock;
} SYSMON_SERVICE_CONTEXT, *PSYSMON_SERVICE_CONTEXT;

typedef enum _SYSMON_OPTIONAL_SOURCE_MASK {
    SysmonOptionalSourceNone = 0x00,
    SysmonOptionalSourceNetwork = 0x01,
    SysmonOptionalSourceDns = 0x02,
    SysmonOptionalSourceWmi = 0x04,
    SysmonOptionalSourceClipboard = 0x08
} SYSMON_OPTIONAL_SOURCE_MASK, *PSYSMON_OPTIONAL_SOURCE_MASK;

/* Global service context */
extern SYSMON_SERVICE_CONTEXT g_ServiceCtx;

/*
 * SysmonServiceMain - SCM entry point (called by StartServiceCtrlDispatcherW)
 */
void WINAPI SysmonServiceMain(
    _In_ DWORD Argc,
    _In_ LPWSTR *Argv);

/*
 * SysmonServiceCtrlHandler - SCM control handler
 *   Handles STOP and SHUTDOWN
 */
DWORD WINAPI SysmonServiceCtrlHandler(
    _In_ DWORD dwControl,
    _In_ DWORD dwEventType,
    _In_ LPVOID lpEventData,
    _In_ LPVOID lpContext);

/*
 * SysmonServiceRunDirect - Run service logic in foreground (debug mode)
 *   Does not register with SCM
 */
SYSMON_STATUS SysmonServiceRunDirect(void);

/*
 * SysmonEnableDebugPrivilege - Enable SeDebugPrivilege for current process
 */
BOOL SysmonEnableDebugPrivilege(void);

UCHAR
SysmonComputeOptionalSourceMask(
    _In_opt_ const SYSMON_CONFIG *Config,
    _In_opt_ PSYSMON_RULE_RUNTIME RuleRuntime);

void
SysmonApplyOptionalSourceMask(
    _Inout_ PSYSMON_SERVICE_CONTEXT ServiceContext,
    _In_ UCHAR OptionalSourceMask);

void
SysmonServiceApplyReloadedConfig(
    _Inout_ PSYSMON_SERVICE_CONTEXT ServiceContext,
    _Inout_ PSYSMON_CONFIG NewConfig,
    _In_opt_ PSYSMON_RULE_RUNTIME NewRuleRuntime);

void
SysmonStopOptionalSources(
    _Inout_ PSYSMON_SERVICE_CONTEXT ServiceContext);

void
SysmonRefreshOptionalSourceHealth(
    _Inout_ PSYSMON_SERVICE_CONTEXT ServiceContext);

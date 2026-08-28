#pragma once

#include "common.h"

struct _SYSMON_SERVICE_CONTEXT;

typedef struct _SYSMON_CLIPBOARD_MONITOR_CONTEXT SYSMON_CLIPBOARD_MONITOR_CONTEXT, *PSYSMON_CLIPBOARD_MONITOR_CONTEXT;

SYSMON_STATUS
SysmonClipboardMonitorStart(
    _Inout_ struct _SYSMON_SERVICE_CONTEXT *ServiceContext,
    _Outptr_result_maybenull_ PSYSMON_CLIPBOARD_MONITOR_CONTEXT *Context);

void
SysmonClipboardMonitorStop(
    _Inout_opt_ PSYSMON_CLIPBOARD_MONITOR_CONTEXT Context);

SYSMON_STATUS
SysmonClipboardHelperRun(
    _In_z_ LPCWSTR EndpointName,
    _In_ HANDLE ParentHandle);

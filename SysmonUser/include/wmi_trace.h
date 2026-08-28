#pragma once

#include "common.h"

struct _SYSMON_SERVICE_CONTEXT;

typedef struct _SYSMON_WMI_TRACE_CONTEXT SYSMON_WMI_TRACE_CONTEXT, *PSYSMON_WMI_TRACE_CONTEXT;

SYSMON_STATUS
SysmonWmiTraceStart(
    _Inout_ struct _SYSMON_SERVICE_CONTEXT *ServiceContext,
    _Outptr_result_maybenull_ PSYSMON_WMI_TRACE_CONTEXT *Context);

void
SysmonWmiTraceStop(
    _Inout_opt_ PSYSMON_WMI_TRACE_CONTEXT Context);

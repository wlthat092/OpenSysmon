#pragma once

#include "common.h"

struct _SYSMON_SERVICE_CONTEXT;

typedef struct _SYSMON_NETWORK_TRACE_CONTEXT SYSMON_NETWORK_TRACE_CONTEXT, *PSYSMON_NETWORK_TRACE_CONTEXT;

SYSMON_STATUS
SysmonNetworkTraceStart(
    _Inout_ struct _SYSMON_SERVICE_CONTEXT *ServiceContext,
    _Outptr_result_maybenull_ PSYSMON_NETWORK_TRACE_CONTEXT *Context);

void
SysmonNetworkTraceStop(
    _Inout_opt_ PSYSMON_NETWORK_TRACE_CONTEXT Context);

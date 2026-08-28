#pragma once

#include "common.h"

struct _SYSMON_SERVICE_CONTEXT;

typedef struct _SYSMON_DNS_TRACE_CONTEXT SYSMON_DNS_TRACE_CONTEXT, *PSYSMON_DNS_TRACE_CONTEXT;

SYSMON_STATUS
SysmonDnsTraceStart(
    _Inout_ struct _SYSMON_SERVICE_CONTEXT *ServiceContext,
    _Outptr_result_maybenull_ PSYSMON_DNS_TRACE_CONTEXT *Context);

void
SysmonDnsTraceStop(
    _Inout_opt_ PSYSMON_DNS_TRACE_CONTEXT Context);

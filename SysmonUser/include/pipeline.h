#pragma once
/*
 * pipeline.h - Event pipeline, rule evaluation interface
 */

#include "common.h"
#include "event.h"

/* Event processing callback type */
typedef void (*SYSMON_EVENT_HANDLER)(
    _In_ PUCHAR EventData,
    _In_ DWORD EventSize,
    _In_ SYSMON_EVENT_ID EventId);

/*
 * SysmonPipelineInit - Initialize the event pipeline
 */
SYSMON_STATUS SysmonPipelineInit(void);

/*
 * SysmonPipelineCleanup - Free pipeline resources
 */
void SysmonPipelineCleanup(void);

/*
 * SysmonPipelineDispatch - Process a raw event from driver
 *   Validates size (>= 0x358), extracts EventId, dispatches to handler
 */
SYSMON_STATUS SysmonPipelineDispatch(
    _In_ PUCHAR EventData,
    _In_ DWORD EventSize);

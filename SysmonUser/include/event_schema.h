#pragma once

#include "event.h"

typedef enum _SYSMON_RENDER_KIND {
    SysmonRenderStringRef,
    SysmonRenderUInt32,
    SysmonRenderUInt32Hex,
    SysmonRenderUInt64,
    SysmonRenderUInt64Hex,
    SysmonRenderBool,
    SysmonRenderProcessTerminatePid
} SYSMON_RENDER_KIND;

typedef struct _SYSMON_EVENT_FIELD_DESCRIPTOR {
    LPCWSTR Name;
    SYSMON_RENDER_KIND Kind;
    USHORT Offset;
} SYSMON_EVENT_FIELD_DESCRIPTOR;

typedef struct _SYSMON_EVENT_SCHEMA {
    const SYSMON_EVENT_FIELD_DESCRIPTOR *Fields;
    DWORD FieldCount;
} SYSMON_EVENT_SCHEMA;

const SYSMON_EVENT_SCHEMA *
GetEventSchema(
    _In_ SYSMON_EVENT_ID EventId);

#pragma once
#include "common.h"
#include "event.h"

/* Pipe event monitoring - classify NPFS operations using volume identity. */
NTSTATUS SysmonClassifyPipeCreateEvent(
    _In_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Out_ PULONG EventType,
    _Out_writes_(PipeNameChars) PWCHAR PipeName,
    _In_ ULONG PipeNameChars
);

NTSTATUS
SysmonBuildPipeEvent(
    _In_ PFLT_CALLBACK_DATA Data,
    _In_ ULONG EventType,
    _In_opt_z_ PCWSTR PipeName,
    _Outptr_ PSYSMON_EVENT_UNION *Event
);

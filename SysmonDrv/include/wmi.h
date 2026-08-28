#pragma once
#include "common.h"

/* WMI event monitoring via registry callback (WBEM path detection) */
BOOLEAN SysmonIsWmiRegistryPath(_In_ PCUNICODE_STRING KeyPath);
NTSTATUS SysmonBuildWmiEvent(
    _In_ ULONG EventId,
    _In_ ULONG ProcessId,
    _In_ PCUNICODE_STRING KeyPath,
    _In_opt_z_ PCWSTR Operation,
    _Out_ PVOID *EventData,
    _Out_ PULONG EventSize
);

NTSTATUS
SysmonProcessWmiRegistryEvent(
    _In_ PCUNICODE_STRING KeyPath,
    _In_ ULONG ProcessId,
    _In_opt_z_ PCWSTR Operation
);

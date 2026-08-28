#pragma once
#include "common.h"

/* DNS query event monitoring via ETW */
NTSTATUS SysmonInitializeDnsMonitoring(VOID);
VOID SysmonCleanupDnsMonitoring(VOID);

NTSTATUS
SysmonCheckDnsRegistryEvent(
    _In_ PCUNICODE_STRING KeyPath,
    _In_ ULONG ProcessId
);

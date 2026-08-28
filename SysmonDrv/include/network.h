#pragma once
#include "common.h"

/* WFP NetworkConnect (Event 3) initialization */
NTSTATUS SysmonInitializeNetworkFilter(_In_ PDRIVER_OBJECT DriverObject);
VOID SysmonCleanupNetworkFilter(VOID);
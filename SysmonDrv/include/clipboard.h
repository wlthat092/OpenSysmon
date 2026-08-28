#pragma once
#include "common.h"

/* Clipboard change event monitoring */
NTSTATUS SysmonInitializeClipboardMonitoring(VOID);
VOID SysmonCleanupClipboardMonitoring(VOID);
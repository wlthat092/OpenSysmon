#pragma once
#include "common.h"

/*
 * ProcessTampering (Event 25) - Process Image Tampering Detection
 *
 * Original Sysmon arms the process at create time and validates from the
 * image-load worker. This clone keeps the same validation flow, but preserves
 * a small bounded retry window when ProcessImageFileName is not yet ready for
 * freshly-created ghosted/doppelganged processes.
 *
 * The validation compares:
 *   1. PEB ImagePathName vs. current ProcessImageFileName (after DOS conversion)
 *   2. The mapped main-image header vs. the current on-disk image header
 */

NTSTATUS SysmonRegisterTamperingDetection(_In_ PDRIVER_OBJECT DriverObject);
VOID SysmonUnregisterTamperingDetection(VOID);
VOID SysmonCheckProcessTamperingOnImageLoad(_In_ HANDLE ProcessId);
VOID SysmonCheckProcessTamperingOnImageLoadSynchronous(_In_ HANDLE ProcessId);
VOID SysmonQueryTamperingDebugStats(_Out_ struct _SYSMON_PROCESS_DEBUG_STATS *Stats);

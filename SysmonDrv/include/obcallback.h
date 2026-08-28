#pragma once
#include "common.h"
#include "process.h"

/*
 * ProcessAccess (Event 10) - OB Object Callbacks
 *
 * Monitors cross-process handle operations via ObRegisterCallbacks.
 * When a process opens a handle to another process with specified access rights,
 * generates SysmonEventProcessAccess (Event 10) with:
 *   - SourceProcessGUID, SourceProcessId, SourceImage
 *   - TargetProcessGUID, TargetProcessId, TargetImage
 *   - GrantedAccess, CallTrace
 *   - RuleName (from config matching)
 *
 * Original Sysmon dynamically resolves ObRegisterCallbacks via MmGetSystemRoutineAddress
 * for compatibility with older OS versions.
 */

/* OB callback registration/unregistration */
NTSTATUS SysmonRegisterObCallbacks(_In_ PDEVICE_OBJECT DeviceObject);
VOID SysmonUnregisterObCallbacks(VOID);

/* OB pre-operation callback */
OB_PREOP_CALLBACK_STATUS
SysmonObPreOperationCallback(
    _In_ PVOID RegistrationContext,
    _Inout_ POB_PRE_OPERATION_INFORMATION OpInfo);

/* Configuration: access masks to monitor */
#define SYSMON_MAX_ACCESS_MASKS  32

typedef struct _SYSMON_ACCESS_FILTER {
    ULONG Count;
    ACCESS_MASK Masks[SYSMON_MAX_ACCESS_MASKS];
    WCHAR Names[SYSMON_MAX_ACCESS_MASKS][64];
} SYSMON_ACCESS_FILTER, *PSYSMON_ACCESS_FILTER;

/* Set process access filter from registry config */
VOID SysmonSetAccessFilter(
    _In_ ULONG Count,
    _In_reads_(Count) ACCESS_MASK *Masks,
    _In_reads_(Count_opt) WCHAR *Names);

VOID
SysmonQueryObDebugStats(
    _Out_ PSYSMON_PROCESS_DEBUG_STATS Stats);

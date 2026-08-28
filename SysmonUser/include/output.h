#pragma once
/*
 * output.h - Output channel API (console, file, ETW)
 */

#include "common.h"
#include "event.h"

/* Output channel flags */
#define SYSMON_OUTPUT_CONSOLE   0x01
#define SYSMON_OUTPUT_FILE      0x02
#define SYSMON_OUTPUT_ETW       0x04

typedef struct _SYSMON_IMAGE_VERSION_INFO {
    WCHAR FileVersion[256];
    WCHAR Description[256];
    WCHAR Product[256];
    WCHAR Company[256];
    WCHAR OriginalFileName[256];
} SYSMON_IMAGE_VERSION_INFO, *PSYSMON_IMAGE_VERSION_INFO;

/*
 * SysmonOutputInit - Initialize output subsystem
 *   Console output always available; file/ETW based on config
 */
SYSMON_STATUS SysmonOutputInit(
    _In_ DWORD OutputChannels,
    _In_opt_ LPCWSTR ArchiveDirectory);

/*
 * SysmonOutputCleanup - Flush and close output handles
 */
void SysmonOutputCleanup(void);

/*
 * SysmonOutputEvent - Write event to all active output channels
 */
void SysmonOutputEvent(
    _In_ PUCHAR EventData,
    _In_ DWORD EventSize,
    _In_ SYSMON_EVENT_ID EventId);

SYSMON_STATUS SysmonEmitServiceStateEvent(
    _In_z_ LPCWSTR State);

SYSMON_STATUS SysmonEmitServiceStateEventTransient(
    _In_z_ LPCWSTR State);

SYSMON_STATUS SysmonEmitConfigChangeEvent(
    _In_opt_z_ LPCWSTR Configuration,
    _In_opt_z_ LPCWSTR ConfigurationFileHash);

void SysmonResolveImageVersionInfo(
    _In_opt_z_ LPCWSTR ModulePath,
    _Out_ PSYSMON_IMAGE_VERSION_INFO VersionInfo);

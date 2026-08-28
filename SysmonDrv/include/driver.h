#pragma once

#include "common.h"
#include "rules.h"

/* Forward declarations */
typedef struct _SYSMON_GLOBAL_CONTEXT SYSMON_GLOBAL_CONTEXT;
typedef SYSMON_GLOBAL_CONTEXT *PSYSMON_GLOBAL_CONTEXT;
struct _SYSMON_EVENT_UNION;

/* Driver mode (from original data_1800268e0) */
extern ULONG g_DriverMode;

/* Global context */
struct _SYSMON_GLOBAL_CONTEXT {
    PDEVICE_OBJECT      DeviceObject;
    UNICODE_STRING      DeviceName;
    UNICODE_STRING      SymbolicLinkName;
    PFLT_FILTER         FilterHandle;
    /* Producer enable flags, packed into a single atomically-updated word so a
       config reload never lets a hot producer observe a cross-generation mix of
       the individual fields (K2 in the 2026-08-04 review). Read via
       SysmonIsProducerEnabled(); written under RuleLock. */
    volatile LONG       ProducerFlags;
    RTL_OSVERSIONINFOW  OsVersion;
    PKEVENT             LowMemoryEvent;
    HANDLE              LowMemoryEventHandle;
    FAST_MUTEX         RuleLock;
    FAST_MUTEX         RegistrationLock;
    PSYSMON_RULE_RUNTIME RuleRuntime;
    ULONG               Options;
    ULONG               HashingAlgorithm;
    BOOLEAN             CheckRevocation;
    BOOLEAN             DnsLookup;
    ULONG               DriverQueueSize;
    ULONG               SigningQueueSize;
    BOOLEAN             CopyOnDeletePE;
    BOOLEAN             ArchiveDirectoryConfigured;
    ULONG               ReloadGeneration;
    EX_RUNDOWN_REF      RunDownRef;
    volatile LONG       CapturePaused;
    volatile LONG       ShutdownStarted;
    ULONG               Mode;
};

extern SYSMON_GLOBAL_CONTEXT g_Context;

/* Producer flag bits for g_Context.ProducerFlags (K2). */
#define SYSMON_FLAG_ENABLED               (0x00000001L)
#define SYSMON_FLAG_PROCESS_NOTIFY        (0x00000002L)
#define SYSMON_FLAG_THREAD_NOTIFY         (0x00000004L)
#define SYSMON_FLAG_IMAGE_NOTIFY          (0x00000008L)
#define SYSMON_FLAG_DRIVER_LOAD_NOTIFY    (0x00000010L)
#define SYSMON_FLAG_IMAGE_LOAD_EVENT      (0x00000020L)
#define SYSMON_FLAG_REGISTRY_NOTIFY       (0x00000040L)
#define SYSMON_FLAG_FILE_NOTIFY           (0x00000080L)
#define SYSMON_FLAG_NETWORK_NOTIFY        (0x00000100L)
#define SYSMON_FLAG_PROCESS_ACCESS_NOTIFY (0x00000200L)
#define SYSMON_FLAG_DNS_QUERY_NOTIFY      (0x00000400L)
#define SYSMON_FLAG_CLIPBOARD_NOTIFY      (0x00000800L)
#define SYSMON_FLAG_TAMPERING_NOTIFY      (0x00001000L)

/* Single atomic read of the producer-flag word: safe at any IRQL. Each call
   reads one atomic snapshot; a caller that reads several flags via separate
   calls may observe a reload in between (same window as the old per-field
   reads, which this conversion preserves). */
FORCEINLINE BOOLEAN
SysmonIsProducerEnabled(_In_ ULONG Flag)
{
    return ((InterlockedCompareExchange(&g_Context.ProducerFlags, 0, 0) & (LONG)Flag) != 0);
}

/* Entry point */
DRIVER_INITIALIZE DriverEntry;
DRIVER_UNLOAD SysmonDriverUnload;

/* IRP dispatch */
DRIVER_DISPATCH SysmonCreateClose;
DRIVER_DISPATCH SysmonDeviceControl;
DRIVER_DISPATCH SysmonCleanup;


/* Init helpers */
VOID SysmonInitializeGlobalContext(_In_ PDRIVER_OBJECT DriverObject, _In_ PUNICODE_STRING RegistryPath);
NTSTATUS SysmonCreateDeviceAndLink(_In_ PDRIVER_OBJECT DriverObject);
VOID SysmonDeleteDeviceAndLink(VOID);
NTSTATUS SysmonLoadConfiguration(VOID);
NTSTATUS SysmonSyncMonitoringRegistration(VOID);
PSYSMON_RULE_RUNTIME SysmonAcquireRuleRuntimeSnapshot(VOID);
VOID SysmonReleaseRuleRuntimeSnapshot(_In_opt_ PSYSMON_RULE_RUNTIME Runtime);
BOOLEAN SysmonAcquireDriverRundown(VOID);
VOID SysmonReleaseDriverRundown(VOID);
NTSTATUS SysmonPublishEvent(_In_ struct _SYSMON_EVENT_UNION *Event);
NTSTATUS SysmonPublishEventWithFilterState(
    _In_ struct _SYSMON_EVENT_UNION *Event,
    _Out_opt_ PBOOLEAN FilteredOut);
VOID SysmonShutdownDriver(_In_ BOOLEAN FilterUnloadInProgress);

FORCEINLINE
BOOLEAN
SysmonIsRuntimeEventConfigured(
    _In_ SYSMON_EVENT_ID EventId,
    _In_ BOOLEAN FallbackEnabled)
{
    PSYSMON_RULE_RUNTIME runtime;
    BOOLEAN enabled;

    enabled = FallbackEnabled;
    runtime = SysmonAcquireRuleRuntimeSnapshot();
    if (runtime != NULL &&
        runtime->Header != NULL &&
        runtime->Header->EventRuleCount != 0) {
        enabled = SysmonRuleRuntimeEventCanProduceLogs(runtime, EventId);
    }
    SysmonReleaseRuleRuntimeSnapshot(runtime);

    return enabled;
}

#include "driver.h"
#include "queue.h"
#include "minifilter.h"
#include "process.h"
#include "registry.h"
#include "communication.h"
#include "network.h"
#include "dns.h"
#include "clipboard.h"
#include "obcallback.h"
#include "tampering.h"
#include "hash.h"
#include "rules.h"
#include "event.h"
#include <wdmsec.h>

static const GUID SYSMON_DEVICE_CLASS_GUID =
{ 0x3cdb86f1, 0x4f0b, 0x4b83, { 0xa5, 0x03, 0x97, 0x2c, 0x56, 0x14, 0x6e, 0x51 } };

#define SYSMON_KERNEL_NETWORK_MONITORING_IMPLEMENTED   FALSE
#define SYSMON_KERNEL_DNS_MONITORING_IMPLEMENTED       FALSE
#define SYSMON_KERNEL_CLIPBOARD_MONITORING_IMPLEMENTED FALSE

/* Globals */
SYSMON_GLOBAL_CONTEXT g_Context;
ULONG g_OsMajorVersion = 0;
ULONG g_OsMinorVersion = 0;
ULONG g_OsBuildNumber = 0;
ULONG g_DriverMode = 2;

static VOID
SysmonDriverCleanupInternal(
    _In_ BOOLEAN FilterUnloadInProgress);

static FORCEINLINE BOOLEAN
SysmonRequiresThreadNotify(VOID)
{
    return SysmonIsProducerEnabled(SYSMON_FLAG_PROCESS_NOTIFY) || SysmonIsProducerEnabled(SYSMON_FLAG_THREAD_NOTIFY);
}

static VOID
SysmonRecordRegistrationFailure(
    _Inout_ PNTSTATUS AggregateStatus,
    _In_ NTSTATUS Status)
{
    if (AggregateStatus != NULL &&
        NT_SUCCESS(*AggregateStatus) &&
        !NT_SUCCESS(Status)) {
        *AggregateStatus = Status;
    }
}

_Use_decl_annotations_
NTSTATUS
DriverEntry(
    PDRIVER_OBJECT  DriverObject,
    PUNICODE_STRING RegistryPath
)
{
    NTSTATUS status;

    DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_INFO_LEVEL,
        "[SysmonDrv] DriverEntry: Loading...\n");

    /*
     * Enable WDK downlevel support for zeroed pool allocations before any
     * helper path can allocate from the driver-wide wrappers.
     */
    ExInitializeDriverRuntime(0);

    /* Get OS version */
    {
        RTL_OSVERSIONINFOW versionInfo = { 0 };
        versionInfo.dwOSVersionInfoSize = sizeof(versionInfo);
        RtlGetVersion(&versionInfo);
        g_OsMajorVersion = versionInfo.dwMajorVersion;
        g_OsMinorVersion = versionInfo.dwMinorVersion;
        g_OsBuildNumber = versionInfo.dwBuildNumber;
        RtlCopyMemory(&g_Context.OsVersion, &versionInfo, sizeof(versionInfo));
    }

    /* Initialize global context */
    SysmonInitializeGlobalContext(DriverObject, RegistryPath);
    SysmonInitializeEventPool();

    /* Create device object and symbolic link */
    status = SysmonCreateDeviceAndLink(DriverObject);
    if (!NT_SUCCESS(status)) {
        SysmonCleanupEventPool();
        DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL,
            "[SysmonDrv] Failed to create device: 0x%08X\n", status);
        return status;
    }

    /* Initialize event queues */
    status = SysmonInitializeQueue();
    if (!NT_SUCCESS(status)) {
        SysmonDeleteDeviceAndLink();
        SysmonCleanupEventPool();
        return status;
    }

    /* Set IRP dispatch table */
    DriverObject->MajorFunction[IRP_MJ_CREATE]         = SysmonCreateClose;
    DriverObject->MajorFunction[IRP_MJ_CLOSE]          = SysmonCreateClose;
    DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = SysmonDeviceControl;
    DriverObject->MajorFunction[IRP_MJ_CLEANUP]        = SysmonCleanup;

    /* Initialize CSQ for IOCTL queueing */
    status = SysmonInitializeCsq(g_Context.DeviceObject);
    if (!NT_SUCCESS(status)) {
        SysmonShutdownDriver(FALSE);
        return status;
    }

    status = SysmonInitializeHashing();
    if (!NT_SUCCESS(status)) {
        DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL,
            "[SysmonDrv] Failed to initialize SymCrypt hashing: 0x%08X\n",
            status);
        SysmonShutdownDriver(FALSE);
        return status;
    }

    status = SysmonLoadConfiguration();
    if (!NT_SUCCESS(status)) {
        DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_WARNING_LEVEL,
            "[SysmonDrv] Initial configuration load failed: 0x%08X\n", status);
    }

    DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_INFO_LEVEL,
        "[SysmonDrv] Registration plan: Proc=%d Thread=%d Image=%d Reg=%d File=%d Net=%d Ob=%d Dns=%d Clip=%d Tamp=%d\n",
        SysmonIsProducerEnabled(SYSMON_FLAG_PROCESS_NOTIFY),
        SysmonIsProducerEnabled(SYSMON_FLAG_THREAD_NOTIFY),
        SysmonIsProducerEnabled(SYSMON_FLAG_IMAGE_NOTIFY),
        SysmonIsProducerEnabled(SYSMON_FLAG_REGISTRY_NOTIFY),
        SysmonIsProducerEnabled(SYSMON_FLAG_FILE_NOTIFY),
        SysmonIsProducerEnabled(SYSMON_FLAG_NETWORK_NOTIFY),
        SysmonIsProducerEnabled(SYSMON_FLAG_PROCESS_ACCESS_NOTIFY),
        SysmonIsProducerEnabled(SYSMON_FLAG_DNS_QUERY_NOTIFY),
        SysmonIsProducerEnabled(SYSMON_FLAG_CLIPBOARD_NOTIFY),
        SysmonIsProducerEnabled(SYSMON_FLAG_TAMPERING_NOTIFY));

    status = SysmonRegisterFilter(DriverObject);
    if (!NT_SUCCESS(status)) {
        DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL,
            "[SysmonDrv] Failed to register filter: 0x%08X\n", status);
        SysmonShutdownDriver(FALSE);
        return status;
    }

    if (SysmonIsProducerEnabled(SYSMON_FLAG_PROCESS_NOTIFY)) {
        status = SysmonRegisterProcessNotify(DriverObject);
        if (!NT_SUCCESS(status)) {
            DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL,
                "[SysmonDrv] Failed to register process notify: 0x%08X\n", status);
            SysmonShutdownDriver(FALSE);
            return status;
        }
    }

    if (SysmonRequiresThreadNotify()) {
        status = SysmonRegisterThreadNotify(DriverObject);
        if (!NT_SUCCESS(status)) {
            DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_WARNING_LEVEL,
                "[SysmonDrv] Thread notify registration unavailable; continuing without Event 8 / thread-assisted Event 1 finalize: 0x%08X\n",
                status);
        }
    }

    if (SysmonIsProducerEnabled(SYSMON_FLAG_IMAGE_NOTIFY)) {
        status = SysmonRegisterImageNotify(DriverObject);
        if (!NT_SUCCESS(status)) {
            DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_WARNING_LEVEL,
                "[SysmonDrv] Failed to register image notify: 0x%08X\n", status);
        }
    }

    if (SysmonIsProducerEnabled(SYSMON_FLAG_REGISTRY_NOTIFY)) {
        status = SysmonRegisterRegistryCallback();
        if (!NT_SUCCESS(status)) {
            DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_WARNING_LEVEL,
                "[SysmonDrv] Failed to register registry callback: 0x%08X\n", status);
        }
    }

    if (SysmonIsProducerEnabled(SYSMON_FLAG_NETWORK_NOTIFY) &&
        SYSMON_KERNEL_NETWORK_MONITORING_IMPLEMENTED) {
        status = SysmonInitializeNetworkFilter(DriverObject);
        if (!NT_SUCCESS(status)) {
            DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_WARNING_LEVEL,
                "[SysmonDrv] Failed to initialize network monitoring: 0x%08X\n", status);
        }
    } else if (SysmonIsProducerEnabled(SYSMON_FLAG_NETWORK_NOTIFY)) {
        DbgPrintEx(
            DPFLTR_DEFAULT_ID,
            DPFLTR_INFO_LEVEL,
            "[SysmonDrv] Kernel network producer not implemented; skipping kernel network monitoring initialization.\n");
    }

    if (SysmonIsProducerEnabled(SYSMON_FLAG_DNS_QUERY_NOTIFY) &&
        SYSMON_KERNEL_DNS_MONITORING_IMPLEMENTED) {
        status = SysmonInitializeDnsMonitoring();
        if (!NT_SUCCESS(status)) {
            DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_WARNING_LEVEL,
                "[SysmonDrv] Failed to initialize DNS monitoring: 0x%08X\n", status);
        }
    } else if (SysmonIsProducerEnabled(SYSMON_FLAG_DNS_QUERY_NOTIFY)) {
        DbgPrintEx(
            DPFLTR_DEFAULT_ID,
            DPFLTR_INFO_LEVEL,
            "[SysmonDrv] Kernel DNS producer not implemented; skipping kernel DNS monitoring initialization.\n");
    }

    if (SysmonIsProducerEnabled(SYSMON_FLAG_CLIPBOARD_NOTIFY) &&
        SYSMON_KERNEL_CLIPBOARD_MONITORING_IMPLEMENTED) {
        status = SysmonInitializeClipboardMonitoring();
        if (!NT_SUCCESS(status)) {
            DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_WARNING_LEVEL,
                "[SysmonDrv] Failed to initialize clipboard monitoring: 0x%08X\n", status);
        }
    } else if (SysmonIsProducerEnabled(SYSMON_FLAG_CLIPBOARD_NOTIFY)) {
        DbgPrintEx(
            DPFLTR_DEFAULT_ID,
            DPFLTR_INFO_LEVEL,
            "[SysmonDrv] Kernel clipboard producer not implemented; skipping kernel clipboard monitoring initialization.\n");
    }

    if (SysmonIsProducerEnabled(SYSMON_FLAG_PROCESS_ACCESS_NOTIFY)) {
        status = SysmonRegisterObCallbacks(g_Context.DeviceObject);
        if (!NT_SUCCESS(status)) {
            DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_WARNING_LEVEL,
                "[SysmonDrv] Failed to register OB callbacks: 0x%08X\n", status);
        }
    }

    if (SysmonIsProducerEnabled(SYSMON_FLAG_TAMPERING_NOTIFY)) {
        status = SysmonRegisterTamperingDetection(DriverObject);
        if (!NT_SUCCESS(status)) {
            DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_WARNING_LEVEL,
                "[SysmonDrv] Failed to register tampering detection: 0x%08X\n", status);
        }
    }

    /* Create low memory notification event */
    {
        UNICODE_STRING lowMemEventName;
        RtlInitUnicodeString(&lowMemEventName,
            L"\\KernelObjects\\LowMemoryCondition");
        g_Context.LowMemoryEvent = IoCreateNotificationEvent(
            &lowMemEventName, &g_Context.LowMemoryEventHandle);
    }

    DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_INFO_LEVEL,
        "[SysmonDrv] DriverEntry: Success, mode=%lu, build=%lu\n",
        g_DriverMode, g_OsBuildNumber);

    DriverObject->DriverUnload = SysmonDriverUnload;
    return STATUS_SUCCESS;
}

VOID
SysmonInitializeGlobalContext(
    _In_ PDRIVER_OBJECT  DriverObject,
    _In_ PUNICODE_STRING RegistryPath
)
{
    UNREFERENCED_PARAMETER(DriverObject);
    UNREFERENCED_PARAMETER(RegistryPath);

    RtlZeroMemory(&g_Context, sizeof(g_Context));
    /* Globally enabled, but no specific producer is active until configuration
       is loaded (see note below), matching the previous Enabled=TRUE +
       *NotifyEnabled=FALSE defaults. */
    g_Context.ProducerFlags = SYSMON_FLAG_ENABLED;
    g_Context.Mode = g_DriverMode;
    /*
     * Register event producers only after configuration is loaded. A
     * driver-only start with all callbacks enabled can create immediate
     * high-CPU load before user mode has supplied any rules or state.
     * (The individual producer flags are zeroed by RtlZeroMemory above and are
     * populated by SysmonLoadConfiguration.)
     */
    g_Context.HashingAlgorithm = SysmonHashSHA1 | SysmonHashMD5;
    g_Context.CheckRevocation = TRUE;
    g_Context.DnsLookup = TRUE;
    g_Context.SigningQueueSize = 1000;
    g_Context.CapturePaused = 0;
    g_Context.ShutdownStarted = 0;
    ExInitializeFastMutex(&g_Context.RuleLock);
    ExInitializeFastMutex(&g_Context.RegistrationLock);
    ExInitializeRundownProtection(&g_Context.RunDownRef);
}

NTSTATUS
SysmonSyncMonitoringRegistration(VOID)
{
    NTSTATUS aggregateStatus = STATUS_SUCCESS;
    NTSTATUS status;
    PDEVICE_OBJECT deviceObject;
    PDRIVER_OBJECT driverObject;

    deviceObject = g_Context.DeviceObject;
    driverObject = (deviceObject != NULL) ? deviceObject->DriverObject : NULL;

    DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_INFO_LEVEL,
        "[SysmonDrv] Live sync plan: Enabled=%d Proc=%d Thread=%d Image=%d Reg=%d File=%d Net=%d Ob=%d Dns=%d Clip=%d Tamp=%d\n",
        SysmonIsProducerEnabled(SYSMON_FLAG_ENABLED),
        SysmonIsProducerEnabled(SYSMON_FLAG_PROCESS_NOTIFY),
        SysmonIsProducerEnabled(SYSMON_FLAG_THREAD_NOTIFY),
        SysmonIsProducerEnabled(SYSMON_FLAG_IMAGE_NOTIFY),
        SysmonIsProducerEnabled(SYSMON_FLAG_REGISTRY_NOTIFY),
        SysmonIsProducerEnabled(SYSMON_FLAG_FILE_NOTIFY),
        SysmonIsProducerEnabled(SYSMON_FLAG_NETWORK_NOTIFY),
        SysmonIsProducerEnabled(SYSMON_FLAG_PROCESS_ACCESS_NOTIFY),
        SysmonIsProducerEnabled(SYSMON_FLAG_DNS_QUERY_NOTIFY),
        SysmonIsProducerEnabled(SYSMON_FLAG_CLIPBOARD_NOTIFY),
        SysmonIsProducerEnabled(SYSMON_FLAG_TAMPERING_NOTIFY));

    if (!SysmonIsProducerEnabled(SYSMON_FLAG_ENABLED)) {
        /*
         * Global disable keeps the minifilter registered and relies on the
         * callback gates in minifilter.c. Tearing the filter down here makes
         * hot re-enable fragile and is reserved for actual driver shutdown.
         */
        SysmonUnregisterTamperingDetection();
        SysmonUnregisterObCallbacks();
        SysmonCleanupClipboardMonitoring();
        SysmonCleanupDnsMonitoring();
        SysmonCleanupNetworkFilter();
        SysmonUnregisterRegistryCallback();
        SysmonUnregisterImageNotify();
        SysmonUnregisterThreadNotify();
        SysmonUnregisterProcessNotify();
        return STATUS_SUCCESS;
    }

    /*
     * Drop registrations for monitors that are no longer enabled before
     * turning on newly requested ones.
     */
    if (!SysmonIsProducerEnabled(SYSMON_FLAG_CLIPBOARD_NOTIFY)) {
        SysmonCleanupClipboardMonitoring();
    }
    if (!SysmonIsProducerEnabled(SYSMON_FLAG_DNS_QUERY_NOTIFY)) {
        SysmonCleanupDnsMonitoring();
    }
    if (!SysmonIsProducerEnabled(SYSMON_FLAG_NETWORK_NOTIFY)) {
        SysmonCleanupNetworkFilter();
    }
    if (!SysmonIsProducerEnabled(SYSMON_FLAG_REGISTRY_NOTIFY)) {
        SysmonUnregisterRegistryCallback();
    }
    if (!SysmonIsProducerEnabled(SYSMON_FLAG_IMAGE_NOTIFY)) {
        SysmonUnregisterImageNotify();
    }
    if (!SysmonRequiresThreadNotify()) {
        SysmonUnregisterThreadNotify();
    }
    if (!SysmonIsProducerEnabled(SYSMON_FLAG_PROCESS_NOTIFY)) {
        SysmonUnregisterProcessNotify();
    }
    if (SysmonIsProducerEnabled(SYSMON_FLAG_PROCESS_NOTIFY)) {
        if (driverObject == NULL) {
            status = STATUS_INVALID_DEVICE_STATE;
        } else {
            status = SysmonRegisterProcessNotify(driverObject);
        }
        if (!NT_SUCCESS(status)) {
            DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_WARNING_LEVEL,
                "[SysmonDrv] Live sync failed to register process notify: 0x%08X\n",
                status);
            SysmonRecordRegistrationFailure(&aggregateStatus, status);
        }
    }

    if (SysmonRequiresThreadNotify()) {
        if (driverObject == NULL) {
            status = STATUS_INVALID_DEVICE_STATE;
            DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_WARNING_LEVEL,
                "[SysmonDrv] Live sync failed to register thread notify: 0x%08X\n",
                status);
            SysmonRecordRegistrationFailure(&aggregateStatus, status);
        } else {
            status = SysmonRegisterThreadNotify(driverObject);
            if (!NT_SUCCESS(status)) {
                DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_WARNING_LEVEL,
                    "[SysmonDrv] Live sync failed to register thread notify: 0x%08X\n",
                    status);
                SysmonRecordRegistrationFailure(&aggregateStatus, status);
            }
        }
    }

    if (SysmonIsProducerEnabled(SYSMON_FLAG_IMAGE_NOTIFY)) {
        if (driverObject == NULL) {
            status = STATUS_INVALID_DEVICE_STATE;
            DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_WARNING_LEVEL,
                "[SysmonDrv] Live sync failed to register image notify: 0x%08X\n",
                status);
            SysmonRecordRegistrationFailure(&aggregateStatus, status);
        } else {
            status = SysmonRegisterImageNotify(driverObject);
            if (!NT_SUCCESS(status)) {
                DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_WARNING_LEVEL,
                    "[SysmonDrv] Live sync failed to register image notify: 0x%08X\n",
                    status);
                SysmonRecordRegistrationFailure(&aggregateStatus, status);
            }
        }
    }

    if (SysmonIsProducerEnabled(SYSMON_FLAG_REGISTRY_NOTIFY)) {
        status = SysmonRegisterRegistryCallback();
        if (!NT_SUCCESS(status)) {
            DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_WARNING_LEVEL,
                "[SysmonDrv] Live sync failed to register registry callback: 0x%08X\n",
                status);
            SysmonRecordRegistrationFailure(&aggregateStatus, status);
        }
    }

    if (SysmonIsProducerEnabled(SYSMON_FLAG_NETWORK_NOTIFY) &&
        SYSMON_KERNEL_NETWORK_MONITORING_IMPLEMENTED) {
        if (driverObject == NULL) {
            status = STATUS_INVALID_DEVICE_STATE;
        } else {
            status = SysmonInitializeNetworkFilter(driverObject);
        }
        if (!NT_SUCCESS(status)) {
            DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_WARNING_LEVEL,
                "[SysmonDrv] Live sync failed to initialize network monitoring: 0x%08X\n",
                status);
            SysmonRecordRegistrationFailure(&aggregateStatus, status);
        }
    } else if (SysmonIsProducerEnabled(SYSMON_FLAG_NETWORK_NOTIFY)) {
        DbgPrintEx(
            DPFLTR_DEFAULT_ID,
            DPFLTR_INFO_LEVEL,
            "[SysmonDrv] Kernel network producer not implemented; skipping kernel network monitoring initialization.\n");
    }

    if (SysmonIsProducerEnabled(SYSMON_FLAG_DNS_QUERY_NOTIFY) &&
        SYSMON_KERNEL_DNS_MONITORING_IMPLEMENTED) {
        status = SysmonInitializeDnsMonitoring();
        if (!NT_SUCCESS(status)) {
            DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_WARNING_LEVEL,
                "[SysmonDrv] Live sync failed to initialize DNS monitoring: 0x%08X\n",
                status);
            SysmonRecordRegistrationFailure(&aggregateStatus, status);
        }
    } else if (SysmonIsProducerEnabled(SYSMON_FLAG_DNS_QUERY_NOTIFY)) {
        DbgPrintEx(
            DPFLTR_DEFAULT_ID,
            DPFLTR_INFO_LEVEL,
            "[SysmonDrv] Kernel DNS producer not implemented; skipping kernel DNS monitoring initialization.\n");
    }

    if (SysmonIsProducerEnabled(SYSMON_FLAG_CLIPBOARD_NOTIFY) &&
        SYSMON_KERNEL_CLIPBOARD_MONITORING_IMPLEMENTED) {
        status = SysmonInitializeClipboardMonitoring();
        if (!NT_SUCCESS(status)) {
            DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_WARNING_LEVEL,
                "[SysmonDrv] Live sync failed to initialize clipboard monitoring: 0x%08X\n",
                status);
            SysmonRecordRegistrationFailure(&aggregateStatus, status);
        }
    } else if (SysmonIsProducerEnabled(SYSMON_FLAG_CLIPBOARD_NOTIFY)) {
        DbgPrintEx(
            DPFLTR_DEFAULT_ID,
            DPFLTR_INFO_LEVEL,
            "[SysmonDrv] Kernel clipboard producer not implemented; skipping kernel clipboard monitoring initialization.\n");
    }

    if (SysmonIsProducerEnabled(SYSMON_FLAG_PROCESS_ACCESS_NOTIFY)) {
        if (deviceObject == NULL) {
            status = STATUS_INVALID_DEVICE_STATE;
        } else {
            status = SysmonRegisterObCallbacks(deviceObject);
        }
        if (!NT_SUCCESS(status)) {
            DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_WARNING_LEVEL,
                "[SysmonDrv] Live sync failed to register process access callbacks: 0x%08X\n",
                status);
            SysmonRecordRegistrationFailure(&aggregateStatus, status);
        }
    }

    if (SysmonIsProducerEnabled(SYSMON_FLAG_TAMPERING_NOTIFY)) {
        if (driverObject == NULL) {
            status = STATUS_INVALID_DEVICE_STATE;
            DbgPrintEx(
                DPFLTR_DEFAULT_ID,
                DPFLTR_WARNING_LEVEL,
                "[SysmonDrv] Live sync failed to register tampering detection: 0x%08X\n",
                status);
            SysmonRecordRegistrationFailure(&aggregateStatus, status);
        } else {
            status = SysmonRegisterTamperingDetection(driverObject);
            if (!NT_SUCCESS(status)) {
                DbgPrintEx(
                    DPFLTR_DEFAULT_ID,
                    DPFLTR_WARNING_LEVEL,
                    "[SysmonDrv] Live sync failed to register tampering detection: 0x%08X\n",
                    status);
                SysmonRecordRegistrationFailure(&aggregateStatus, status);
            }
        }
    }

    /*
     * Event 10 and Event 25 are intentionally excluded from per-feature
     * hot unregistration. Event 10 callbacks can remain registered and
     * cheaply self-gate on SysmonIsProducerEnabled(SYSMON_FLAG_PROCESS_ACCESS_NOTIFY), which is
     * safer than tearing down OB callbacks live. Event 25 now self-gates on
     * SysmonIsProducerEnabled(SYSMON_FLAG_TAMPERING_NOTIFY) while reusing the shared image-load path.
     */

    return aggregateStatus;
}

NTSTATUS
SysmonCreateDeviceAndLink(
    _In_ PDRIVER_OBJECT DriverObject
)
{
    NTSTATUS status;
    UNICODE_STRING deviceName;
    UNICODE_STRING symbolicLinkName;
    UNICODE_STRING deviceSddl;
    PDEVICE_OBJECT deviceObject = NULL;

    RtlInitUnicodeString(&deviceName, L"\\Device\\Sysmon");
    RtlInitUnicodeString(&symbolicLinkName, L"\\DosDevices\\Sysmon");
    RtlInitUnicodeString(&deviceSddl, L"D:P(A;;GA;;;SY)(A;;GA;;;BA)");

    status = IoCreateDeviceSecure(
        DriverObject,
        sizeof(DEVICE_EXTENSION),
        &deviceName,
        FILE_DEVICE_UNKNOWN,
        FILE_DEVICE_SECURE_OPEN,
        FALSE,
        &deviceSddl,
        &SYSMON_DEVICE_CLASS_GUID,
        &deviceObject
    );
    if (!NT_SUCCESS(status)) {
        return status;
    }

    status = IoCreateSymbolicLink(&symbolicLinkName, &deviceName);
    if (!NT_SUCCESS(status)) {
        IoDeleteDevice(deviceObject);
        return status;
    }

    g_Context.DeviceObject = deviceObject;
    g_Context.DeviceName = deviceName;
    g_Context.SymbolicLinkName = symbolicLinkName;

    return STATUS_SUCCESS;
}

VOID
SysmonDeleteDeviceAndLink(VOID)
{
    if (g_Context.SymbolicLinkName.Buffer != NULL) {
        IoDeleteSymbolicLink(&g_Context.SymbolicLinkName);
        g_Context.SymbolicLinkName.Buffer = NULL;
    }
    if (g_Context.DeviceObject != NULL) {
        IoDeleteDevice(g_Context.DeviceObject);
        g_Context.DeviceObject = NULL;
    }
}

PSYSMON_RULE_RUNTIME
SysmonAcquireRuleRuntimeSnapshot(VOID)
{
    PSYSMON_RULE_RUNTIME runtime = NULL;

    ExAcquireFastMutex(&g_Context.RuleLock);
    runtime = g_Context.RuleRuntime;
    if (runtime != NULL &&
        !ExAcquireRundownProtection(&runtime->RundownRef)) {
        runtime = NULL;
    }
    ExReleaseFastMutex(&g_Context.RuleLock);

    return runtime;
}

VOID
SysmonReleaseRuleRuntimeSnapshot(
    _In_opt_ PSYSMON_RULE_RUNTIME Runtime)
{
    if (Runtime == NULL) {
        return;
    }

    ExReleaseRundownProtection(&Runtime->RundownRef);
}

BOOLEAN
SysmonAcquireDriverRundown(VOID)
{
    if (InterlockedCompareExchange(&g_Context.ShutdownStarted, 0, 0) != 0) {
        return FALSE;
    }

    if (!ExAcquireRundownProtection(&g_Context.RunDownRef)) {
        return FALSE;
    }

    if (InterlockedCompareExchange(&g_Context.ShutdownStarted, 0, 0) != 0) {
        ExReleaseRundownProtection(&g_Context.RunDownRef);
        return FALSE;
    }

    return TRUE;
}

VOID
SysmonReleaseDriverRundown(VOID)
{
    ExReleaseRundownProtection(&g_Context.RunDownRef);
}

_Use_decl_annotations_
VOID
SysmonDriverUnload(
    PDRIVER_OBJECT DriverObject)
{
    UNREFERENCED_PARAMETER(DriverObject);
    SysmonShutdownDriver(FALSE);
}

VOID
SysmonShutdownDriver(
    _In_ BOOLEAN FilterUnloadInProgress)
{
    SysmonDriverCleanupInternal(FilterUnloadInProgress);
}

static VOID
SysmonDriverCleanupInternal(
    _In_ BOOLEAN FilterUnloadInProgress)
{
    PSYSMON_RULE_RUNTIME oldRuntime = NULL;

    if (InterlockedExchange(&g_Context.ShutdownStarted, 1) != 0) {
        return;
    }

    InterlockedExchange(&g_Context.CapturePaused, 1);
    InterlockedAnd(&g_Context.ProducerFlags, ~SYSMON_FLAG_ENABLED);

    /*
     * Match the original teardown direction: first block new entrants and wait
     * for in-flight rundown users to leave, then tear down registrations.
     *
     * Holding RegistrationLock across the rundown wait can deadlock with a
     * live config-notify path that already owns rundown protection and is about
     * to acquire the same lock.
     */
    ExWaitForRundownProtectionRelease(&g_Context.RunDownRef);

    if (!FilterUnloadInProgress) {
        SysmonUnregisterFilter();
    }

    ExAcquireFastMutex(&g_Context.RegistrationLock);

    SysmonUnregisterObCallbacks();
    SysmonUnregisterTamperingDetection();
    SysmonUnregisterRegistryCallback();
    SysmonUnregisterImageNotify();
    SysmonUnregisterThreadNotify();
    SysmonUnregisterProcessNotify();
    SysmonCleanupClipboardMonitoring();
    SysmonCleanupDnsMonitoring();
    SysmonCleanupNetworkFilter();
    ExReleaseFastMutex(&g_Context.RegistrationLock);

    if (g_Context.LowMemoryEventHandle != NULL) {
        ZwClose(g_Context.LowMemoryEventHandle);
        g_Context.LowMemoryEventHandle = NULL;
    }

    ExAcquireFastMutex(&g_Context.RuleLock);
    oldRuntime = g_Context.RuleRuntime;
    g_Context.RuleRuntime = NULL;
    ExReleaseFastMutex(&g_Context.RuleLock);

    if (oldRuntime != NULL) {
        ExWaitForRundownProtectionRelease(&oldRuntime->RundownRef);
        SysmonFreeRuleRuntime(oldRuntime);
    }

    SysmonDrainPendingEventIrps(STATUS_DELETE_PENDING);
    SysmonDrainPendingQueryIrps(STATUS_DELETE_PENDING);

    SysmonCleanupQueue();
    SysmonCleanupEventPool();
    SysmonCleanupHashing();
    SysmonDeleteDeviceAndLink();
}



NTSTATUS
SysmonCreateClose(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ PIRP Irp
)
{
    UNREFERENCED_PARAMETER(DeviceObject);

    Irp->IoStatus.Status = STATUS_SUCCESS;
    Irp->IoStatus.Information = 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return STATUS_SUCCESS;
}

NTSTATUS
SysmonDeviceControl(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ PIRP Irp
)
{
    PIO_STACK_LOCATION irpSp = IoGetCurrentIrpStackLocation(Irp);
    NTSTATUS status = STATUS_INVALID_DEVICE_REQUEST;
    ULONG_PTR information = 0;
    ULONG ioControlCode = irpSp->Parameters.DeviceIoControl.IoControlCode;
    ULONG inputLength = irpSp->Parameters.DeviceIoControl.InputBufferLength;
    ULONG outputLength = irpSp->Parameters.DeviceIoControl.OutputBufferLength;
    PVOID systemBuffer = Irp->AssociatedIrp.SystemBuffer;

    switch (ioControlCode) {
    case IOCTL_SYSMON_INIT:
        /* Init/Handshake: 4-byte version input, no output */
        status = SysmonHandleInit(Irp, inputLength, systemBuffer);
        break;

    case IOCTL_SYSMON_GET_EVENT:
        /* Get Event: overlapped via CSQ */
        /* Try synchronous first (if event already available) */
        status = SysmonHandleGetEvent(Irp);
        if (status == STATUS_NO_MORE_ENTRIES) {
            /* No event available - pend the IRP in CSQ */
            status = SysmonPendGetEventIrp(DeviceObject, Irp);
            if (status == STATUS_PENDING) {
                return STATUS_PENDING;
            }
        } else if (NT_SUCCESS(status)) {
            /* Use actual event size set by SysmonHandleGetEvent, not buffer size */
            information = Irp->IoStatus.Information;
        }
        break;

    case IOCTL_SYSMON_CONFIG_NOTIFY:
        /* Config/Rule refresh notify: no input, no output */
        status = SysmonHandleConfigNotify(Irp);
        break;

    case IOCTL_SYSMON_PROCESS_CACHE:
        /* Process cache request: 8-byte input, up to 0x4002 output */
        status = SysmonHandleProcessCache(Irp, inputLength, systemBuffer,
            outputLength, systemBuffer);
        if (NT_SUCCESS(status)) {
            information = min(outputLength, 0x4002);
        }
        break;

    case IOCTL_SYSMON_QUERY_ANSWER:
        /* Query answer: 0x60 byte input, no output */
        status = SysmonHandleQueryAnswer(Irp, inputLength, systemBuffer);
        break;

    case IOCTL_SYSMON_STOP:
        /* Stop/Close: no input, no output */
        status = SysmonHandleStop(Irp);
        break;

    case IOCTL_SYSMON_GET_QUERY:
        /* Get query event: overlapped via dedicated query queue */
        status = SysmonHandleGetQueryEvent(Irp);
        if (status == STATUS_NO_MORE_ENTRIES) {
            status = SysmonPendGetQueryIrp(DeviceObject, Irp);
            if (status == STATUS_PENDING) {
                return STATUS_PENDING;
            }
        } else if (NT_SUCCESS(status)) {
            information = Irp->IoStatus.Information;
        }
        break;

    case IOCTL_SYSMON_GET_STATS:
        /* Clone-only debug stats: up to sizeof(SYSMON_PROCESS_DEBUG_STATS) output */
        status = SysmonHandleGetStats(Irp, outputLength, systemBuffer);
        if (NT_SUCCESS(status)) {
            information = min(outputLength, (ULONG)sizeof(SYSMON_PROCESS_DEBUG_STATS));
        }
        break;

    default:
        DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_WARNING_LEVEL,
            "[SysmonDrv] Unknown IOCTL: 0x%08X\n", ioControlCode);
        status = STATUS_INVALID_DEVICE_REQUEST;
        break;
    }

    Irp->IoStatus.Status = status;
    Irp->IoStatus.Information = information;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return status;
}

NTSTATUS
SysmonCleanup(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ PIRP Irp
)
{
    PIO_STACK_LOCATION irpSp = IoGetCurrentIrpStackLocation(Irp);
    UNREFERENCED_PARAMETER(DeviceObject);

    /* Cancel all pending IRPs for this file object */
    SysmonCancelPendingIrpsForFileObject(irpSp->FileObject, STATUS_CANCELLED);

    Irp->IoStatus.Status = STATUS_SUCCESS;
    Irp->IoStatus.Information = 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return STATUS_SUCCESS;
}




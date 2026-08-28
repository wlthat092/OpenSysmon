#pragma once
/*
 * installer.h - Service/driver install, uninstall, manifest registration
 */

#include "common.h"

/*
 * SysmonInstall - Install Sysmon service + driver
 *   1. Create SysmonDrv driver service (kernel)
 *   2. Create Sysmon user service
 *   3. Write default registry parameters
 *   4. Configure minifilter instance
 *   5. Start the service
 */
SYSMON_STATUS SysmonInstall(
    _In_opt_ LPCWSTR ConfigPath,
    _In_ LPCWSTR ServiceName);

/*
 * SysmonUninstall - Stop and remove both services
 *   1. Stop Sysmon service
 *   2. Delete Sysmon service
 *   3. Stop SysmonDrv driver service
 *   4. Delete SysmonDrv driver service
 *   5. Clean up registry
 */
SYSMON_STATUS SysmonUninstall(
    _In_ BOOL Force,
    _In_ LPCWSTR ServiceName);

/*
 * SysmonInstallManifest - Install ETW event manifest
 */
SYSMON_STATUS SysmonInstallManifest(void);

/*
 * SysmonUpdateConfig - Parse config file, write to registry, notify driver
 */
SYSMON_STATUS SysmonUpdateConfig(
    _In_ LPCWSTR ConfigFilePath,
    _In_ LPCWSTR ServiceName);

/*
 * SysmonResetConfigDefaults - Restore default configuration values
 */
SYSMON_STATUS SysmonResetConfigDefaults(
    _In_ LPCWSTR ServiceName);

/*
 * SysmonDumpConfiguration - Dump the current persisted configuration
 */
SYSMON_STATUS SysmonDumpConfiguration(
    _In_ LPCWSTR ServiceName);

/*
 * SysmonPrintConfigHelp - Print configuration file help text
 */
SYSMON_STATUS SysmonPrintConfigHelp(void);

/*
 * SysmonPrintSchema - Print schema manifest fragments for the latest or
 * requested schema version. If DumpAll is TRUE, print every available
 * schema manifest in the embedded resource.
 */
SYSMON_STATUS SysmonPrintSchema(
    _In_opt_ LPCWSTR Version,
    _In_ BOOL DumpAll);

/*
 * cli.c - Argument parsing (-i/-u/-c/-m/-s/-d)
 *
 * Original (main function at 0x140088xxx):
 *   No args → StartServiceCtrlDispatcherW
 *   -i [config] → Install service + driver
 *   -u [force] → Uninstall
 *   -c [config] / -c -- → Dump current config, update config, or restore defaults
 *   -m → Install manifest
 *   -s [version|all] → Print schema
 *   -d → Debug foreground mode
 */

#include "../include/cli.h"
#include "../include/clipboard_monitor.h"
#include "../include/installer.h"
#include "../include/service.h"

#include "../include/runtime.hpp"

static void
SysmonPersistAcceptedEula(void)
{
    ScopedRegKey hKey;
    DWORD accepted = 1;

    if (RegCreateKeyExW(
            HKEY_CURRENT_USER,
            L"Software\\Sysinternals\\System Monitor",
            0,
            NULL,
            0,
            KEY_SET_VALUE,
            NULL,
            hKey.put(),
            NULL) == ERROR_SUCCESS) {
        RegSetValueExW(hKey.get(), L"EulaAccepted", 0, REG_DWORD, (const BYTE *)&accepted, sizeof(accepted));
    }
}

/*
 * SysmonParseCommandLine - Parse argc/argv into SYSMON_CLI_ARGS
 */
SYSMON_STATUS SysmonParseCommandLine(int Argc, LPWSTR *Argv, PSYSMON_CLI_ARGS Args)
{
    int i;

    if (!Args) return SYSMON_ERROR_INVALID_PARAM;

    ZeroMemory(Args, sizeof(SYSMON_CLI_ARGS));
    Args->Action = SysmonActionServiceStart;  /* Default: SCM mode */
    Args->ServiceName = SYSMON_SERVICE_NAME;

    if (Argc < 2) {
        return SYSMON_SUCCESS;  /* No args = SCM service start */
    }

    for (i = 1; i < Argc; i++) {
        if (_wcsicmp(Argv[i], L"-i") == 0) {
            Args->Action = SysmonActionInstall;
            /* Optional config file follows */
            if (i + 1 < Argc && Argv[i + 1][0] != L'-') {
                Args->ConfigPath = Argv[++i];
            }
        }
        else if (_wcsicmp(Argv[i], L"-u") == 0) {
            Args->Action = SysmonActionUninstall;
            /* Optional "force" keyword */
            if (i + 1 < Argc && _wcsicmp(Argv[i + 1], L"force") == 0) {
                Args->ForceUninstall = TRUE;
                i++;
            }
        }
        else if (_wcsicmp(Argv[i], L"-accepteula") == 0 ||
                 _wcsicmp(Argv[i], L"/accepteula") == 0) {
            /*
             * Original Sysmon accepts this switch on install paths. The clone
             * currently has no interactive EULA gate, so recognizing it as a
             * no-op keeps command-line compatibility without changing behavior.
             */
            Args->AcceptEula = TRUE;
        }
        else if (_wcsicmp(Argv[i], L"-c") == 0) {
            Args->Action = SysmonActionUpdateConfig;
            if (i + 1 < Argc) {
                if (_wcsicmp(Argv[i + 1], L"--") == 0) {
                    Args->ResetDefaults = TRUE;
                    i++;
                } else if (Argv[i + 1][0] != L'-') {
                    Args->ConfigPath = Argv[++i];
                }
            }
        }
        else if (_wcsicmp(Argv[i], L"-m") == 0) {
            Args->Action = SysmonActionInstallManifest;
        }
        else if (_wcsicmp(Argv[i], L"-s") == 0) {
            Args->Action = SysmonActionPrintSchema;
            if (i + 1 < Argc) {
                if (_wcsicmp(Argv[i + 1], L"-a") == 0 ||
                    _wcsicmp(Argv[i + 1], L"all") == 0) {
                    Args->DumpAll = TRUE;
                    i++;
                } else if (Argv[i + 1][0] != L'-') {
                    Args->SchemaVersion = Argv[++i];
                }
            }
        }
        else if (_wcsicmp(Argv[i], L"-d") == 0) {
            Args->Action = SysmonActionDebugRun;
        }
        else if (_wcsicmp(Argv[i], L"-z") == 0) {
            Args->Action = SysmonActionClipboardHelper;
            if (i + 1 < Argc) {
                Args->ClipboardInstance = Argv[++i];
            } else {
                SysmonReportError(SYSMON_COMPONENT_CLI, 0, "Missing pipe name for -z");
                return SYSMON_ERROR_INVALID_PARAM;
            }
        }
        else if (_wcsicmp(Argv[i], L"-p") == 0) {
            if (i + 1 < Argc) {
                Args->ClipboardParentHandle = (HANDLE)(ULONG_PTR)_wcstoui64(Argv[++i], NULL, 10);
            }
        }
        else if (_wcsicmp(Argv[i], L"-h") == 0 || _wcsicmp(Argv[i], L"--help") == 0 || _wcsicmp(Argv[i], L"-?") == 0) {
            if (i + 1 < Argc && _wcsicmp(Argv[i + 1], L"config") == 0) {
                Args->Action = SysmonActionPrintConfigHelp;
                i++;
            } else {
                SysmonPrintUsage();
                return ERROR_CANCELLED;
            }
        }
        else if (_wcsicmp(Argv[i], L"-n") == 0 && i + 1 < Argc) {
            /* Service name override (undocumented) */
            Args->ServiceName = Argv[++i];
        }
        else {
            SysmonReportError(SYSMON_COMPONENT_CLI, 0,
                "Unknown option: %ls", Argv[i]);
            SysmonPrintUsage();
            return SYSMON_ERROR_INVALID_PARAM;
        }
    }

    return SYSMON_SUCCESS;
}

/*
 * SysmonDispatchAction - Execute the parsed CLI action
 */
SYSMON_STATUS SysmonDispatchAction(PSYSMON_CLI_ARGS Args)
{
    SYSMON_STATUS status;

    if (!Args) return SYSMON_ERROR_INVALID_PARAM;

    if (Args->AcceptEula) {
        SysmonPersistAcceptedEula();
    }

    switch (Args->Action) {
    case SysmonActionInstall:
        status = SysmonInstall(Args->ConfigPath, Args->ServiceName);
        break;

    case SysmonActionUninstall:
        status = SysmonUninstall(Args->ForceUninstall, Args->ServiceName);
        break;

    case SysmonActionUpdateConfig:
        if (Args->ResetDefaults) {
            status = SysmonResetConfigDefaults(Args->ServiceName);
        } else if (Args->ConfigPath != NULL) {
            status = SysmonUpdateConfig(Args->ConfigPath, Args->ServiceName);
        } else {
            status = SysmonDumpConfiguration(Args->ServiceName);
        }
        break;

    case SysmonActionInstallManifest:
        status = SysmonInstallManifest();
        break;

    case SysmonActionPrintSchema:
        status = SysmonPrintSchema(Args->SchemaVersion, Args->DumpAll);
        break;

    case SysmonActionPrintConfigHelp:
        status = SysmonPrintConfigHelp();
        break;

    case SysmonActionDebugRun:
        SysmonLogInfo(SYSMON_COMPONENT_CLI, "Starting in debug mode...");
        status = SysmonServiceRunDirect();
        break;

    case SysmonActionClipboardHelper:
        status = SysmonClipboardHelperRun(Args->ClipboardInstance, Args->ClipboardParentHandle);
        break;

    case SysmonActionServiceStart:
        SysmonPrintUsage();
        status = SYSMON_SUCCESS;
        break;

    default:
        SysmonPrintUsage();
        status = SYSMON_ERROR_INVALID_PARAM;
        break;
    }

    return status;
}

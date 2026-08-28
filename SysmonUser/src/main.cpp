/*
 * main.c - Entry point: CLI dispatch vs SCM service start
 *
 * Original Sysmon behavior:
 *   No arguments → StartServiceCtrlDispatcherW (SCM service mode)
 *   With arguments → CLI mode, parse and dispatch
 */

#include "../include/common.h"
#include "../include/cli.h"
#include "../include/service.h"
#include "../include/installer.h"

#include "../include/runtime.hpp"

/* Entry point: wmain for Unicode argument parsing */
int wmain(int argc, LPWSTR *argv)
{
    SYSMON_CLI_ARGS args;
    SYSMON_STATUS status;

    /* Parse command line */
    status = SysmonParseCommandLine(argc, argv, &args);
    if (status != SYSMON_SUCCESS) {
        return (int)status;
    }

    /* Dispatch based on action */
    if (args.Action == SysmonActionServiceStart) {
        /* No arguments - SCM service mode */
        SERVICE_TABLE_ENTRYW serviceTable[] = {
            { (LPWSTR)SYSMON_SERVICE_NAME, SysmonServiceMain },
            { NULL, NULL }
        };

        if (!StartServiceCtrlDispatcherW(serviceTable)) {
            DWORD err = GetLastError();
            if (err == ERROR_FAILED_SERVICE_CONTROLLER_CONNECT) {
                /* Not running as service - try direct run */
                return (int)SysmonServiceRunDirect();
            }
            SysmonReportError(SYSMON_COMPONENT_SERVICE, err,
                "Failed to start service control dispatcher");
            return (int)err;
        }
        return 0;
    }

    /* CLI mode */
    status = SysmonDispatchAction(&args);
    return (int)status;
}

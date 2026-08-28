#pragma once
/*
 * cli.h - CLI argument parsing, subcommand dispatch
 */

#include "common.h"

/* CLI action types */
typedef enum _SYSMON_CLI_ACTION {
    SysmonActionNone = 0,
    SysmonActionInstall,        /* -i [config] */
    SysmonActionUninstall,      /* -u [force] */
    SysmonActionUpdateConfig,   /* -c [config] / -c -- */
    SysmonActionInstallManifest,/* -m */
    SysmonActionPrintSchema,    /* -s [<version>|all] */
    SysmonActionPrintConfigHelp,/* -? config */
    SysmonActionDebugRun,       /* -d */
    SysmonActionClipboardHelper,/* -z <pipe> */
    SysmonActionServiceStart    /* no args - SCM service start */
} SYSMON_CLI_ACTION;

/* Parsed CLI arguments */
typedef struct _SYSMON_CLI_ARGS {
    SYSMON_CLI_ACTION Action;
    LPWSTR ConfigPath;      /* -i or -c config file path */
    BOOL ForceUninstall;    /* -u force */
    BOOL AcceptEula;        /* -accepteula */
    BOOL DumpAll;           /* -s all / -s -a */
    BOOL ResetDefaults;     /* -c -- */
    LPCWSTR SchemaVersion;  /* -s <version> */
    LPCWSTR ClipboardInstance; /* -z <pipe> */
    HANDLE ClipboardParentHandle; /* -p <HandleValue> */
    LPCWSTR ServiceName;    /* Service name override (default: Sysmon) */
} SYSMON_CLI_ARGS, *PSYSMON_CLI_ARGS;

/*
 * SysmonParseCommandLine - Parse argc/argv into SYSMON_CLI_ARGS
 *   Returns ERROR_SUCCESS on success, error code on failure
 */
SYSMON_STATUS SysmonParseCommandLine(
    _In_ int Argc,
    _In_ LPWSTR *Argv,
    _Out_ PSYSMON_CLI_ARGS Args);

/*
 * SysmonDispatchAction - Execute the parsed CLI action
 */
SYSMON_STATUS SysmonDispatchAction(_In_ PSYSMON_CLI_ARGS Args);

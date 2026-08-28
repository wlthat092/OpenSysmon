/*
 * installer.c - Service/driver installation and uninstallation
 *
 * Original (sub_140089290 for CreateServiceW, sub_140087940 for uninstall):
 *   Install:
 *     1. OpenSCManagerW
 *     2. CreateServiceW for SysmonDrv (kernel driver, SERVICE_KERNEL_DRIVER)
 *     3. CreateServiceW for Sysmon (win32 own process, auto-start)
 *     4. Write registry Parameters
 *     5. Configure minifilter instance
 *     6. Start service
 *   Uninstall:
 *     1. OpenServiceW + ControlService(STOP) + DeleteService for Sysmon
 *     2. OpenServiceW + ControlService(STOP) + DeleteService for SysmonDrv
 *     3. Cleanup registry
 */

#include "../include/installer.h"
#include "../include/config.h"
#include "../include/protocol.h"
#include "../include/output.h"

/* SysmonDrv binary path (in System32\drivers) */
#define SYSMON_DRIVER_PATH      L"%SystemRoot%\\System32\\drivers\\SysmonDrv.sys"
#define SYSMON_EXE_PATH         L"%SystemRoot%\\System32\\Sysmon.exe"

/* Registry path for minifilter instance */
#define SYSMON_FILTER_REG_PARENT_PATH  L"System\\CurrentControlSet\\Services\\SysmonDrv\\Instances"
#define SYSMON_FILTER_REG_CHILD_PATH   L"System\\CurrentControlSet\\Services\\SysmonDrv\\Instances\\Sysmon Instance"
#define SYSMON_FILTER_GROUP     L"FSFilter Activity Monitor"
#define SYSMON_SCHEMA_RESOURCE_NAME L"Sysmonschema"
#define SYSMON_SCHEMA_RESOURCE_TYPE L"XML"
#define SYSMON_SCHEMA_RCDATA_ID 200
#define SYSMON_EVENT_MANIFEST_RCDATA_ID 201

static VOID
SysmonTryEmitPersistedConfigChangeEvent(
    _In_ LPCWSTR ServiceName,
    _In_opt_ LPCWSTR DefaultConfiguration);

static DWORD
SysmonQueryServiceCurrentState(
    _In_ SC_HANDLE Service,
    _Out_ LPDWORD CurrentState)
{
    SERVICE_STATUS_PROCESS statusProcess;
    DWORD bytesNeeded = 0;

    if (CurrentState == NULL) {
        return ERROR_INVALID_PARAMETER;
    }

    *CurrentState = SERVICE_STOPPED;
    ZeroMemory(&statusProcess, sizeof(statusProcess));
    if (!QueryServiceStatusEx(
            Service,
            SC_STATUS_PROCESS_INFO,
            (LPBYTE)&statusProcess,
            sizeof(statusProcess),
            &bytesNeeded)) {
        return GetLastError();
    }

    *CurrentState = statusProcess.dwCurrentState;
    return ERROR_SUCCESS;
}

static DWORD
SysmonWaitForServiceStopped(
    _In_ SC_HANDLE Service,
    _In_ LPCWSTR ServiceName,
    _In_ DWORD TimeoutMs)
{
    DWORD waitedMs = 0;
    DWORD currentState = SERVICE_STOPPED;
    DWORD error;

    while (waitedMs <= TimeoutMs) {
        error = SysmonQueryServiceCurrentState(Service, &currentState);
        if (error != ERROR_SUCCESS) {
            return error;
        }

        if (currentState == SERVICE_STOPPED) {
            return ERROR_SUCCESS;
        }

        if (currentState != SERVICE_STOP_PENDING &&
            currentState != SERVICE_RUNNING &&
            currentState != SERVICE_START_PENDING) {
            break;
        }

        Sleep(1000);
        waitedMs += 1000;
    }

    SysmonLogWarning(
        SYSMON_COMPONENT_INSTALLER,
        "%ls failed to stop within %lu ms (state=%lu)",
        ServiceName,
        (unsigned long)TimeoutMs,
        (unsigned long)currentState);
    return ERROR_TIMEOUT;
}

static DWORD
SysmonWaitForServiceDeletion(
    _In_ SC_HANDLE ScManager,
    _In_ LPCWSTR ServiceName,
    _In_ DWORD TimeoutMs)
{
    DWORD waitedMs = 0;

    while (waitedMs <= TimeoutMs) {
        SC_HANDLE service = OpenServiceW(ScManager, ServiceName, SERVICE_QUERY_STATUS);
        if (service == NULL) {
            DWORD error = GetLastError();
            if (error == ERROR_SERVICE_DOES_NOT_EXIST) {
                return ERROR_SUCCESS;
            }
            return error;
        }

        CloseServiceHandle(service);
        Sleep(500);
        waitedMs += 500;
    }

    return ERROR_SERVICE_MARKED_FOR_DELETE;
}

static DWORD
SysmonStopAndDeleteService(
    _In_ SC_HANDLE ScManager,
    _In_ LPCWSTR ServiceName)
{
    SC_HANDLE service;
    SERVICE_STATUS status;
    DWORD error;

    service = OpenServiceW(
        ScManager,
        ServiceName,
        SERVICE_STOP | SERVICE_QUERY_STATUS | DELETE);
    if (service == NULL) {
        error = GetLastError();
        if (error == ERROR_SERVICE_DOES_NOT_EXIST) {
            return ERROR_SUCCESS;
        }
        return error;
    }

    ZeroMemory(&status, sizeof(status));
    if (!ControlService(service, SERVICE_CONTROL_STOP, &status)) {
        error = GetLastError();
        if (error != ERROR_SERVICE_NOT_ACTIVE) {
            CloseServiceHandle(service);
            return error;
        }
    }

    error = SysmonWaitForServiceStopped(service, ServiceName, 120000);
    if (error != ERROR_SUCCESS && error != ERROR_SERVICE_NOT_ACTIVE) {
        CloseServiceHandle(service);
        return error;
    }

    if (!DeleteService(service)) {
        error = GetLastError();
        if (error != ERROR_SERVICE_MARKED_FOR_DELETE) {
            CloseServiceHandle(service);
            return error;
        }
    }

    CloseServiceHandle(service);
    return SysmonWaitForServiceDeletion(ScManager, ServiceName, 30000);
}

static SYSMON_STATUS
SysmonUninstallManifest(void);

static DWORD
SysmonRunProcessAndWait(
    _In_opt_ LPCWSTR ApplicationName,
    _In_ LPCWSTR CommandLine)
{
    STARTUPINFOW si;
    PROCESS_INFORMATION pi;
    WCHAR commandLineBuffer[1024];
    DWORD exitCode = ERROR_GEN_FAILURE;

    ZeroMemory(&si, sizeof(si));
    ZeroMemory(&pi, sizeof(pi));
    si.cb = sizeof(si);

    if (wcscpy_s(
            commandLineBuffer,
            RTL_NUMBER_OF(commandLineBuffer),
            CommandLine) != 0) {
        return ERROR_BUFFER_OVERFLOW;
    }

    if (!CreateProcessW(
            ApplicationName,
            commandLineBuffer,
            NULL,
            NULL,
            FALSE,
            CREATE_NO_WINDOW,
            NULL,
            NULL,
            &si,
            &pi)) {
        return GetLastError();
    }

    WaitForSingleObject(pi.hProcess, INFINITE);
    if (!GetExitCodeProcess(pi.hProcess, &exitCode)) {
        exitCode = GetLastError();
    }

    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    return exitCode;
}

static BOOL
SysmonBuildSystemToolPath(
    _In_z_ LPCWSTR ToolName,
    _Out_writes_(BufferChars) LPWSTR Buffer,
    _In_ DWORD BufferChars)
{
    WCHAR systemDirectory[MAX_PATH];
    UINT systemDirLength;

    if (ToolName == NULL || Buffer == NULL || BufferChars == 0) {
        return FALSE;
    }

    systemDirLength = GetSystemDirectoryW(systemDirectory, RTL_NUMBER_OF(systemDirectory));
    if (systemDirLength == 0 || systemDirLength >= RTL_NUMBER_OF(systemDirectory)) {
        return FALSE;
    }

    return SUCCEEDED(_snwprintf_s(
        Buffer,
        BufferChars,
        _TRUNCATE,
        L"%ls\\%ls",
        systemDirectory,
        ToolName));
}

static SYSMON_STATUS
SysmonWriteManifestFile(
    _Out_writes_(ManifestPathChars) LPWSTR ManifestPath,
    _In_ DWORD ManifestPathChars)
{
    WCHAR tempPath[MAX_PATH];
    WCHAR manifestPath[MAX_PATH];
    HANDLE manifestFile = INVALID_HANDLE_VALUE;
    DWORD bytesWritten;
    HMODULE moduleHandle;
    HRSRC resourceInfo;
    HGLOBAL resourceData;
    DWORD resourceSize;
    LPCVOID resourceBytes;
    DWORD status;

    if (ManifestPath == NULL || ManifestPathChars == 0) {
        return ERROR_INVALID_PARAMETER;
    }

    if (GetTempPathW(RTL_NUMBER_OF(tempPath), tempPath) == 0) {
        return GetLastError();
    }

    if (GetTempFileNameW(tempPath, L"SYM", 0, manifestPath) == 0) {
        return GetLastError();
    }

    manifestFile = CreateFileW(
        manifestPath,
        GENERIC_WRITE,
        0,
        NULL,
        CREATE_ALWAYS,
        FILE_ATTRIBUTE_TEMPORARY,
        NULL);
    if (manifestFile == INVALID_HANDLE_VALUE) {
        DeleteFileW(manifestPath);
        return GetLastError();
    }

    moduleHandle = GetModuleHandleW(NULL);
    if (moduleHandle == NULL) {
        status = GetLastError();
        CloseHandle(manifestFile);
        DeleteFileW(manifestPath);
        return status != ERROR_SUCCESS ? status : ERROR_INVALID_HANDLE;
    }

    resourceInfo = FindResourceW(
        moduleHandle,
        MAKEINTRESOURCEW(SYSMON_EVENT_MANIFEST_RCDATA_ID),
        RT_RCDATA);
    if (resourceInfo == NULL) {
        status = GetLastError();
        CloseHandle(manifestFile);
        DeleteFileW(manifestPath);
        return status != ERROR_SUCCESS ? status : ERROR_RESOURCE_DATA_NOT_FOUND;
    }

    resourceSize = SizeofResource(moduleHandle, resourceInfo);
    resourceData = LoadResource(moduleHandle, resourceInfo);
    resourceBytes = (resourceData != NULL) ? LockResource(resourceData) : NULL;
    if (resourceBytes == NULL || resourceSize == 0) {
        status = GetLastError();
        CloseHandle(manifestFile);
        DeleteFileW(manifestPath);
        return status != ERROR_SUCCESS ? status : ERROR_RESOURCE_DATA_NOT_FOUND;
    }

    if (!WriteFile(
            manifestFile,
            resourceBytes,
            resourceSize,
            &bytesWritten,
            NULL) ||
        bytesWritten != resourceSize) {
        status = GetLastError();
        CloseHandle(manifestFile);
        DeleteFileW(manifestPath);
        return status != ERROR_SUCCESS ? status : ERROR_WRITE_FAULT;
    }

    CloseHandle(manifestFile);

    if (wcscpy_s(ManifestPath, ManifestPathChars, manifestPath) != 0) {
        DeleteFileW(manifestPath);
        return ERROR_BUFFER_OVERFLOW;
    }

    return SYSMON_SUCCESS;
}

static BOOL
SysmonUpdateServiceConfigIfNeeded(
    _In_ SC_HANDLE Service,
    _In_ DWORD ServiceType,
    _In_ DWORD StartType,
    _In_ LPCWSTR BinaryPath,
    _In_opt_ LPCWSTR LoadOrderGroup,
    _In_opt_ LPCWSTR ServiceStartName)
{
    return ChangeServiceConfigW(
        Service,
        ServiceType,
        StartType,
        SERVICE_NO_CHANGE,
        BinaryPath,
        LoadOrderGroup,
        NULL,
        NULL,
        ServiceStartName,
        NULL,
        NULL);
}

static BOOL
SysmonConfigureServiceRecovery(
    _In_ SC_HANDLE Service)
{
    SC_ACTION actions[3];
    SERVICE_FAILURE_ACTIONSW failureActions;
    SERVICE_FAILURE_ACTIONS_FLAG failureFlag;

    if (Service == NULL) {
        SetLastError(ERROR_INVALID_HANDLE);
        return FALSE;
    }

    ZeroMemory(actions, sizeof(actions));
    actions[0].Type = SC_ACTION_RESTART;
    actions[0].Delay = 5000;
    actions[1].Type = SC_ACTION_RESTART;
    actions[1].Delay = 5000;
    actions[2].Type = SC_ACTION_RESTART;
    actions[2].Delay = 15000;

    ZeroMemory(&failureActions, sizeof(failureActions));
    failureActions.dwResetPeriod = 86400;
    failureActions.cActions = ARRAYSIZE(actions);
    failureActions.lpsaActions = actions;

    if (!ChangeServiceConfig2W(
            Service,
            SERVICE_CONFIG_FAILURE_ACTIONS,
            &failureActions)) {
        return FALSE;
    }

    failureFlag.fFailureActionsOnNonCrashFailures = TRUE;
    if (!ChangeServiceConfig2W(
            Service,
            SERVICE_CONFIG_FAILURE_ACTIONS_FLAG,
            &failureFlag)) {
        return FALSE;
    }

    return TRUE;
}

static LONG
SysmonConfigureMinifilterInstanceKeys(VOID)
{
    HKEY parentKey = NULL;
    HKEY childKey = NULL;
    LONG result;
    DWORD flags = 0;
    static const WCHAR instanceName[] = L"Sysmon Instance";

    result = RegCreateKeyExW(
        HKEY_LOCAL_MACHINE,
        SYSMON_FILTER_REG_PARENT_PATH,
        0,
        NULL,
        0,
        KEY_WRITE,
        NULL,
        &parentKey,
        NULL);
    if (result != ERROR_SUCCESS) {
        goto cleanup;
    }

    result = RegSetValueExW(
        parentKey,
        L"DefaultInstance",
        0,
        REG_SZ,
        (const BYTE*)instanceName,
        (DWORD)(sizeof(instanceName)));
    if (result != ERROR_SUCCESS) {
        goto cleanup;
    }

    result = RegCreateKeyExW(
        HKEY_LOCAL_MACHINE,
        SYSMON_FILTER_REG_CHILD_PATH,
        0,
        NULL,
        0,
        KEY_WRITE,
        NULL,
        &childKey,
        NULL);
    if (result != ERROR_SUCCESS) {
        goto cleanup;
    }

    result = RegSetValueExW(
        childKey,
        L"Altitude",
        0,
        REG_SZ,
        (const BYTE*)SYSMON_FILTER_ALTITUDE,
        (DWORD)((wcslen(SYSMON_FILTER_ALTITUDE) + 1) * sizeof(WCHAR)));
    if (result != ERROR_SUCCESS) {
        goto cleanup;
    }

    result = RegSetValueExW(
        childKey,
        L"Flags",
        0,
        REG_DWORD,
        (const BYTE*)&flags,
        sizeof(flags));

cleanup:
    if (childKey != NULL) {
        RegCloseKey(childKey);
    }
    if (parentKey != NULL) {
        RegCloseKey(parentKey);
    }

    return result;
}

static void
SysmonPrintLabelValue(
    _In_z_ LPCWSTR Label,
    _In_z_ LPCWSTR Value)
{
    fwprintf(stdout, L"%-34ls%ls\n", Label, Value);
}

static void
SysmonPrintLabelDword(
    _In_z_ LPCWSTR Label,
    _In_ DWORD Value)
{
    fwprintf(stdout, L"%-34ls%lu\n", Label, (unsigned long)Value);
}

static LPCWSTR
SysmonEnabledDisabledString(
    _In_ BOOL Enabled)
{
    return Enabled ? L"enabled" : L"disabled";
}

static void
SysmonAppendHashingAlgorithmName(
    _Inout_updates_(BufferChars) PWCHAR Buffer,
    _In_ size_t BufferChars,
    _In_z_ LPCWSTR Name,
    _Inout_ PBOOL First)
{
    if (Buffer == NULL || BufferChars == 0 || Name == NULL || First == NULL) {
        return;
    }

    if (!*First) {
        wcscat_s(Buffer, BufferChars, L",");
    }
    wcscat_s(Buffer, BufferChars, Name);
    *First = FALSE;
}

static void
SysmonFormatHashingAlgorithms(
    _In_ DWORD HashingAlgorithm,
    _Out_writes_(BufferChars) PWCHAR Buffer,
    _In_ size_t BufferChars)
{
    BOOL first = TRUE;

    if (Buffer == NULL || BufferChars == 0) {
        return;
    }

    Buffer[0] = L'\0';
    if (HashingAlgorithm == 0) {
        wcscpy_s(Buffer, BufferChars, L"None");
        return;
    }

    if ((HashingAlgorithm & SYSMON_HASH_MD5) != 0) {
        SysmonAppendHashingAlgorithmName(Buffer, BufferChars, L"MD5", &first);
    }
    if ((HashingAlgorithm & SYSMON_HASH_SHA1) != 0) {
        SysmonAppendHashingAlgorithmName(Buffer, BufferChars, L"SHA1", &first);
    }
    if ((HashingAlgorithm & SYSMON_HASH_SHA256) != 0) {
        SysmonAppendHashingAlgorithmName(Buffer, BufferChars, L"SHA256", &first);
    }
    if ((HashingAlgorithm & SYSMON_HASH_IMPHASH) != 0) {
        SysmonAppendHashingAlgorithmName(Buffer, BufferChars, L"IMPHASH", &first);
    }

    if (Buffer[0] == L'\0') {
        wcscpy_s(Buffer, BufferChars, L"None");
    }
}

static void
SysmonPrintRuleConfigurationSummary(
    _In_ const SYSMON_CONFIG *Config)
{
    SYSMON_RULES_BLOB_INFO blobInfo;
    SYSMON_STATUS status;

    if (Config->Rules == NULL || Config->RulesSize == 0) {
        fwprintf(stdout, L"No rules installed\n");
        return;
    }

    status = SysmonQueryRuleBlobInfo(Config->Rules, Config->RulesSize, &blobInfo);
    if (status != SYSMON_SUCCESS) {
        fwprintf(stdout, L"Failed to open rules configuration with last ruleError %u\n",
            (unsigned long)status);
        return;
    }

    if (blobInfo.EventRuleCount == 0 || blobInfo.RuleCount == 0) {
        fwprintf(stdout, L"No rules installed\n");
        return;
    }

    fwprintf(stdout,
        L"Rule configuration (binary version %u.%02u):\n",
        blobInfo.MajorVersion,
        blobInfo.MinorVersion);
    fwprintf(stdout,
        L"  groups=%u eventRules=%u rules=%u expressions=%u bytes=%u\n",
        blobInfo.GroupCount,
        blobInfo.EventRuleCount,
        blobInfo.RuleCount,
        blobInfo.ExpressionCount,
        blobInfo.TotalSize);
}

/*
 * SysmonInstall - Install Sysmon service + driver
 */
SYSMON_STATUS SysmonInstall(LPCWSTR ConfigPath, LPCWSTR ServiceName)
{
    SC_HANDLE scManager = NULL;
    SC_HANDLE driverService = NULL;
    SC_HANDLE sysmonService = NULL;
    WCHAR exePath[MAX_PATH];
    DWORD err = NO_ERROR;
    SYSMON_CONFIG parsedConfig;
    SYSMON_STATUS status = SYSMON_SUCCESS;
    LPCWSTR targetServiceName = (ServiceName != NULL) ? ServiceName : SYSMON_SERVICE_NAME;

    SysmonLogInfo(SYSMON_COMPONENT_INSTALLER, "Installing Sysmon...");
    ZeroMemory(&parsedConfig, sizeof(parsedConfig));

    /* Open SCM */
    scManager = OpenSCManagerW(NULL, NULL, SC_MANAGER_ALL_ACCESS);
    if (scManager == NULL) {
        err = GetLastError();
        SysmonReportError(SYSMON_COMPONENT_INSTALLER, err, "OpenSCManager failed");
        goto cleanup;
    }

    /* Create SysmonDrv driver service */
    driverService = CreateServiceW(
        scManager,
        SYSMON_DRIVER_SERVICE_NAME,
        SYSMON_DRIVER_SERVICE_NAME,
        SERVICE_ALL_ACCESS,
        SERVICE_FILE_SYSTEM_DRIVER,
        SERVICE_SYSTEM_START,
        SERVICE_ERROR_NORMAL,
        SYSMON_DRIVER_PATH,
        SYSMON_FILTER_GROUP, NULL, NULL, NULL, NULL);

    if (driverService == NULL) {
        err = GetLastError();
        if (err == ERROR_SERVICE_MARKED_FOR_DELETE) {
            DWORD waitErr = SysmonWaitForServiceDeletion(
                scManager,
                SYSMON_DRIVER_SERVICE_NAME,
                30000);
            if (waitErr == ERROR_SUCCESS) {
                driverService = CreateServiceW(
                    scManager,
                    SYSMON_DRIVER_SERVICE_NAME,
                    SYSMON_DRIVER_SERVICE_NAME,
                    SERVICE_ALL_ACCESS,
                    SERVICE_FILE_SYSTEM_DRIVER,
                    SERVICE_SYSTEM_START,
                    SERVICE_ERROR_NORMAL,
                    SYSMON_DRIVER_PATH,
                    SYSMON_FILTER_GROUP, NULL, NULL, NULL, NULL);
                if (driverService == NULL) {
                    err = GetLastError();
                } else {
                    err = NO_ERROR;
                }
            } else {
                err = waitErr;
            }
        }

        if (err == ERROR_SERVICE_EXISTS) {
            SysmonLogInfo(SYSMON_COMPONENT_INSTALLER, "SysmonDrv service already exists");
            driverService = OpenServiceW(scManager, SYSMON_DRIVER_SERVICE_NAME, SERVICE_ALL_ACCESS);
            if (driverService == NULL) {
                err = GetLastError();
                SysmonReportError(SYSMON_COMPONENT_INSTALLER, err,
                    "Failed to open existing SysmonDrv service");
                goto cleanup;
            }

            if (!SysmonUpdateServiceConfigIfNeeded(
                    driverService,
                    SERVICE_FILE_SYSTEM_DRIVER,
                    SERVICE_SYSTEM_START,
                    SYSMON_DRIVER_PATH,
                    SYSMON_FILTER_GROUP,
                    NULL)) {
                err = GetLastError();
                SysmonReportError(SYSMON_COMPONENT_INSTALLER, err,
                    "Failed to update SysmonDrv driver service configuration");
                goto cleanup;
            }
        } else {
            SysmonReportError(SYSMON_COMPONENT_INSTALLER, err,
                "Failed to create SysmonDrv driver service");
            goto cleanup;
        }
    }

    /* Write minifilter instance registry keys */
    {
        LONG result = SysmonConfigureMinifilterInstanceKeys();
        if (result != ERROR_SUCCESS) {
            err = (DWORD)result;
            SysmonReportError(SYSMON_COMPONENT_INSTALLER, err,
                "Failed to configure SysmonDrv minifilter instance registry keys");
            goto cleanup;
        }
    }

    /* Get our exe path */
    if (!ExpandEnvironmentStringsW(SYSMON_EXE_PATH, exePath, MAX_PATH)) {
        wcscpy_s(exePath, MAX_PATH, L"C:\\Windows\\System32\\Sysmon.exe");
    }

    /* Create Sysmon user service */
    sysmonService = CreateServiceW(
        scManager,
        targetServiceName,
        targetServiceName,
        SERVICE_ALL_ACCESS,
        SERVICE_WIN32_OWN_PROCESS,
        SERVICE_AUTO_START,
        SERVICE_ERROR_NORMAL,
        exePath,
        NULL, NULL, NULL, L"LocalSystem", NULL);

    if (sysmonService == NULL) {
        err = GetLastError();
        if (err == ERROR_SERVICE_MARKED_FOR_DELETE) {
            DWORD waitErr = SysmonWaitForServiceDeletion(
                scManager,
                targetServiceName,
                30000);
            if (waitErr == ERROR_SUCCESS) {
                sysmonService = CreateServiceW(
                    scManager,
                    targetServiceName,
                    targetServiceName,
                    SERVICE_ALL_ACCESS,
                    SERVICE_WIN32_OWN_PROCESS,
                    SERVICE_AUTO_START,
                    SERVICE_ERROR_NORMAL,
                    exePath,
                    NULL, NULL, NULL, L"LocalSystem", NULL);
                if (sysmonService == NULL) {
                    err = GetLastError();
                } else {
                    err = NO_ERROR;
                }
            } else {
                err = waitErr;
            }
        }

        if (err == ERROR_SERVICE_EXISTS) {
            SysmonLogInfo(SYSMON_COMPONENT_INSTALLER, "Sysmon service already exists");
            sysmonService = OpenServiceW(scManager, targetServiceName, SERVICE_ALL_ACCESS);
            if (sysmonService == NULL) {
                err = GetLastError();
                SysmonReportError(SYSMON_COMPONENT_INSTALLER, err,
                    "Failed to open existing Sysmon service");
                goto cleanup;
            }

            if (!SysmonUpdateServiceConfigIfNeeded(
                    sysmonService,
                    SERVICE_WIN32_OWN_PROCESS,
                    SERVICE_AUTO_START,
                    exePath,
                    NULL,
                    L"LocalSystem")) {
                err = GetLastError();
                SysmonReportError(SYSMON_COMPONENT_INSTALLER, err,
                    "Failed to update Sysmon service configuration");
                goto cleanup;
            }
        } else {
            SysmonReportError(SYSMON_COMPONENT_INSTALLER, err,
                "Failed to create Sysmon service");
            goto cleanup;
        }
    }

    if (!SysmonConfigureServiceRecovery(sysmonService)) {
        err = GetLastError();
        SysmonReportError(SYSMON_COMPONENT_INSTALLER, err,
            "Failed to configure Sysmon service recovery policy");
        goto cleanup;
    }

    /* Write default registry parameters */
    {
        HKEY hKey;
        WCHAR regPath[512];
        _snwprintf_s(regPath, _countof(regPath), _TRUNCATE,
            L"System\\CurrentControlSet\\Services\\%s\\Parameters",
            targetServiceName);

        LONG result = RegCreateKeyExW(HKEY_LOCAL_MACHINE, regPath,
            0, NULL, 0, KEY_WRITE, NULL, &hKey, NULL);
        if (result == ERROR_SUCCESS) {
            /* Write default signing queue size */
            DWORD signingQueueSize = 1000;
            RegSetValueExW(hKey, L"SigningQueueSize", 0, REG_DWORD,
                (BYTE*)&signingQueueSize, sizeof(DWORD));

            RegCloseKey(hKey);
        }
    }

    status = SysmonInstallManifest();
    if (status != SYSMON_SUCCESS) {
        err = status;
        SysmonReportError(SYSMON_COMPONENT_INSTALLER, status,
            "Failed to install Microsoft-Windows-Sysmon manifest");
        goto cleanup;
    }

    if (ConfigPath != NULL) {
        status = SysmonParseXmlConfig(ConfigPath, &parsedConfig);
        if (status != SYSMON_SUCCESS) {
            err = status;
            SysmonReportError(SYSMON_COMPONENT_INSTALLER, status,
                "Failed to parse config file during install: %ls", ConfigPath);
            goto cleanup;
        }

        status = SysmonConfigPersistCompiled(targetServiceName, ConfigPath, &parsedConfig);
        if (status != SYSMON_SUCCESS) {
            err = status;
            SysmonReportError(SYSMON_COMPONENT_INSTALLER, status,
                "Failed to persist configuration during install: %ls", ConfigPath);
            goto cleanup;
        }
    }

    SysmonTryEmitPersistedConfigChangeEvent(
        targetServiceName,
        (ConfigPath != NULL && ConfigPath[0] != L'\0') ? NULL : GetCommandLineW());

    /* Start the driver immediately so user mode can connect without reboot. */
    if (driverService != NULL) {
        if (StartServiceW(driverService, 0, NULL)) {
            SysmonLogInfo(SYSMON_COMPONENT_INSTALLER, "SysmonDrv service started");
        } else {
            err = GetLastError();
            if (err != ERROR_SERVICE_ALREADY_RUNNING) {
                SysmonReportError(SYSMON_COMPONENT_INSTALLER, err,
                    "Failed to start SysmonDrv service");
                goto cleanup;
            }
        }
    }

    /* Start the Sysmon service */
    if (sysmonService != NULL) {
        if (StartServiceW(sysmonService, 0, NULL)) {
            SysmonLogInfo(SYSMON_COMPONENT_INSTALLER, "Sysmon service started");
        } else {
            err = GetLastError();
            if (err != ERROR_SERVICE_ALREADY_RUNNING) {
                SysmonReportError(SYSMON_COMPONENT_INSTALLER, err,
                    "Failed to start Sysmon service");
                goto cleanup;
            }
        }
    }

    SysmonLogInfo(SYSMON_COMPONENT_INSTALLER,
        "Sysmon installed successfully. Use 'Sysmon.exe -c <config>' to apply rules.");

cleanup:
    SysmonConfigFree(&parsedConfig);
    if (driverService) CloseServiceHandle(driverService);
    if (sysmonService) CloseServiceHandle(sysmonService);
    if (scManager) CloseServiceHandle(scManager);
    return err;
}

/*
 * SysmonUninstall - Stop and remove both services
 */
SYSMON_STATUS SysmonUninstall(BOOL Force, LPCWSTR ServiceName)
{
    SC_HANDLE scManager = NULL;
    DWORD err = NO_ERROR;
    SYSMON_STATUS manifestStatus;
    LPCWSTR targetServiceName = (ServiceName != NULL) ? ServiceName : SYSMON_SERVICE_NAME;

    UNREFERENCED_PARAMETER(Force);

    SysmonLogInfo(SYSMON_COMPONENT_INSTALLER, "Uninstalling Sysmon...");

    scManager = OpenSCManagerW(NULL, NULL, SC_MANAGER_ALL_ACCESS);
    if (scManager == NULL) {
        err = GetLastError();
        SysmonReportError(SYSMON_COMPONENT_INSTALLER, err, "OpenSCManager failed");
        return err;
    }

    err = SysmonStopAndDeleteService(scManager, targetServiceName);
    if (err != NO_ERROR) {
        SysmonReportError(
            SYSMON_COMPONENT_INSTALLER,
            err,
            "Failed to stop/delete Sysmon service");
    } else {
        SysmonLogInfo(SYSMON_COMPONENT_INSTALLER, "Sysmon service deleted");
    }

    {
        DWORD driverErr = SysmonStopAndDeleteService(scManager, SYSMON_DRIVER_SERVICE_NAME);
        if (driverErr != NO_ERROR) {
            SysmonReportError(
                SYSMON_COMPONENT_INSTALLER,
                driverErr,
                "Failed to stop/delete SysmonDrv service");
            if (err == NO_ERROR) {
                err = driverErr;
            }
        } else {
            SysmonLogInfo(SYSMON_COMPONENT_INSTALLER, "SysmonDrv service deleted");
        }
    }

    /* Clean up registry parameters */
    {
        WCHAR regPath[512];
        _snwprintf_s(regPath, _countof(regPath), _TRUNCATE,
            L"System\\CurrentControlSet\\Services\\%s\\Parameters",
            targetServiceName);
        RegDeleteKeyW(HKEY_LOCAL_MACHINE, regPath);
    }

    /* Clean up minifilter instance tree */
    RegDeleteTreeW(HKEY_LOCAL_MACHINE, SYSMON_FILTER_REG_PARENT_PATH);

    manifestStatus = SysmonUninstallManifest();
    if (manifestStatus != SYSMON_SUCCESS) {
        SysmonReportError(
            SYSMON_COMPONENT_INSTALLER,
            manifestStatus,
            "Failed to uninstall Microsoft-Windows-Sysmon manifest");
        if (err == NO_ERROR) {
            err = manifestStatus;
        }
    }

    CloseServiceHandle(scManager);
    SysmonLogInfo(SYSMON_COMPONENT_INSTALLER, "Sysmon uninstalled successfully");
    return err;
}

/*
 * SysmonInstallManifest - Install ETW event manifest
 */
SYSMON_STATUS SysmonInstallManifest(void)
{
    WCHAR manifestPath[MAX_PATH];
    WCHAR wevtutilPath[MAX_PATH];
    WCHAR uninstallCommand[1200];
    WCHAR installCommand[1200];
    DWORD exitCode;
    SYSMON_STATUS status;

    status = SysmonWriteManifestFile(manifestPath, RTL_NUMBER_OF(manifestPath));
    if (status != SYSMON_SUCCESS) {
        SysmonReportError(SYSMON_COMPONENT_INSTALLER, status,
            "Failed to write temporary ETW manifest");
        return status;
    }

    if (!SysmonBuildSystemToolPath(L"wevtutil.exe", wevtutilPath, RTL_NUMBER_OF(wevtutilPath))) {
        DeleteFileW(manifestPath);
        return ERROR_PATH_NOT_FOUND;
    }

    _snwprintf_s(
        uninstallCommand,
        RTL_NUMBER_OF(uninstallCommand),
        _TRUNCATE,
        L"wevtutil.exe um \"%ls\"",
        manifestPath);
    exitCode = SysmonRunProcessAndWait(wevtutilPath, uninstallCommand);
    if (exitCode != ERROR_SUCCESS) {
        SysmonLogInfo(
            SYSMON_COMPONENT_INSTALLER,
            "Manifest uninstall returned %lu; continuing with install",
            (unsigned long)exitCode);
    }

    _snwprintf_s(
        installCommand,
        RTL_NUMBER_OF(installCommand),
        _TRUNCATE,
        L"wevtutil.exe im \"%ls\"",
        manifestPath);
    exitCode = SysmonRunProcessAndWait(wevtutilPath, installCommand);
    DeleteFileW(manifestPath);

    if (exitCode != ERROR_SUCCESS) {
        SysmonReportError(
            SYSMON_COMPONENT_INSTALLER,
            exitCode,
            "wevtutil manifest install failed");
        return exitCode;
    }

    SysmonLogInfo(
        SYSMON_COMPONENT_INSTALLER,
        "Microsoft-Windows-Sysmon manifest installed");
    return SYSMON_SUCCESS;
}

SYSMON_STATUS
SysmonUninstallManifest(void)
{
    WCHAR manifestPath[MAX_PATH];
    WCHAR wevtutilPath[MAX_PATH];
    WCHAR uninstallCommand[1200];
    DWORD exitCode;
    SYSMON_STATUS status;

    status = SysmonWriteManifestFile(manifestPath, RTL_NUMBER_OF(manifestPath));
    if (status != SYSMON_SUCCESS) {
        return status;
    }

    if (!SysmonBuildSystemToolPath(L"wevtutil.exe", wevtutilPath, RTL_NUMBER_OF(wevtutilPath))) {
        DeleteFileW(manifestPath);
        return ERROR_PATH_NOT_FOUND;
    }

    _snwprintf_s(
        uninstallCommand,
        RTL_NUMBER_OF(uninstallCommand),
        _TRUNCATE,
        L"wevtutil.exe um \"%ls\"",
        manifestPath);
    exitCode = SysmonRunProcessAndWait(wevtutilPath, uninstallCommand);
    DeleteFileW(manifestPath);

    if (exitCode != ERROR_SUCCESS) {
        return exitCode;
    }

    SysmonLogInfo(
        SYSMON_COMPONENT_INSTALLER,
        "Microsoft-Windows-Sysmon manifest uninstalled");
    return SYSMON_SUCCESS;
}

/*
 * SysmonNotifyConfigChange - Notify the running driver/service about config updates
 */
static SYSMON_STATUS
SysmonNotifyConfigChange(VOID)
{
    SYSMON_TRANSPORT transport;
    HANDLE stopEvent;
    SYSMON_STATUS status;

    stopEvent = CreateEventW(NULL, TRUE, FALSE, NULL);
    if (stopEvent == NULL) {
        status = GetLastError();
        SysmonReportError(SYSMON_COMPONENT_INSTALLER, status,
            "Failed to create config update event");
        return status;
    }

    ZeroMemory(&transport, sizeof(transport));
    status = SysmonTransportInit(&transport, stopEvent);
    if (status != SYSMON_SUCCESS) {
        SysmonReportError(SYSMON_COMPONENT_INSTALLER, status,
            "Failed to initialize transport for config notify");
        CloseHandle(stopEvent);
        return status;
    }

    status = SysmonSendConfigNotify(&transport);
    if (status != SYSMON_SUCCESS) {
        SysmonReportError(SYSMON_COMPONENT_INSTALLER, status,
            "Failed to notify driver of configuration change");
        SysmonTransportCleanup(&transport);
        CloseHandle(stopEvent);
        return status;
    }

    SysmonLogInfo(SYSMON_COMPONENT_INSTALLER,
        "Driver notified of configuration change");
    SysmonTransportCleanup(&transport);
    CloseHandle(stopEvent);
    return SYSMON_SUCCESS;
}

static VOID
SysmonTryEmitPersistedConfigChangeEvent(
    _In_ LPCWSTR ServiceName,
    _In_opt_ LPCWSTR DefaultConfiguration)
{
    SYSMON_CONFIG persistedConfig;
    LPCWSTR configuration;
    SYSMON_STATUS status;

    ZeroMemory(&persistedConfig, sizeof(persistedConfig));
    status = SysmonConfigLoad(&persistedConfig, ServiceName);
    if (status != SYSMON_SUCCESS) {
        SysmonLogWarning(
            SYSMON_COMPONENT_INSTALLER,
            "Failed to reload persisted configuration for Event 16 emission: %lu",
            (unsigned long)status);
        return;
    }

    configuration = persistedConfig.ConfigFile;
    if ((configuration == NULL || configuration[0] == L'\0') &&
        DefaultConfiguration != NULL &&
        DefaultConfiguration[0] != L'\0') {
        configuration = DefaultConfiguration;
    }

    status = SysmonStagePendingConfigChangeEvent(
        ServiceName,
        configuration,
        persistedConfig.ConfigHash);
    if (status != SYSMON_SUCCESS) {
        SysmonLogWarning(
            SYSMON_COMPONENT_INSTALLER,
            "Failed to stage pending Event 16 for service '%ls': %lu",
            ServiceName,
            (unsigned long)status);
    }

    SysmonConfigFree(&persistedConfig);
}

/*
 * SysmonUpdateConfig - Parse config file, write to registry, notify driver
 */
SYSMON_STATUS SysmonUpdateConfig(LPCWSTR ConfigFilePath, LPCWSTR ServiceName)
{
    HANDLE hFile = INVALID_HANDLE_VALUE;
    SYSMON_CONFIG parsedConfig;
    SYSMON_STATUS status;
    LPCWSTR targetServiceName = (ServiceName != NULL) ? ServiceName : SYSMON_SERVICE_NAME;

    SysmonLogInfo(SYSMON_COMPONENT_INSTALLER,
        "Updating configuration from: %ls", ConfigFilePath);

    ZeroMemory(&parsedConfig, sizeof(parsedConfig));

    /* Verify file exists */
    hFile = CreateFileW(ConfigFilePath, GENERIC_READ, FILE_SHARE_READ,
        NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        status = GetLastError();
        SysmonReportError(SYSMON_COMPONENT_INSTALLER, status,
            "Cannot open config file: %ls", ConfigFilePath);
        return status;
    }
    CloseHandle(hFile);
    hFile = INVALID_HANDLE_VALUE;

    status = SysmonParseXmlConfig(ConfigFilePath, &parsedConfig);
    if (status != SYSMON_SUCCESS) {
        SysmonReportError(SYSMON_COMPONENT_INSTALLER, status,
            "Failed to parse config file: %ls", ConfigFilePath);
        return status;
    }

    SysmonLogInfo(SYSMON_COMPONENT_INSTALLER,
        "Parsed XML config: Hashing=0x%02X CheckRevocation=%s DnsLookup=%s RuleGroups=%u",
        parsedConfig.HashingAlgorithm,
        parsedConfig.CheckRevocation ? "TRUE" : "FALSE",
        parsedConfig.DnsLookup ? "TRUE" : "FALSE",
        parsedConfig.RuleSet.GroupCount);

    status = SysmonConfigPersistCompiled(targetServiceName, ConfigFilePath, &parsedConfig);
    if (status != SYSMON_SUCCESS) {
        SysmonReportError(SYSMON_COMPONENT_INSTALLER, status,
            "Failed to persist compiled configuration for service '%ls'", targetServiceName);
        goto cleanup;
    }

    status = SysmonNotifyConfigChange();
    if (status != SYSMON_SUCCESS) {
        goto cleanup;
    }

    SysmonTryEmitPersistedConfigChangeEvent(targetServiceName, NULL);

cleanup:
    if (hFile != INVALID_HANDLE_VALUE) {
        CloseHandle(hFile);
    }
    SysmonConfigFree(&parsedConfig);
    return status;
}

/*
 * SysmonResetConfigDefaults - Restore the default registry-backed configuration
 */
SYSMON_STATUS SysmonResetConfigDefaults(LPCWSTR ServiceName)
{
    SYSMON_CONFIG defaultConfig;
    SYSMON_STATUS status;
    LPCWSTR targetServiceName = (ServiceName != NULL) ? ServiceName : SYSMON_SERVICE_NAME;

    ZeroMemory(&defaultConfig, sizeof(defaultConfig));
    defaultConfig.HashingAlgorithm = SYSMON_HASH_DEFAULT;
    defaultConfig.CheckRevocation = TRUE;
    defaultConfig.DnsLookup = TRUE;
    defaultConfig.SigningQueueSize = 1000;

    SysmonLogInfo(SYSMON_COMPONENT_INSTALLER,
        "Restoring default configuration");

    status = SysmonConfigPersistCompiled(targetServiceName, NULL, &defaultConfig);
    if (status != SYSMON_SUCCESS) {
        SysmonReportError(SYSMON_COMPONENT_INSTALLER, status,
            "Failed to persist default configuration for service '%ls'", targetServiceName);
        return status;
    }

    status = SysmonNotifyConfigChange();
    if (status == SYSMON_SUCCESS) {
        SysmonTryEmitPersistedConfigChangeEvent(targetServiceName, L"Defaults");
    }

    return status;
}

typedef struct _SYSMON_SCHEMA_EVENT_ENTRY {
    LPCWSTR Id;
    LPCWSTR Tag;
    LPCWSTR Event;
} SYSMON_SCHEMA_EVENT_ENTRY, *PSYSMON_SCHEMA_EVENT_ENTRY;

static const WCHAR g_SysmonSchemaUsageText[] =
    L"Configuration files can be specified after the -i (installation) or -c "
    L"(configuration) switches. They make it easier to deploy a preset "
    L"configuration and to filter captured events.\n\n"
    L"A simple configuration xml file looks like this:\n\n";

static const WCHAR g_SysmonSchemaSampleConfig[] =
    L"  <!-- Capture all hashes -->\n"
    L"  <HashAlgorithms>*</HashAlgorithms>\n"
    L"  <EventFiltering>\n"
    L"    <!-- Log all drivers except if the signature -->\n"
    L"    <!-- contains Microsoft or Windows -->\n"
    L"    <DriverLoad onmatch=\"exclude\">\n"
    L"      <Signature condition=\"contains\">microsoft</Signature>\n"
    L"      <Signature condition=\"contains\">windows</Signature>\n"
    L"    </DriverLoad>\n"
    L"    <!-- Do not log process termination -->\n"
    L"    <ProcessTerminate onmatch=\"include\" />\n"
    L"    <!-- Log network connection if the destination port equals 443 -->\n"
    L"    <!-- or 80, and the process is not Internet Explorer -->\n"
    L"    <NetworkConnect onmatch=\"include\">\n"
    L"      <DestinationPort>443</DestinationPort>\n"
    L"      <DestinationPort>80</DestinationPort>\n"
    L"    </NetworkConnect>\n"
    L"    <NetworkConnect onmatch=\"exclude\">\n"
    L"      <Image condition=\"end with\">iexplore.exe</Image>\n"
    L"    </NetworkConnect>\n"
    L"  </EventFiltering>\n"
    L"</Sysmon>\n";

static const WCHAR g_SysmonSchemaConfigEntriesText[] =
    L"The configuration file contains a schemaversion attribute on the Sysmon "
    L"tag. This version is independent from the Sysmon binary version and "
    L"allows the parsing of older configuration files. The current schema "
    L"version is shown in the sample configuration.\n\n"
    L"Configuration entries are directly under the Sysmon tag and filters are "
    L"under the EventFiltering tag. Configuration entries are similar to "
    L"command line switches, and have their configuration entry described in "
    L"the Sysmon usage output. Parameters are optional based on the tag. If a "
    L"command line switch also enables an event, it needs to be configured "
    L"through its filter tag.\n\n"
    L"Configuration entries include the following:\n\n"
    L"  Entry                  Value    Description\n"
    L"  ArchiveDirectory       String   Name of directories at volume roots into which copy-on-delete\n"
    L"                                  files are moved. The directory is protected with a System ACL.\n"
    L"                                  Default: Sysmon\n"
    L"  CheckRevocation        Boolean  Controls signature revocation checks.\n"
    L"                                  Default: True\n"
    L"  CopyOnDeletePE         Boolean  Preserves deleted executable image files.\n"
    L"                                  Default: False\n"
    L"  CopyOnDeleteSIDs       Strings  Comma-separated list of account SIDs for which file deletes\n"
    L"                                  will be preserved.\n"
    L"  CopyOnDeleteExtensions Strings  Extensions for files that are preserved on delete.\n"
    L"  CopyOnDeleteProcesses  Strings  Process names for which file deletes will be preserved.\n"
    L"  DnsLookup              Boolean  Controls reverse DNS lookup.\n"
    L"                                  Default: True\n"
    L"  DriverQueueSize        Number   Controls how many events the Sysmon driver caches in its queue.\n"
    L"                                  If the Sysmon service is slower than the driver, the queue fills\n"
    L"                                  and the oldest events are dropped.\n"
    L"                                  Default: 50000\n"
    L"  SigningQueueSize       Number   Controls how many images for ImageLoad events to queue.\n"
    L"                                  Default: 1000\n"
    L"  DriverName             String   Uses the specified name for driver and service images.\n"
    L"  HashAlgorithms         Strings  Hash algorithm(s) to apply for hashing. Supported values include\n"
    L"                                  MD5, SHA1, SHA256, IMPHASH and * (all).\n"
    L"                                  Default: None\n"
    L"  FieldSizes             Strings  Comma-separated list of FieldName:Size entries that specify\n"
    L"                                  the maximum sizes for field output.\n"
    L"                                  Example: CommandLine:100,Image:20\n"
    L"\n"
    L"Event filtering allows you to filter generated events. In many cases events "
    L"can be noisy and gathering everything is not possible. For example, you "
    L"might be interested in network connections only for a certain process, "
    L"but not all of them. You can filter the output on the host, reducing the "
    L"data to collect.\n\n"
    L"Each event has its own filter tag under EventFiltering:\n\n";

static const SYSMON_SCHEMA_EVENT_ENTRY g_SysmonSchemaEventEntries[] = {
    { L"1",  L"ProcessCreate",          L"Process creation" },
    { L"2",  L"FileCreateTime",         L"A process changed a file creation time" },
    { L"3",  L"NetworkConnect",         L"Network connection detected" },
    { L"4",  L"-",                      L"Sysmon service state changed" },
    { L"5",  L"ProcessTerminate",       L"Process terminated" },
    { L"6",  L"DriverLoad",             L"Driver loaded" },
    { L"7",  L"ImageLoad",              L"Image loaded" },
    { L"8",  L"CreateRemoteThread",     L"CreateRemoteThread" },
    { L"9",  L"RawAccessRead",          L"RawAccessRead" },
    { L"10", L"ProcessAccess",          L"ProcessAccess" },
    { L"11", L"FileCreate",             L"FileCreate" },
    { L"12", L"RegistryEvent",          L"RegistryEvent (Object create and delete)" },
    { L"13", L"RegistryEvent",          L"RegistryEvent (Value Set)" },
    { L"14", L"RegistryEvent",          L"RegistryEvent (Key and Value Rename)" },
    { L"15", L"FileCreateStreamHash",   L"FileCreateStreamHash" },
    { L"16", L"-",                      L"Sysmon config state changed" },
    { L"17", L"PipeEvent",              L"Pipe Created" },
    { L"18", L"PipeEvent",              L"Pipe Connected" },
    { L"19", L"WmiEvent",               L"WmiEventFilter activity detected" },
    { L"20", L"WmiEvent",               L"WmiEventConsumer activity detected" },
    { L"21", L"WmiEvent",               L"WmiEventConsumerToFilter activity detected" },
    { L"22", L"DnsQuery",               L"DNSEvent" },
    { L"23", L"FileDelete",             L"FileDelete (A File Delete archived)" },
    { L"24", L"ClipboardChange",        L"Clipboard changed" },
    { L"25", L"ProcessTampering",       L"Process Tampering" },
    { L"26", L"FileDeleteDetected",     L"File Delete logged" },
    { L"27", L"FileBlockExecutable",    L"File Block Executable" },
    { L"28", L"FileBlockShredding",     L"File Block Shredding" },
    { L"29", L"FileExecutableDetected", L"File Executable Detected" }
};

static const WCHAR g_SysmonSchemaFilterText[] =
    L"You can also find these tags in the event viewer on the task name.\n\n"
    L"The onmatch filter is applied if events are matched. It can be changed "
    L"with the \"onmatch\" attribute for the filter tag. If the value is "
    L"\"include\", only matched events are included. If it is set to "
    L"\"exclude\", the event will be included except when a rule matches.\n\n"
    L"Each tag under the filter tag is a field name from the event. Each field "
    L"entry is tested against generated events; if one matches, the rule is "
    L"applied and the rest is ignored.\n\n"
    L"For example, this rule discards any process event where the IntegrityLevel "
    L"is Medium:\n\n"
    L"  <ProcessCreate onmatch=\"exclude\">\n"
    L"    <IntegrityLevel>Medium</IntegrityLevel>\n"
    L"  </ProcessCreate>\n\n"
    L"Field entries can use other conditions to match the value. The conditions "
    L"are as follows (all are case insensitive):\n\n"
    L"is             Default, values are equal.\n"
    L"is not         Values are different.\n"
    L"contains       The field contains this value.\n"
    L"contains any   The field contains any of the ; delimited values.\n"
    L"is any         The field equals one of the ; delimited values.\n"
    L"contains all   The field contains all of the ; delimited values.\n"
    L"excludes       The field does not contain this value.\n"
    L"excludes any   The field does not contain one or more of the ; delimited values.\n"
    L"excludes all   The field does not contain any of the ; delimited values.\n"
    L"begin with     The field begins with this value.\n"
    L"not begin with The field does not begin with this value.\n"
    L"end with       The field ends with this value.\n"
    L"not end with   The field does not end with this value.\n"
    L"less than      Lexicographical comparison is less than zero.\n"
    L"more than      Lexicographical comparison is more than zero.\n"
    L"image          Match an image path (full path or only image name).\n"
    L"               For example: lsass.exe matches c:\\windows\\system32\\lsass.exe.\n\n"
    L"You can use a different condition by specifying it as an attribute. This "
    L"excludes network activity from processes with iexplore.exe in their "
    L"path:\n\n"
    L"  <NetworkConnect onmatch=\"exclude\">\n"
    L"    <Image condition=\"contains\">iexplore.exe</Image>\n"
    L"  </NetworkConnect>\n\n"
    L"You can use both include and exclude rules for the same tag, where "
    L"exclude rules override include rules. Within a rule, filter conditions "
    L"have OR behavior. In the sample configuration shown earlier, the "
    L"networking filter uses both an include and exclude rule to capture "
    L"activity to ports 80 and 443 by all processes except those that have "
    L"iexplore.exe in their name.\n\n";

static const WCHAR g_SysmonSchemaRuleGroupText[] =
    L"It is also possible to override the way that rules are combined by using "
    L"a RuleGroup, which allows the rule combine type for one or more events "
    L"to be set explicitly to AND or OR.\n\n"
    L"The following example demonstrates this usage. In the first rule group, "
    L"a process create event is generated when timeout.exe is executed only "
    L"with a command line argument of \"100\", but a process terminate event "
    L"is generated for termination of ping.exe and timeout.exe.\n\n"
    L"  <EventFiltering>\n"
    L"    <RuleGroup name=\"group 1\" groupRelation=\"and\">\n"
    L"      <ProcessCreate onmatch=\"include\">\n"
    L"        <Image condition=\"contains\">timeout.exe</Image>\n"
    L"        <CommandLine condition=\"contains\">100</CommandLine>\n"
    L"      </ProcessCreate>\n"
    L"    </RuleGroup>\n"
    L"    <RuleGroup groupRelation=\"or\">\n"
    L"      <ProcessTerminate onmatch=\"include\">\n"
    L"        <Image condition=\"contains\">timeout.exe</Image>\n"
    L"        <Image condition=\"contains\">ping.exe</Image>\n"
    L"      </ProcessTerminate>\n"
    L"    </RuleGroup>\n"
    L"    <ImageLoad onmatch=\"include\" />\n"
    L"  </EventFiltering>\n\n";

static const WCHAR g_SysmonSchemaRuleText[] =
    L"In addition, the <Rule> element can be used to extend the groupRelation "
    L"attribute down to individual rules. As with RuleGroup, these can also "
    L"have an optional name attribute and can be combined with classic rules. "
    L"The following example demonstrates this usage:\n\n"
    L"  <EventFiltering>\n"
    L"    <RuleGroup name=\"group 1\" groupRelation=\"or\">\n"
    L"      <ProcessCreate onmatch=\"include\">\n"
    L"        <Image condition=\"contains any\">chrome.exe;firefox.exe;iexplore.exe</Image>\n"
    L"        <Rule name=\"powershell by cmd\" groupRelation=\"and\">\n"
    L"          <Image condition=\"end with\">powershell.exe</Image>\n"
    L"          <ParentImage condition=\"contains\">cmd.exe</ParentImage>\n"
    L"        </Rule>\n"
    L"        <Rule groupRelation=\"and\">\n"
    L"          <Image condition=\"end with\">cmd.exe</Image>\n"
    L"          <ParentImage condition=\"end with\">explorer.exe</ParentImage>\n"
    L"        </Rule>\n"
    L"      </ProcessCreate>\n"
    L"    </RuleGroup>\n"
    L"  </EventFiltering>\n\n"
    L"To have Sysmon report which rule match resulted in an event being logged, "
    L"add names to rules:\n\n"
    L"  <NetworkConnect onmatch=\"exclude\">\n"
    L"    <Image name=\"network iexplore\" condition=\"contains\">iexplore.exe</Image>\n"
    L"  </NetworkConnect>\n";

static VOID
SysmonPrintConfigHelpText(
    _In_ LPCWSTR Version)
{
    DWORD index;

    fwprintf(stderr, L"Configuration usage (current schema is version: %ls):\n\n", Version);
    fputws(g_SysmonSchemaUsageText, stderr);
    fwprintf(stderr, L"<Sysmon schemaversion=\"%ls\">\n", Version);
    fputws(g_SysmonSchemaSampleConfig, stderr);
    fputws(L"\n", stderr);
    fputws(g_SysmonSchemaConfigEntriesText, stderr);

    fwprintf(stderr, L"%-6ls %-20ls %ls\n", L"Id", L"Tag", L"Event");
    for (index = 0; index < RTL_NUMBER_OF(g_SysmonSchemaEventEntries); index++) {
        const SYSMON_SCHEMA_EVENT_ENTRY *entry = &g_SysmonSchemaEventEntries[index];
        fwprintf(stderr, L"%-6ls %-20ls %ls\n", entry->Id, entry->Tag, entry->Event);
    }

    fputws(L"\n", stderr);
    fputws(g_SysmonSchemaFilterText, stderr);
    fputws(g_SysmonSchemaRuleGroupText, stderr);
    fputws(g_SysmonSchemaRuleText, stderr);
}

static SYSMON_STATUS
SysmonLoadSchemaResourceText(
    _Outptr_result_z_ LPWSTR *ResourceText)
{
    HMODULE moduleHandle;
    HRSRC resourceInfo;
    HGLOBAL resourceData;
    DWORD resourceSize;
    const void *resourceBytes;
    SIZE_T charCount;
    LPWSTR text;

    if (ResourceText == NULL) {
        return SYSMON_ERROR_INVALID_PARAM;
    }

    *ResourceText = NULL;
    moduleHandle = GetModuleHandleW(NULL);
    if (moduleHandle == NULL) {
        return GetLastError();
    }

    resourceInfo = FindResourceW(
        moduleHandle,
        SYSMON_SCHEMA_RESOURCE_NAME,
        SYSMON_SCHEMA_RESOURCE_TYPE);
    if (resourceInfo == NULL) {
        resourceInfo = FindResourceW(
            moduleHandle,
            MAKEINTRESOURCEW(SYSMON_SCHEMA_RCDATA_ID),
            RT_RCDATA);
    }
    if (resourceInfo == NULL) {
        return GetLastError();
    }

    resourceSize = SizeofResource(moduleHandle, resourceInfo);
    resourceData = LoadResource(moduleHandle, resourceInfo);
    if (resourceData == NULL) {
        return GetLastError();
    }

    resourceBytes = LockResource(resourceData);
    if (resourceBytes == NULL) {
        return GetLastError();
    }

    charCount = resourceSize / sizeof(WCHAR);
    text = (LPWSTR)SYSMON_ALLOC((charCount + 1) * sizeof(WCHAR));
    if (text == NULL) {
        return SYSMON_ERROR_OUT_OF_MEMORY;
    }

    CopyMemory(text, resourceBytes, resourceSize);
    text[charCount] = L'\0';
    *ResourceText = text;
    return SYSMON_SUCCESS;
}

static LPWSTR
SysmonFindSchemaManifest(
    _Inout_ LPWSTR SearchStart,
    _In_opt_ LPCWSTR Version)
{
    static const WCHAR manifestTag[] = L"<manifest";
    static const WCHAR versionTag[] = L"schemaversion=\"";
    SIZE_T versionLength;
    LPWSTR manifest;

    versionLength = (Version != NULL) ? wcslen(Version) : 0;
    manifest = wcsstr(SearchStart, manifestTag);
    while (manifest != NULL) {
        LPWSTR versionMarker;

        if (versionLength == 0) {
            return manifest;
        }

        versionMarker = wcsstr(manifest, versionTag);
        if (versionMarker != NULL) {
            versionMarker += RTL_NUMBER_OF(versionTag) - 1;
            if (wcsncmp(versionMarker, Version, versionLength) == 0) {
                return manifest;
            }
        }

        manifest = wcsstr(manifest + (RTL_NUMBER_OF(manifestTag) - 1), manifestTag);
    }

    return NULL;
}

static LPWSTR
SysmonFindSchemaManifestEnd(
    _Inout_ LPWSTR ManifestStart)
{
    static const WCHAR manifestEndTag[] = L"</manifest>";
    LPWSTR manifestEnd;

    manifestEnd = wcsstr(ManifestStart, manifestEndTag);
    if (manifestEnd == NULL) {
        return NULL;
    }

    return manifestEnd + (RTL_NUMBER_OF(manifestEndTag) - 1);
}

static VOID
SysmonPrintSchemaManifestFragment(
    _Inout_ LPWSTR ManifestStart)
{
    LPWSTR manifestEnd;
    WCHAR saved;

    manifestEnd = SysmonFindSchemaManifestEnd(ManifestStart);
    if (manifestEnd == NULL) {
        fwprintf(stdout, L"%ls", ManifestStart);
        return;
    }

    saved = *manifestEnd;
    *manifestEnd = L'\0';
    fwprintf(stdout, L"%ls\n", ManifestStart);
    *manifestEnd = saved;
}

static VOID
SysmonRewriteSchemaOptionNamesInPlace(
    _Inout_updates_z_(cchText) LPWSTR Text,
    _In_ SIZE_T cchText,
    _In_z_ LPCWSTR OldValue,
    _In_z_ LPCWSTR NewValue)
{
    SIZE_T oldLength;
    SIZE_T newLength;
    LPWSTR match;

    UNREFERENCED_PARAMETER(cchText);

    if (Text == NULL || OldValue == NULL || NewValue == NULL) {
        return;
    }

    oldLength = wcslen(OldValue);
    newLength = wcslen(NewValue);
    if (oldLength == 0 || newLength > oldLength) {
        return;
    }

    match = wcsstr(Text, OldValue);
    while (match != NULL) {
        SIZE_T tailChars = wcslen(match + oldLength) + 1;

        RtlCopyMemory(match, NewValue, newLength * sizeof(WCHAR));
        if (newLength < oldLength) {
            RtlMoveMemory(
                match + newLength,
                match + oldLength,
                tailChars * sizeof(WCHAR));
        }

        match = wcsstr(match + newLength, OldValue);
    }
}

SYSMON_STATUS SysmonPrintConfigHelp(void)
{
    SysmonPrintConfigHelpText(SYSMON_SCHEMA_VERSION);
    return SYSMON_SUCCESS;
}

/*
 * SysmonDumpConfiguration - Print the current configuration summary
 */
SYSMON_STATUS SysmonDumpConfiguration(LPCWSTR ServiceName)
{
    SYSMON_CONFIG config;
    SYSMON_STATUS status;
    LPCWSTR targetServiceName = (ServiceName != NULL) ? ServiceName : SYSMON_SERVICE_NAME;
    WCHAR hashingAlgorithms[64];
    LPCWSTR archiveDirectory;
    LPCWSTR copyOnDeleteSids;
    LPCWSTR copyOnDeleteExtensions;
    LPCWSTR copyOnDeleteProcesses;

    status = SysmonConfigLoad(&config, targetServiceName);
    if (status != SYSMON_SUCCESS) {
        return status;
    }

    SysmonFormatHashingAlgorithms(config.HashingAlgorithm, hashingAlgorithms, _countof(hashingAlgorithms));
    archiveDirectory = (config.ArchiveDirectory != NULL && config.ArchiveDirectory[0] != L'\0')
        ? config.ArchiveDirectory
        : L"-";
    copyOnDeleteSids = (config.CopyOnDeleteSIDs != NULL && config.CopyOnDeleteSIDs[0] != L'\0')
        ? config.CopyOnDeleteSIDs
        : L"-";
    copyOnDeleteExtensions = (config.CopyOnDeleteExtensions != NULL && config.CopyOnDeleteExtensions[0] != L'\0')
        ? config.CopyOnDeleteExtensions
        : L"-";
    copyOnDeleteProcesses = (config.CopyOnDeleteProcesses != NULL && config.CopyOnDeleteProcesses[0] != L'\0')
        ? config.CopyOnDeleteProcesses
        : L"-";

    fwprintf(stdout, L"Current configuration:\n");
    SysmonPrintLabelValue(L" - Service name:", targetServiceName);
    SysmonPrintLabelValue(L" - Driver name:", SYSMON_DRIVER_SERVICE_NAME);
    if (config.ConfigFile != NULL && config.ConfigFile[0] != L'\0') {
        SysmonPrintLabelValue(L" - Config file:", config.ConfigFile);
    }
    if (config.ConfigHash != NULL && config.ConfigHash[0] != L'\0') {
        SysmonPrintLabelValue(L" - Config hash:", config.ConfigHash);
    }
    if (config.FieldSizes != NULL && config.FieldSizes[0] != L'\0') {
        SysmonPrintLabelValue(L" - Field Sizes:", config.FieldSizes);
    }

    fwprintf(stdout, L"\n");
    SysmonPrintLabelValue(L" - HashingAlgorithms:", hashingAlgorithms);
    SysmonPrintLabelValue(
        L" - Network connection:",
        SysmonEnabledDisabledString((config.Options & SYSMON_OPTION_NETWORK_CONNECT) != 0));
    SysmonPrintLabelValue(L" - Archive Directory:", archiveDirectory);
    SysmonPrintLabelValue(
        L" - CopyOnDeletePE:",
        SysmonEnabledDisabledString(config.CopyOnDeletePE));
    SysmonPrintLabelValue(L" - CopyOnDeleteSIDs:", copyOnDeleteSids);
    SysmonPrintLabelValue(L" - CopyOnDeleteExtensions:", copyOnDeleteExtensions);
    SysmonPrintLabelValue(L" - CopyOnDeleteProcesses:", copyOnDeleteProcesses);
    SysmonPrintLabelValue(
        L" - Image loading:",
        SysmonEnabledDisabledString((config.Options & SYSMON_OPTION_IMAGE_LOAD) != 0));
    SysmonPrintLabelValue(L" - CRL checking:", SysmonEnabledDisabledString(config.CheckRevocation));
    SysmonPrintLabelValue(L" - DNS lookup:", SysmonEnabledDisabledString(config.DnsLookup));
    if (config.DriverQueueSize != 0) {
        SysmonPrintLabelDword(L" - DriverQueueSize:", config.DriverQueueSize);
    }
    if (config.SigningQueueSize != 0) {
        SysmonPrintLabelDword(L" - SigningQueueSize:", config.SigningQueueSize);
    }

    fwprintf(stdout, L"\n");
    SysmonPrintRuleConfigurationSummary(&config);

    SysmonConfigFree(&config);
    return SYSMON_SUCCESS;
}

/*
 * SysmonPrintSchema - Print embedded schema manifest fragments
 */
SYSMON_STATUS SysmonPrintSchema(LPCWSTR Version, BOOL DumpAll)
{
    LPWSTR resourceText;
    LPWSTR manifest;
    SYSMON_STATUS status;

    resourceText = NULL;
    status = SysmonLoadSchemaResourceText(&resourceText);
    if (status != SYSMON_SUCCESS) {
        SysmonLogError(
            SYSMON_COMPONENT_INSTALLER,
            status,
            "Failed to load embedded schema resource");
        return status;
    }

    SysmonRewriteSchemaOptionNamesInPlace(
        resourceText,
        wcslen(resourceText) + 1,
        L"CopyOnDelete_PE",
        L"CopyOnDeletePE");
    SysmonRewriteSchemaOptionNamesInPlace(
        resourceText,
        wcslen(resourceText) + 1,
        L"CopyOnDelete_SIDs",
        L"CopyOnDeleteSIDs");
    SysmonRewriteSchemaOptionNamesInPlace(
        resourceText,
        wcslen(resourceText) + 1,
        L"CopyOnDelete_Extensions",
        L"CopyOnDeleteExtensions");
    SysmonRewriteSchemaOptionNamesInPlace(
        resourceText,
        wcslen(resourceText) + 1,
        L"CopyOnDelete_Processes",
        L"CopyOnDeleteProcesses");

    manifest = SysmonFindSchemaManifest(resourceText, DumpAll ? NULL : Version);
    if (manifest == NULL) {
        fwprintf(stdout, L"There is no schema that matches that version.\n");
        SYSMON_FREE(resourceText);
        return SYSMON_SUCCESS;
    }

    do {
        SysmonPrintSchemaManifestFragment(manifest);
        if (!DumpAll) {
            break;
        }

        manifest = SysmonFindSchemaManifestEnd(manifest);
        if (manifest != NULL) {
            manifest = SysmonFindSchemaManifest(manifest, NULL);
        }
    } while (manifest != NULL);

    SYSMON_FREE(resourceText);
    return SYSMON_SUCCESS;
}


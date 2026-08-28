/*
 * common.c - Error handling, logging, and utility functions
 */

#include "../include/common.h"

static LPCWSTR
SysmonGetProcessBaseName(
    _Out_writes_(BufferCount) LPWSTR Buffer,
    _In_ DWORD BufferCount)
{
    LPWSTR name;

    if (Buffer == NULL || BufferCount == 0) {
        return L"Sysmon.exe";
    }

    if (GetModuleFileNameW(NULL, Buffer, BufferCount) == 0) {
        lstrcpynW(Buffer, L"Sysmon.exe", BufferCount);
        return Buffer;
    }

    name = wcsrchr(Buffer, L'\\');
    if (name != NULL && name[1] != L'\0') {
        return name + 1;
    }

    return Buffer;
}

void SysmonReportError(
    const char *Component,
    DWORD ErrorCode,
    const char *Format, ...)
{
    va_list args;
    char message[1024];

    va_start(args, Format);
    _vsnprintf_s(message, sizeof(message), _TRUNCATE, Format, args);
    va_end(args);

    if (ErrorCode != 0) {
        fprintf(stderr, "[Sysmon] [%s] Error %u (0x%08X): %s\n",
                Component, ErrorCode, ErrorCode, message);
    } else {
        fprintf(stderr, "[Sysmon] [%s] %s\n", Component, message);
    }
}

void SysmonLogInfo(const char *Component, const char *Format, ...)
{
    va_list args;
    char message[1024];

    va_start(args, Format);
    _vsnprintf_s(message, sizeof(message), _TRUNCATE, Format, args);
    va_end(args);

    fprintf(stdout, "[Sysmon] [%s] %s\n", Component, message);
}

void SysmonLogWarning(const char *Component, const char *Format, ...)
{
    va_list args;
    char message[1024];

    va_start(args, Format);
    _vsnprintf_s(message, sizeof(message), _TRUNCATE, Format, args);
    va_end(args);

    fprintf(stderr, "[Sysmon] [%s] WARNING: %s\n", Component, message);
}

void SysmonLogError(const char *Component, DWORD ErrorCode, const char *Format, ...)
{
    va_list args;
    char message[1024];

    va_start(args, Format);
    _vsnprintf_s(message, sizeof(message), _TRUNCATE, Format, args);
    va_end(args);

    SysmonReportError(Component, ErrorCode, "%s", message);
}

void SysmonPrintUsage(void)
{
    WCHAR imagePath[MAX_PATH];
    LPCWSTR baseName;

    baseName = SysmonGetProcessBaseName(imagePath, RTL_NUMBER_OF(imagePath));

    fwprintf(stderr, L"Usage:\n");
    fwprintf(stderr, L"Install:                 %ls -i [<configfile>]\n", baseName);
    fwprintf(stderr, L"Update configuration:    %ls -c [<configfile>]\n", baseName);
    fwprintf(stderr, L"Install event manifest:  %ls -m\n", baseName);
    fwprintf(stderr, L"Print schema:            %ls -s\n", baseName);
    fwprintf(stderr, L"Uninstall:               %ls -u [force]\n", baseName);
    fwprintf(stderr, L"  -c   Update configuration of an installed Sysmon driver or dump the\n");
    fwprintf(stderr, L"       current configuration if no other argument is provided. Optionally\n");
    fwprintf(stderr, L"       take a configuration file.\n");
    fwprintf(stderr, L"  -i   Install service and driver. Optionally take a configuration file.\n");
    fwprintf(stderr, L"  -m   Install the event manifest (done on service install as well)).\n");
    fwprintf(stderr, L"  -s   Print configuration schema definition of the specified version.\n");
    fwprintf(stderr, L"       Specify 'all' to dump all schema versions (default is latest)).\n");
    fwprintf(stderr, L"  -u   Uninstall service and driver. Adding force causes uninstall to proceed\n");
    fwprintf(stderr, L"       even when some components are not installed.\n");
    fwprintf(stderr, L"\n");
    fwprintf(
        stderr,
        L"The service logs events immediately and the driver installs as a boot-start "
        L"driver to capture activity from early in the boot that the service will "
        L"write to the event log when it starts.\n\n");
    fwprintf(
        stderr,
        L"On Vista and higher, events are stored in "
        L"\"Applications and Services Logs/Microsoft/Windows/Sysmon/Operational\". "
        L"On older systems, events are written to the System event log.\n\n");
    fwprintf(
        stderr,
        L"Use the '-? config' command for configuration file documentation. More "
        L"examples are available on the Sysinternals website.\n\n");
    fwprintf(
        stderr,
        L"Specify -accepteula or /accepteula to automatically accept the EULA on installation, "
        L"otherwise you will be interactively prompted to accept it.\n\n");
    fwprintf(stderr, L"Neither install nor uninstall requires a reboot.\n\n");
}

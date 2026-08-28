#pragma once
/*
 * common.h - Universal types, macros, error handling, logging for SysmonUser
 */

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <stdint.h>
#include <cwctype>

/* Service name - matches original Sysmon */
#define SYSMON_SERVICE_NAME         L"Sysmon"
#define SYSMON_SERVICE_NAME_A       "Sysmon"
#define SYSMON_DRIVER_SERVICE_NAME  L"SysmonDrv"
#define SYSMON_DEVICE_PATH          L"\\\\.\\Sysmon"

/* Driver minifilter altitude */
#define SYSMON_FILTER_ALTITUDE      L"385201"

/* Version constants */
#define SYSMON_VERSION_MAJOR    15
#define SYSMON_VERSION_MINOR    0
#define SYSMON_VERSION_BUILD    0
#define SYSMON_VERSION ((SYSMON_VERSION_MAJOR << 16) | SYSMON_VERSION_MINOR)
#define SYSMON_SCHEMA_VERSION   L"4.91"

/* Buffer sizes */
#define SYSMON_EVENT_BUFFER_SIZE    0x40000  /* 256KB - original event buffer */
#define SYSMON_STATS_BUFFER_SIZE    0x40000  /* 256KB - original stats buffer */
#define SYSMON_MIN_EVENT_SIZE       0x358    /* minimum valid event size */
#define SYSMON_QUERY_ANSWER_SIZE    0x60     /* query answer structure size */
#define SYSMON_PROCESS_CACHE_OUT    0x4002   /* process cache output size */

/* Reconnect parameters */
#define SYSMON_RECONNECT_MAX_RETRIES    10
#define SYSMON_RECONNECT_SLEEP_MS       500

/* Registry path template */
#define SYSMON_REG_PARAMS_PATH      L"System\\CurrentControlSet\\Services\\%s\\Parameters"

/* Error reporting component tags */
#define SYSMON_COMPONENT_CLI            "CLI"
#define SYSMON_COMPONENT_SERVICE        "Service"
#define SYSMON_COMPONENT_PROTOCOL       "Protocol"
#define SYSMON_COMPONENT_CONFIG         "Config"
#define SYSMON_COMPONENT_PIPELINE       "Pipeline"
#define SYSMON_COMPONENT_OUTPUT         "Output"
#define SYSMON_COMPONENT_INSTALLER      "Installer"
#define SYSMON_COMPONENT_DRIVER_COMM    "DriverCommunication"

/* Macro: UNREFERENCED_PARAMETER already defined in Windows headers */

/* Safe close handle */
#define SYSMON_SAFE_CLOSE_HANDLE(h) do { \
    if ((h) != NULL && (h) != INVALID_HANDLE_VALUE) { \
        CloseHandle(h); \
        (h) = NULL; \
    } \
} while(0)

/* Aligned malloc/free */
#define SYSMON_ALLOC(size)          HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, (size))
#define SYSMON_FREE(ptr)            do { if (ptr) { HeapFree(GetProcessHeap(), 0, (ptr)); (ptr) = NULL; } } while(0)

/* Error codes */
typedef DWORD SYSMON_STATUS;
#define SYSMON_SUCCESS              ERROR_SUCCESS
#define SYSMON_ERROR_INVALID_PARAM  ERROR_INVALID_PARAMETER
#define SYSMON_ERROR_OUT_OF_MEMORY  ERROR_NOT_ENOUGH_MEMORY
#define SYSMON_ERROR_NOT_FOUND      ERROR_NOT_FOUND
#define SYSMON_ERROR_ALREADY_EXISTS ERROR_ALREADY_EXISTS

static inline BOOL
SysmonIsPlaceholderString(
    _In_opt_z_ PCWSTR Value)
{
    return Value == NULL ||
        Value[0] == L'\0' ||
        wcscmp(Value, L"-") == 0 ||
        wcscmp(Value, L"Unavailable") == 0;
}

static inline BOOL
SysmonIsSinglePathComponent(
    _In_opt_z_ PCWSTR Value)
{
    SIZE_T length;

    if (Value == NULL || Value[0] == L'\0') {
        return FALSE;
    }

    if (wcscmp(Value, L".") == 0 || wcscmp(Value, L"..") == 0) {
        return FALSE;
    }

    length = wcslen(Value);
    if (length != 0 &&
        (Value[length - 1] == L'.' || Value[length - 1] == L' ')) {
        return FALSE;
    }

    return wcschr(Value, L'\\') == NULL &&
        wcschr(Value, L'/') == NULL &&
        wcschr(Value, L':') == NULL;
}

static inline DWORD
SysmonComputeInsensitiveWideHash(
    _In_opt_z_ PCWSTR Text,
    _Out_opt_ DWORD *TextLength)
{
    const DWORD fnvOffset = 2166136261u;
    const DWORD fnvPrime = 16777619u;
    DWORD hash;
    DWORD length;

    if (TextLength != NULL) {
        *TextLength = 0;
    }

    if (Text == NULL) {
        return 0;
    }

    hash = fnvOffset;
    length = 0;
    while (Text[length] != L'\0') {
        hash ^= (DWORD)(WCHAR)towupper(Text[length]);
        hash *= fnvPrime;
        length += 1;
    }

    if (TextLength != NULL) {
        *TextLength = length;
    }

    return hash;
}

static inline BOOL
SysmonInsensitiveWideTextMatches(
    _In_ DWORD CachedHash,
    _In_ DWORD CachedLength,
    _In_opt_z_ PCWSTR CachedText,
    _In_ DWORD TextHash,
    _In_ DWORD TextLength,
    _In_opt_z_ PCWSTR Text)
{
    if (CachedHash != TextHash ||
        CachedLength != TextLength ||
        CachedText == NULL ||
        Text == NULL) {
        return FALSE;
    }

    return _wcsicmp(CachedText, Text) == 0;
}

static inline VOID
SysmonInitializeBucketHeads(
    _Out_writes_(BucketCount) LONG *Buckets,
    _In_ size_t BucketCount)
{
    size_t index;

    if (Buckets == NULL) {
        return;
    }

    for (index = 0; index < BucketCount; index++) {
        Buckets[index] = -1;
    }
}

static inline BOOL
SysmonCopyWideText(
    _Out_writes_(BufferChars) PWCHAR Buffer,
    _In_ size_t BufferChars,
    _In_opt_z_ PCWSTR Text)
{
    if (Buffer == NULL || BufferChars == 0 || Text == NULL) {
        return FALSE;
    }

    return wcscpy_s(Buffer, BufferChars, Text) == 0;
}

/*
 * SysmonReportError - Print formatted error to stderr
 */
void SysmonReportError(
    _In_ const char *Component,
    _In_ DWORD ErrorCode,
    _In_ _Printf_format_string_ const char *Format,
    ...);

/*
 * SysmonLogInfo / LogWarning / LogError - Logging helpers
 */
void SysmonLogInfo(_In_ const char *Component, _In_ const char *Format, ...);
void SysmonLogWarning(_In_ const char *Component, _In_ const char *Format, ...);
void SysmonLogError(_In_ const char *Component, _In_ DWORD ErrorCode, _In_ const char *Format, ...);

/*
 * SysmonPrintUsage - Print CLI usage information
 */
void SysmonPrintUsage(void);

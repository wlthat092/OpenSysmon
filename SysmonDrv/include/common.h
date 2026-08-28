#pragma once

#ifndef POOL_ZERO_DOWN_LEVEL_SUPPORT
#define POOL_ZERO_DOWN_LEVEL_SUPPORT
#endif

#include <fltKernel.h>
#include <ntddk.h>
#include <dontuse.h>
#include <suppress.h>

/* Pool tags */
#define SYSMON_POOL_TAG         'mSyS'
#define SYSMON_EVENT_TAG        0x34737953  /* 'Sys4' */

/* Driver constants */
#define SYSMON_EVENT_DATA_SIZE  0x1000
#define SYSMON_MAX_QUEUE_EVENTS 8192
#define SYSMON_MAX_QUEUE_SIZE   (SYSMON_MAX_QUEUE_EVENTS * SYSMON_EVENT_DATA_SIZE)
#define SYSMON_MAX_PATH         512
#define SYSMON_MAX_CMDLINE      1024
#define SYSMON_MAX_HASH_STRING  256
#define SYSMON_MAX_GUID_STRING  40
#define SYSMON_MAX_SID_STRING   128

#ifndef SYSMON_ENABLE_HOTPATH_DEBUG
#define SYSMON_ENABLE_HOTPATH_DEBUG 0
#endif

#if SYSMON_ENABLE_HOTPATH_DEBUG
#define SYSMON_HOTPATH_LOG(_level, ...) \
    DbgPrintEx(DPFLTR_DEFAULT_ID, (_level), __VA_ARGS__)
#else
#define SYSMON_HOTPATH_LOG(_level, ...) ((void)0)
#endif

/* OS version globals */
extern ULONG g_OsMajorVersion;
extern ULONG g_OsMinorVersion;
extern ULONG g_OsBuildNumber;

typedef NTSTATUS (NTAPI *PFN_PS_SET_CREATE_PROCESS_NOTIFY_ROUTINE_EX)(
    PCREATE_PROCESS_NOTIFY_ROUTINE_EX NotifyRoutine,
    BOOLEAN Remove);

typedef NTSTATUS (NTAPI *PFN_PS_SET_CREATE_PROCESS_NOTIFY_ROUTINE)(
    PCREATE_PROCESS_NOTIFY_ROUTINE NotifyRoutine,
    BOOLEAN Remove);

typedef NTSTATUS (NTAPI *PFN_PS_SET_CREATE_PROCESS_NOTIFY_ROUTINE_EX2)(
    ULONG NotifyType,
    PVOID NotifyInformation,
    BOOLEAN Remove);

/*
 * SysmonGetPoolType - NonPagedPoolNx on RS2+ (build 14393+),
 * NonPagedPool on older systems.
 */
FORCEINLINE
POOL_TYPE
SysmonGetPoolType(VOID)
{
    if (g_OsMajorVersion > 10 ||
        (g_OsMajorVersion == 10 && g_OsBuildNumber >= 14393))
    {
        return NonPagedPoolNx;
    }
    return NonPagedPool;
}

FORCEINLINE
PVOID
SysmonAllocatePoolWithTag(
    _In_ SIZE_T Size,
    _In_ ULONG Tag)
{
    PVOID allocation;

    /*
     * Use the WDK's downlevel-compatible zeroing wrapper after DriverEntry
     * opts the runtime in via ExInitializeDriverRuntime.
     */
    return ExAllocatePoolZero(SysmonGetPoolType(), Size, Tag);
}

FORCEINLINE
PVOID
SysmonAllocatePool(_In_ SIZE_T Size)
{
    return SysmonAllocatePoolWithTag(Size, SYSMON_POOL_TAG);
}

FORCEINLINE
VOID
SysmonFreePoolWithTag(
    _In_opt_ PVOID Ptr,
    _In_ ULONG Tag)
{
    if (Ptr != NULL) {
        ExFreePoolWithTag(Ptr, Tag);
    }
}

FORCEINLINE
VOID
SysmonFreePool(_In_opt_ PVOID Ptr)
{
    SysmonFreePoolWithTag(Ptr, SYSMON_POOL_TAG);
}

FORCEINLINE
ULONG
SysmonReadPackedUlong(
    _In_reads_bytes_(sizeof(ULONG)) const void *Address)
{
    ULONG value;

    RtlCopyMemory(&value, Address, sizeof(value));
    return value;
}

FORCEINLINE
VOID
SysmonWritePackedUlong(
    _Out_writes_bytes_(sizeof(ULONG)) void *Address,
    _In_ ULONG Value)
{
    RtlCopyMemory(Address, &Value, sizeof(Value));
}

FORCEINLINE
ULONGLONG
SysmonReadPackedUlongLong(
    _In_reads_bytes_(sizeof(ULONGLONG)) const void *Address)
{
    ULONGLONG value;

    RtlCopyMemory(&value, Address, sizeof(value));
    return value;
}

FORCEINLINE
VOID
SysmonWritePackedUlongLong(
    _Out_writes_bytes_(sizeof(ULONGLONG)) void *Address,
    _In_ ULONGLONG Value)
{
    RtlCopyMemory(Address, &Value, sizeof(Value));
}

FORCEINLINE
BOOLEAN
SysmonReadPackedBoolean(
    _In_reads_bytes_(sizeof(BOOLEAN)) const void *Address)
{
    BOOLEAN value;

    RtlCopyMemory(&value, Address, sizeof(value));
    return value;
}

FORCEINLINE
VOID
SysmonWritePackedBoolean(
    _Out_writes_bytes_(sizeof(BOOLEAN)) void *Address,
    _In_ BOOLEAN Value)
{
    RtlCopyMemory(Address, &Value, sizeof(Value));
}

FORCEINLINE
LONGLONG
SysmonGetCurrentTimestamp(VOID)
{
    LARGE_INTEGER systemTime;
    KeQuerySystemTime(&systemTime);
    return systemTime.QuadPart;
}

FORCEINLINE
VOID
SysmonCopyWideStringWithLength(
    _Out_writes_(DstChars) PWCHAR Dst,
    _In_ ULONG DstChars,
    _In_opt_ PCWSTR Src,
    _In_ ULONG SrcChars)
{
    ULONG copyChars;

    if (Dst == NULL || DstChars == 0) {
        return;
    }

    Dst[0] = L'\0';
    if (Src == NULL || SrcChars == 0 || Src[0] == L'\0') {
        return;
    }

    copyChars = SrcChars;
    if (copyChars >= DstChars) {
        copyChars = DstChars - 1;
    }

    RtlCopyMemory(Dst, Src, copyChars * sizeof(WCHAR));
    Dst[copyChars] = L'\0';
}

FORCEINLINE
VOID
SysmonCopyWideString(
    _Out_writes_(DstChars) PWCHAR Dst,
    _In_ ULONG DstChars,
    _In_opt_z_ PCWSTR Src)
{
    if (Dst == NULL || DstChars == 0) {
        return;
    }

    if (Src == NULL) {
        Dst[0] = L'\0';
        return;
    }

    SysmonCopyWideStringWithLength(
        Dst,
        DstChars,
        Src,
        (ULONG)wcslen(Src));
}

FORCEINLINE
VOID
SysmonCopyUnicodeString(
    _Out_writes_(DstChars) PWCHAR Dst,
    _In_ ULONG DstChars,
    _In_opt_ PCUNICODE_STRING Src)
{
    ULONG copyChars;

    if (Dst == NULL || DstChars == 0) {
        return;
    }

    Dst[0] = L'\0';
    if (Src == NULL || Src->Buffer == NULL || Src->Length == 0) {
        return;
    }

    copyChars = Src->Length / sizeof(WCHAR);
    if (copyChars >= DstChars) {
        copyChars = DstChars - 1;
    }

    RtlCopyMemory(Dst, Src->Buffer, copyChars * sizeof(WCHAR));
    Dst[copyChars] = L'\0';
}

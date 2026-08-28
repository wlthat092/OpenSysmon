#include "utils.h"

/*
 * Safely copy a UNICODE_STRING to a fixed-size WCHAR buffer.
 */
VOID
SysmonSafeStringCopy(
    _Out_writes_(MaxChars) WCHAR *Dst,
    _In_opt_ PCUNICODE_STRING Src,
    _In_ ULONG MaxChars)
{
    ULONG copyLen;

    if (Dst == NULL || MaxChars == 0) return;

    if (Src == NULL || Src->Buffer == NULL || Src->Length == 0) {
        Dst[0] = L'\0';
        return;
    }

    copyLen = Src->Length / sizeof(WCHAR);
    if (copyLen >= MaxChars) copyLen = MaxChars - 1;
    RtlCopyMemory(Dst, Src->Buffer, copyLen * sizeof(WCHAR));
    Dst[copyLen] = L'\0';
}

/*
 * Convert ANSI string to wide string.
 */
NTSTATUS
SysmonAnsiToWide(
    _In_ const CHAR *Ansi,
    _Out_writes_(MaxChars) WCHAR *Wide,
    _In_ ULONG MaxChars)
{
    UNICODE_STRING ansiStr;
    UNICODE_STRING wideStr;
    NTSTATUS status;

    if (Ansi == NULL || Wide == NULL || MaxChars == 0) {
        return STATUS_INVALID_PARAMETER;
    }
    if (MaxChars > (MAXUSHORT / sizeof(WCHAR))) {
        return STATUS_INVALID_BUFFER_SIZE;
    }

    RtlInitAnsiString(&ansiStr, Ansi);
    wideStr.Buffer = Wide;
    wideStr.MaximumLength = (USHORT)(MaxChars * sizeof(WCHAR));
    wideStr.Length = 0;

    status = RtlAnsiStringToUnicodeString(&wideStr, &ansiStr, FALSE);
    return status;
}

/*
 * Convert wide string to ANSI.
 */
NTSTATUS
SysmonWideToAnsi(
    _In_ PCWSTR Wide,
    _Out_writes_(MaxChars) CHAR *Ansi,
    _In_ ULONG MaxChars)
{
    UNICODE_STRING wideStr;
    ANSI_STRING ansiStr;
    NTSTATUS status;

    if (Wide == NULL || Ansi == NULL || MaxChars == 0) {
        return STATUS_INVALID_PARAMETER;
    }
    if (MaxChars > MAXUSHORT) {
        return STATUS_INVALID_BUFFER_SIZE;
    }

    RtlInitUnicodeString(&wideStr, Wide);
    ansiStr.Buffer = Ansi;
    ansiStr.MaximumLength = (USHORT)MaxChars;
    ansiStr.Length = 0;

    status = RtlUnicodeStringToAnsiString(&ansiStr, &wideStr, FALSE);
    return status;
}

/*
 * Format a Windows FILETIME (100-nanosecond intervals since 1601-01-01)
 * as a UTC string "YYYY-MM-DD HH:MM:SS.fff".
 */
NTSTATUS
SysmonFormatTimestamp(
    _In_ LONGLONG Timestamp,
    _Out_writes_(64) WCHAR *Buffer)
{
    TIME_FIELDS timeFields;
    LARGE_INTEGER li;

    if (Buffer == NULL) return STATUS_INVALID_PARAMETER;

    li.QuadPart = Timestamp;
    RtlTimeToTimeFields(&li, &timeFields);

    _snwprintf_s(Buffer, 64, _TRUNCATE,
        L"%04d-%02d-%02d %02d:%02d:%02d.%03d",
        timeFields.Year, timeFields.Month, timeFields.Day,
        timeFields.Hour, timeFields.Minute, timeFields.Second,
        timeFields.Milliseconds);
    return STATUS_SUCCESS;
}

/*
 * Simple string hash (FNV-1a variant) for quick lookups.
 */
ULONG
SysmonHashString(
    _In_ PCWSTR String,
    _In_ ULONG MaxLen)
{
    ULONG hash = 2166136261u;
    ULONG i;

    if (String == NULL) return 0;

    for (i = 0; i < MaxLen && String[i] != L'\0'; i++) {
        hash ^= (ULONG)String[i];
        hash *= 16777619u;
    }
    return hash;
}

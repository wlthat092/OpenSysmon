#pragma once
#include "common.h"

/* Wide-char string copy with null termination */
VOID
SysmonSafeStringCopy(
    _Out_writes_(MaxChars) WCHAR *Dst,
    _In_opt_ PCUNICODE_STRING Src,
    _In_ ULONG MaxChars
);

/* Convert ANSI string to wide string */
NTSTATUS
SysmonAnsiToWide(
    _In_ const CHAR *Ansi,
    _Out_writes_(MaxChars) WCHAR *Wide,
    _In_ ULONG MaxChars
);

/* Convert wide string to ANSI */
NTSTATUS
SysmonWideToAnsi(
    _In_ PCWSTR Wide,
    _Out_writes_(MaxChars) CHAR *Ansi,
    _In_ ULONG MaxChars
);

/* Format a LARGE_INTEGER timestamp as UTC string "YYYY-MM-DD HH:MM:SS.fff" */
NTSTATUS
SysmonFormatTimestamp(
    _In_ LONGLONG Timestamp,
    _Out_writes_(64) WCHAR *Buffer
);

/* Hash a wide string to a 32-bit value (for quick lookups) */
ULONG
SysmonHashString(
    _In_ PCWSTR String,
    _In_ ULONG MaxLen
);
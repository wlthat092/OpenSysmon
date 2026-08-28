#pragma once
/*
 * path_cache.h - Shared NT path to Win32 path conversion cache
 */

#include "common.h"

BOOL
SysmonConvertNtPathToWin32Path(
    _In_z_ PCWSTR NtPath,
    _Out_writes_(BufferChars) PWCHAR Buffer,
    _In_ size_t BufferChars);

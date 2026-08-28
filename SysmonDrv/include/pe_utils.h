#pragma once

#include "common.h"

static __forceinline BOOLEAN
SysmonPeHasRange(
    _In_ ULONG FileSize,
    _In_ ULONG Offset,
    _In_ ULONG Length)
{
    return (Offset <= FileSize && Length <= (FileSize - Offset));
}

static __forceinline BOOLEAN
SysmonPeAddUlong(
    _In_ ULONG Left,
    _In_ ULONG Right,
    _Out_ ULONG *Result)
{
    if (Result == NULL || Left > (MAXULONG - Right)) {
        return FALSE;
    }

    *Result = Left + Right;
    return TRUE;
}

static __forceinline BOOLEAN
SysmonPeMultiplyUlong(
    _In_ ULONG Left,
    _In_ ULONG Right,
    _Out_ ULONG *Result)
{
    if (Result == NULL) {
        return FALSE;
    }

    if (Left != 0 && Right > (MAXULONG / Left)) {
        return FALSE;
    }

    *Result = Left * Right;
    return TRUE;
}

static __forceinline BOOLEAN
SysmonPeReadUshort(
    _In_reads_(FileSize) const UCHAR *FileData,
    _In_ ULONG FileSize,
    _In_ ULONG Offset,
    _Out_ USHORT *Value)
{
    if (FileData == NULL || Value == NULL ||
        !SysmonPeHasRange(FileSize, Offset, sizeof(USHORT))) {
        return FALSE;
    }

    RtlCopyMemory(Value, FileData + Offset, sizeof(USHORT));
    return TRUE;
}

static __forceinline BOOLEAN
SysmonPeReadUlong(
    _In_reads_(FileSize) const UCHAR *FileData,
    _In_ ULONG FileSize,
    _In_ ULONG Offset,
    _Out_ ULONG *Value)
{
    if (FileData == NULL || Value == NULL ||
        !SysmonPeHasRange(FileSize, Offset, sizeof(ULONG))) {
        return FALSE;
    }

    RtlCopyMemory(Value, FileData + Offset, sizeof(ULONG));
    return TRUE;
}

static __forceinline BOOLEAN
SysmonPeReadUlongLong(
    _In_reads_(FileSize) const UCHAR *FileData,
    _In_ ULONG FileSize,
    _In_ ULONG Offset,
    _Out_ ULONGLONG *Value)
{
    if (FileData == NULL || Value == NULL ||
        !SysmonPeHasRange(FileSize, Offset, sizeof(ULONGLONG))) {
        return FALSE;
    }

    RtlCopyMemory(Value, FileData + Offset, sizeof(ULONGLONG));
    return TRUE;
}

static __forceinline BOOLEAN
SysmonPeGetLayout(
    _In_reads_(FileSize) const UCHAR *FileData,
    _In_ ULONG FileSize,
    _Out_opt_ ULONG *PeOffset,
    _Out_opt_ USHORT *NumSections,
    _Out_opt_ ULONG *SectionTableOffset,
    _Out_opt_ USHORT *OptHdrSize,
    _Out_opt_ BOOLEAN *Is64)
{
    ULONG peOffset;
    ULONG sectionTableOffset;
    USHORT numSections;
    USHORT optHdrSize;
    USHORT magic;
    ULONG sectionTableSize;

    if (FileData == NULL || !SysmonPeHasRange(FileSize, 0, 0x40)) {
        return FALSE;
    }

    if (FileData[0] != 'M' || FileData[1] != 'Z') {
        return FALSE;
    }

    if (!SysmonPeReadUlong(FileData, FileSize, 0x3C, &peOffset) ||
        !SysmonPeHasRange(FileSize, peOffset, 0x1A) ||
        RtlCompareMemory(FileData + peOffset, "PE\0\0", 4) != 4 ||
        !SysmonPeReadUshort(FileData, FileSize, peOffset + 0x06, &numSections) ||
        !SysmonPeReadUshort(FileData, FileSize, peOffset + 0x14, &optHdrSize) ||
        !SysmonPeReadUshort(FileData, FileSize, peOffset + 0x18, &magic)) {
        return FALSE;
    }

    if (magic != 0x10b && magic != 0x20b) {
        return FALSE;
    }

    if (!SysmonPeAddUlong(peOffset, 0x18, &sectionTableOffset) ||
        !SysmonPeAddUlong(sectionTableOffset, optHdrSize, &sectionTableOffset) ||
        !SysmonPeMultiplyUlong((ULONG)numSections, 40, &sectionTableSize) ||
        !SysmonPeHasRange(FileSize, sectionTableOffset, sectionTableSize)) {
        return FALSE;
    }

    if (PeOffset != NULL) {
        *PeOffset = peOffset;
    }
    if (NumSections != NULL) {
        *NumSections = numSections;
    }
    if (SectionTableOffset != NULL) {
        *SectionTableOffset = sectionTableOffset;
    }
    if (OptHdrSize != NULL) {
        *OptHdrSize = optHdrSize;
    }
    if (Is64 != NULL) {
        *Is64 = (magic == 0x20b);
    }

    return TRUE;
}

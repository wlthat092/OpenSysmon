#include "minifilter.h"
#include "obcallback.h"
#include "tampering.h"
#include "queue.h"
#include "event.h"
#include "driver.h"
#include "communication.h"
#include "fileinfo.h"
#include "hash.h"
#include "pipe.h"
#include "process.h"
#include "processinfo.h"
#include "utils.h"

PFLT_FILTER g_FilterHandle = NULL;
#if DBG
static volatile LONG g_FileCreateCandidateCount = 0;
static volatile LONG g_FileCreatePostCreateCount = 0;
static volatile LONG g_FileCreateIrqlDropCount = 0;
static volatile LONG g_FileCreateStatusFailureCount = 0;
static volatile LONG g_FileCreateNotCreatedCount = 0;
static volatile LONG g_FileCreatePublishAttemptCount = 0;
static volatile LONG g_LastFileCreateStatus = 0;
static volatile LONG g_LastFileCreateInfo = 0;
static volatile LONG g_LastFileCreateIrql = 0;
static volatile LONG g_LastFileCreateDisposition = 0;
static volatile LONG g_LastFileCreateReportStatus = 0;
static volatile LONG g_FileBlockContextCreateCount = 0;
static volatile LONG g_FileBlockWriteCallbackCount = 0;
static volatile LONG g_FileBlockSawWriteCount = 0;
static volatile LONG g_FileBlockHeaderCheckCount = 0;
static volatile LONG g_FileBlockHeaderMatchCount = 0;
static volatile LONG g_FileBlockFinalizeAttemptCount = 0;
static volatile LONG g_FileBlockFinalizeSkipNoWriteCount = 0;
static volatile LONG g_FileBlockFinalizeSkipNotPeCount = 0;
static volatile LONG g_FileBlockFinalizeWouldBlockCount = 0;
static volatile LONG g_FileBlockFinalizeWouldDetectCount = 0;
static volatile LONG g_FileBlockActionSuccessCount = 0;
static volatile LONG g_FileBlockEvent27Count = 0;
static volatile LONG g_FileBlockEvent29Count = 0;
static volatile LONG g_FileBlockLastFlags = 0;
static volatile LONG g_FileBlockLastActionStatus = 0;
static volatile LONG g_FileBlockLastReportStatus = 0;
#define SYSMON_FILE_CREATE_STAT_INC(Counter) InterlockedIncrement(&(Counter))
#define SYSMON_FILE_CREATE_STAT_SET(Counter, Value) InterlockedExchange(&(Counter), (LONG)(Value))
#define SYSMON_FILE_CREATE_STAT_READ(Counter) ((ULONG)(Counter))
#define SYSMON_FILE_BLOCK_STAT_INC(Counter) InterlockedIncrement(&(Counter))
#define SYSMON_FILE_BLOCK_STAT_SET(Counter, Value) InterlockedExchange(&(Counter), (LONG)(Value))
#define SYSMON_FILE_BLOCK_STAT_READ(Counter) ((ULONG)(Counter))
#else
#define SYSMON_FILE_CREATE_STAT_INC(Counter) ((VOID)0)
#define SYSMON_FILE_CREATE_STAT_SET(Counter, Value) ((VOID)0)
#define SYSMON_FILE_CREATE_STAT_READ(Counter) (0UL)
#define SYSMON_FILE_BLOCK_STAT_INC(Counter) ((VOID)0)
#define SYSMON_FILE_BLOCK_STAT_SET(Counter, Value) ((VOID)0)
#define SYSMON_FILE_BLOCK_STAT_READ(Counter) (0UL)
#endif
static volatile LONG g_MinifilterLookasideInitialized = 0;
static NPAGED_LOOKASIDE_LIST g_MinifilterProcessInfoLookaside;
static NPAGED_LOOKASIDE_LIST g_MinifilterFileInfoLookaside;

static VOID
SysmonInitializeMinifilterLookasides(VOID)
{
    if (InterlockedCompareExchange(&g_MinifilterLookasideInitialized, 1, 0) != 0) {
        return;
    }

    ExInitializeNPagedLookasideList(
        &g_MinifilterProcessInfoLookaside,
        NULL,
        NULL,
        0,
        sizeof(SYSMON_PROCESS_INFO),
        SYSMON_POOL_TAG,
        0);
    ExInitializeNPagedLookasideList(
        &g_MinifilterFileInfoLookaside,
        NULL,
        NULL,
        0,
        sizeof(SYSMON_FILE_INFO),
        SYSMON_POOL_TAG,
        0);
}

static VOID
SysmonCleanupMinifilterLookasides(VOID)
{
    if (InterlockedExchange(&g_MinifilterLookasideInitialized, 0) == 0) {
        return;
    }

    ExDeleteNPagedLookasideList(&g_MinifilterFileInfoLookaside);
    ExDeleteNPagedLookasideList(&g_MinifilterProcessInfoLookaside);
}

static SYSMON_PROCESS_INFO *
SysmonAllocateMinifilterProcessInfo(VOID)
{
    SYSMON_PROCESS_INFO *processInfo;

    if (InterlockedCompareExchange(&g_MinifilterLookasideInitialized, 0, 0) == 0) {
        return (SYSMON_PROCESS_INFO *)SysmonAllocatePool(sizeof(SYSMON_PROCESS_INFO));
    }

    processInfo = (SYSMON_PROCESS_INFO *)ExAllocateFromNPagedLookasideList(
        &g_MinifilterProcessInfoLookaside);
    if (processInfo != NULL) {
        RtlZeroMemory(processInfo, sizeof(*processInfo));
    }

    return processInfo;
}

static VOID
SysmonFreeMinifilterProcessInfo(_In_opt_ SYSMON_PROCESS_INFO *ProcessInfo)
{
    if (ProcessInfo == NULL) {
        return;
    }

    if (InterlockedCompareExchange(&g_MinifilterLookasideInitialized, 0, 0) != 0) {
        ExFreeToNPagedLookasideList(&g_MinifilterProcessInfoLookaside, ProcessInfo);
        return;
    }

    SysmonFreePool(ProcessInfo);
}

static SYSMON_FILE_INFO *
SysmonAllocateMinifilterFileInfo(VOID)
{
    SYSMON_FILE_INFO *fileInfo;

    if (InterlockedCompareExchange(&g_MinifilterLookasideInitialized, 0, 0) == 0) {
        return (SYSMON_FILE_INFO *)SysmonAllocatePool(sizeof(SYSMON_FILE_INFO));
    }

    fileInfo = (SYSMON_FILE_INFO *)ExAllocateFromNPagedLookasideList(
        &g_MinifilterFileInfoLookaside);
    if (fileInfo != NULL) {
        RtlZeroMemory(fileInfo, sizeof(*fileInfo));
    }

    return fileInfo;
}

static VOID
SysmonFreeMinifilterFileInfo(_In_opt_ SYSMON_FILE_INFO *FileInfo)
{
    if (FileInfo == NULL) {
        return;
    }

    if (InterlockedCompareExchange(&g_MinifilterLookasideInitialized, 0, 0) != 0) {
        ExFreeToNPagedLookasideList(&g_MinifilterFileInfoLookaside, FileInfo);
        return;
    }

    SysmonFreePool(FileInfo);
}

/* ========================================================================
 * Helper: Check if request is from user mode
 * ======================================================================== */
static FORCEINLINE BOOLEAN
SysmonIsUserModeRequest(_In_ PFLT_CALLBACK_DATA Data)
{
    return (Data->RequestorMode == UserMode);
}

static FORCEINLINE BOOLEAN
SysmonEnterMinifilterCallback(VOID)
{
    if (!SysmonAcquireDriverRundown()) {
        return FALSE;
    }

    if (InterlockedCompareExchange(&g_Context.CapturePaused, 0, 0) != 0) {
        SysmonReleaseDriverRundown();
        return FALSE;
    }

    return TRUE;
}

static FORCEINLINE VOID
SysmonLeaveMinifilterCallback(VOID)
{
    SysmonReleaseDriverRundown();
}

/* ========================================================================
 * Helper: Check if file is on a raw volume
 * ======================================================================== */
static BOOLEAN
SysmonTryGetRawVolumeDeviceName(
    _In_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Out_writes_(BufferChars) PWCHAR Buffer,
    _In_ ULONG BufferChars)
{
    PFLT_FILE_NAME_INFORMATION nameInfo = NULL;
    PFILE_OBJECT fileObj;
    static const WCHAR volumePrefix[] = L"\\Device\\HarddiskVolume";
    ULONG nameChars;
    ULONG prefixChars;
    ULONG index;
    NTSTATUS status;

    if (Buffer == NULL || BufferChars == 0) {
        return FALSE;
    }

    Buffer[0] = L'\0';

    /*
     * Match the original minifilter path: detect a direct volume open via the
     * opened-name components rather than by string-prefix matching alone.
     */
    status = FltGetFileNameInformation(
        Data,
        FLT_FILE_NAME_QUERY_ALWAYS_ALLOW_CACHE_LOOKUP | FLT_FILE_NAME_OPENED,
        &nameInfo);
    if (NT_SUCCESS(status)) {
        status = FltParseFileNameInformation(nameInfo);
        if (NT_SUCCESS(status) &&
            nameInfo->ParentDir.Length == 0 &&
            nameInfo->Share.Length == 0 &&
            nameInfo->FinalComponent.Length == 0 &&
            nameInfo->Extension.Length == 0 &&
            nameInfo->Volume.Length != 0) {
            SysmonCopyUnicodeString(Buffer, BufferChars, &nameInfo->Volume);
            FltReleaseFileNameInformation(nameInfo);
            return (Buffer[0] != L'\0');
        }

        FltReleaseFileNameInformation(nameInfo);
    }

    /*
     * Keep a conservative fallback for cases where name parsing is
     * unavailable, but only for exact volume device opens.
     */
    if (FltObjects == NULL) {
        return FALSE;
    }

    fileObj = FltObjects->FileObject;
    if (fileObj == NULL || fileObj->FileName.Buffer == NULL || fileObj->FileName.Length == 0) {
        return FALSE;
    }

    nameChars = fileObj->FileName.Length / sizeof(WCHAR);
    prefixChars = (ULONG)((sizeof(volumePrefix) / sizeof(WCHAR)) - 1);
    if (nameChars < prefixChars ||
        RtlCompareMemory(fileObj->FileName.Buffer, volumePrefix, prefixChars * sizeof(WCHAR)) !=
            prefixChars * sizeof(WCHAR)) {
        return FALSE;
    }

    index = prefixChars;
    while (index < nameChars &&
           fileObj->FileName.Buffer[index] >= L'0' &&
           fileObj->FileName.Buffer[index] <= L'9') {
        index++;
    }

    if (index != nameChars) {
        return FALSE;
    }

    SysmonCopyUnicodeString(Buffer, BufferChars, &fileObj->FileName);
    return (Buffer[0] != L'\0');
}

/* ========================================================================
 * Helper: Check if filename has alternate data stream
 * ======================================================================== */
static FORCEINLINE BOOLEAN
SysmonHasAlternateStream(_In_ PCUNICODE_STRING FileName)
{
    USHORT i;
    if (FileName == NULL || FileName->Buffer == NULL) return FALSE;
    /* Look for ':' in filename (after drive letter if present) */
    for (i = 6; i < FileName->Length / sizeof(WCHAR); i++) {
        if (FileName->Buffer[i] == L':') return TRUE;
    }
    return FALSE;
}

/* ========================================================================
 * Helper: Check if file is an executable (by extension)
 * ======================================================================== */
static BOOLEAN
SysmonIsExecutable(_In_ PCUNICODE_STRING FileName)
{
    static const WCHAR exeExt[] = L".exe";
    static const WCHAR dllExt[] = L".dll";
    static const WCHAR sysExt[] = L".sys";
    static const WCHAR scrExt[] = L".scr";
    static const WCHAR comExt[] = L".com";
    static const WCHAR batExt[] = L".bat";
    static const WCHAR cmdExt[] = L".cmd";
    static const WCHAR ps1Ext[] = L".ps1";
    USHORT len;
    PCWSTR ext;

    if (FileName == NULL || FileName->Buffer == NULL || FileName->Length < 8) {
        return FALSE;
    }

    len = FileName->Length / sizeof(WCHAR);
    ext = FileName->Buffer + len - 4;

    return (_wcsnicmp(ext, exeExt, 4) == 0 ||
            _wcsnicmp(ext, dllExt, 4) == 0 ||
            _wcsnicmp(ext, sysExt, 4) == 0 ||
            _wcsnicmp(ext, scrExt, 4) == 0 ||
            _wcsnicmp(ext, comExt, 4) == 0 ||
            _wcsnicmp(ext, batExt, 4) == 0 ||
            _wcsnicmp(ext, cmdExt, 4) == 0 ||
            _wcsnicmp(ext, ps1Ext, 4) == 0);
}

#define SYSMON_FILE_BLOCK_CTX_ARMED             0x00000001UL
#define SYSMON_FILE_BLOCK_CTX_CREATE_SUCCEEDED  0x00000002UL
#define SYSMON_FILE_BLOCK_CTX_FILE_CREATED      0x00000004UL
/*
 * Keep the low FileBlock state bits aligned with the original Sysmon 15.20
 * stream-handle context layout observed in SysmonDrv+0x2930/0x61A0/0x6330.
 */
#define SYSMON_FILE_BLOCK_CTX_SAW_WRITE         0x00000008UL
#define SYSMON_FILE_BLOCK_CTX_HEADER_CHECKED    0x00000010UL
#define SYSMON_FILE_BLOCK_CTX_IS_PE             0x00000020UL
#define SYSMON_FILE_BLOCK_CTX_EVENT_REPORTED    0x80000000UL

typedef struct _SYSMON_FILE_BLOCK_STREAM_CONTEXT {
    ULONG Flags;
    ULONG ProcessId;
    UCHAR CreateDisposition;
    WCHAR OriginalPath[SYSMON_MAX_PATH];
    WCHAR Extension[64];
} SYSMON_FILE_BLOCK_STREAM_CONTEXT, *PSYSMON_FILE_BLOCK_STREAM_CONTEXT;

typedef struct _SYSMON_FILE_BLOCK_SOURCE_IDENTITY {
    LARGE_INTEGER EndOfFile;
    LARGE_INTEGER AllocationSize;
    LARGE_INTEGER CreationTime;
    LARGE_INTEGER LastWriteTime;
    LARGE_INTEGER ChangeTime;
    ULONG FileAttributes;
} SYSMON_FILE_BLOCK_SOURCE_IDENTITY, *PSYSMON_FILE_BLOCK_SOURCE_IDENTITY;

static VOID
SysmonExtractExtension(
    _In_opt_z_ PCWSTR Path,
    _Out_writes_(ExtensionChars) PWCHAR Extension,
    _In_ ULONG ExtensionChars)
{
    PCWSTR cursor;
    PCWSTR lastDot = NULL;
    PCWSTR lastSeparator = NULL;

    if (Extension == NULL || ExtensionChars == 0) {
        return;
    }

    Extension[0] = L'\0';
    if (Path == NULL || Path[0] == L'\0') {
        return;
    }

    for (cursor = Path; *cursor != L'\0'; cursor++) {
        if (*cursor == L'\\' || *cursor == L'/') {
            lastSeparator = cursor;
            lastDot = NULL;
        } else if (*cursor == L'.') {
            lastDot = cursor;
        }
    }

    if (lastDot == NULL ||
        (lastSeparator != NULL && lastDot <= lastSeparator)) {
        return;
    }

    SysmonCopyWideString(Extension, ExtensionChars, lastDot);
}

static BOOLEAN
SysmonReadBytesAtOffset(
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ LARGE_INTEGER ByteOffset,
    _Out_writes_bytes_(BufferSize) PUCHAR Buffer,
    _In_ ULONG BufferSize,
    _Out_ PULONG BytesRead)
{
    NTSTATUS status;

    if (BytesRead == NULL ||
        Buffer == NULL ||
        BufferSize == 0 ||
        FltObjects == NULL ||
        FltObjects->Instance == NULL ||
        FltObjects->FileObject == NULL) {
        return FALSE;
    }

    *BytesRead = 0;
    status = FltReadFile(
        FltObjects->Instance,
        FltObjects->FileObject,
        &ByteOffset,
        BufferSize,
        Buffer,
        FLTFL_IO_OPERATION_NON_CACHED | FLTFL_IO_OPERATION_DO_NOT_UPDATE_BYTE_OFFSET,
        BytesRead,
        NULL,
        NULL);
    return NT_SUCCESS(status);
}

static BOOLEAN
SysmonBuildNtFilePath(
    _In_z_ PCWSTR FilePath,
    _Out_ PUNICODE_STRING NtPath,
    _Out_writes_(BufferChars) PWCHAR Buffer,
    _In_ ULONG BufferChars)
{
    if (FilePath == NULL || FilePath[0] == L'\0' ||
        NtPath == NULL || Buffer == NULL || BufferChars == 0) {
        return FALSE;
    }

    Buffer[0] = L'\0';
    if (((FilePath[0] >= L'A' && FilePath[0] <= L'Z') ||
         (FilePath[0] >= L'a' && FilePath[0] <= L'z')) &&
        FilePath[1] == L':') {
        if (_snwprintf_s(Buffer, BufferChars, _TRUNCATE, L"\\??\\%ls", FilePath) < 0) {
            return FALSE;
        }
    } else {
        SysmonCopyWideString(Buffer, BufferChars, FilePath);
    }

    RtlInitUnicodeString(NtPath, Buffer);
    return NtPath->Buffer != NULL && NtPath->Length != 0;
}

static BOOLEAN
SysmonDetectPeFromPath(
    _In_z_ PCWSTR FilePath)
{
    WCHAR ntPathBuffer[SYSMON_MAX_PATH + 8];
    UNICODE_STRING ntPath;
    OBJECT_ATTRIBUTES objectAttributes;
    IO_STATUS_BLOCK ioStatusBlock;
    LARGE_INTEGER offset;
    HANDLE fileHandle = NULL;
    UCHAR dosHeader[0x40];
    UCHAR peSignature[4];
    ULONG bytesRead = 0;
    ULONG peOffset = 0;
    NTSTATUS status;
    BOOLEAN isPe = FALSE;

    if (!SysmonBuildNtFilePath(
            FilePath,
            &ntPath,
            ntPathBuffer,
            RTL_NUMBER_OF(ntPathBuffer))) {
        return FALSE;
    }

    InitializeObjectAttributes(
        &objectAttributes,
        &ntPath,
        OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
        NULL,
        NULL);

    status = ZwOpenFile(
        &fileHandle,
        FILE_GENERIC_READ | SYNCHRONIZE,
        &objectAttributes,
        &ioStatusBlock,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT);
    if (!NT_SUCCESS(status)) {
        return FALSE;
    }

    offset.QuadPart = 0;
    status = ZwReadFile(
        fileHandle,
        NULL,
        NULL,
        NULL,
        &ioStatusBlock,
        dosHeader,
        sizeof(dosHeader),
        &offset,
        NULL);
    if (!NT_SUCCESS(status) ||
        ioStatusBlock.Information < sizeof(dosHeader) ||
        dosHeader[0] != 'M' ||
        dosHeader[1] != 'Z') {
        goto Cleanup;
    }

    RtlCopyMemory(&peOffset, dosHeader + 0x3C, sizeof(peOffset));
    offset.QuadPart = peOffset;
    status = ZwReadFile(
        fileHandle,
        NULL,
        NULL,
        NULL,
        &ioStatusBlock,
        peSignature,
        sizeof(peSignature),
        &offset,
        NULL);
    bytesRead = (ULONG)ioStatusBlock.Information;
    if (NT_SUCCESS(status) &&
        bytesRead >= sizeof(peSignature) &&
        RtlCompareMemory(peSignature, "PE\0\0", sizeof(peSignature)) ==
            sizeof(peSignature)) {
        isPe = TRUE;
    }

Cleanup:
    if (fileHandle != NULL) {
        ZwClose(fileHandle);
    }
    return isPe;
}

static BOOLEAN
SysmonDetectPeFromFileObject(
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Out_opt_ PBOOLEAN HeaderChecked)
{
    UCHAR dosHeader[0x40];
    UCHAR peSignature[4];
    LARGE_INTEGER offset;
    ULONG bytesRead = 0;
    ULONG peOffset = 0;
    BOOLEAN headerChecked = FALSE;
    BOOLEAN isPe = FALSE;

    if (HeaderChecked != NULL) {
        *HeaderChecked = FALSE;
    }

    offset.QuadPart = 0;
    if (!SysmonReadBytesAtOffset(
            FltObjects,
            offset,
            dosHeader,
            sizeof(dosHeader),
            &bytesRead) ||
        bytesRead < sizeof(dosHeader)) {
        goto Exit;
    }

    if (dosHeader[0] != 'M' || dosHeader[1] != 'Z') {
        headerChecked = TRUE;
        goto Exit;
    }

    RtlCopyMemory(&peOffset, dosHeader + 0x3C, sizeof(peOffset));
    offset.QuadPart = peOffset;
    if (!SysmonReadBytesAtOffset(
            FltObjects,
            offset,
            peSignature,
            sizeof(peSignature),
            &bytesRead) ||
        bytesRead < sizeof(peSignature)) {
        goto Exit;
    }

    headerChecked = TRUE;
    isPe = (RtlCompareMemory(peSignature, "PE\0\0", sizeof(peSignature)) ==
            sizeof(peSignature));

Exit:
    if (HeaderChecked != NULL) {
        *HeaderChecked = headerChecked;
    }

    return isPe;
}

static NTSTATUS
SysmonCaptureFileIdentity(
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Out_ PSYSMON_FILE_BLOCK_SOURCE_IDENTITY Identity)
{
    FILE_STANDARD_INFORMATION standardInfo;
    FILE_BASIC_INFORMATION basicInfo;
    ULONG returnedBytes = 0;
    NTSTATUS status;

    if (FltObjects == NULL ||
        FltObjects->Instance == NULL ||
        FltObjects->FileObject == NULL ||
        Identity == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    RtlZeroMemory(Identity, sizeof(*Identity));
    RtlZeroMemory(&standardInfo, sizeof(standardInfo));
    RtlZeroMemory(&basicInfo, sizeof(basicInfo));

    status = FltQueryInformationFile(
        FltObjects->Instance,
        FltObjects->FileObject,
        &standardInfo,
        sizeof(standardInfo),
        FileStandardInformation,
        &returnedBytes);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    status = FltQueryInformationFile(
        FltObjects->Instance,
        FltObjects->FileObject,
        &basicInfo,
        sizeof(basicInfo),
        FileBasicInformation,
        &returnedBytes);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    Identity->EndOfFile = standardInfo.EndOfFile;
    Identity->AllocationSize = standardInfo.AllocationSize;
    Identity->CreationTime = basicInfo.CreationTime;
    Identity->LastWriteTime = basicInfo.LastWriteTime;
    Identity->ChangeTime = basicInfo.ChangeTime;
    Identity->FileAttributes = basicInfo.FileAttributes;
    return STATUS_SUCCESS;
}

static BOOLEAN
SysmonFileIdentityMatches(
    _In_ const SYSMON_FILE_BLOCK_SOURCE_IDENTITY *Left,
    _In_ const SYSMON_FILE_BLOCK_SOURCE_IDENTITY *Right)
{
    if (Left == NULL || Right == NULL) {
        return FALSE;
    }

    return Left->EndOfFile.QuadPart == Right->EndOfFile.QuadPart &&
        Left->AllocationSize.QuadPart == Right->AllocationSize.QuadPart &&
        Left->CreationTime.QuadPart == Right->CreationTime.QuadPart &&
        Left->LastWriteTime.QuadPart == Right->LastWriteTime.QuadPart &&
        Left->ChangeTime.QuadPart == Right->ChangeTime.QuadPart &&
        Left->FileAttributes == Right->FileAttributes;
}

static BOOLEAN
SysmonRevalidateFileBlockExecutable(
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Inout_ PSYSMON_FILE_BLOCK_STREAM_CONTEXT StreamContext)
{
    BOOLEAN headerChecked = FALSE;
    BOOLEAN isPe;

    if (StreamContext == NULL) {
        return FALSE;
    }

    isPe = SysmonDetectPeFromFileObject(FltObjects, &headerChecked);
    if (headerChecked) {
        StreamContext->Flags |= SYSMON_FILE_BLOCK_CTX_HEADER_CHECKED;
        if (isPe) {
            StreamContext->Flags |= SYSMON_FILE_BLOCK_CTX_IS_PE;
        } else {
            StreamContext->Flags &= ~SYSMON_FILE_BLOCK_CTX_IS_PE;
        }
    }

    return isPe;
}

static NTSTATUS
SysmonLookupFileBlockStreamContext(
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Outptr_ PSYSMON_FILE_BLOCK_STREAM_CONTEXT *StreamContextOut)
{
    if (StreamContextOut == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    *StreamContextOut = NULL;
    if (FltObjects == NULL ||
        FltObjects->Instance == NULL ||
        FltObjects->FileObject == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    return FltGetStreamHandleContext(
        FltObjects->Instance,
        FltObjects->FileObject,
        (PFLT_CONTEXT *)StreamContextOut);
}

static NTSTATUS
SysmonGetOrCreateFileBlockStreamContext(
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Outptr_ PSYSMON_FILE_BLOCK_STREAM_CONTEXT *StreamContextOut)
{
    PSYSMON_FILE_BLOCK_STREAM_CONTEXT streamContext = NULL;
    PFLT_CONTEXT existingContext = NULL;
    NTSTATUS status;

    if (StreamContextOut == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    *StreamContextOut = NULL;

    status = SysmonLookupFileBlockStreamContext(FltObjects, &streamContext);
    if (NT_SUCCESS(status) && streamContext != NULL) {
        *StreamContextOut = streamContext;
        return STATUS_SUCCESS;
    }

    if (g_FilterHandle == NULL ||
        FltObjects == NULL ||
        FltObjects->Instance == NULL ||
        FltObjects->FileObject == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    status = FltAllocateContext(
        g_FilterHandle,
        FLT_STREAMHANDLE_CONTEXT,
        sizeof(*streamContext),
        SysmonGetPoolType(),
        (PFLT_CONTEXT *)&streamContext);
    if (!NT_SUCCESS(status) || streamContext == NULL) {
        return status;
    }

    RtlZeroMemory(streamContext, sizeof(*streamContext));

    status = FltSetStreamHandleContext(
        FltObjects->Instance,
        FltObjects->FileObject,
        FLT_SET_CONTEXT_KEEP_IF_EXISTS,
        streamContext,
        &existingContext);
    if (status == STATUS_FLT_CONTEXT_ALREADY_DEFINED &&
        existingContext != NULL) {
        FltReleaseContext(streamContext);
        *StreamContextOut = (PSYSMON_FILE_BLOCK_STREAM_CONTEXT)existingContext;
        return STATUS_SUCCESS;
    }

    if (existingContext != NULL) {
        FltReleaseContext(existingContext);
    }

    if (!NT_SUCCESS(status)) {
        FltReleaseContext(streamContext);
        return status;
    }

    *StreamContextOut = streamContext;
    return STATUS_SUCCESS;
}

static BOOLEAN
SysmonMultiSzContainsInsensitive(
    _In_reads_bytes_opt_(MultiSzBytes) PCWSTR MultiSz,
    _In_ ULONG MultiSzBytes,
    _In_z_ PCWSTR Value)
{
    PCWSTR current;
    SIZE_T valueLength;
    ULONG remainingBytes;

    if (MultiSz == NULL ||
        MultiSzBytes < (2 * sizeof(WCHAR)) ||
        Value == NULL ||
        Value[0] == L'\0') {
        return FALSE;
    }

    valueLength = wcslen(Value);
    current = MultiSz;
    remainingBytes = MultiSzBytes;
    while (remainingBytes >= sizeof(WCHAR) && *current != L'\0') {
        SIZE_T currentLength = wcslen(current);
        SIZE_T currentBytes = (currentLength + 1) * sizeof(WCHAR);

        if (currentBytes > remainingBytes) {
            break;
        }

        if (_wcsnicmp(current, Value, valueLength + 1) == 0) {
            return TRUE;
        }

        current += currentLength + 1;
        remainingBytes -= (ULONG)currentBytes;
    }

    return FALSE;
}

static BOOLEAN
SysmonShouldPreserveExecutableSample(
    _In_opt_ PSYSMON_RULE_RUNTIME Runtime,
    _In_z_ PCWSTR Extension,
    _In_z_ PCWSTR RequestorImage,
    _In_z_ PCWSTR RequestorSid)
{
    if (Runtime == NULL) {
        return FALSE;
    }

    if (Runtime->CopyOnDeletePE) {
        return TRUE;
    }

    if (SysmonMultiSzContainsInsensitive(
            Runtime->CopyOnDeleteExtensionsMultiSz,
            Runtime->CopyOnDeleteExtensionsBytes,
            Extension)) {
        return TRUE;
    }

    if (SysmonMultiSzContainsInsensitive(
            Runtime->CopyOnDeleteProcessesMultiSz,
            Runtime->CopyOnDeleteProcessesBytes,
            RequestorImage)) {
        return TRUE;
    }

    if (SysmonMultiSzContainsInsensitive(
            Runtime->CopyOnDeleteSIDsMultiSz,
            Runtime->CopyOnDeleteSIDsBytes,
            RequestorSid)) {
        return TRUE;
    }

    return FALSE;
}

static BOOLEAN
SysmonExtractTaggedHashValue(
    _In_z_ PCWSTR HashString,
    _In_z_ PCWSTR Label,
    _Out_writes_(OutputChars) PWCHAR Output,
    _In_ ULONG OutputChars)
{
    WCHAR pattern[32];
    const WCHAR *cursor;
    const WCHAR *valueStart;
    const WCHAR *valueEnd;
    SIZE_T patternLength;
    SIZE_T valueChars;

    if (HashString == NULL ||
        Label == NULL ||
        Output == NULL ||
        OutputChars == 0) {
        return FALSE;
    }

    Output[0] = L'\0';
    if (_snwprintf_s(pattern, RTL_NUMBER_OF(pattern), _TRUNCATE, L"%ls=", Label) < 0) {
        return FALSE;
    }

    patternLength = wcslen(pattern);
    for (cursor = HashString; *cursor != L'\0'; ) {
        while (*cursor == L' ' || *cursor == L',') {
            cursor++;
        }

        if (_wcsnicmp(cursor, pattern, patternLength) == 0) {
            valueStart = cursor + patternLength;
            valueEnd = valueStart;
            while (*valueEnd != L'\0' && *valueEnd != L',') {
                valueEnd++;
            }

            valueChars = (SIZE_T)(valueEnd - valueStart);
            SysmonCopyWideStringWithLength(Output, OutputChars, valueStart, (ULONG)valueChars);
            return (Output[0] != L'\0');
        }

        while (*cursor != L'\0' && *cursor != L',') {
            cursor++;
        }
        if (*cursor == L',') {
            cursor++;
        }
    }

    return FALSE;
}

static BOOLEAN
SysmonBuildArchiveHashKeyFromHashString(
    _In_z_ PCWSTR HashString,
    _In_ ULONG HashMask,
    _Out_writes_(BufferChars) PWCHAR Buffer,
    _In_ ULONG BufferChars)
{
    static const struct {
        ULONG Mask;
        PCWSTR Label;
    } g_HashPreference[] = {
        { SysmonHashSHA1, L"SHA1" },
        { SysmonHashMD5, L"MD5" },
        { SysmonHashSHA256, L"SHA256" },
        { SysmonHashIMPHASH, L"IMPHASH" }
    };
    ULONG index;

    if (Buffer == NULL || BufferChars == 0) {
        return FALSE;
    }

    Buffer[0] = L'\0';
    if (HashString == NULL ||
        HashString[0] == L'\0' ||
        HashString[0] == L'-' ||
        _wcsnicmp(HashString, L"ERR=", 4) == 0) {
        return FALSE;
    }

    for (index = 0; index < RTL_NUMBER_OF(g_HashPreference); index++) {
        if ((HashMask & g_HashPreference[index].Mask) != 0 &&
            SysmonExtractTaggedHashValue(
                HashString,
                g_HashPreference[index].Label,
                Buffer,
                BufferChars)) {
            return TRUE;
        }
    }

    for (index = 0; index < RTL_NUMBER_OF(g_HashPreference); index++) {
        if (SysmonExtractTaggedHashValue(
                HashString,
                g_HashPreference[index].Label,
                Buffer,
                BufferChars)) {
            return TRUE;
        }
    }

    return FALSE;
}

static NTSTATUS
SysmonBuildArchiveHashKey(
    _In_z_ PCWSTR OriginalPath,
    _In_ ULONG HashingAlgorithm,
    _Out_writes_(SYSMON_MAX_HASH_STRING) PWCHAR ArchiveKey)
{
    SYSMON_FILE_INFO fileInfo;
    NTSTATUS status;

    if (OriginalPath == NULL || ArchiveKey == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    RtlZeroMemory(&fileInfo, sizeof(fileInfo));
    ArchiveKey[0] = L'\0';
    status = SysmonCollectFileInfoByPathEx(
        OriginalPath,
        SYSMON_FILEINFO_REQUEST_HASHES,
        &fileInfo);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    return SysmonBuildArchiveHashKeyFromHashString(
            fileInfo.Hashes,
            HashingAlgorithm,
            ArchiveKey,
            SYSMON_MAX_HASH_STRING)
        ? STATUS_SUCCESS
        : STATUS_NOT_FOUND;
}

static NTSTATUS
SysmonBuildArchiveRootPath(
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ PCUNICODE_STRING ArchiveDirectoryComponent,
    _Out_writes_(SYSMON_MAX_PATH) PWCHAR ArchiveRoot)
{
    UNICODE_STRING archiveRoot;
    ULONG bufferSizeNeeded = 0;
    NTSTATUS status;

    if (FltObjects == NULL ||
        FltObjects->Volume == NULL ||
        ArchiveDirectoryComponent == NULL ||
        ArchiveDirectoryComponent->Buffer == NULL ||
        ArchiveRoot == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    ArchiveRoot[0] = L'\0';
    status = FltGetVolumeName(FltObjects->Volume, NULL, &bufferSizeNeeded);
    if (status != STATUS_BUFFER_TOO_SMALL || bufferSizeNeeded < sizeof(WCHAR)) {
        return status;
    }

    if (bufferSizeNeeded > (SYSMON_MAX_PATH * sizeof(WCHAR))) {
        return STATUS_BUFFER_OVERFLOW;
    }

    RtlZeroMemory(ArchiveRoot, SYSMON_MAX_PATH * sizeof(WCHAR));
    archiveRoot.Buffer = ArchiveRoot;
    archiveRoot.Length = 0;
    archiveRoot.MaximumLength = (USHORT)(SYSMON_MAX_PATH * sizeof(WCHAR));

    status = FltGetVolumeName(FltObjects->Volume, &archiveRoot, NULL);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    if ((ULONG)archiveRoot.Length +
            (ULONG)ArchiveDirectoryComponent->Length +
            sizeof(WCHAR) >
        archiveRoot.MaximumLength) {
        return STATUS_BUFFER_OVERFLOW;
    }

    status = RtlAppendUnicodeStringToString(&archiveRoot, ArchiveDirectoryComponent);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    ArchiveRoot[archiveRoot.Length / sizeof(WCHAR)] = L'\0';
    return STATUS_SUCCESS;
}

static NTSTATUS
SysmonBuildArchiveDestinationName(
    _In_ PSYSMON_RULE_RUNTIME Runtime,
    _In_z_ PCWSTR OriginalPath,
    _Out_writes_(SYSMON_MAX_PATH) PWCHAR ArchiveFileName)
{
    WCHAR archiveKey[SYSMON_MAX_HASH_STRING];
    WCHAR extension[64];
    NTSTATUS status;

    if (Runtime == NULL ||
        OriginalPath == NULL ||
        ArchiveFileName == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    status = SysmonBuildArchiveHashKey(
        OriginalPath,
        Runtime->HashingAlgorithm,
        archiveKey);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    SysmonExtractExtension(OriginalPath, extension, RTL_NUMBER_OF(extension));
    if (extension[0] != L'\0') {
        if (_snwprintf_s(
                ArchiveFileName,
                SYSMON_MAX_PATH,
                _TRUNCATE,
                L"%ls%ls",
                archiveKey,
                extension) < 0) {
            return STATUS_BUFFER_OVERFLOW;
        }
    } else {
        if (_snwprintf_s(
                ArchiveFileName,
                SYSMON_MAX_PATH,
                _TRUNCATE,
                L"%ls",
                archiveKey) < 0) {
            return STATUS_BUFFER_OVERFLOW;
        }
    }

    return STATUS_SUCCESS;
}

static NTSTATUS
SysmonBuildArchiveDirectorySecurityDescriptor(
    _Out_ PSECURITY_DESCRIPTOR SecurityDescriptor,
    _Outptr_ PACL *DaclOut,
    _Outptr_ PACL *SaclOut)
{
    PACL dacl = NULL;
    PACL sacl = NULL;
    ULONG daclSize;
    ULONG saclSize;
    ULONG mandatorySidLength;
    NTSTATUS status;
    PSYSTEM_MANDATORY_LABEL_ACE mandatoryAce;

    if (SecurityDescriptor == NULL || DaclOut == NULL || SaclOut == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    *DaclOut = NULL;
    *SaclOut = NULL;

    daclSize =
        sizeof(ACL) +
        sizeof(ACCESS_ALLOWED_ACE) +
        RtlLengthSid(SeExports->SeLocalSystemSid) -
        sizeof(ULONG);
    dacl = (PACL)SysmonAllocatePool(daclSize);
    if (dacl == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    mandatorySidLength = RtlLengthSid(SeExports->SeSystemMandatorySid);
    saclSize =
        sizeof(ACL) +
        sizeof(SYSTEM_MANDATORY_LABEL_ACE) +
        mandatorySidLength -
        sizeof(ULONG);
    sacl = (PACL)SysmonAllocatePool(saclSize);
    if (sacl == NULL) {
        SysmonFreePool(dacl);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    status = RtlCreateAcl(dacl, daclSize, ACL_REVISION);
    if (!NT_SUCCESS(status)) {
        goto Cleanup;
    }

    status = RtlAddAccessAllowedAceEx(
        dacl,
        ACL_REVISION,
        OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE,
        GENERIC_ALL,
        SeExports->SeLocalSystemSid);
    if (!NT_SUCCESS(status)) {
        goto Cleanup;
    }

    status = RtlCreateSecurityDescriptor(SecurityDescriptor, SECURITY_DESCRIPTOR_REVISION);
    if (!NT_SUCCESS(status)) {
        goto Cleanup;
    }

    status = RtlSetOwnerSecurityDescriptor(
        SecurityDescriptor,
        SeExports->SeLocalSystemSid,
        FALSE);
    if (!NT_SUCCESS(status)) {
        goto Cleanup;
    }

    status = RtlSetDaclSecurityDescriptor(
        SecurityDescriptor,
        TRUE,
        dacl,
        FALSE);
    if (!NT_SUCCESS(status)) {
        goto Cleanup;
    }

    status = RtlCreateAcl(sacl, saclSize, ACL_REVISION);
    if (!NT_SUCCESS(status)) {
        goto Cleanup;
    }

    mandatoryAce = (PSYSTEM_MANDATORY_LABEL_ACE)((PUCHAR)sacl + sizeof(ACL));
    mandatoryAce->Header.AceType = SYSTEM_MANDATORY_LABEL_ACE_TYPE;
    mandatoryAce->Header.AceFlags = 0;
    mandatoryAce->Header.AceSize = (USHORT)(
        sizeof(SYSTEM_MANDATORY_LABEL_ACE) +
        mandatorySidLength -
        sizeof(ULONG));
    mandatoryAce->Mask =
        SYSTEM_MANDATORY_LABEL_NO_WRITE_UP |
        SYSTEM_MANDATORY_LABEL_NO_READ_UP |
        SYSTEM_MANDATORY_LABEL_NO_EXECUTE_UP;
    status = RtlCopySid(
        mandatorySidLength,
        &mandatoryAce->SidStart,
        SeExports->SeSystemMandatorySid);
    if (!NT_SUCCESS(status)) {
        goto Cleanup;
    }

    sacl->AceCount = 1;
    sacl->AclSize = (USHORT)(sizeof(ACL) + mandatoryAce->Header.AceSize);

    status = RtlSetSaclSecurityDescriptor(
        SecurityDescriptor,
        TRUE,
        sacl,
        FALSE);
    if (!NT_SUCCESS(status)) {
        goto Cleanup;
    }

    status = RtlSetControlSecurityDescriptor(
        SecurityDescriptor,
        SE_DACL_PROTECTED | SE_SACL_PROTECTED,
        SE_DACL_PROTECTED | SE_SACL_PROTECTED);
    if (!NT_SUCCESS(status)) {
        goto Cleanup;
    }

    *DaclOut = dacl;
    *SaclOut = sacl;
    return STATUS_SUCCESS;

Cleanup:
    SysmonFreePool(sacl);
    SysmonFreePool(dacl);
    return status;
}

static NTSTATUS
SysmonValidateArchiveDirectoryHandle(
    _In_ HANDLE DirectoryHandle)
{
    FILE_BASIC_INFORMATION basicInfo;
    IO_STATUS_BLOCK ioStatusBlock;
    PSECURITY_DESCRIPTOR securityDescriptor = NULL;
    ULONG securityLength = 0;
    SECURITY_INFORMATION securityInformation;
    NTSTATUS status;
    PSID ownerSid = NULL;
    PACL dacl = NULL;
    PACL sacl = NULL;
    PVOID ace = NULL;
    BOOLEAN ownerDefaulted = FALSE;
    BOOLEAN daclPresent = FALSE;
    BOOLEAN daclDefaulted = FALSE;
    BOOLEAN saclPresent = FALSE;
    BOOLEAN saclDefaulted = FALSE;
    PACE_HEADER aceHeader;

    if (DirectoryHandle == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    status = ZwQueryInformationFile(
        DirectoryHandle,
        &ioStatusBlock,
        &basicInfo,
        sizeof(basicInfo),
        FileBasicInformation);
    if (NT_SUCCESS(status) &&
        (basicInfo.FileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0) {
        return STATUS_DIRECTORY_IS_A_REPARSE_POINT;
    }

    securityInformation =
        OWNER_SECURITY_INFORMATION |
        DACL_SECURITY_INFORMATION |
        SACL_SECURITY_INFORMATION |
        LABEL_SECURITY_INFORMATION;
    status = ZwQuerySecurityObject(
        DirectoryHandle,
        securityInformation,
        NULL,
        0,
        &securityLength);
    if (status == STATUS_INVALID_DEVICE_REQUEST) {
        return STATUS_SUCCESS;
    }
    if (status != STATUS_BUFFER_TOO_SMALL &&
        status != STATUS_BUFFER_OVERFLOW) {
        return status;
    }

    securityDescriptor = (PSECURITY_DESCRIPTOR)SysmonAllocatePool(securityLength);
    if (securityDescriptor == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    status = ZwQuerySecurityObject(
        DirectoryHandle,
        securityInformation,
        securityDescriptor,
        securityLength,
        &securityLength);
    if (!NT_SUCCESS(status)) {
        goto Cleanup;
    }

    status = RtlGetOwnerSecurityDescriptor(
        securityDescriptor,
        &ownerSid,
        &ownerDefaulted);
    if (!NT_SUCCESS(status)) {
        goto Cleanup;
    }

    if (!RtlEqualSid(ownerSid, SeExports->SeLocalSystemSid)) {
        status = STATUS_INVALID_SID;
        goto Cleanup;
    }

    status = RtlGetDaclSecurityDescriptor(
        securityDescriptor,
        &daclPresent,
        &dacl,
        &daclDefaulted);
    if (!NT_SUCCESS(status)) {
        goto Cleanup;
    }

    if (!daclPresent || dacl == NULL || dacl->AceCount != 1) {
        status = STATUS_INVALID_ACL;
        goto Cleanup;
    }

    status = RtlGetAce(dacl, 0, &ace);
    if (!NT_SUCCESS(status)) {
        goto Cleanup;
    }

    aceHeader = (PACE_HEADER)ace;
    if (aceHeader->AceType != ACCESS_ALLOWED_ACE_TYPE ||
        !RtlEqualSid(
            (PSID)&((PACCESS_ALLOWED_ACE)ace)->SidStart,
            SeExports->SeLocalSystemSid)) {
        status = STATUS_INVALID_ACL;
        goto Cleanup;
    }

    status = RtlGetSaclSecurityDescriptor(
        securityDescriptor,
        &saclPresent,
        &sacl,
        &saclDefaulted);
    if (!NT_SUCCESS(status)) {
        goto Cleanup;
    }

    if (!saclPresent || sacl == NULL || sacl->AceCount != 1) {
        status = STATUS_INVALID_ACL;
        goto Cleanup;
    }

    status = RtlGetAce(sacl, 0, &ace);
    if (!NT_SUCCESS(status)) {
        goto Cleanup;
    }

    aceHeader = (PACE_HEADER)ace;
    if (aceHeader->AceType != SYSTEM_MANDATORY_LABEL_ACE_TYPE) {
        status = STATUS_INVALID_ACL;
        goto Cleanup;
    }

    if (!RtlEqualSid(
            (PSID)&((PSYSTEM_MANDATORY_LABEL_ACE)ace)->SidStart,
            SeExports->SeSystemMandatorySid)) {
        status = STATUS_INVALID_SID;
        goto Cleanup;
    }

    status = STATUS_SUCCESS;

Cleanup:
    SysmonFreePool(securityDescriptor);
    return status;
}

static VOID
SysmonLogArchiveDirectoryValidationFailure(
    _In_z_ PCWSTR DirectoryPath,
    _In_ NTSTATUS Status)
{
    PCWSTR reason;

    if (DirectoryPath == NULL || DirectoryPath[0] == L'\0') {
        return;
    }

    if (Status == STATUS_DIRECTORY_IS_A_REPARSE_POINT) {
        reason = L"path is a reparse point";
    } else if (Status == STATUS_INVALID_SID) {
        reason = L"owner is not System";
    } else {
        reason = L"ACL is too permissive and must be limited to System access";
    }

    DbgPrintEx(
        DPFLTR_DEFAULT_ID,
        DPFLTR_WARNING_LEVEL,
        "[SysmonDrv] The \"%ws\" %ws. Archiving is disabled.\n",
        DirectoryPath,
        reason);
}

static NTSTATUS
SysmonOpenArchiveDirectory(
    _In_z_ PCWSTR DirectoryPath,
    _Out_ PHANDLE DirectoryHandle)
{
    UNICODE_STRING ntPath;
    OBJECT_ATTRIBUTES objectAttributes;
    IO_STATUS_BLOCK ioStatusBlock;
    SECURITY_DESCRIPTOR securityDescriptor;
    PACL dacl = NULL;
    PACL sacl = NULL;
    HANDLE directoryHandle = NULL;
    NTSTATUS status;

    if (DirectoryHandle == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    *DirectoryHandle = NULL;
    if (DirectoryPath == NULL || DirectoryPath[0] == L'\0') {
        return STATUS_INVALID_PARAMETER;
    }

    status = SysmonBuildArchiveDirectorySecurityDescriptor(
        &securityDescriptor,
        &dacl,
        &sacl);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    RtlInitUnicodeString(&ntPath, DirectoryPath);
    InitializeObjectAttributes(
        &objectAttributes,
        &ntPath,
        OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
        NULL,
        &securityDescriptor);

    status = ZwCreateFile(
        &directoryHandle,
        FILE_GENERIC_READ |
            FILE_GENERIC_WRITE |
            SYNCHRONIZE |
            READ_CONTROL |
            WRITE_DAC |
            WRITE_OWNER |
            ACCESS_SYSTEM_SECURITY,
        &objectAttributes,
        &ioStatusBlock,
        NULL,
        FILE_ATTRIBUTE_DIRECTORY,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        FILE_OPEN_IF,
        FILE_DIRECTORY_FILE |
            FILE_SYNCHRONOUS_IO_NONALERT |
            FILE_OPEN_FOR_BACKUP_INTENT,
        NULL,
        0);

    if (NT_SUCCESS(status)) {
        status = SysmonValidateArchiveDirectoryHandle(directoryHandle);
        if (!NT_SUCCESS(status)) {
            SysmonLogArchiveDirectoryValidationFailure(DirectoryPath, status);
        } else {
            *DirectoryHandle = directoryHandle;
            directoryHandle = NULL;
        }
    } else {
        DbgPrintEx(
            DPFLTR_DEFAULT_ID,
            DPFLTR_WARNING_LEVEL,
            "[SysmonDrv] Failed to prepare archive directory \"%ws\": 0x%08X. Archiving is disabled.\n",
            DirectoryPath,
            status);
    }

    if (directoryHandle != NULL) {
        ZwClose(directoryHandle);
    }
    SysmonFreePool(sacl);
    SysmonFreePool(dacl);

    return status;
}

static NTSTATUS
SysmonTryRenameToArchive(
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ HANDLE ArchiveDirectoryHandle,
    _In_z_ PCWSTR ArchiveFileName)
{
    SIZE_T destinationChars;
    SIZE_T renameInfoSize;
    PFILE_RENAME_INFORMATION renameInfo = NULL;
    NTSTATUS status;

    if (FltObjects == NULL ||
        FltObjects->Instance == NULL ||
        FltObjects->FileObject == NULL ||
        ArchiveDirectoryHandle == NULL ||
        ArchiveFileName == NULL ||
        ArchiveFileName[0] == L'\0') {
        return STATUS_INVALID_PARAMETER;
    }

    destinationChars = wcslen(ArchiveFileName);
    renameInfoSize =
        FIELD_OFFSET(FILE_RENAME_INFORMATION, FileName) +
        (destinationChars * sizeof(WCHAR));
    renameInfo = (PFILE_RENAME_INFORMATION)SysmonAllocatePool(renameInfoSize);
    if (renameInfo == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    RtlZeroMemory(renameInfo, renameInfoSize);
    renameInfo->ReplaceIfExists = TRUE;
    renameInfo->RootDirectory = ArchiveDirectoryHandle;
    renameInfo->FileNameLength = (ULONG)(destinationChars * sizeof(WCHAR));
    RtlCopyMemory(
        renameInfo->FileName,
        ArchiveFileName,
        renameInfo->FileNameLength);

    status = FltSetInformationFile(
        FltObjects->Instance,
        FltObjects->FileObject,
        renameInfo,
        (ULONG)renameInfoSize,
        FileRenameInformation);
    SysmonFreePool(renameInfo);

    return status;
}

static NTSTATUS
SysmonCreateArchiveFileHandle(
    _In_ HANDLE ArchiveDirectoryHandle,
    _In_z_ PCWSTR ArchiveFileName,
    _Out_ PHANDLE FileHandle)
{
    UNICODE_STRING archiveName;
    OBJECT_ATTRIBUTES objectAttributes;
    IO_STATUS_BLOCK ioStatusBlock;

    if (ArchiveDirectoryHandle == NULL ||
        ArchiveFileName == NULL ||
        ArchiveFileName[0] == L'\0' ||
        FileHandle == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    *FileHandle = NULL;
    RtlInitUnicodeString(&archiveName, ArchiveFileName);
    InitializeObjectAttributes(
        &objectAttributes,
        &archiveName,
        OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
        ArchiveDirectoryHandle,
        NULL);

    return ZwCreateFile(
        FileHandle,
        FILE_GENERIC_WRITE | DELETE | SYNCHRONIZE,
        &objectAttributes,
        &ioStatusBlock,
        NULL,
        FILE_ATTRIBUTE_NORMAL,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        FILE_OVERWRITE_IF,
        FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT,
        NULL,
        0);
}

static NTSTATUS
SysmonTryDeleteOriginalFile(
    _In_ PCFLT_RELATED_OBJECTS FltObjects)
{
    FILE_DISPOSITION_INFORMATION disposition;

    if (FltObjects == NULL ||
        FltObjects->Instance == NULL ||
        FltObjects->FileObject == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    disposition.DeleteFile = TRUE;
    return FltSetInformationFile(
        FltObjects->Instance,
        FltObjects->FileObject,
        &disposition,
        sizeof(disposition),
        FileDispositionInformation);
}

static NTSTATUS
SysmonTryCopyToArchiveAndDelete(
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ HANDLE ArchiveDirectoryHandle,
    _In_z_ PCWSTR ArchiveFileName,
    _Out_ PBOOLEAN SourceChanged)
{
    SYSMON_FILE_BLOCK_SOURCE_IDENTITY sourceIdentityBefore;
    SYSMON_FILE_BLOCK_SOURCE_IDENTITY sourceIdentityAfter;
    HANDLE archiveHandle = NULL;
    LARGE_INTEGER sourceOffset;
    LARGE_INTEGER destinationOffset;
    IO_STATUS_BLOCK ioStatusBlock;
    PUCHAR buffer = NULL;
    ULONG bytesRead;
    NTSTATUS status = STATUS_UNSUCCESSFUL;

    if (SourceChanged != NULL) {
        *SourceChanged = FALSE;
    }

    if (FltObjects == NULL ||
        FltObjects->Instance == NULL ||
        FltObjects->FileObject == NULL ||
        ArchiveDirectoryHandle == NULL ||
        ArchiveFileName == NULL ||
        ArchiveFileName[0] == L'\0' ||
        SourceChanged == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    status = SysmonCaptureFileIdentity(FltObjects, &sourceIdentityBefore);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    status = SysmonCreateArchiveFileHandle(
        ArchiveDirectoryHandle,
        ArchiveFileName,
        &archiveHandle);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    buffer = (PUCHAR)SysmonAllocatePool(64 * 1024);
    if (buffer == NULL) {
        status = STATUS_INSUFFICIENT_RESOURCES;
        goto cleanup;
    }

    sourceOffset.QuadPart = 0;
    destinationOffset.QuadPart = 0;
    for (;;) {
        bytesRead = 0;
        if (!SysmonReadBytesAtOffset(
                FltObjects,
                sourceOffset,
                buffer,
                64 * 1024,
                &bytesRead)) {
            status = STATUS_UNSUCCESSFUL;
            goto cleanup;
        }

        if (bytesRead == 0) {
            status = STATUS_SUCCESS;
            break;
        }

        status = ZwWriteFile(
            archiveHandle,
            NULL,
            NULL,
            NULL,
            &ioStatusBlock,
            buffer,
            bytesRead,
            &destinationOffset,
            NULL);
        if (!NT_SUCCESS(status)) {
            goto cleanup;
        }

        sourceOffset.QuadPart += bytesRead;
        destinationOffset.QuadPart += bytesRead;
        if (bytesRead < (64 * 1024)) {
            status = STATUS_SUCCESS;
            break;
        }
    }

    if (NT_SUCCESS(status)) {
        status = SysmonCaptureFileIdentity(FltObjects, &sourceIdentityAfter);
    }

    if (NT_SUCCESS(status) &&
        !SysmonFileIdentityMatches(&sourceIdentityBefore, &sourceIdentityAfter)) {
        *SourceChanged = TRUE;
        status = STATUS_UNSUCCESSFUL;
        if (archiveHandle != NULL) {
            FILE_DISPOSITION_INFORMATION disposition;

            disposition.DeleteFile = TRUE;
            (void)ZwSetInformationFile(
                archiveHandle,
                &ioStatusBlock,
                &disposition,
                sizeof(disposition),
                FileDispositionInformation);
        }
    }

    if (NT_SUCCESS(status)) {
        status = SysmonTryDeleteOriginalFile(FltObjects);
    }

cleanup:
    SysmonFreePool(buffer);
    if (archiveHandle != NULL) {
        ZwClose(archiveHandle);
    }
    return status;
}

static NTSTATUS
SysmonExecuteFileBlockCleanup(
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ PSYSMON_RULE_RUNTIME Runtime,
    _In_ PSYSMON_FILE_BLOCK_STREAM_CONTEXT StreamContext,
    _In_ BOOLEAN PreserveSample)
{
    WCHAR archiveRoot[SYSMON_MAX_PATH];
    WCHAR archiveFileName[SYSMON_MAX_PATH];
    HANDLE archiveDirectoryHandle = NULL;
    BOOLEAN sourceChanged = FALSE;
    NTSTATUS status = STATUS_UNSUCCESSFUL;

    if (FltObjects == NULL || StreamContext == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    if (!SysmonRevalidateFileBlockExecutable(FltObjects, StreamContext)) {
        DbgPrintEx(
            DPFLTR_DEFAULT_ID,
            DPFLTR_WARNING_LEVEL,
            "[SysmonDrv] FileBlockExecutable cleanup skipped: executable header changed before action\n");
        return STATUS_NOT_FOUND;
    }

    if (PreserveSample &&
        Runtime != NULL &&
        Runtime->ArchiveDirectoryComponent.Buffer != NULL &&
        StreamContext->OriginalPath[0] != L'\0') {
        status = SysmonBuildArchiveRootPath(
            FltObjects,
            &Runtime->ArchiveDirectoryComponent,
            archiveRoot);
        if (NT_SUCCESS(status)) {
            status = SysmonOpenArchiveDirectory(
                archiveRoot,
                &archiveDirectoryHandle);
        }

        if (NT_SUCCESS(status)) {
            status = SysmonBuildArchiveDestinationName(
                Runtime,
                StreamContext->OriginalPath,
                archiveFileName);
        }

        if (NT_SUCCESS(status)) {
            status = SysmonTryRenameToArchive(
                FltObjects,
                archiveDirectoryHandle,
                archiveFileName);
            if (NT_SUCCESS(status)) {
                goto Cleanup;
            }

            status = SysmonTryCopyToArchiveAndDelete(
                FltObjects,
                archiveDirectoryHandle,
                archiveFileName,
                &sourceChanged);
            if (sourceChanged) {
                goto Cleanup;
            }
            if (NT_SUCCESS(status)) {
                goto Cleanup;
            }
        }
    }

    status = SysmonTryDeleteOriginalFile(FltObjects);

Cleanup:
    if (archiveDirectoryHandle != NULL) {
        ZwClose(archiveDirectoryHandle);
    }
    return status;
}

/* ========================================================================
 * Helpers: Build canonical file/raw payloads
 * ======================================================================== */

typedef struct _SYSMON_FILE_EVENT_CONTEXT {
    ULONG ProcessId;
    WCHAR ProcessGuid[SYSMON_MAX_GUID_STRING];
    WCHAR Image[SYSMON_MAX_PATH];
    WCHAR User[SYSMON_MAX_SID_STRING];
    WCHAR TargetFilename[SYSMON_MAX_PATH];
    WCHAR CreationUtcTime[64];
    WCHAR PreviousCreationUtcTime[64];
    WCHAR Hashes[SYSMON_MAX_HASH_STRING];
    BOOLEAN IsExecutable;
} SYSMON_FILE_EVENT_CONTEXT, *PSYSMON_FILE_EVENT_CONTEXT;

typedef struct _SYSMON_CREATE_EVENT_CONTEXT {
    ULONG PipeEventId;
    WCHAR PipeName[SYSMON_MAX_PATH];
    WCHAR RawDeviceName[SYSMON_MAX_PATH];
    BOOLEAN ReportRawAccessRead;
    UCHAR CreateDisposition;
    BOOLEAN ReportFileCreate;
    BOOLEAN ReportStreamHash;
    BOOLEAN ExecutableCandidate;
    BOOLEAN ArmFileBlockContext;
} SYSMON_CREATE_EVENT_CONTEXT, *PSYSMON_CREATE_EVENT_CONTEXT;

typedef struct _SYSMON_SETINFO_EVENT_CONTEXT {
    LARGE_INTEGER NewCreationTime;
    LARGE_INTEGER PreviousCreationTime;
    BOOLEAN ReportFileCreateTime;
    BOOLEAN ReportFileDeleteDetected;
    BOOLEAN ReportFileDelete;
    BOOLEAN ReportFileBlockShredding;
} SYSMON_SETINFO_EVENT_CONTEXT, *PSYSMON_SETINFO_EVENT_CONTEXT;

static VOID
SysmonCaptureFileName(
    _In_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Out_writes_(BufferChars) PWCHAR Buffer,
    _In_ ULONG BufferChars)
{
    NTSTATUS status;
    PFLT_FILE_NAME_INFORMATION nameInfo = NULL;

    Buffer[0] = L'\0';

    if (KeGetCurrentIrql() == PASSIVE_LEVEL) {
        status = FltGetFileNameInformation(
            Data,
            FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_DEFAULT,
            &nameInfo);
        if (NT_SUCCESS(status)) {
            FltParseFileNameInformation(nameInfo);
            if (nameInfo->Name.Length > 0) {
                SysmonCopyUnicodeString(Buffer, BufferChars, &nameInfo->Name);
            }
            FltReleaseFileNameInformation(nameInfo);
        }
    }

    if (Buffer[0] == L'\0' && FltObjects != NULL && FltObjects->FileObject != NULL) {
        SysmonCopyUnicodeString(
            Buffer,
            BufferChars,
            &FltObjects->FileObject->FileName);
    }
}

static VOID
SysmonFormatOptionalTimestamp(
    _In_ LONGLONG Timestamp,
    _Out_writes_(64) PWCHAR Buffer)
{
    Buffer[0] = L'\0';
    if (Timestamp != 0 &&
        !NT_SUCCESS(SysmonFormatTimestamp(Timestamp, Buffer))) {
        Buffer[0] = L'\0';
    }
}

static BOOLEAN
SysmonCanCollectEventDetails(_In_z_ PCSTR Operation)
{
    if (KeGetCurrentIrql() == PASSIVE_LEVEL) {
        return TRUE;
    }

    DbgPrintEx(
        DPFLTR_DEFAULT_ID,
        DPFLTR_WARNING_LEVEL,
        "[SysmonDrv] %s deferred: callback IRQL is not PASSIVE_LEVEL\n",
        Operation);
    return FALSE;
}

VOID
SysmonQueryMinifilterDebugStats(
    _Out_ PSYSMON_PROCESS_DEBUG_STATS Stats)
{
    if (Stats == NULL) {
        return;
    }

    Stats->FileCreateCandidateCount = SYSMON_FILE_CREATE_STAT_READ(g_FileCreateCandidateCount);
    Stats->FileCreatePostCreateCount = SYSMON_FILE_CREATE_STAT_READ(g_FileCreatePostCreateCount);
    Stats->FileCreateIrqlDropCount = SYSMON_FILE_CREATE_STAT_READ(g_FileCreateIrqlDropCount);
    Stats->FileCreateStatusFailureCount = SYSMON_FILE_CREATE_STAT_READ(g_FileCreateStatusFailureCount);
    Stats->FileCreateNotCreatedCount = SYSMON_FILE_CREATE_STAT_READ(g_FileCreateNotCreatedCount);
    Stats->FileCreatePublishAttemptCount = SYSMON_FILE_CREATE_STAT_READ(g_FileCreatePublishAttemptCount);
    Stats->LastFileCreateStatus = SYSMON_FILE_CREATE_STAT_READ(g_LastFileCreateStatus);
    Stats->LastFileCreateInfo = SYSMON_FILE_CREATE_STAT_READ(g_LastFileCreateInfo);
    Stats->LastFileCreateIrql = SYSMON_FILE_CREATE_STAT_READ(g_LastFileCreateIrql);
    Stats->LastFileCreateDisposition = SYSMON_FILE_CREATE_STAT_READ(g_LastFileCreateDisposition);
    Stats->LastFileCreateReportStatus = SYSMON_FILE_CREATE_STAT_READ(g_LastFileCreateReportStatus);
    Stats->FileBlockContextCreateCount = SYSMON_FILE_BLOCK_STAT_READ(g_FileBlockContextCreateCount);
    Stats->FileBlockWriteCallbackCount = SYSMON_FILE_BLOCK_STAT_READ(g_FileBlockWriteCallbackCount);
    Stats->FileBlockSawWriteCount = SYSMON_FILE_BLOCK_STAT_READ(g_FileBlockSawWriteCount);
    Stats->FileBlockHeaderCheckCount = SYSMON_FILE_BLOCK_STAT_READ(g_FileBlockHeaderCheckCount);
    Stats->FileBlockHeaderMatchCount = SYSMON_FILE_BLOCK_STAT_READ(g_FileBlockHeaderMatchCount);
    Stats->FileBlockFinalizeAttemptCount = SYSMON_FILE_BLOCK_STAT_READ(g_FileBlockFinalizeAttemptCount);
    Stats->FileBlockFinalizeSkipNoWriteCount = SYSMON_FILE_BLOCK_STAT_READ(g_FileBlockFinalizeSkipNoWriteCount);
    Stats->FileBlockFinalizeSkipNotPeCount = SYSMON_FILE_BLOCK_STAT_READ(g_FileBlockFinalizeSkipNotPeCount);
    Stats->FileBlockFinalizeWouldBlockCount = SYSMON_FILE_BLOCK_STAT_READ(g_FileBlockFinalizeWouldBlockCount);
    Stats->FileBlockFinalizeWouldDetectCount = SYSMON_FILE_BLOCK_STAT_READ(g_FileBlockFinalizeWouldDetectCount);
    Stats->FileBlockActionSuccessCount = SYSMON_FILE_BLOCK_STAT_READ(g_FileBlockActionSuccessCount);
    Stats->FileBlockEvent27Count = SYSMON_FILE_BLOCK_STAT_READ(g_FileBlockEvent27Count);
    Stats->FileBlockEvent29Count = SYSMON_FILE_BLOCK_STAT_READ(g_FileBlockEvent29Count);
    Stats->FileBlockLastFlags = SYSMON_FILE_BLOCK_STAT_READ(g_FileBlockLastFlags);
    Stats->FileBlockLastActionStatus = SYSMON_FILE_BLOCK_STAT_READ(g_FileBlockLastActionStatus);
    Stats->FileBlockLastReportStatus = SYSMON_FILE_BLOCK_STAT_READ(g_FileBlockLastReportStatus);
}

static BOOLEAN
SysmonCreateRequestMayModifyExecutable(
    _In_ PFLT_CALLBACK_DATA Data)
{
    ACCESS_MASK desiredAccess;

    if (Data == NULL ||
        Data->Iopb == NULL ||
        Data->Iopb->Parameters.Create.SecurityContext == NULL) {
        return FALSE;
    }

    desiredAccess = Data->Iopb->Parameters.Create.SecurityContext->DesiredAccess;
    return ((desiredAccess & (FILE_WRITE_DATA |
                              FILE_APPEND_DATA |
                              FILE_WRITE_EA |
                              FILE_WRITE_ATTRIBUTES |
                              DELETE |
                              GENERIC_WRITE |
                              GENERIC_ALL)) != 0);
}

static BOOLEAN
SysmonCaptureChangingCreationTime(
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_opt_ PFILE_BASIC_INFORMATION BasicInfo,
    _Out_opt_ LARGE_INTEGER *PreviousCreationTime)
{
    SYSMON_FILE_INFO *fileInfo;
    BOOLEAN isChanging = TRUE;

    if (PreviousCreationTime != NULL) {
        PreviousCreationTime->QuadPart = 0;
    }

    if (BasicInfo == NULL || BasicInfo->CreationTime.QuadPart == 0) {
        return FALSE;
    }

    if (!SysmonCanCollectEventDetails("FileCreateTime predicate")) {
        return FALSE;
    }

    fileInfo = SysmonAllocateMinifilterFileInfo();
    if (fileInfo == NULL) {
        return TRUE;
    }

    SysmonQueryFileBasicInfo(FltObjects, fileInfo);
    if (PreviousCreationTime != NULL) {
        *PreviousCreationTime = fileInfo->CreationTime;
    }
    if (fileInfo->CreationTime.QuadPart != 0 &&
        fileInfo->CreationTime.QuadPart == BasicInfo->CreationTime.QuadPart) {
        isChanging = FALSE;
    }

    SysmonFreeMinifilterFileInfo(fileInfo);
    return isChanging;
}

static VOID
SysmonPopulateProcessContext(_Inout_ PSYSMON_FILE_EVENT_CONTEXT Context)
{
    SYSMON_PROCESS_INFO *processInfo;

    processInfo = SysmonAllocateMinifilterProcessInfo();
    if (processInfo == NULL) {
        return;
    }

    if (NT_SUCCESS(SysmonCollectProcessInfo(
            (HANDLE)(ULONG_PTR)Context->ProcessId,
            processInfo))) {
        SysmonCopyWideStringWithLength(
            Context->ProcessGuid,
            RTL_NUMBER_OF(Context->ProcessGuid),
            processInfo->ProcessGuid,
            SYSMON_GUID_STRING_CHARS);
        SysmonCopyWideString(
            Context->Image,
            RTL_NUMBER_OF(Context->Image),
            processInfo->ImagePath);
        /*
         * Account-name resolution is still deferred in kernel producers;
         * carry the SID text in the canonical User slot rather than inventing
         * a domain\name.
         */
        SysmonCopyWideString(
            Context->User,
            RTL_NUMBER_OF(Context->User),
            processInfo->UserSid);
    }

    SysmonFreeMinifilterProcessInfo(processInfo);
}

static VOID
SysmonPopulateFileContext(
    _In_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ BOOLEAN CaptureFileInfo,
    _Inout_ PSYSMON_FILE_EVENT_CONTEXT Context)
{
    UNICODE_STRING targetName;
    SYSMON_FILE_INFO *fileInfo = NULL;

    if (Context->TargetFilename[0] == L'\0') {
        SysmonCaptureFileName(
            Data,
            FltObjects,
            Context->TargetFilename,
            RTL_NUMBER_OF(Context->TargetFilename));
    }

    RtlInitUnicodeString(&targetName, Context->TargetFilename);
    Context->IsExecutable = SysmonIsExecutable(&targetName);

    if (!CaptureFileInfo) {
        return;
    }

    fileInfo = SysmonAllocateMinifilterFileInfo();
    if (fileInfo == NULL) {
        return;
    }

    if (NT_SUCCESS(SysmonCollectFileInfo(Data, FltObjects, fileInfo))) {
        if (Context->TargetFilename[0] == L'\0') {
            SysmonCopyWideString(
                Context->TargetFilename,
                RTL_NUMBER_OF(Context->TargetFilename),
                fileInfo->FilePath);
        }

        SysmonCopyWideString(
            Context->Hashes,
            RTL_NUMBER_OF(Context->Hashes),
            fileInfo->Hashes);
        SysmonFormatOptionalTimestamp(
            fileInfo->CreationTime.QuadPart,
            Context->CreationUtcTime);
        if (fileInfo->IsPeFile) {
            Context->IsExecutable = TRUE;
        }
    }

    SysmonFreeMinifilterFileInfo(fileInfo);
}

static VOID
SysmonSubmitEvent(_In_ PSYSMON_EVENT_UNION Event)
{
    SysmonPublishEvent(Event);
}

static BOOLEAN
SysmonShouldArchiveFileDeleteEvent(
    _In_ PSYSMON_EVENT_UNION Event)
{
    PSYSMON_RULE_RUNTIME runtime;
    BOOLEAN archived;

    if (Event == NULL) {
        return FALSE;
    }

    runtime = SysmonAcquireRuleRuntimeSnapshot();
    archived = SysmonShouldCaptureEvent(runtime, SysmonEventFileDelete, Event);
    SysmonReleaseRuleRuntimeSnapshot(runtime);
    return archived;
}

static NTSTATUS
SysmonBuildCanonicalFileEvent(
    _In_ SYSMON_EVENT_ID EventId,
    _In_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_opt_z_ PCWSTR TargetPathOverride,
    _In_opt_ const LARGE_INTEGER *NewCreationTime,
    _In_opt_ const LARGE_INTEGER *PreviousCreationTime,
    _Outptr_ PSYSMON_EVENT_UNION *EventOut)
{
    PSYSMON_EVENT_UNION event;
    SYSMON_EVENT_PAYLOAD_BUILDER builder;
    SYSMON_FILE_EVENT_CONTEXT context;
    BOOLEAN archived = FALSE;
    BOOLEAN captureFileInfo;
    BOOLEAN hasTargetPathOverride;
    BOOLEAN rawAccessTargetCaptured = FALSE;

    if (EventOut == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    *EventOut = NULL;

    if (!SysmonCanCollectEventDetails("canonical file event")) {
        return STATUS_UNSUCCESSFUL;
    }

    RtlZeroMemory(&context, sizeof(context));
    context.ProcessId = (ULONG)(ULONG_PTR)FltGetRequestorProcessId(Data);

    SysmonPopulateProcessContext(&context);

    captureFileInfo =
        (EventId == SysmonEventFileCreateTime ||
         EventId == SysmonEventFileCreate ||
         EventId == SysmonEventFileCreateStreamHash ||
         EventId == SysmonEventFileDelete ||
         EventId == SysmonEventFileDeleteDetected ||
         EventId == SysmonEventFileBlockExecutable ||
         EventId == SysmonEventFileBlockShredding ||
         EventId == SysmonEventFileExecutableDetected);

    hasTargetPathOverride =
        (TargetPathOverride != NULL && TargetPathOverride[0] != L'\0');

    if (EventId == SysmonEventRawAccessRead && hasTargetPathOverride) {
        SysmonCopyWideString(
            context.TargetFilename,
            RTL_NUMBER_OF(context.TargetFilename),
            TargetPathOverride);
        captureFileInfo = FALSE;
        rawAccessTargetCaptured = TRUE;
    } else if (EventId == SysmonEventRawAccessRead &&
               SysmonTryGetRawVolumeDeviceName(
                   Data,
                   FltObjects,
                   context.TargetFilename,
                   RTL_NUMBER_OF(context.TargetFilename))) {
        captureFileInfo = FALSE;
        rawAccessTargetCaptured = TRUE;
    }

    SysmonPopulateFileContext(Data, FltObjects, captureFileInfo, &context);
    if (hasTargetPathOverride && !rawAccessTargetCaptured) {
        SysmonCopyWideString(
            context.TargetFilename,
            RTL_NUMBER_OF(context.TargetFilename),
            TargetPathOverride);
    }

    if (EventId == SysmonEventFileCreateTime) {
        context.PreviousCreationUtcTime[0] = L'\0';
        if (PreviousCreationTime != NULL && PreviousCreationTime->QuadPart != 0) {
            SysmonFormatOptionalTimestamp(
                PreviousCreationTime->QuadPart,
                context.PreviousCreationUtcTime);
        }
        if (NewCreationTime != NULL && NewCreationTime->QuadPart != 0) {
            SysmonFormatOptionalTimestamp(
                NewCreationTime->QuadPart,
                context.CreationUtcTime);
        }
    }

    event = SysmonAllocateEvent(EventId);
    if (event == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    switch (EventId) {
    case SysmonEventFileCreateTime:
    {
        SYSMON_EVENT_FILE_CREATE_TIME_PAYLOAD *eventData;

        SysmonBeginStringPayload(event, sizeof(*eventData), &builder);
        eventData = (SYSMON_EVENT_FILE_CREATE_TIME_PAYLOAD *)event->RawData;
        eventData->ProcessId = context.ProcessId;
        SysmonAddStringField(event, &builder, &eventData->RuleName, NULL);
        SysmonAddCurrentUtcTimeField(event, &builder, &eventData->UtcTime);
        SysmonAddFixedLengthStringField(
            event,
            &builder,
            &eventData->ProcessGuid,
            context.ProcessGuid,
            SYSMON_GUID_STRING_CHARS);
        SysmonAddStringField(event, &builder, &eventData->Image, context.Image);
        SysmonAddStringField(event, &builder, &eventData->TargetFilename, context.TargetFilename);
        SysmonAddFixedLengthStringField(
            event,
            &builder,
            &eventData->CreationUtcTime,
            context.CreationUtcTime,
            SYSMON_TIMESTAMP_STRING_CHARS);
        SysmonAddFixedLengthStringField(
            event,
            &builder,
            &eventData->PreviousCreationUtcTime,
            context.PreviousCreationUtcTime,
            SYSMON_TIMESTAMP_STRING_CHARS);
        SysmonAddStringField(event, &builder, &eventData->User, context.User);
        break;
    }
      case SysmonEventRawAccessRead:
      {
          SYSMON_EVENT_RAW_ACCESS_READ_PAYLOAD *eventData;

          SysmonBeginStringPayload(event, sizeof(*eventData), &builder);
          eventData = (SYSMON_EVENT_RAW_ACCESS_READ_PAYLOAD *)event->RawData;
          eventData->ProcessId = context.ProcessId;
          SysmonAddStringLiteralField(event, &builder, &eventData->RuleName, L"-");
          SysmonAddCurrentUtcTimeField(event, &builder, &eventData->UtcTime);
          SysmonAddFixedLengthStringField(
              event,
              &builder,
              &eventData->ProcessGuid,
              context.ProcessGuid,
              SYSMON_GUID_STRING_CHARS);
          SysmonAddStringField(event, &builder, &eventData->Image, context.Image);
          SysmonAddStringField(event, &builder, &eventData->Device, context.TargetFilename);
          SysmonAddStringField(event, &builder, &eventData->User, context.User);
          break;
      }
      case SysmonEventFileCreate:
      {
          SYSMON_EVENT_FILE_CREATE_PAYLOAD *eventData;

          SysmonBeginStringPayload(event, sizeof(*eventData), &builder);
          eventData = (SYSMON_EVENT_FILE_CREATE_PAYLOAD *)event->RawData;
          eventData->ProcessId = context.ProcessId;
          SysmonAddStringLiteralField(event, &builder, &eventData->RuleName, L"-");
          SysmonAddCurrentUtcTimeField(event, &builder, &eventData->UtcTime);
          SysmonAddFixedLengthStringField(
              event,
              &builder,
              &eventData->ProcessGuid,
              context.ProcessGuid,
              SYSMON_GUID_STRING_CHARS);
          SysmonAddStringField(event, &builder, &eventData->Image, context.Image);
          SysmonAddStringField(event, &builder, &eventData->TargetFilename, context.TargetFilename);
          /* Pre-create cannot always query the new file's create time reliably. */
          SysmonAddFixedLengthStringField(
              event,
              &builder,
              &eventData->CreationUtcTime,
              context.CreationUtcTime,
              SYSMON_TIMESTAMP_STRING_CHARS);
          SysmonAddStringField(event, &builder, &eventData->User, context.User);
          break;
      }
      case SysmonEventFileCreateStreamHash:
      {
          SYSMON_EVENT_FILE_CREATE_STREAM_HASH_PAYLOAD *eventData;

          SysmonBeginStringPayload(event, sizeof(*eventData), &builder);
          eventData = (SYSMON_EVENT_FILE_CREATE_STREAM_HASH_PAYLOAD *)event->RawData;
          eventData->ProcessId = context.ProcessId;
          SysmonAddStringLiteralField(event, &builder, &eventData->RuleName, L"-");
          SysmonAddCurrentUtcTimeField(event, &builder, &eventData->UtcTime);
          SysmonAddFixedLengthStringField(
              event,
              &builder,
              &eventData->ProcessGuid,
              context.ProcessGuid,
              SYSMON_GUID_STRING_CHARS);
          SysmonAddStringField(event, &builder, &eventData->Image, context.Image);
          SysmonAddStringField(event, &builder, &eventData->TargetFilename, context.TargetFilename);
          SysmonAddFixedLengthStringField(
              event,
              &builder,
              &eventData->CreationUtcTime,
              context.CreationUtcTime,
              SYSMON_TIMESTAMP_STRING_CHARS);
          SysmonAddStringField(event, &builder, &eventData->Hash, context.Hashes);
          SysmonAddStringLiteralField(event, &builder, &eventData->Contents, L"-");
          SysmonAddStringField(event, &builder, &eventData->User, context.User);
          break;
      }
    case SysmonEventFileDelete:
    {
        SYSMON_EVENT_FILE_DELETE_PAYLOAD *eventData;

        SysmonBeginStringPayload(event, sizeof(*eventData), &builder);
        eventData = (SYSMON_EVENT_FILE_DELETE_PAYLOAD *)event->RawData;
        eventData->ProcessId = context.ProcessId;
        eventData->IsExecutable = context.IsExecutable;
        eventData->Archived = archived;
        SysmonAddStringField(event, &builder, &eventData->RuleName, NULL);
        SysmonAddCurrentUtcTimeField(event, &builder, &eventData->UtcTime);
        SysmonAddFixedLengthStringField(
            event,
            &builder,
            &eventData->ProcessGuid,
            context.ProcessGuid,
            SYSMON_GUID_STRING_CHARS);
        SysmonAddStringField(event, &builder, &eventData->User, context.User);
        SysmonAddStringField(event, &builder, &eventData->Image, context.Image);
        SysmonAddStringField(event, &builder, &eventData->TargetFilename, context.TargetFilename);
        SysmonAddStringField(event, &builder, &eventData->Hashes, context.Hashes);
        archived = SysmonShouldArchiveFileDeleteEvent(event);
        eventData->Archived = archived;
        break;
    }
    case SysmonEventFileDeleteDetected:
    case SysmonEventFileBlockShredding:
    {
        SYSMON_EVENT_FILE_BLOCK_PAYLOAD *eventData;

        SysmonBeginStringPayload(event, sizeof(*eventData), &builder);
        eventData = (SYSMON_EVENT_FILE_BLOCK_PAYLOAD *)event->RawData;
        eventData->ProcessId = context.ProcessId;
        eventData->IsExecutable = context.IsExecutable;
        SysmonAddStringField(event, &builder, &eventData->RuleName, NULL);
        SysmonAddCurrentUtcTimeField(event, &builder, &eventData->UtcTime);
        SysmonAddFixedLengthStringField(
            event,
            &builder,
            &eventData->ProcessGuid,
            context.ProcessGuid,
            SYSMON_GUID_STRING_CHARS);
        SysmonAddStringField(event, &builder, &eventData->User, context.User);
        SysmonAddStringField(event, &builder, &eventData->Image, context.Image);
        SysmonAddStringField(event, &builder, &eventData->TargetFilename, context.TargetFilename);
        SysmonAddStringField(event, &builder, &eventData->Hashes, context.Hashes);
        break;
    }
    case SysmonEventFileBlockExecutable:
    case SysmonEventFileExecutableDetected:
    {
        SYSMON_EVENT_FILE_HASH_PAYLOAD *eventData;

        SysmonBeginStringPayload(event, sizeof(*eventData), &builder);
        eventData = (SYSMON_EVENT_FILE_HASH_PAYLOAD *)event->RawData;
        eventData->ProcessId = context.ProcessId;
        SysmonAddStringField(event, &builder, &eventData->RuleName, NULL);
        SysmonAddCurrentUtcTimeField(event, &builder, &eventData->UtcTime);
        SysmonAddFixedLengthStringField(
            event,
            &builder,
            &eventData->ProcessGuid,
            context.ProcessGuid,
            SYSMON_GUID_STRING_CHARS);
        SysmonAddStringField(event, &builder, &eventData->User, context.User);
        SysmonAddStringField(event, &builder, &eventData->Image, context.Image);
        SysmonAddStringField(event, &builder, &eventData->TargetFilename, context.TargetFilename);
        SysmonAddStringField(event, &builder, &eventData->Hashes, context.Hashes);
        break;
    }
    default:
        SysmonFreeEvent(event);
        return STATUS_NOT_SUPPORTED;
    }

    *EventOut = event;
    return STATUS_SUCCESS;
}

static NTSTATUS
SysmonPrepareCanonicalFileEventForCapture(
    _In_ SYSMON_EVENT_ID EventId,
    _In_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_opt_z_ PCWSTR TargetPathOverride,
    _In_opt_ PSYSMON_RULE_RUNTIME Runtime,
    _Outptr_ PSYSMON_EVENT_UNION *EventOut,
    _Out_ PBOOLEAN WouldCapture)
{
    NTSTATUS status;
    PSYSMON_EVENT_UNION event = NULL;

    if (EventOut == NULL || WouldCapture == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    *EventOut = NULL;
    *WouldCapture = FALSE;

    status = SysmonBuildCanonicalFileEvent(
        EventId,
        Data,
        FltObjects,
        TargetPathOverride,
        NULL,
        NULL,
        &event);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    if (event == NULL) {
        return STATUS_UNSUCCESSFUL;
    }

    *WouldCapture = SysmonShouldCaptureEvent(Runtime, EventId, event);
    if (!*WouldCapture) {
        SysmonFreeEvent(event);
        event = NULL;
    }

    *EventOut = event;
    return STATUS_SUCCESS;
}

static VOID
SysmonSubmitPreparedEvent(
    _Inout_ PSYSMON_EVENT_UNION *Event)
{
    if (Event != NULL && *Event != NULL) {
        SysmonSubmitEvent(*Event);
        SysmonFreeEvent(*Event);
        *Event = NULL;
    }
}

static BOOLEAN
SysmonFinalizeFileBlockContext(
    _In_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Inout_ PSYSMON_FILE_BLOCK_STREAM_CONTEXT StreamContext,
    _In_ BOOLEAN FinalAttempt)
{
    PSYSMON_EVENT_UNION blockEvent = NULL;
    PSYSMON_EVENT_UNION detectEvent = NULL;
    PSYSMON_RULE_RUNTIME runtime = NULL;
    SYSMON_FILE_EVENT_CONTEXT requestContext;
    BOOLEAN shouldReportBlock = FALSE;
    BOOLEAN shouldReportDetected = FALSE;
    BOOLEAN preserveSample = FALSE;
    BOOLEAN isPe = FALSE;
    BOOLEAN deleteContext = TRUE;
    NTSTATUS actionStatus = STATUS_UNSUCCESSFUL;
    NTSTATUS blockEvalStatus = STATUS_UNSUCCESSFUL;
    NTSTATUS detectEvalStatus = STATUS_UNSUCCESSFUL;
    NTSTATUS reportStatus = STATUS_UNSUCCESSFUL;

    if (StreamContext == NULL) {
        return TRUE;
    }

    SYSMON_FILE_BLOCK_STAT_INC(g_FileBlockFinalizeAttemptCount);
    SYSMON_FILE_BLOCK_STAT_SET(g_FileBlockLastFlags, StreamContext->Flags);

    if ((StreamContext->Flags & SYSMON_FILE_BLOCK_CTX_EVENT_REPORTED) != 0 ||
        (StreamContext->Flags & SYSMON_FILE_BLOCK_CTX_ARMED) == 0 ||
        (StreamContext->Flags & SYSMON_FILE_BLOCK_CTX_CREATE_SUCCEEDED) == 0 ||
        (StreamContext->Flags & SYSMON_FILE_BLOCK_CTX_SAW_WRITE) == 0) {
        if ((StreamContext->Flags & SYSMON_FILE_BLOCK_CTX_SAW_WRITE) == 0) {
            SYSMON_FILE_BLOCK_STAT_INC(g_FileBlockFinalizeSkipNoWriteCount);
        }
        return TRUE;
    }

    if (KeGetCurrentIrql() != PASSIVE_LEVEL) {
        if (!FinalAttempt) {
            return FALSE;
        }

        DbgPrintEx(
            DPFLTR_DEFAULT_ID,
            DPFLTR_WARNING_LEVEL,
            "[SysmonDrv] FileBlockExecutable finalize skipped at IRQL %lu\n",
            KeGetCurrentIrql());
        return TRUE;
    }

    if ((StreamContext->Flags & SYSMON_FILE_BLOCK_CTX_IS_PE) == 0) {
        isPe = SysmonDetectPeFromFileObject(FltObjects, NULL);
        if (!isPe &&
            (StreamContext->Flags & SYSMON_FILE_BLOCK_CTX_FILE_CREATED) == 0 &&
            StreamContext->OriginalPath[0] != L'\0') {
            isPe = SysmonDetectPeFromPath(StreamContext->OriginalPath);
        }
        if (isPe) {
            StreamContext->Flags |=
                SYSMON_FILE_BLOCK_CTX_HEADER_CHECKED |
                SYSMON_FILE_BLOCK_CTX_IS_PE;
        }
    }

    if ((StreamContext->Flags & SYSMON_FILE_BLOCK_CTX_IS_PE) == 0) {
        SYSMON_FILE_BLOCK_STAT_INC(g_FileBlockFinalizeSkipNotPeCount);
        return TRUE;
    }

    runtime = SysmonAcquireRuleRuntimeSnapshot();
    blockEvalStatus = SysmonPrepareCanonicalFileEventForCapture(
        SysmonEventFileBlockExecutable,
        Data,
        FltObjects,
        StreamContext->OriginalPath,
        runtime,
        &blockEvent,
        &shouldReportBlock);
    if (!NT_SUCCESS(blockEvalStatus)) {
        DbgPrintEx(
            DPFLTR_DEFAULT_ID,
            DPFLTR_WARNING_LEVEL,
            "[SysmonDrv] FileBlockExecutable event preparation failed: 0x%08X\n",
            blockEvalStatus);
        shouldReportBlock = SysmonRuleRuntimeHasEvent(
            runtime,
            SysmonEventFileBlockExecutable);
    }

    if (!shouldReportBlock) {
        detectEvalStatus = SysmonPrepareCanonicalFileEventForCapture(
            SysmonEventFileExecutableDetected,
            Data,
            FltObjects,
            StreamContext->OriginalPath,
            runtime,
            &detectEvent,
            &shouldReportDetected);
        if (!NT_SUCCESS(detectEvalStatus)) {
            DbgPrintEx(
                DPFLTR_DEFAULT_ID,
                DPFLTR_WARNING_LEVEL,
                "[SysmonDrv] FileExecutableDetected event preparation failed: 0x%08X\n",
                detectEvalStatus);
            shouldReportDetected = SysmonRuleRuntimeHasEvent(
                runtime,
                SysmonEventFileExecutableDetected);
        }
    }

    if (!shouldReportBlock && !shouldReportDetected) {
        goto Cleanup;
    }

    if (shouldReportBlock) {
        SYSMON_FILE_BLOCK_STAT_INC(g_FileBlockFinalizeWouldBlockCount);
        RtlZeroMemory(&requestContext, sizeof(requestContext));
        requestContext.ProcessId =
            (StreamContext->ProcessId != 0)
                ? StreamContext->ProcessId
                : (ULONG)(ULONG_PTR)FltGetRequestorProcessId(Data);
        SysmonPopulateProcessContext(&requestContext);
        preserveSample = SysmonShouldPreserveExecutableSample(
            runtime,
            StreamContext->Extension,
            requestContext.Image,
            requestContext.User);
        actionStatus = SysmonExecuteFileBlockCleanup(
            FltObjects,
            runtime,
            StreamContext,
            preserveSample);
        SYSMON_FILE_BLOCK_STAT_SET(g_FileBlockLastActionStatus, actionStatus);
        if (!NT_SUCCESS(actionStatus)) {
            deleteContext = FinalAttempt;
            if (FinalAttempt) {
                DbgPrintEx(
                    DPFLTR_DEFAULT_ID,
                    DPFLTR_WARNING_LEVEL,
                    "[SysmonDrv] FileBlockExecutable cleanup failed: 0x%08X\n",
                    actionStatus);
            }
            goto Cleanup;
        }

        SYSMON_FILE_BLOCK_STAT_INC(g_FileBlockActionSuccessCount);

        if (blockEvent != NULL) {
            SysmonSubmitPreparedEvent(&blockEvent);
            SYSMON_FILE_BLOCK_STAT_INC(g_FileBlockEvent27Count);
            SYSMON_FILE_BLOCK_STAT_SET(g_FileBlockLastReportStatus, STATUS_SUCCESS);
            StreamContext->Flags |= SYSMON_FILE_BLOCK_CTX_EVENT_REPORTED;
            goto Cleanup;
        }

        reportStatus = SysmonReportCanonicalFileEvent(
            SysmonEventFileBlockExecutable,
            Data,
            FltObjects,
            StreamContext->OriginalPath,
            NULL,
            NULL);
        if (NT_SUCCESS(reportStatus)) {
            SYSMON_FILE_BLOCK_STAT_INC(g_FileBlockEvent27Count);
            SYSMON_FILE_BLOCK_STAT_SET(g_FileBlockLastReportStatus, reportStatus);
            StreamContext->Flags |= SYSMON_FILE_BLOCK_CTX_EVENT_REPORTED;
            goto Cleanup;
        }

        SYSMON_FILE_BLOCK_STAT_SET(g_FileBlockLastReportStatus, reportStatus);
        deleteContext = FinalAttempt;
        if (FinalAttempt) {
            DbgPrintEx(
                DPFLTR_DEFAULT_ID,
                DPFLTR_WARNING_LEVEL,
                "[SysmonDrv] FileBlockExecutable report failed: 0x%08X\n",
                reportStatus);
        }
        goto Cleanup;
    }

    SYSMON_FILE_BLOCK_STAT_INC(g_FileBlockFinalizeWouldDetectCount);
    if (detectEvent != NULL) {
        SysmonSubmitPreparedEvent(&detectEvent);
        SYSMON_FILE_BLOCK_STAT_INC(g_FileBlockEvent29Count);
        SYSMON_FILE_BLOCK_STAT_SET(g_FileBlockLastReportStatus, STATUS_SUCCESS);
        StreamContext->Flags |= SYSMON_FILE_BLOCK_CTX_EVENT_REPORTED;
        goto Cleanup;
    }

    reportStatus = SysmonReportCanonicalFileEvent(
        SysmonEventFileExecutableDetected,
        Data,
        FltObjects,
        StreamContext->OriginalPath,
        NULL,
        NULL);
    if (NT_SUCCESS(reportStatus)) {
        SYSMON_FILE_BLOCK_STAT_INC(g_FileBlockEvent29Count);
        SYSMON_FILE_BLOCK_STAT_SET(g_FileBlockLastReportStatus, reportStatus);
        StreamContext->Flags |= SYSMON_FILE_BLOCK_CTX_EVENT_REPORTED;
        goto Cleanup;
    }

    SYSMON_FILE_BLOCK_STAT_SET(g_FileBlockLastReportStatus, reportStatus);
    deleteContext = FinalAttempt;
    if (FinalAttempt) {
        DbgPrintEx(
            DPFLTR_DEFAULT_ID,
            DPFLTR_WARNING_LEVEL,
            "[SysmonDrv] FileExecutableDetected report failed: 0x%08X\n",
            reportStatus);
    }

Cleanup:
    if (blockEvent != NULL) {
        SysmonFreeEvent(blockEvent);
    }
    if (detectEvent != NULL) {
        SysmonFreeEvent(detectEvent);
    }
    if (runtime != NULL) {
        SysmonReleaseRuleRuntimeSnapshot(runtime);
    }

    return deleteContext;
}

static NTSTATUS
SysmonReportCanonicalFileEvent(
    _In_ SYSMON_EVENT_ID EventId,
    _In_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_opt_z_ PCWSTR TargetPathOverride,
    _In_opt_ const LARGE_INTEGER *NewCreationTime,
    _In_opt_ const LARGE_INTEGER *PreviousCreationTime)
{
    PSYSMON_EVENT_UNION event = NULL;
    NTSTATUS status;

    status = SysmonBuildCanonicalFileEvent(
        EventId,
        Data,
        FltObjects,
        TargetPathOverride,
        NewCreationTime,
        PreviousCreationTime,
        &event);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    if (event == NULL) {
        return STATUS_UNSUCCESSFUL;
    }

    SysmonSubmitEvent(event);
    SysmonFreeEvent(event);

    return STATUS_SUCCESS;
}

/* ========================================================================
 * Pre-operation callbacks
 * ======================================================================== */

/*
 * IRP_MJ_CREATE - File Creation (Events 11, 15, 17, 18)
 *
 * Handles:
 *   - FileCreate (Event 11): Regular file creation
 *   - FileCreateStreamHash (Event 15): Alternate data stream creation
 *   - PipeEvent Created (Event 17): Named pipe creation
 *   - PipeEvent Connected (Event 18): Named pipe connection
 *   - Executable candidates are only armed here; Event 29 remains deferred
 *     until the cleanup-stage state machine.
 */
FLT_PREOP_CALLBACK_STATUS
FilterPreCreate(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID *CompletionContext)
{
    PSYSMON_CREATE_EVENT_CONTEXT createContext = NULL;
    BOOLEAN isStream = FALSE;
    ULONG disposition;

    *CompletionContext = NULL;

    if (!SysmonEnterMinifilterCallback()) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    if (!SysmonIsUserModeRequest(Data)) {
        SysmonLeaveMinifilterCallback();
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    if (!SysmonIsProducerEnabled(SYSMON_FLAG_ENABLED) || !SysmonIsProducerEnabled(SYSMON_FLAG_FILE_NOTIFY)) {
        SysmonLeaveMinifilterCallback();
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    createContext = (PSYSMON_CREATE_EVENT_CONTEXT)SysmonAllocatePool(sizeof(SYSMON_CREATE_EVENT_CONTEXT));
    if (createContext == NULL) {
        SysmonLeaveMinifilterCallback();
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }
    RtlZeroMemory(createContext, sizeof(SYSMON_CREATE_EVENT_CONTEXT));

    /* Check for named pipe creation/connection (Events 17, 18). */
    if (NT_SUCCESS(SysmonClassifyPipeCreateEvent(
            Data,
            FltObjects,
            &createContext->PipeEventId,
            createContext->PipeName,
            RTL_NUMBER_OF(createContext->PipeName))) &&
        createContext->PipeEventId != 0) {
        *CompletionContext = createContext;
        SysmonLeaveMinifilterCallback();
        return FLT_PREOP_SUCCESS_WITH_CALLBACK;
    }

    /*
     * Match original Sysmon Event 9 timing: detect the direct volume open on
     * create and emit only after the open succeeds.
     */
    if (SysmonTryGetRawVolumeDeviceName(
            Data,
            FltObjects,
            createContext->RawDeviceName,
            RTL_NUMBER_OF(createContext->RawDeviceName))) {
        createContext->ReportRawAccessRead = TRUE;
        *CompletionContext = createContext;
        SysmonLeaveMinifilterCallback();
        return FLT_PREOP_SUCCESS_WITH_CALLBACK;
    }

    if (Data->Iopb->MajorFunction == IRP_MJ_CREATE_NAMED_PIPE) {
        SysmonFreePool(createContext);
        SysmonLeaveMinifilterCallback();
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    disposition = (Data->Iopb->Parameters.Create.Options >> 24) & 0xFF;

    /* Check for alternate data stream creation (Event 15) */
    if (FltObjects->FileObject != NULL && FltObjects->FileObject->FileName.Length > 0) {
        isStream = SysmonHasAlternateStream(&FltObjects->FileObject->FileName);
        if (isStream) {
            createContext->ReportStreamHash = TRUE;
            *CompletionContext = createContext;
            SysmonLeaveMinifilterCallback();
            return FLT_PREOP_SUCCESS_WITH_CALLBACK;
        }
    }

    /* Check for file creation (Event 11) */
    if (disposition == FILE_CREATE || disposition == FILE_OPEN_IF ||
        disposition == FILE_OVERWRITE_IF || disposition == FILE_SUPERSEDE) {
        createContext->CreateDisposition = (UCHAR)disposition;
        createContext->ReportFileCreate = TRUE;
        SYSMON_FILE_CREATE_STAT_INC(g_FileCreateCandidateCount);

        /* Executable extensions are only used for early candidate arming. */
        if (FltObjects->FileObject != NULL && FltObjects->FileObject->FileName.Length > 0) {
            if (SysmonIsExecutable(&FltObjects->FileObject->FileName)) {
                createContext->ExecutableCandidate = TRUE;
                createContext->ArmFileBlockContext =
                    SysmonCreateRequestMayModifyExecutable(Data);
            }
        }
    }

    if (createContext->ReportFileCreate ||
        createContext->ArmFileBlockContext) {
        *CompletionContext = createContext;
        SysmonLeaveMinifilterCallback();
        return FLT_PREOP_SUCCESS_WITH_CALLBACK;
    }

    SysmonFreePool(createContext);
    SysmonLeaveMinifilterCallback();
    return FLT_PREOP_SUCCESS_NO_CALLBACK;
}

/*
 * IRP_MJ_SET_INFORMATION - File Time/Disposition Changes (Events 2, 23, 26)
 *
 * Handles:
 *   - FileCreateTime (Event 2): File creation time modification
 *   - FileDelete (Event 23): File deletion (archived)
 *   - FileDeleteDetected (Event 26): File deletion detection
 */
FLT_PREOP_CALLBACK_STATUS
FilterPreSetInfo(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID *CompletionContext)
{
    PSYSMON_SETINFO_EVENT_CONTEXT setInfoContext = NULL;
    FILE_INFORMATION_CLASS infoClass;

    *CompletionContext = NULL;

    if (!SysmonEnterMinifilterCallback()) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    if (!SysmonIsUserModeRequest(Data)) {
        SysmonLeaveMinifilterCallback();
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    if (!SysmonIsProducerEnabled(SYSMON_FLAG_ENABLED) || !SysmonIsProducerEnabled(SYSMON_FLAG_FILE_NOTIFY)) {
        SysmonLeaveMinifilterCallback();
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    infoClass = Data->Iopb->Parameters.SetFileInformation.FileInformationClass;

    setInfoContext = (PSYSMON_SETINFO_EVENT_CONTEXT)SysmonAllocatePool(sizeof(SYSMON_SETINFO_EVENT_CONTEXT));
    if (setInfoContext == NULL) {
        SysmonLeaveMinifilterCallback();
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }
    RtlZeroMemory(setInfoContext, sizeof(SYSMON_SETINFO_EVENT_CONTEXT));

    /* File creation time changed (Event 2) */
    if (infoClass == FileBasicInformation) {
        PFILE_BASIC_INFORMATION basicInfo =
            (PFILE_BASIC_INFORMATION)Data->Iopb->Parameters.SetFileInformation.InfoBuffer;
        if (SysmonCaptureChangingCreationTime(
                FltObjects,
                basicInfo,
                &setInfoContext->PreviousCreationTime)) {
            setInfoContext->ReportFileCreateTime = TRUE;
            setInfoContext->NewCreationTime = basicInfo->CreationTime;
        }
    }

    /* File deletion (Events 23, 26) */
    if (infoClass == FileDispositionInformation) {
        PFILE_DISPOSITION_INFORMATION dispInfo =
            (PFILE_DISPOSITION_INFORMATION)Data->Iopb->Parameters.SetFileInformation.InfoBuffer;
        if (dispInfo != NULL && dispInfo->DeleteFile) {
            setInfoContext->ReportFileDeleteDetected = TRUE;
            setInfoContext->ReportFileDelete = TRUE;
        }
    }

    /* Extended disposition delete (Events 23, 26; POSIX delete also maps to Event 28). */
    if (infoClass == FileDispositionInformationEx) {
        PFILE_DISPOSITION_INFORMATION_EX dispExInfo =
            (PFILE_DISPOSITION_INFORMATION_EX)Data->Iopb->Parameters.SetFileInformation.InfoBuffer;
        if (dispExInfo != NULL && (dispExInfo->Flags & FILE_DISPOSITION_DELETE)) {
            setInfoContext->ReportFileDeleteDetected = TRUE;
            setInfoContext->ReportFileDelete = TRUE;
            if (dispExInfo->Flags & FILE_DISPOSITION_POSIX_SEMANTICS) {
                setInfoContext->ReportFileBlockShredding = TRUE;
            }
        }
    }

    if (setInfoContext->ReportFileCreateTime ||
        setInfoContext->ReportFileDeleteDetected ||
        setInfoContext->ReportFileDelete ||
        setInfoContext->ReportFileBlockShredding) {
        *CompletionContext = setInfoContext;
        SysmonLeaveMinifilterCallback();
        return FLT_PREOP_SUCCESS_WITH_CALLBACK;
    }

    SysmonFreePool(setInfoContext);
    SysmonLeaveMinifilterCallback();
    return FLT_PREOP_SUCCESS_NO_CALLBACK;
}

static FLT_POSTOP_CALLBACK_STATUS FLTAPI
FilterPostSetInfo(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_opt_ PVOID CompletionContext,
    _In_ FLT_POST_OPERATION_FLAGS Flags)
{
    PSYSMON_SETINFO_EVENT_CONTEXT setInfoContext =
        (PSYSMON_SETINFO_EVENT_CONTEXT)CompletionContext;

    if (!SysmonEnterMinifilterCallback()) {
        if (setInfoContext != NULL) {
            SysmonFreePool(setInfoContext);
        }
        return FLT_POSTOP_FINISHED_PROCESSING;
    }

    if (setInfoContext == NULL) {
        SysmonLeaveMinifilterCallback();
        return FLT_POSTOP_FINISHED_PROCESSING;
    }

    if ((Flags & FLTFL_POST_OPERATION_DRAINING) ||
        !NT_SUCCESS(Data->IoStatus.Status) ||
        !SysmonIsProducerEnabled(SYSMON_FLAG_ENABLED) ||
        !SysmonIsProducerEnabled(SYSMON_FLAG_FILE_NOTIFY) ||
        !SysmonCanCollectEventDetails("post-set-information event")) {
        SysmonFreePool(setInfoContext);
        SysmonLeaveMinifilterCallback();
        return FLT_POSTOP_FINISHED_PROCESSING;
    }

    if (setInfoContext->ReportFileCreateTime) {
        SysmonReportCanonicalFileEvent(
            SysmonEventFileCreateTime,
            Data,
            FltObjects,
            NULL,
            &setInfoContext->NewCreationTime,
            &setInfoContext->PreviousCreationTime);
    }

    if (setInfoContext->ReportFileDeleteDetected) {
        SysmonReportCanonicalFileEvent(SysmonEventFileDeleteDetected, Data, FltObjects, NULL, NULL, NULL);
    }

    if (setInfoContext->ReportFileDelete) {
        SysmonReportCanonicalFileEvent(SysmonEventFileDelete, Data, FltObjects, NULL, NULL, NULL);
    }

    if (setInfoContext->ReportFileBlockShredding) {
        SysmonReportCanonicalFileEvent(SysmonEventFileBlockShredding, Data, FltObjects, NULL, NULL, NULL);
    }

    SysmonFreePool(setInfoContext);
    SysmonLeaveMinifilterCallback();
    return FLT_POSTOP_FINISHED_PROCESSING;
}

/*
 * IRP_MJ_READ
 */
FLT_PREOP_CALLBACK_STATUS
FilterPreRead(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID *CompletionContext)
{
    UNREFERENCED_PARAMETER(Data);
    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(CompletionContext);

    if (!SysmonEnterMinifilterCallback()) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    SysmonLeaveMinifilterCallback();
    return FLT_PREOP_SUCCESS_NO_CALLBACK;
}

/*
 * IRP_MJ_WRITE - Track writes for the file-block executable state machine.
 */
FLT_PREOP_CALLBACK_STATUS
FilterPreWrite(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID *CompletionContext)
{
    PSYSMON_FILE_BLOCK_STREAM_CONTEXT streamContext = NULL;

    *CompletionContext = NULL;

    if (!SysmonEnterMinifilterCallback()) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    if (!SysmonIsUserModeRequest(Data) ||
        !SysmonIsProducerEnabled(SYSMON_FLAG_ENABLED) ||
        !SysmonIsProducerEnabled(SYSMON_FLAG_FILE_NOTIFY) ||
        Data->Iopb == NULL ||
        Data->Iopb->Parameters.Write.Length == 0) {
        SysmonLeaveMinifilterCallback();
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    if (NT_SUCCESS(SysmonLookupFileBlockStreamContext(FltObjects, &streamContext)) &&
        streamContext != NULL) {
        BOOLEAN armed =
            ((streamContext->Flags & SYSMON_FILE_BLOCK_CTX_ARMED) != 0);

        FltReleaseContext(streamContext);
        SysmonLeaveMinifilterCallback();
        return armed ? FLT_PREOP_SUCCESS_WITH_CALLBACK :
                       FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    SysmonLeaveMinifilterCallback();
    return FLT_PREOP_SUCCESS_NO_CALLBACK;
}

FLT_POSTOP_CALLBACK_STATUS FLTAPI
FilterPostWrite(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_opt_ PVOID CompletionContext,
    _In_ FLT_POST_OPERATION_FLAGS Flags)
{
    PSYSMON_FILE_BLOCK_STREAM_CONTEXT streamContext = NULL;
    ULONG_PTR bytesWritten;
    BOOLEAN headerChecked = FALSE;
    BOOLEAN isPe = FALSE;

    UNREFERENCED_PARAMETER(CompletionContext);

    if (!SysmonEnterMinifilterCallback()) {
        return FLT_POSTOP_FINISHED_PROCESSING;
    }

    if ((Flags & FLTFL_POST_OPERATION_DRAINING) ||
        !NT_SUCCESS(Data->IoStatus.Status) ||
        !SysmonIsProducerEnabled(SYSMON_FLAG_ENABLED) ||
        !SysmonIsProducerEnabled(SYSMON_FLAG_FILE_NOTIFY)) {
        SysmonLeaveMinifilterCallback();
        return FLT_POSTOP_FINISHED_PROCESSING;
    }

    bytesWritten = (ULONG_PTR)Data->IoStatus.Information;
    if (bytesWritten == 0 ||
        !NT_SUCCESS(SysmonLookupFileBlockStreamContext(FltObjects, &streamContext)) ||
        streamContext == NULL) {
        SysmonLeaveMinifilterCallback();
        return FLT_POSTOP_FINISHED_PROCESSING;
    }

    if ((streamContext->Flags & SYSMON_FILE_BLOCK_CTX_ARMED) != 0) {
        SYSMON_FILE_BLOCK_STAT_INC(g_FileBlockWriteCallbackCount);
        streamContext->Flags |= SYSMON_FILE_BLOCK_CTX_SAW_WRITE;
        SYSMON_FILE_BLOCK_STAT_INC(g_FileBlockSawWriteCount);

        /*
         * The create path only arms user-originated handles. Subsequent writes
         * for the same handle may still arrive from Cache Manager worker
         * threads, so don't re-filter on RequestorMode here.
         *
         * Keep retrying only while the header cannot be read decisively. Once
         * the header is checked, cache both PE and non-PE outcomes for this
         * handle, matching the original driver's one-shot header flag.
         */
        if ((streamContext->Flags & SYSMON_FILE_BLOCK_CTX_HEADER_CHECKED) == 0 &&
            SysmonCanCollectEventDetails("post-write PE header check")) {
            SYSMON_FILE_BLOCK_STAT_INC(g_FileBlockHeaderCheckCount);
            isPe = SysmonDetectPeFromFileObject(FltObjects, &headerChecked);
            if (headerChecked) {
                streamContext->Flags |= SYSMON_FILE_BLOCK_CTX_HEADER_CHECKED;
                if (isPe) {
                    streamContext->Flags |= SYSMON_FILE_BLOCK_CTX_IS_PE;
                    SYSMON_FILE_BLOCK_STAT_INC(g_FileBlockHeaderMatchCount);
                }
            }
        }
    }

    FltReleaseContext(streamContext);
    SysmonLeaveMinifilterCallback();
    return FLT_POSTOP_FINISHED_PROCESSING;
}

/*
 * IRP_MJ_CLEANUP - File handle cleanup
 */
FLT_PREOP_CALLBACK_STATUS
FilterPreCleanup(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID *CompletionContext)
{
    PSYSMON_FILE_BLOCK_STREAM_CONTEXT streamContext = NULL;
    BOOLEAN deleteContext;

    *CompletionContext = NULL;
    if (!SysmonEnterMinifilterCallback()) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    if (!SysmonIsProducerEnabled(SYSMON_FLAG_ENABLED) ||
        !SysmonIsProducerEnabled(SYSMON_FLAG_FILE_NOTIFY)) {
        SysmonLeaveMinifilterCallback();
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    if (!NT_SUCCESS(SysmonLookupFileBlockStreamContext(FltObjects, &streamContext)) ||
        streamContext == NULL) {
        SysmonLeaveMinifilterCallback();
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    deleteContext = SysmonFinalizeFileBlockContext(
        Data,
        FltObjects,
        streamContext,
        FALSE);
    if (deleteContext &&
        FltObjects != NULL &&
        FltObjects->Instance != NULL &&
        FltObjects->FileObject != NULL) {
        (void)FltDeleteStreamHandleContext(
            FltObjects->Instance,
            FltObjects->FileObject,
            NULL);
    }
    FltReleaseContext(streamContext);
    SysmonLeaveMinifilterCallback();
    return FLT_PREOP_SUCCESS_NO_CALLBACK;
}

/*
 * IRP_MJ_CLOSE - File handle close
 */
FLT_PREOP_CALLBACK_STATUS
FilterPreClose(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID *CompletionContext)
{
    PSYSMON_FILE_BLOCK_STREAM_CONTEXT streamContext = NULL;
    BOOLEAN deleteContext = FALSE;

    UNREFERENCED_PARAMETER(CompletionContext);
    if (!SysmonEnterMinifilterCallback()) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    if (NT_SUCCESS(SysmonLookupFileBlockStreamContext(FltObjects, &streamContext)) &&
        streamContext != NULL) {
        deleteContext = SysmonFinalizeFileBlockContext(
            Data,
            FltObjects,
            streamContext,
            TRUE);
        FltReleaseContext(streamContext);

        if (deleteContext &&
            FltObjects != NULL &&
            FltObjects->Instance != NULL &&
            FltObjects->FileObject != NULL) {
            (void)FltDeleteStreamHandleContext(
                FltObjects->Instance,
                FltObjects->FileObject,
                NULL);
        }
    }
    SysmonLeaveMinifilterCallback();
    return FLT_PREOP_SUCCESS_NO_CALLBACK;
}

static FLT_POSTOP_CALLBACK_STATUS FLTAPI
FilterPostCreate(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_opt_ PVOID CompletionContext,
    _In_ FLT_POST_OPERATION_FLAGS Flags)
{
    PSYSMON_CREATE_EVENT_CONTEXT createContext =
        (PSYSMON_CREATE_EVENT_CONTEXT)CompletionContext;
    PSYSMON_FILE_BLOCK_STREAM_CONTEXT streamContext = NULL;
    BOOLEAN fileCreated;
    BOOLEAN canCollectEventDetails;
    NTSTATUS reportStatus;
    NTSTATUS contextStatus;
    WCHAR capturedPath[SYSMON_MAX_PATH];

    if (!SysmonEnterMinifilterCallback()) {
        if (createContext != NULL) {
            SysmonFreePool(createContext);
        }
        return FLT_POSTOP_FINISHED_PROCESSING;
    }

    if (createContext == NULL) {
        SysmonLeaveMinifilterCallback();
        return FLT_POSTOP_FINISHED_PROCESSING;
    }

    if (createContext->ReportFileCreate) {
        SYSMON_FILE_CREATE_STAT_INC(g_FileCreatePostCreateCount);
        SYSMON_FILE_CREATE_STAT_SET(g_LastFileCreateStatus, Data->IoStatus.Status);
        SYSMON_FILE_CREATE_STAT_SET(g_LastFileCreateInfo, Data->IoStatus.Information);
        SYSMON_FILE_CREATE_STAT_SET(g_LastFileCreateIrql, KeGetCurrentIrql());
        SYSMON_FILE_CREATE_STAT_SET(g_LastFileCreateDisposition, createContext->CreateDisposition);
    }

    if (Flags & FLTFL_POST_OPERATION_DRAINING) {
        SysmonFreePool(createContext);
        SysmonLeaveMinifilterCallback();
        return FLT_POSTOP_FINISHED_PROCESSING;
    }

    if (!NT_SUCCESS(Data->IoStatus.Status)) {
        if (createContext->ReportFileCreate) {
            SYSMON_FILE_CREATE_STAT_INC(g_FileCreateStatusFailureCount);
        }
        SysmonFreePool(createContext);
        SysmonLeaveMinifilterCallback();
        return FLT_POSTOP_FINISHED_PROCESSING;
    }

    if (!SysmonIsProducerEnabled(SYSMON_FLAG_ENABLED) || !SysmonIsProducerEnabled(SYSMON_FLAG_FILE_NOTIFY)) {
        SysmonFreePool(createContext);
        SysmonLeaveMinifilterCallback();
        return FLT_POSTOP_FINISHED_PROCESSING;
    }

    fileCreated = (Data->IoStatus.Information == FILE_CREATED ||
                   Data->IoStatus.Information == FILE_SUPERSEDED ||
                   Data->IoStatus.Information == FILE_OVERWRITTEN);
    if (createContext->ReportFileCreate && !fileCreated) {
        SYSMON_FILE_CREATE_STAT_INC(g_FileCreateNotCreatedCount);
    }

    if (createContext->ArmFileBlockContext) {
        contextStatus = SysmonGetOrCreateFileBlockStreamContext(
            FltObjects,
            &streamContext);
        if (NT_SUCCESS(contextStatus) && streamContext != NULL) {
            SYSMON_FILE_BLOCK_STAT_INC(g_FileBlockContextCreateCount);
            capturedPath[0] = L'\0';
            SysmonCaptureFileName(
                Data,
                FltObjects,
                capturedPath,
                RTL_NUMBER_OF(capturedPath));

            streamContext->Flags =
                SYSMON_FILE_BLOCK_CTX_ARMED |
                SYSMON_FILE_BLOCK_CTX_CREATE_SUCCEEDED;
            if (fileCreated) {
                streamContext->Flags |= SYSMON_FILE_BLOCK_CTX_FILE_CREATED;
            }
            streamContext->ProcessId =
                (ULONG)(ULONG_PTR)FltGetRequestorProcessId(Data);
            streamContext->CreateDisposition = createContext->CreateDisposition;
            streamContext->OriginalPath[0] = L'\0';
            streamContext->Extension[0] = L'\0';

            if (capturedPath[0] != L'\0') {
                SysmonCopyWideString(
                    streamContext->OriginalPath,
                    RTL_NUMBER_OF(streamContext->OriginalPath),
                    capturedPath);
                SysmonExtractExtension(
                    streamContext->OriginalPath,
                    streamContext->Extension,
                    RTL_NUMBER_OF(streamContext->Extension));
            }

            FltReleaseContext(streamContext);
            streamContext = NULL;
        }
    }

    canCollectEventDetails = SysmonCanCollectEventDetails("post-create event");
    if (!canCollectEventDetails) {
        if (createContext->ReportFileCreate) {
            SYSMON_FILE_CREATE_STAT_INC(g_FileCreateIrqlDropCount);
        }
        SysmonFreePool(createContext);
        SysmonLeaveMinifilterCallback();
        return FLT_POSTOP_FINISHED_PROCESSING;
    }

    if (createContext->PipeEventId != 0) {
        PSYSMON_EVENT_UNION pipeEvent = NULL;
        if (NT_SUCCESS(SysmonBuildPipeEvent(
                Data,
                createContext->PipeEventId,
                createContext->PipeName,
                &pipeEvent)) &&
            pipeEvent != NULL) {
            SysmonSubmitEvent(pipeEvent);
            SysmonFreeEvent(pipeEvent);
        }
    }

    if (createContext->ReportRawAccessRead) {
        SysmonReportCanonicalFileEvent(
            SysmonEventRawAccessRead,
            Data,
            FltObjects,
            createContext->RawDeviceName,
            NULL,
            NULL);
    }

    if (createContext->ReportStreamHash && fileCreated) {
        SysmonReportCanonicalFileEvent(SysmonEventFileCreateStreamHash, Data, FltObjects, NULL, NULL, NULL);
    }

    if (createContext->ReportFileCreate && fileCreated) {
        SYSMON_FILE_CREATE_STAT_INC(g_FileCreatePublishAttemptCount);
        reportStatus = SysmonReportCanonicalFileEvent(
            SysmonEventFileCreate,
            Data,
            FltObjects,
            NULL,
            NULL,
            NULL);
        SYSMON_FILE_CREATE_STAT_SET(g_LastFileCreateReportStatus, reportStatus);
    }

    if (createContext->ExecutableCandidate) {
        /*
         * Event 27 remains deferred to the cleanup-stage state machine. Create
         * and write only advance per-handle state.
         */
    }

    SysmonFreePool(createContext);
    SysmonLeaveMinifilterCallback();
    return FLT_POSTOP_FINISHED_PROCESSING;
}

/* ========================================================================
 * Filter registration
 * ======================================================================== */

/* Operation registration table */
static const FLT_OPERATION_REGISTRATION g_Operations[] = {
    { IRP_MJ_CREATE,          0, FilterPreCreate,   FilterPostCreate },
    { IRP_MJ_CREATE_NAMED_PIPE, 0, FilterPreCreate, FilterPostCreate },
    { IRP_MJ_WRITE,           0, FilterPreWrite,    FilterPostWrite },
    { IRP_MJ_READ,            0, FilterPreRead,     NULL },
    { IRP_MJ_SET_INFORMATION, 0, FilterPreSetInfo,  FilterPostSetInfo },
    { IRP_MJ_CLEANUP,         0, FilterPreCleanup,  NULL },
    { IRP_MJ_CLOSE,           0, FilterPreClose,    NULL },
    { IRP_MJ_OPERATION_END }
};

static const FLT_CONTEXT_REGISTRATION g_Contexts[] = {
    {
        FLT_STREAMHANDLE_CONTEXT,
        0,
        NULL,
        sizeof(SYSMON_FILE_BLOCK_STREAM_CONTEXT),
        'bSmS',
        NULL,
        NULL,
        NULL
    },
    { FLT_CONTEXT_END }
};

static const FLT_REGISTRATION g_FilterRegistration = {
    sizeof(FLT_REGISTRATION),
    FLT_REGISTRATION_VERSION,
    FLTFL_REGISTRATION_SUPPORT_NPFS_MSFS,
    g_Contexts,
    g_Operations,
    FilterUnload,
    FilterInstanceSetup,
    FilterInstanceQueryTeardown,
    NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL
};

/* Filter unload callback */
NTSTATUS NTAPI
FilterUnload(_In_ PFLT_FILTER FilterObject)
{
    UNREFERENCED_PARAMETER(FilterObject);

    SysmonShutdownDriver(TRUE);
    SysmonCleanupMinifilterLookasides();
    if (g_FilterHandle == FilterObject) {
        g_FilterHandle = NULL;
    }

    DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_INFO_LEVEL,
        "[SysmonDrv] FilterUnload: acknowledged\n");

    return STATUS_SUCCESS;
}

/* Instance setup callback */
NTSTATUS FLTAPI
FilterInstanceSetup(
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ FLT_INSTANCE_SETUP_FLAGS Flags,
    _In_ DEVICE_TYPE VolumeDeviceType,
    _In_ FLT_FILESYSTEM_TYPE VolumeFilesystemType)
{
    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(Flags);
    UNREFERENCED_PARAMETER(VolumeDeviceType);
    UNREFERENCED_PARAMETER(VolumeFilesystemType);
    return STATUS_SUCCESS;
}

/* Instance query teardown callback */
NTSTATUS FLTAPI
FilterInstanceQueryTeardown(
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ FLT_INSTANCE_QUERY_TEARDOWN_FLAGS Flags)
{
    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(Flags);
    return STATUS_SUCCESS;
}

NTSTATUS
SysmonRegisterFilter(_In_ PDRIVER_OBJECT DriverObject)
{
    NTSTATUS status;

    if (g_FilterHandle != NULL) {
        return STATUS_SUCCESS;
    }

    status = FltRegisterFilter(DriverObject, &g_FilterRegistration, &g_FilterHandle);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    SysmonInitializeMinifilterLookasides();

    status = FltStartFiltering(g_FilterHandle);
    if (!NT_SUCCESS(status)) {
        SysmonCleanupMinifilterLookasides();
        FltUnregisterFilter(g_FilterHandle);
        g_FilterHandle = NULL;
        return status;
    }

    return STATUS_SUCCESS;
}

VOID
SysmonUnregisterFilter(VOID)
{
    if (g_FilterHandle != NULL) {
        FltUnregisterFilter(g_FilterHandle);
        g_FilterHandle = NULL;
    }

    SysmonCleanupMinifilterLookasides();
}

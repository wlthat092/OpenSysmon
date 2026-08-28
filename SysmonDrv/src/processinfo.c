#include "processinfo.h"
#include "driver.h"
#include "hash.h"
#include "process.h"
#include "utils.h"
#include <ntimage.h>

/* Process access rights (may not be in kernel headers) */
#ifndef PROCESS_QUERY_INFORMATION
#define PROCESS_QUERY_INFORMATION 0x0400
#endif
#ifndef PROCESS_VM_READ
#define PROCESS_VM_READ 0x0010
#endif
#ifndef PROCESS_QUERY_LIMITED_INFORMATION
#define PROCESS_QUERY_LIMITED_INFORMATION 0x1000
#endif

typedef struct _SYSMON_PROCESS_SESSION_INFORMATION {
    ULONG SessionId;
} SYSMON_PROCESS_SESSION_INFORMATION, *PSYSMON_PROCESS_SESSION_INFORMATION;

static VOID
SysmonPopulateCachedProcessMetadata(
    _Inout_ PSYSMON_PROCESS_INFO Info)
{
    SYSMON_PROCESS_CACHE_METADATA cachedMetadata;

    if (Info == NULL || Info->ProcessId == 0) {
        return;
    }

    RtlZeroMemory(&cachedMetadata, sizeof(cachedMetadata));
    if (!SysmonLookupCachedProcessMetadata(Info->ProcessId, &cachedMetadata)) {
        return;
    }

    if (Info->CreateTime == 0) {
        Info->CreateTime = cachedMetadata.CreateTime;
    }
    if (Info->ProcessGuid[0] == L'\0') {
        SysmonCopyWideStringWithLength(
            Info->ProcessGuid,
            RTL_NUMBER_OF(Info->ProcessGuid),
            cachedMetadata.ProcessGuid,
            SYSMON_GUID_STRING_CHARS);
    }
    if (Info->ImagePath[0] == L'\0') {
        SysmonCopyWideString(
            Info->ImagePath,
            RTL_NUMBER_OF(Info->ImagePath),
            cachedMetadata.Image);
    }
    if (Info->UserSid[0] == L'\0') {
        SysmonCopyWideString(
            Info->UserSid,
            RTL_NUMBER_OF(Info->UserSid),
            cachedMetadata.UserSid);
    }
}

typedef struct _SYSMON_CURDIR64 {
    UNICODE_STRING DosPath;
    HANDLE Handle;
} SYSMON_CURDIR64, *PSYSMON_CURDIR64;

typedef struct _SYSMON_RTL_USER_PROCESS_PARAMETERS64 {
    ULONG MaximumLength;
    ULONG Length;
    ULONG Flags;
    ULONG DebugFlags;
    HANDLE ConsoleHandle;
    ULONG ConsoleFlags;
    HANDLE StandardInput;
    HANDLE StandardOutput;
    HANDLE StandardError;
    SYSMON_CURDIR64 CurrentDirectory;
    UNICODE_STRING DllPath;
    UNICODE_STRING ImagePathName;
    UNICODE_STRING CommandLine;
} SYSMON_RTL_USER_PROCESS_PARAMETERS64, *PSYSMON_RTL_USER_PROCESS_PARAMETERS64;

typedef struct _SYSMON_PEB64 {
    UCHAR Reserved1[2];
    UCHAR BeingDebugged;
    UCHAR Reserved2[1];
    PVOID Reserved3[2];
    PVOID Ldr;
    PSYSMON_RTL_USER_PROCESS_PARAMETERS64 ProcessParameters;
} SYSMON_PEB64, *PSYSMON_PEB64;

typedef struct _SYSMON_UNICODE_STRING32 {
    USHORT Length;
    USHORT MaximumLength;
    ULONG Buffer;
} SYSMON_UNICODE_STRING32, *PSYSMON_UNICODE_STRING32;

typedef struct _SYSMON_CURDIR32 {
    SYSMON_UNICODE_STRING32 DosPath;
    ULONG Handle;
} SYSMON_CURDIR32, *PSYSMON_CURDIR32;

typedef struct _SYSMON_RTL_USER_PROCESS_PARAMETERS32 {
    ULONG MaximumLength;
    ULONG Length;
    ULONG Flags;
    ULONG DebugFlags;
    ULONG ConsoleHandle;
    ULONG ConsoleFlags;
    ULONG StandardInput;
    ULONG StandardOutput;
    ULONG StandardError;
    SYSMON_CURDIR32 CurrentDirectory;
    SYSMON_UNICODE_STRING32 DllPath;
    SYSMON_UNICODE_STRING32 ImagePathName;
    SYSMON_UNICODE_STRING32 CommandLine;
} SYSMON_RTL_USER_PROCESS_PARAMETERS32, *PSYSMON_RTL_USER_PROCESS_PARAMETERS32;

typedef struct _SYSMON_PEB32 {
    UCHAR Reserved1[2];
    UCHAR BeingDebugged;
    UCHAR Reserved2[1];
    ULONG Reserved3[2];
    ULONG Ldr;
    ULONG ProcessParameters;
} SYSMON_PEB32, *PSYSMON_PEB32;

typedef struct _SYSMON_LIST_ENTRY64 {
    ULONGLONG Flink;
    ULONGLONG Blink;
} SYSMON_LIST_ENTRY64, *PSYSMON_LIST_ENTRY64;

typedef struct _SYSMON_LIST_ENTRY32 {
    ULONG Flink;
    ULONG Blink;
} SYSMON_LIST_ENTRY32, *PSYSMON_LIST_ENTRY32;

typedef struct _SYSMON_PEB_LDR_DATA64 {
    ULONG Length;
    UCHAR Initialized;
    UCHAR Reserved1[3];
    ULONGLONG SsHandle;
    SYSMON_LIST_ENTRY64 InLoadOrderModuleList;
    SYSMON_LIST_ENTRY64 InMemoryOrderModuleList;
} SYSMON_PEB_LDR_DATA64, *PSYSMON_PEB_LDR_DATA64;

typedef struct _SYSMON_PEB_LDR_DATA32 {
    ULONG Length;
    UCHAR Initialized;
    UCHAR Reserved1[3];
    ULONG SsHandle;
    SYSMON_LIST_ENTRY32 InLoadOrderModuleList;
    SYSMON_LIST_ENTRY32 InMemoryOrderModuleList;
} SYSMON_PEB_LDR_DATA32, *PSYSMON_PEB_LDR_DATA32;

typedef struct _SYSMON_LDR_DATA_TABLE_ENTRY64 {
    SYSMON_LIST_ENTRY64 InLoadOrderLinks;
    SYSMON_LIST_ENTRY64 InMemoryOrderLinks;
    SYSMON_LIST_ENTRY64 InInitializationOrderLinks;
    ULONGLONG DllBase;
    ULONGLONG EntryPoint;
    ULONG SizeOfImage;
    ULONG Reserved1;
    UNICODE_STRING FullDllName;
    UNICODE_STRING BaseDllName;
} SYSMON_LDR_DATA_TABLE_ENTRY64, *PSYSMON_LDR_DATA_TABLE_ENTRY64;

typedef struct _SYSMON_LDR_DATA_TABLE_ENTRY32 {
    SYSMON_LIST_ENTRY32 InLoadOrderLinks;
    SYSMON_LIST_ENTRY32 InMemoryOrderLinks;
    SYSMON_LIST_ENTRY32 InInitializationOrderLinks;
    ULONG DllBase;
    ULONG EntryPoint;
    ULONG SizeOfImage;
    SYSMON_UNICODE_STRING32 FullDllName;
    SYSMON_UNICODE_STRING32 BaseDllName;
} SYSMON_LDR_DATA_TABLE_ENTRY32, *PSYSMON_LDR_DATA_TABLE_ENTRY32;

C_ASSERT(FIELD_OFFSET(SYSMON_RTL_USER_PROCESS_PARAMETERS64, CurrentDirectory) == 0x38);
C_ASSERT(FIELD_OFFSET(SYSMON_RTL_USER_PROCESS_PARAMETERS64, ImagePathName) == 0x60);
C_ASSERT(FIELD_OFFSET(SYSMON_RTL_USER_PROCESS_PARAMETERS64, CommandLine) == 0x70);
C_ASSERT(FIELD_OFFSET(SYSMON_PEB64, ProcessParameters) == 0x20);
C_ASSERT(FIELD_OFFSET(SYSMON_PEB_LDR_DATA64, InMemoryOrderModuleList) == 0x20);
C_ASSERT(FIELD_OFFSET(SYSMON_PEB_LDR_DATA32, InMemoryOrderModuleList) == 0x14);
C_ASSERT(FIELD_OFFSET(SYSMON_LDR_DATA_TABLE_ENTRY64, DllBase) == 0x30);

static NTSTATUS
SysmonCopyAttachedUnicodeString(
    _In_ PCUNICODE_STRING Source,
    _Out_writes_(MaxLen) WCHAR *Destination,
    _In_ ULONG MaxLen)
{
    ULONG copyChars;

    if (Destination == NULL || MaxLen == 0) {
        return STATUS_INVALID_PARAMETER;
    }

    Destination[0] = L'\0';

    __try {
        ProbeForRead(Source, sizeof(*Source), __alignof(WCHAR));
        if (Source->Buffer == NULL || Source->Length == 0) {
            return STATUS_NOT_FOUND;
        }

        copyChars = Source->Length / sizeof(WCHAR);
        if (copyChars >= MaxLen) {
            copyChars = MaxLen - 1;
        }

        ProbeForRead(Source->Buffer, copyChars * sizeof(WCHAR), sizeof(WCHAR));
        RtlCopyMemory(Destination, Source->Buffer, copyChars * sizeof(WCHAR));
        Destination[copyChars] = L'\0';
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        Destination[0] = L'\0';
        return GetExceptionCode();
    }

    return STATUS_SUCCESS;
}

static NTSTATUS
SysmonCopyAttachedUnicodeString32(
    _In_ const SYSMON_UNICODE_STRING32 *Source,
    _Out_writes_(MaxLen) WCHAR *Destination,
    _In_ ULONG MaxLen)
{
    ULONG copyChars;
    PWCHAR sourceBuffer;

    if (Destination == NULL || MaxLen == 0) {
        return STATUS_INVALID_PARAMETER;
    }

    Destination[0] = L'\0';

    __try {
        ProbeForRead(Source, sizeof(*Source), sizeof(USHORT));
        if (Source->Buffer == 0 || Source->Length == 0) {
            return STATUS_NOT_FOUND;
        }

        copyChars = Source->Length / sizeof(WCHAR);
        if (copyChars >= MaxLen) {
            copyChars = MaxLen - 1;
        }

        sourceBuffer = (PWCHAR)(ULONG_PTR)Source->Buffer;
        ProbeForRead(sourceBuffer, copyChars * sizeof(WCHAR), sizeof(WCHAR));
        RtlCopyMemory(Destination, sourceBuffer, copyChars * sizeof(WCHAR));
        Destination[copyChars] = L'\0';
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        Destination[0] = L'\0';
        return GetExceptionCode();
    }

    return STATUS_SUCCESS;
}

static NTSTATUS
SysmonCopyAttachedAnsiString(
    _In_reads_bytes_(MAXUSHORT) PCCHAR Source,
    _Out_writes_(MaxLen) WCHAR *Destination,
    _In_ ULONG MaxLen)
{
    ULONG index;
    ULONG chunkOffset;
    ULONG remainingChars;
    SIZE_T chunkBytes;
    CHAR character;

    if (Destination == NULL || MaxLen == 0) {
        return STATUS_INVALID_PARAMETER;
    }

    Destination[0] = L'\0';

    __try {
        index = 0;
        while (index < MaxLen - 1) {
            /*
             * Probe attached user memory a page at a time so we validate the
             * readable range beyond the first byte without reintroducing
             * per-character ProbeForRead overhead.
             */
            remainingChars = (MaxLen - 1) - index;
            chunkOffset = (ULONG)BYTE_OFFSET(Source + index);
            chunkBytes = PAGE_SIZE - chunkOffset;
            if (chunkBytes > remainingChars) {
                chunkBytes = remainingChars;
            }

            ProbeForRead(Source + index, chunkBytes, sizeof(CHAR));
            while (chunkBytes > 0) {
                character = Source[index];
                if (character == '\0') {
                    Destination[index] = L'\0';
                    return STATUS_SUCCESS;
                }

                Destination[index] = (WCHAR)(UCHAR)character;
                index += 1;
                chunkBytes -= 1;
            }
        }
        Destination[index] = L'\0';
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        Destination[0] = L'\0';
        return GetExceptionCode();
    }

    return (Destination[0] != L'\0') ? STATUS_SUCCESS : STATUS_NOT_FOUND;
}

/* Forward declaration for PsGetProcessImagePath (available Win10+) */
extern PCHAR PsGetProcessImageFileName(_In_ PEPROCESS Process);
extern PVOID PsGetProcessPeb(_In_ PEPROCESS Process);
extern PVOID PsGetProcessWow64Process(_In_ PEPROCESS Process);

NTSTATUS
SysmonQueryPrimaryTokenUserSidForProcessObject(
    _In_ PEPROCESS Process,
    _Out_writes_(UserSidChars) PWCHAR UserSid,
    _In_ ULONG UserSidChars)
{
    NTSTATUS status;
    PACCESS_TOKEN primaryToken = NULL;
    PTOKEN_USER tokenUser = NULL;
    UNICODE_STRING sidString;

    if (Process == NULL || UserSid == NULL || UserSidChars == 0) {
        return STATUS_INVALID_PARAMETER;
    }

    UserSid[0] = L'\0';
    primaryToken = PsReferencePrimaryToken(Process);
    if (primaryToken == NULL) {
        return STATUS_NOT_FOUND;
    }

    status = SeQueryInformationToken(
        primaryToken,
        TokenUser,
        (PVOID *)&tokenUser);
    if (NT_SUCCESS(status) &&
        tokenUser != NULL &&
        tokenUser->User.Sid != NULL) {
        RtlInitUnicodeString(&sidString, NULL);
        status = RtlConvertSidToUnicodeString(
            &sidString,
            tokenUser->User.Sid,
            TRUE);
        if (NT_SUCCESS(status) && sidString.Buffer != NULL) {
            ULONG copyLen = sidString.Length / sizeof(WCHAR);

            if (copyLen >= UserSidChars) {
                copyLen = UserSidChars - 1;
            }

            RtlCopyMemory(UserSid, sidString.Buffer, copyLen * sizeof(WCHAR));
            UserSid[copyLen] = L'\0';
            RtlFreeUnicodeString(&sidString);
        }
    }

    if (tokenUser != NULL) {
        ExFreePool(tokenUser);
    }

    PsDereferencePrimaryToken(primaryToken);
    return status;
}

static LONGLONG
SysmonQueryProcessCreateTime(_In_ HANDLE ProcessHandle)
{
    KERNEL_USER_TIMES times;
    ULONG returnLength = 0;
    NTSTATUS status;

    RtlZeroMemory(&times, sizeof(times));
    status = ZwQueryInformationProcess(
        ProcessHandle,
        ProcessTimes,
        &times,
        sizeof(times),
        &returnLength);
    if (NT_SUCCESS(status)) {
        return times.CreateTime.QuadPart;
    }

    return 0;
}

static VOID
SysmonFormatLogonGuid(
    _In_ ULONGLONG LogonId,
    _Out_writes_(SYSMON_MAX_GUID_STRING) WCHAR *GuidString)
{
    static const WCHAR templateGuid[] = L"{00000000-0000-0000-0000-000000000000}";
    ULONG index;

    RtlCopyMemory(GuidString, templateGuid, sizeof(templateGuid));

    for (index = 0; index < 4; index++) {
        ULONG shift = (3 - index) * 4;
        GuidString[20 + index] = L"0123456789abcdef"[(LogonId >> (48 + shift)) & 0x0F];
    }

    for (index = 0; index < 12; index++) {
        ULONG shift = (11 - index) * 4;
        GuidString[25 + index] = L"0123456789abcdef"[(LogonId >> shift) & 0x0F];
    }
}

/*
 * Generate deterministic GUID string from PID and creation time.
 * Format: {xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx}
 * Uses MD5 hash of (PID + CreateTime) as the GUID source.
 */
VOID
SysmonGenerateProcessGuid(
    _In_ ULONG ProcessId,
    _In_ LONGLONG CreateTime,
    _Out_writes_(40) WCHAR *GuidString)
{
    UCHAR digest[16];
    UCHAR src[12];
    ULONG i;
    NTSTATUS status;

    /* Combine PID + CreateTime as hash input */
    *(ULONG *)src = ProcessId;
    *(LONGLONG *)(src + 4) = CreateTime;

    status = SysmonComputeMd5Buffer(src, sizeof(src), digest);
    if (!NT_SUCCESS(status)) {
        RtlZeroMemory(digest, sizeof(digest));
    }

    /* Format as GUID: {xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx} */
    GuidString[0] = L'{';
    for (i = 0; i < 4; i++) {
        GuidString[1 + i * 2]     = L"0123456789abcdef"[(digest[i] >> 4) & 0x0F];
        GuidString[1 + i * 2 + 1] = L"0123456789abcdef"[digest[i] & 0x0F];
    }
    GuidString[9] = L'-';
    for (i = 0; i < 2; i++) {
        GuidString[10 + i * 2]     = L"0123456789abcdef"[(digest[4+i] >> 4) & 0x0F];
        GuidString[10 + i * 2 + 1] = L"0123456789abcdef"[digest[4+i] & 0x0F];
    }
    GuidString[14] = L'-';
    for (i = 0; i < 2; i++) {
        GuidString[15 + i * 2]     = L"0123456789abcdef"[(digest[6+i] >> 4) & 0x0F];
        GuidString[15 + i * 2 + 1] = L"0123456789abcdef"[digest[6+i] & 0x0F];
    }
    GuidString[19] = L'-';
    for (i = 0; i < 2; i++) {
        GuidString[20 + i * 2]     = L"0123456789abcdef"[(digest[8+i] >> 4) & 0x0F];
        GuidString[20 + i * 2 + 1] = L"0123456789abcdef"[digest[8+i] & 0x0F];
    }
    GuidString[24] = L'-';
    for (i = 0; i < 6; i++) {
        GuidString[25 + i * 2]     = L"0123456789abcdef"[(digest[10+i] >> 4) & 0x0F];
        GuidString[25 + i * 2 + 1] = L"0123456789abcdef"[digest[10+i] & 0x0F];
    }
    GuidString[37] = L'}';
    GuidString[38] = L'\0';
}

/*
 * Query process token information: SID, integrity level, elevation.
 */
NTSTATUS
SysmonQueryProcessTokenInfo(
    _In_ HANDLE ProcessHandle,
    _Out_ PSYSMON_PROCESS_INFO Info)
{
    NTSTATUS status;
    HANDLE tokenHandle = NULL;
    ULONG returnLength;
    PTOKEN_USER tokenUser = NULL;
    PTOKEN_MANDATORY_LABEL tokenLabel = NULL;
    UNICODE_STRING sidString;
    ULONG isAppContainer = 0;

    /* Open process token */
    status = ZwOpenProcessToken(ProcessHandle, TOKEN_QUERY, &tokenHandle);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    returnLength = 0;
    status = ZwQueryInformationToken(tokenHandle, TokenStatistics, NULL, 0, &returnLength);
    if (status == STATUS_BUFFER_TOO_SMALL) {
        PTOKEN_STATISTICS tokenStats = (PTOKEN_STATISTICS)SysmonAllocatePool(returnLength);
        if (tokenStats != NULL) {
            status = ZwQueryInformationToken(tokenHandle, TokenStatistics,
                tokenStats, returnLength, &returnLength);
            if (NT_SUCCESS(status)) {
                Info->LogonId =
                    ((ULONGLONG)(ULONG)tokenStats->AuthenticationId.HighPart << 32) |
                    tokenStats->AuthenticationId.LowPart;
                SysmonFormatLogonGuid(Info->LogonId, Info->LogonGuid);
            }
            SysmonFreePool(tokenStats);
        }
    }

    /* Query user SID */
    status = ZwQueryInformationToken(tokenHandle, TokenUser, NULL, 0, &returnLength);
    if (status == STATUS_BUFFER_TOO_SMALL) {
        tokenUser = (PTOKEN_USER)SysmonAllocatePool(returnLength);
        if (tokenUser != NULL) {
            status = ZwQueryInformationToken(tokenHandle, TokenUser,
                tokenUser, returnLength, &returnLength);
            if (NT_SUCCESS(status)) {
                RtlInitUnicodeString(&sidString, NULL);
                status = RtlConvertSidToUnicodeString(&sidString, tokenUser->User.Sid, TRUE);
                if (NT_SUCCESS(status) && sidString.Buffer != NULL) {
                    if (sidString.Length > 0) {
                        ULONG copyLen = sidString.Length / sizeof(WCHAR);
                        if (copyLen >= SYSMON_MAX_SID_STRING) copyLen = SYSMON_MAX_SID_STRING - 1;
                        RtlCopyMemory(Info->UserSid, sidString.Buffer, copyLen * sizeof(WCHAR));
                        Info->UserSid[copyLen] = L'\0';
                    }
                    RtlFreeUnicodeString(&sidString);
                }
            }
            SysmonFreePool(tokenUser);
        }
    }

    /* Query integrity level */
    status = ZwQueryInformationToken(tokenHandle, TokenIntegrityLevel, NULL, 0, &returnLength);
    if (status == STATUS_BUFFER_TOO_SMALL) {
        tokenLabel = (PTOKEN_MANDATORY_LABEL)SysmonAllocatePool(returnLength);
        if (tokenLabel != NULL) {
            status = ZwQueryInformationToken(tokenHandle, TokenIntegrityLevel,
                tokenLabel, returnLength, &returnLength);
            if (NT_SUCCESS(status)) {
                ULONG integrityLevel = *RtlSubAuthoritySid(
                    tokenLabel->Label.Sid,
                    *RtlSubAuthorityCountSid(tokenLabel->Label.Sid) - 1);

                if (integrityLevel >= SECURITY_MANDATORY_SYSTEM_RID) {
                    RtlCopyMemory(Info->IntegrityLevel, L"System", 14);
                } else if (integrityLevel >= SECURITY_MANDATORY_HIGH_RID) {
                    RtlCopyMemory(Info->IntegrityLevel, L"High", 10);
                } else if (integrityLevel >= SECURITY_MANDATORY_MEDIUM_RID) {
                    RtlCopyMemory(Info->IntegrityLevel, L"Medium", 14);
                } else if (integrityLevel >= SECURITY_MANDATORY_LOW_RID) {
                    RtlCopyMemory(Info->IntegrityLevel, L"Low", 8);
                } else {
                    RtlCopyMemory(Info->IntegrityLevel, L"Untrusted", 20);
                }
            }
            SysmonFreePool(tokenLabel);
        }
    }

    returnLength = 0;
    status = ZwQueryInformationToken(tokenHandle, TokenIsAppContainer,
        &isAppContainer, sizeof(isAppContainer), &returnLength);
    if (NT_SUCCESS(status) && isAppContainer != 0) {
        RtlCopyMemory(Info->IntegrityLevel, L"AppContainer", sizeof(L"AppContainer"));
    }

    /* Query elevation */
    {
        TOKEN_ELEVATION elevation = { 0 };
        returnLength = 0;
        status = ZwQueryInformationToken(tokenHandle, TokenElevation,
            &elevation, sizeof(elevation), &returnLength);
        if (NT_SUCCESS(status)) {
            Info->IsElevated = (elevation.TokenIsElevated != 0);
        }
    }

    /* Query elevation type */
    {
        TOKEN_ELEVATION_TYPE elevationType = TokenElevationTypeDefault;
        returnLength = 0;
        status = ZwQueryInformationToken(tokenHandle, TokenElevationType,
            &elevationType, sizeof(elevationType), &returnLength);
        if (NT_SUCCESS(status)) {
            Info->ElevationType = elevationType;
        }
    }

    ZwClose(tokenHandle);
    return STATUS_SUCCESS;
}

/*
 * Query process command line via ZwQueryInformationProcess.
 */
static NTSTATUS
SysmonQueryCommandLine(
    _In_ HANDLE ProcessHandle,
    _Out_writes_(MaxLen) WCHAR *CommandLine,
    _In_ ULONG MaxLen)
{
    NTSTATUS status;
    ULONG returnLength = 0;
    PUNICODE_STRING cmdLine = NULL;
    ULONG bufSize;

    /* First call to get required buffer size */
    status = ZwQueryInformationProcess(ProcessHandle,
        ProcessCommandLineInformation, NULL, 0, &returnLength);

    if (status != STATUS_BUFFER_TOO_SMALL && status != STATUS_INFO_LENGTH_MISMATCH) {
        return status;
    }

    bufSize = returnLength + sizeof(WCHAR);
    cmdLine = (PUNICODE_STRING)SysmonAllocatePool(bufSize);
    if (cmdLine == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    RtlZeroMemory(cmdLine, bufSize);
    status = ZwQueryInformationProcess(ProcessHandle,
        ProcessCommandLineInformation, cmdLine, bufSize, &returnLength);

    if (NT_SUCCESS(status) && cmdLine->Buffer != NULL && cmdLine->Length > 0) {
        ULONG copyLen = cmdLine->Length / sizeof(WCHAR);
        if (copyLen >= MaxLen) copyLen = MaxLen - 1;
        RtlCopyMemory(CommandLine, cmdLine->Buffer, copyLen * sizeof(WCHAR));
        CommandLine[copyLen] = L'\0';
    }

    SysmonFreePool(cmdLine);
    return status;
}

/*
 * Query current directory via ZwQueryInformationProcess.
 */
static NTSTATUS
SysmonQueryCurrentDirectory(
    _In_ HANDLE ProcessHandle,
    _In_ PEPROCESS ProcessObject,
    _Out_writes_(MaxLen) WCHAR *CurrentDir,
    _In_ ULONG MaxLen)
{
    KAPC_STATE apcState;
    PROCESS_BASIC_INFORMATION basicInfo = { 0 };
    ULONG returnLength = 0;
    PVOID wow64Peb = NULL;
    NTSTATUS status;
    CurrentDir[0] = L'\0';
    if (ProcessHandle == NULL || ProcessObject == NULL || MaxLen == 0) {
        return STATUS_INVALID_PARAMETER;
    }

    status = ZwQueryInformationProcess(
        ProcessHandle,
        ProcessBasicInformation,
        &basicInfo,
        sizeof(basicInfo),
        &returnLength);
    if (!NT_SUCCESS(status) || basicInfo.PebBaseAddress == NULL) {
        return status;
    }

    (void)ZwQueryInformationProcess(
        ProcessHandle,
        ProcessWow64Information,
        &wow64Peb,
        sizeof(wow64Peb),
        &returnLength);

    KeStackAttachProcess(ProcessObject, &apcState);
    __try {
        if (wow64Peb != NULL) {
            const SYSMON_PEB32 *peb32 = (const SYSMON_PEB32 *)(ULONG_PTR)wow64Peb;
            const SYSMON_RTL_USER_PROCESS_PARAMETERS32 *params32;

            ProbeForRead(peb32, sizeof(*peb32), sizeof(ULONG));
            if (peb32->ProcessParameters != 0) {
                params32 = (const SYSMON_RTL_USER_PROCESS_PARAMETERS32 *)(ULONG_PTR)peb32->ProcessParameters;
                ProbeForRead(params32, sizeof(*params32), sizeof(ULONG));
                status = SysmonCopyAttachedUnicodeString32(
                    &params32->CurrentDirectory.DosPath,
                    CurrentDir,
                    MaxLen);
                if (NT_SUCCESS(status) && CurrentDir[0] != L'\0') {
                    KeUnstackDetachProcess(&apcState);
                    return STATUS_SUCCESS;
                }
            }
        }

        {
            const SYSMON_PEB64 *peb = (const SYSMON_PEB64 *)basicInfo.PebBaseAddress;
            const SYSMON_RTL_USER_PROCESS_PARAMETERS64 *params64;

            ProbeForRead(peb, sizeof(*peb), sizeof(PVOID));
            if (peb->ProcessParameters == NULL) {
                status = STATUS_NOT_FOUND;
            } else {
                params64 = (const SYSMON_RTL_USER_PROCESS_PARAMETERS64 *)peb->ProcessParameters;
                ProbeForRead(params64, sizeof(*params64), sizeof(ULONG));
                status = SysmonCopyAttachedUnicodeString(
                    &params64->CurrentDirectory.DosPath,
                    CurrentDir,
                    MaxLen);
            }
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        status = GetExceptionCode();
        CurrentDir[0] = L'\0';
    }
    KeUnstackDetachProcess(&apcState);

    return status;
}

static NTSTATUS
SysmonResolveUserAddressAttached64(
    _In_ const SYSMON_PEB64 *Peb,
    _In_ ULONGLONG Address,
    _Out_writes_(ModulePathChars) WCHAR *ModulePath,
    _In_ ULONG ModulePathChars,
    _Out_opt_ PULONGLONG ModuleBase,
    _Out_opt_ PULONG ModuleSize)
{
    const SYSMON_PEB_LDR_DATA64 *ldr;
    ULONGLONG listHead;
    ULONGLONG current;
    ULONG guard;

    if (ModulePath == NULL || ModulePathChars == 0) {
        return STATUS_INVALID_PARAMETER;
    }

    ModulePath[0] = L'\0';
    if (ModuleBase != NULL) {
        *ModuleBase = 0;
    }
    if (ModuleSize != NULL) {
        *ModuleSize = 0;
    }

    __try {
        ProbeForRead(Peb, sizeof(*Peb), sizeof(PVOID));
        if (Peb->Ldr == NULL) {
            return STATUS_NOT_FOUND;
        }

        ldr = (const SYSMON_PEB_LDR_DATA64 *)Peb->Ldr;
        ProbeForRead(ldr, sizeof(*ldr), sizeof(PVOID));

        listHead = (ULONGLONG)(ULONG_PTR)&ldr->InMemoryOrderModuleList;
        current = ldr->InMemoryOrderModuleList.Flink;
        for (guard = 0; current != 0 && current != listHead && guard < 0x200; guard++) {
            const SYSMON_LDR_DATA_TABLE_ENTRY64 *entry;
            ULONGLONG base;
            ULONG size;

            entry = CONTAINING_RECORD(
                (const SYSMON_LIST_ENTRY64 *)(ULONG_PTR)current,
                SYSMON_LDR_DATA_TABLE_ENTRY64,
                InMemoryOrderLinks);
            ProbeForRead(entry, sizeof(*entry), sizeof(PVOID));

            base = entry->DllBase;
            size = entry->SizeOfImage;
            if (size != 0 &&
                Address > base &&
                Address < base + size) {
                NTSTATUS status;

                status = SysmonCopyAttachedUnicodeString(
                    &entry->FullDllName,
                    ModulePath,
                    ModulePathChars);
                if (NT_SUCCESS(status)) {
                    if (ModuleBase != NULL) {
                        *ModuleBase = base;
                    }
                    if (ModuleSize != NULL) {
                        *ModuleSize = size;
                    }
                    return STATUS_SUCCESS;
                }
            }

            current = entry->InMemoryOrderLinks.Flink;
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        ModulePath[0] = L'\0';
        return GetExceptionCode();
    }

    return STATUS_NOT_FOUND;
}

static VOID
SysmonAppendPointerTraceString(
    _Inout_ PWCHAR *Cursor,
    _Inout_ PULONG Remaining,
    _In_ PVOID Address)
{
    ULONGLONG value;
    ULONG index;

    if (Cursor == NULL || *Cursor == NULL || Remaining == NULL || *Remaining < 20) {
        return;
    }

    value = (ULONGLONG)(ULONG_PTR)Address;
    (*Cursor)[0] = L'0';
    (*Cursor)[1] = L'x';
    for (index = 0; index < 16; index++) {
        ULONG shift = (15 - index) * 4;
        (*Cursor)[2 + index] = L"0123456789abcdef"[(value >> shift) & 0x0F];
    }
    (*Cursor)[18] = L'|';
    (*Cursor)[19] = L'\0';
    *Cursor += 19;
    *Remaining -= 19;
}

static VOID
SysmonAppendResolvedTraceString(
    _Inout_ PWCHAR *Cursor,
    _Inout_ PULONG Remaining,
    _In_ LPCWSTR ModulePath,
    _In_ ULONGLONG ModuleBase,
    _In_ ULONGLONG Address)
{
    int written;

    if (Cursor == NULL || *Cursor == NULL || Remaining == NULL || *Remaining == 0) {
        return;
    }

    written = _snwprintf_s(
        *Cursor,
        *Remaining,
        _TRUNCATE,
        L"%ls+%llx|",
        ModulePath,
        Address - ModuleBase);
    if (written > 0) {
        *Cursor += written;
        *Remaining -= min(*Remaining, (ULONG)written);
    }
}

static NTSTATUS
SysmonResolveUserAddressAttached32(
    _In_ const SYSMON_PEB32 *Peb32,
    _In_ ULONGLONG Address,
    _Out_writes_(ModulePathChars) WCHAR *ModulePath,
    _In_ ULONG ModulePathChars,
    _Out_opt_ PULONGLONG ModuleBase,
    _Out_opt_ PULONG ModuleSize)
{
    const SYSMON_PEB_LDR_DATA32 *ldr;
    ULONG listHead;
    ULONG current;
    ULONG guard;

    if (ModulePath == NULL || ModulePathChars == 0) {
        return STATUS_INVALID_PARAMETER;
    }

    ModulePath[0] = L'\0';
    if (ModuleBase != NULL) {
        *ModuleBase = 0;
    }
    if (ModuleSize != NULL) {
        *ModuleSize = 0;
    }

    __try {
        ProbeForRead(Peb32, sizeof(*Peb32), sizeof(ULONG));
        if (Peb32->Ldr == 0) {
            return STATUS_NOT_FOUND;
        }

        ldr = (const SYSMON_PEB_LDR_DATA32 *)(ULONG_PTR)Peb32->Ldr;
        ProbeForRead(ldr, sizeof(*ldr), sizeof(ULONG));

        listHead = (ULONG)(ULONG_PTR)&ldr->InMemoryOrderModuleList;
        current = ldr->InMemoryOrderModuleList.Flink;
        for (guard = 0; current != 0 && current != listHead && guard < 0x200; guard++) {
            const SYSMON_LDR_DATA_TABLE_ENTRY32 *entry;
            ULONGLONG base;
            ULONG size;

            entry = CONTAINING_RECORD(
                (const SYSMON_LIST_ENTRY32 *)(ULONG_PTR)current,
                SYSMON_LDR_DATA_TABLE_ENTRY32,
                InMemoryOrderLinks);
            ProbeForRead(entry, sizeof(*entry), sizeof(ULONG));

            base = entry->DllBase;
            size = entry->SizeOfImage;
            if (size != 0 &&
                Address > base &&
                Address < base + size) {
                NTSTATUS status;

                status = SysmonCopyAttachedUnicodeString32(
                    &entry->FullDllName,
                    ModulePath,
                    ModulePathChars);
                if (NT_SUCCESS(status)) {
                    if (ModuleBase != NULL) {
                        *ModuleBase = base;
                    }
                    if (ModuleSize != NULL) {
                        *ModuleSize = size;
                    }
                    return STATUS_SUCCESS;
                }
            }

            current = entry->InMemoryOrderLinks.Flink;
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        ModulePath[0] = L'\0';
        return GetExceptionCode();
    }

    return STATUS_NOT_FOUND;
}

static NTSTATUS
SysmonResolveUserExportNameAttached(
    _In_ ULONGLONG ModuleBase,
    _In_ ULONG ModuleSize,
    _In_ ULONGLONG Address,
    _Out_writes_(FunctionNameChars) WCHAR *FunctionName,
    _In_ ULONG FunctionNameChars)
{
    PIMAGE_DOS_HEADER dosHeader;
    PIMAGE_NT_HEADERS32 nt32;
    PIMAGE_NT_HEADERS64 nt64;
    PIMAGE_EXPORT_DIRECTORY exportDirectory;
    ULONG exportRva;
    ULONG exportSize;
    ULONG targetRva;
    PULONG functionTable;
    ULONG index;

    if (FunctionName == NULL || FunctionNameChars == 0) {
        return STATUS_INVALID_PARAMETER;
    }

    FunctionName[0] = L'\0';
    if (Address < ModuleBase || Address - ModuleBase > MAXULONG) {
        return STATUS_NOT_FOUND;
    }

    targetRva = (ULONG)(Address - ModuleBase);

    __try {
        dosHeader = (PIMAGE_DOS_HEADER)(ULONG_PTR)ModuleBase;
        ProbeForRead(dosHeader, sizeof(*dosHeader), sizeof(USHORT));
        if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
            return STATUS_NOT_FOUND;
        }

        nt64 = (PIMAGE_NT_HEADERS64)(ULONG_PTR)(ModuleBase + dosHeader->e_lfanew);
        ProbeForRead(nt64, sizeof(*nt64), sizeof(ULONG));
        if (nt64->Signature != IMAGE_NT_SIGNATURE) {
            return STATUS_NOT_FOUND;
        }

        exportRva = 0;
        exportSize = 0;
        if (nt64->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
            exportRva = nt64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
            exportSize = nt64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;
        } else if (nt64->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC) {
            nt32 = (PIMAGE_NT_HEADERS32)nt64;
            ProbeForRead(nt32, sizeof(*nt32), sizeof(ULONG));
            exportRva = nt32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
            exportSize = nt32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;
        }

        if (exportRva == 0 || exportSize < sizeof(IMAGE_EXPORT_DIRECTORY)) {
            return STATUS_NOT_FOUND;
        }

        exportDirectory = (PIMAGE_EXPORT_DIRECTORY)(ULONG_PTR)(ModuleBase + exportRva);
        ProbeForRead(exportDirectory, sizeof(*exportDirectory), sizeof(ULONG));
        if (exportDirectory->AddressOfFunctions == 0 || exportDirectory->NumberOfFunctions == 0) {
            return STATUS_NOT_FOUND;
        }

        functionTable = (PULONG)(ULONG_PTR)(ModuleBase + exportDirectory->AddressOfFunctions);
        ProbeForRead(functionTable, exportDirectory->NumberOfFunctions * sizeof(ULONG), sizeof(ULONG));

        if (exportDirectory->AddressOfNames != 0 &&
            exportDirectory->AddressOfNameOrdinals != 0 &&
            exportDirectory->NumberOfNames != 0) {
            PULONG nameTable;
            PUSHORT ordinalTable;

            nameTable = (PULONG)(ULONG_PTR)(ModuleBase + exportDirectory->AddressOfNames);
            ordinalTable = (PUSHORT)(ULONG_PTR)(ModuleBase + exportDirectory->AddressOfNameOrdinals);
            ProbeForRead(nameTable, exportDirectory->NumberOfNames * sizeof(ULONG), sizeof(ULONG));
            ProbeForRead(ordinalTable, exportDirectory->NumberOfNames * sizeof(USHORT), sizeof(USHORT));

            for (index = 0; index < exportDirectory->NumberOfNames; index++) {
                USHORT ordinalIndex;

                ordinalIndex = ordinalTable[index];
                if (ordinalIndex >= exportDirectory->NumberOfFunctions) {
                    continue;
                }

                if (functionTable[ordinalIndex] == targetRva) {
                    return SysmonCopyAttachedAnsiString(
                        (PCCHAR)(ULONG_PTR)(ModuleBase + nameTable[index]),
                        FunctionName,
                        FunctionNameChars);
                }
            }
        }

        for (index = 0; index < exportDirectory->NumberOfFunctions; index++) {
            if (functionTable[index] == targetRva) {
                _snwprintf_s(
                    FunctionName,
                    FunctionNameChars,
                    _TRUNCATE,
                    L"Ordinal%lu",
                    exportDirectory->Base + index);
                return STATUS_SUCCESS;
            }
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        FunctionName[0] = L'\0';
        return GetExceptionCode();
    }

    UNREFERENCED_PARAMETER(ModuleSize);
    return STATUS_NOT_FOUND;
}

NTSTATUS
SysmonResolveUserStartContextForProcessObject(
    _In_ PEPROCESS ProcessObject,
    _In_ ULONGLONG Address,
    _Out_writes_(ModulePathChars) PWCHAR ModulePath,
    _In_ ULONG ModulePathChars,
    _Out_writes_(FunctionNameChars) PWCHAR FunctionName,
    _In_ ULONG FunctionNameChars)
{
    KAPC_STATE apcState;
    PVOID peb;
    const SYSMON_PEB32 *wow64Peb;
    ULONGLONG moduleBase;
    ULONG moduleSize;
    NTSTATUS status;

    if (ProcessObject == NULL ||
        ModulePath == NULL ||
        ModulePathChars == 0 ||
        FunctionName == NULL ||
        FunctionNameChars == 0) {
        return STATUS_INVALID_PARAMETER;
    }

    ModulePath[0] = L'\0';
    FunctionName[0] = L'\0';
    moduleBase = 0;
    moduleSize = 0;
    peb = PsGetProcessPeb(ProcessObject);
    wow64Peb = (const SYSMON_PEB32 *)(ULONG_PTR)PsGetProcessWow64Process(ProcessObject);
    status = STATUS_NOT_FOUND;

    KeStackAttachProcess(ProcessObject, &apcState);
    __try {
        if (peb != NULL) {
            status = SysmonResolveUserAddressAttached64(
                (const SYSMON_PEB64 *)peb,
                Address,
                ModulePath,
                ModulePathChars,
                &moduleBase,
                &moduleSize);
            if (NT_SUCCESS(status)) {
                (void)SysmonResolveUserExportNameAttached(
                    moduleBase,
                    moduleSize,
                    Address,
                    FunctionName,
                    FunctionNameChars);
                status = STATUS_SUCCESS;
            }
        }

        if (!NT_SUCCESS(status)) {
            if (wow64Peb != NULL &&
                (PVOID)(ULONG_PTR)wow64Peb <= MmHighestUserAddress) {
                status = SysmonResolveUserAddressAttached32(
                    wow64Peb,
                    Address,
                    ModulePath,
                    ModulePathChars,
                    &moduleBase,
                    &moduleSize);
                if (NT_SUCCESS(status)) {
                    (void)SysmonResolveUserExportNameAttached(
                        moduleBase,
                        moduleSize,
                        Address,
                        FunctionName,
                        FunctionNameChars);
                    status = STATUS_SUCCESS;
                }
            }
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        ModulePath[0] = L'\0';
        FunctionName[0] = L'\0';
        status = GetExceptionCode();
    }
    KeUnstackDetachProcess(&apcState);

    return status;
}

NTSTATUS
SysmonResolveUserAddress(
    _In_ HANDLE ProcessId,
    _In_ ULONGLONG Address,
    _Out_writes_(ModulePathChars) PWCHAR ModulePath,
    _In_ ULONG ModulePathChars,
    _Out_opt_ PULONGLONG ModuleBase,
    _Out_opt_ PULONG ModuleSize)
{
    KAPC_STATE apcState;
    PROCESS_BASIC_INFORMATION basicInfo;
    PEPROCESS process = NULL;
    HANDLE processHandle = NULL;
    OBJECT_ATTRIBUTES objectAttributes;
    CLIENT_ID clientId;
    PVOID wow64Peb = NULL;
    ULONG returnLength = 0;
    NTSTATUS status;

    if (ModulePath == NULL || ModulePathChars == 0) {
        return STATUS_INVALID_PARAMETER;
    }

    ModulePath[0] = L'\0';
    if (ModuleBase != NULL) {
        *ModuleBase = 0;
    }
    if (ModuleSize != NULL) {
        *ModuleSize = 0;
    }

    if ((PVOID)(ULONG_PTR)Address > MmHighestUserAddress) {
        return STATUS_NOT_FOUND;
    }

    RtlZeroMemory(&basicInfo, sizeof(basicInfo));

    status = PsLookupProcessByProcessId(ProcessId, &process);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    InitializeObjectAttributes(&objectAttributes, NULL, OBJ_KERNEL_HANDLE, NULL, NULL);
    clientId.UniqueProcess = ProcessId;
    clientId.UniqueThread = NULL;

    status = ZwOpenProcess(
        &processHandle,
        PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,
        &objectAttributes,
        &clientId);
    if (!NT_SUCCESS(status)) {
        status = ZwOpenProcess(
            &processHandle,
            PROCESS_QUERY_LIMITED_INFORMATION,
            &objectAttributes,
            &clientId);
        if (!NT_SUCCESS(status)) {
            ObDereferenceObject(process);
            return status;
        }
    }

    status = ZwQueryInformationProcess(
        processHandle,
        ProcessBasicInformation,
        &basicInfo,
        sizeof(basicInfo),
        &returnLength);
    if (!NT_SUCCESS(status) || basicInfo.PebBaseAddress == NULL) {
        ZwClose(processHandle);
        ObDereferenceObject(process);
        return NT_SUCCESS(status) ? STATUS_NOT_FOUND : status;
    }

    (void)ZwQueryInformationProcess(
        processHandle,
        ProcessWow64Information,
        &wow64Peb,
        sizeof(wow64Peb),
        &returnLength);

    KeStackAttachProcess(process, &apcState);
    __try {
        if (wow64Peb != NULL) {
            status = SysmonResolveUserAddressAttached32(
                (const SYSMON_PEB32 *)(ULONG_PTR)wow64Peb,
                Address,
                ModulePath,
                ModulePathChars,
                ModuleBase,
                ModuleSize);
        } else {
            status = SysmonResolveUserAddressAttached64(
                (const SYSMON_PEB64 *)basicInfo.PebBaseAddress,
                Address,
                ModulePath,
                ModulePathChars,
                ModuleBase,
                ModuleSize);
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        status = GetExceptionCode();
        ModulePath[0] = L'\0';
    }
    KeUnstackDetachProcess(&apcState);

    ZwClose(processHandle);
    ObDereferenceObject(process);
    return status;
}

NTSTATUS
SysmonFormatCallTraceForProcess(
    _In_ HANDLE ProcessId,
    _In_reads_(FrameCount) PVOID *Frames,
    _In_ USHORT FrameCount,
    _Out_writes_(BufferChars) PWCHAR Buffer,
    _In_ ULONG BufferChars)
{
    KAPC_STATE apcState;
    PROCESS_BASIC_INFORMATION basicInfo;
    PEPROCESS process = NULL;
    HANDLE processHandle = NULL;
    OBJECT_ATTRIBUTES objectAttributes;
    CLIENT_ID clientId;
    PVOID wow64Peb = NULL;
    ULONG returnLength = 0;
    ULONG index;
    PWCHAR cursor;
    ULONG remaining;
    NTSTATUS status;

    if (Buffer == NULL || BufferChars == 0) {
        return STATUS_INVALID_PARAMETER;
    }

    Buffer[0] = L'\0';
    if (Frames == NULL || FrameCount == 0) {
        return STATUS_SUCCESS;
    }

    RtlZeroMemory(&basicInfo, sizeof(basicInfo));

    status = PsLookupProcessByProcessId(ProcessId, &process);
    if (!NT_SUCCESS(status)) {
        for (index = 0; index < FrameCount && index < 24; index++) {
            cursor = Buffer + wcslen(Buffer);
            remaining = (ULONG)(BufferChars - wcslen(Buffer));
            if (remaining <= 20) {
                break;
            }
            SysmonAppendPointerTraceString(&cursor, &remaining, Frames[index]);
        }
        if (Buffer[0] != L'\0') {
            SIZE_T length = wcslen(Buffer);
            if (length != 0 && Buffer[length - 1] == L'|') {
                Buffer[length - 1] = L'\0';
            }
        }
        return status;
    }

    InitializeObjectAttributes(&objectAttributes, NULL, OBJ_KERNEL_HANDLE, NULL, NULL);
    clientId.UniqueProcess = ProcessId;
    clientId.UniqueThread = NULL;

    status = ZwOpenProcess(
        &processHandle,
        PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,
        &objectAttributes,
        &clientId);
    if (!NT_SUCCESS(status)) {
        status = ZwOpenProcess(
            &processHandle,
            PROCESS_QUERY_LIMITED_INFORMATION,
            &objectAttributes,
            &clientId);
        if (!NT_SUCCESS(status)) {
            ObDereferenceObject(process);
            return status;
        }
    }

    status = ZwQueryInformationProcess(
        processHandle,
        ProcessBasicInformation,
        &basicInfo,
        sizeof(basicInfo),
        &returnLength);
    if (!NT_SUCCESS(status) || basicInfo.PebBaseAddress == NULL) {
        ZwClose(processHandle);
        ObDereferenceObject(process);
        return NT_SUCCESS(status) ? STATUS_NOT_FOUND : status;
    }

    (void)ZwQueryInformationProcess(
        processHandle,
        ProcessWow64Information,
        &wow64Peb,
        sizeof(wow64Peb),
        &returnLength);

    cursor = Buffer;
    remaining = BufferChars;

    KeStackAttachProcess(process, &apcState);
    __try {
        for (index = 0; index < FrameCount && index < 24 && remaining > 20; index++) {
            ULONGLONG addressValue;
            WCHAR modulePath[SYSMON_MAX_PATH];
            ULONGLONG moduleBase;
            ULONG moduleSize;
            NTSTATUS resolveStatus;

            addressValue = (ULONGLONG)(ULONG_PTR)Frames[index];
            modulePath[0] = L'\0';
            moduleBase = 0;
            moduleSize = 0;

            if ((PVOID)(ULONG_PTR)addressValue > MmHighestUserAddress) {
                SysmonAppendPointerTraceString(&cursor, &remaining, Frames[index]);
                continue;
            }

            resolveStatus = SysmonResolveUserAddressAttached64(
                (const SYSMON_PEB64 *)basicInfo.PebBaseAddress,
                addressValue,
                modulePath,
                RTL_NUMBER_OF(modulePath),
                &moduleBase,
                &moduleSize);
            if (!NT_SUCCESS(resolveStatus) &&
                wow64Peb != NULL) {
                resolveStatus = SysmonResolveUserAddressAttached32(
                    (const SYSMON_PEB32 *)(ULONG_PTR)wow64Peb,
                    addressValue,
                    modulePath,
                    RTL_NUMBER_OF(modulePath),
                    &moduleBase,
                    &moduleSize);
            }

            if (NT_SUCCESS(resolveStatus) &&
                modulePath[0] != L'\0' &&
                addressValue >= moduleBase) {
                SysmonAppendResolvedTraceString(
                    &cursor,
                    &remaining,
                    modulePath,
                    moduleBase,
                    addressValue);
            } else {
                SysmonAppendPointerTraceString(&cursor, &remaining, Frames[index]);
            }
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        status = GetExceptionCode();
        Buffer[0] = L'\0';
    }
    KeUnstackDetachProcess(&apcState);

    if (status == STATUS_SUCCESS && cursor != Buffer && cursor[-1] == L'|') {
        cursor[-1] = L'\0';
    }

    ZwClose(processHandle);
    ObDereferenceObject(process);
    return status;
}

NTSTATUS
SysmonResolveUserExportName(
    _In_ HANDLE ProcessId,
    _In_ ULONGLONG Address,
    _Out_writes_(FunctionNameChars) PWCHAR FunctionName,
    _In_ ULONG FunctionNameChars)
{
    WCHAR modulePath[SYSMON_MAX_PATH];
    ULONGLONG moduleBase;
    ULONG moduleSize;
    KAPC_STATE apcState;
    PROCESS_BASIC_INFORMATION basicInfo;
    PEPROCESS process = NULL;
    HANDLE processHandle = NULL;
    OBJECT_ATTRIBUTES objectAttributes;
    CLIENT_ID clientId;
    PVOID wow64Peb = NULL;
    ULONG returnLength = 0;
    NTSTATUS status;

    if (FunctionName == NULL || FunctionNameChars == 0) {
        return STATUS_INVALID_PARAMETER;
    }

    FunctionName[0] = L'\0';
    modulePath[0] = L'\0';
    moduleBase = 0;
    moduleSize = 0;

    status = SysmonResolveUserAddress(
        ProcessId,
        Address,
        modulePath,
        RTL_NUMBER_OF(modulePath),
        &moduleBase,
        &moduleSize);
    if (!NT_SUCCESS(status) || moduleBase == 0 || moduleSize == 0) {
        return status;
    }

    status = PsLookupProcessByProcessId(ProcessId, &process);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    InitializeObjectAttributes(&objectAttributes, NULL, OBJ_KERNEL_HANDLE, NULL, NULL);
    clientId.UniqueProcess = ProcessId;
    clientId.UniqueThread = NULL;

    status = ZwOpenProcess(
        &processHandle,
        PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,
        &objectAttributes,
        &clientId);
    if (!NT_SUCCESS(status)) {
        status = ZwOpenProcess(
            &processHandle,
            PROCESS_QUERY_LIMITED_INFORMATION,
            &objectAttributes,
            &clientId);
        if (!NT_SUCCESS(status)) {
            ObDereferenceObject(process);
            return status;
        }
    }

    RtlZeroMemory(&basicInfo, sizeof(basicInfo));
    status = ZwQueryInformationProcess(
        processHandle,
        ProcessBasicInformation,
        &basicInfo,
        sizeof(basicInfo),
        &returnLength);
    if (!NT_SUCCESS(status) || basicInfo.PebBaseAddress == NULL) {
        ZwClose(processHandle);
        ObDereferenceObject(process);
        return NT_SUCCESS(status) ? STATUS_NOT_FOUND : status;
    }

    (void)ZwQueryInformationProcess(
        processHandle,
        ProcessWow64Information,
        &wow64Peb,
        sizeof(wow64Peb),
        &returnLength);

    KeStackAttachProcess(process, &apcState);
    status = SysmonResolveUserExportNameAttached(
        moduleBase,
        moduleSize,
        Address,
        FunctionName,
        FunctionNameChars);
    KeUnstackDetachProcess(&apcState);

    ZwClose(processHandle);
    ObDereferenceObject(process);
    UNREFERENCED_PARAMETER(wow64Peb);
    return status;
}

static NTSTATUS
SysmonCollectProcessInfoInternal(
    _In_ HANDLE ProcessId,
    _Out_ PSYSMON_PROCESS_INFO Info,
    _In_ BOOLEAN QueryCommandLine,
    _In_ BOOLEAN QueryCurrentDirectory,
    _In_ BOOLEAN QueryTokenInfo)
{
    NTSTATUS status;
    PEPROCESS process = NULL;
    HANDLE processHandle = NULL;
    OBJECT_ATTRIBUTES objAttr;
    CLIENT_ID clientId;
    PROCESS_BASIC_INFORMATION basicInfo = { 0 };
    ULONG returnLength = 0;

    RtlZeroMemory(Info, sizeof(SYSMON_PROCESS_INFO));
    Info->ProcessId = (ULONG)(ULONG_PTR)ProcessId;

    status = PsLookupProcessByProcessId(ProcessId, &process);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    InitializeObjectAttributes(&objAttr, NULL, OBJ_KERNEL_HANDLE, NULL, NULL);
    clientId.UniqueProcess = ProcessId;
    clientId.UniqueThread = NULL;

    status = ZwOpenProcess(&processHandle,
        PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,
        &objAttr, &clientId);
    if (!NT_SUCCESS(status)) {
        status = ZwOpenProcess(&processHandle,
            PROCESS_QUERY_LIMITED_INFORMATION,
            &objAttr, &clientId);
        if (!NT_SUCCESS(status)) {
            ObDereferenceObject(process);
            return status;
        }
    }

    status = ZwQueryInformationProcess(processHandle,
        ProcessBasicInformation, &basicInfo,
        sizeof(basicInfo), &returnLength);
    if (NT_SUCCESS(status)) {
        Info->ParentProcessId = (ULONG)(ULONG_PTR)basicInfo.InheritedFromUniqueProcessId;
    }

    Info->CreateTime = SysmonQueryProcessCreateTime(processHandle);
    if (Info->CreateTime == 0) {
        Info->CreateTime = SysmonGetCurrentTimestamp();
    }

    {
        SYSMON_PROCESS_SESSION_INFORMATION sessionInfo;
        ULONG sessRetLen = 0;

        RtlZeroMemory(&sessionInfo, sizeof(sessionInfo));
        if (NT_SUCCESS(ZwQueryInformationProcess(
                processHandle,
                ProcessSessionInformation,
                &sessionInfo,
                sizeof(sessionInfo),
                &sessRetLen))) {
            Info->SessionId = sessionInfo.SessionId;
        }
    }

    {
        ULONG pathLen = 0;

        status = ZwQueryInformationProcess(processHandle,
            ProcessImageFileName, NULL, 0, &pathLen);
        if (status == STATUS_BUFFER_TOO_SMALL || status == STATUS_INFO_LENGTH_MISMATCH) {
            PUNICODE_STRING imgPath = (PUNICODE_STRING)SysmonAllocatePool(pathLen + sizeof(WCHAR));
            if (imgPath != NULL) {
                RtlZeroMemory(imgPath, pathLen + sizeof(WCHAR));
                status = ZwQueryInformationProcess(processHandle,
                    ProcessImageFileName, imgPath, pathLen, &pathLen);
                if (NT_SUCCESS(status) && imgPath->Buffer != NULL) {
                    ULONG copyLen = imgPath->Length / sizeof(WCHAR);
                    if (copyLen >= SYSMON_MAX_PATH) copyLen = SYSMON_MAX_PATH - 1;
                    RtlCopyMemory(Info->ImagePath, imgPath->Buffer, copyLen * sizeof(WCHAR));
                    Info->ImagePath[copyLen] = L'\0';
                }
                SysmonFreePool(imgPath);
            }
        }
    }

    if (Info->ProcessId == 4) {
        RtlCopyMemory(Info->ImagePath, L"System", sizeof(L"System"));
    }

    if (QueryCommandLine) {
        SysmonQueryCommandLine(processHandle, Info->CommandLine, SYSMON_MAX_CMDLINE);
    }

    if (QueryCurrentDirectory) {
        (void)SysmonQueryCurrentDirectory(processHandle, process, Info->CurrentDirectory, SYSMON_MAX_PATH);
    }

    if (QueryTokenInfo) {
        SysmonQueryProcessTokenInfo(processHandle, Info);
        if (Info->UserSid[0] == L'\0') {
            (void)SysmonQueryPrimaryTokenUserSidForProcessObject(
                process,
                Info->UserSid,
                RTL_NUMBER_OF(Info->UserSid));
        }
    }

    SysmonPopulateCachedProcessMetadata(Info);
    SysmonGenerateProcessGuid(Info->ProcessId, Info->CreateTime, Info->ProcessGuid);

    ZwClose(processHandle);
    ObDereferenceObject(process);
    return STATUS_SUCCESS;
}

/*
 * Collect full process info for a given PID.
 * Opens the process, queries all available information.
 */
NTSTATUS
SysmonCollectProcessInfo(
    _In_ HANDLE ProcessId,
    _Out_ PSYSMON_PROCESS_INFO Info)
{
    return SysmonCollectProcessInfoInternal(ProcessId, Info, TRUE, TRUE, TRUE);
}

NTSTATUS
SysmonCollectProcessInfoForCreateNotify(
    _In_ HANDLE ProcessId,
    _Out_ PSYSMON_PROCESS_INFO Info)
{
    /*
     * Process create callbacks fire before the new process has a stable user
     * address space for ProcessCommandLineInformation. Avoid command-line and
     * current-directory probing on this path and let CreateInfo provide those
     * user-mode fields, but still collect token data so ProcessCreate carries
     * the raw SID/logon/integrity information that original Sysmon later
     * formats in user mode.
     */
    return SysmonCollectProcessInfoInternal(ProcessId, Info, FALSE, FALSE, TRUE);
}

NTSTATUS
SysmonCollectProcessIdentity(
    _In_ HANDLE ProcessId,
    _Out_ PSYSMON_PROCESS_INFO Info)
{
    /*
     * Hot paths such as Event 10 only need the process GUID identity and
     * image path. Avoid command-line/current-directory/token queries there.
     */
    return SysmonCollectProcessInfoInternal(ProcessId, Info, FALSE, FALSE, FALSE);
}

NTSTATUS
SysmonCollectProcessTokenIdentity(
    _In_ HANDLE ProcessId,
    _Out_ PSYSMON_PROCESS_INFO Info)
{
    /*
     * Registry and ProcessAccess enrichment need image/guid plus token-backed
     * SID data, but they do not need command-line or current-directory probes.
     */
    return SysmonCollectProcessInfoInternal(ProcessId, Info, FALSE, FALSE, TRUE);
}

#define COBJMACROS

#include "../include/clipboard_monitor.h"

#include "../include/config.h"
#include "../include/event.h"
#include "../include/packed_read.hpp"
#include "../include/pipeline.h"
#include "../include/rules.h"
#include "../include/runtime.hpp"
#include "../include/service.h"
#include "../include/source_common.h"

#include "../build/SysmonClipboard_h.h"

#include <rpcasync.h>

/* MIDL memory allocation callbacks required by RPC runtime */
void *__RPC_USER MIDL_user_allocate(size_t Size) {
    return SYSMON_ALLOC(Size);
}

void __RPC_USER MIDL_user_free(void *Ptr) {
    SYSMON_FREE(Ptr);
}

#include <wincrypt.h>
#include <sddl.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <wtsapi32.h>

#ifndef PROCESS_QUERY_LIMITED_INFORMATION
#define PROCESS_QUERY_LIMITED_INFORMATION 0x1000
#endif

#define SYSMON_CLIPBOARD_CLASS_NAME             L"smclip"
#define SYSMON_CLIPBOARD_EVENT_BUFFER_SIZE      8192
#define SYSMON_CLIPBOARD_MAX_HELPERS            32
#define SYSMON_CLIPBOARD_MAX_TEXT_CHARS         32768
#define SYSMON_CLIPBOARD_RPC_RETRY_COUNT        10
#define SYSMON_CLIPBOARD_RPC_RETRY_DELAY_MS     50

typedef BOOL (WINAPI *PFN_AddClipboardFormatListener)(HWND);
typedef BOOL (WINAPI *PFN_RemoveClipboardFormatListener)(HWND);

typedef struct _SYSMON_CLIPBOARD_HELPER_ENTRY {
    DWORD SessionId;
    HANDLE ProcessHandle;
} SYSMON_CLIPBOARD_HELPER_ENTRY, *PSYSMON_CLIPBOARD_HELPER_ENTRY;

struct _SYSMON_CLIPBOARD_MONITOR_CONTEXT {
    PSYSMON_SERVICE_CONTEXT ServiceContext;
    HANDLE ManagerThread;
    CRITICAL_SECTION HelperLock;
    SYSMON_CLIPBOARD_HELPER_ENTRY Helpers[SYSMON_CLIPBOARD_MAX_HELPERS];
    PSYSMON_RULE_RUNTIME RuleRuntime;
    const BYTE *RuleSourceBlob;
    DWORD RuleSourceBlobSize;
    WCHAR EndpointName[128];
    volatile LONG StopRequested;
};

typedef struct _SYSMON_CLIPBOARD_HELPER_CONTEXT {
    handle_t Binding;
    HWND NextViewer;
    DWORD LastSequenceNumber;
    WCHAR LastContentKey[65];
    PFN_AddClipboardFormatListener AddClipboardFormatListenerFn;
    PFN_RemoveClipboardFormatListener RemoveClipboardFormatListenerFn;
    BOOL UsingFormatListener;
} SYSMON_CLIPBOARD_HELPER_CONTEXT, *PSYSMON_CLIPBOARD_HELPER_CONTEXT;

static PSYSMON_CLIPBOARD_MONITOR_CONTEXT g_ClipboardContext = NULL;

static void
SysmonRefreshRuleRuntime(
    _Inout_ PSYSMON_CLIPBOARD_MONITOR_CONTEXT Context)
{
    if (Context == NULL || Context->ServiceContext == NULL) {
        return;
    }

    SysmonRefreshSourceRuleRuntime(
        Context->ServiceContext,
        &Context->RuleRuntime,
        &Context->RuleSourceBlob,
        &Context->RuleSourceBlobSize,
        0,
        NULL);
}

static BOOL
SysmonResolveArchiveDirectory(
    _In_opt_z_ LPCWSTR ConfigValue,
    _Out_writes_(BufferChars) PWCHAR Buffer,
    _In_ size_t BufferChars)
{
    WCHAR windowsDir[MAX_PATH];

    if (Buffer == NULL || BufferChars == 0) {
        return FALSE;
    }

    Buffer[0] = L'\0';
    if (ConfigValue == NULL || ConfigValue[0] == L'\0') {
        return FALSE;
    }

    if ((wcslen(ConfigValue) >= 2 && ConfigValue[1] == L':') ||
        (ConfigValue[0] == L'\\' && ConfigValue[1] == L'\\')) {
        wcscpy_s(Buffer, BufferChars, ConfigValue);
        return TRUE;
    }

    if (GetWindowsDirectoryW(windowsDir, _countof(windowsDir)) == 0 || windowsDir[1] != L':') {
        return FALSE;
    }

    _snwprintf_s(Buffer, BufferChars, _TRUNCATE, L"%c:\\%ls", windowsDir[0], ConfigValue);
    return TRUE;
}

static BOOL
SysmonAppendHashString(
    _Inout_updates_(BufferChars) PWCHAR Buffer,
    _In_ size_t BufferChars,
    _In_z_ LPCWSTR Prefix,
    _In_reads_(DigestSize) const BYTE *Digest,
    _In_ DWORD DigestSize,
    _Inout_ PBOOL First)
{
    static const WCHAR g_HexDigits[] = L"0123456789ABCDEF";
    WCHAR hex[65];
    size_t offset = 0;
    DWORD index;

    if (Buffer == NULL || Prefix == NULL || Digest == NULL || First == NULL) {
        return FALSE;
    }

    if (DigestSize * 2 + 1 > _countof(hex)) {
        return FALSE;
    }

    for (index = 0; index < DigestSize; index++) {
        hex[index * 2] = g_HexDigits[(Digest[index] >> 4) & 0x0F];
        hex[index * 2 + 1] = g_HexDigits[Digest[index] & 0x0F];
    }
    hex[DigestSize * 2] = L'\0';

    if (!*First) {
        wcscat_s(Buffer, BufferChars, L",");
    }

    offset = wcslen(Buffer);
    _snwprintf_s(Buffer + offset, BufferChars - offset, _TRUNCATE, L"%ls=%ls", Prefix, hex);
    *First = FALSE;
    return TRUE;
}

static BOOL
SysmonComputeClipboardHashes(
    _In_z_ LPCWSTR Text,
    _In_ DWORD HashMask,
    _Out_writes_(BufferChars) PWCHAR Buffer,
    _In_ size_t BufferChars)
{
    HCRYPTPROV provider = 0;
    HCRYPTHASH md5Hash = 0;
    HCRYPTHASH sha1Hash = 0;
    HCRYPTHASH sha256Hash = 0;
    BYTE digest[32];
    const BYTE *textBytes;
    DWORD textByteCount;
    DWORD digestSize;
    BOOL first = TRUE;
    BOOL any = FALSE;

    if (Buffer == NULL || BufferChars == 0) {
        return FALSE;
    }

    wcscpy_s(Buffer, BufferChars, L"-");
    if (Text == NULL || HashMask == 0) {
        return TRUE;
    }

    textBytes = (const BYTE *)Text;
    textByteCount = (DWORD)(wcslen(Text) * sizeof(WCHAR));

    if (!CryptAcquireContextW(&provider, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) {
        goto cleanup;
    }

    if ((HashMask & SYSMON_HASH_MD5) != 0 &&
        !CryptCreateHash(provider, CALG_MD5, 0, 0, &md5Hash)) {
        goto cleanup;
    }
    if ((HashMask & SYSMON_HASH_SHA1) != 0 &&
        !CryptCreateHash(provider, CALG_SHA1, 0, 0, &sha1Hash)) {
        goto cleanup;
    }
    if ((HashMask & SYSMON_HASH_SHA256) != 0 &&
        !CryptCreateHash(provider, CALG_SHA_256, 0, 0, &sha256Hash)) {
        goto cleanup;
    }

    if (md5Hash != 0 && !CryptHashData(md5Hash, textBytes, textByteCount, 0)) {
        goto cleanup;
    }
    if (sha1Hash != 0 && !CryptHashData(sha1Hash, textBytes, textByteCount, 0)) {
        goto cleanup;
    }
    if (sha256Hash != 0 && !CryptHashData(sha256Hash, textBytes, textByteCount, 0)) {
        goto cleanup;
    }

    Buffer[0] = L'\0';
    if (sha1Hash != 0) {
        digestSize = 20;
        if (!CryptGetHashParam(sha1Hash, HP_HASHVAL, digest, &digestSize, 0) ||
            !SysmonAppendHashString(Buffer, BufferChars, L"SHA1", digest, digestSize, &first)) {
            goto cleanup;
        }
        any = TRUE;
    }

    if (md5Hash != 0) {
        digestSize = 16;
        if (!CryptGetHashParam(md5Hash, HP_HASHVAL, digest, &digestSize, 0) ||
            !SysmonAppendHashString(Buffer, BufferChars, L"MD5", digest, digestSize, &first)) {
            goto cleanup;
        }
        any = TRUE;
    }

    if (sha256Hash != 0) {
        digestSize = 32;
        if (!CryptGetHashParam(sha256Hash, HP_HASHVAL, digest, &digestSize, 0) ||
            !SysmonAppendHashString(Buffer, BufferChars, L"SHA256", digest, digestSize, &first)) {
            goto cleanup;
        }
        any = TRUE;
    }

    if ((HashMask & SYSMON_HASH_IMPHASH) != 0) {
        if (!first) {
            wcscat_s(Buffer, BufferChars, L",");
        }
        wcscat_s(Buffer, BufferChars, L"IMPHASH=00000000000000000000000000000000");
        first = FALSE;
        any = TRUE;
    }

cleanup:
    if (!any) {
        wcscpy_s(Buffer, BufferChars, L"-");
    }
    if (md5Hash != 0) {
        CryptDestroyHash(md5Hash);
    }
    if (sha1Hash != 0) {
        CryptDestroyHash(sha1Hash);
    }
    if (sha256Hash != 0) {
        CryptDestroyHash(sha256Hash);
    }
    if (provider != 0) {
        CryptReleaseContext(provider, 0);
    }
    return any || HashMask == 0;
}

static BOOL
SysmonComputeClipboardHashIdentity(
    _In_z_ LPCWSTR Text,
    _In_ ALG_ID Algorithm,
    _Out_writes_(BufferChars) PWCHAR Buffer,
    _In_ size_t BufferChars)
{
    static const WCHAR g_HexDigits[] = L"0123456789ABCDEF";
    HCRYPTPROV provider = 0;
    HCRYPTHASH hash = 0;
    BYTE digest[32];
    DWORD digestSize = 0;
    const BYTE *textBytes;
    DWORD textByteCount;
    DWORD index;
    BOOL success = FALSE;

    if (Text == NULL || Buffer == NULL || BufferChars == 0) {
        return FALSE;
    }

    switch (Algorithm) {
    case CALG_MD5:
        digestSize = 16;
        break;
    case CALG_SHA1:
        digestSize = 20;
        break;
    case CALG_SHA_256:
        digestSize = 32;
        break;
    default:
        return FALSE;
    }

    if (BufferChars <= digestSize * 2) {
        return FALSE;
    }

    textBytes = (const BYTE *)Text;
    textByteCount = (DWORD)(wcslen(Text) * sizeof(WCHAR));

    if (!CryptAcquireContextW(&provider, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) {
        goto cleanup;
    }

    if (!CryptCreateHash(provider, Algorithm, 0, 0, &hash)) {
        goto cleanup;
    }

    if (!CryptHashData(hash, textBytes, textByteCount, 0)) {
        goto cleanup;
    }

    if (!CryptGetHashParam(hash, HP_HASHVAL, digest, &digestSize, 0)) {
        goto cleanup;
    }

    for (index = 0; index < digestSize; index++) {
        Buffer[index * 2] = g_HexDigits[(digest[index] >> 4) & 0x0F];
        Buffer[index * 2 + 1] = g_HexDigits[digest[index] & 0x0F];
    }
    Buffer[digestSize * 2] = L'\0';
    success = TRUE;

cleanup:
    if (hash != 0) {
        CryptDestroyHash(hash);
    }
    if (provider != 0) {
        CryptReleaseContext(provider, 0);
    }
    return success;
}

static BOOL
SysmonBuildClipboardArchiveKey(
    _In_z_ LPCWSTR Text,
    _In_ DWORD HashMask,
    _Out_writes_(BufferChars) PWCHAR Buffer,
    _In_ size_t BufferChars)
{
    if (Buffer == NULL || BufferChars == 0) {
        return FALSE;
    }

    if ((HashMask & SYSMON_HASH_SHA1) != 0 &&
        SysmonComputeClipboardHashIdentity(Text, CALG_SHA1, Buffer, BufferChars)) {
        return TRUE;
    }
    if ((HashMask & SYSMON_HASH_MD5) != 0 &&
        SysmonComputeClipboardHashIdentity(Text, CALG_MD5, Buffer, BufferChars)) {
        return TRUE;
    }
    if ((HashMask & SYSMON_HASH_SHA256) != 0 &&
        SysmonComputeClipboardHashIdentity(Text, CALG_SHA_256, Buffer, BufferChars)) {
        return TRUE;
    }
    if ((HashMask & SYSMON_HASH_IMPHASH) != 0) {
        wcscpy_s(Buffer, BufferChars, L"00000000000000000000000000000000");
        return TRUE;
    }

    return SysmonComputeClipboardHashIdentity(Text, CALG_SHA1, Buffer, BufferChars);
}

static BOOL
SysmonBuildSessionUserName(
    _In_ DWORD SessionId,
    _Out_writes_(BufferChars) PWCHAR Buffer,
    _In_ size_t BufferChars)
{
    LPWSTR userName = NULL;
    LPWSTR domainName = NULL;
    DWORD bytes = 0;
    BOOL success = FALSE;

    if (Buffer == NULL || BufferChars == 0) {
        return FALSE;
    }

    if (!WTSQuerySessionInformationW(WTS_CURRENT_SERVER_HANDLE, SessionId, WTSUserName, &userName, &bytes) ||
        userName == NULL || userName[0] == L'\0') {
        wcscpy_s(Buffer, BufferChars, L"-");
    } else if (WTSQuerySessionInformationW(WTS_CURRENT_SERVER_HANDLE, SessionId, WTSDomainName, &domainName, &bytes) &&
               domainName != NULL && domainName[0] != L'\0') {
        _snwprintf_s(Buffer, BufferChars, _TRUNCATE, L"%ls\\%ls", domainName, userName);
    } else {
        _snwprintf_s(Buffer, BufferChars, _TRUNCATE, L"%ls", userName);
    }

    success = (Buffer[0] != L'\0' && Buffer[0] != L'-');

    if (userName != NULL) {
        WTSFreeMemory(userName);
    }
    if (domainName != NULL) {
        WTSFreeMemory(domainName);
    }

    return success;
}

static BOOL
SysmonBuildClientInfo(
    _In_ DWORD SessionId,
    _Out_writes_(BufferChars) PWCHAR Buffer,
    _In_ size_t BufferChars)
{
    LPWSTR clientName = NULL;
    WTS_CLIENT_ADDRESS *clientAddress = NULL;
    DWORD bytes = 0;
    WCHAR ipAddress[64];
    WCHAR sessionUser[256];
    BOOL success = TRUE;

    if (Buffer == NULL || BufferChars == 0) {
        return FALSE;
    }

    SysmonCopyOrPlaceholder(ipAddress, _countof(ipAddress), L"");
    if (SysmonBuildSessionUserName(SessionId, sessionUser, _countof(sessionUser))) {
        _snwprintf_s(Buffer, BufferChars, _TRUNCATE, L"user: %ls", sessionUser);
    } else {
        wcscpy_s(Buffer, BufferChars, L"user: ?");
    }

    if (WTSQuerySessionInformationW(WTS_CURRENT_SERVER_HANDLE, SessionId, WTSClientAddress, (LPWSTR *)&clientAddress, &bytes) &&
        clientAddress != NULL &&
        clientAddress->AddressFamily == AF_INET) {
        SOCKADDR_IN address;

        ZeroMemory(&address, sizeof(address));
        address.sin_family = AF_INET;
        CopyMemory(&address.sin_addr, &clientAddress->Address[2], sizeof(address.sin_addr));
        if (address.sin_addr.S_un.S_addr != 0) {
            if (InetNtopW(AF_INET, &address.sin_addr, ipAddress, _countof(ipAddress)) != NULL) {
                wcscat_s(Buffer, BufferChars, L" ip: ");
                wcscat_s(Buffer, BufferChars, ipAddress);
            }
        }
    }

    if (WTSQuerySessionInformationW(WTS_CURRENT_SERVER_HANDLE, SessionId, WTSClientName, &clientName, &bytes) &&
        clientName != NULL && clientName[0] != L'\0') {
        wcscat_s(Buffer, BufferChars, L" hostname: ");
        wcscat_s(Buffer, BufferChars, clientName);
    }

    if (clientName != NULL) {
        WTSFreeMemory(clientName);
    }
    if (clientAddress != NULL) {
        WTSFreeMemory(clientAddress);
    }

    return success;
}

static BOOL
SysmonPopulateUserFromClientInfo(
    _In_z_ LPCWSTR ClientInfo,
    _Out_writes_(BufferChars) PWCHAR Buffer,
    _In_ size_t BufferChars)
{
    static const WCHAR g_UserPrefix[] = L"user: ";
    const WCHAR *valueStart;
    const WCHAR *valueEnd;
    size_t valueChars;

    if (ClientInfo == NULL || Buffer == NULL || BufferChars == 0) {
        return FALSE;
    }

    if (_wcsnicmp(ClientInfo, g_UserPrefix, RTL_NUMBER_OF(g_UserPrefix) - 1) != 0) {
        return FALSE;
    }

    valueStart = ClientInfo + (RTL_NUMBER_OF(g_UserPrefix) - 1);
    valueEnd = wcsstr(valueStart, L" ip: ");
    if (valueEnd == NULL) {
        valueEnd = wcsstr(valueStart, L" hostname: ");
    }
    if (valueEnd == NULL) {
        valueEnd = valueStart + wcslen(valueStart);
    }

    valueChars = (size_t)(valueEnd - valueStart);
    if (valueChars == 0 || valueChars >= BufferChars) {
        return FALSE;
    }

    wcsncpy_s(Buffer, BufferChars, valueStart, valueChars);
    return TRUE;
}

static BOOL g_ClipboardSecurityPrivilegeEnabled = FALSE;
static INIT_ONCE g_ClipboardSecurityPrivilegeOnce = INIT_ONCE_STATIC_INIT;

static BOOL CALLBACK
SysmonEnableClipboardSecurityPrivilege(
    PINIT_ONCE InitOnce,
    PVOID Parameter,
    PVOID *Context)
{
    HANDLE token = NULL;
    TOKEN_PRIVILEGES privileges;
    LUID luid;
    BOOL enabled = FALSE;

    UNREFERENCED_PARAMETER(InitOnce);
    UNREFERENCED_PARAMETER(Parameter);
    UNREFERENCED_PARAMETER(Context);
    if (OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &token) &&
        LookupPrivilegeValueW(NULL, SE_SECURITY_NAME, &luid)) {
            ZeroMemory(&privileges, sizeof(privileges));
            privileges.PrivilegeCount = 1;
            privileges.Privileges[0].Luid = luid;
            privileges.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
            SetLastError(ERROR_SUCCESS);
            if (AdjustTokenPrivileges(token, FALSE, &privileges, sizeof(privileges), NULL, NULL) &&
            GetLastError() == ERROR_SUCCESS) {
            enabled = TRUE;
        }
    }
    if (token != NULL) {
        CloseHandle(token);
    }
    g_ClipboardSecurityPrivilegeEnabled = enabled;
    return TRUE;
}

static BOOL
SysmonArchiveObjectHasExpectedSecurity(
    _In_z_ LPCWSTR Path,
    _In_ BOOL Directory)
{
    HANDLE objectHandle;
    DWORD openFlags = FILE_FLAG_OPEN_REPARSE_POINT;
    DWORD desiredAccess = READ_CONTROL | ACCESS_SYSTEM_SECURITY;
    BY_HANDLE_FILE_INFORMATION fileInfo;
    PSECURITY_DESCRIPTOR descriptor = NULL;
    DWORD descriptorSize = 0;
    PSID ownerSid = NULL;
    BOOL ownerDefaulted = FALSE;
    PACL dacl = NULL;
    PACL sacl = NULL;
    BOOL daclPresent = FALSE;
    BOOL saclPresent = FALSE;
    BOOL valid = FALSE;

    if (Path == NULL || Path[0] == L'\0') {
        return FALSE;
    }
    if (Directory) {
        openFlags |= FILE_FLAG_BACKUP_SEMANTICS;
    }

    objectHandle = CreateFileW(
        Path,
        desiredAccess,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        NULL,
        OPEN_EXISTING,
        openFlags,
        NULL);
    if (objectHandle == INVALID_HANDLE_VALUE) {
        return FALSE;
    }

    if (!GetFileInformationByHandle(objectHandle, &fileInfo) ||
        (fileInfo.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0 ||
        (Directory && (fileInfo.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) == 0) ||
        (!Directory && (fileInfo.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0)) {
        CloseHandle(objectHandle);
        return FALSE;
    }

    GetFileSecurityW(
        Path,
        OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION | SACL_SECURITY_INFORMATION,
        NULL,
        0,
        &descriptorSize);
    if (descriptorSize != 0) {
        descriptor = (PSECURITY_DESCRIPTOR)LocalAlloc(LPTR, descriptorSize);
    }
    if (descriptor != NULL &&
        GetFileSecurityW(
            Path,
            OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION | SACL_SECURITY_INFORMATION,
            descriptor,
            descriptorSize,
            &descriptorSize) &&
        GetSecurityDescriptorOwner(descriptor, &ownerSid, &ownerDefaulted) &&
        ownerSid != NULL && IsWellKnownSid(ownerSid, WinLocalSystemSid) &&
        GetSecurityDescriptorDacl(descriptor, &daclPresent, &dacl, &ownerDefaulted) &&
        daclPresent && dacl != NULL && dacl->AceCount == 1 &&
        GetSecurityDescriptorSacl(descriptor, &saclPresent, &sacl, &ownerDefaulted) &&
        saclPresent && sacl != NULL && sacl->AceCount == 1) {
        LPVOID daclAce = NULL;
        LPVOID saclAce = NULL;

        valid = GetAce(dacl, 0, &daclAce) &&
            ((PACE_HEADER)daclAce)->AceType == ACCESS_ALLOWED_ACE_TYPE &&
            ((PACCESS_ALLOWED_ACE)daclAce)->Mask == FILE_ALL_ACCESS &&
            IsWellKnownSid(&((PACCESS_ALLOWED_ACE)daclAce)->SidStart, WinLocalSystemSid) &&
            GetAce(sacl, 0, &saclAce) &&
            ((PACE_HEADER)saclAce)->AceType == SYSTEM_MANDATORY_LABEL_ACE_TYPE &&
            (((PSYSTEM_MANDATORY_LABEL_ACE)saclAce)->Mask & SYSTEM_MANDATORY_LABEL_NO_WRITE_UP) != 0 &&
            IsWellKnownSid(&((PSYSTEM_MANDATORY_LABEL_ACE)saclAce)->SidStart, WinSystemLabelSid);
    }

    if (descriptor != NULL) {
        LocalFree(descriptor);
    }
    CloseHandle(objectHandle);
    return valid;
}

static BOOL
SysmonArchiveClipboardText(
    _In_opt_z_ LPCWSTR ArchiveDirectory,
    _In_z_ LPCWSTR Text,
    _In_z_ LPCWSTR ArchiveKey,
    _Out_ PBOOL Archived)
{
    WCHAR archivePath[MAX_PATH];
    WCHAR filePath[MAX_PATH];
    HANDLE fileHandle = INVALID_HANDLE_VALUE;
    SECURITY_ATTRIBUTES securityAttributes;
    PSECURITY_DESCRIPTOR securityDescriptor = NULL;
    DWORD securityDescriptorSize = 0;
    WORD bom = 0xFEFF;
    DWORD bytesWritten;
    DWORD lastError = ERROR_SUCCESS;

    if (Archived == NULL) {
        return FALSE;
    }

    *Archived = FALSE;
    if (Text == NULL || Text[0] == L'\0') {
        return TRUE;
    }
    if (ArchiveKey == NULL || ArchiveKey[0] == L'\0') {
        return FALSE;
    }

    InitOnceExecuteOnce(
        &g_ClipboardSecurityPrivilegeOnce,
        SysmonEnableClipboardSecurityPrivilege,
        NULL,
        NULL);
    if (!g_ClipboardSecurityPrivilegeEnabled) {
        return FALSE;
    }

    if (!SysmonResolveArchiveDirectory(ArchiveDirectory, archivePath, _countof(archivePath))) {
        return TRUE;
    }

    ZeroMemory(&securityAttributes, sizeof(securityAttributes));
    securityAttributes.nLength = sizeof(securityAttributes);
    if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(
            L"O:SYD:P(A;;FA;;;SY)S:(ML;;NW;;;SI)",
            SDDL_REVISION_1,
            &securityDescriptor,
            &securityDescriptorSize)) {
        return FALSE;
    }
    securityAttributes.lpSecurityDescriptor = securityDescriptor;
    if (!CreateDirectoryW(archivePath, &securityAttributes) &&
        GetLastError() != ERROR_ALREADY_EXISTS) {
        LocalFree(securityDescriptor);
        return FALSE;
    }

    if (!SysmonArchiveObjectHasExpectedSecurity(archivePath, TRUE)) {
        LocalFree(securityDescriptor);
        return FALSE;
    }

    _snwprintf_s(
        filePath,
        _countof(filePath),
        _TRUNCATE,
        L"%ls\\CLIP-%ls",
        archivePath,
        ArchiveKey);

    fileHandle = CreateFileW(
        filePath,
        GENERIC_WRITE,
        /* The subsequent security validation reopens the file and requests
           the full sharing set. Keep this handle compatible with that check
           while retaining exclusive write access through the requested
           access mask. */
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        &securityAttributes,
        OPEN_ALWAYS,
        FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT,
        NULL);
    LocalFree(securityDescriptor);
    securityDescriptor = NULL;
    if (fileHandle == INVALID_HANDLE_VALUE) {
        return FALSE;
    }

    lastError = GetLastError();
    {
        BY_HANDLE_FILE_INFORMATION fileInfo;
        if (!GetFileInformationByHandle(fileHandle, &fileInfo) ||
            (fileInfo.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0) {
            CloseHandle(fileHandle);
            return FALSE;
        }
    }
    if (!SysmonArchiveObjectHasExpectedSecurity(filePath, FALSE)) {
        CloseHandle(fileHandle);
        return FALSE;
    }
    if (lastError == ERROR_ALREADY_EXISTS) {
        CloseHandle(fileHandle);
        *Archived = TRUE;
        return TRUE;
    }

    if (!WriteFile(fileHandle, &bom, sizeof(bom), &bytesWritten, NULL)) {
        CloseHandle(fileHandle);
        return FALSE;
    }

    if (!WriteFile(
            fileHandle,
            Text,
            (DWORD)(wcslen(Text) * sizeof(WCHAR)),
            &bytesWritten,
            NULL)) {
        CloseHandle(fileHandle);
        return FALSE;
    }

    CloseHandle(fileHandle);
    *Archived = TRUE;
    return TRUE;
}

static void
SysmonDispatchClipboardEvent(
    _Inout_ PSYSMON_CLIPBOARD_MONITOR_CONTEXT Context,
    _In_ DWORD SessionId,
    _In_ DWORD OwnerProcessId,
    _In_opt_ const SYSMON_PROCESS_METADATA *PacketMetadata,
    _In_z_ LPCWSTR Text)
{
    BYTE eventBuffer[SYSMON_CLIPBOARD_EVENT_BUFFER_SIZE];
    SYSMON_EVENT_PAYLOAD_BUILDER builder;
    PSYSMON_EVENT_HEADER header;
    SYSMON_EVENT_CLIPBOARD_CHANGE_PAYLOAD *payload;
    SYSMON_PROCESS_METADATA metadata;
    WCHAR utcTime[64];
    WCHAR userField[256];
    WCHAR clientInfo[512];
    WCHAR hashes[512];
    WCHAR archiveKey[65];
    WCHAR archiveDirectory[MAX_PATH];
    DWORD hashMask = 0;
    BOOL archived = FALSE;
    ULONGLONG timestamp = 0;

    if (Context == NULL || Text == NULL) {
        return;
    }

    SysmonRefreshRuleRuntime(Context);
    if (Context->RuleRuntime != NULL &&
        !SysmonRuleRuntimeEventCanProduceLogs(Context->RuleRuntime, SysmonEventClipboardChange)) {
        return;
    }

    SysmonFormatCurrentUtcTime(utcTime, _countof(utcTime), &timestamp);

    ZeroMemory(&metadata, sizeof(metadata));
    if (PacketMetadata != NULL) {
        CopyMemory(&metadata, PacketMetadata, sizeof(metadata));
    }

    if (metadata.ProcessId == 0) {
        metadata.ProcessId = OwnerProcessId;
    }

    if (metadata.ProcessGuid[0] == L'\0' ||
        metadata.ProcessGuid[0] == L'-' ||
        metadata.Image[0] == L'\0' ||
        metadata.Image[0] == L'-' ||
        metadata.UserName[0] == L'\0' ||
        metadata.UserName[0] == L'-') {
        SYSMON_PROCESS_METADATA refreshedMetadata;

        if (SysmonCollectProcessMetadataAtTime(
                Context->ServiceContext,
                OwnerProcessId,
                &timestamp,
                &refreshedMetadata)) {
            metadata = refreshedMetadata;
        }
    }
    SysmonBuildClientInfo(SessionId, clientInfo, _countof(clientInfo));
    SysmonCopyOrPlaceholder(userField, _countof(userField), metadata.UserName);
    if (userField[0] == L'-') {
        if (!SysmonBuildSessionUserName(SessionId, userField, _countof(userField))) {
            (void)SysmonPopulateUserFromClientInfo(clientInfo, userField, _countof(userField));
        }
    }
    wcscpy_s(hashes, _countof(hashes), L"-");
    archiveKey[0] = L'\0';
    archiveDirectory[0] = L'\0';

    {
        CriticalSectionGuard configLock(&Context->ServiceContext->ConfigLock);

        hashMask = Context->ServiceContext->Config.HashingAlgorithm;
        if (Context->ServiceContext->Config.ArchiveDirectory != NULL) {
            SysmonCopyOrPlaceholder(
                archiveDirectory,
                _countof(archiveDirectory),
                Context->ServiceContext->Config.ArchiveDirectory);
        }
    }

    SysmonComputeClipboardHashes(Text, hashMask, hashes, _countof(hashes));
    if (SysmonBuildClipboardArchiveKey(Text, hashMask, archiveKey, _countof(archiveKey))) {
        SysmonArchiveClipboardText(archiveDirectory, Text, archiveKey, &archived);
    }

    SysmonInitializeEventBuffer(
        eventBuffer,
        sizeof(eventBuffer),
        SysmonEventClipboardChange,
        sizeof(*payload),
        &builder,
        timestamp);

    header = (PSYSMON_EVENT_HEADER)eventBuffer;
    if (header->EventSize == 0) {
        return;
    }

    payload = (SYSMON_EVENT_CLIPBOARD_CHANGE_PAYLOAD *)(eventBuffer + SYSMON_EVENT_HEADER_SIZE);
    ZeroMemory(payload, sizeof(*payload));
    SysmonWritePackedValue<DWORD>(&payload->ProcessId, metadata.ProcessId);
    payload->Session = SessionId;
    payload->Archived = archived ? TRUE : FALSE;

    SysmonAddStringField(eventBuffer, sizeof(eventBuffer), &builder, &payload->RuleName, L"-");
    SysmonAddStringField(eventBuffer, sizeof(eventBuffer), &builder, &payload->UtcTime, utcTime);
    SysmonAddStringField(eventBuffer, sizeof(eventBuffer), &builder, &payload->ProcessGuid, metadata.ProcessGuid);
    SysmonAddStringField(eventBuffer, sizeof(eventBuffer), &builder, &payload->Image, metadata.Image);
    SysmonAddStringField(eventBuffer, sizeof(eventBuffer), &builder, &payload->ClientInfo, clientInfo);
    SysmonAddStringField(eventBuffer, sizeof(eventBuffer), &builder, &payload->Hashes, hashes);
    SysmonAddStringField(eventBuffer, sizeof(eventBuffer), &builder, &payload->User, userField);

    if (Context->RuleRuntime == NULL ||
        SysmonShouldCaptureEvent(
            Context->RuleRuntime,
            SysmonEventClipboardChange,
            eventBuffer,
            ((PSYSMON_EVENT_HEADER)eventBuffer)->EventSize)) {
        SysmonPipelineDispatch(eventBuffer, ((PSYSMON_EVENT_HEADER)eventBuffer)->EventSize);
    }
}

static int
SysmonFindHelperSlot(
    _In_ PSYSMON_CLIPBOARD_MONITOR_CONTEXT Context,
    _In_ DWORD SessionId)
{
    int index;

    for (index = 0; index < SYSMON_CLIPBOARD_MAX_HELPERS; index++) {
        if (Context->Helpers[index].ProcessHandle != NULL &&
            Context->Helpers[index].SessionId == SessionId) {
            return index;
        }
    }

    return -1;
}

static int
SysmonFindFreeHelperSlot(
    _In_ PSYSMON_CLIPBOARD_MONITOR_CONTEXT Context)
{
    int index;

    for (index = 0; index < SYSMON_CLIPBOARD_MAX_HELPERS; index++) {
        if (Context->Helpers[index].ProcessHandle == NULL) {
            return index;
        }
    }

    return -1;
}

static void
SysmonRemoveHelperSlot(
    _Inout_ PSYSMON_CLIPBOARD_MONITOR_CONTEXT Context,
    _In_ int Index,
    _In_ BOOL Terminate)
{
    if (Index < 0 || Index >= SYSMON_CLIPBOARD_MAX_HELPERS) {
        return;
    }

    if (Context->Helpers[Index].ProcessHandle != NULL) {
        if (Terminate) {
            TerminateProcess(Context->Helpers[Index].ProcessHandle, 0);
        }
        CloseHandle(Context->Helpers[Index].ProcessHandle);
    }

    ZeroMemory(&Context->Helpers[Index], sizeof(Context->Helpers[Index]));
}

static BOOL
SysmonIsSessionEligible(
    _In_ WTS_CONNECTSTATE_CLASS State)
{
    return (State == WTSActive || State == WTSConnected);
}

static BOOL
SysmonSpawnClipboardHelper(
    _Inout_ PSYSMON_CLIPBOARD_MONITOR_CONTEXT Context,
    _In_ DWORD SessionId)
{
    HANDLE userToken = NULL;
    HANDLE primaryToken = NULL;
    HANDLE duplicatedHandle = NULL;
    STARTUPINFOW startupInfo;
    PROCESS_INFORMATION processInfo;
    WCHAR exePath[MAX_PATH];
    WCHAR commandLine[512];
    int slot;
    BOOL success = FALSE;

    if (Context == NULL) {
        return FALSE;
    }

    if (!WTSQueryUserToken(SessionId, &userToken)) {
        goto cleanup;
    }

    if (!DuplicateTokenEx(
            userToken,
            TOKEN_ASSIGN_PRIMARY | TOKEN_DUPLICATE | TOKEN_QUERY | TOKEN_ADJUST_DEFAULT | TOKEN_ADJUST_SESSIONID,
            NULL,
            SecurityImpersonation,
            TokenPrimary,
            &primaryToken)) {
        goto cleanup;
    }

    if (GetModuleFileNameW(NULL, exePath, _countof(exePath)) == 0) {
        goto cleanup;
    }

    if (!DuplicateHandle(
            GetCurrentProcess(),
            GetCurrentProcess(),
            GetCurrentProcess(),
            &duplicatedHandle,
            SYNCHRONIZE,
            TRUE,  // bInheritHandle
            DUPLICATE_SAME_ACCESS)) {
        goto cleanup;
    }

    _snwprintf_s(
        commandLine,
        _countof(commandLine),
        _TRUNCATE,
        L"\"%ls\" -z \"%ls\" -p %llu",
        exePath,
        Context->EndpointName,
        (ULONGLONG)(ULONG_PTR)duplicatedHandle);

    ZeroMemory(&startupInfo, sizeof(startupInfo));
    ZeroMemory(&processInfo, sizeof(processInfo));
    startupInfo.cb = sizeof(startupInfo);
    startupInfo.lpDesktop = const_cast<LPWSTR>(L"WinSta0\\Default");

    if (!CreateProcessAsUserW(
            primaryToken,
            exePath,
            commandLine,
            NULL,
            NULL,
            TRUE,
            CREATE_NO_WINDOW,
            NULL,
            NULL,
            &startupInfo,
            &processInfo)) {
        goto cleanup;
    }

    CloseHandle(duplicatedHandle);
    duplicatedHandle = NULL;

    CloseHandle(processInfo.hThread);

    slot = SysmonFindFreeHelperSlot(Context);
    if (slot >= 0) {
        Context->Helpers[slot].SessionId = SessionId;
        Context->Helpers[slot].ProcessHandle = processInfo.hProcess;
        success = TRUE;
    } else {
        TerminateProcess(processInfo.hProcess, 0);
        CloseHandle(processInfo.hProcess);
    }

cleanup:
    if (duplicatedHandle != NULL) {
        CloseHandle(duplicatedHandle);
    }
    SYSMON_SAFE_CLOSE_HANDLE(primaryToken);
    SYSMON_SAFE_CLOSE_HANDLE(userToken);
    return success;
}

static void
SysmonSynchronizeHelpers(
    _Inout_ PSYSMON_CLIPBOARD_MONITOR_CONTEXT Context)
{
    PWTS_SESSION_INFOW sessions = NULL;
    DWORD sessionCount = 0;
    DWORD seenSessions[SYSMON_CLIPBOARD_MAX_HELPERS];
    DWORD seenCount = 0;
    DWORD index;

    if (Context == NULL) {
        return;
    }

    if (!WTSEnumerateSessionsW(WTS_CURRENT_SERVER_HANDLE, 0, 1, &sessions, &sessionCount)) {
        return;
    }

    CriticalSectionGuard helperLock(&Context->HelperLock);

    for (index = 0; index < sessionCount; index++) {
        int slot;
        DWORD exitCode = STILL_ACTIVE;

        if (!SysmonIsSessionEligible(sessions[index].State)) {
            continue;
        }

        if (seenCount < _countof(seenSessions)) {
            seenSessions[seenCount++] = sessions[index].SessionId;
        }

        slot = SysmonFindHelperSlot(Context, sessions[index].SessionId);
        if (slot >= 0) {
            if (!GetExitCodeProcess(Context->Helpers[slot].ProcessHandle, &exitCode) ||
                exitCode != STILL_ACTIVE) {
                SysmonRemoveHelperSlot(Context, slot, FALSE);
                slot = -1;
            }
        }

        if (slot < 0) {
            SysmonSpawnClipboardHelper(Context, sessions[index].SessionId);
        }
    }

    for (index = 0; index < SYSMON_CLIPBOARD_MAX_HELPERS; index++) {
        BOOL keep = FALSE;
        DWORD seenIndex;

        if (Context->Helpers[index].ProcessHandle == NULL) {
            continue;
        }

        for (seenIndex = 0; seenIndex < seenCount; seenIndex++) {
            if (Context->Helpers[index].SessionId == seenSessions[seenIndex]) {
                keep = TRUE;
                break;
            }
        }

        if (!keep) {
            SysmonRemoveHelperSlot(Context, (int)index, TRUE);
        }
    }
    WTSFreeMemory(sessions);
}

static DWORD WINAPI
SysmonClipboardManagerThread(
    _In_ LPVOID Parameter)
{
    PSYSMON_CLIPBOARD_MONITOR_CONTEXT context = (PSYSMON_CLIPBOARD_MONITOR_CONTEXT)Parameter;

    while (context != NULL && InterlockedCompareExchange(&context->StopRequested, 0, 0) == 0) {
        SysmonSynchronizeHelpers(context);

        if (WaitForSingleObject(context->ServiceContext->StopEvent, 5000) == WAIT_OBJECT_0) {
            break;
        }
    }

    return 0;
}

static void
SysmonClipboardHelperSend(
    _In_ PSYSMON_CLIPBOARD_HELPER_CONTEXT Context,
    _In_ DWORD SessionId,
    _In_ DWORD OwnerProcessId,
    _In_opt_ const SYSMON_PROCESS_METADATA *Metadata,
    _In_z_ LPCWSTR Text)
{
    UNREFERENCED_PARAMETER(Metadata);

    if (Context == NULL || Text == NULL || Context->Binding == NULL) {
        return;
    }

    /* The server's interface security callback authorizes callers by helper PID.
       A helper's very first call can race with the manager registering it in the
       helpers table, so retry briefly on access-denied before giving up. */
    for (DWORD attempt = 0; attempt < SYSMON_CLIPBOARD_RPC_RETRY_COUNT; attempt++) {
        RpcTryExcept {
            SysmonClipboardSend(Context->Binding, SessionId, OwnerProcessId, (wchar_t*)Text);
            break;
        }
        RpcExcept(1) {
            if (RpcExceptionCode() == RPC_S_ACCESS_DENIED &&
                attempt + 1 < SYSMON_CLIPBOARD_RPC_RETRY_COUNT) {
                Sleep(SYSMON_CLIPBOARD_RPC_RETRY_DELAY_MS);
                continue;
            }
            SysmonLogWarning(SYSMON_COMPONENT_SERVICE,
                "Clipboard RPC call failed: %lu",
                RpcExceptionCode());
            break;
        }
        RpcEndExcept
    }
}

static BOOL
SysmonClipboardHelperReadText(
    _Inout_ PSYSMON_CLIPBOARD_HELPER_CONTEXT Context,
    _Outptr_result_z_ LPWSTR *Text)
{
    static const UINT g_Formats[] = { 13, 1, 7 };
    DWORD sequenceNumber;
    int selectedFormat;
    int retries = 0;
    HANDLE clipboardData = NULL;
    const void *rawData = NULL;
    SIZE_T rawBytes;
    LPWSTR result = NULL;
    BOOL success = FALSE;

    if (Context == NULL || Text == NULL) {
        return FALSE;
    }

    *Text = NULL;
    sequenceNumber = GetClipboardSequenceNumber();
    if (Context->LastSequenceNumber == sequenceNumber) {
        return FALSE;
    }

    selectedFormat = GetPriorityClipboardFormat((UINT *)g_Formats, (int)_countof(g_Formats));
    if (selectedFormat <= 0) {
        return FALSE;
    }

    while (!OpenClipboard(NULL)) {
        Sleep(300);
        retries++;
        if (retries >= 5) {
            return FALSE;
        }
    }

    clipboardData = GetClipboardData((UINT)selectedFormat);
    if (clipboardData == NULL) {
        goto cleanup;
    }

    rawData = GlobalLock(clipboardData);
    if (rawData == NULL) {
        goto cleanup;
    }

    rawBytes = GlobalSize(clipboardData);
    if (rawBytes == 0) {
        goto cleanup;
    }

    if (selectedFormat == 13) {
        SIZE_T maxChars = rawBytes / sizeof(WCHAR);
        SIZE_T textChars = 0;

        while (textChars < maxChars && ((const WCHAR *)rawData)[textChars] != L'\0') {
            textChars++;
        }

        result = (LPWSTR)SYSMON_ALLOC((textChars + 1) * sizeof(WCHAR));
        if (result == NULL) {
            goto cleanup;
        }

        CopyMemory(result, rawData, textChars * sizeof(WCHAR));
        result[textChars] = L'\0';
        success = (textChars != 0);
    } else {
        UINT codePage = (selectedFormat == 7) ? CP_OEMCP : CP_ACP;
        int wideChars;

        wideChars = MultiByteToWideChar(codePage, 0, (LPCCH)rawData, (int)rawBytes, NULL, 0);
        if (wideChars <= 0) {
            goto cleanup;
        }

        result = (LPWSTR)SYSMON_ALLOC((SIZE_T)(wideChars + 1) * sizeof(WCHAR));
        if (result == NULL) {
            goto cleanup;
        }

        if (MultiByteToWideChar(codePage, 0, (LPCCH)rawData, (int)rawBytes, result, wideChars) <= 0) {
            goto cleanup;
        }

        result[wideChars] = L'\0';
        success = (wideChars != 0);
    }

    if (success) {
        Context->LastSequenceNumber = sequenceNumber;
        *Text = result;
        result = NULL;
    }

cleanup:
    if (rawData != NULL) {
        GlobalUnlock(clipboardData);
    }
    CloseClipboard();
    SYSMON_FREE(result);
    return success;
}

static void
SysmonClipboardHelperNotify(
    _Inout_ PSYSMON_CLIPBOARD_HELPER_CONTEXT Context)
{
    HWND ownerWindow;
    DWORD ownerProcessId = 0;
    DWORD sessionId = 0;
    WCHAR contentKey[65];
    SYSMON_PROCESS_METADATA metadata;
    LPWSTR text = NULL;

    if (Context == NULL) {
        return;
    }

    ownerWindow = GetClipboardOwner();
    if (ownerWindow != NULL) {
        GetWindowThreadProcessId(ownerWindow, &ownerProcessId);
    }

    ZeroMemory(&metadata, sizeof(metadata));
    if (ownerProcessId != 0) {
        (void)SysmonCollectProcessMetadata(NULL, ownerProcessId, &metadata);
    }

    if (!SysmonClipboardHelperReadText(Context, &text)) {
        return;
    }

    if (SysmonComputeClipboardHashIdentity(text, CALG_SHA1, contentKey, _countof(contentKey))) {
        if (_wcsicmp(Context->LastContentKey, contentKey) == 0) {
            SYSMON_FREE(text);
            return;
        }
    } else {
        contentKey[0] = L'\0';
    }

    ProcessIdToSessionId(GetCurrentProcessId(), &sessionId);
    SysmonClipboardHelperSend(Context, sessionId, ownerProcessId, &metadata, text);
    if (contentKey[0] != L'\0') {
        wcscpy_s(Context->LastContentKey, _countof(Context->LastContentKey), contentKey);
    }
    SYSMON_FREE(text);
}

static LRESULT CALLBACK
SysmonClipboardHelperWndProc(
    _In_ HWND WindowHandle,
    _In_ UINT Message,
    _In_ WPARAM WParam,
    _In_ LPARAM LParam)
{
    PSYSMON_CLIPBOARD_HELPER_CONTEXT context =
        (PSYSMON_CLIPBOARD_HELPER_CONTEXT)GetWindowLongPtrW(WindowHandle, GWLP_USERDATA);

    switch (Message) {
    case WM_NCCREATE:
        SetWindowLongPtrW(
            WindowHandle,
            GWLP_USERDATA,
            (LONG_PTR)((LPCREATESTRUCTW)LParam)->lpCreateParams);
        return TRUE;

    case WM_CREATE:
        if (context != NULL &&
            context->AddClipboardFormatListenerFn != NULL &&
            context->RemoveClipboardFormatListenerFn != NULL &&
            context->AddClipboardFormatListenerFn(WindowHandle)) {
            context->UsingFormatListener = TRUE;
        } else if (context != NULL) {
            context->NextViewer = SetClipboardViewer(WindowHandle);
            context->UsingFormatListener = FALSE;
        }
        return 0;

    case WM_CLIPBOARDUPDATE:
    case WM_DRAWCLIPBOARD:
        if (context != NULL) {
            SysmonClipboardHelperNotify(context);
            if (Message == WM_DRAWCLIPBOARD && context->NextViewer != NULL) {
                SendMessageW(context->NextViewer, Message, WParam, LParam);
            }
        }
        return 0;

    case WM_CHANGECBCHAIN:
        if (context != NULL && !context->UsingFormatListener) {
            if ((HWND)WParam == context->NextViewer) {
                context->NextViewer = (HWND)LParam;
            } else if (context->NextViewer != NULL) {
                SendMessageW(context->NextViewer, Message, WParam, LParam);
            }
        }
        return 0;

    case WM_DESTROY:
        if (context != NULL) {
            if (context->UsingFormatListener &&
                context->RemoveClipboardFormatListenerFn != NULL) {
                context->RemoveClipboardFormatListenerFn(WindowHandle);
            } else if (context->NextViewer != NULL) {
                ChangeClipboardChain(WindowHandle, context->NextViewer);
            }
        }
        PostQuitMessage(0);
        return 0;
    }

    return DefWindowProcW(WindowHandle, Message, WParam, LParam);
}

static DWORD WINAPI
SysmonClipboardParentMonitor(
    _In_ LPVOID Parameter)
{
    HANDLE parentHandle = (HANDLE)Parameter;

    if (parentHandle != NULL) {
        WaitForSingleObject(parentHandle, INFINITE);
        CloseHandle(parentHandle);
    }

    ExitProcess(0);
    return 0;
}

SYSMON_STATUS
SysmonClipboardHelperRun(
    _In_z_ LPCWSTR EndpointName,
    _In_ HANDLE ParentHandle)
{
    WNDCLASSW windowClass;
    MSG message;
    HMODULE user32Module;
    HWND windowHandle;
    SYSMON_CLIPBOARD_HELPER_CONTEXT context;
    RPC_WSTR stringBinding = NULL;

    if (EndpointName == NULL || EndpointName[0] == L'\0') {
        return SYSMON_ERROR_INVALID_PARAM;
    }

    FreeConsole();

    ZeroMemory(&context, sizeof(context));

    /* RPC binding */
    {
        RPC_STATUS rpcStatus = RpcStringBindingComposeW(
            NULL, (RPC_WSTR)L"ncalrpc", NULL, (RPC_WSTR)EndpointName, NULL, &stringBinding);
        if (rpcStatus != RPC_S_OK) {
            return rpcStatus;
        }
    }
    {
        RPC_STATUS rpcStatus = RpcBindingFromStringBindingW(stringBinding, &context.Binding);
        RpcStringFreeW(&stringBinding);
        if (rpcStatus != RPC_S_OK) {
            return rpcStatus;
        }
    }

    /* Start parent monitor thread */
    if (ParentHandle != NULL) {
        HANDLE monitorThread = CreateThread(NULL, 0, SysmonClipboardParentMonitor, ParentHandle, 0, NULL);
        if (monitorThread != NULL) {
            CloseHandle(monitorThread);
        }
    }

    user32Module = GetModuleHandleW(L"user32.dll");
    if (user32Module != NULL) {
        context.AddClipboardFormatListenerFn =
            (PFN_AddClipboardFormatListener)GetProcAddress(user32Module, "AddClipboardFormatListener");
        context.RemoveClipboardFormatListenerFn =
            (PFN_RemoveClipboardFormatListener)GetProcAddress(user32Module, "RemoveClipboardFormatListener");
    }

    ZeroMemory(&windowClass, sizeof(windowClass));
    windowClass.lpfnWndProc = SysmonClipboardHelperWndProc;
    windowClass.hInstance = GetModuleHandleW(NULL);
    windowClass.lpszClassName = SYSMON_CLIPBOARD_CLASS_NAME;
    RegisterClassW(&windowClass);

    windowHandle = CreateWindowExW(
        0,
        SYSMON_CLIPBOARD_CLASS_NAME,
        SYSMON_CLIPBOARD_CLASS_NAME,
        WS_OVERLAPPED,
        0,
        0,
        0,
        0,
        NULL,
        NULL,
        windowClass.hInstance,
        &context);
    if (windowHandle == NULL) {
        RpcBindingFree(&context.Binding);
        return GetLastError();
    }

    while (GetMessageW(&message, NULL, 0, 0) > 0) {
        TranslateMessage(&message);
        DispatchMessageW(&message);
    }

    RpcBindingFree(&context.Binding);
    return SYSMON_SUCCESS;
}

void SysmonClipboardRegister(handle_t hBinding) {
    UNREFERENCED_PARAMETER(hBinding);
}

void SysmonClipboardSend(handle_t hBinding, DWORD SessionId, DWORD OwnerProcessId, wchar_t *Text) {
    PSYSMON_CLIPBOARD_MONITOR_CONTEXT context =
        (PSYSMON_CLIPBOARD_MONITOR_CONTEXT)InterlockedCompareExchangePointer(
            (PVOID volatile *)&g_ClipboardContext, NULL, NULL);

    UNREFERENCED_PARAMETER(hBinding);

    if (Text == NULL || Text[0] == L'\0' || context == NULL) {
        return;
    }

    SysmonDispatchClipboardEvent(context, SessionId, OwnerProcessId, NULL, Text);
}

static RPC_STATUS
SysmonClipboardRpcSecurityCallback(
    _In_ RPC_IF_HANDLE InterfaceUuid,
    _In_opt_ void *Context)
{
    PSYSMON_CLIPBOARD_MONITOR_CONTEXT monitorContext;
    RPC_CALL_ATTRIBUTES_V3 callAttributes;
    LONG index;

    UNREFERENCED_PARAMETER(InterfaceUuid);
    UNREFERENCED_PARAMETER(Context);

    monitorContext = (PSYSMON_CLIPBOARD_MONITOR_CONTEXT)InterlockedCompareExchangePointer(
        (PVOID volatile *)&g_ClipboardContext, NULL, NULL);
    if (monitorContext == NULL) {
        return RPC_S_ACCESS_DENIED;
    }

    ZeroMemory(&callAttributes, sizeof(callAttributes));
    /* RPC_CALL_ATTRIBUTES_VERSION resolves from the build's NTDDI_VERSION, which
       may be older than this SDK's default; hardcode 3 for the V3 struct we use. */
    callAttributes.Version = 3;
    callAttributes.Flags = RPC_QUERY_CLIENT_PID;
    if (RpcServerInqCallAttributes(NULL, &callAttributes) != RPC_S_OK ||
        callAttributes.ClientPID == 0) {
        return RPC_S_ACCESS_DENIED;
    }

    /* Only calls from helper processes this service spawned are allowed. A local
       process that discovers the random endpoint name is rejected, so forged
       clipboard events cannot be injected into the security event stream.
       See P1/3.4 in the 2026-08-04 review. */
    EnterCriticalSection(&monitorContext->HelperLock);
    for (index = 0; index < SYSMON_CLIPBOARD_MAX_HELPERS; index++) {
        HANDLE helperHandle = monitorContext->Helpers[index].ProcessHandle;

        if (helperHandle != NULL &&
            GetProcessId(helperHandle) == (DWORD)(ULONG_PTR)callAttributes.ClientPID) {
            LeaveCriticalSection(&monitorContext->HelperLock);
            return RPC_S_OK;
        }
    }
    LeaveCriticalSection(&monitorContext->HelperLock);

    return RPC_S_ACCESS_DENIED;
}

SYSMON_STATUS
SysmonClipboardMonitorStart(
    _Inout_ PSYSMON_SERVICE_CONTEXT ServiceContext,
    _Outptr_result_maybenull_ PSYSMON_CLIPBOARD_MONITOR_CONTEXT *Context)
{
    PSYSMON_CLIPBOARD_MONITOR_CONTEXT context;
    HCRYPTPROV hProv = 0;
    ULONGLONG randomValue;
    RPC_STATUS rpcStatus;
    int retryCount;

    if (Context == NULL || ServiceContext == NULL) {
        return SYSMON_ERROR_INVALID_PARAM;
    }

    *Context = NULL;

    context = (PSYSMON_CLIPBOARD_MONITOR_CONTEXT)SYSMON_ALLOC(sizeof(*context));
    if (context == NULL) {
        return SYSMON_ERROR_OUT_OF_MEMORY;
    }

    ZeroMemory(context, sizeof(*context));
    context->ServiceContext = ServiceContext;
    InitializeCriticalSection(&context->HelperLock);

    /* Generate random endpoint name (matching original Sysmon CryptGenRandom approach) */
    if (!CryptAcquireContextW(&hProv, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT)) {
        DeleteCriticalSection(&context->HelperLock);
        SYSMON_FREE(context);
        return GetLastError();
    }
    CryptGenRandom(hProv, sizeof(randomValue), (BYTE *)&randomValue);
    CryptReleaseContext(hProv, 0);

    _snwprintf_s(
        context->EndpointName,
        _countof(context->EndpointName),
        _TRUNCATE,
        L"syscliprpc%I64X",
        randomValue);

    /* Register RPC protocol sequence (retry up to 10 times on duplicate endpoint) */
    for (retryCount = 0; retryCount < 10; retryCount++) {
        rpcStatus = RpcServerUseProtseqEpW(
            (RPC_WSTR)L"ncalrpc",
            1234,
            (RPC_WSTR)context->EndpointName,
            NULL);
        if (rpcStatus == RPC_S_DUPLICATE_ENDPOINT) {
            CryptAcquireContextW(&hProv, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT);
            CryptGenRandom(hProv, sizeof(randomValue), (BYTE *)&randomValue);
            CryptReleaseContext(hProv, 0);
            _snwprintf_s(
                context->EndpointName,
                _countof(context->EndpointName),
                _TRUNCATE,
                L"syscliprpc%I64X",
                randomValue);
            continue;
        }
        break;
    }

    if (rpcStatus != RPC_S_OK) {
        SysmonLogError(SYSMON_COMPONENT_SERVICE, rpcStatus,
            "Failed to register RPC protocol sequence");
        DeleteCriticalSection(&context->HelperLock);
        SYSMON_FREE(context);
        return rpcStatus;
    }

    /* Register RPC interface with auto-listen. The interface security callback
       restricts callers to the helper processes this service spawned. */
    rpcStatus = RpcServerRegisterIfEx(
        SysmonClipboard_v1_0_s_ifspec,
        NULL,
        NULL,
        RPC_IF_AUTOLISTEN,
        1234,
        SysmonClipboardRpcSecurityCallback);
    if (rpcStatus != RPC_S_OK) {
        SysmonLogError(SYSMON_COMPONENT_SERVICE, rpcStatus,
            "Failed to register RPC interface");
        DeleteCriticalSection(&context->HelperLock);
        SYSMON_FREE(context);
        return rpcStatus;
    }

    /* Set global context for RPC callbacks */
    InterlockedExchangePointer((PVOID volatile *)&g_ClipboardContext, context);

    /* Start Manager thread */
    context->ManagerThread = CreateThread(NULL, 0, SysmonClipboardManagerThread, context, 0, NULL);
    if (context->ManagerThread == NULL) {
        DWORD lastError = GetLastError();
        RpcServerUnregisterIf(SysmonClipboard_v1_0_s_ifspec, NULL, 1);
        RpcMgmtStopServerListening(NULL);
        RpcMgmtWaitServerListen();
        InterlockedExchangePointer((PVOID volatile *)&g_ClipboardContext, NULL);
        DeleteCriticalSection(&context->HelperLock);
        SYSMON_FREE(context);
        return lastError;
    }

    *Context = context;
    return SYSMON_SUCCESS;
}

void
SysmonClipboardMonitorStop(
    _Inout_opt_ PSYSMON_CLIPBOARD_MONITOR_CONTEXT Context)
{
    int index;

    if (Context == NULL) {
        return;
    }

    InterlockedExchange(&Context->StopRequested, 1);

    /* Unregister RPC interface and stop listening */
    RpcServerUnregisterIf(SysmonClipboard_v1_0_s_ifspec, NULL, 1);
    RpcMgmtStopServerListening(NULL);
    RpcMgmtWaitServerListen();

    /* Clear global context */
    InterlockedExchangePointer((PVOID volatile *)&g_ClipboardContext, NULL);

    /* Wait for Manager thread to exit */
    if (Context->ManagerThread != NULL) {
        WaitForSingleObject(Context->ManagerThread, INFINITE);
        CloseHandle(Context->ManagerThread);
        Context->ManagerThread = NULL;
    }

    /* Terminate all helper processes */
    {
        CriticalSectionGuard helperLock(&Context->HelperLock);

        for (index = 0; index < SYSMON_CLIPBOARD_MAX_HELPERS; index++) {
            if (Context->Helpers[index].ProcessHandle != NULL) {
                SysmonRemoveHelperSlot(Context, index, TRUE);
            }
        }
    }

    DeleteCriticalSection(&Context->HelperLock);

    if (Context->RuleRuntime != NULL) {
        SysmonFreeRuleRuntime(Context->RuleRuntime);
        Context->RuleRuntime = NULL;
    }

    SYSMON_FREE(Context);
}

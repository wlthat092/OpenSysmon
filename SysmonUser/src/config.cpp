/*
 * config.c - Registry read/write, hot reload thread, config snapshot
 * Reads from: HKLM\SYSTEM\CurrentControlSet\Services\<ServiceName>\Parameters
 */

#include "../include/config.h"
#include "../include/protocol.h"
#include "../include/service.h"
#include "../include/output.h"

#include <wincrypt.h>

#include "../include/runtime.hpp"

static void
SysmonConfigFreeRule(
    _Inout_ PSYSMON_RULE Rule)
{
    DWORD index;

    if (Rule == NULL) {
        return;
    }

    SYSMON_FREE(Rule->Name);

    for (index = 0; index < Rule->ExpressionCount; index++) {
        SYSMON_FREE(Rule->Expressions[index].FieldName);
        Rule->Expressions[index].FieldName = NULL;
        SYSMON_FREE(Rule->Expressions[index].Value);
    }

    SYSMON_FREE(Rule->Expressions);
    ZeroMemory(Rule, sizeof(*Rule));
}

static void
SysmonConfigFreeEventRule(
    _Inout_ PSYSMON_EVENT_RULE EventRule)
{
    DWORD index;

    if (EventRule == NULL) {
        return;
    }

    for (index = 0; index < EventRule->RuleCount; index++) {
        SysmonConfigFreeRule(&EventRule->Rules[index]);
    }

    SYSMON_FREE(EventRule->Rules);
    ZeroMemory(EventRule, sizeof(*EventRule));
}

void
SysmonConfigFreeRuleSet(
    PSYSMON_RULE_SET RuleSet)
{
    DWORD groupIndex;

    if (RuleSet == NULL) {
        return;
    }

    for (groupIndex = 0; groupIndex < RuleSet->GroupCount; groupIndex++) {
        DWORD eventIndex;
        PSYSMON_RULE_GROUP group = &RuleSet->Groups[groupIndex];

        SYSMON_FREE(group->Name);

        for (eventIndex = 0; eventIndex < group->EventRuleCount; eventIndex++) {
            SysmonConfigFreeEventRule(&group->EventRules[eventIndex]);
        }

        SYSMON_FREE(group->EventRules);
    }

    SYSMON_FREE(RuleSet->Groups);
    ZeroMemory(RuleSet, sizeof(*RuleSet));
}

static SYSMON_STATUS
SysmonRegWriteDword(
    _In_ HKEY Key,
    _In_ LPCWSTR ValueName,
    _In_ DWORD Value)
{
    LONG result;

    result = RegSetValueExW(Key, ValueName, 0, REG_DWORD, (const BYTE *)&Value, sizeof(Value));
    return (result == ERROR_SUCCESS) ? SYSMON_SUCCESS : (SYSMON_STATUS)result;
}

static SYSMON_STATUS
SysmonRegWriteBool(
    _In_ HKEY Key,
    _In_ LPCWSTR ValueName,
    _In_ BOOL Value)
{
    BYTE data;
    LONG result;

    data = Value ? 1 : 0;
    result = RegSetValueExW(Key, ValueName, 0, REG_BINARY, &data, sizeof(data));
    return (result == ERROR_SUCCESS) ? SYSMON_SUCCESS : (SYSMON_STATUS)result;
}

static SYSMON_STATUS
SysmonRegWriteString(
    _In_ HKEY Key,
    _In_ LPCWSTR ValueName,
    _In_opt_ LPCWSTR Value)
{
    LONG result;
    const WCHAR *text;
    DWORD size;

    text = (Value != NULL) ? Value : L"";
    size = (DWORD)((wcslen(text) + 1) * sizeof(WCHAR));

    result = RegSetValueExW(Key, ValueName, 0, REG_SZ, (const BYTE *)text, size);
    return (result == ERROR_SUCCESS) ? SYSMON_SUCCESS : (SYSMON_STATUS)result;
}

static SYSMON_STATUS
SysmonRegWriteOptionalString(
    _In_ HKEY Key,
    _In_ LPCWSTR ValueName,
    _In_opt_ LPCWSTR Value)
{
    LONG result;

    if (Value == NULL || Value[0] == L'\0') {
        result = RegDeleteValueW(Key, ValueName);
        if (result == ERROR_SUCCESS || result == ERROR_FILE_NOT_FOUND) {
            return SYSMON_SUCCESS;
        }

        return (SYSMON_STATUS)result;
    }

    return SysmonRegWriteString(Key, ValueName, Value);
}

static SYSMON_STATUS
SysmonRegWriteZeroLengthString(
    _In_ HKEY Key,
    _In_ LPCWSTR ValueName)
{
    LONG result;

    result = RegSetValueExW(
        Key,
        ValueName,
        0,
        REG_SZ,
        (const BYTE *)L"",
        sizeof(WCHAR));
    return (result == ERROR_SUCCESS) ? SYSMON_SUCCESS : (SYSMON_STATUS)result;
}

static SYSMON_STATUS
SysmonRegWriteOptionalMultiSz(
    _In_ HKEY Key,
    _In_ LPCWSTR ValueName,
    _In_reads_bytes_opt_(ValueSize) const BYTE *Value,
    _In_ DWORD ValueSize)
{
    LONG result;

    if (Value == NULL || ValueSize == 0) {
        result = RegDeleteValueW(Key, ValueName);
        if (result == ERROR_SUCCESS || result == ERROR_FILE_NOT_FOUND) {
            return SYSMON_SUCCESS;
        }

        return (SYSMON_STATUS)result;
    }

    result = RegSetValueExW(Key, ValueName, 0, REG_MULTI_SZ, Value, ValueSize);
    return (result == ERROR_SUCCESS) ? SYSMON_SUCCESS : (SYSMON_STATUS)result;
}

static SYSMON_STATUS
SysmonRegWriteBinary(
    _In_ HKEY Key,
    _In_ LPCWSTR ValueName,
    _In_reads_bytes_opt_(ValueSize) const BYTE *Value,
    _In_ DWORD ValueSize)
{
    LONG result;

    result = RegSetValueExW(Key, ValueName, 0, REG_BINARY, Value, ValueSize);
    return (result == ERROR_SUCCESS) ? SYSMON_SUCCESS : (SYSMON_STATUS)result;
}

static SYSMON_STATUS
SysmonRegWriteOptionalBinary(
    _In_ HKEY Key,
    _In_ LPCWSTR ValueName,
    _In_reads_bytes_opt_(ValueSize) const BYTE *Value,
    _In_ DWORD ValueSize)
{
    LONG result;

    if (Value == NULL || ValueSize == 0) {
        result = RegDeleteValueW(Key, ValueName);
        if (result == ERROR_SUCCESS || result == ERROR_FILE_NOT_FOUND) {
            return SYSMON_SUCCESS;
        }

        return (SYSMON_STATUS)result;
    }

    return SysmonRegWriteBinary(Key, ValueName, Value, ValueSize);
}

static SYSMON_STATUS
SysmonRegDeleteIfPresent(
    _In_ HKEY Key,
    _In_ LPCWSTR ValueName)
{
    LONG result;

    result = RegDeleteValueW(Key, ValueName);
    if (result == ERROR_SUCCESS || result == ERROR_FILE_NOT_FOUND) {
        return SYSMON_SUCCESS;
    }

    return (SYSMON_STATUS)result;
}

static SYSMON_STATUS
SysmonBuildFullPathCopy(
    _In_ LPCWSTR Path,
    _Out_ LPWSTR *FullPath)
{
    DWORD charCount;

    *FullPath = NULL;

    charCount = GetFullPathNameW(Path, 0, NULL, NULL);
    if (charCount == 0) {
        return GetLastError();
    }

    *FullPath = (LPWSTR)SYSMON_ALLOC((SIZE_T)charCount * sizeof(WCHAR));
    if (*FullPath == NULL) {
        return SYSMON_ERROR_OUT_OF_MEMORY;
    }

    if (GetFullPathNameW(Path, charCount, *FullPath, NULL) == 0) {
        SYSMON_FREE(*FullPath);
        return GetLastError();
    }

    return SYSMON_SUCCESS;
}

static SYSMON_STATUS
SysmonComputeConfigHash(
    _In_ LPCWSTR ConfigFilePath,
    _Out_ LPWSTR *ConfigHash)
{
    static const WCHAR g_HexDigits[] = L"0123456789ABCDEF";
    BYTE buffer[4096];
    BYTE hash[64];
    DWORD hashSize = sizeof(hash);
    DWORD bytesRead = 0;
    HANDLE fileHandle = INVALID_HANDLE_VALUE;
    HCRYPTPROV cryptoProvider = 0;
    HCRYPTHASH cryptoHash = 0;
    LPWSTR hashText = NULL;
    DWORD index;
    SYSMON_STATUS status = SYSMON_SUCCESS;

    *ConfigHash = NULL;

    fileHandle = CreateFileW(
        ConfigFilePath,
        GENERIC_READ,
        FILE_SHARE_READ,
        NULL,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        NULL);
    if (fileHandle == INVALID_HANDLE_VALUE) {
        return GetLastError();
    }

    if (!CryptAcquireContextW(&cryptoProvider, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) {
        status = GetLastError();
        goto cleanup;
    }

    if (!CryptCreateHash(cryptoProvider, CALG_SHA1, 0, 0, &cryptoHash)) {
        status = GetLastError();
        goto cleanup;
    }

    for (;;) {
        if (!ReadFile(fileHandle, buffer, sizeof(buffer), &bytesRead, NULL)) {
            status = GetLastError();
            goto cleanup;
        }

        if (bytesRead == 0) {
            break;
        }

        if (!CryptHashData(cryptoHash, buffer, bytesRead, 0)) {
            status = GetLastError();
            goto cleanup;
        }
    }

    if (!CryptGetHashParam(cryptoHash, HP_HASHVAL, hash, &hashSize, 0)) {
        status = GetLastError();
        goto cleanup;
    }

    hashText = (LPWSTR)SYSMON_ALLOC((((SIZE_T)hashSize * 2) + 1) * sizeof(WCHAR));
    if (hashText == NULL) {
        status = SYSMON_ERROR_OUT_OF_MEMORY;
        goto cleanup;
    }

    for (index = 0; index < hashSize; index++) {
        hashText[index * 2] = g_HexDigits[(hash[index] >> 4) & 0x0F];
        hashText[(index * 2) + 1] = g_HexDigits[hash[index] & 0x0F];
    }
    hashText[hashSize * 2] = L'\0';
    *ConfigHash = hashText;
    hashText = NULL;

cleanup:
    SYSMON_FREE(hashText);
    if (cryptoHash != 0) {
        CryptDestroyHash(cryptoHash);
    }
    if (cryptoProvider != 0) {
        CryptReleaseContext(cryptoProvider, 0);
    }
    if (fileHandle != INVALID_HANDLE_VALUE) {
        CloseHandle(fileHandle);
    }
    return status;
}

/*
 * SysmonOpenParametersKey - Open the Parameters registry key
 */
SYSMON_STATUS SysmonOpenParametersKey(
    PHKEY KeyHandle,
    LPCWSTR ServiceName,
    REGSAM DesiredAccess)
{
    WCHAR regPath[512];

    _snwprintf_s(regPath, _countof(regPath), _TRUNCATE,
        L"System\\CurrentControlSet\\Services\\%s\\Parameters", ServiceName);

    LONG result = RegOpenKeyExW(
        HKEY_LOCAL_MACHINE,
        regPath,
        0,
        DesiredAccess,
        KeyHandle);

    return (result == ERROR_SUCCESS) ? SYSMON_SUCCESS : (SYSMON_STATUS)result;
}

/*
 * SysmonRegReadDword - Read a REG_DWORD value
 */
SYSMON_STATUS SysmonRegReadDword(HKEY Key, LPCWSTR ValueName, PDWORD Value)
{
    DWORD size = sizeof(DWORD);
    DWORD type = REG_DWORD;

    LONG result = RegQueryValueExW(Key, ValueName, NULL, &type, (LPBYTE)Value, &size);
    if (result != ERROR_SUCCESS) return (SYSMON_STATUS)result;
    if (type != REG_DWORD) return ERROR_DATATYPE_MISMATCH;

    return SYSMON_SUCCESS;
}

/*
 * SysmonRegReadBool - Read a 1-byte REG_BINARY as boolean (true if non-zero)
 */
SYSMON_STATUS SysmonRegReadBool(HKEY Key, LPCWSTR ValueName, PBOOL Value)
{
    BYTE data;
    DWORD size = sizeof(data);
    DWORD type = REG_BINARY;

    LONG result = RegQueryValueExW(Key, ValueName, NULL, &type, &data, &size);
    if (result != ERROR_SUCCESS) {
        *Value = TRUE;  /* Default to true for CheckRevocation/DnsLookup */
        return (SYSMON_STATUS)result;
    }

    *Value = (data != 0);
    return SYSMON_SUCCESS;
}

/*
 * SysmonRegReadString - Read a REG_SZ string (caller must free with SYSMON_FREE)
 */
SYSMON_STATUS SysmonRegReadString(HKEY Key, LPCWSTR ValueName, LPWSTR *Value)
{
    DWORD size = 0;
    DWORD type = REG_SZ;

    *Value = NULL;

    /* Query size first */
    LONG result = RegQueryValueExW(Key, ValueName, NULL, &type, NULL, &size);
    if (result != ERROR_SUCCESS) return (SYSMON_STATUS)result;

    if (size == 0) {
        size = sizeof(WCHAR);
    }

    *Value = (LPWSTR)SYSMON_ALLOC(size);
    if (*Value == NULL) return SYSMON_ERROR_OUT_OF_MEMORY;

    result = RegQueryValueExW(Key, ValueName, NULL, &type, (LPBYTE)*Value, &size);
    if (result != ERROR_SUCCESS) {
        SYSMON_FREE(*Value);
        return (SYSMON_STATUS)result;
    }

    if (size == 0) {
        (*Value)[0] = L'\0';
    }

    return SYSMON_SUCCESS;
}

/*
 * SysmonRegReadBinary - Read a REG_BINARY value (caller must free with SYSMON_FREE)
 */
SYSMON_STATUS SysmonRegReadBinary(HKEY Key, LPCWSTR ValueName, PBYTE *Value, PDWORD ValueSize)
{
    DWORD size = 0;
    DWORD type = REG_BINARY;

    *Value = NULL;
    *ValueSize = 0;

    LONG result = RegQueryValueExW(Key, ValueName, NULL, &type, NULL, &size);
    if (result != ERROR_SUCCESS) return (SYSMON_STATUS)result;

    *Value = (PBYTE)SYSMON_ALLOC(size);
    if (*Value == NULL) return SYSMON_ERROR_OUT_OF_MEMORY;

    result = RegQueryValueExW(Key, ValueName, NULL, &type, *Value, &size);
    if (result != ERROR_SUCCESS) {
        SYSMON_FREE(*Value);
        return (SYSMON_STATUS)result;
    }

    *ValueSize = size;
    return SYSMON_SUCCESS;
}

static void
SysmonLogConfigReadFailure(
    _In_z_ LPCWSTR ValueName,
    _In_ SYSMON_STATUS Status)
{
    if (ValueName == NULL ||
        Status == SYSMON_SUCCESS ||
        Status == ERROR_FILE_NOT_FOUND) {
        return;
    }

    SysmonLogWarning(
        SYSMON_COMPONENT_CONFIG,
        "Failed to read registry value '%ls': %lu",
        ValueName,
        (unsigned long)Status);
}

SYSMON_STATUS
SysmonConfigPersistCompiled(
    LPCWSTR ServiceName,
    LPCWSTR ConfigFilePath,
    const SYSMON_CONFIG *Config)
{
    HKEY hKey = NULL;
    LPWSTR fullPath = NULL;
    LPWSTR configHash = NULL;
    PBYTE rulesBlob = NULL;
    DWORD rulesBlobSize = 0;
    DWORD hashingAlgorithm;
    SYSMON_STATUS status;

    if (ServiceName == NULL || Config == NULL) {
        return SYSMON_ERROR_INVALID_PARAM;
    }

    if (ConfigFilePath != NULL && ConfigFilePath[0] != L'\0') {
        status = SysmonBuildFullPathCopy(ConfigFilePath, &fullPath);
        if (status != SYSMON_SUCCESS) {
            return status;
        }

        status = SysmonComputeConfigHash(ConfigFilePath, &configHash);
        if (status != SYSMON_SUCCESS) {
            goto cleanup;
        }
    }

    status = SysmonSerializeRules(&Config->RuleSet, &rulesBlob, &rulesBlobSize);
    if (status != SYSMON_SUCCESS) {
        goto cleanup;
    }

    status = SysmonOpenParametersKey(&hKey, ServiceName, KEY_WRITE);
    if (status != SYSMON_SUCCESS) {
        goto cleanup;
    }

    hashingAlgorithm = (Config->HashingAlgorithm != 0) ? Config->HashingAlgorithm : SYSMON_HASH_DEFAULT;

    status = SysmonRegWriteOptionalString(hKey, L"ConfigFile", fullPath);
    if (status != SYSMON_SUCCESS) goto cleanup;

    if (configHash != NULL && configHash[0] != L'\0') {
        status = SysmonRegWriteString(hKey, L"ConfigHash", configHash);
    } else {
        status = SysmonRegWriteZeroLengthString(hKey, L"ConfigHash");
    }
    if (status != SYSMON_SUCCESS) goto cleanup;

    status = SysmonRegWriteDword(hKey, L"Options", Config->Options);
    if (status != SYSMON_SUCCESS) goto cleanup;

    status = SysmonRegWriteDword(hKey, L"HashingAlgorithm", hashingAlgorithm);
    if (status != SYSMON_SUCCESS) goto cleanup;

    status = SysmonRegWriteBool(hKey, L"CheckRevocation", Config->CheckRevocation);
    if (status != SYSMON_SUCCESS) goto cleanup;

    status = SysmonRegWriteBool(hKey, L"DnsLookup", Config->DnsLookup);
    if (status != SYSMON_SUCCESS) goto cleanup;

    status = SysmonRegWriteOptionalString(hKey, L"ArchiveDirectory", Config->ArchiveDirectory);
    if (status != SYSMON_SUCCESS) goto cleanup;

    status = SysmonRegWriteBool(hKey, L"CopyOnDeletePE", Config->CopyOnDeletePE);
    if (status != SYSMON_SUCCESS) goto cleanup;

    status = SysmonRegWriteOptionalString(hKey, L"CopyOnDeleteSIDs", Config->CopyOnDeleteSIDs);
    if (status != SYSMON_SUCCESS) goto cleanup;

    status = SysmonRegWriteOptionalString(hKey, L"CopyOnDeleteExtensions", Config->CopyOnDeleteExtensions);
    if (status != SYSMON_SUCCESS) goto cleanup;

    status = SysmonRegWriteOptionalString(hKey, L"CopyOnDeleteProcesses", Config->CopyOnDeleteProcesses);
    if (status != SYSMON_SUCCESS) goto cleanup;

    status = SysmonRegWriteOptionalString(hKey, L"FieldSizes", Config->FieldSizes);
    if (status != SYSMON_SUCCESS) goto cleanup;

    status = SysmonRegWriteDword(hKey, L"SigningQueueSize", Config->SigningQueueSize);
    if (status != SYSMON_SUCCESS) goto cleanup;

    status = SysmonRegWriteDword(hKey, L"SigningWorkerCount", Config->SigningWorkerCount);
    if (status != SYSMON_SUCCESS) goto cleanup;

    status = SysmonRegDeleteIfPresent(hKey, L"ProcessNotify");
    if (status != SYSMON_SUCCESS) goto cleanup;
    status = SysmonRegDeleteIfPresent(hKey, L"ThreadNotify");
    if (status != SYSMON_SUCCESS) goto cleanup;
    status = SysmonRegDeleteIfPresent(hKey, L"ImageNotify");
    if (status != SYSMON_SUCCESS) goto cleanup;
    status = SysmonRegDeleteIfPresent(hKey, L"RegistryNotify");
    if (status != SYSMON_SUCCESS) goto cleanup;
    status = SysmonRegDeleteIfPresent(hKey, L"FileNotify");
    if (status != SYSMON_SUCCESS) goto cleanup;

    if (Config->DriverQueueSize != 0) {
        status = SysmonRegWriteDword(hKey, L"DriverQueueSize", Config->DriverQueueSize);
    } else {
        LONG result = RegDeleteValueW(hKey, L"DriverQueueSize");
        status = (result == ERROR_SUCCESS || result == ERROR_FILE_NOT_FOUND)
            ? SYSMON_SUCCESS
            : (SYSMON_STATUS)result;
    }
    if (status != SYSMON_SUCCESS) goto cleanup;

    status = SysmonRegWriteBinary(hKey, L"Rules", rulesBlob, rulesBlobSize);
    if (status != SYSMON_SUCCESS) goto cleanup;

    status = SysmonRegWriteOptionalMultiSz(
        hKey,
        L"ProcessAccessNames",
        (const BYTE *)Config->ProcessAccessNames,
        Config->ProcessAccessNamesSize);
    if (status != SYSMON_SUCCESS) goto cleanup;

    status = SysmonRegWriteOptionalBinary(
        hKey,
        L"ProcessAccessMasks",
        Config->ProcessAccessMasks,
        Config->ProcessAccessMasksSize);

cleanup:
    if (hKey != NULL) {
        RegCloseKey(hKey);
    }
    SYSMON_FREE(fullPath);
    SYSMON_FREE(configHash);
    SYSMON_FREE(rulesBlob);
    return status;
}

SYSMON_STATUS
SysmonStagePendingConfigChangeEvent(
    _In_ LPCWSTR ServiceName,
    _In_opt_ LPCWSTR Configuration,
    _In_opt_ LPCWSTR ConfigurationFileHash)
{
    HKEY hKey = NULL;
    SYSMON_STATUS status;
    LONG result;

    if (ServiceName == NULL) {
        return SYSMON_ERROR_INVALID_PARAM;
    }

    status = SysmonOpenParametersKey(&hKey, ServiceName, KEY_WRITE);
    if (status != SYSMON_SUCCESS) {
        return status;
    }

    /*
     * Keep the pending Event 16 pair consistent for the service flush thread:
     * clear any stale values first, then publish hash before configuration.
     * Flush only treats configuration as the ready marker, so writing it last
     * avoids mixed old/new registry state.
     */
    result = RegDeleteValueW(hKey, SYSMON_REGVALUE_PENDING_CONFIG_EVENT_CONFIGURATION);
    if (result != ERROR_SUCCESS && result != ERROR_FILE_NOT_FOUND) {
        status = (SYSMON_STATUS)result;
    } else {
        result = RegDeleteValueW(hKey, SYSMON_REGVALUE_PENDING_CONFIG_EVENT_HASH);
        if (result != ERROR_SUCCESS && result != ERROR_FILE_NOT_FOUND) {
            status = (SYSMON_STATUS)result;
        } else {
            status = SysmonRegWriteOptionalString(
                hKey,
                SYSMON_REGVALUE_PENDING_CONFIG_EVENT_HASH,
                ConfigurationFileHash);
            if (status == SYSMON_SUCCESS) {
                status = SysmonRegWriteOptionalString(
                    hKey,
                    SYSMON_REGVALUE_PENDING_CONFIG_EVENT_CONFIGURATION,
                    Configuration);
                if (status != SYSMON_SUCCESS) {
                    RegDeleteValueW(hKey, SYSMON_REGVALUE_PENDING_CONFIG_EVENT_HASH);
                }
            }
        }
    }

    RegCloseKey(hKey);
    return status;
}

void
SysmonTryFlushPendingConfigChangeEvent(
    _In_ LPCWSTR ServiceName)
{
    HKEY hKey = NULL;
    LPWSTR configuration = NULL;
    LPWSTR configurationFileHash = NULL;
    SYSMON_STATUS status;

    if (ServiceName == NULL) {
        return;
    }

    status = SysmonOpenParametersKey(&hKey, ServiceName, KEY_READ | KEY_WRITE);
    if (status != SYSMON_SUCCESS) {
        return;
    }

    if (SysmonRegReadString(
            hKey,
            SYSMON_REGVALUE_PENDING_CONFIG_EVENT_CONFIGURATION,
            &configuration) != SYSMON_SUCCESS) {
        configuration = NULL;
    }

    if (SysmonRegReadString(
            hKey,
            SYSMON_REGVALUE_PENDING_CONFIG_EVENT_HASH,
            &configurationFileHash) != SYSMON_SUCCESS) {
        configurationFileHash = NULL;
    }

    if (configuration == NULL || configuration[0] == L'\0') {
        goto cleanup;
    }

    status = SysmonEmitConfigChangeEvent(configuration, configurationFileHash);
    if (status != SYSMON_SUCCESS) {
        SysmonLogWarning(
            SYSMON_COMPONENT_CONFIG,
            "Failed to flush pending Event 16 for service '%ls': %lu",
            ServiceName,
            (unsigned long)status);
        goto cleanup;
    }

    RegDeleteValueW(hKey, SYSMON_REGVALUE_PENDING_CONFIG_EVENT_CONFIGURATION);
    RegDeleteValueW(hKey, SYSMON_REGVALUE_PENDING_CONFIG_EVENT_HASH);

cleanup:
    if (hKey != NULL) {
        RegCloseKey(hKey);
    }
    SYSMON_FREE(configuration);
    SYSMON_FREE(configurationFileHash);
}

/*
 * SysmonConfigLoad - Read all configuration from registry
 *
 * Reads all known keys from the Parameters subkey:
 *   Options, HashingAlgorithm, Rules, FieldSizes, ConfigFile, ConfigHash,
 *   ArchiveDirectory, CheckRevocation, DnsLookup, DriverQueueSize,
 *   SigningQueueSize, SigningWorkerCount, ProcessAccessNames, ProcessAccessMasks
 */
SYSMON_STATUS SysmonConfigLoad(PSYSMON_CONFIG Config, LPCWSTR ServiceName)
{
    HKEY hKey = NULL;
    SYSMON_STATUS status;

    if (!Config || !ServiceName) return SYSMON_ERROR_INVALID_PARAM;

    ZeroMemory(Config, sizeof(SYSMON_CONFIG));

    /* Set defaults */
    Config->HashingAlgorithm = SYSMON_HASH_DEFAULT;
    Config->CheckRevocation = TRUE;
    Config->DnsLookup = TRUE;
    Config->CopyOnDeletePE = FALSE;
    Config->SigningQueueSize = 1000;
    Config->SigningWorkerCount = 0;

    /* Open Parameters key */
    status = SysmonOpenParametersKey(&hKey, ServiceName, KEY_READ);
    if (status != SYSMON_SUCCESS) {
        if (status != ERROR_FILE_NOT_FOUND) {
            SysmonLogWarning(
                SYSMON_COMPONENT_CONFIG,
                "Failed to open Parameters key, using defaults (error %u)",
                status);
        }
        return SYSMON_SUCCESS;  /* Return with defaults */
    }

    /* Read Options bitmask */
    {
        DWORD val = 0;
        status = SysmonRegReadDword(hKey, L"Options", &val);
        if (status == SYSMON_SUCCESS) {
            Config->Options = val;
        } else {
            SysmonLogConfigReadFailure(L"Options", status);
        }
    }

    /* Read HashingAlgorithm bitmask */
    {
        DWORD val = 0;
        status = SysmonRegReadDword(hKey, L"HashingAlgorithm", &val);
        if (status == SYSMON_SUCCESS) {
            Config->HashingAlgorithm = val;
        } else {
            SysmonLogConfigReadFailure(L"HashingAlgorithm", status);
        }
    }

    /* Read boolean options */
    {
        BOOL val;
        status = SysmonRegReadBool(hKey, L"CheckRevocation", &val);
        if (status == SYSMON_SUCCESS) {
            Config->CheckRevocation = val;
        } else {
            SysmonLogConfigReadFailure(L"CheckRevocation", status);
        }
        status = SysmonRegReadBool(hKey, L"DnsLookup", &val);
        if (status == SYSMON_SUCCESS) {
            Config->DnsLookup = val;
        } else {
            SysmonLogConfigReadFailure(L"DnsLookup", status);
        }
        status = SysmonRegReadBool(hKey, L"CopyOnDeletePE", &val);
        if (status == SYSMON_SUCCESS) {
            Config->CopyOnDeletePE = val;
        } else {
            SysmonLogConfigReadFailure(L"CopyOnDeletePE", status);
        }
    }

    /* Read numeric options */
    {
        DWORD val;
        status = SysmonRegReadDword(hKey, L"DriverQueueSize", &val);
        if (status == SYSMON_SUCCESS) {
            Config->DriverQueueSize = val;
        } else {
            SysmonLogConfigReadFailure(L"DriverQueueSize", status);
        }
        status = SysmonRegReadDword(hKey, L"SigningQueueSize", &val);
        if (status == SYSMON_SUCCESS) {
            Config->SigningQueueSize = val;
        } else {
            SysmonLogConfigReadFailure(L"SigningQueueSize", status);
        }
        status = SysmonRegReadDword(hKey, L"SigningWorkerCount", &val);
        if (status == SYSMON_SUCCESS) {
            Config->SigningWorkerCount = val;
        } else {
            SysmonLogConfigReadFailure(L"SigningWorkerCount", status);
        }
    }

    /* Read string options */
    status = SysmonRegReadString(hKey, L"ConfigFile", &Config->ConfigFile);
    SysmonLogConfigReadFailure(L"ConfigFile", status);
    status = SysmonRegReadString(hKey, L"ConfigHash", &Config->ConfigHash);
    SysmonLogConfigReadFailure(L"ConfigHash", status);
    status = SysmonRegReadString(hKey, L"ArchiveDirectory", &Config->ArchiveDirectory);
    SysmonLogConfigReadFailure(L"ArchiveDirectory", status);
    if (status == SYSMON_SUCCESS &&
        Config->ArchiveDirectory != NULL &&
        Config->ArchiveDirectory[0] != L'\0' &&
        !SysmonIsSinglePathComponent(Config->ArchiveDirectory)) {
        SysmonLogWarning(
            SYSMON_COMPONENT_CONFIG,
            "Ignoring invalid registry value 'ArchiveDirectory': '%ls'",
            Config->ArchiveDirectory);
        SYSMON_FREE(Config->ArchiveDirectory);
        Config->ArchiveDirectory = NULL;
    }
    status = SysmonRegReadString(hKey, L"CopyOnDeleteSIDs", &Config->CopyOnDeleteSIDs);
    SysmonLogConfigReadFailure(L"CopyOnDeleteSIDs", status);
    status = SysmonRegReadString(hKey, L"CopyOnDeleteExtensions", &Config->CopyOnDeleteExtensions);
    SysmonLogConfigReadFailure(L"CopyOnDeleteExtensions", status);
    status = SysmonRegReadString(hKey, L"CopyOnDeleteProcesses", &Config->CopyOnDeleteProcesses);
    SysmonLogConfigReadFailure(L"CopyOnDeleteProcesses", status);
    status = SysmonRegReadString(hKey, L"FieldSizes", &Config->FieldSizes);
    SysmonLogConfigReadFailure(L"FieldSizes", status);
    if (status == SYSMON_SUCCESS &&
        Config->FieldSizes != NULL &&
        !SysmonValidateFieldSizesText(Config->FieldSizes)) {
        SysmonLogWarning(
            SYSMON_COMPONENT_CONFIG,
            "Ignoring invalid registry value 'FieldSizes': '%ls'",
            Config->FieldSizes);
        SYSMON_FREE(Config->FieldSizes);
        Config->FieldSizes = NULL;
    }

    /* Read Rules binary */
    status = SysmonRegReadBinary(hKey, L"Rules", &Config->Rules, &Config->RulesSize);
    SysmonLogConfigReadFailure(L"Rules", status);

    /* Read ProcessAccessNames (REG_MULTI_SZ) */
    {
        DWORD size = 0;
        DWORD type = REG_MULTI_SZ;
        LONG result = RegQueryValueExW(hKey, L"ProcessAccessNames", NULL, &type, NULL, &size);
        if (result == ERROR_SUCCESS && type == REG_MULTI_SZ && size > 0) {
            Config->ProcessAccessNames = (LPWSTR)SYSMON_ALLOC(size);
            if (Config->ProcessAccessNames) {
                result = RegQueryValueExW(
                    hKey,
                    L"ProcessAccessNames",
                    NULL,
                    &type,
                    (LPBYTE)Config->ProcessAccessNames,
                    &size);
                if (result == ERROR_SUCCESS) {
                    Config->ProcessAccessNamesSize = size;
                } else {
                    SYSMON_FREE(Config->ProcessAccessNames);
                    SysmonLogConfigReadFailure(L"ProcessAccessNames", (SYSMON_STATUS)result);
                }
            }
        } else if (result == ERROR_SUCCESS && type != REG_MULTI_SZ) {
            SysmonLogConfigReadFailure(L"ProcessAccessNames", ERROR_DATATYPE_MISMATCH);
        } else {
            SysmonLogConfigReadFailure(L"ProcessAccessNames", (SYSMON_STATUS)result);
        }
    }

    /* Read ProcessAccessMasks (REG_BINARY) */
    status = SysmonRegReadBinary(
        hKey,
        L"ProcessAccessMasks",
        &Config->ProcessAccessMasks,
        &Config->ProcessAccessMasksSize);
    SysmonLogConfigReadFailure(L"ProcessAccessMasks", status);

    RegCloseKey(hKey);
    return SYSMON_SUCCESS;
}

/*
 * SysmonConfigFree - Free all allocated fields in config
 */
void SysmonConfigFree(PSYSMON_CONFIG Config)
{
    if (!Config) return;

    SysmonConfigFreeRuleSet(&Config->RuleSet);
    SYSMON_FREE(Config->ConfigFile);
    SYSMON_FREE(Config->ConfigHash);
    SYSMON_FREE(Config->ArchiveDirectory);
    SYSMON_FREE(Config->CopyOnDeleteSIDs);
    SYSMON_FREE(Config->CopyOnDeleteExtensions);
    SYSMON_FREE(Config->CopyOnDeleteProcesses);
    SYSMON_FREE(Config->FieldSizes);
    SYSMON_FREE(Config->Rules);
    SYSMON_FREE(Config->ProcessAccessNames);
    SYSMON_FREE(Config->ProcessAccessMasks);
    ZeroMemory(Config, sizeof(SYSMON_CONFIG));
}

/*
 * SysmonConfigMonitorThread - Thread proc for registry change notification
 *
 * Original (sub_14008a9f0):
 *   1. Open Parameters key
 *   2. RegNotifyChangeKeyValue loop
 *   3. On change:
 *      a. Open separate device handle
 *      b. Send IOCTL 0x83400008 (config notify)
 *      c. Close handle
 *      d. Check "Stop" value → if exists and admin, trigger stop
 *      e. Reload config, check for rule changes
 *   4. On repeated errors (10), break
 */
DWORD WINAPI SysmonConfigMonitorThread(LPVOID Param)
{
    /* Use global service context g_ServiceCtx */
    HKEY hKey = NULL;
    HANDLE changeEvent = NULL;
    SYSMON_STATUS status;
    int errorCount = 0;

    UNREFERENCED_PARAMETER(Param);

    /* Open the Parameters key with notify access */
    status = SysmonOpenParametersKey(&hKey, SYSMON_SERVICE_NAME, KEY_READ | KEY_NOTIFY);
    if (status != SYSMON_SUCCESS) {
        SysmonLogError(SYSMON_COMPONENT_CONFIG, status,
            "Failed to start configuration monitor - cannot open Parameters key");
        return (DWORD)status;
    }

    changeEvent = CreateEventW(NULL, FALSE, FALSE, NULL);
    if (changeEvent == NULL) {
        status = GetLastError();
        RegCloseKey(hKey);
        SysmonLogError(SYSMON_COMPONENT_CONFIG, status,
            "Failed to create configuration monitor event");
        return (DWORD)status;
    }

    SysmonLogInfo(SYSMON_COMPONENT_CONFIG, "Configuration monitor started");

    while (TRUE) {
        HANDLE waitHandles[2];
        DWORD waitResult;

        /* Wait for registry change notification */
        LONG result = RegNotifyChangeKeyValue(
            hKey,
            TRUE,   /* Watch subtree */
            REG_NOTIFY_CHANGE_NAME | REG_NOTIFY_CHANGE_LAST_SET,
            changeEvent,
            TRUE);   /* Asynchronous */

        if (result != ERROR_SUCCESS) {
            errorCount++;
            if (errorCount >= 10) {
                SysmonLogError(SYSMON_COMPONENT_CONFIG, result,
                    "Too many registry notification failures, stopping monitor");
                break;
            }
            continue;
        }

        waitHandles[0] = g_ServiceCtx.StopEvent;
        waitHandles[1] = changeEvent;
        waitResult = WaitForMultipleObjects(_countof(waitHandles), waitHandles, FALSE, INFINITE);

        if (waitResult == WAIT_OBJECT_0) {
            break;
        }

        if (waitResult != (WAIT_OBJECT_0 + 1)) {
            errorCount++;
            if (errorCount >= 10) {
                SysmonLogError(
                    SYSMON_COMPONENT_CONFIG,
                    GetLastError(),
                    "Configuration monitor wait failed repeatedly, stopping monitor");
                break;
            }
            continue;
        }

        errorCount = 0;  /* Reset on success */

        if (WaitForSingleObject(g_ServiceCtx.StopEvent, 0) == WAIT_OBJECT_0) {
            break;
        }

        /* Send config notify to driver */
        status = SysmonSendConfigNotify(&g_ServiceCtx.Transport);
        if (status != SYSMON_SUCCESS) {
            if (WaitForSingleObject(g_ServiceCtx.StopEvent, 0) == WAIT_OBJECT_0) {
                break;
            }
            SysmonLogError(SYSMON_COMPONENT_CONFIG, status,
                "Failed to send config notify to driver");
        }

        /* Check for "Stop" value (admin-initiated stop) */
        {
            HKEY hParamsKey = NULL;
            status = SysmonOpenParametersKey(&hParamsKey, SYSMON_SERVICE_NAME, KEY_READ);
            if (status == SYSMON_SUCCESS) {
                DWORD stopVal = 0;
                if (SysmonRegReadDword(hParamsKey, L"Stop", &stopVal) == SYSMON_SUCCESS) {
                    /* Delete the Stop value */
                    RegDeleteValueW(hParamsKey, L"Stop");

                    /* Signal service to stop */
                    SetEvent(g_ServiceCtx.StopEvent);
                    RegCloseKey(hParamsKey);
                    break;
                }

                /* Reload configuration */
                {
                    SYSMON_CONFIG newConfig;
                    PSYSMON_RULE_RUNTIME newRuntime;
                    BOOL stopping;

                    ZeroMemory(&newConfig, sizeof(newConfig));
                    newRuntime = NULL;
                    if (SysmonConfigLoad(&newConfig, SYSMON_SERVICE_NAME) == SYSMON_SUCCESS) {
                        if (newConfig.Rules != NULL && newConfig.RulesSize != 0) {
                            status = SysmonLoadRuleRuntime(
                                newConfig.Rules,
                                newConfig.RulesSize,
                                &newRuntime);
                            if (status != SYSMON_SUCCESS) {
                                SysmonLogWarning(
                                    SYSMON_COMPONENT_CONFIG,
                                    "Failed to reload user-mode rule runtime: %lu",
                                    (unsigned long)status);
                                SysmonConfigFree(&newConfig);
                                SysmonFreeRuleRuntime(newRuntime);
                                RegCloseKey(hParamsKey);
                                continue;
                            }
                        }

                        stopping = (!g_ServiceCtx.Running) ||
                            (g_ServiceCtx.StopEvent != NULL &&
                                WaitForSingleObject(g_ServiceCtx.StopEvent, 0) == WAIT_OBJECT_0);
                        if (stopping) {
                            SysmonConfigFree(&newConfig);
                            SysmonFreeRuleRuntime(newRuntime);
                            RegCloseKey(hParamsKey);
                            break;
                        }

                        SysmonServiceApplyReloadedConfig(
                            &g_ServiceCtx,
                            &newConfig,
                            newRuntime);

                        SysmonLogInfo(SYSMON_COMPONENT_CONFIG, "Configuration reloaded");
                        SysmonTryFlushPendingConfigChangeEvent(SYSMON_SERVICE_NAME);
                        RegCloseKey(hParamsKey);
                        continue;
                    }
                }

                RegCloseKey(hParamsKey);
            }
        }
    }

    if (changeEvent != NULL) {
        CloseHandle(changeEvent);
    }
    RegCloseKey(hKey);
    SysmonLogInfo(SYSMON_COMPONENT_CONFIG, "Configuration monitor stopped");
    return 0;
}



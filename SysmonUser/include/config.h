#pragma once
/*
 * config.h - ConfigManager API, registry key definitions, Options/HashingAlgorithm bit enums
 */

#include "common.h"
#include "rules.h"

/* ========================================================================
 * Options Bitmask (REG_DWORD)
 * From Sysmon64.exe binary reverse engineering
 * ======================================================================== */
#define SYSMON_OPTION_NETWORK_CONNECT    0x01
#define SYSMON_OPTION_IMAGE_LOAD         0x02
#define SYSMON_OPTION_PIPE_MONITORING    0x04
#define SYSMON_OPTION_DRIVER_NAME        0x08

/* ========================================================================
 * HashingAlgorithm Bitmask (REG_DWORD)
 * ======================================================================== */
#define SYSMON_HASH_MD5                  0x01
#define SYSMON_HASH_SHA1                 0x02
#define SYSMON_HASH_SHA256               0x04
#define SYSMON_HASH_IMPHASH              0x08
#define SYSMON_HASH_DEFAULT              0x00

/* ========================================================================
 * Config Structure
 * ======================================================================== */
typedef struct _SYSMON_CONFIG {
    /* Options bitmask */
    DWORD Options;
    /* Hashing algorithm bitmask */
    DWORD HashingAlgorithm;
    /* Boolean options */
    BOOL CheckRevocation;
    BOOL DnsLookup;
    /* Numeric options */
    DWORD DriverQueueSize;
    DWORD SigningQueueSize;     /* Default 1000 */
    DWORD SigningWorkerCount;   /* Default 0 (auto) */
    /* String options */
    LPWSTR ConfigFile;
    LPWSTR ConfigHash;
    LPWSTR ArchiveDirectory;
    BOOL CopyOnDeletePE;
    LPWSTR CopyOnDeleteSIDs;
    LPWSTR CopyOnDeleteExtensions;
    LPWSTR CopyOnDeleteProcesses;
    /* Rules binary blob */
    PBYTE Rules;
    DWORD RulesSize;
    /* Parsed rule model */
    SYSMON_RULE_SET RuleSet;
    /* Field sizes string */
    LPWSTR FieldSizes;
    /* Process access monitoring */
    LPWSTR ProcessAccessNames;  /* MULTI_SZ */
    DWORD ProcessAccessNamesSize;
    PBYTE ProcessAccessMasks;
    DWORD ProcessAccessMasksSize;
} SYSMON_CONFIG, *PSYSMON_CONFIG;

#define SYSMON_REGVALUE_PENDING_CONFIG_EVENT_CONFIGURATION L"PendingConfigEventConfiguration"
#define SYSMON_REGVALUE_PENDING_CONFIG_EVENT_HASH          L"PendingConfigEventHash"

/* ========================================================================
 * Config API
 * ======================================================================== */

/*
 * SysmonConfigLoad - Read all configuration from registry
 *   Opens HKLM\SYSTEM\CurrentControlSet\Services\<ServiceName>\Parameters
 */
SYSMON_STATUS SysmonConfigLoad(
    _Out_ PSYSMON_CONFIG Config,
    _In_ LPCWSTR ServiceName);

/*
 * SysmonConfigFree - Free all allocated fields in config
 */
void SysmonConfigFree(_Inout_ PSYSMON_CONFIG Config);

/* Validate the persisted FieldSizes grammar and event field names. */
BOOL SysmonValidateFieldSizesText(_In_opt_z_ LPCWSTR Text);

/*
 * SysmonConfigFreeRuleSet - Free rule-model allocations owned by SYSMON_CONFIG.RuleSet
 */
void SysmonConfigFreeRuleSet(_Inout_ PSYSMON_RULE_SET RuleSet);

/*
 * SysmonConfigMonitorThread - Thread proc for registry change notification
 *   Monitors Parameters key, sends IOCTL 0x08 on changes
 *   Checks "Stop" value to trigger service shutdown
 */
DWORD WINAPI SysmonConfigMonitorThread(_In_ LPVOID Param);

/*
 * SysmonOpenParametersKey - Open the Parameters registry key
 */
SYSMON_STATUS SysmonOpenParametersKey(
    _Out_ PHKEY KeyHandle,
    _In_ LPCWSTR ServiceName,
    _In_ REGSAM DesiredAccess);

/*
 * SysmonRegReadDword - Read a REG_DWORD value
 */
SYSMON_STATUS SysmonRegReadDword(
    _In_ HKEY Key,
    _In_ LPCWSTR ValueName,
    _Out_ PDWORD Value);

/*
 * SysmonRegReadBool - Read a 1-byte REG_BINARY as boolean
 */
SYSMON_STATUS SysmonRegReadBool(
    _In_ HKEY Key,
    _In_ LPCWSTR ValueName,
    _Out_ PBOOL Value);

/*
 * SysmonRegReadString - Read a REG_SZ string (caller must free)
 */
SYSMON_STATUS SysmonRegReadString(
    _In_ HKEY Key,
    _In_ LPCWSTR ValueName,
    _Out_ LPWSTR *Value);

/*
 * SysmonRegReadBinary - Read a REG_BINARY value (caller must free)
 */
SYSMON_STATUS SysmonRegReadBinary(
    _In_ HKEY Key,
    _In_ LPCWSTR ValueName,
    _Out_ PBYTE *Value,
    _Out_ PDWORD ValueSize);

/*
 * SysmonConfigPersistCompiled - Serialize and persist the parsed config model
 *   Writes ConfigFile, ConfigHash, Rules, and related option values together.
 */
SYSMON_STATUS SysmonConfigPersistCompiled(
    _In_ LPCWSTR ServiceName,
    _In_opt_ LPCWSTR ConfigFilePath,
    _In_ const SYSMON_CONFIG *Config);

SYSMON_STATUS SysmonStagePendingConfigChangeEvent(
    _In_ LPCWSTR ServiceName,
    _In_opt_ LPCWSTR Configuration,
    _In_opt_ LPCWSTR ConfigurationFileHash);

void SysmonTryFlushPendingConfigChangeEvent(
    _In_ LPCWSTR ServiceName);

/*
 * SysmonParseXmlConfig - Parse a Sysmon XML config into the shared config/rule model
 *   Populates top-level options and RuleSet from an XML file on disk.
 */
SYSMON_STATUS SysmonParseXmlConfig(
    _In_ LPCWSTR XmlPath,
    _Out_ PSYSMON_CONFIG Config);

/*
 * SysmonFreeParsedXmlConfig - Free parser-owned allocations created by SysmonParseXmlConfig
 *   Compatibility wrapper around SysmonConfigFree for transient parsed configs.
 */
void SysmonFreeParsedXmlConfig(
    _Inout_ PSYSMON_CONFIG Config);

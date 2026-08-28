#include "event.h"
#include "process.h"
#include "utils.h"

static volatile LONG g_SequenceNumber = 0;
static volatile LONG g_CachedCurrentControlSet = 0;
static volatile LONG g_EventPoolInitialized = 0;
static NPAGED_LOOKASIDE_LIST g_EventLookaside;

typedef enum _SYSMON_FIELD_RENDER_KIND {
    SysmonFieldRenderStringRef = 1,
    SysmonFieldRenderUInt32,
    SysmonFieldRenderUInt32Hex,
    SysmonFieldRenderUInt64Hex,
    SysmonFieldRenderBool
} SYSMON_FIELD_RENDER_KIND;

typedef struct _SYSMON_EVENT_FIELD_DESCRIPTOR {
    PCWSTR FieldName;
    SYSMON_FIELD_RENDER_KIND Kind;
    USHORT Offset;
} SYSMON_EVENT_FIELD_DESCRIPTOR, *PSYSMON_EVENT_FIELD_DESCRIPTOR;

typedef struct _SYSMON_EVENT_SCHEMA {
    ULONG MinimumEventSize;
    const SYSMON_EVENT_FIELD_DESCRIPTOR *Fields;
    ULONG FieldCount;
} SYSMON_EVENT_SCHEMA, *PSYSMON_EVENT_SCHEMA;

#define FIELD_DESC(type, name, kind, member) \
    { name, kind, (USHORT)FIELD_OFFSET(type, member) }

static const SYSMON_EVENT_FIELD_DESCRIPTOR g_ProcessCreateFields[] = {
    FIELD_DESC(SYSMON_EVENT_PROCESS_CREATE_PAYLOAD, L"RuleName", SysmonFieldRenderStringRef, RuleName),
    FIELD_DESC(SYSMON_EVENT_PROCESS_CREATE_PAYLOAD, L"UtcTime", SysmonFieldRenderStringRef, UtcTime),
    FIELD_DESC(SYSMON_EVENT_PROCESS_CREATE_PAYLOAD, L"ProcessGuid", SysmonFieldRenderStringRef, ProcessGuid),
    FIELD_DESC(SYSMON_EVENT_PROCESS_CREATE_PAYLOAD, L"ProcessId", SysmonFieldRenderUInt32, ProcessId),
    FIELD_DESC(SYSMON_EVENT_PROCESS_CREATE_PAYLOAD, L"Image", SysmonFieldRenderStringRef, Image),
    FIELD_DESC(SYSMON_EVENT_PROCESS_CREATE_PAYLOAD, L"FileVersion", SysmonFieldRenderStringRef, FileVersion),
    FIELD_DESC(SYSMON_EVENT_PROCESS_CREATE_PAYLOAD, L"Description", SysmonFieldRenderStringRef, Description),
    FIELD_DESC(SYSMON_EVENT_PROCESS_CREATE_PAYLOAD, L"Product", SysmonFieldRenderStringRef, Product),
    FIELD_DESC(SYSMON_EVENT_PROCESS_CREATE_PAYLOAD, L"Company", SysmonFieldRenderStringRef, Company),
    FIELD_DESC(SYSMON_EVENT_PROCESS_CREATE_PAYLOAD, L"OriginalFileName", SysmonFieldRenderStringRef, OriginalFileName),
    FIELD_DESC(SYSMON_EVENT_PROCESS_CREATE_PAYLOAD, L"CommandLine", SysmonFieldRenderStringRef, CommandLine),
    FIELD_DESC(SYSMON_EVENT_PROCESS_CREATE_PAYLOAD, L"CurrentDirectory", SysmonFieldRenderStringRef, CurrentDirectory),
    FIELD_DESC(SYSMON_EVENT_PROCESS_CREATE_PAYLOAD, L"User", SysmonFieldRenderStringRef, User),
    FIELD_DESC(SYSMON_EVENT_PROCESS_CREATE_PAYLOAD, L"LogonGuid", SysmonFieldRenderStringRef, LogonGuid),
    FIELD_DESC(SYSMON_EVENT_PROCESS_CREATE_PAYLOAD, L"LogonId", SysmonFieldRenderUInt64Hex, LogonId),
    FIELD_DESC(SYSMON_EVENT_PROCESS_CREATE_PAYLOAD, L"TerminalSessionId", SysmonFieldRenderUInt32, TerminalSessionId),
    FIELD_DESC(SYSMON_EVENT_PROCESS_CREATE_PAYLOAD, L"IntegrityLevel", SysmonFieldRenderStringRef, IntegrityLevel),
    FIELD_DESC(SYSMON_EVENT_PROCESS_CREATE_PAYLOAD, L"Hashes", SysmonFieldRenderStringRef, Hashes),
    FIELD_DESC(SYSMON_EVENT_PROCESS_CREATE_PAYLOAD, L"ParentProcessGuid", SysmonFieldRenderStringRef, ParentProcessGuid),
    FIELD_DESC(SYSMON_EVENT_PROCESS_CREATE_PAYLOAD, L"ParentProcessId", SysmonFieldRenderUInt32, ParentProcessId),
    FIELD_DESC(SYSMON_EVENT_PROCESS_CREATE_PAYLOAD, L"ParentImage", SysmonFieldRenderStringRef, ParentImage),
    FIELD_DESC(SYSMON_EVENT_PROCESS_CREATE_PAYLOAD, L"ParentCommandLine", SysmonFieldRenderStringRef, ParentCommandLine),
    FIELD_DESC(SYSMON_EVENT_PROCESS_CREATE_PAYLOAD, L"ParentUser", SysmonFieldRenderStringRef, ParentUser),
};

static const SYSMON_EVENT_FIELD_DESCRIPTOR g_FileCreateTimeFields[] = {
    FIELD_DESC(SYSMON_EVENT_FILE_CREATE_TIME_PAYLOAD, L"RuleName", SysmonFieldRenderStringRef, RuleName),
    FIELD_DESC(SYSMON_EVENT_FILE_CREATE_TIME_PAYLOAD, L"UtcTime", SysmonFieldRenderStringRef, UtcTime),
    FIELD_DESC(SYSMON_EVENT_FILE_CREATE_TIME_PAYLOAD, L"ProcessGuid", SysmonFieldRenderStringRef, ProcessGuid),
    FIELD_DESC(SYSMON_EVENT_FILE_CREATE_TIME_PAYLOAD, L"ProcessId", SysmonFieldRenderUInt32, ProcessId),
    FIELD_DESC(SYSMON_EVENT_FILE_CREATE_TIME_PAYLOAD, L"Image", SysmonFieldRenderStringRef, Image),
    FIELD_DESC(SYSMON_EVENT_FILE_CREATE_TIME_PAYLOAD, L"TargetFilename", SysmonFieldRenderStringRef, TargetFilename),
    FIELD_DESC(SYSMON_EVENT_FILE_CREATE_TIME_PAYLOAD, L"CreationUtcTime", SysmonFieldRenderStringRef, CreationUtcTime),
    FIELD_DESC(SYSMON_EVENT_FILE_CREATE_TIME_PAYLOAD, L"PreviousCreationUtcTime", SysmonFieldRenderStringRef, PreviousCreationUtcTime),
    FIELD_DESC(SYSMON_EVENT_FILE_CREATE_TIME_PAYLOAD, L"User", SysmonFieldRenderStringRef, User),
};

static const SYSMON_EVENT_FIELD_DESCRIPTOR g_NetworkConnectFields[] = {
    FIELD_DESC(SYSMON_EVENT_NETWORK_CONNECT_PAYLOAD, L"RuleName", SysmonFieldRenderStringRef, RuleName),
    FIELD_DESC(SYSMON_EVENT_NETWORK_CONNECT_PAYLOAD, L"UtcTime", SysmonFieldRenderStringRef, UtcTime),
    FIELD_DESC(SYSMON_EVENT_NETWORK_CONNECT_PAYLOAD, L"ProcessGuid", SysmonFieldRenderStringRef, ProcessGuid),
    FIELD_DESC(SYSMON_EVENT_NETWORK_CONNECT_PAYLOAD, L"ProcessId", SysmonFieldRenderUInt32, ProcessId),
    FIELD_DESC(SYSMON_EVENT_NETWORK_CONNECT_PAYLOAD, L"Image", SysmonFieldRenderStringRef, Image),
    FIELD_DESC(SYSMON_EVENT_NETWORK_CONNECT_PAYLOAD, L"User", SysmonFieldRenderStringRef, User),
    FIELD_DESC(SYSMON_EVENT_NETWORK_CONNECT_PAYLOAD, L"Protocol", SysmonFieldRenderStringRef, Protocol),
    FIELD_DESC(SYSMON_EVENT_NETWORK_CONNECT_PAYLOAD, L"Initiated", SysmonFieldRenderBool, Initiated),
    FIELD_DESC(SYSMON_EVENT_NETWORK_CONNECT_PAYLOAD, L"SourceIsIpv6", SysmonFieldRenderBool, SourceIsIpv6),
    FIELD_DESC(SYSMON_EVENT_NETWORK_CONNECT_PAYLOAD, L"SourceIp", SysmonFieldRenderStringRef, SourceIp),
    FIELD_DESC(SYSMON_EVENT_NETWORK_CONNECT_PAYLOAD, L"SourceHostname", SysmonFieldRenderStringRef, SourceHostname),
    FIELD_DESC(SYSMON_EVENT_NETWORK_CONNECT_PAYLOAD, L"SourcePort", SysmonFieldRenderUInt32, SourcePort),
    FIELD_DESC(SYSMON_EVENT_NETWORK_CONNECT_PAYLOAD, L"SourcePortName", SysmonFieldRenderStringRef, SourcePortName),
    FIELD_DESC(SYSMON_EVENT_NETWORK_CONNECT_PAYLOAD, L"DestinationIsIpv6", SysmonFieldRenderBool, DestinationIsIpv6),
    FIELD_DESC(SYSMON_EVENT_NETWORK_CONNECT_PAYLOAD, L"DestinationIp", SysmonFieldRenderStringRef, DestinationIp),
    FIELD_DESC(SYSMON_EVENT_NETWORK_CONNECT_PAYLOAD, L"DestinationHostname", SysmonFieldRenderStringRef, DestinationHostname),
    FIELD_DESC(SYSMON_EVENT_NETWORK_CONNECT_PAYLOAD, L"DestinationPort", SysmonFieldRenderUInt32, DestinationPort),
    FIELD_DESC(SYSMON_EVENT_NETWORK_CONNECT_PAYLOAD, L"DestinationPortName", SysmonFieldRenderStringRef, DestinationPortName),
};

static const SYSMON_EVENT_FIELD_DESCRIPTOR g_ServiceStateFields[] = {
    FIELD_DESC(SYSMON_EVENT_SERVICE_STATE_PAYLOAD, L"UtcTime", SysmonFieldRenderStringRef, UtcTime),
    FIELD_DESC(SYSMON_EVENT_SERVICE_STATE_PAYLOAD, L"State", SysmonFieldRenderStringRef, State),
    FIELD_DESC(SYSMON_EVENT_SERVICE_STATE_PAYLOAD, L"Version", SysmonFieldRenderStringRef, Version),
    FIELD_DESC(SYSMON_EVENT_SERVICE_STATE_PAYLOAD, L"SchemaVersion", SysmonFieldRenderStringRef, SchemaVersion),
};

static const SYSMON_EVENT_FIELD_DESCRIPTOR g_ProcessTerminateFields[] = {
    FIELD_DESC(SYSMON_EVENT_PROCESS_TERMINATE_PAYLOAD, L"RuleName", SysmonFieldRenderStringRef, RuleName),
    FIELD_DESC(SYSMON_EVENT_PROCESS_TERMINATE_PAYLOAD, L"UtcTime", SysmonFieldRenderStringRef, UtcTime),
    FIELD_DESC(SYSMON_EVENT_PROCESS_TERMINATE_PAYLOAD, L"ProcessGuid", SysmonFieldRenderStringRef, ProcessGuid),
    FIELD_DESC(SYSMON_EVENT_PROCESS_TERMINATE_PAYLOAD, L"ProcessId", SysmonFieldRenderUInt32, ProcessId),
    FIELD_DESC(SYSMON_EVENT_PROCESS_TERMINATE_PAYLOAD, L"Image", SysmonFieldRenderStringRef, Image),
    FIELD_DESC(SYSMON_EVENT_PROCESS_TERMINATE_PAYLOAD, L"User", SysmonFieldRenderStringRef, User),
};

static const SYSMON_EVENT_FIELD_DESCRIPTOR g_DriverLoadFields[] = {
    FIELD_DESC(SYSMON_EVENT_DRIVER_LOAD_PAYLOAD, L"RuleName", SysmonFieldRenderStringRef, RuleName),
    FIELD_DESC(SYSMON_EVENT_DRIVER_LOAD_PAYLOAD, L"UtcTime", SysmonFieldRenderStringRef, UtcTime),
    FIELD_DESC(SYSMON_EVENT_DRIVER_LOAD_PAYLOAD, L"ImageLoaded", SysmonFieldRenderStringRef, ImageLoaded),
    FIELD_DESC(SYSMON_EVENT_DRIVER_LOAD_PAYLOAD, L"Hashes", SysmonFieldRenderStringRef, Hashes),
    FIELD_DESC(SYSMON_EVENT_DRIVER_LOAD_PAYLOAD, L"Signed", SysmonFieldRenderBool, Signed),
    FIELD_DESC(SYSMON_EVENT_DRIVER_LOAD_PAYLOAD, L"Signature", SysmonFieldRenderStringRef, Signature),
    FIELD_DESC(SYSMON_EVENT_DRIVER_LOAD_PAYLOAD, L"SignatureStatus", SysmonFieldRenderStringRef, SignatureStatus),
};

static const SYSMON_EVENT_FIELD_DESCRIPTOR g_ImageLoadFields[] = {
    FIELD_DESC(SYSMON_EVENT_IMAGE_LOAD_PAYLOAD, L"RuleName", SysmonFieldRenderStringRef, RuleName),
    FIELD_DESC(SYSMON_EVENT_IMAGE_LOAD_PAYLOAD, L"UtcTime", SysmonFieldRenderStringRef, UtcTime),
    FIELD_DESC(SYSMON_EVENT_IMAGE_LOAD_PAYLOAD, L"ProcessGuid", SysmonFieldRenderStringRef, ProcessGuid),
    FIELD_DESC(SYSMON_EVENT_IMAGE_LOAD_PAYLOAD, L"ProcessId", SysmonFieldRenderUInt32, ProcessId),
    FIELD_DESC(SYSMON_EVENT_IMAGE_LOAD_PAYLOAD, L"Image", SysmonFieldRenderStringRef, Image),
    FIELD_DESC(SYSMON_EVENT_IMAGE_LOAD_PAYLOAD, L"ImageLoaded", SysmonFieldRenderStringRef, ImageLoaded),
    FIELD_DESC(SYSMON_EVENT_IMAGE_LOAD_PAYLOAD, L"FileVersion", SysmonFieldRenderStringRef, FileVersion),
    FIELD_DESC(SYSMON_EVENT_IMAGE_LOAD_PAYLOAD, L"Description", SysmonFieldRenderStringRef, Description),
    FIELD_DESC(SYSMON_EVENT_IMAGE_LOAD_PAYLOAD, L"Product", SysmonFieldRenderStringRef, Product),
    FIELD_DESC(SYSMON_EVENT_IMAGE_LOAD_PAYLOAD, L"Company", SysmonFieldRenderStringRef, Company),
    FIELD_DESC(SYSMON_EVENT_IMAGE_LOAD_PAYLOAD, L"OriginalFileName", SysmonFieldRenderStringRef, OriginalFileName),
    FIELD_DESC(SYSMON_EVENT_IMAGE_LOAD_PAYLOAD, L"Hashes", SysmonFieldRenderStringRef, Hashes),
    FIELD_DESC(SYSMON_EVENT_IMAGE_LOAD_PAYLOAD, L"Signed", SysmonFieldRenderBool, Signed),
    FIELD_DESC(SYSMON_EVENT_IMAGE_LOAD_PAYLOAD, L"Signature", SysmonFieldRenderStringRef, Signature),
    FIELD_DESC(SYSMON_EVENT_IMAGE_LOAD_PAYLOAD, L"SignatureStatus", SysmonFieldRenderStringRef, SignatureStatus),
    FIELD_DESC(SYSMON_EVENT_IMAGE_LOAD_PAYLOAD, L"User", SysmonFieldRenderStringRef, User),
};

static const SYSMON_EVENT_FIELD_DESCRIPTOR g_CreateRemoteThreadFields[] = {
    FIELD_DESC(SYSMON_EVENT_CREATE_REMOTE_THREAD_PAYLOAD, L"RuleName", SysmonFieldRenderStringRef, RuleName),
    FIELD_DESC(SYSMON_EVENT_CREATE_REMOTE_THREAD_PAYLOAD, L"UtcTime", SysmonFieldRenderStringRef, UtcTime),
    FIELD_DESC(SYSMON_EVENT_CREATE_REMOTE_THREAD_PAYLOAD, L"SourceProcessGuid", SysmonFieldRenderStringRef, SourceProcessGuid),
    FIELD_DESC(SYSMON_EVENT_CREATE_REMOTE_THREAD_PAYLOAD, L"SourceProcessId", SysmonFieldRenderUInt32, SourceProcessId),
    FIELD_DESC(SYSMON_EVENT_CREATE_REMOTE_THREAD_PAYLOAD, L"SourceImage", SysmonFieldRenderStringRef, SourceImage),
    FIELD_DESC(SYSMON_EVENT_CREATE_REMOTE_THREAD_PAYLOAD, L"TargetProcessGuid", SysmonFieldRenderStringRef, TargetProcessGuid),
    FIELD_DESC(SYSMON_EVENT_CREATE_REMOTE_THREAD_PAYLOAD, L"TargetProcessId", SysmonFieldRenderUInt32, TargetProcessId),
    FIELD_DESC(SYSMON_EVENT_CREATE_REMOTE_THREAD_PAYLOAD, L"TargetImage", SysmonFieldRenderStringRef, TargetImage),
    FIELD_DESC(SYSMON_EVENT_CREATE_REMOTE_THREAD_PAYLOAD, L"NewThreadId", SysmonFieldRenderUInt32, NewThreadId),
    FIELD_DESC(SYSMON_EVENT_CREATE_REMOTE_THREAD_PAYLOAD, L"StartAddress", SysmonFieldRenderUInt64Hex, StartAddress),
    FIELD_DESC(SYSMON_EVENT_CREATE_REMOTE_THREAD_PAYLOAD, L"StartModule", SysmonFieldRenderStringRef, StartModule),
    FIELD_DESC(SYSMON_EVENT_CREATE_REMOTE_THREAD_PAYLOAD, L"StartFunction", SysmonFieldRenderStringRef, StartFunction),
    FIELD_DESC(SYSMON_EVENT_CREATE_REMOTE_THREAD_PAYLOAD, L"SourceUser", SysmonFieldRenderStringRef, SourceUser),
    FIELD_DESC(SYSMON_EVENT_CREATE_REMOTE_THREAD_PAYLOAD, L"TargetUser", SysmonFieldRenderStringRef, TargetUser),
};

static const SYSMON_EVENT_FIELD_DESCRIPTOR g_RawAccessReadFields[] = {
    FIELD_DESC(SYSMON_EVENT_RAW_ACCESS_READ_PAYLOAD, L"RuleName", SysmonFieldRenderStringRef, RuleName),
    FIELD_DESC(SYSMON_EVENT_RAW_ACCESS_READ_PAYLOAD, L"UtcTime", SysmonFieldRenderStringRef, UtcTime),
    FIELD_DESC(SYSMON_EVENT_RAW_ACCESS_READ_PAYLOAD, L"ProcessGuid", SysmonFieldRenderStringRef, ProcessGuid),
    FIELD_DESC(SYSMON_EVENT_RAW_ACCESS_READ_PAYLOAD, L"ProcessId", SysmonFieldRenderUInt32, ProcessId),
    FIELD_DESC(SYSMON_EVENT_RAW_ACCESS_READ_PAYLOAD, L"Image", SysmonFieldRenderStringRef, Image),
    FIELD_DESC(SYSMON_EVENT_RAW_ACCESS_READ_PAYLOAD, L"Device", SysmonFieldRenderStringRef, Device),
    FIELD_DESC(SYSMON_EVENT_RAW_ACCESS_READ_PAYLOAD, L"User", SysmonFieldRenderStringRef, User),
};

static const SYSMON_EVENT_FIELD_DESCRIPTOR g_ProcessAccessFields[] = {
    FIELD_DESC(SYSMON_EVENT_PROCESS_ACCESS_PAYLOAD, L"RuleName", SysmonFieldRenderStringRef, RuleName),
    FIELD_DESC(SYSMON_EVENT_PROCESS_ACCESS_PAYLOAD, L"UtcTime", SysmonFieldRenderStringRef, UtcTime),
    FIELD_DESC(SYSMON_EVENT_PROCESS_ACCESS_PAYLOAD, L"SourceProcessGUID", SysmonFieldRenderStringRef, SourceProcessGUID),
    FIELD_DESC(SYSMON_EVENT_PROCESS_ACCESS_PAYLOAD, L"SourceProcessId", SysmonFieldRenderUInt32, SourceProcessId),
    FIELD_DESC(SYSMON_EVENT_PROCESS_ACCESS_PAYLOAD, L"SourceThreadId", SysmonFieldRenderUInt32, SourceThreadId),
    FIELD_DESC(SYSMON_EVENT_PROCESS_ACCESS_PAYLOAD, L"SourceImage", SysmonFieldRenderStringRef, SourceImage),
    FIELD_DESC(SYSMON_EVENT_PROCESS_ACCESS_PAYLOAD, L"TargetProcessGUID", SysmonFieldRenderStringRef, TargetProcessGUID),
    FIELD_DESC(SYSMON_EVENT_PROCESS_ACCESS_PAYLOAD, L"TargetProcessId", SysmonFieldRenderUInt32, TargetProcessId),
    FIELD_DESC(SYSMON_EVENT_PROCESS_ACCESS_PAYLOAD, L"TargetImage", SysmonFieldRenderStringRef, TargetImage),
    FIELD_DESC(SYSMON_EVENT_PROCESS_ACCESS_PAYLOAD, L"GrantedAccess", SysmonFieldRenderUInt32Hex, GrantedAccess),
    FIELD_DESC(SYSMON_EVENT_PROCESS_ACCESS_PAYLOAD, L"CallTrace", SysmonFieldRenderStringRef, CallTrace),
    FIELD_DESC(SYSMON_EVENT_PROCESS_ACCESS_PAYLOAD, L"SourceUser", SysmonFieldRenderStringRef, SourceUser),
    FIELD_DESC(SYSMON_EVENT_PROCESS_ACCESS_PAYLOAD, L"TargetUser", SysmonFieldRenderStringRef, TargetUser),
};

static const SYSMON_EVENT_FIELD_DESCRIPTOR g_FileCreateFields[] = {
    FIELD_DESC(SYSMON_EVENT_FILE_CREATE_PAYLOAD, L"RuleName", SysmonFieldRenderStringRef, RuleName),
    FIELD_DESC(SYSMON_EVENT_FILE_CREATE_PAYLOAD, L"UtcTime", SysmonFieldRenderStringRef, UtcTime),
    FIELD_DESC(SYSMON_EVENT_FILE_CREATE_PAYLOAD, L"ProcessGuid", SysmonFieldRenderStringRef, ProcessGuid),
    FIELD_DESC(SYSMON_EVENT_FILE_CREATE_PAYLOAD, L"ProcessId", SysmonFieldRenderUInt32, ProcessId),
    FIELD_DESC(SYSMON_EVENT_FILE_CREATE_PAYLOAD, L"Image", SysmonFieldRenderStringRef, Image),
    FIELD_DESC(SYSMON_EVENT_FILE_CREATE_PAYLOAD, L"TargetFilename", SysmonFieldRenderStringRef, TargetFilename),
    FIELD_DESC(SYSMON_EVENT_FILE_CREATE_PAYLOAD, L"CreationUtcTime", SysmonFieldRenderStringRef, CreationUtcTime),
    FIELD_DESC(SYSMON_EVENT_FILE_CREATE_PAYLOAD, L"User", SysmonFieldRenderStringRef, User),
};

static const SYSMON_EVENT_FIELD_DESCRIPTOR g_RegistryEventFields[] = {
    FIELD_DESC(SYSMON_EVENT_REGISTRY_EVENT_PAYLOAD, L"RuleName", SysmonFieldRenderStringRef, RuleName),
    FIELD_DESC(SYSMON_EVENT_REGISTRY_EVENT_PAYLOAD, L"EventType", SysmonFieldRenderStringRef, EventType),
    FIELD_DESC(SYSMON_EVENT_REGISTRY_EVENT_PAYLOAD, L"UtcTime", SysmonFieldRenderStringRef, UtcTime),
    FIELD_DESC(SYSMON_EVENT_REGISTRY_EVENT_PAYLOAD, L"ProcessGuid", SysmonFieldRenderStringRef, ProcessGuid),
    FIELD_DESC(SYSMON_EVENT_REGISTRY_EVENT_PAYLOAD, L"ProcessId", SysmonFieldRenderUInt32, ProcessId),
    FIELD_DESC(SYSMON_EVENT_REGISTRY_EVENT_PAYLOAD, L"Image", SysmonFieldRenderStringRef, Image),
    FIELD_DESC(SYSMON_EVENT_REGISTRY_EVENT_PAYLOAD, L"TargetObject", SysmonFieldRenderStringRef, TargetObject),
    FIELD_DESC(SYSMON_EVENT_REGISTRY_EVENT_PAYLOAD, L"User", SysmonFieldRenderStringRef, User),
};

static const SYSMON_EVENT_FIELD_DESCRIPTOR g_RegistryValueSetFields[] = {
    FIELD_DESC(SYSMON_EVENT_REGISTRY_VALUE_SET_PAYLOAD, L"RuleName", SysmonFieldRenderStringRef, RuleName),
    FIELD_DESC(SYSMON_EVENT_REGISTRY_VALUE_SET_PAYLOAD, L"EventType", SysmonFieldRenderStringRef, EventType),
    FIELD_DESC(SYSMON_EVENT_REGISTRY_VALUE_SET_PAYLOAD, L"UtcTime", SysmonFieldRenderStringRef, UtcTime),
    FIELD_DESC(SYSMON_EVENT_REGISTRY_VALUE_SET_PAYLOAD, L"ProcessGuid", SysmonFieldRenderStringRef, ProcessGuid),
    FIELD_DESC(SYSMON_EVENT_REGISTRY_VALUE_SET_PAYLOAD, L"ProcessId", SysmonFieldRenderUInt32, ProcessId),
    FIELD_DESC(SYSMON_EVENT_REGISTRY_VALUE_SET_PAYLOAD, L"Image", SysmonFieldRenderStringRef, Image),
    FIELD_DESC(SYSMON_EVENT_REGISTRY_VALUE_SET_PAYLOAD, L"TargetObject", SysmonFieldRenderStringRef, TargetObject),
    FIELD_DESC(SYSMON_EVENT_REGISTRY_VALUE_SET_PAYLOAD, L"Details", SysmonFieldRenderStringRef, Details),
    FIELD_DESC(SYSMON_EVENT_REGISTRY_VALUE_SET_PAYLOAD, L"User", SysmonFieldRenderStringRef, User),
};

static const SYSMON_EVENT_FIELD_DESCRIPTOR g_RegistryRenameFields[] = {
    FIELD_DESC(SYSMON_EVENT_REGISTRY_RENAME_PAYLOAD, L"RuleName", SysmonFieldRenderStringRef, RuleName),
    FIELD_DESC(SYSMON_EVENT_REGISTRY_RENAME_PAYLOAD, L"EventType", SysmonFieldRenderStringRef, EventType),
    FIELD_DESC(SYSMON_EVENT_REGISTRY_RENAME_PAYLOAD, L"UtcTime", SysmonFieldRenderStringRef, UtcTime),
    FIELD_DESC(SYSMON_EVENT_REGISTRY_RENAME_PAYLOAD, L"ProcessGuid", SysmonFieldRenderStringRef, ProcessGuid),
    FIELD_DESC(SYSMON_EVENT_REGISTRY_RENAME_PAYLOAD, L"ProcessId", SysmonFieldRenderUInt32, ProcessId),
    FIELD_DESC(SYSMON_EVENT_REGISTRY_RENAME_PAYLOAD, L"Image", SysmonFieldRenderStringRef, Image),
    FIELD_DESC(SYSMON_EVENT_REGISTRY_RENAME_PAYLOAD, L"TargetObject", SysmonFieldRenderStringRef, TargetObject),
    FIELD_DESC(SYSMON_EVENT_REGISTRY_RENAME_PAYLOAD, L"NewName", SysmonFieldRenderStringRef, NewName),
    FIELD_DESC(SYSMON_EVENT_REGISTRY_RENAME_PAYLOAD, L"User", SysmonFieldRenderStringRef, User),
};

static const SYSMON_EVENT_FIELD_DESCRIPTOR g_FileCreateStreamHashFields[] = {
    FIELD_DESC(SYSMON_EVENT_FILE_CREATE_STREAM_HASH_PAYLOAD, L"RuleName", SysmonFieldRenderStringRef, RuleName),
    FIELD_DESC(SYSMON_EVENT_FILE_CREATE_STREAM_HASH_PAYLOAD, L"UtcTime", SysmonFieldRenderStringRef, UtcTime),
    FIELD_DESC(SYSMON_EVENT_FILE_CREATE_STREAM_HASH_PAYLOAD, L"ProcessGuid", SysmonFieldRenderStringRef, ProcessGuid),
    FIELD_DESC(SYSMON_EVENT_FILE_CREATE_STREAM_HASH_PAYLOAD, L"ProcessId", SysmonFieldRenderUInt32, ProcessId),
    FIELD_DESC(SYSMON_EVENT_FILE_CREATE_STREAM_HASH_PAYLOAD, L"Image", SysmonFieldRenderStringRef, Image),
    FIELD_DESC(SYSMON_EVENT_FILE_CREATE_STREAM_HASH_PAYLOAD, L"TargetFilename", SysmonFieldRenderStringRef, TargetFilename),
    FIELD_DESC(SYSMON_EVENT_FILE_CREATE_STREAM_HASH_PAYLOAD, L"CreationUtcTime", SysmonFieldRenderStringRef, CreationUtcTime),
    FIELD_DESC(SYSMON_EVENT_FILE_CREATE_STREAM_HASH_PAYLOAD, L"Hash", SysmonFieldRenderStringRef, Hash),
    FIELD_DESC(SYSMON_EVENT_FILE_CREATE_STREAM_HASH_PAYLOAD, L"Contents", SysmonFieldRenderStringRef, Contents),
    FIELD_DESC(SYSMON_EVENT_FILE_CREATE_STREAM_HASH_PAYLOAD, L"User", SysmonFieldRenderStringRef, User),
};

static const SYSMON_EVENT_FIELD_DESCRIPTOR g_ConfigChangeFields[] = {
    FIELD_DESC(SYSMON_EVENT_CONFIG_CHANGE_PAYLOAD, L"UtcTime", SysmonFieldRenderStringRef, UtcTime),
    FIELD_DESC(SYSMON_EVENT_CONFIG_CHANGE_PAYLOAD, L"Configuration", SysmonFieldRenderStringRef, Configuration),
    FIELD_DESC(SYSMON_EVENT_CONFIG_CHANGE_PAYLOAD, L"ConfigurationFileHash", SysmonFieldRenderStringRef, ConfigurationFileHash),
};

static const SYSMON_EVENT_FIELD_DESCRIPTOR g_PipeFields[] = {
    FIELD_DESC(SYSMON_EVENT_PIPE_PAYLOAD, L"RuleName", SysmonFieldRenderStringRef, RuleName),
    FIELD_DESC(SYSMON_EVENT_PIPE_PAYLOAD, L"EventType", SysmonFieldRenderStringRef, EventType),
    FIELD_DESC(SYSMON_EVENT_PIPE_PAYLOAD, L"UtcTime", SysmonFieldRenderStringRef, UtcTime),
    FIELD_DESC(SYSMON_EVENT_PIPE_PAYLOAD, L"ProcessGuid", SysmonFieldRenderStringRef, ProcessGuid),
    FIELD_DESC(SYSMON_EVENT_PIPE_PAYLOAD, L"ProcessId", SysmonFieldRenderUInt32, ProcessId),
    FIELD_DESC(SYSMON_EVENT_PIPE_PAYLOAD, L"PipeName", SysmonFieldRenderStringRef, PipeName),
    FIELD_DESC(SYSMON_EVENT_PIPE_PAYLOAD, L"Image", SysmonFieldRenderStringRef, Image),
    FIELD_DESC(SYSMON_EVENT_PIPE_PAYLOAD, L"User", SysmonFieldRenderStringRef, User),
};

static const SYSMON_EVENT_FIELD_DESCRIPTOR g_PipeCreatedFields[] = {
    FIELD_DESC(SYSMON_EVENT_PIPE_CREATED_PAYLOAD, L"RuleName", SysmonFieldRenderStringRef, RuleName),
    FIELD_DESC(SYSMON_EVENT_PIPE_CREATED_PAYLOAD, L"EventType", SysmonFieldRenderStringRef, EventType),
    FIELD_DESC(SYSMON_EVENT_PIPE_CREATED_PAYLOAD, L"UtcTime", SysmonFieldRenderStringRef, UtcTime),
    FIELD_DESC(SYSMON_EVENT_PIPE_CREATED_PAYLOAD, L"ProcessGuid", SysmonFieldRenderStringRef, ProcessGuid),
    FIELD_DESC(SYSMON_EVENT_PIPE_CREATED_PAYLOAD, L"ProcessId", SysmonFieldRenderUInt32, ProcessId),
    FIELD_DESC(SYSMON_EVENT_PIPE_CREATED_PAYLOAD, L"PipeName", SysmonFieldRenderStringRef, PipeName),
    FIELD_DESC(SYSMON_EVENT_PIPE_CREATED_PAYLOAD, L"Image", SysmonFieldRenderStringRef, Image),
    FIELD_DESC(SYSMON_EVENT_PIPE_CREATED_PAYLOAD, L"User", SysmonFieldRenderStringRef, User),
};

static const SYSMON_EVENT_FIELD_DESCRIPTOR g_WmiFilterFields[] = {
    FIELD_DESC(SYSMON_EVENT_WMI_FILTER_PAYLOAD, L"RuleName", SysmonFieldRenderStringRef, RuleName),
    FIELD_DESC(SYSMON_EVENT_WMI_FILTER_PAYLOAD, L"EventType", SysmonFieldRenderStringRef, EventType),
    FIELD_DESC(SYSMON_EVENT_WMI_FILTER_PAYLOAD, L"UtcTime", SysmonFieldRenderStringRef, UtcTime),
    FIELD_DESC(SYSMON_EVENT_WMI_FILTER_PAYLOAD, L"Operation", SysmonFieldRenderStringRef, Operation),
    FIELD_DESC(SYSMON_EVENT_WMI_FILTER_PAYLOAD, L"User", SysmonFieldRenderStringRef, User),
    FIELD_DESC(SYSMON_EVENT_WMI_FILTER_PAYLOAD, L"EventNamespace", SysmonFieldRenderStringRef, EventNamespace),
    FIELD_DESC(SYSMON_EVENT_WMI_FILTER_PAYLOAD, L"Name", SysmonFieldRenderStringRef, Name),
    FIELD_DESC(SYSMON_EVENT_WMI_FILTER_PAYLOAD, L"Query", SysmonFieldRenderStringRef, Query),
};

static const SYSMON_EVENT_FIELD_DESCRIPTOR g_WmiConsumerFields[] = {
    FIELD_DESC(SYSMON_EVENT_WMI_CONSUMER_PAYLOAD, L"RuleName", SysmonFieldRenderStringRef, RuleName),
    FIELD_DESC(SYSMON_EVENT_WMI_CONSUMER_PAYLOAD, L"EventType", SysmonFieldRenderStringRef, EventType),
    FIELD_DESC(SYSMON_EVENT_WMI_CONSUMER_PAYLOAD, L"UtcTime", SysmonFieldRenderStringRef, UtcTime),
    FIELD_DESC(SYSMON_EVENT_WMI_CONSUMER_PAYLOAD, L"Operation", SysmonFieldRenderStringRef, Operation),
    FIELD_DESC(SYSMON_EVENT_WMI_CONSUMER_PAYLOAD, L"User", SysmonFieldRenderStringRef, User),
    FIELD_DESC(SYSMON_EVENT_WMI_CONSUMER_PAYLOAD, L"Name", SysmonFieldRenderStringRef, Name),
    FIELD_DESC(SYSMON_EVENT_WMI_CONSUMER_PAYLOAD, L"Type", SysmonFieldRenderStringRef, Type),
    FIELD_DESC(SYSMON_EVENT_WMI_CONSUMER_PAYLOAD, L"Destination", SysmonFieldRenderStringRef, Destination),
};

static const SYSMON_EVENT_FIELD_DESCRIPTOR g_WmiConsumerToFilterFields[] = {
    FIELD_DESC(SYSMON_EVENT_WMI_CONSUMER_TO_FILTER_PAYLOAD, L"RuleName", SysmonFieldRenderStringRef, RuleName),
    FIELD_DESC(SYSMON_EVENT_WMI_CONSUMER_TO_FILTER_PAYLOAD, L"EventType", SysmonFieldRenderStringRef, EventType),
    FIELD_DESC(SYSMON_EVENT_WMI_CONSUMER_TO_FILTER_PAYLOAD, L"UtcTime", SysmonFieldRenderStringRef, UtcTime),
    FIELD_DESC(SYSMON_EVENT_WMI_CONSUMER_TO_FILTER_PAYLOAD, L"Operation", SysmonFieldRenderStringRef, Operation),
    FIELD_DESC(SYSMON_EVENT_WMI_CONSUMER_TO_FILTER_PAYLOAD, L"User", SysmonFieldRenderStringRef, User),
    FIELD_DESC(SYSMON_EVENT_WMI_CONSUMER_TO_FILTER_PAYLOAD, L"Consumer", SysmonFieldRenderStringRef, Consumer),
    FIELD_DESC(SYSMON_EVENT_WMI_CONSUMER_TO_FILTER_PAYLOAD, L"Filter", SysmonFieldRenderStringRef, Filter),
};

static const SYSMON_EVENT_FIELD_DESCRIPTOR g_DnsQueryFields[] = {
    FIELD_DESC(SYSMON_EVENT_DNS_QUERY_PAYLOAD, L"RuleName", SysmonFieldRenderStringRef, RuleName),
    FIELD_DESC(SYSMON_EVENT_DNS_QUERY_PAYLOAD, L"UtcTime", SysmonFieldRenderStringRef, UtcTime),
    FIELD_DESC(SYSMON_EVENT_DNS_QUERY_PAYLOAD, L"ProcessGuid", SysmonFieldRenderStringRef, ProcessGuid),
    FIELD_DESC(SYSMON_EVENT_DNS_QUERY_PAYLOAD, L"ProcessId", SysmonFieldRenderUInt32, ProcessId),
    FIELD_DESC(SYSMON_EVENT_DNS_QUERY_PAYLOAD, L"QueryName", SysmonFieldRenderStringRef, QueryName),
    FIELD_DESC(SYSMON_EVENT_DNS_QUERY_PAYLOAD, L"QueryStatus", SysmonFieldRenderStringRef, QueryStatus),
    FIELD_DESC(SYSMON_EVENT_DNS_QUERY_PAYLOAD, L"QueryResults", SysmonFieldRenderStringRef, QueryResults),
    FIELD_DESC(SYSMON_EVENT_DNS_QUERY_PAYLOAD, L"Image", SysmonFieldRenderStringRef, Image),
    FIELD_DESC(SYSMON_EVENT_DNS_QUERY_PAYLOAD, L"User", SysmonFieldRenderStringRef, User),
};

static const SYSMON_EVENT_FIELD_DESCRIPTOR g_FileDeleteFields[] = {
    FIELD_DESC(SYSMON_EVENT_FILE_DELETE_PAYLOAD, L"RuleName", SysmonFieldRenderStringRef, RuleName),
    FIELD_DESC(SYSMON_EVENT_FILE_DELETE_PAYLOAD, L"UtcTime", SysmonFieldRenderStringRef, UtcTime),
    FIELD_DESC(SYSMON_EVENT_FILE_DELETE_PAYLOAD, L"ProcessGuid", SysmonFieldRenderStringRef, ProcessGuid),
    FIELD_DESC(SYSMON_EVENT_FILE_DELETE_PAYLOAD, L"ProcessId", SysmonFieldRenderUInt32, ProcessId),
    FIELD_DESC(SYSMON_EVENT_FILE_DELETE_PAYLOAD, L"User", SysmonFieldRenderStringRef, User),
    FIELD_DESC(SYSMON_EVENT_FILE_DELETE_PAYLOAD, L"Image", SysmonFieldRenderStringRef, Image),
    FIELD_DESC(SYSMON_EVENT_FILE_DELETE_PAYLOAD, L"TargetFilename", SysmonFieldRenderStringRef, TargetFilename),
    FIELD_DESC(SYSMON_EVENT_FILE_DELETE_PAYLOAD, L"Hashes", SysmonFieldRenderStringRef, Hashes),
    FIELD_DESC(SYSMON_EVENT_FILE_DELETE_PAYLOAD, L"IsExecutable", SysmonFieldRenderBool, IsExecutable),
    FIELD_DESC(SYSMON_EVENT_FILE_DELETE_PAYLOAD, L"Archived", SysmonFieldRenderBool, Archived),
};

static const SYSMON_EVENT_FIELD_DESCRIPTOR g_ClipboardChangeFields[] = {
    FIELD_DESC(SYSMON_EVENT_CLIPBOARD_CHANGE_PAYLOAD, L"RuleName", SysmonFieldRenderStringRef, RuleName),
    FIELD_DESC(SYSMON_EVENT_CLIPBOARD_CHANGE_PAYLOAD, L"UtcTime", SysmonFieldRenderStringRef, UtcTime),
    FIELD_DESC(SYSMON_EVENT_CLIPBOARD_CHANGE_PAYLOAD, L"ProcessGuid", SysmonFieldRenderStringRef, ProcessGuid),
    FIELD_DESC(SYSMON_EVENT_CLIPBOARD_CHANGE_PAYLOAD, L"ProcessId", SysmonFieldRenderUInt32, ProcessId),
    FIELD_DESC(SYSMON_EVENT_CLIPBOARD_CHANGE_PAYLOAD, L"Image", SysmonFieldRenderStringRef, Image),
    FIELD_DESC(SYSMON_EVENT_CLIPBOARD_CHANGE_PAYLOAD, L"Session", SysmonFieldRenderUInt32, Session),
    FIELD_DESC(SYSMON_EVENT_CLIPBOARD_CHANGE_PAYLOAD, L"ClientInfo", SysmonFieldRenderStringRef, ClientInfo),
    FIELD_DESC(SYSMON_EVENT_CLIPBOARD_CHANGE_PAYLOAD, L"Hashes", SysmonFieldRenderStringRef, Hashes),
    FIELD_DESC(SYSMON_EVENT_CLIPBOARD_CHANGE_PAYLOAD, L"Archived", SysmonFieldRenderBool, Archived),
    FIELD_DESC(SYSMON_EVENT_CLIPBOARD_CHANGE_PAYLOAD, L"User", SysmonFieldRenderStringRef, User),
};

static const SYSMON_EVENT_FIELD_DESCRIPTOR g_ProcessTamperingFields[] = {
    FIELD_DESC(SYSMON_EVENT_PROCESS_TAMPERING_PAYLOAD, L"RuleName", SysmonFieldRenderStringRef, RuleName),
    FIELD_DESC(SYSMON_EVENT_PROCESS_TAMPERING_PAYLOAD, L"UtcTime", SysmonFieldRenderStringRef, UtcTime),
    FIELD_DESC(SYSMON_EVENT_PROCESS_TAMPERING_PAYLOAD, L"ProcessGuid", SysmonFieldRenderStringRef, ProcessGuid),
    FIELD_DESC(SYSMON_EVENT_PROCESS_TAMPERING_PAYLOAD, L"ProcessId", SysmonFieldRenderUInt32, ProcessId),
    FIELD_DESC(SYSMON_EVENT_PROCESS_TAMPERING_PAYLOAD, L"Image", SysmonFieldRenderStringRef, Image),
    FIELD_DESC(SYSMON_EVENT_PROCESS_TAMPERING_PAYLOAD, L"Type", SysmonFieldRenderStringRef, Type),
    FIELD_DESC(SYSMON_EVENT_PROCESS_TAMPERING_PAYLOAD, L"User", SysmonFieldRenderStringRef, User),
};

static const SYSMON_EVENT_FIELD_DESCRIPTOR g_FileBlockFields[] = {
    FIELD_DESC(SYSMON_EVENT_FILE_BLOCK_PAYLOAD, L"RuleName", SysmonFieldRenderStringRef, RuleName),
    FIELD_DESC(SYSMON_EVENT_FILE_BLOCK_PAYLOAD, L"UtcTime", SysmonFieldRenderStringRef, UtcTime),
    FIELD_DESC(SYSMON_EVENT_FILE_BLOCK_PAYLOAD, L"ProcessGuid", SysmonFieldRenderStringRef, ProcessGuid),
    FIELD_DESC(SYSMON_EVENT_FILE_BLOCK_PAYLOAD, L"ProcessId", SysmonFieldRenderUInt32, ProcessId),
    FIELD_DESC(SYSMON_EVENT_FILE_BLOCK_PAYLOAD, L"User", SysmonFieldRenderStringRef, User),
    FIELD_DESC(SYSMON_EVENT_FILE_BLOCK_PAYLOAD, L"Image", SysmonFieldRenderStringRef, Image),
    FIELD_DESC(SYSMON_EVENT_FILE_BLOCK_PAYLOAD, L"TargetFilename", SysmonFieldRenderStringRef, TargetFilename),
    FIELD_DESC(SYSMON_EVENT_FILE_BLOCK_PAYLOAD, L"Hashes", SysmonFieldRenderStringRef, Hashes),
    FIELD_DESC(SYSMON_EVENT_FILE_BLOCK_PAYLOAD, L"IsExecutable", SysmonFieldRenderBool, IsExecutable),
};

static const SYSMON_EVENT_FIELD_DESCRIPTOR g_FileHashFields[] = {
    FIELD_DESC(SYSMON_EVENT_FILE_HASH_PAYLOAD, L"RuleName", SysmonFieldRenderStringRef, RuleName),
    FIELD_DESC(SYSMON_EVENT_FILE_HASH_PAYLOAD, L"UtcTime", SysmonFieldRenderStringRef, UtcTime),
    FIELD_DESC(SYSMON_EVENT_FILE_HASH_PAYLOAD, L"ProcessGuid", SysmonFieldRenderStringRef, ProcessGuid),
    FIELD_DESC(SYSMON_EVENT_FILE_HASH_PAYLOAD, L"ProcessId", SysmonFieldRenderUInt32, ProcessId),
    FIELD_DESC(SYSMON_EVENT_FILE_HASH_PAYLOAD, L"User", SysmonFieldRenderStringRef, User),
    FIELD_DESC(SYSMON_EVENT_FILE_HASH_PAYLOAD, L"Image", SysmonFieldRenderStringRef, Image),
    FIELD_DESC(SYSMON_EVENT_FILE_HASH_PAYLOAD, L"TargetFilename", SysmonFieldRenderStringRef, TargetFilename),
    FIELD_DESC(SYSMON_EVENT_FILE_HASH_PAYLOAD, L"Hashes", SysmonFieldRenderStringRef, Hashes),
};

static const SYSMON_EVENT_SCHEMA g_ProcessCreateSchema = {
    SYSMON_EVENT_CONTRACT_SIZE(SYSMON_EVENT_PROCESS_CREATE_PAYLOAD),
    g_ProcessCreateFields,
    RTL_NUMBER_OF(g_ProcessCreateFields)
};
static const SYSMON_EVENT_SCHEMA g_FileCreateTimeSchema = {
    SYSMON_EVENT_CONTRACT_SIZE(SYSMON_EVENT_FILE_CREATE_TIME_PAYLOAD),
    g_FileCreateTimeFields,
    RTL_NUMBER_OF(g_FileCreateTimeFields)
};
static const SYSMON_EVENT_SCHEMA g_NetworkConnectSchema = {
    SYSMON_EVENT_CONTRACT_SIZE(SYSMON_EVENT_NETWORK_CONNECT_PAYLOAD),
    g_NetworkConnectFields,
    RTL_NUMBER_OF(g_NetworkConnectFields)
};
static const SYSMON_EVENT_SCHEMA g_ServiceStateSchema = {
    SYSMON_EVENT_CONTRACT_SIZE(SYSMON_EVENT_SERVICE_STATE_PAYLOAD),
    g_ServiceStateFields,
    RTL_NUMBER_OF(g_ServiceStateFields)
};
static const SYSMON_EVENT_SCHEMA g_ProcessTerminateSchema = {
    SYSMON_EVENT_CONTRACT_SIZE(SYSMON_EVENT_PROCESS_TERMINATE_PAYLOAD),
    g_ProcessTerminateFields,
    RTL_NUMBER_OF(g_ProcessTerminateFields)
};
static const SYSMON_EVENT_SCHEMA g_DriverLoadSchema = {
    SYSMON_EVENT_CONTRACT_SIZE(SYSMON_EVENT_DRIVER_LOAD_PAYLOAD),
    g_DriverLoadFields,
    RTL_NUMBER_OF(g_DriverLoadFields)
};
static const SYSMON_EVENT_SCHEMA g_ImageLoadSchema = {
    SYSMON_EVENT_CONTRACT_SIZE(SYSMON_EVENT_IMAGE_LOAD_PAYLOAD),
    g_ImageLoadFields,
    RTL_NUMBER_OF(g_ImageLoadFields)
};
static const SYSMON_EVENT_SCHEMA g_CreateRemoteThreadSchema = {
    SYSMON_EVENT_CONTRACT_SIZE(SYSMON_EVENT_CREATE_REMOTE_THREAD_PAYLOAD),
    g_CreateRemoteThreadFields,
    RTL_NUMBER_OF(g_CreateRemoteThreadFields)
};
static const SYSMON_EVENT_SCHEMA g_RawAccessReadSchema = {
    SYSMON_EVENT_CONTRACT_SIZE(SYSMON_EVENT_RAW_ACCESS_READ_PAYLOAD),
    g_RawAccessReadFields,
    RTL_NUMBER_OF(g_RawAccessReadFields)
};
static const SYSMON_EVENT_SCHEMA g_ProcessAccessSchema = {
    SYSMON_EVENT_CONTRACT_SIZE(SYSMON_EVENT_PROCESS_ACCESS_PAYLOAD),
    g_ProcessAccessFields,
    RTL_NUMBER_OF(g_ProcessAccessFields)
};
static const SYSMON_EVENT_SCHEMA g_FileCreateSchema = {
    SYSMON_EVENT_CONTRACT_SIZE(SYSMON_EVENT_FILE_CREATE_PAYLOAD),
    g_FileCreateFields,
    RTL_NUMBER_OF(g_FileCreateFields)
};
static const SYSMON_EVENT_SCHEMA g_RegistryEventSchema = {
    SYSMON_EVENT_CONTRACT_SIZE(SYSMON_EVENT_REGISTRY_EVENT_PAYLOAD),
    g_RegistryEventFields,
    RTL_NUMBER_OF(g_RegistryEventFields)
};
static const SYSMON_EVENT_SCHEMA g_RegistryValueSetSchema = {
    SYSMON_EVENT_CONTRACT_SIZE(SYSMON_EVENT_REGISTRY_VALUE_SET_PAYLOAD),
    g_RegistryValueSetFields,
    RTL_NUMBER_OF(g_RegistryValueSetFields)
};
static const SYSMON_EVENT_SCHEMA g_RegistryRenameSchema = {
    SYSMON_EVENT_CONTRACT_SIZE(SYSMON_EVENT_REGISTRY_RENAME_PAYLOAD),
    g_RegistryRenameFields,
    RTL_NUMBER_OF(g_RegistryRenameFields)
};
static const SYSMON_EVENT_SCHEMA g_FileCreateStreamHashSchema = {
    SYSMON_EVENT_CONTRACT_SIZE(SYSMON_EVENT_FILE_CREATE_STREAM_HASH_PAYLOAD),
    g_FileCreateStreamHashFields,
    RTL_NUMBER_OF(g_FileCreateStreamHashFields)
};
static const SYSMON_EVENT_SCHEMA g_ConfigChangeSchema = {
    SYSMON_EVENT_CONTRACT_SIZE(SYSMON_EVENT_CONFIG_CHANGE_PAYLOAD),
    g_ConfigChangeFields,
    RTL_NUMBER_OF(g_ConfigChangeFields)
};
static const SYSMON_EVENT_SCHEMA g_PipeSchema = {
    SYSMON_EVENT_CONTRACT_SIZE(SYSMON_EVENT_PIPE_PAYLOAD),
    g_PipeFields,
    RTL_NUMBER_OF(g_PipeFields)
};
static const SYSMON_EVENT_SCHEMA g_PipeCreatedSchema = {
    SYSMON_EVENT_CONTRACT_SIZE(SYSMON_EVENT_PIPE_CREATED_PAYLOAD),
    g_PipeCreatedFields,
    RTL_NUMBER_OF(g_PipeCreatedFields)
};
static const SYSMON_EVENT_SCHEMA g_WmiFilterSchema = {
    SYSMON_EVENT_CONTRACT_SIZE(SYSMON_EVENT_WMI_FILTER_PAYLOAD),
    g_WmiFilterFields,
    RTL_NUMBER_OF(g_WmiFilterFields)
};
static const SYSMON_EVENT_SCHEMA g_WmiConsumerSchema = {
    SYSMON_EVENT_CONTRACT_SIZE(SYSMON_EVENT_WMI_CONSUMER_PAYLOAD),
    g_WmiConsumerFields,
    RTL_NUMBER_OF(g_WmiConsumerFields)
};
static const SYSMON_EVENT_SCHEMA g_WmiConsumerToFilterSchema = {
    SYSMON_EVENT_CONTRACT_SIZE(SYSMON_EVENT_WMI_CONSUMER_TO_FILTER_PAYLOAD),
    g_WmiConsumerToFilterFields,
    RTL_NUMBER_OF(g_WmiConsumerToFilterFields)
};
static const SYSMON_EVENT_SCHEMA g_DnsQuerySchema = {
    SYSMON_EVENT_CONTRACT_SIZE(SYSMON_EVENT_DNS_QUERY_PAYLOAD),
    g_DnsQueryFields,
    RTL_NUMBER_OF(g_DnsQueryFields)
};
static const SYSMON_EVENT_SCHEMA g_FileDeleteSchema = {
    SYSMON_EVENT_CONTRACT_SIZE(SYSMON_EVENT_FILE_DELETE_PAYLOAD),
    g_FileDeleteFields,
    RTL_NUMBER_OF(g_FileDeleteFields)
};
static const SYSMON_EVENT_SCHEMA g_ClipboardChangeSchema = {
    SYSMON_EVENT_CONTRACT_SIZE(SYSMON_EVENT_CLIPBOARD_CHANGE_PAYLOAD),
    g_ClipboardChangeFields,
    RTL_NUMBER_OF(g_ClipboardChangeFields)
};
static const SYSMON_EVENT_SCHEMA g_ProcessTamperingSchema = {
    SYSMON_EVENT_CONTRACT_SIZE(SYSMON_EVENT_PROCESS_TAMPERING_PAYLOAD),
    g_ProcessTamperingFields,
    RTL_NUMBER_OF(g_ProcessTamperingFields)
};
static const SYSMON_EVENT_SCHEMA g_FileBlockSchema = {
    SYSMON_EVENT_CONTRACT_SIZE(SYSMON_EVENT_FILE_BLOCK_PAYLOAD),
    g_FileBlockFields,
    RTL_NUMBER_OF(g_FileBlockFields)
};
static const SYSMON_EVENT_SCHEMA g_FileHashSchema = {
    SYSMON_EVENT_CONTRACT_SIZE(SYSMON_EVENT_FILE_HASH_PAYLOAD),
    g_FileHashFields,
    RTL_NUMBER_OF(g_FileHashFields)
};

static BOOLEAN
SysmonFormatHexUlonglong(
    _In_ ULONGLONG Value,
    _Out_writes_(BufferChars) PWCHAR Buffer,
    _In_ ULONG BufferChars)
{
    WCHAR digits[16];
    ULONG index;
    ULONG firstNonZero;
    ULONG outIndex;

    if (Buffer == NULL || BufferChars < 4) {
        return FALSE;
    }

    for (index = 0; index < RTL_NUMBER_OF(digits); index++) {
        ULONG shift = (ULONG)((RTL_NUMBER_OF(digits) - 1 - index) * 4);
        digits[index] = L"0123456789abcdef"[(Value >> shift) & 0x0F];
    }

    firstNonZero = 0;
    while (firstNonZero < RTL_NUMBER_OF(digits) - 1 && digits[firstNonZero] == L'0') {
        firstNonZero++;
    }

    if (BufferChars < 3 + (RTL_NUMBER_OF(digits) - firstNonZero)) {
        return FALSE;
    }

    Buffer[0] = L'0';
    Buffer[1] = L'x';
    outIndex = 2;
    for (index = firstNonZero; index < RTL_NUMBER_OF(digits); index++) {
        Buffer[outIndex++] = digits[index];
    }
    Buffer[outIndex] = L'\0';

    return TRUE;
}

static BOOLEAN
SysmonCopyLiteralString(
    _Out_writes_(BufferChars) PWCHAR Buffer,
    _In_ ULONG BufferChars,
    _In_z_ PCWSTR Value)
{
    SIZE_T chars;

    if (Buffer == NULL || BufferChars == 0 || Value == NULL) {
        return FALSE;
    }

    chars = wcslen(Value);
    if (chars >= BufferChars) {
        return FALSE;
    }

    RtlCopyMemory(Buffer, Value, (chars + 1) * sizeof(WCHAR));
    return TRUE;
}

static BOOLEAN
SysmonFormatUInt32(
    _In_ ULONG Value,
    _Out_writes_(BufferChars) PWCHAR Buffer,
    _In_ ULONG BufferChars,
    _In_ ULONG Base)
{
    UNICODE_STRING bufferString;

    if (Buffer == NULL || BufferChars == 0) {
        return FALSE;
    }

    bufferString.Buffer = Buffer;
    bufferString.Length = 0;
    bufferString.MaximumLength = (USHORT)(BufferChars * sizeof(WCHAR));
    return NT_SUCCESS(RtlIntegerToUnicodeString(Value, Base, &bufferString));
}

static BOOLEAN
SysmonFormatBoolean(
    _In_ BOOLEAN Value,
    _Out_writes_(BufferChars) PWCHAR Buffer,
    _In_ ULONG BufferChars)
{
    return SysmonCopyLiteralString(Buffer, BufferChars, Value ? L"true" : L"false");
}

static PCWSTR
SysmonNormalizeFieldName(
    _In_ PCWSTR FieldName)
{
    if (FieldName == NULL || FieldName[0] == L'\0') {
        return NULL;
    }

    switch (FieldName[0]) {
    case L'U':
    case L'u':
        if (_wcsicmp(FieldName, L"UTCTime") == 0) {
            return L"UtcTime";
        }
        if (_wcsicmp(FieldName, L"UserSid") == 0) {
            return L"User";
        }
        break;
    case L'D':
    case L'd':
        if (_wcsicmp(FieldName, L"DestIp") == 0) {
            return L"DestinationIp";
        }
        if (_wcsicmp(FieldName, L"DestPort") == 0) {
            return L"DestinationPort";
        }
        if (_wcsicmp(FieldName, L"DestHostname") == 0) {
            return L"DestinationHostname";
        }
        break;
    case L'Q':
    case L'q':
        if (_wcsicmp(FieldName, L"QueryResultString") == 0) {
            return L"QueryResults";
        }
        break;
    case L'C':
    case L'c':
        if (_wcsicmp(FieldName, L"Connected") == 0) {
            return L"Initiated";
        }
        break;
    default:
        break;
    }

    return FieldName;
}

static BOOLEAN
SysmonIsRegistryRuleField(
    _In_ SYSMON_EVENT_ID EventId,
    _In_ PCWSTR FieldName)
{
    if (FieldName == NULL) {
        return FALSE;
    }

    if (EventId != SysmonEventRegistryEvent &&
        EventId != SysmonEventRegistryValueSet &&
        EventId != SysmonEventRegistryRename) {
        return FALSE;
    }

    return _wcsicmp(FieldName, L"TargetObject") == 0 ||
        _wcsicmp(FieldName, L"NewName") == 0;
}

static BOOLEAN
SysmonEventFieldNameMatches(
    _In_ SYSMON_EVENT_ID EventId,
    _In_ PCWSTR NormalizedFieldName,
    _In_ PCWSTR SchemaFieldName)
{
    if (_wcsicmp(NormalizedFieldName, SchemaFieldName) == 0) {
        return TRUE;
    }

    if (EventId != SysmonEventProcessAccess) {
        return FALSE;
    }

    /*
     * ProcessAccess historically accepts both Guid and GUID spellings while
     * the payload schema stores the uppercase-GUID field names.
     */
    return ((_wcsicmp(NormalizedFieldName, L"SourceProcessGuid") == 0 ||
             _wcsicmp(NormalizedFieldName, L"SourceProcessGUID") == 0) &&
            _wcsicmp(SchemaFieldName, L"SourceProcessGUID") == 0) ||
           ((_wcsicmp(NormalizedFieldName, L"TargetProcessGuid") == 0 ||
             _wcsicmp(NormalizedFieldName, L"TargetProcessGUID") == 0) &&
            _wcsicmp(SchemaFieldName, L"TargetProcessGUID") == 0);
}

static BOOLEAN
SysmonQueryCurrentControlSetName(
    _Out_writes_(BufferChars) PWCHAR Buffer,
    _In_ ULONG BufferChars)
{
    static const WCHAR g_SelectPath[] = L"\\Registry\\Machine\\System\\Select";
    LONG cachedCurrent;
    UCHAR valueBuffer[sizeof(KEY_VALUE_PARTIAL_INFORMATION) + sizeof(ULONG)];
    UNICODE_STRING keyPath;
    UNICODE_STRING valueName;
    OBJECT_ATTRIBUTES attributes;
    HANDLE keyHandle = NULL;
    PKEY_VALUE_PARTIAL_INFORMATION valueInfo;
    ULONG resultLength;
    ULONG current = 0;
    NTSTATUS status;

    if (Buffer == NULL || BufferChars < 16) {
        return FALSE;
    }

    cachedCurrent = InterlockedCompareExchange(&g_CachedCurrentControlSet, 0, 0);
    if (cachedCurrent != 0) {
        _snwprintf_s(Buffer, BufferChars, _TRUNCATE, L"ControlSet%03lu", (ULONG)cachedCurrent);
        return TRUE;
    }

    Buffer[0] = L'\0';
    RtlInitUnicodeString(&keyPath, g_SelectPath);
    InitializeObjectAttributes(
        &attributes,
        &keyPath,
        OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
        NULL,
        NULL);

    status = ZwOpenKey(&keyHandle, KEY_QUERY_VALUE, &attributes);
    if (!NT_SUCCESS(status)) {
        return FALSE;
    }

    RtlInitUnicodeString(&valueName, L"Current");
    RtlZeroMemory(valueBuffer, sizeof(valueBuffer));
    resultLength = 0;
    status = ZwQueryValueKey(
        keyHandle,
        &valueName,
        KeyValuePartialInformation,
        valueBuffer,
        sizeof(valueBuffer),
        &resultLength);
    ZwClose(keyHandle);
    if (!NT_SUCCESS(status)) {
        return FALSE;
    }

    valueInfo = (PKEY_VALUE_PARTIAL_INFORMATION)valueBuffer;
    if (valueInfo->Type != REG_DWORD ||
        valueInfo->DataLength < sizeof(ULONG)) {
        return FALSE;
    }

    RtlCopyMemory(&current, valueInfo->Data, sizeof(current));
    cachedCurrent = InterlockedCompareExchange(&g_CachedCurrentControlSet, (LONG)current, 0);
    if (cachedCurrent == 0) {
        cachedCurrent = (LONG)current;
    }
    _snwprintf_s(Buffer, BufferChars, _TRUNCATE, L"ControlSet%03lu", (ULONG)cachedCurrent);
    return TRUE;
}

static VOID
SysmonNormalizeRegistryFieldForMatching(
    _Inout_updates_(BufferChars) PWCHAR Buffer,
    _In_ ULONG BufferChars)
{
    static const WCHAR g_NativePrefix[] = L"\\REGISTRY\\";
    static const WCHAR g_Hklm[] = L"HKLM";
    static const WCHAR g_HkeyLocalMachine[] = L"HKEY_LOCAL_MACHINE";
    static const WCHAR g_Hku[] = L"HKU";
    static const WCHAR g_HkeyUsers[] = L"HKEY_USERS";
    static const WCHAR g_Hkcr[] = L"HKCR";
    static const WCHAR g_HkeyClassesRoot[] = L"HKEY_CLASSES_ROOT";
    static const WCHAR g_MachineRoot[] = L"\\REGISTRY\\MACHINE";
    static const WCHAR g_UserRoot[] = L"\\REGISTRY\\USER";
    static const WCHAR g_ClassesRoot[] = L"\\REGISTRY\\MACHINE\\SOFTWARE\\Classes";
    static const WCHAR g_CurrentControlSetPrefix[] =
        L"\\REGISTRY\\MACHINE\\SYSTEM\\CurrentControlSet";
    static const WCHAR g_HardwareProfilesPrefix[] =
        L"\\REGISTRY\\MACHINE\\SYSTEM\\CurrentControlSet\\Hardware Profiles\\Current";
    WCHAR normalized[SYSMON_MAX_CMDLINE];
    WCHAR controlSetName[16];
    PCWSTR source;
    PCWSTR nativeRoot;
    PCWSTR suffix;
    SIZE_T nativeRootChars;
    SIZE_T suffixChars;

    if (Buffer == NULL || BufferChars == 0 || Buffer[0] == L'\0') {
        return;
    }

    source = Buffer;
    nativeRoot = NULL;
    suffix = NULL;
    normalized[0] = L'\0';

    switch (source[0]) {
    case L'\\':
        if (_wcsnicmp(source, g_NativePrefix, RTL_NUMBER_OF(g_NativePrefix) - 1) == 0) {
            (void)SysmonCopyLiteralString(normalized, RTL_NUMBER_OF(normalized), source);
        }
        break;
    case L'H':
    case L'h':
        if (_wcsnicmp(source, g_HkeyLocalMachine, RTL_NUMBER_OF(g_HkeyLocalMachine) - 1) == 0 &&
            (source[RTL_NUMBER_OF(g_HkeyLocalMachine) - 1] == L'\0' ||
             source[RTL_NUMBER_OF(g_HkeyLocalMachine) - 1] == L'\\')) {
            nativeRoot = g_MachineRoot;
            suffix = source + RTL_NUMBER_OF(g_HkeyLocalMachine) - 1;
        } else if (_wcsnicmp(source, g_Hklm, RTL_NUMBER_OF(g_Hklm) - 1) == 0 &&
                   (source[RTL_NUMBER_OF(g_Hklm) - 1] == L'\0' ||
                    source[RTL_NUMBER_OF(g_Hklm) - 1] == L'\\')) {
            nativeRoot = g_MachineRoot;
            suffix = source + RTL_NUMBER_OF(g_Hklm) - 1;
        } else if (_wcsnicmp(source, g_HkeyUsers, RTL_NUMBER_OF(g_HkeyUsers) - 1) == 0 &&
                   (source[RTL_NUMBER_OF(g_HkeyUsers) - 1] == L'\0' ||
                    source[RTL_NUMBER_OF(g_HkeyUsers) - 1] == L'\\')) {
            nativeRoot = g_UserRoot;
            suffix = source + RTL_NUMBER_OF(g_HkeyUsers) - 1;
        } else if (_wcsnicmp(source, g_Hku, RTL_NUMBER_OF(g_Hku) - 1) == 0 &&
                   (source[RTL_NUMBER_OF(g_Hku) - 1] == L'\0' ||
                    source[RTL_NUMBER_OF(g_Hku) - 1] == L'\\')) {
            nativeRoot = g_UserRoot;
            suffix = source + RTL_NUMBER_OF(g_Hku) - 1;
        } else if (_wcsnicmp(source, g_HkeyClassesRoot, RTL_NUMBER_OF(g_HkeyClassesRoot) - 1) == 0 &&
                   (source[RTL_NUMBER_OF(g_HkeyClassesRoot) - 1] == L'\0' ||
                    source[RTL_NUMBER_OF(g_HkeyClassesRoot) - 1] == L'\\')) {
            nativeRoot = g_ClassesRoot;
            suffix = source + RTL_NUMBER_OF(g_HkeyClassesRoot) - 1;
        } else if (_wcsnicmp(source, g_Hkcr, RTL_NUMBER_OF(g_Hkcr) - 1) == 0 &&
                   (source[RTL_NUMBER_OF(g_Hkcr) - 1] == L'\0' ||
                    source[RTL_NUMBER_OF(g_Hkcr) - 1] == L'\\')) {
            nativeRoot = g_ClassesRoot;
            suffix = source + RTL_NUMBER_OF(g_Hkcr) - 1;
        }
        break;
    default:
        break;
    }

    if (nativeRoot != NULL && suffix != NULL) {
        nativeRootChars = wcslen(nativeRoot);
        suffixChars = wcslen(suffix);
        if (nativeRootChars + suffixChars >= RTL_NUMBER_OF(normalized)) {
            suffixChars = RTL_NUMBER_OF(normalized) - nativeRootChars - 1;
        }

        RtlCopyMemory(normalized, nativeRoot, nativeRootChars * sizeof(WCHAR));
        RtlCopyMemory(normalized + nativeRootChars, suffix, suffixChars * sizeof(WCHAR));
        normalized[nativeRootChars + suffixChars] = L'\0';
    }

    if (normalized[0] == L'\0') {
        return;
    }

    if (_wcsnicmp(
            normalized,
            g_CurrentControlSetPrefix,
            RTL_NUMBER_OF(g_CurrentControlSetPrefix) - 1) == 0 &&
        _wcsnicmp(
            normalized,
            g_HardwareProfilesPrefix,
            RTL_NUMBER_OF(g_HardwareProfilesPrefix) - 1) != 0 &&
        SysmonQueryCurrentControlSetName(controlSetName, RTL_NUMBER_OF(controlSetName))) {
        suffix = normalized + RTL_NUMBER_OF(g_CurrentControlSetPrefix) - 1;
        _snwprintf_s(
            Buffer,
            BufferChars,
            _TRUNCATE,
            L"\\REGISTRY\\MACHINE\\SYSTEM\\%ls%ls",
            controlSetName,
            suffix);
        return;
    }

    (void)SysmonCopyLiteralString(Buffer, BufferChars, normalized);
}

static const SYSMON_EVENT_SCHEMA *
SysmonGetEventSchema(
    _In_ SYSMON_EVENT_ID EventId)
{
    switch (EventId) {
    case SysmonEventProcessCreate:
        return &g_ProcessCreateSchema;
    case SysmonEventFileCreateTime:
        return &g_FileCreateTimeSchema;
    case SysmonEventNetworkConnect:
        return &g_NetworkConnectSchema;
    case SysmonEventServiceState:
        return &g_ServiceStateSchema;
    case SysmonEventProcessTerminate:
        return &g_ProcessTerminateSchema;
    case SysmonEventDriverLoad:
        return &g_DriverLoadSchema;
    case SysmonEventImageLoad:
        return &g_ImageLoadSchema;
    case SysmonEventCreateRemoteThread:
        return &g_CreateRemoteThreadSchema;
    case SysmonEventRawAccessRead:
        return &g_RawAccessReadSchema;
    case SysmonEventProcessAccess:
        return &g_ProcessAccessSchema;
    case SysmonEventFileCreate:
        return &g_FileCreateSchema;
    case SysmonEventRegistryEvent:
        return &g_RegistryEventSchema;
    case SysmonEventRegistryValueSet:
        return &g_RegistryValueSetSchema;
    case SysmonEventRegistryRename:
        return &g_RegistryRenameSchema;
    case SysmonEventFileCreateStreamHash:
        return &g_FileCreateStreamHashSchema;
    case SysmonEventConfigChange:
        return &g_ConfigChangeSchema;
    case SysmonEventPipeCreated:
        return &g_PipeCreatedSchema;
    case SysmonEventPipeConnected:
        return &g_PipeSchema;
    case SysmonEventWmiFilter:
        return &g_WmiFilterSchema;
    case SysmonEventWmiConsumer:
        return &g_WmiConsumerSchema;
    case SysmonEventWmiConsumerToFilter:
        return &g_WmiConsumerToFilterSchema;
    case SysmonEventDnsQuery:
        return &g_DnsQuerySchema;
    case SysmonEventFileDelete:
        return &g_FileDeleteSchema;
    case SysmonEventClipboardChange:
        return &g_ClipboardChangeSchema;
    case SysmonEventProcessTampering:
        return &g_ProcessTamperingSchema;
    case SysmonEventFileDeleteDetected:
    case SysmonEventFileBlockShredding:
        return &g_FileBlockSchema;
    case SysmonEventFileBlockExecutable:
    case SysmonEventFileExecutableDetected:
        return &g_FileHashSchema;
    default:
        return NULL;
    }
}

PSYSMON_EVENT_UNION
SysmonAllocateEvent(SYSMON_EVENT_ID EventId)
{
    PSYSMON_EVENT_UNION event;

    if (InterlockedCompareExchange(&g_EventPoolInitialized, 0, 0) != 0) {
        event = (PSYSMON_EVENT_UNION)ExAllocateFromNPagedLookasideList(&g_EventLookaside);
    } else {
        event = (PSYSMON_EVENT_UNION)SysmonAllocatePoolWithTag(
            sizeof(SYSMON_EVENT_UNION),
            SYSMON_EVENT_TAG);
    }
    if (event == NULL) {
        return NULL;
    }

    RtlZeroMemory(event, sizeof(SYSMON_EVENT_UNION));
    event->Header.EventId = (ULONG)EventId;
    event->Header.EventSize = sizeof(SYSMON_EVENT_UNION);
    event->Header.SequenceNumber = (ULONG)InterlockedIncrement(&g_SequenceNumber);
    event->Header.Timestamp = SysmonGetCurrentTimestamp();

    return event;
}

VOID
SysmonFreeEvent(_In_opt_ PSYSMON_EVENT_UNION Event)
{
    if (Event == NULL) {
        return;
    }

    if (InterlockedCompareExchange(&g_EventPoolInitialized, 0, 0) != 0) {
        ExFreeToNPagedLookasideList(&g_EventLookaside, Event);
    } else {
        SysmonFreePoolWithTag(Event, SYSMON_EVENT_TAG);
    }
}

VOID
SysmonInitializeEventPool(VOID)
{
    if (InterlockedCompareExchange(&g_EventPoolInitialized, 1, 0) != 0) {
        return;
    }

    ExInitializeNPagedLookasideList(
        &g_EventLookaside,
        NULL,
        NULL,
        0,
        sizeof(SYSMON_EVENT_UNION),
        SYSMON_EVENT_TAG,
        0);
}

VOID
SysmonCleanupEventPool(VOID)
{
    if (InterlockedExchange(&g_EventPoolInitialized, 0) == 0) {
        return;
    }

    ExDeleteNPagedLookasideList(&g_EventLookaside);
}

VOID
SysmonBeginStringPayload(
    _Inout_ PSYSMON_EVENT_UNION Event,
    _In_ ULONG PayloadSize,
    _Out_ PSYSMON_EVENT_PAYLOAD_BUILDER Builder)
{
    if (Event == NULL || Builder == NULL) {
        return;
    }

    /*
     * SysmonAllocateEvent has already zeroed the entire SYSMON_EVENT_UNION
     * (including RawData) via RtlZeroMemory. Skip the redundant per-field
     * zeroing here to avoid ~4KB memset on the event hot path.
     */
    Builder->PayloadSize = PayloadSize;
    Builder->Cursor = PayloadSize;
    Event->Header.EventSize = (ULONG)(sizeof(SYSMON_EVENT_HEADER) + PayloadSize);
}

NTSTATUS
SysmonAddStringFieldWithLength(
    _Inout_ PSYSMON_EVENT_UNION Event,
    _Inout_ PSYSMON_EVENT_PAYLOAD_BUILDER Builder,
    _Out_ SYSMON_EVENT_STRING_REF *Ref,
    _In_reads_or_z_(SourceChars) PCWSTR Source,
    _In_ SIZE_T SourceChars)
{
    ULONG bytes;
    ULONG bytesWithTerminator;
    PUCHAR destination;
    BOOLEAN truncated = FALSE;

    if (Event == NULL || Builder == NULL || Ref == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    Ref->Offset = 0;
    Ref->LengthBytes = 0;

    if (Source == NULL || Source[0] == L'\0') {
        return STATUS_SUCCESS;
    }

    if (SourceChars > (MAXULONG / sizeof(WCHAR))) {
        return STATUS_INVALID_BUFFER_SIZE;
    }

    bytes = (ULONG)(SourceChars * sizeof(WCHAR));
    bytesWithTerminator = bytes + sizeof(WCHAR);

    if (Builder->Cursor > SYSMON_EVENT_DATA_SIZE ||
        SYSMON_EVENT_DATA_SIZE - Builder->Cursor < sizeof(WCHAR)) {
        DbgPrintEx(
            DPFLTR_DEFAULT_ID,
            DPFLTR_WARNING_LEVEL,
            "[SysmonDrv] Event %lu string field dropped: payload full\n",
            Event->Header.EventId);
        return STATUS_BUFFER_TOO_SMALL;
    }

    if (bytesWithTerminator > SYSMON_EVENT_DATA_SIZE - Builder->Cursor) {
        bytes = (SYSMON_EVENT_DATA_SIZE - Builder->Cursor) - sizeof(WCHAR);
        bytes -= bytes % sizeof(WCHAR);
        bytesWithTerminator = bytes + sizeof(WCHAR);
        truncated = TRUE;
    }

    destination = Event->RawData + Builder->Cursor;
    RtlCopyMemory(destination, Source, bytes);
    RtlZeroMemory(destination + bytes, sizeof(WCHAR));

    Ref->Offset = Builder->Cursor;
    Ref->LengthBytes = bytes;
    Builder->Cursor += bytesWithTerminator;
    Event->Header.EventSize = (ULONG)(sizeof(SYSMON_EVENT_HEADER) + Builder->Cursor);

    if (truncated) {
        DbgPrintEx(
            DPFLTR_DEFAULT_ID,
            DPFLTR_WARNING_LEVEL,
            "[SysmonDrv] Event %lu string field truncated to %lu bytes\n",
            Event->Header.EventId,
            bytes);
        return STATUS_BUFFER_OVERFLOW;
    }

    return STATUS_SUCCESS;
}

NTSTATUS
SysmonAddStringField(
    _Inout_ PSYSMON_EVENT_UNION Event,
    _Inout_ PSYSMON_EVENT_PAYLOAD_BUILDER Builder,
    _Out_ SYSMON_EVENT_STRING_REF *Ref,
    _In_opt_z_ PCWSTR Source)
{
    if (Source == NULL || Source[0] == L'\0') {
        return SysmonAddStringFieldWithLength(Event, Builder, Ref, Source, 0);
    }

    return SysmonAddStringFieldWithLength(
        Event,
        Builder,
        Ref,
        Source,
        wcslen(Source));
}

NTSTATUS
SysmonAddCurrentUtcTimeField(
    _Inout_ PSYSMON_EVENT_UNION Event,
    _Inout_ PSYSMON_EVENT_PAYLOAD_BUILDER Builder,
    _Out_ SYSMON_EVENT_STRING_REF *Ref)
{
    WCHAR utcTime[64];
    NTSTATUS status;

    if (Event == NULL || Builder == NULL || Ref == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    status = SysmonFormatTimestamp(Event->Header.Timestamp, utcTime);
    if (!NT_SUCCESS(status)) {
        utcTime[0] = L'\0';
    }

    return SysmonAddStringFieldWithLength(
        Event,
        Builder,
        Ref,
        utcTime,
        (utcTime[0] != L'\0') ? SYSMON_TIMESTAMP_STRING_CHARS : 0);
}

BOOLEAN
SysmonCopyStringField(
    _In_ PSYSMON_EVENT_UNION Event,
    _In_ SYSMON_EVENT_STRING_REF Ref,
    _Out_writes_(BufferChars) PWCHAR Buffer,
    _In_ ULONG BufferChars)
{
    ULONG copyBytes;

    if (Event == NULL || Buffer == NULL || BufferChars == 0) {
        return FALSE;
    }

    Buffer[0] = L'\0';

    if (Ref.LengthBytes == 0 ||
        Ref.Offset >= SYSMON_EVENT_DATA_SIZE ||
        Ref.LengthBytes > SYSMON_EVENT_DATA_SIZE - Ref.Offset) {
        return FALSE;
    }

    copyBytes = Ref.LengthBytes;
    if (copyBytes >= BufferChars * sizeof(WCHAR)) {
        copyBytes = (BufferChars - 1) * sizeof(WCHAR);
    }

    RtlCopyMemory(Buffer, Event->RawData + Ref.Offset, copyBytes);
    Buffer[copyBytes / sizeof(WCHAR)] = L'\0';
    return TRUE;
}

PSYSMON_PROCESS_CREATE_EVENT_DATA
SysmonGetProcessCreateEventData(
    _In_ PSYSMON_EVENT_UNION Event)
{
    if (Event == NULL ||
        Event->Header.EventId != SysmonEventProcessCreate ||
        Event->Header.EventSize < SYSMON_PROCESS_CREATE_EVENT_SIZE) {
        return NULL;
    }

    return (PSYSMON_PROCESS_CREATE_EVENT_DATA)Event->RawData;
}

BOOLEAN
SysmonExtractProcessCreateField(
    _In_ PSYSMON_EVENT_UNION Event,
    _In_ PCWSTR FieldName,
    _Out_writes_(BufferChars) PWCHAR Buffer,
    _In_ ULONG BufferChars)
{
    return SysmonExtractEventField(Event, FieldName, Buffer, BufferChars);
}

static BOOLEAN
SysmonExtractEventFieldByDescriptor(
    _In_ PSYSMON_EVENT_UNION Event,
    _In_ const SYSMON_EVENT_FIELD_DESCRIPTOR *Field,
    _Out_writes_(BufferChars) PWCHAR Buffer,
    _In_ ULONG BufferChars)
{
    const UCHAR *payloadBase;
    SYSMON_EVENT_ID eventId;

    payloadBase = Event->RawData;
    eventId = (SYSMON_EVENT_ID)Event->Header.EventId;

    switch (Field->Kind) {
    case SysmonFieldRenderStringRef:
    {
        SYSMON_EVENT_STRING_REF ref;
        BOOLEAN copied;

        RtlCopyMemory(&ref, payloadBase + Field->Offset, sizeof(ref));
        copied = SysmonCopyStringField(Event, ref, Buffer, BufferChars);
        if (copied && SysmonIsRegistryRuleField(eventId, Field->FieldName)) {
            SysmonNormalizeRegistryFieldForMatching(Buffer, BufferChars);
        }
        return copied;
    }

    case SysmonFieldRenderUInt32:
    {
        ULONG value;

        RtlCopyMemory(&value, payloadBase + Field->Offset, sizeof(value));
        return SysmonFormatUInt32(value, Buffer, BufferChars, 10);
    }

    case SysmonFieldRenderUInt32Hex:
    {
        ULONG value;

        RtlCopyMemory(&value, payloadBase + Field->Offset, sizeof(value));
        return SysmonFormatHexUlonglong(value, Buffer, BufferChars);
    }

    case SysmonFieldRenderUInt64Hex:
    {
        ULONGLONG value;

        RtlCopyMemory(&value, payloadBase + Field->Offset, sizeof(value));
        return SysmonFormatHexUlonglong(value, Buffer, BufferChars);
    }

    case SysmonFieldRenderBool:
    {
        BOOLEAN value;

        RtlCopyMemory(&value, payloadBase + Field->Offset, sizeof(value));
        return SysmonFormatBoolean(value, Buffer, BufferChars);
    }

    default:
        return FALSE;
    }
}

BOOLEAN
SysmonResolveEventField(
    _In_ SYSMON_EVENT_ID EventId,
    _In_ PCWSTR FieldName,
    _Out_ SYSMON_RESOLVED_EVENT_FIELD *ResolvedField)
{
    const SYSMON_EVENT_SCHEMA *schema;
    ULONG fieldIndex;
    PCWSTR normalizedFieldName;

    if (ResolvedField == NULL) {
        return FALSE;
    }

    ResolvedField->EventId = EventId;
    ResolvedField->FieldIndex = SYSMON_EVENT_FIELD_INDEX_UNRESOLVED;

    if (FieldName == NULL) {
        return FALSE;
    }

    normalizedFieldName = SysmonNormalizeFieldName(FieldName);
    schema = SysmonGetEventSchema(EventId);
    if (normalizedFieldName == NULL || schema == NULL) {
        return FALSE;
    }

    for (fieldIndex = 0; fieldIndex < schema->FieldCount; fieldIndex++) {
        if (SysmonEventFieldNameMatches(
                EventId,
                normalizedFieldName,
                schema->Fields[fieldIndex].FieldName)) {
            if (fieldIndex >= SYSMON_EVENT_FIELD_INDEX_UNRESOLVED) {
                return FALSE;
            }

            ResolvedField->FieldIndex = (USHORT)fieldIndex;
            return TRUE;
        }
    }

    return FALSE;
}

BOOLEAN
SysmonExtractResolvedEventField(
    _In_ PSYSMON_EVENT_UNION Event,
    _In_ const SYSMON_RESOLVED_EVENT_FIELD *ResolvedField,
    _Out_writes_(BufferChars) PWCHAR Buffer,
    _In_ ULONG BufferChars)
{
    const SYSMON_EVENT_SCHEMA *schema;
    SYSMON_EVENT_ID eventId;

    if (Event == NULL || ResolvedField == NULL || Buffer == NULL || BufferChars == 0) {
        return FALSE;
    }

    Buffer[0] = L'\0';
    eventId = (SYSMON_EVENT_ID)Event->Header.EventId;
    if (ResolvedField->EventId != eventId ||
        ResolvedField->FieldIndex == SYSMON_EVENT_FIELD_INDEX_UNRESOLVED) {
        return FALSE;
    }

    schema = SysmonGetEventSchema(eventId);
    if (schema == NULL ||
        Event->Header.EventSize < schema->MinimumEventSize ||
        ResolvedField->FieldIndex >= schema->FieldCount) {
        return FALSE;
    }

    return SysmonExtractEventFieldByDescriptor(
        Event,
        &schema->Fields[ResolvedField->FieldIndex],
        Buffer,
        BufferChars);
}

BOOLEAN
SysmonExtractEventField(
    _In_ PSYSMON_EVENT_UNION Event,
    _In_ PCWSTR FieldName,
    _Out_writes_(BufferChars) PWCHAR Buffer,
    _In_ ULONG BufferChars)
{
    SYSMON_RESOLVED_EVENT_FIELD resolvedField;

    if (Event == NULL || FieldName == NULL || Buffer == NULL || BufferChars == 0) {
        return FALSE;
    }

    Buffer[0] = L'\0';

    if (!SysmonResolveEventField(
            (SYSMON_EVENT_ID)Event->Header.EventId,
            FieldName,
            &resolvedField)) {
        return FALSE;
    }

    return SysmonExtractResolvedEventField(Event, &resolvedField, Buffer, BufferChars);
}

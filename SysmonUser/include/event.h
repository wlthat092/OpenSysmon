#pragma once
/*
 * event.h - Event structures, field definitions, event IDs
 *
 * STRICTLY aligned with SysmonDrv kernel driver event IDs.
 * These match the original Sysmon64.exe event schema.
 */

#include "common.h"

/* ========================================================================
 * Event IDs - matches SysmonDrv/include/event.h exactly
 * ======================================================================== */
typedef enum _SYSMON_EVENT_ID {
    SysmonEventNone = 0,
    SysmonEventProcessCreate        = 1,    /* Process Create */
    SysmonEventFileCreateTime       = 2,    /* File creation time changed */
    SysmonEventNetworkConnect       = 3,    /* Network connection detected */
    SysmonEventServiceState         = 4,    /* Sysmon service state change (internal) */
    SysmonEventProcessTerminate     = 5,    /* Process terminated */
    SysmonEventDriverLoad           = 6,    /* Driver loaded */
    SysmonEventImageLoad            = 7,    /* Image loaded (DLL/EXE) */
    SysmonEventCreateRemoteThread   = 8,    /* CreateRemoteThread detected */
    SysmonEventCreateThread         = SysmonEventCreateRemoteThread,
    SysmonEventRawAccessRead        = 9,    /* RawAccessRead detected */
    SysmonEventProcessAccess        = 10,   /* Process accessed */
    SysmonEventFileCreate           = 11,   /* File created */
    SysmonEventRegistryEvent        = 12,   /* Registry object added/deleted */
    SysmonEventRegistryValueSet     = 13,   /* Registry value set */
    SysmonEventRegistrySetValue     = SysmonEventRegistryValueSet,
    SysmonEventRegistryRename       = 14,   /* Registry object renamed */
    SysmonEventFileCreateStreamHash = 15,   /* File stream created */
    SysmonEventConfigChange         = 16,   /* Config changed (internal) */
    SysmonEventPipeCreated          = 17,   /* Named pipe created */
    SysmonEventPipeConnected        = 18,   /* Named pipe connected */
    SysmonEventWmiFilter            = 19,   /* WMI event filter */
    SysmonEventWmiConsumer          = 20,   /* WMI event consumer */
    SysmonEventWmiConsumerToFilter  = 21,   /* WMI consumer to filter activity */
    SysmonEventDnsQuery             = 22,   /* DNS query */
    SysmonEventFileDelete           = 23,   /* File delete archived */
    SysmonEventClipboardChange      = 24,   /* Clipboard content changed */
    SysmonEventProcessTampering     = 25,   /* Process image tampering */
    SysmonEventFileDeleteDetected   = 26,   /* File delete detected */
    SysmonEventFileBlockExecutable  = 27,   /* File block executable */
    SysmonEventFileBlockShredding   = 28,   /* File block shredding */
    SysmonEventFileExecutableDetected = 29, /* Executable file detected */
    SysmonEventDropped              = 254,  /* Event dropped (internal) */
    SysmonEventError                = 255   /* Error event */
} SYSMON_EVENT_ID;

/* ========================================================================
 * Event Header - present at the start of every event from driver
 * Matches SysmonDrv/include/event.h SYSMON_EVENT_HEADER layout
 * ======================================================================== */
#pragma pack(push, 1)
typedef struct _SYSMON_EVENT_HEADER {
    ULONG       EventId;        /* SYSMON_EVENT_ID */
    ULONG       EventSize;      /* Total event size including header */
    ULONG       SequenceNumber; /* Monotonic sequence counter */
    ULONG       Padding;
    LONGLONG    Timestamp;      /* Event timestamp (100ns units since 1601) */
} SYSMON_EVENT_HEADER, *PSYSMON_EVENT_HEADER;
#pragma pack(pop)

/* Minimum size sanity check */
#define SYSMON_EVENT_HEADER_SIZE    sizeof(SYSMON_EVENT_HEADER)

/* ========================================================================
 * Event Field Name Constants
 *
 * Values below use the canonical Data/@Name strings from events/*.xml.
 * Keep case-sensitive variants where the XML schema differs by event.
 * ======================================================================== */
#define EVT_FIELD_ARCHIVED                  L"Archived"
#define EVT_FIELD_CALL_TRACE                L"CallTrace"
#define EVT_FIELD_CLIENT_INFO               L"ClientInfo"
#define EVT_FIELD_COMMAND_LINE              L"CommandLine"
#define EVT_FIELD_COMPANY                   L"Company"
#define EVT_FIELD_CONFIGURATION             L"Configuration"
#define EVT_FIELD_CONFIGURATION_FILE_HASH   L"ConfigurationFileHash"
#define EVT_FIELD_CONTENTS                  L"Contents"
#define EVT_FIELD_CONSUMER                  L"Consumer"
#define EVT_FIELD_CREATION_UTC_TIME         L"CreationUtcTime"
#define EVT_FIELD_CURRENT_DIRECTORY         L"CurrentDirectory"
#define EVT_FIELD_DESCRIPTION               L"Description"
#define EVT_FIELD_DESTINATION               L"Destination"
#define EVT_FIELD_DESTINATION_HOSTNAME      L"DestinationHostname"
#define EVT_FIELD_DESTINATION_IP            L"DestinationIp"
#define EVT_FIELD_DESTINATION_IS_IPV6       L"DestinationIsIpv6"
#define EVT_FIELD_DESTINATION_PORT          L"DestinationPort"
#define EVT_FIELD_DESTINATION_PORT_NAME     L"DestinationPortName"
#define EVT_FIELD_DETAILS                   L"Details"
#define EVT_FIELD_DEVICE                    L"Device"
#define EVT_FIELD_EVENT_NAMESPACE           L"EventNamespace"
#define EVT_FIELD_EVENT_TYPE                L"EventType"
#define EVT_FIELD_FILE_VERSION              L"FileVersion"
#define EVT_FIELD_FILTER                    L"Filter"
#define EVT_FIELD_GRANTED_ACCESS            L"GrantedAccess"
#define EVT_FIELD_HASH                      L"Hash"
#define EVT_FIELD_HASHES                    L"Hashes"
#define EVT_FIELD_IMAGE                     L"Image"
#define EVT_FIELD_IMAGE_LOADED              L"ImageLoaded"
#define EVT_FIELD_INITIATED                 L"Initiated"
#define EVT_FIELD_INTEGRITY_LEVEL           L"IntegrityLevel"
#define EVT_FIELD_IS_EXECUTABLE             L"IsExecutable"
#define EVT_FIELD_LOGON_GUID                L"LogonGuid"
#define EVT_FIELD_LOGON_ID                  L"LogonId"
#define EVT_FIELD_NAME                      L"Name"
#define EVT_FIELD_NEW_NAME                  L"NewName"
#define EVT_FIELD_NEW_THREAD_ID             L"NewThreadId"
#define EVT_FIELD_OPERATION                 L"Operation"
#define EVT_FIELD_ORIGINAL_FILENAME         L"OriginalFileName"
#define EVT_FIELD_PARENT_COMMAND_LINE       L"ParentCommandLine"
#define EVT_FIELD_PARENT_IMAGE              L"ParentImage"
#define EVT_FIELD_PARENT_PROCESS_GUID       L"ParentProcessGuid"
#define EVT_FIELD_PARENT_PROCESS_ID         L"ParentProcessId"
#define EVT_FIELD_PARENT_USER               L"ParentUser"
#define EVT_FIELD_PIPE_NAME                 L"PipeName"
#define EVT_FIELD_PREVIOUS_CREATION_UTC_TIME L"PreviousCreationUtcTime"
#define EVT_FIELD_PROCESS_GUID              L"ProcessGuid"
#define EVT_FIELD_PROCESS_ID                L"ProcessId"
#define EVT_FIELD_PRODUCT                   L"Product"
#define EVT_FIELD_PROTOCOL                  L"Protocol"
#define EVT_FIELD_QUERY                     L"Query"
#define EVT_FIELD_QUERY_NAME                L"QueryName"
#define EVT_FIELD_QUERY_RESULTS             L"QueryResults"
#define EVT_FIELD_QUERY_STATUS              L"QueryStatus"
#define EVT_FIELD_RULE_NAME                 L"RuleName"
#define EVT_FIELD_SCHEMA_VERSION            L"SchemaVersion"
#define EVT_FIELD_SESSION                   L"Session"
#define EVT_FIELD_SIGNATURE                 L"Signature"
#define EVT_FIELD_SIGNATURE_STATUS          L"SignatureStatus"
#define EVT_FIELD_SIGNED                    L"Signed"
#define EVT_FIELD_SOURCE_HOSTNAME           L"SourceHostname"
#define EVT_FIELD_SOURCE_IMAGE              L"SourceImage"
#define EVT_FIELD_SOURCE_IP                 L"SourceIp"
#define EVT_FIELD_SOURCE_IS_IPV6            L"SourceIsIpv6"
#define EVT_FIELD_SOURCE_PORT               L"SourcePort"
#define EVT_FIELD_SOURCE_PORT_NAME          L"SourcePortName"
#define EVT_FIELD_SOURCE_PROCESS_GUID       L"SourceProcessGuid"
#define EVT_FIELD_SOURCE_PROCESS_GUID_CAPS  L"SourceProcessGUID"
#define EVT_FIELD_SOURCE_PROCESS_ID         L"SourceProcessId"
#define EVT_FIELD_SOURCE_THREAD_ID          L"SourceThreadId"
#define EVT_FIELD_SOURCE_USER               L"SourceUser"
#define EVT_FIELD_START_ADDRESS             L"StartAddress"
#define EVT_FIELD_START_FUNCTION            L"StartFunction"
#define EVT_FIELD_START_MODULE              L"StartModule"
#define EVT_FIELD_STATE                     L"State"
#define EVT_FIELD_TARGET_FILENAME           L"TargetFilename"
#define EVT_FIELD_TARGET_IMAGE              L"TargetImage"
#define EVT_FIELD_TARGET_OBJECT             L"TargetObject"
#define EVT_FIELD_TARGET_PROCESS_GUID       L"TargetProcessGuid"
#define EVT_FIELD_TARGET_PROCESS_GUID_CAPS  L"TargetProcessGUID"
#define EVT_FIELD_TARGET_PROCESS_ID         L"TargetProcessId"
#define EVT_FIELD_TARGET_USER               L"TargetUser"
#define EVT_FIELD_TERMINAL_SESSION_ID       L"TerminalSessionId"
#define EVT_FIELD_TYPE                      L"Type"
#define EVT_FIELD_USER                      L"User"
#define EVT_FIELD_UTC_TIME                  L"UtcTime"
#define EVT_FIELD_VERSION                   L"Version"

/* Non-canonical compatibility names still emitted/consumed by older code. */
#define EVT_FIELD_CONNECTED                 L"Connected"
#define EVT_FIELD_QUERY_RESULT_STR          L"QueryResultString"
#define EVT_FIELD_USER_SID                  L"UserSid"
#define EVT_FIELD_DEST_IP                   EVT_FIELD_DESTINATION_IP
#define EVT_FIELD_DEST_PORT                 EVT_FIELD_DESTINATION_PORT
#define EVT_FIELD_DEST_HOSTNAME             EVT_FIELD_DESTINATION_HOSTNAME
#define EVT_FIELD_UTCTIME                   EVT_FIELD_UTC_TIME

/* ========================================================================
 * Canonical Event Payload Contract Skeletons
 *
 * String fields are represented by offsets into the event payload string
 * area. These skeletons intentionally model the canonical XML fields without
 * requiring this slice to rewrite current fixed-buffer producers.
 * ======================================================================== */
#pragma pack(push, 1)
typedef struct _SYSMON_EVENT_STRING_REF {
    DWORD Offset;
    DWORD LengthBytes;
} SYSMON_EVENT_STRING_REF;

typedef struct _SYSMON_EVENT_PAYLOAD_BUILDER {
    DWORD PayloadSize;
    DWORD Cursor;
    DWORD Capacity;
} SYSMON_EVENT_PAYLOAD_BUILDER, *PSYSMON_EVENT_PAYLOAD_BUILDER;

typedef struct _SYSMON_EVENT_PROCESS_CREATE_PAYLOAD {
    SYSMON_EVENT_STRING_REF RuleName;
    SYSMON_EVENT_STRING_REF UtcTime;
    SYSMON_EVENT_STRING_REF ProcessGuid;
    DWORD ProcessId;
    SYSMON_EVENT_STRING_REF Image;
    SYSMON_EVENT_STRING_REF FileVersion;
    SYSMON_EVENT_STRING_REF Description;
    SYSMON_EVENT_STRING_REF Product;
    SYSMON_EVENT_STRING_REF Company;
    SYSMON_EVENT_STRING_REF OriginalFileName;
    SYSMON_EVENT_STRING_REF CommandLine;
    SYSMON_EVENT_STRING_REF CurrentDirectory;
    SYSMON_EVENT_STRING_REF User;
    SYSMON_EVENT_STRING_REF LogonGuid;
    ULONGLONG LogonId;
    DWORD TerminalSessionId;
    SYSMON_EVENT_STRING_REF IntegrityLevel;
    SYSMON_EVENT_STRING_REF Hashes;
    SYSMON_EVENT_STRING_REF ParentProcessGuid;
    DWORD ParentProcessId;
    SYSMON_EVENT_STRING_REF ParentImage;
    SYSMON_EVENT_STRING_REF ParentCommandLine;
    SYSMON_EVENT_STRING_REF ParentUser;
} SYSMON_EVENT_PROCESS_CREATE_PAYLOAD;

typedef struct _SYSMON_EVENT_FILE_CREATE_TIME_PAYLOAD {
    SYSMON_EVENT_STRING_REF RuleName;
    SYSMON_EVENT_STRING_REF UtcTime;
    SYSMON_EVENT_STRING_REF ProcessGuid;
    DWORD ProcessId;
    SYSMON_EVENT_STRING_REF Image;
    SYSMON_EVENT_STRING_REF TargetFilename;
    SYSMON_EVENT_STRING_REF CreationUtcTime;
    SYSMON_EVENT_STRING_REF PreviousCreationUtcTime;
    SYSMON_EVENT_STRING_REF User;
} SYSMON_EVENT_FILE_CREATE_TIME_PAYLOAD;

typedef struct _SYSMON_EVENT_NETWORK_CONNECT_PAYLOAD {
    SYSMON_EVENT_STRING_REF RuleName;
    SYSMON_EVENT_STRING_REF UtcTime;
    SYSMON_EVENT_STRING_REF ProcessGuid;
    DWORD ProcessId;
    SYSMON_EVENT_STRING_REF Image;
    SYSMON_EVENT_STRING_REF User;
    SYSMON_EVENT_STRING_REF Protocol;
    BOOLEAN Initiated;
    BOOLEAN SourceIsIpv6;
    SYSMON_EVENT_STRING_REF SourceIp;
    SYSMON_EVENT_STRING_REF SourceHostname;
    DWORD SourcePort;
    SYSMON_EVENT_STRING_REF SourcePortName;
    BOOLEAN DestinationIsIpv6;
    SYSMON_EVENT_STRING_REF DestinationIp;
    SYSMON_EVENT_STRING_REF DestinationHostname;
    DWORD DestinationPort;
    SYSMON_EVENT_STRING_REF DestinationPortName;
} SYSMON_EVENT_NETWORK_CONNECT_PAYLOAD;

typedef struct _SYSMON_EVENT_SERVICE_STATE_PAYLOAD {
    SYSMON_EVENT_STRING_REF UtcTime;
    SYSMON_EVENT_STRING_REF State;
    SYSMON_EVENT_STRING_REF Version;
    SYSMON_EVENT_STRING_REF SchemaVersion;
} SYSMON_EVENT_SERVICE_STATE_PAYLOAD;

typedef struct _SYSMON_EVENT_PROCESS_TERMINATE_PAYLOAD {
    SYSMON_EVENT_STRING_REF RuleName;
    SYSMON_EVENT_STRING_REF UtcTime;
    SYSMON_EVENT_STRING_REF ProcessGuid;
    DWORD ProcessId;
    SYSMON_EVENT_STRING_REF Image;
    SYSMON_EVENT_STRING_REF User;
} SYSMON_EVENT_PROCESS_TERMINATE_PAYLOAD;

typedef struct _SYSMON_EVENT_IMAGE_LOAD_PAYLOAD {
    SYSMON_EVENT_STRING_REF RuleName;
    SYSMON_EVENT_STRING_REF UtcTime;
    SYSMON_EVENT_STRING_REF ProcessGuid;
    DWORD ProcessId;
    SYSMON_EVENT_STRING_REF Image;
    SYSMON_EVENT_STRING_REF ImageLoaded;
    SYSMON_EVENT_STRING_REF Hashes;
    BOOLEAN Signed;
    SYSMON_EVENT_STRING_REF Signature;
    SYSMON_EVENT_STRING_REF SignatureStatus;
    SYSMON_EVENT_STRING_REF FileVersion;
    SYSMON_EVENT_STRING_REF Description;
    SYSMON_EVENT_STRING_REF Product;
    SYSMON_EVENT_STRING_REF Company;
    SYSMON_EVENT_STRING_REF OriginalFileName;
    SYSMON_EVENT_STRING_REF User;
} SYSMON_EVENT_IMAGE_LOAD_PAYLOAD;

typedef struct _SYSMON_EVENT_DRIVER_LOAD_PAYLOAD {
    SYSMON_EVENT_STRING_REF RuleName;
    SYSMON_EVENT_STRING_REF UtcTime;
    SYSMON_EVENT_STRING_REF ImageLoaded;
    SYSMON_EVENT_STRING_REF Hashes;
    BOOLEAN Signed;
    SYSMON_EVENT_STRING_REF Signature;
    SYSMON_EVENT_STRING_REF SignatureStatus;
} SYSMON_EVENT_DRIVER_LOAD_PAYLOAD;

typedef struct _SYSMON_EVENT_CREATE_REMOTE_THREAD_PAYLOAD {
    SYSMON_EVENT_STRING_REF RuleName;
    SYSMON_EVENT_STRING_REF UtcTime;
    SYSMON_EVENT_STRING_REF SourceProcessGuid;
    DWORD SourceProcessId;
    SYSMON_EVENT_STRING_REF SourceImage;
    SYSMON_EVENT_STRING_REF TargetProcessGuid;
    DWORD TargetProcessId;
    SYSMON_EVENT_STRING_REF TargetImage;
    DWORD NewThreadId;
    ULONGLONG StartAddress;
    SYSMON_EVENT_STRING_REF StartModule;
    SYSMON_EVENT_STRING_REF StartFunction;
    SYSMON_EVENT_STRING_REF SourceUser;
    SYSMON_EVENT_STRING_REF TargetUser;
} SYSMON_EVENT_CREATE_REMOTE_THREAD_PAYLOAD;

typedef struct _SYSMON_EVENT_RAW_ACCESS_READ_PAYLOAD {
    SYSMON_EVENT_STRING_REF RuleName;
    SYSMON_EVENT_STRING_REF UtcTime;
    SYSMON_EVENT_STRING_REF ProcessGuid;
    DWORD ProcessId;
    SYSMON_EVENT_STRING_REF Image;
    SYSMON_EVENT_STRING_REF Device;
    SYSMON_EVENT_STRING_REF User;
} SYSMON_EVENT_RAW_ACCESS_READ_PAYLOAD;

typedef struct _SYSMON_EVENT_PROCESS_ACCESS_PAYLOAD {
    SYSMON_EVENT_STRING_REF RuleName;
    SYSMON_EVENT_STRING_REF UtcTime;
    SYSMON_EVENT_STRING_REF SourceProcessGUID;
    DWORD SourceProcessId;
    DWORD SourceThreadId;
    SYSMON_EVENT_STRING_REF SourceImage;
    SYSMON_EVENT_STRING_REF TargetProcessGUID;
    DWORD TargetProcessId;
    SYSMON_EVENT_STRING_REF TargetImage;
    DWORD GrantedAccess;
    SYSMON_EVENT_STRING_REF CallTrace;
    SYSMON_EVENT_STRING_REF SourceUser;
    SYSMON_EVENT_STRING_REF TargetUser;
} SYSMON_EVENT_PROCESS_ACCESS_PAYLOAD;

typedef struct _SYSMON_EVENT_FILE_CREATE_PAYLOAD {
    SYSMON_EVENT_STRING_REF RuleName;
    SYSMON_EVENT_STRING_REF UtcTime;
    SYSMON_EVENT_STRING_REF ProcessGuid;
    DWORD ProcessId;
    SYSMON_EVENT_STRING_REF Image;
    SYSMON_EVENT_STRING_REF TargetFilename;
    SYSMON_EVENT_STRING_REF CreationUtcTime;
    SYSMON_EVENT_STRING_REF User;
} SYSMON_EVENT_FILE_CREATE_PAYLOAD;

typedef struct _SYSMON_EVENT_REGISTRY_EVENT_PAYLOAD {
    SYSMON_EVENT_STRING_REF RuleName;
    SYSMON_EVENT_STRING_REF EventType;
    SYSMON_EVENT_STRING_REF UtcTime;
    SYSMON_EVENT_STRING_REF ProcessGuid;
    DWORD ProcessId;
    SYSMON_EVENT_STRING_REF Image;
    SYSMON_EVENT_STRING_REF TargetObject;
    SYSMON_EVENT_STRING_REF User;
} SYSMON_EVENT_REGISTRY_EVENT_PAYLOAD;

typedef struct _SYSMON_EVENT_REGISTRY_VALUE_SET_PAYLOAD {
    SYSMON_EVENT_STRING_REF RuleName;
    SYSMON_EVENT_STRING_REF EventType;
    SYSMON_EVENT_STRING_REF UtcTime;
    SYSMON_EVENT_STRING_REF ProcessGuid;
    DWORD ProcessId;
    SYSMON_EVENT_STRING_REF Image;
    SYSMON_EVENT_STRING_REF TargetObject;
    SYSMON_EVENT_STRING_REF Details;
    SYSMON_EVENT_STRING_REF User;
} SYSMON_EVENT_REGISTRY_VALUE_SET_PAYLOAD;

typedef struct _SYSMON_EVENT_REGISTRY_RENAME_PAYLOAD {
    SYSMON_EVENT_STRING_REF RuleName;
    SYSMON_EVENT_STRING_REF EventType;
    SYSMON_EVENT_STRING_REF UtcTime;
    SYSMON_EVENT_STRING_REF ProcessGuid;
    DWORD ProcessId;
    SYSMON_EVENT_STRING_REF Image;
    SYSMON_EVENT_STRING_REF TargetObject;
    SYSMON_EVENT_STRING_REF NewName;
    SYSMON_EVENT_STRING_REF User;
} SYSMON_EVENT_REGISTRY_RENAME_PAYLOAD;

typedef struct _SYSMON_EVENT_FILE_CREATE_STREAM_HASH_PAYLOAD {
    SYSMON_EVENT_STRING_REF RuleName;
    SYSMON_EVENT_STRING_REF UtcTime;
    SYSMON_EVENT_STRING_REF ProcessGuid;
    DWORD ProcessId;
    SYSMON_EVENT_STRING_REF Image;
    SYSMON_EVENT_STRING_REF TargetFilename;
    SYSMON_EVENT_STRING_REF CreationUtcTime;
    SYSMON_EVENT_STRING_REF Hash;
    SYSMON_EVENT_STRING_REF Contents;
    SYSMON_EVENT_STRING_REF User;
} SYSMON_EVENT_FILE_CREATE_STREAM_HASH_PAYLOAD;

typedef struct _SYSMON_EVENT_CONFIG_CHANGE_PAYLOAD {
    SYSMON_EVENT_STRING_REF UtcTime;
    SYSMON_EVENT_STRING_REF Configuration;
    SYSMON_EVENT_STRING_REF ConfigurationFileHash;
} SYSMON_EVENT_CONFIG_CHANGE_PAYLOAD;

typedef struct _SYSMON_EVENT_PIPE_PAYLOAD {
    SYSMON_EVENT_STRING_REF RuleName;
    SYSMON_EVENT_STRING_REF EventType;
    SYSMON_EVENT_STRING_REF UtcTime;
    SYSMON_EVENT_STRING_REF ProcessGuid;
    DWORD ProcessId;
    SYSMON_EVENT_STRING_REF PipeName;
    SYSMON_EVENT_STRING_REF Image;
    SYSMON_EVENT_STRING_REF User;
} SYSMON_EVENT_PIPE_PAYLOAD;

typedef struct _SYSMON_EVENT_PIPE_CREATED_PAYLOAD {
    SYSMON_EVENT_STRING_REF RuleName;
    SYSMON_EVENT_STRING_REF EventType;
    SYSMON_EVENT_STRING_REF UtcTime;
    SYSMON_EVENT_STRING_REF ProcessGuid;
    DWORD ProcessId;
    SYSMON_EVENT_STRING_REF PipeName;
    SYSMON_EVENT_STRING_REF Image;
    SYSMON_EVENT_STRING_REF User;
} SYSMON_EVENT_PIPE_CREATED_PAYLOAD;

typedef struct _SYSMON_EVENT_WMI_FILTER_PAYLOAD {
    SYSMON_EVENT_STRING_REF RuleName;
    SYSMON_EVENT_STRING_REF EventType;
    SYSMON_EVENT_STRING_REF UtcTime;
    SYSMON_EVENT_STRING_REF Operation;
    SYSMON_EVENT_STRING_REF User;
    SYSMON_EVENT_STRING_REF EventNamespace;
    SYSMON_EVENT_STRING_REF Name;
    SYSMON_EVENT_STRING_REF Query;
} SYSMON_EVENT_WMI_FILTER_PAYLOAD;

typedef struct _SYSMON_EVENT_WMI_CONSUMER_PAYLOAD {
    SYSMON_EVENT_STRING_REF RuleName;
    SYSMON_EVENT_STRING_REF EventType;
    SYSMON_EVENT_STRING_REF UtcTime;
    SYSMON_EVENT_STRING_REF Operation;
    SYSMON_EVENT_STRING_REF User;
    SYSMON_EVENT_STRING_REF Name;
    SYSMON_EVENT_STRING_REF Type;
    SYSMON_EVENT_STRING_REF Destination;
} SYSMON_EVENT_WMI_CONSUMER_PAYLOAD;

typedef struct _SYSMON_EVENT_WMI_CONSUMER_TO_FILTER_PAYLOAD {
    SYSMON_EVENT_STRING_REF RuleName;
    SYSMON_EVENT_STRING_REF EventType;
    SYSMON_EVENT_STRING_REF UtcTime;
    SYSMON_EVENT_STRING_REF Operation;
    SYSMON_EVENT_STRING_REF User;
    SYSMON_EVENT_STRING_REF Consumer;
    SYSMON_EVENT_STRING_REF Filter;
} SYSMON_EVENT_WMI_CONSUMER_TO_FILTER_PAYLOAD;

typedef struct _SYSMON_EVENT_DNS_QUERY_PAYLOAD {
    SYSMON_EVENT_STRING_REF RuleName;
    SYSMON_EVENT_STRING_REF UtcTime;
    SYSMON_EVENT_STRING_REF ProcessGuid;
    DWORD ProcessId;
    SYSMON_EVENT_STRING_REF QueryName;
    SYSMON_EVENT_STRING_REF QueryStatus;
    SYSMON_EVENT_STRING_REF QueryResults;
    SYSMON_EVENT_STRING_REF Image;
    SYSMON_EVENT_STRING_REF User;
} SYSMON_EVENT_DNS_QUERY_PAYLOAD;

typedef struct _SYSMON_EVENT_FILE_DELETE_PAYLOAD {
    SYSMON_EVENT_STRING_REF RuleName;
    SYSMON_EVENT_STRING_REF UtcTime;
    SYSMON_EVENT_STRING_REF ProcessGuid;
    DWORD ProcessId;
    SYSMON_EVENT_STRING_REF User;
    SYSMON_EVENT_STRING_REF Image;
    SYSMON_EVENT_STRING_REF TargetFilename;
    SYSMON_EVENT_STRING_REF Hashes;
    BOOLEAN IsExecutable;
    BOOLEAN Archived;
} SYSMON_EVENT_FILE_DELETE_PAYLOAD;

typedef struct _SYSMON_EVENT_CLIPBOARD_CHANGE_PAYLOAD {
    SYSMON_EVENT_STRING_REF RuleName;
    SYSMON_EVENT_STRING_REF UtcTime;
    SYSMON_EVENT_STRING_REF ProcessGuid;
    DWORD ProcessId;
    SYSMON_EVENT_STRING_REF Image;
    DWORD Session;
    SYSMON_EVENT_STRING_REF ClientInfo;
    SYSMON_EVENT_STRING_REF Hashes;
    BOOLEAN Archived;
    SYSMON_EVENT_STRING_REF User;
} SYSMON_EVENT_CLIPBOARD_CHANGE_PAYLOAD;

typedef struct _SYSMON_EVENT_PROCESS_TAMPERING_PAYLOAD {
    SYSMON_EVENT_STRING_REF RuleName;
    SYSMON_EVENT_STRING_REF UtcTime;
    SYSMON_EVENT_STRING_REF ProcessGuid;
    DWORD ProcessId;
    SYSMON_EVENT_STRING_REF Image;
    SYSMON_EVENT_STRING_REF Type;
    SYSMON_EVENT_STRING_REF User;
} SYSMON_EVENT_PROCESS_TAMPERING_PAYLOAD;

typedef struct _SYSMON_EVENT_FILE_BLOCK_PAYLOAD {
    SYSMON_EVENT_STRING_REF RuleName;
    SYSMON_EVENT_STRING_REF UtcTime;
    SYSMON_EVENT_STRING_REF ProcessGuid;
    DWORD ProcessId;
    SYSMON_EVENT_STRING_REF User;
    SYSMON_EVENT_STRING_REF Image;
    SYSMON_EVENT_STRING_REF TargetFilename;
    SYSMON_EVENT_STRING_REF Hashes;
    BOOLEAN IsExecutable;
} SYSMON_EVENT_FILE_BLOCK_PAYLOAD;

typedef struct _SYSMON_EVENT_FILE_HASH_PAYLOAD {
    SYSMON_EVENT_STRING_REF RuleName;
    SYSMON_EVENT_STRING_REF UtcTime;
    SYSMON_EVENT_STRING_REF ProcessGuid;
    DWORD ProcessId;
    SYSMON_EVENT_STRING_REF User;
    SYSMON_EVENT_STRING_REF Image;
    SYSMON_EVENT_STRING_REF TargetFilename;
    SYSMON_EVENT_STRING_REF Hashes;
} SYSMON_EVENT_FILE_HASH_PAYLOAD;
#pragma pack(pop)

#define SYSMON_EVENT_CONTRACT_SIZE(type) ((DWORD)(SYSMON_EVENT_HEADER_SIZE + sizeof(type)))

/*
 * SysmonGetEventMinSize - Get minimum event size for given event type
 */
DWORD SysmonGetEventMinSize(_In_ SYSMON_EVENT_ID EventId);

BOOL SysmonFormatSyntheticUtcTimestamp(
    _In_ ULONGLONG RawTimestamp,
    _Out_writes_(BufferChars) PWCHAR Buffer,
    _In_ size_t BufferChars,
    _Out_opt_ PULONGLONG Timestamp);

void SysmonInitializeEventBuffer(
    _Out_writes_bytes_(EventBufferSize) PBYTE EventBuffer,
    _In_ DWORD EventBufferSize,
    _In_ SYSMON_EVENT_ID EventId,
    _In_ DWORD PayloadSize,
    _Out_ PSYSMON_EVENT_PAYLOAD_BUILDER Builder,
    _In_opt_ ULONGLONG Timestamp);

SYSMON_STATUS SysmonAddStringField(
    _Inout_updates_bytes_(EventBufferSize) PBYTE EventBuffer,
    _In_ DWORD EventBufferSize,
    _Inout_ PSYSMON_EVENT_PAYLOAD_BUILDER Builder,
    _Out_ SYSMON_EVENT_STRING_REF *Ref,
    _In_opt_z_ PCWSTR Source);

BOOL SysmonCopyStringField(
    _In_reads_bytes_(EventSize) const BYTE *EventData,
    _In_ DWORD EventSize,
    _In_ SYSMON_EVENT_STRING_REF Ref,
    _Out_writes_(BufferChars) PWCHAR Buffer,
    _In_ size_t BufferChars);

BOOL SysmonExtractEventField(
    _In_reads_bytes_(EventSize) const BYTE *EventData,
    _In_ DWORD EventSize,
    _In_ SYSMON_EVENT_ID EventId,
    _In_ LPCWSTR FieldName,
    _Out_writes_(BufferChars) PWCHAR Buffer,
    _In_ size_t BufferChars);

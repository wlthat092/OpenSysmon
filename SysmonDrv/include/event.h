#pragma once
#include "common.h"

typedef enum _SYSMON_EVENT_ID {
    SysmonEventNull                = 0,
    SysmonEventProcessCreate       = 1,    /* Process Create */
    SysmonEventFileCreateTime      = 2,    /* File creation time changed */
    SysmonEventNetworkConnect      = 3,    /* Network connection detected */
    SysmonEventServiceState        = 4,    /* Sysmon service state change (internal) */
    SysmonEventProcessTerminate    = 5,    /* Process terminated */
    SysmonEventDriverLoad          = 6,    /* Driver loaded */
    SysmonEventImageLoad           = 7,    /* Image loaded (DLL/EXE) */
    SysmonEventCreateThread        = 8,    /* CreateRemoteThread detected */
    SysmonEventCreateRemoteThread  = SysmonEventCreateThread,
    SysmonEventRawAccessRead       = 9,    /* RawAccessRead detected */
    SysmonEventProcessAccess       = 10,   /* Process accessed */
    SysmonEventFileCreate          = 11,   /* File created */
    SysmonEventRegistryEvent       = 12,   /* Registry object added/deleted */
    SysmonEventRegistryValueSet    = 13,   /* Registry value set */
    SysmonEventRegistrySetValue    = SysmonEventRegistryValueSet,
    SysmonEventRegistryRename      = 14,   /* Registry object renamed */
    SysmonEventFileCreateStreamHash= 15,   /* File stream created */
    SysmonEventConfigChange        = 16,   /* Sysmon config changed (internal) */
    SysmonEventPipeCreated         = 17,   /* Named pipe created */
    SysmonEventPipeConnected       = 18,   /* Named pipe connected */
    SysmonEventWmiFilter           = 19,   /* WMI event filter */
    SysmonEventWmiConsumer         = 20,   /* WMI event consumer */
    SysmonEventWmiConsumerToFilter = 21,   /* WMI consumer to filter activity */
    SysmonEventDnsQuery            = 22,   /* DNS query */
    SysmonEventFileDelete          = 23,   /* File delete archived */
    SysmonEventClipboardChange     = 24,   /* Clipboard content changed */
    SysmonEventProcessTampering    = 25,   /* Process image tampering */
    SysmonEventFileDeleteDetected  = 26,   /* File delete detected */
    SysmonEventFileBlockExecutable = 27,   /* File block executable */
    SysmonEventFileBlockShredding  = 28,   /* File block shredding */
    SysmonEventFileExecutableDetected = 29,/* Executable file detected */
    SysmonEventDropped             = 254,  /* Event dropped (internal) */
    SysmonEventError               = 255   /* Error event */
} SYSMON_EVENT_ID;

typedef enum _SYSMON_REGISTRY_EVENT_TYPE {
    SysmonRegCreateKey = 0,
    SysmonRegDeleteKey,
    SysmonRegRenameKey,
    SysmonRegCreateValue,
    SysmonRegDeleteValue,
    SysmonRegRenameValue,
    SysmonRegSetValue
} SYSMON_REGISTRY_EVENT_TYPE;

typedef enum _SYSMON_HASH_TYPE {
    SysmonHashNone = 0,
    SysmonHashMD5    = 0x0001,
    SysmonHashSHA1   = 0x0002,
    SysmonHashSHA256 = 0x0004,
    SysmonHashIMPHASH = 0x0008
} SYSMON_HASH_TYPE;

typedef struct _SYSMON_EVENT_HEADER {
    ULONG       EventId;
    ULONG       EventSize;
    ULONG       SequenceNumber;
    ULONG       Padding;
    LONGLONG    Timestamp;
} SYSMON_EVENT_HEADER, *PSYSMON_EVENT_HEADER;

#define SYSMON_EVENT_HEADER_SIZE    sizeof(SYSMON_EVENT_HEADER)
#define SYSMON_EVENT_CONTRACT_SIZE(type) ((ULONG)(SYSMON_EVENT_HEADER_SIZE + sizeof(type)))
#define SYSMON_TIMESTAMP_STRING_CHARS 23
#define SYSMON_GUID_STRING_CHARS      38

typedef struct _SYSMON_EVENT_UNION {
    SYSMON_EVENT_HEADER Header;
    UCHAR RawData[SYSMON_EVENT_DATA_SIZE];
} SYSMON_EVENT_UNION, *PSYSMON_EVENT_UNION;

#define SYSMON_EVENT_FIELD_INDEX_UNRESOLVED 0xFFFF

typedef struct _SYSMON_RESOLVED_EVENT_FIELD {
    SYSMON_EVENT_ID EventId;
    USHORT FieldIndex;
} SYSMON_RESOLVED_EVENT_FIELD, *PSYSMON_RESOLVED_EVENT_FIELD;

PSYSMON_EVENT_UNION SysmonAllocateEvent(SYSMON_EVENT_ID EventId);
VOID SysmonFreeEvent(_In_opt_ PSYSMON_EVENT_UNION Event);
VOID SysmonInitializeEventPool(VOID);
VOID SysmonCleanupEventPool(VOID);

/* ========================================================================
 * Canonical Event Payload Contract Skeletons
 *
 * The XML schema in events/*.xml is the authority for field names. String
 * fields are represented by payload-local byte offsets so the contract can
 * describe all canonical fields without forcing this slice to rewrite current
 * fixed-buffer producers.
 * ======================================================================== */
#pragma pack(push, 1)
typedef struct _SYSMON_EVENT_STRING_REF {
    ULONG Offset;
    ULONG LengthBytes;
} SYSMON_EVENT_STRING_REF;

typedef struct _SYSMON_EVENT_PAYLOAD_BUILDER {
    ULONG PayloadSize;
    ULONG Cursor;
} SYSMON_EVENT_PAYLOAD_BUILDER, *PSYSMON_EVENT_PAYLOAD_BUILDER;

typedef struct _SYSMON_EVENT_PROCESS_CREATE_PAYLOAD {
    SYSMON_EVENT_STRING_REF RuleName;
    SYSMON_EVENT_STRING_REF UtcTime;
    SYSMON_EVENT_STRING_REF ProcessGuid;
    ULONG ProcessId;
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
    ULONG TerminalSessionId;
    SYSMON_EVENT_STRING_REF IntegrityLevel;
    SYSMON_EVENT_STRING_REF Hashes;
    SYSMON_EVENT_STRING_REF ParentProcessGuid;
    ULONG ParentProcessId;
    SYSMON_EVENT_STRING_REF ParentImage;
    SYSMON_EVENT_STRING_REF ParentCommandLine;
    SYSMON_EVENT_STRING_REF ParentUser;
} SYSMON_EVENT_PROCESS_CREATE_PAYLOAD;

typedef struct _SYSMON_EVENT_FILE_CREATE_TIME_PAYLOAD {
    SYSMON_EVENT_STRING_REF RuleName;
    SYSMON_EVENT_STRING_REF UtcTime;
    SYSMON_EVENT_STRING_REF ProcessGuid;
    ULONG ProcessId;
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
    ULONG ProcessId;
    SYSMON_EVENT_STRING_REF Image;
    SYSMON_EVENT_STRING_REF User;
    SYSMON_EVENT_STRING_REF Protocol;
    BOOLEAN Initiated;
    BOOLEAN SourceIsIpv6;
    SYSMON_EVENT_STRING_REF SourceIp;
    SYSMON_EVENT_STRING_REF SourceHostname;
    ULONG SourcePort;
    SYSMON_EVENT_STRING_REF SourcePortName;
    BOOLEAN DestinationIsIpv6;
    SYSMON_EVENT_STRING_REF DestinationIp;
    SYSMON_EVENT_STRING_REF DestinationHostname;
    ULONG DestinationPort;
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
    ULONG ProcessId;
    SYSMON_EVENT_STRING_REF Image;
    SYSMON_EVENT_STRING_REF User;
} SYSMON_EVENT_PROCESS_TERMINATE_PAYLOAD;

typedef struct _SYSMON_EVENT_IMAGE_LOAD_PAYLOAD {
    SYSMON_EVENT_STRING_REF RuleName;
    SYSMON_EVENT_STRING_REF UtcTime;
    SYSMON_EVENT_STRING_REF ProcessGuid;
    ULONG ProcessId;
    SYSMON_EVENT_STRING_REF Image;
    SYSMON_EVENT_STRING_REF ImageLoaded;
    SYSMON_EVENT_STRING_REF Hashes;
    BOOLEAN Signed;
    SYSMON_EVENT_STRING_REF Signature;
    SYSMON_EVENT_STRING_REF SignatureStatus;
    /*
     * Sysmon uses version-resource fields when filtering ImageLoad rules
     * even though they are not part of the canonical Event ID 7 XML output.
     * Keep them as an internal tail extension so the driver and user-mode
     * rule engines can match original configs without changing rendered XML.
     */
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
    ULONG SourceProcessId;
    SYSMON_EVENT_STRING_REF SourceImage;
    SYSMON_EVENT_STRING_REF TargetProcessGuid;
    ULONG TargetProcessId;
    SYSMON_EVENT_STRING_REF TargetImage;
    ULONG NewThreadId;
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
    ULONG ProcessId;
    SYSMON_EVENT_STRING_REF Image;
    SYSMON_EVENT_STRING_REF Device;
    SYSMON_EVENT_STRING_REF User;
} SYSMON_EVENT_RAW_ACCESS_READ_PAYLOAD;

typedef struct _SYSMON_EVENT_PROCESS_ACCESS_PAYLOAD {
    SYSMON_EVENT_STRING_REF RuleName;
    SYSMON_EVENT_STRING_REF UtcTime;
    SYSMON_EVENT_STRING_REF SourceProcessGUID;
    ULONG SourceProcessId;
    ULONG SourceThreadId;
    SYSMON_EVENT_STRING_REF SourceImage;
    SYSMON_EVENT_STRING_REF TargetProcessGUID;
    ULONG TargetProcessId;
    SYSMON_EVENT_STRING_REF TargetImage;
    ULONG GrantedAccess;
    SYSMON_EVENT_STRING_REF CallTrace;
    SYSMON_EVENT_STRING_REF SourceUser;
    SYSMON_EVENT_STRING_REF TargetUser;
} SYSMON_EVENT_PROCESS_ACCESS_PAYLOAD;

typedef struct _SYSMON_EVENT_FILE_CREATE_PAYLOAD {
    SYSMON_EVENT_STRING_REF RuleName;
    SYSMON_EVENT_STRING_REF UtcTime;
    SYSMON_EVENT_STRING_REF ProcessGuid;
    ULONG ProcessId;
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
    ULONG ProcessId;
    SYSMON_EVENT_STRING_REF Image;
    SYSMON_EVENT_STRING_REF TargetObject;
    SYSMON_EVENT_STRING_REF User;
} SYSMON_EVENT_REGISTRY_EVENT_PAYLOAD;

typedef struct _SYSMON_EVENT_REGISTRY_VALUE_SET_PAYLOAD {
    SYSMON_EVENT_STRING_REF RuleName;
    SYSMON_EVENT_STRING_REF EventType;
    SYSMON_EVENT_STRING_REF UtcTime;
    SYSMON_EVENT_STRING_REF ProcessGuid;
    ULONG ProcessId;
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
    ULONG ProcessId;
    SYSMON_EVENT_STRING_REF Image;
    SYSMON_EVENT_STRING_REF TargetObject;
    SYSMON_EVENT_STRING_REF NewName;
    SYSMON_EVENT_STRING_REF User;
} SYSMON_EVENT_REGISTRY_RENAME_PAYLOAD;

typedef struct _SYSMON_EVENT_FILE_CREATE_STREAM_HASH_PAYLOAD {
    SYSMON_EVENT_STRING_REF RuleName;
    SYSMON_EVENT_STRING_REF UtcTime;
    SYSMON_EVENT_STRING_REF ProcessGuid;
    ULONG ProcessId;
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
    ULONG ProcessId;
    SYSMON_EVENT_STRING_REF PipeName;
    SYSMON_EVENT_STRING_REF Image;
    SYSMON_EVENT_STRING_REF User;
} SYSMON_EVENT_PIPE_PAYLOAD;

typedef struct _SYSMON_EVENT_PIPE_CREATED_PAYLOAD {
    SYSMON_EVENT_STRING_REF RuleName;
    SYSMON_EVENT_STRING_REF EventType;
    SYSMON_EVENT_STRING_REF UtcTime;
    SYSMON_EVENT_STRING_REF ProcessGuid;
    ULONG ProcessId;
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
    ULONG ProcessId;
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
    ULONG ProcessId;
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
    ULONG ProcessId;
    SYSMON_EVENT_STRING_REF Image;
    ULONG Session;
    SYSMON_EVENT_STRING_REF ClientInfo;
    SYSMON_EVENT_STRING_REF Hashes;
    BOOLEAN Archived;
    SYSMON_EVENT_STRING_REF User;
} SYSMON_EVENT_CLIPBOARD_CHANGE_PAYLOAD;

typedef struct _SYSMON_EVENT_PROCESS_TAMPERING_PAYLOAD {
    SYSMON_EVENT_STRING_REF RuleName;
    SYSMON_EVENT_STRING_REF UtcTime;
    SYSMON_EVENT_STRING_REF ProcessGuid;
    ULONG ProcessId;
    SYSMON_EVENT_STRING_REF Image;
    SYSMON_EVENT_STRING_REF Type;
    SYSMON_EVENT_STRING_REF User;
} SYSMON_EVENT_PROCESS_TAMPERING_PAYLOAD;

typedef struct _SYSMON_EVENT_FILE_BLOCK_PAYLOAD {
    SYSMON_EVENT_STRING_REF RuleName;
    SYSMON_EVENT_STRING_REF UtcTime;
    SYSMON_EVENT_STRING_REF ProcessGuid;
    ULONG ProcessId;
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
    ULONG ProcessId;
    SYSMON_EVENT_STRING_REF User;
    SYSMON_EVENT_STRING_REF Image;
    SYSMON_EVENT_STRING_REF TargetFilename;
    SYSMON_EVENT_STRING_REF Hashes;
} SYSMON_EVENT_FILE_HASH_PAYLOAD;
#pragma pack(pop)

VOID
SysmonBeginStringPayload(
    _Inout_ PSYSMON_EVENT_UNION Event,
    _In_ ULONG PayloadSize,
    _Out_ PSYSMON_EVENT_PAYLOAD_BUILDER Builder);

NTSTATUS
SysmonAddStringField(
    _Inout_ PSYSMON_EVENT_UNION Event,
    _Inout_ PSYSMON_EVENT_PAYLOAD_BUILDER Builder,
    _Out_ SYSMON_EVENT_STRING_REF *Ref,
    _In_opt_z_ PCWSTR Source);

NTSTATUS
SysmonAddStringFieldWithLength(
    _Inout_ PSYSMON_EVENT_UNION Event,
    _Inout_ PSYSMON_EVENT_PAYLOAD_BUILDER Builder,
    _Out_ SYSMON_EVENT_STRING_REF *Ref,
    _In_reads_or_z_(SourceChars) PCWSTR Source,
    _In_ SIZE_T SourceChars);

FORCEINLINE
NTSTATUS
SysmonAddFixedLengthStringField(
    _Inout_ PSYSMON_EVENT_UNION Event,
    _Inout_ PSYSMON_EVENT_PAYLOAD_BUILDER Builder,
    _Out_ SYSMON_EVENT_STRING_REF *Ref,
    _In_opt_z_ PCWSTR Source,
    _In_ SIZE_T SourceChars)
{
    return SysmonAddStringFieldWithLength(
        Event,
        Builder,
        Ref,
        Source,
        (Source != NULL && Source[0] != L'\0') ? SourceChars : 0);
}

#define SysmonAddStringLiteralField(_Event, _Builder, _Ref, _Literal) \
    SysmonAddStringFieldWithLength(                                      \
        (_Event),                                                        \
        (_Builder),                                                      \
        (_Ref),                                                          \
        (_Literal),                                                      \
        RTL_NUMBER_OF(_Literal) - 1)

NTSTATUS
SysmonAddCurrentUtcTimeField(
    _Inout_ PSYSMON_EVENT_UNION Event,
    _Inout_ PSYSMON_EVENT_PAYLOAD_BUILDER Builder,
    _Out_ SYSMON_EVENT_STRING_REF *Ref);

BOOLEAN
SysmonCopyStringField(
    _In_ PSYSMON_EVENT_UNION Event,
    _In_ SYSMON_EVENT_STRING_REF Ref,
    _Out_writes_(BufferChars) PWCHAR Buffer,
    _In_ ULONG BufferChars);

BOOLEAN
SysmonExtractEventField(
    _In_ PSYSMON_EVENT_UNION Event,
    _In_ PCWSTR FieldName,
    _Out_writes_(BufferChars) PWCHAR Buffer,
    _In_ ULONG BufferChars);

BOOLEAN
SysmonResolveEventField(
    _In_ SYSMON_EVENT_ID EventId,
    _In_ PCWSTR FieldName,
    _Out_ SYSMON_RESOLVED_EVENT_FIELD *ResolvedField);

BOOLEAN
SysmonExtractResolvedEventField(
    _In_ PSYSMON_EVENT_UNION Event,
    _In_ const SYSMON_RESOLVED_EVENT_FIELD *ResolvedField,
    _Out_writes_(BufferChars) PWCHAR Buffer,
    _In_ ULONG BufferChars);

/* ========================================================================
 * Legacy Producer Payloads
 *
 * These fixed-buffer structs pre-date the canonical XML contract above and
 * are retained only so current producers continue to compile in this slice.
 * Do not use these names/layouts as canonical schema definitions.
 * ======================================================================== */

/* Legacy network connection producer payload */
typedef struct _SYSMON_NETWORK_EVENT_DATA {
    ULONG       EventId;
    ULONG       EventSize;
    ULONG       SequenceNumber;
    ULONG       Padding;
    LONGLONG    Timestamp;
    ULONG       ProcessId;
    ULONG       SrcPort;
    ULONG       DstPort;
    ULONG       Protocol;       /* 6=TCP, 17=UDP */
    WCHAR       SrcIp[64];
    WCHAR       DstIp[64];
    WCHAR       Image[SYSMON_MAX_PATH];
} SYSMON_NETWORK_EVENT_DATA;

/* Legacy pipe producer payload */
typedef struct _SYSMON_PIPE_EVENT_DATA {
    ULONG       EventId;
    ULONG       EventSize;
    ULONG       SequenceNumber;
    ULONG       Padding;
    LONGLONG    Timestamp;
    ULONG       ProcessId;
    ULONG       PipeType;       /* 1=Named Pipe */
    WCHAR       PipeName[SYSMON_MAX_PATH];
} SYSMON_PIPE_EVENT_DATA;

/* Legacy WMI producer payload */
typedef struct _SYSMON_WMI_EVENT_DATA {
    ULONG       EventId;
    ULONG       EventSize;
    ULONG       SequenceNumber;
    ULONG       Padding;
    LONGLONG    Timestamp;
    ULONG       ProcessId;
    WCHAR       Operation[256];
    WCHAR       Destination[SYSMON_MAX_PATH];
    WCHAR       UserSid[SYSMON_MAX_SID_STRING];
} SYSMON_WMI_EVENT_DATA;

/* Legacy DNS query producer payload */
typedef struct _SYSMON_DNS_EVENT_DATA {
    ULONG       EventId;
    ULONG       EventSize;
    ULONG       SequenceNumber;
    ULONG       Padding;
    LONGLONG    Timestamp;
    ULONG       ProcessId;
    ULONG       QueryStatus;
    ULONG       QueryOptions;
    WCHAR       QueryName[SYSMON_MAX_PATH];
    WCHAR       QueryResults[SYSMON_MAX_PATH];
} SYSMON_DNS_EVENT_DATA;

/* Legacy clipboard producer payload */
typedef struct _SYSMON_CLIPBOARD_EVENT_DATA {
    ULONG       EventId;
    ULONG       EventSize;
    ULONG       SequenceNumber;
    ULONG       Padding;
    LONGLONG    Timestamp;
    ULONG       ProcessId;
    WCHAR       ClipboardContent[SYSMON_MAX_PATH];
} SYSMON_CLIPBOARD_EVENT_DATA;

/* Legacy process tampering producer payload */
typedef struct _SYSMON_PROCESS_TAMPERING_DATA {
    ULONG       EventId;
    ULONG       EventSize;
    ULONG       SequenceNumber;
    ULONG       Padding;
    LONGLONG    Timestamp;
    ULONG       ProcessId;
    ULONG       TamperType;
    WCHAR       Image[SYSMON_MAX_PATH];
} SYSMON_PROCESS_TAMPERING_DATA;

/* Legacy file block producer payload */
typedef struct _SYSMON_FILE_BLOCK_EVENT_DATA {
    ULONG       EventId;
    ULONG       EventSize;
    ULONG       SequenceNumber;
    ULONG       Padding;
    LONGLONG    Timestamp;
    ULONG       ProcessId;
    WCHAR       TargetFilename[SYSMON_MAX_PATH];
    WCHAR       Hashes[SYSMON_MAX_HASH_STRING];
} SYSMON_FILE_BLOCK_EVENT_DATA;

#include "../include/event_schema.h"

#include <stddef.h>

#define FIELD_DESC(type, name, kind, member) \
    { name, kind, (USHORT)offsetof(type, member) }

#define SYSMON_DEFINE_EVENT_FIELD_TABLE(Name, PayloadType, ...) \
    static const SYSMON_EVENT_FIELD_DESCRIPTOR g_##Name##Fields[] = { __VA_ARGS__ }; \
    static const SYSMON_EVENT_SCHEMA g_##Name##Schema = { \
        g_##Name##Fields, \
        (DWORD)_countof(g_##Name##Fields) \
    };
#define SYSMON_FIELD_STRINGREF SysmonRenderStringRef
#define SYSMON_FIELD_UINT32 SysmonRenderUInt32
#define SYSMON_FIELD_UINT32HEX SysmonRenderUInt32Hex
#define SYSMON_FIELD_UINT64HEX SysmonRenderUInt64Hex
#define SYSMON_FIELD_BOOL SysmonRenderBool
#define SYSMON_FIELD_PROCESS_TERMINATE_PID SysmonRenderProcessTerminatePid
#include "../include/event_field_tables.inc"
#undef SYSMON_FIELD_PROCESS_TERMINATE_PID
#undef SYSMON_FIELD_BOOL
#undef SYSMON_FIELD_UINT64HEX
#undef SYSMON_FIELD_UINT32HEX
#undef SYSMON_FIELD_UINT32
#undef SYSMON_FIELD_STRINGREF
#undef SYSMON_DEFINE_EVENT_FIELD_TABLE

const SYSMON_EVENT_SCHEMA *
GetEventSchema(
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
        return &g_PipeConnectedSchema;
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

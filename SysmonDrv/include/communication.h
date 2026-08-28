#pragma once
#include "common.h"

/*
 * Original Sysmon IOCTL Protocol (from Sysmon64.exe binary analysis)
 *
 * Device type: 0x8340 (custom)
 * All IOCTLs use METHOD_BUFFERED + FILE_ANY_ACCESS
 *
 * Code        Function  Input     Output    Semantics
 * 0x83400000  0x00      4 bytes   None      Init/Handshake (version/mode)
 * 0x83400004  0x01      None      <=0x40000 Get Event (overlapped, pended via CSQ)
 * 0x83400008  0x02      None      None      Config/Rule refresh notify
 * 0x8340000c  0x03      8 bytes   <=0x4002  Process cache request
 * 0x83400010  0x04      0x60      None      Query answer
 * 0x83400014  0x05      None      None      Stop/Close communication
 * 0x83400018  0x06      None      <=0x40000 Get query event (overlapped)
 * 0x8340001c  0x07      None      <=0x40000 Get debug stats (clone-only)
 */

#define FILE_DEVICE_SYSMON  0x8340

/* Use FILE_ANY_ACCESS and METHOD_BUFFERED to match original raw codes */
#define IOCTL_SYSMON_INIT           CTL_CODE(FILE_DEVICE_SYSMON, 0x00, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_SYSMON_GET_EVENT      CTL_CODE(FILE_DEVICE_SYSMON, 0x01, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_SYSMON_CONFIG_NOTIFY  CTL_CODE(FILE_DEVICE_SYSMON, 0x02, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_SYSMON_PROCESS_CACHE  CTL_CODE(FILE_DEVICE_SYSMON, 0x03, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_SYSMON_QUERY_ANSWER   CTL_CODE(FILE_DEVICE_SYSMON, 0x04, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_SYSMON_STOP           CTL_CODE(FILE_DEVICE_SYSMON, 0x05, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_SYSMON_GET_QUERY      CTL_CODE(FILE_DEVICE_SYSMON, 0x06, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_SYSMON_GET_STATS      CTL_CODE(FILE_DEVICE_SYSMON, 0x07, METHOD_BUFFERED, FILE_ANY_ACCESS)

/* Legacy aliases for backward compatibility */
#define IOCTL_SYSMON_SET_CONFIG     IOCTL_SYSMON_CONFIG_NOTIFY

#define SYSMON_PROCESS_CACHE_SIGNATURE 0x43504353u /* 'SCPC' */
#define SYSMON_PROCESS_CACHE_VERSION   1u

typedef struct _SYSMON_PROCESS_CACHE_RESPONSE {
    ULONG Signature;
    ULONG Version;
    ULONG ProcessId;
    ULONG Reserved;
    LONGLONG CreateTime;
    WCHAR ProcessGuid[SYSMON_MAX_GUID_STRING];
    WCHAR Image[SYSMON_MAX_PATH];
    WCHAR UserSid[SYSMON_MAX_SID_STRING];
} SYSMON_PROCESS_CACHE_RESPONSE, *PSYSMON_PROCESS_CACHE_RESPONSE;

typedef struct _SYSMON_QUERY_ANSWER {
    ULONG RequestId;
    ULONG ResultCode;
    UCHAR HasExtendedBlob;
    UCHAR Reserved[0x60 - sizeof(ULONG) - sizeof(ULONG) - sizeof(UCHAR)];
} SYSMON_QUERY_ANSWER, *PSYSMON_QUERY_ANSWER;

#define SYSMON_QUERY_TYPE_FILE_DELETE 15u
#define SYSMON_QUERY_TYPE_WMI_FILTER  19u
#define SYSMON_QUERY_TYPE_WMI_CONSUMER 20u
#define SYSMON_QUERY_TYPE_WMI_BINDING 21u

#define SYSMON_QUERY_FLAG_IS_EXECUTABLE 0x00000001u

typedef struct _SYSMON_QUERY_RECORD {
    ULONG QueryType;
    ULONG RecordSize;
    ULONG RequestId;
    ULONG Flags;
    ULONG ProcessId;
    ULONG EventId;
    LONGLONG Timestamp;
    WCHAR ProcessGuid[SYSMON_MAX_GUID_STRING];
    WCHAR User[SYSMON_MAX_SID_STRING];
    WCHAR Image[SYSMON_MAX_PATH];
    WCHAR TargetFilename[SYSMON_MAX_PATH];
    WCHAR Hashes[SYSMON_MAX_HASH_STRING];
    WCHAR Name[256];
    WCHAR Type[128];
    WCHAR Destination[256];
    WCHAR Consumer[256];
    WCHAR Filter[256];
} SYSMON_QUERY_RECORD, *PSYSMON_QUERY_RECORD;

typedef struct _SYSMON_IRP_CSQ_QUEUE {
    IO_CSQ Csq;
    LIST_ENTRY PendingIrpList;
    KSPIN_LOCK Lock;
} SYSMON_IRP_CSQ_QUEUE, *PSYSMON_IRP_CSQ_QUEUE;

/* Device extension containing CSQs for normal events and query events. */
typedef struct _DEVICE_EXTENSION {
    SYSMON_IRP_CSQ_QUEUE EventQueue;
    SYSMON_IRP_CSQ_QUEUE QueryQueue;
    /* File object of the single event consumer. GET_EVENT from any other file
       object is rejected so events are never misdelivered across clients (K1).
       Guarded by EventQueue.Lock. */
    PFILE_OBJECT EventConsumerFileObject;
    /* File object of the single query consumer, mirroring EventConsumerFileObject
       for the query queue. Guarded by QueryQueue.Lock. */
    PFILE_OBJECT QueryConsumerFileObject;
} DEVICE_EXTENSION, *PDEVICE_EXTENSION;

/* CSQ initialization */
NTSTATUS SysmonInitializeCsq(_In_ PDEVICE_OBJECT DeviceObject);

/* Event completion via CSQ */
BOOLEAN SysmonCompletePendingEventIrp(_In_ struct _SYSMON_EVENT_UNION *Event);
BOOLEAN SysmonCompletePendingQueryIrp(
    _In_reads_bytes_(RecordSize) PVOID QueryRecord,
    _In_ ULONG RecordSize);
NTSTATUS SysmonPublishEvent(
    _In_ struct _SYSMON_EVENT_UNION *Event);
NTSTATUS SysmonPublishEventWithFilterState(
    _In_ struct _SYSMON_EVENT_UNION *Event,
    _Out_opt_ PBOOLEAN FilteredOut);
NTSTATUS SysmonPendGetEventIrp(_In_ PDEVICE_OBJECT DeviceObject, _In_ PIRP Irp);
NTSTATUS SysmonPendGetQueryIrp(_In_ PDEVICE_OBJECT DeviceObject, _In_ PIRP Irp);
VOID SysmonCancelPendingIrpsForFileObject(_In_opt_ PFILE_OBJECT FileObject, _In_ NTSTATUS Status);
VOID SysmonDrainPendingEventIrps(_In_ NTSTATUS Status);
VOID SysmonDrainPendingQueryIrps(_In_ NTSTATUS Status);
NTSTATUS SysmonSubmitQueryRecordAndWait(
    _Inout_ PSYSMON_QUERY_RECORD QueryRecord,
    _Out_ PULONG ResultCode);

/* IOCTL handlers */
NTSTATUS SysmonHandleInit(_In_ PIRP Irp, _In_ ULONG InputLength, _In_opt_ PVOID InputBuffer);
NTSTATUS SysmonHandleConfigNotify(_In_ PIRP Irp);
NTSTATUS SysmonHandleProcessCache(_In_ PIRP Irp, _In_ ULONG InputLength, _In_opt_ PVOID InputBuffer,
    _In_ ULONG OutputLength, _Out_opt_ PVOID OutputBuffer);
NTSTATUS SysmonHandleQueryAnswer(_In_ PIRP Irp, _In_ ULONG InputLength, _In_opt_ PVOID InputBuffer);
NTSTATUS SysmonHandleGetQueryEvent(_In_ PIRP Irp);
NTSTATUS SysmonHandleStop(_In_ PIRP Irp);
NTSTATUS SysmonHandleGetStats(_In_ PIRP Irp, _In_ ULONG OutputLength, _Out_opt_ PVOID OutputBuffer);
NTSTATUS SysmonHandleGetEvent(_In_ PIRP Irp);

extern volatile LONG g_ProcessCallbackCount;

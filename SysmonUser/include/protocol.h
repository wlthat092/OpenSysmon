#pragma once
/*
 * protocol.h - IOCTL codes, command structures, ProtocolTransport API
 * Strictly aligned with original Sysmon64.exe 0x8340xxxx protocol
 */

#include "common.h"

/* ========================================================================
 * IOCTL Command Codes - Original Sysmon Protocol
 * Device type: FILE_DEVICE_UNKNOWN (0x22) but CTL_CODE macro with custom type
 * In original: device type 0x8340 used directly in the IOCTL code
 * ======================================================================== */

/*
 * Original IOCTL code layout (from pseudo-code):
 *   0x83400000 = Init/Handshake
 *   0x83400004 = Get Event (overlapped)
 *   0x83400008 = Config/Rule refresh notify
 *   0x8340000c = Process cache request
 *   0x83400010 = Query answer
 *   0x83400014 = Stop/Close communication
 *   0x83400018 = Get query event (overlapped)
 *   0x8340001c = Get debug stats (clone-only)
 *
 * Keep the exact wire values, but name the base/offset pieces so protocol
 * updates do not silently desynchronize user mode from the driver.
 */
#define SYSMON_IOCTL_BASE               0x83400000UL
#define SYSMON_IOCTL_OFFSET_INIT        0x00000000UL
#define SYSMON_IOCTL_OFFSET_GET_EVENT   0x00000004UL
#define SYSMON_IOCTL_OFFSET_CONFIG      0x00000008UL
#define SYSMON_IOCTL_OFFSET_PROCESS     0x0000000CUL
#define SYSMON_IOCTL_OFFSET_QUERY_ANS   0x00000010UL
#define SYSMON_IOCTL_OFFSET_STOP        0x00000014UL
#define SYSMON_IOCTL_OFFSET_GET_QUERY   0x00000018UL
#define SYSMON_IOCTL_OFFSET_GET_STATS   0x0000001CUL

#define SYSMON_IOCTL_INIT               (SYSMON_IOCTL_BASE + SYSMON_IOCTL_OFFSET_INIT)
#define SYSMON_IOCTL_GET_EVENT          (SYSMON_IOCTL_BASE + SYSMON_IOCTL_OFFSET_GET_EVENT)
#define SYSMON_IOCTL_CONFIG_NOTIFY      (SYSMON_IOCTL_BASE + SYSMON_IOCTL_OFFSET_CONFIG)
#define SYSMON_IOCTL_PROCESS_CACHE      (SYSMON_IOCTL_BASE + SYSMON_IOCTL_OFFSET_PROCESS)
#define SYSMON_IOCTL_QUERY_ANSWER       (SYSMON_IOCTL_BASE + SYSMON_IOCTL_OFFSET_QUERY_ANS)
#define SYSMON_IOCTL_STOP               (SYSMON_IOCTL_BASE + SYSMON_IOCTL_OFFSET_STOP)
#define SYSMON_IOCTL_GET_QUERY          (SYSMON_IOCTL_BASE + SYSMON_IOCTL_OFFSET_GET_QUERY)
#define SYSMON_IOCTL_GET_STATS          (SYSMON_IOCTL_BASE + SYSMON_IOCTL_OFFSET_GET_STATS)

#define SYSMON_PROTOCOL_INIT_HANDSHAKE_VALUE 0x000005F0UL

#define SYSMON_PROCESS_CACHE_SIGNATURE  0x43504353u
#define SYSMON_PROCESS_CACHE_VERSION    1u
#define SYSMON_PROCESS_CACHE_QUERY_FLAG 1u

/* ========================================================================
 * Transport Structures
 * ======================================================================== */

typedef struct _SYSMON_TRANSPORT {
    HANDLE DeviceHandle;        /* Handle to \\.\Sysmon device */
    HANDLE StopEvent;           /* Manual-reset stop event */
    HANDLE DriverEvent;         /* Auto-reset event from driver (overlapped) */
    CRITICAL_SECTION Lock;      /* Serialize transport operations */
    volatile BOOL Connected;    /* Connection state flag */
    WCHAR DevicePath[260];      /* Device path string */
} SYSMON_TRANSPORT, *PSYSMON_TRANSPORT;

#pragma pack(push, 1)
typedef struct _SYSMON_PROCESS_CACHE_QUERY {
    DWORD ProcessId;
    DWORD QueryFlags;
} SYSMON_PROCESS_CACHE_QUERY, *PSYSMON_PROCESS_CACHE_QUERY;

typedef struct _SYSMON_PROCESS_CACHE_RESPONSE {
    DWORD Signature;
    DWORD Version;
    DWORD ProcessId;
    DWORD Reserved;
    ULONGLONG CreateTime;
    WCHAR ProcessGuid[40];
    WCHAR Image[MAX_PATH];
    WCHAR UserSid[128];
} SYSMON_PROCESS_CACHE_RESPONSE, *PSYSMON_PROCESS_CACHE_RESPONSE;

typedef struct _SYSMON_QUERY_ANSWER {
    DWORD RequestId;
    DWORD ResultCode;
    BYTE HasExtendedBlob;
    BYTE Reserved[0x60 - sizeof(DWORD) - sizeof(DWORD) - sizeof(BYTE)];
} SYSMON_QUERY_ANSWER, *PSYSMON_QUERY_ANSWER;

#define SYSMON_QUERY_TYPE_FILE_DELETE 15u
#define SYSMON_QUERY_TYPE_WMI_FILTER  19u
#define SYSMON_QUERY_TYPE_WMI_CONSUMER 20u
#define SYSMON_QUERY_TYPE_WMI_BINDING 21u

#define SYSMON_QUERY_FLAG_IS_EXECUTABLE 0x00000001u

typedef struct _SYSMON_QUERY_RECORD {
    DWORD QueryType;
    DWORD RecordSize;
    DWORD RequestId;
    DWORD Flags;
    DWORD ProcessId;
    DWORD EventId;
    LONGLONG Timestamp;
    WCHAR ProcessGuid[40];
    WCHAR User[128];
    WCHAR Image[512];
    WCHAR TargetFilename[512];
    WCHAR Hashes[256];
    WCHAR Name[256];
    WCHAR Type[128];
    WCHAR Destination[256];
    WCHAR Consumer[256];
    WCHAR Filter[256];
} SYSMON_QUERY_RECORD, *PSYSMON_QUERY_RECORD;
#pragma pack(pop)

static_assert(sizeof(SYSMON_PROCESS_CACHE_QUERY) == 8, "SYSMON_PROCESS_CACHE_QUERY wire size mismatch");
static_assert(sizeof(SYSMON_PROCESS_CACHE_RESPONSE) == 0x370, "SYSMON_PROCESS_CACHE_RESPONSE wire size mismatch");
static_assert(sizeof(SYSMON_QUERY_ANSWER) == 0x60, "SYSMON_QUERY_ANSWER wire size mismatch");
static_assert(sizeof(SYSMON_QUERY_RECORD) == 0x1470, "SYSMON_QUERY_RECORD wire size mismatch");

/* ========================================================================
 * Protocol API
 * ======================================================================== */

/*
 * SysmonTransportInit - Initialize transport structure, create events
 */
SYSMON_STATUS SysmonTransportInit(
    _Out_ PSYSMON_TRANSPORT Transport,
    _In_ HANDLE StopEvent);

/*
 * SysmonTransportCleanup - Close handles, delete CS
 */
void SysmonTransportCleanup(_Inout_ PSYSMON_TRANSPORT Transport);

/*
 * SysmonTransportConnect - Open device, send INIT handshake
 *   Input buffer: 4 bytes (version/mode)
 */
SYSMON_STATUS SysmonTransportConnect(_Inout_ PSYSMON_TRANSPORT Transport);

/*
 * SysmonTransportDisconnect - Send STOP, close device handle
 */
void SysmonTransportDisconnect(_Inout_ PSYSMON_TRANSPORT Transport);

/*
 * SysmonSendConfigNotify - Send CONFIG_NOTIFY (0x08) to trigger driver config reload
 */
SYSMON_STATUS SysmonSendConfigNotify(_In_ PSYSMON_TRANSPORT Transport);

/*
 * SysmonSendStop - Send STOP command (0x14)
 */
SYSMON_STATUS SysmonSendStop(_In_ PSYSMON_TRANSPORT Transport);

/*
 * SysmonRecvEvent - Overlapped event receive
 *   Output buffer: up to 0x40000 bytes
 *   Returns bytes received in *BytesReturned
 *   Returns ERROR_TIMEOUT when stop event is signaled and ERROR_RETRY when
 *   the periodic health-check wait expires.
 */
SYSMON_STATUS SysmonRecvEvent(
    _In_ PSYSMON_TRANSPORT Transport,
    _Out_writes_bytes_to_(BufferSize, *BytesReturned) PVOID Buffer,
    _In_ DWORD BufferSize,
    _Out_ PDWORD BytesReturned);

/*
 * SysmonRecvStats - Overlapped stats receive
 *   Output buffer: up to 0x40000 bytes
 */
SYSMON_STATUS SysmonRecvStats(
    _In_ PSYSMON_TRANSPORT Transport,
    _Out_writes_bytes_to_(BufferSize, *BytesReturned) PVOID Buffer,
    _In_ DWORD BufferSize,
    _Out_ PDWORD BytesReturned);

/*
 * SysmonSendProcessCacheRequest - Send PROCESS_CACHE (0x0c)
 *   Input: 8 bytes, Output: 0x4002 bytes
 */
SYSMON_STATUS SysmonSendProcessCacheRequest(
    _In_ PSYSMON_TRANSPORT Transport,
    _In_reads_bytes_(8) PVOID InputBuffer,
    _Out_writes_bytes_to_(0x4002, *BytesReturned) PVOID OutputBuffer,
    _Out_ PDWORD BytesReturned);

SYSMON_STATUS SysmonQueryProcessCache(
    _In_ PSYSMON_TRANSPORT Transport,
    _In_ DWORD ProcessId,
    _Out_ PSYSMON_PROCESS_CACHE_RESPONSE Response);

BOOL SysmonResolveSidStringToAccountName(
    _In_z_ PCWSTR SidText,
    _Out_writes_(BufferChars) PWCHAR Buffer,
    _In_ size_t BufferChars);

/*
 * SysmonSendQueryAnswer - Send QUERY_ANSWER (0x10)
 *   Input: 0x60 bytes
 */
SYSMON_STATUS SysmonSendQueryAnswer(
    _In_ PSYSMON_TRANSPORT Transport,
    _In_reads_bytes_(SYSMON_QUERY_ANSWER_SIZE) PVOID InputBuffer);

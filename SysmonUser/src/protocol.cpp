/*
 * protocol.c - DeviceIoControl wrapper, overlapped IO, reconnect logic
 * Strictly aligned with original Sysmon64.exe protocol (0x8340xxxx codes)
 */

#include "../include/protocol.h"
#include "../include/config.h"

#include <sddl.h>

#include "../include/runtime.hpp"

/*
 * SysmonTransportInit - Initialize transport, create events
 * Original: sub_140089a70 preamble (create events, critical section)
 */
SYSMON_STATUS SysmonTransportInit(
    PSYSMON_TRANSPORT Transport,
    HANDLE StopEvent)
{
    if (!Transport || !StopEvent) {
        return SYSMON_ERROR_INVALID_PARAM;
    }

    ZeroMemory(Transport, sizeof(SYSMON_TRANSPORT));
    Transport->DeviceHandle = INVALID_HANDLE_VALUE;
    Transport->StopEvent = StopEvent;
    Transport->Connected = FALSE;

    /* Create auto-reset event for driver overlapped notifications */
    Transport->DriverEvent = CreateEventW(NULL, FALSE, FALSE, NULL);
    if (Transport->DriverEvent == NULL) {
        return GetLastError();
    }

    InitializeCriticalSection(&Transport->Lock);

    /* Build device path: \\.\ServiceName */
    _snwprintf_s(Transport->DevicePath, _countof(Transport->DevicePath),
        _TRUNCATE, L"\\\\.\\%s", SYSMON_SERVICE_NAME);

    return SYSMON_SUCCESS;
}

/*
 * SysmonTransportCleanup - Close handles, delete CS
 */
void SysmonTransportCleanup(PSYSMON_TRANSPORT Transport)
{
    if (!Transport) return;

    SysmonTransportDisconnect(Transport);

    if (Transport->DriverEvent != NULL) {
        ScopedHandle driverEvent;
        driverEvent.reset(Transport->DriverEvent);
        Transport->DriverEvent = NULL;
    }

    DeleteCriticalSection(&Transport->Lock);
}

/*
 * SysmonTransportConnect - Open device and send INIT handshake
 *
 * Original (sub_140089a70):
 *   var_228 = sprintf("\\.\%s", data_1401b4110)  [service name]
 *   var_238 = SYSMON_PROTOCOL_INIT_HANDSHAKE_VALUE [version/mode input]
 *   var_258 = 3                                   [mode]
 *   CreateFileW(var_228, 0xC0000000, 0, NULL, OPEN_EXISTING, 0x40000080, NULL)
 *   DeviceIoControl(handle, 0x83400000, &var_238, 4, NULL, 0, ...)
 */
SYSMON_STATUS SysmonTransportConnect(PSYSMON_TRANSPORT Transport)
{
    ScopedHandle deviceHandle;
    DWORD initInput = SYSMON_PROTOCOL_INIT_HANDSHAKE_VALUE;
    DWORD bytesReturned = 0;
    BOOL success;

    if (Transport == NULL) {
        return SYSMON_ERROR_INVALID_PARAM;
    }

    {
        CriticalSectionGuard transportLock(&Transport->Lock);

        /* Close existing handle if any */
        if (Transport->DeviceHandle != INVALID_HANDLE_VALUE) {
            ScopedHandle existingHandle;
            existingHandle.reset(Transport->DeviceHandle);
            Transport->DeviceHandle = INVALID_HANDLE_VALUE;
        }
        Transport->Connected = FALSE;

        /* Open device with overlapped + security flags matching original */
        deviceHandle.reset(CreateFileW(
            Transport->DevicePath,
            GENERIC_READ | GENERIC_WRITE,   /* 0xC0000000 */
            0,                /* 0 */
            NULL,
            OPEN_EXISTING,
            FILE_FLAG_OVERLAPPED | FILE_ATTRIBUTE_NORMAL,  /* 0x40000080 */
            NULL));

        if (!deviceHandle.valid()) {
            return GetLastError();
        }

        /* Send INIT handshake (0x83400000) with version data */
        success = DeviceIoControl(
            deviceHandle.get(),
            SYSMON_IOCTL_INIT,
            &initInput, sizeof(initInput),  /* 4 bytes input */
            NULL, 0,                         /* No output */
            &bytesReturned,
            NULL);

        if (!success) {
            return GetLastError();
        }

        Transport->DeviceHandle = deviceHandle.release();
        Transport->Connected = TRUE;
    }
    return SYSMON_SUCCESS;
}

/*
 * SysmonTransportDisconnect - Send STOP and close device
 * Original (sub_14008adc0): DeviceIoControl(rcx, 0x83400014, ...)
 */
void SysmonTransportDisconnect(PSYSMON_TRANSPORT Transport)
{
    if (!Transport) return;

    {
        CriticalSectionGuard transportLock(&Transport->Lock);

        if (Transport->DeviceHandle != INVALID_HANDLE_VALUE &&
            Transport->DeviceHandle != NULL) {
            /* Send STOP command */
            DWORD bytesReturned = 0;
            DeviceIoControl(
                Transport->DeviceHandle,
                SYSMON_IOCTL_STOP,
                NULL, 0,
                NULL, 0,
                &bytesReturned,
                NULL);

            ScopedHandle deviceHandle;
            deviceHandle.reset(Transport->DeviceHandle);
            Transport->DeviceHandle = INVALID_HANDLE_VALUE;
        }

        Transport->Connected = FALSE;
    }
}

/*
 * SysmonSendConfigNotify - Send config refresh notification
 * Original (ConfigMonitorThread): DeviceIoControl(handle, 0x83400008, ...)
 *
 * Opens a separate handle to the device (matching original behavior:
 * ConfigMonitorThread opens its own handle for each notification)
 */
SYSMON_STATUS SysmonSendConfigNotify(PSYSMON_TRANSPORT Transport)
{
    ScopedHandle tempDevice;
    DWORD bytesReturned = 0;
    BOOL success;

    /* Original opens a separate handle for config notify */
    tempDevice.reset(CreateFileW(
        Transport->DevicePath,
        GENERIC_READ | GENERIC_WRITE,
        0,
        NULL,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        NULL));

    if (!tempDevice.valid()) {
        return GetLastError();
    }

    success = DeviceIoControl(
        tempDevice.get(),
        SYSMON_IOCTL_CONFIG_NOTIFY,
        NULL, 0,
        NULL, 0,
        &bytesReturned,
        NULL);

    return success ? SYSMON_SUCCESS : GetLastError();
}

/*
 * SysmonSendStop - Send STOP command
 */
SYSMON_STATUS SysmonSendStop(PSYSMON_TRANSPORT Transport)
{
    DWORD bytesReturned = 0;
    BOOL success;

    if (!Transport || Transport->DeviceHandle == INVALID_HANDLE_VALUE) {
        return SYSMON_ERROR_INVALID_PARAM;
    }

    success = DeviceIoControl(
        Transport->DeviceHandle,
        SYSMON_IOCTL_STOP,
        NULL, 0,
        NULL, 0,
        &bytesReturned,
        NULL);

    return success ? SYSMON_SUCCESS : GetLastError();
}

/*
 * SysmonRecvEvent - Overlapped event receive with stop-aware wait
 *
 * Original (sub_14008a570 event loop):
 *   DeviceIoControl(handle, 0x83400004, NULL, 0, buffer, 0x40000, &bytes, &overlapped)
 *   On ERROR_IO_INCOMPLETE (0x3E5):
 *     WaitForMultipleObjects(2, [driverEvent, stopEvent], FALSE, INFINITE)
 *     If index==1 → stop signaled, break
 *     GetOverlappedResult → get event data
 *   On ERROR_INVALID_HANDLE (6) → reconnect loop (10 retries, 500ms sleep)
 *   Validate event size >= 0x358
 */
SYSMON_STATUS SysmonRecvEvent(
    PSYSMON_TRANSPORT Transport,
    PVOID Buffer,
    DWORD BufferSize,
    PDWORD BytesReturned)
{
    OVERLAPPED overlapped;
    DWORD bytesReturned = 0;
    BOOL success;
    DWORD waitResult;

    if (!Transport || !Buffer || !BytesReturned) {
        return SYSMON_ERROR_INVALID_PARAM;
    }

    ZeroMemory(&overlapped, sizeof(OVERLAPPED));
    overlapped.hEvent = Transport->DriverEvent;

retry:
    /* Issue overlapped IOCTL */
    success = DeviceIoControl(
        Transport->DeviceHandle,
        SYSMON_IOCTL_GET_EVENT,
        NULL, 0,
        Buffer, BufferSize,
        &bytesReturned,
        &overlapped);

    if (!success) {
        DWORD err = GetLastError();

        if (err == ERROR_IO_PENDING) {
            /* Wait for either driver event or stop event */
            HANDLE waitHandles[2] = { Transport->DriverEvent, Transport->StopEvent };
            waitResult = WaitForMultipleObjects(2, waitHandles, FALSE, 1000);

            if (waitResult == WAIT_TIMEOUT ||
                waitResult == WAIT_OBJECT_0 + 1) {
                BOOL stopRequested = waitResult == WAIT_OBJECT_0 + 1;

                /*
                 * Do not return while the IRP still owns this stack OVERLAPPED
                 * (or the caller's output buffer).  The health-check timeout
                 * re-enters this function and would otherwise reuse both
                 * objects while the cancelled request can still complete.
                 */
                CancelIoEx(Transport->DeviceHandle, &overlapped);
                (void)GetOverlappedResult(
                    Transport->DeviceHandle,
                    &overlapped,
                    &bytesReturned,
                    TRUE);
                *BytesReturned = 0;
                return stopRequested ? ERROR_TIMEOUT : ERROR_RETRY;
            }

            /* Driver event signaled - get result */
            if (!GetOverlappedResult(Transport->DeviceHandle, &overlapped, &bytesReturned, FALSE)) {
                err = GetLastError();
                /* Reconnect on handle errors */
                if (err == ERROR_INVALID_HANDLE || err == ERROR_ACCESS_DENIED) {
                    goto reconnect;
                }
                return err;
            }
        } else if (err == ERROR_INVALID_HANDLE || err == ERROR_ACCESS_DENIED) {
            goto reconnect;
        } else {
            return err;
        }
    }

    /* Check stop event before processing */
    if (WaitForSingleObject(Transport->StopEvent, 0) == WAIT_OBJECT_0) {
        *BytesReturned = 0;
        return ERROR_TIMEOUT;
    }

    *BytesReturned = bytesReturned;
    return SYSMON_SUCCESS;

reconnect:
    /* Reconnect loop - matching original: 10 retries, 500ms sleep */
    {
        int retries;
        for (retries = 0; retries < SYSMON_RECONNECT_MAX_RETRIES; retries++) {
            if (WaitForSingleObject(Transport->StopEvent, 0) == WAIT_OBJECT_0) {
                *BytesReturned = 0;
                return ERROR_TIMEOUT;
            }

            Sleep(SYSMON_RECONNECT_SLEEP_MS);

            if (SysmonTransportConnect(Transport) == SYSMON_SUCCESS) {
                /* Re-notify config after reconnect */
                SysmonSendConfigNotify(Transport);
                goto retry;
            }
        }

        SysmonLogError(SYSMON_COMPONENT_PROTOCOL, GetLastError(),
            "Failed to access the driver after %d retries", SYSMON_RECONNECT_MAX_RETRIES);
        *BytesReturned = 0;
        return ERROR_CONNECTION_UNAVAIL;
    }
}

/*
 * SysmonRecvStats - Overlapped stats receive
 * Original (sub_14008a210): DeviceIoControl(handle, 0x83400018, NULL, 0, buf, 0x40000, ...)
 */
SYSMON_STATUS SysmonRecvStats(
    PSYSMON_TRANSPORT Transport,
    PVOID Buffer,
    DWORD BufferSize,
    PDWORD BytesReturned)
{
    OVERLAPPED overlapped;
    DWORD bytesReturned = 0;
    BOOL success;
    HANDLE waitHandles[2];

    if (!Transport || !Buffer || !BytesReturned) {
        return SYSMON_ERROR_INVALID_PARAM;
    }

    ZeroMemory(&overlapped, sizeof(OVERLAPPED));
    overlapped.hEvent = Transport->DriverEvent;

    success = DeviceIoControl(
        Transport->DeviceHandle,
        SYSMON_IOCTL_GET_STATS,
        NULL, 0,
        Buffer, BufferSize,
        &bytesReturned,
        &overlapped);

    if (!success) {
        DWORD err = GetLastError();
        if (err == ERROR_IO_PENDING) {
            waitHandles[0] = Transport->DriverEvent;
            waitHandles[1] = Transport->StopEvent;
            DWORD waitResult = WaitForMultipleObjects(2, waitHandles, FALSE, INFINITE);
            if (waitResult == 1) {
                CancelIo(Transport->DeviceHandle);
                *BytesReturned = 0;
                return ERROR_TIMEOUT;
            }
            if (!GetOverlappedResult(Transport->DeviceHandle, &overlapped, &bytesReturned, FALSE)) {
                return GetLastError();
            }
        } else {
            return err;
        }
    }

    *BytesReturned = bytesReturned;
    return SYSMON_SUCCESS;
}

/*
 * SysmonSendProcessCacheRequest - Process cache query
 * Original (sub_14007810a): DeviceIoControl(handle, 0x8340000c, &input, 8, &output, 0x4002, ...)
 */
SYSMON_STATUS SysmonSendProcessCacheRequest(
    PSYSMON_TRANSPORT Transport,
    PVOID InputBuffer,
    PVOID OutputBuffer,
    PDWORD BytesReturned)
{
    BOOL success;

    if (!Transport || !InputBuffer || !OutputBuffer || !BytesReturned) {
        return SYSMON_ERROR_INVALID_PARAM;
    }

    success = DeviceIoControl(
        Transport->DeviceHandle,
        SYSMON_IOCTL_PROCESS_CACHE,
        InputBuffer, 8,
        OutputBuffer, SYSMON_PROCESS_CACHE_OUT,
        BytesReturned,
        NULL);

    return success ? SYSMON_SUCCESS : GetLastError();
}

SYSMON_STATUS SysmonQueryProcessCache(
    PSYSMON_TRANSPORT Transport,
    DWORD ProcessId,
    PSYSMON_PROCESS_CACHE_RESPONSE Response)
{
    SYSMON_PROCESS_CACHE_QUERY query;
    BYTE *responseBuffer = NULL;
    PSYSMON_PROCESS_CACHE_RESPONSE wireResponse;
    SYSMON_STATUS status;
    DWORD bytesReturned = 0;

    if (!Transport || !Response) {
        return SYSMON_ERROR_INVALID_PARAM;
    }

    ZeroMemory(&query, sizeof(query));
    ZeroMemory(Response, sizeof(*Response));
    responseBuffer = static_cast<BYTE *>(SYSMON_ALLOC(SYSMON_PROCESS_CACHE_OUT));
    if (responseBuffer == NULL) {
        return SYSMON_ERROR_OUT_OF_MEMORY;
    }
    query.ProcessId = ProcessId;
    query.QueryFlags = SYSMON_PROCESS_CACHE_QUERY_FLAG;

    status = SysmonSendProcessCacheRequest(
        Transport,
        &query,
        responseBuffer,
        &bytesReturned);
    if (status != SYSMON_SUCCESS) {
        SYSMON_FREE(responseBuffer);
        return status;
    }

    if (bytesReturned < sizeof(*Response)) {
        SYSMON_FREE(responseBuffer);
        return ERROR_INVALID_DATA;
    }

    wireResponse = (PSYSMON_PROCESS_CACHE_RESPONSE)responseBuffer;
    if (wireResponse->Signature != SYSMON_PROCESS_CACHE_SIGNATURE ||
        wireResponse->Version != SYSMON_PROCESS_CACHE_VERSION ||
        wireResponse->ProcessId != ProcessId) {
        SYSMON_FREE(responseBuffer);
        return ERROR_INVALID_DATA;
    }

    CopyMemory(Response, wireResponse, sizeof(*Response));
    SYSMON_FREE(responseBuffer);

    return SYSMON_SUCCESS;
}

BOOL SysmonResolveSidStringToAccountName(
    PCWSTR SidText,
    PWCHAR Buffer,
    size_t BufferChars)
{
    WCHAR userName[128];
    WCHAR domainName[128];
    DWORD userNameChars = (DWORD)_countof(userName);
    DWORD domainNameChars = (DWORD)_countof(domainName);
    SID_NAME_USE sidUse;
    PSID sid = NULL;
    BOOL success = FALSE;

    if (Buffer == NULL || BufferChars == 0) {
        return FALSE;
    }

    Buffer[0] = L'\0';
    if (SidText == NULL || SidText[0] == L'\0' ||
        (SidText[0] == L'-' && SidText[1] == L'\0')) {
        return FALSE;
    }

    if (!ConvertStringSidToSidW(SidText, &sid)) {
        wcsncpy_s(Buffer, BufferChars, SidText, _TRUNCATE);
        return TRUE;
    }

    if (LookupAccountSidW(
            NULL,
            sid,
            userName,
            &userNameChars,
            domainName,
            &domainNameChars,
            &sidUse) &&
        userName[0] != L'\0') {
        if (domainName[0] != L'\0') {
            _snwprintf_s(
                Buffer,
                BufferChars,
                _TRUNCATE,
                L"%ls\\%ls",
                domainName,
                userName);
        } else {
            wcsncpy_s(Buffer, BufferChars, userName, _TRUNCATE);
        }
        success = TRUE;
    } else {
        wcsncpy_s(Buffer, BufferChars, SidText, _TRUNCATE);
        success = TRUE;
    }

    LocalFree(sid);
    return success;
}

/*
 * SysmonSendQueryAnswer - Query answer send
 * Original: DeviceIoControl(handle, 0x83400010, &data, 0x60, NULL, 0, ...)
 */
SYSMON_STATUS SysmonSendQueryAnswer(
    PSYSMON_TRANSPORT Transport,
    PVOID InputBuffer)
{
    DWORD bytesReturned = 0;
    BOOL success;

    if (!Transport || !InputBuffer) {
        return SYSMON_ERROR_INVALID_PARAM;
    }

    success = DeviceIoControl(
        Transport->DeviceHandle,
        SYSMON_IOCTL_QUERY_ANSWER,
        InputBuffer, SYSMON_QUERY_ANSWER_SIZE,
        NULL, 0,
        &bytesReturned,
        NULL);

    return success ? SYSMON_SUCCESS : GetLastError();
}


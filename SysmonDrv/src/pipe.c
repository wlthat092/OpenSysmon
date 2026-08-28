#include "pipe.h"
#include "queue.h"
#include "event.h"
#include "driver.h"
#include "processinfo.h"

/*
 * PipeEvent (Events 17, 18) - Named Pipe Monitoring
 *
 * Reverse guidance:
 *   - identify NPFS by volume identity (\Device\NamedPipe), not by filename
 *   - classify server creation separately from client connection
 *   - carry the pipe name captured from the file object into the event
 */

typedef enum _SYSMON_PIPE_OBJECT_TYPE {
    SysmonPipeObjectNone = 0,
    SysmonPipeObjectMailslot = 1,
    SysmonPipeObjectNamedPipe = 2
} SYSMON_PIPE_OBJECT_TYPE;

static SYSMON_PIPE_OBJECT_TYPE
SysmonGetPipeObjectType(_In_ PCFLT_RELATED_OBJECTS FltObjects)
{
    UNICODE_STRING volumeName;
    UNICODE_STRING namedPipeDevice;
    UNICODE_STRING mailslotDevice;
    PWCHAR volumeBuffer;
    ULONG bufferSizeNeeded;
    NTSTATUS status;

    if (FltObjects == NULL || FltObjects->Volume == NULL) {
        return SysmonPipeObjectNone;
    }

    bufferSizeNeeded = 0;
    status = FltGetVolumeName(FltObjects->Volume, NULL, &bufferSizeNeeded);
    if (status != STATUS_BUFFER_TOO_SMALL || bufferSizeNeeded < sizeof(WCHAR)) {
        return SysmonPipeObjectNone;
    }

    if (bufferSizeNeeded > 1024) {
        return SysmonPipeObjectNone;
    }

    volumeBuffer = (PWCHAR)SysmonAllocatePool(bufferSizeNeeded);
    if (volumeBuffer == NULL) {
        return SysmonPipeObjectNone;
    }

    RtlZeroMemory(volumeBuffer, bufferSizeNeeded);
    volumeName.Buffer = volumeBuffer;
    volumeName.Length = 0;
    volumeName.MaximumLength = (USHORT)bufferSizeNeeded;

    status = FltGetVolumeName(FltObjects->Volume, &volumeName, NULL);
    RtlInitUnicodeString(&namedPipeDevice, L"\\Device\\NamedPipe");
    RtlInitUnicodeString(&mailslotDevice, L"\\Device\\Mailslot");

    if (NT_SUCCESS(status)) {
        if (RtlCompareUnicodeString(&volumeName, &namedPipeDevice, TRUE) == 0) {
            SysmonFreePool(volumeBuffer);
            return SysmonPipeObjectNamedPipe;
        }

        if (RtlCompareUnicodeString(&volumeName, &mailslotDevice, TRUE) == 0) {
            SysmonFreePool(volumeBuffer);
            return SysmonPipeObjectMailslot;
        }
    }

    SysmonFreePool(volumeBuffer);
    return SysmonPipeObjectNone;
}

static VOID
SysmonCopyPipeName(
    _In_opt_ PCUNICODE_STRING FileName,
    _Out_writes_(BufferChars) PWCHAR Buffer,
    _In_ ULONG BufferChars)
{
    static const WCHAR namedPipeDevice[] = L"\\Device\\NamedPipe";
    static const WCHAR anonymousPipe[] = L"<Anonymous Pipe>";
    PCWSTR source;
    ULONG sourceChars;
    ULONG prefixChars;
    ULONG copyChars;

    if (Buffer == NULL || BufferChars == 0) {
        return;
    }

    Buffer[0] = L'\0';

    if (FileName == NULL || FileName->Buffer == NULL) {
        copyChars = RTL_NUMBER_OF(anonymousPipe) - 1;
        if (copyChars >= BufferChars) {
            copyChars = BufferChars - 1;
        }
        RtlCopyMemory(Buffer, anonymousPipe, copyChars * sizeof(WCHAR));
        Buffer[copyChars] = L'\0';
        return;
    }

    if (FileName->Length == 0) {
        copyChars = RTL_NUMBER_OF(anonymousPipe) - 1;
        if (copyChars >= BufferChars) {
            copyChars = BufferChars - 1;
        }
        RtlCopyMemory(Buffer, anonymousPipe, copyChars * sizeof(WCHAR));
        Buffer[copyChars] = L'\0';
        return;
    }

    source = FileName->Buffer;
    sourceChars = FileName->Length / sizeof(WCHAR);
    prefixChars = (ULONG)((sizeof(namedPipeDevice) / sizeof(WCHAR)) - 1);

    if (sourceChars >= prefixChars &&
        RtlCompareMemory(source, namedPipeDevice, prefixChars * sizeof(WCHAR)) ==
            prefixChars * sizeof(WCHAR)) {
        source += prefixChars;
        sourceChars -= prefixChars;
    }

    copyChars = sourceChars;
    if (copyChars >= BufferChars) {
        copyChars = BufferChars - 1;
    }

    if (copyChars > 0) {
        RtlCopyMemory(Buffer, source, copyChars * sizeof(WCHAR));
    }
    Buffer[copyChars] = L'\0';
}

/*
 * Build and enqueue a pipe event.
 */
NTSTATUS
SysmonBuildPipeEvent(
    _In_ PFLT_CALLBACK_DATA Data,
    _In_ ULONG EventType,  /* 17 = Created, 18 = Connected */
    _In_opt_z_ PCWSTR PipeName,
    _Outptr_ PSYSMON_EVENT_UNION *Event)
{
    PSYSMON_EVENT_UNION event = NULL;
    SYSMON_EVENT_PAYLOAD_BUILDER builder;
      SYSMON_PROCESS_INFO *processInfo = NULL;
      ULONG processId;
      PCWSTR processGuid = NULL;
      PCWSTR image = NULL;
      PCWSTR user = NULL;
      PCWSTR eventTypeName;

    *Event = NULL;

    if (KeGetCurrentIrql() != PASSIVE_LEVEL) {
        DbgPrintEx(
            DPFLTR_DEFAULT_ID,
            DPFLTR_WARNING_LEVEL,
            "[SysmonDrv] pipe event deferred: callback IRQL is not PASSIVE_LEVEL\n");
        return STATUS_UNSUCCESSFUL;
    }

    event = SysmonAllocateEvent((SYSMON_EVENT_ID)EventType);
    if (event == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    processId = (ULONG)(ULONG_PTR)FltGetRequestorProcessId(Data);

    processInfo = (SYSMON_PROCESS_INFO *)SysmonAllocatePool(sizeof(SYSMON_PROCESS_INFO));
      if (processInfo != NULL &&
          NT_SUCCESS(SysmonCollectProcessInfo((HANDLE)(ULONG_PTR)processId, processInfo))) {
          processGuid = processInfo->ProcessGuid;
          image = processInfo->ImagePath;
          user = processInfo->UserSid;
      }

      eventTypeName =
          (EventType == SysmonEventPipeCreated) ? L"CreatePipe" : L"ConnectPipe";

      if (EventType == SysmonEventPipeCreated) {
          SYSMON_EVENT_PIPE_CREATED_PAYLOAD *eventData;

          SysmonBeginStringPayload(event, sizeof(SYSMON_EVENT_PIPE_CREATED_PAYLOAD), &builder);
          eventData = (SYSMON_EVENT_PIPE_CREATED_PAYLOAD *)event->RawData;
          eventData->ProcessId = processId;
          SysmonAddStringField(event, &builder, &eventData->RuleName, L"-");
          SysmonAddStringField(event, &builder, &eventData->EventType, eventTypeName);
          SysmonAddCurrentUtcTimeField(event, &builder, &eventData->UtcTime);
          SysmonAddStringField(event, &builder, &eventData->ProcessGuid, processGuid);
          SysmonAddStringField(event, &builder, &eventData->PipeName, PipeName);
          SysmonAddStringField(event, &builder, &eventData->Image, image);
          SysmonAddStringField(event, &builder, &eventData->User, user);
      } else {
          SYSMON_EVENT_PIPE_PAYLOAD *eventData;

          SysmonBeginStringPayload(event, sizeof(SYSMON_EVENT_PIPE_PAYLOAD), &builder);
          eventData = (SYSMON_EVENT_PIPE_PAYLOAD *)event->RawData;
          eventData->ProcessId = processId;
          SysmonAddStringField(event, &builder, &eventData->RuleName, L"-");
          SysmonAddStringField(event, &builder, &eventData->EventType, eventTypeName);
          SysmonAddCurrentUtcTimeField(event, &builder, &eventData->UtcTime);
          SysmonAddStringField(event, &builder, &eventData->ProcessGuid, processGuid);
          SysmonAddStringField(event, &builder, &eventData->PipeName, PipeName);
          SysmonAddStringField(event, &builder, &eventData->Image, image);
          SysmonAddStringField(event, &builder, &eventData->User, user);
      }

    if (processInfo != NULL) {
        SysmonFreePool(processInfo);
    }

    *Event = event;
    return STATUS_SUCCESS;
}

/*
 * Classify named-pipe operations using the same primary signal as the reverse:
 * NPFS volume identity. Event 17 comes from create-named-pipe; Event 18 comes
 * from a normal create/open against an existing named pipe.
 */
NTSTATUS
SysmonClassifyPipeCreateEvent(
    _In_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Out_ PULONG EventType,
    _Out_writes_(PipeNameChars) PWCHAR PipeName,
    _In_ ULONG PipeNameChars)
{
    SYSMON_PIPE_OBJECT_TYPE pipeType;

    if (EventType == NULL || PipeName == NULL || PipeNameChars == 0) {
        return STATUS_INVALID_PARAMETER;
    }

    *EventType = 0;
    PipeName[0] = L'\0';

    pipeType = SysmonGetPipeObjectType(FltObjects);
    if (pipeType != SysmonPipeObjectNamedPipe) {
        return STATUS_SUCCESS;
    }

    if (Data->Iopb->MajorFunction == IRP_MJ_CREATE_NAMED_PIPE) {
        *EventType = SysmonEventPipeCreated;
    } else if (Data->Iopb->MajorFunction == IRP_MJ_CREATE) {
        *EventType = SysmonEventPipeConnected;
    } else {
        return STATUS_SUCCESS;
    }

    if (FltObjects != NULL && FltObjects->FileObject != NULL) {
        SysmonCopyPipeName(&FltObjects->FileObject->FileName, PipeName, PipeNameChars);
    } else {
        SysmonCopyPipeName(NULL, PipeName, PipeNameChars);
    }

    return STATUS_SUCCESS;
}

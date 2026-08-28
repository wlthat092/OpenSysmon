#pragma once
#include "common.h"
#include "event.h"
#include "rules.h"

typedef SYSMON_EVENT_PROCESS_CREATE_PAYLOAD
    SYSMON_PROCESS_CREATE_EVENT_DATA, *PSYSMON_PROCESS_CREATE_EVENT_DATA;

typedef SYSMON_EVENT_PROCESS_TERMINATE_PAYLOAD
    SYSMON_PROCESS_TERMINATE_EVENT_DATA, *PSYSMON_PROCESS_TERMINATE_EVENT_DATA;

typedef struct _SYSMON_PROCESS_DEBUG_STATS {
    ULONG ProcessCallbackCount;
    ULONG ProcessCreateAttemptCount;
    ULONG ProcessCreateCapturedCount;
    ULONG ProcessCreateFilteredCount;
    ULONG ProcessCreateDeliveryCount;
    ULONG ProcessCreateFailureCount;
    ULONG GenericFilterEvaluatedCount;
    ULONG GenericFilterDroppedCount;
    ULONG LastEvaluatedEventId;
    ULONG LastDroppedEventId;
    ULONG RuntimeGroupCount;
    ULONG RuntimeEventRuleCount;
    ULONG ReloadGeneration;
    ULONG FileCreateCandidateCount;
    ULONG FileCreatePostCreateCount;
    ULONG FileCreateIrqlDropCount;
    ULONG FileCreateStatusFailureCount;
    ULONG FileCreateNotCreatedCount;
    ULONG FileCreatePublishAttemptCount;
    ULONG LastFileCreateStatus;
    ULONG LastFileCreateInfo;
    ULONG LastFileCreateIrql;
    ULONG LastFileCreateDisposition;
    ULONG LastFileCreateReportStatus;
    /* Keep FileBlock stats ABI-stable; Probe-SysmonStats.ps1 decodes these fields by ordinal. */
    ULONG FileBlockContextCreateCount;
    ULONG FileBlockWriteCallbackCount;
    ULONG FileBlockSawWriteCount;
    ULONG FileBlockHeaderCheckCount;
    ULONG FileBlockHeaderMatchCount;
    ULONG FileBlockFinalizeAttemptCount;
    ULONG FileBlockFinalizeSkipNoWriteCount;
    ULONG FileBlockFinalizeSkipNotPeCount;
    ULONG FileBlockFinalizeWouldBlockCount;
    ULONG FileBlockFinalizeWouldDetectCount;
    ULONG FileBlockActionSuccessCount;
    ULONG FileBlockEvent27Count;
    ULONG FileBlockEvent29Count;
    ULONG FileBlockLastFlags;
    ULONG FileBlockLastActionStatus;
    ULONG FileBlockLastReportStatus;
    ULONG ObRegisterAttemptCount;
    ULONG ObRegisterSuccessCount;
    ULONG ObRegisterLastStatus;
    ULONG ObPostCallbackCount;
    ULONG ObWorkItemQueuedCount;
    ULONG ObWorkItemProcessedCount;
    ULONG ObEventPublishedCount;
    ULONG ContextEnabled;
    ULONG ContextProcessNotifyEnabled;
    ULONG ContextThreadNotifyEnabled;
    ULONG ContextProcessAccessNotifyEnabled;
    ULONG RuntimeHasProcessAccessEvent;
    ULONG StatsStructSize;
    ULONG StatsVersion;
    ULONG RuntimeFirstEventId;
    ULONG RuntimeFirstRuleCount;
    ULONG RuntimeFirstMatchType;
    ULONG ObDropObjectTypeMismatch;
    ULONG ObDropOperationMismatch;
    ULONG ObDropKernelHandle;
    ULONG ObDropSameProcess;
    ULONG ObDropQueueLimit;
    ULONG ObDropWorkerUnavailable;
    ULONG ObDropAllocationFailure;
    ULONG ThreadCallbackCount;
    ULONG ThreadCreateCallbackCount;
    ULONG ThreadDropClaimedPendingCreate;
    ULONG ThreadDropSystemProcess;
    ULONG ThreadDropSystemThread;
    ULONG ThreadDropSelfTarget;
    ULONG ThreadEventPublishedCount;
    ULONG ThreadLastSourceProcessId;
    ULONG ThreadLastTargetProcessId;
    ULONG ThreadLastThreadId;
    ULONG ContextImageNotifyEnabled;
    ULONG ContextImageLoadEventEnabled;
    ULONG ContextHashingAlgorithm;
    ULONG LastImageTargetEventId;
    ULONG LastImageRuleRequirements;
    ULONG LastImageFileInfoRequestMask;
    ULONG LastImageCollectStatus;
    ULONG LastImageHaveFileInfo;
    ULONG LastImageHashValueState;
    ULONG LastImageHashMaskUsed;
    ULONG LastImageHashStatus;
    ULONG LastImageAvailableMask;
    ULONG LastImageFileContentMode;
    ULONG ImageQueueDropCount;
    ULONG LastImageDropReason;
    ULONG EventQueueDropCount;
    ULONG QueryQueueDropCount;
    ULONG LastEventQueueDropReason;
    ULONG LastQueryQueueDropReason;
    ULONG LastEventQueueDropEventId;
    ULONG LastQueryQueueDropType;
    ULONG FileInfoCollectCallCount;
    ULONG FileInfoCacheLookupCount;
    ULONG FileInfoCacheHitCount;
    ULONG FileInfoCacheStoreCount;
    ULONG FileInfoMapAttemptCount;
    ULONG FileInfoMapSuccessCount;
    ULONG FileInfoReadFallbackCount;
    ULONG FileInfoReadRetryCount;
    ULONG FileInfoHashComputeCount;
    ULONG FileInfoVersionParseCount;
    ULONG FileInfoMapUsecTotal;
    ULONG FileInfoReadUsecTotal;
    ULONG FileInfoHashUsecTotal;
    ULONG FileInfoVersionUsecTotal;
    ULONG ImphashCallCount;
    ULONG ImphashReadRvaCallCount;
    ULONG ImphashImportDescriptorCount;
    ULONG ImphashImportEntryCount;
    ULONG ImphashHashedImportCount;
    ULONG ImphashOrdinalImportCount;
    ULONG ImphashSectionCachePoolAllocCount;
    ULONG ImphashSectionCountTotal;
    ULONG TamperTrackProcessCount;
    ULONG TamperCheckCallCount;
    ULONG TamperPendingHitCount;
    ULONG TamperUntrackMissCount;
    ULONG TamperReportCount;
    ULONG TamperLastProcessId;
    ULONG TamperLastStage;
    ULONG TamperLastDecision;
    ULONG TamperLastOpenProcessStatus;
    ULONG TamperLastCaptureStatus;
    ULONG TamperLastQueryImageStatus;
    ULONG TamperLastNormalizeStatus;
    ULONG TamperLastOpenFileStatus;
    ULONG TamperLastReadFileStatus;
    ULONG TamperLookupProcessFailCount;
    ULONG TamperOpenProcessFailCount;
    ULONG TamperCaptureFailCount;
    ULONG TamperQueryImageFailCount;
    ULONG TamperLastQueryFailProcessId;
    ULONG TamperLastQueryFailStatus;
    ULONG TamperPathMismatchCount;
    ULONG TamperOpenFileDeletedCount;
    ULONG TamperOpenFileLockedCount;
    ULONG TamperHeaderMismatchCount;
    ULONG TamperCleanCount;
    ULONG TamperRecentTrackPid0;
    ULONG TamperRecentTrackPid1;
    ULONG TamperRecentTrackPid2;
    ULONG TamperRecentTrackPid3;
    ULONG TamperRecentDecisionPid0;
    ULONG TamperRecentDecisionPid1;
    ULONG TamperRecentDecisionPid2;
    ULONG TamperRecentDecisionPid3;
    ULONG TamperRecentDecisionCode0;
    ULONG TamperRecentDecisionCode1;
    ULONG TamperRecentDecisionCode2;
    ULONG TamperRecentDecisionCode3;
} SYSMON_PROCESS_DEBUG_STATS, *PSYSMON_PROCESS_DEBUG_STATS;

#define SYSMON_PROCESS_DEBUG_STATS_VERSION  14u

typedef struct _SYSMON_PROCESS_CACHE_METADATA {
    ULONG ProcessId;
    LONGLONG CreateTime;
    WCHAR ProcessGuid[SYSMON_MAX_GUID_STRING];
    WCHAR Image[SYSMON_MAX_PATH];
    WCHAR UserSid[SYSMON_MAX_SID_STRING];
} SYSMON_PROCESS_CACHE_METADATA, *PSYSMON_PROCESS_CACHE_METADATA;

#define SYSMON_PROCESS_CREATE_EVENT_SIZE \
    SYSMON_EVENT_CONTRACT_SIZE(SYSMON_EVENT_PROCESS_CREATE_PAYLOAD)

#define SYSMON_PROCESS_TERMINATE_EVENT_SIZE \
    SYSMON_EVENT_CONTRACT_SIZE(SYSMON_EVENT_PROCESS_TERMINATE_PAYLOAD)

NTSTATUS SysmonRegisterProcessNotify(_In_ PDRIVER_OBJECT DriverObject);
VOID SysmonUnregisterProcessNotify(VOID);
NTSTATUS SysmonRegisterThreadNotify(_In_ PDRIVER_OBJECT DriverObject);
VOID SysmonUnregisterThreadNotify(VOID);
NTSTATUS SysmonRegisterImageNotify(_In_ PDRIVER_OBJECT DriverObject);
VOID SysmonUnregisterImageNotify(VOID);

PSYSMON_PROCESS_CREATE_EVENT_DATA
SysmonGetProcessCreateEventData(
    _In_ PSYSMON_EVENT_UNION Event);

BOOLEAN
SysmonExtractProcessCreateField(
    _In_ PSYSMON_EVENT_UNION Event,
    _In_ PCWSTR FieldName,
    _Out_writes_(BufferChars) PWCHAR Buffer,
    _In_ ULONG BufferChars);

VOID
SysmonQueryProcessDebugStats(
    _Out_ PSYSMON_PROCESS_DEBUG_STATS Stats);

VOID
SysmonQueryMinifilterDebugStats(
    _Out_ PSYSMON_PROCESS_DEBUG_STATS Stats);

VOID
SysmonQueryObDebugStats(
    _Out_ PSYSMON_PROCESS_DEBUG_STATS Stats);

VOID
SysmonQueryThreadDebugStats(
    _Out_ PSYSMON_PROCESS_DEBUG_STATS Stats);

VOID
SysmonQueryImageDebugStats(
    _Out_ PSYSMON_PROCESS_DEBUG_STATS Stats);

BOOLEAN
SysmonLookupCachedProcessMetadata(
    _In_ ULONG ProcessId,
    _Out_ PSYSMON_PROCESS_CACHE_METADATA Metadata);

BOOLEAN
SysmonTryFinalizePendingProcessCreate(
    _In_ HANDLE ProcessId);

BOOLEAN
SysmonTryFinalizePendingProcessCreateEx(
    _In_ HANDLE ProcessId,
    _Out_opt_ PBOOLEAN ClaimedPendingCreate);

BOOLEAN
SysmonQueuePendingProcessCreateFinalize(
    _In_ HANDLE ProcessId);

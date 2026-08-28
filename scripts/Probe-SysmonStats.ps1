$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

function Initialize-SysmonNativeType {
    if ('SysmonNative' -as [type]) {
        return
    }

    $assemblyName = New-Object System.Reflection.AssemblyName('SysmonNativeDynamic')
    $assemblyBuilder = [AppDomain]::CurrentDomain.DefineDynamicAssembly(
        $assemblyName,
        [System.Reflection.Emit.AssemblyBuilderAccess]::Run)
    $moduleBuilder = $assemblyBuilder.DefineDynamicModule('SysmonNativeDynamicModule', $false)
    $typeBuilder = $moduleBuilder.DefineType(
        'SysmonNative',
        [System.Reflection.TypeAttributes]'Public, Abstract, Sealed')

    $methodAttributes = [System.Reflection.MethodAttributes]'Public, Static, PinvokeImpl'
    $callingConvention = [System.Reflection.CallingConventions]::Standard
    $winapi = [Runtime.InteropServices.CallingConvention]::Winapi

    $methods = @(
        @{
            Name = 'CreateFileW'
            Dll = 'kernel32.dll'
            ReturnType = [IntPtr]
            ParameterTypes = [Type[]]@(
                [string],
                [UInt32],
                [UInt32],
                [IntPtr],
                [UInt32],
                [UInt32],
                [IntPtr])
            CharSet = [Runtime.InteropServices.CharSet]::Unicode
        }
        @{
            Name = 'DeviceIoControl'
            Dll = 'kernel32.dll'
            ReturnType = [bool]
            ParameterTypes = [Type[]]@(
                [IntPtr],
                [UInt32],
                [IntPtr],
                [UInt32],
                [byte[]],
                [UInt32],
                ([UInt32].MakeByRefType()),
                [IntPtr])
            CharSet = [Runtime.InteropServices.CharSet]::Auto
        }
        @{
            Name = 'CloseHandle'
            Dll = 'kernel32.dll'
            ReturnType = [bool]
            ParameterTypes = [Type[]]@([IntPtr])
            CharSet = [Runtime.InteropServices.CharSet]::Auto
        }
        @{
            Name = 'GetLastError'
            Dll = 'kernel32.dll'
            ReturnType = [UInt32]
            ParameterTypes = [Type[]]@()
            CharSet = [Runtime.InteropServices.CharSet]::Auto
        }
    )

    foreach ($definition in $methods) {
        $methodBuilder = $typeBuilder.DefinePInvokeMethod(
            $definition.Name,
            $definition.Dll,
            $methodAttributes,
            $callingConvention,
            $definition.ReturnType,
            $definition.ParameterTypes,
            $winapi,
            $definition.CharSet)
        $methodBuilder.SetImplementationFlags(
            $methodBuilder.GetMethodImplementationFlags() -bor
            [System.Reflection.MethodImplAttributes]::PreserveSig)
    }

    [void]$typeBuilder.CreateType()
}

function Get-HexUInt32([string]$hex) {
    return [Convert]::ToUInt32($hex, 16)
}

Initialize-SysmonNativeType

$devicePath = "\\.\Sysmon"
$genericRead = Get-HexUInt32 "80000000"
$genericWrite = Get-HexUInt32 "40000000"
$openExisting = [uint32]3
$fileAttributeNormal = [uint32]0x80
$ioctlInit = Get-HexUInt32 "83400000"
$ioctlStats = Get-HexUInt32 "8340001C"
$fieldNames = @(
    'ProcessCallbackCount',
    'ProcessCreateAttemptCount',
    'ProcessCreateCapturedCount',
    'ProcessCreateFilteredCount',
    'ProcessCreateDeliveryCount',
    'ProcessCreateFailureCount',
    'GenericFilterEvaluatedCount',
    'GenericFilterDroppedCount',
    'LastEvaluatedEventId',
    'LastDroppedEventId',
    'RuntimeGroupCount',
    'RuntimeEventRuleCount',
    'ReloadGeneration',
    'FileCreateCandidateCount',
    'FileCreatePostCreateCount',
    'FileCreateIrqlDropCount',
    'FileCreateStatusFailureCount',
    'FileCreateNotCreatedCount',
    'FileCreatePublishAttemptCount',
    'LastFileCreateStatus',
    'LastFileCreateInfo',
    'LastFileCreateIrql',
    'LastFileCreateDisposition',
    'LastFileCreateReportStatus',
    'FileBlockContextCreateCount',
    'FileBlockWriteCallbackCount',
    'FileBlockSawWriteCount',
    'FileBlockHeaderCheckCount',
    'FileBlockHeaderMatchCount',
    'FileBlockFinalizeAttemptCount',
    'FileBlockFinalizeSkipNoWriteCount',
    'FileBlockFinalizeSkipNotPeCount',
    'FileBlockFinalizeWouldBlockCount',
    'FileBlockFinalizeWouldDetectCount',
    'FileBlockActionSuccessCount',
    'FileBlockEvent27Count',
    'FileBlockEvent29Count',
    'FileBlockLastFlags',
    'FileBlockLastActionStatus',
    'FileBlockLastReportStatus',
    'ObRegisterAttemptCount',
    'ObRegisterSuccessCount',
    'ObRegisterLastStatus',
    'ObPostCallbackCount',
    'ObWorkItemQueuedCount',
    'ObWorkItemProcessedCount',
    'ObEventPublishedCount',
    'ContextEnabled',
    'ContextProcessNotifyEnabled',
    'ContextThreadNotifyEnabled',
    'ContextProcessAccessNotifyEnabled',
    'RuntimeHasProcessAccessEvent',
    'StatsStructSize',
    'StatsVersion',
    'RuntimeFirstEventId',
    'RuntimeFirstRuleCount',
    'RuntimeFirstMatchType',
    'ObDropObjectTypeMismatch',
    'ObDropOperationMismatch',
    'ObDropKernelHandle',
    'ObDropSameProcess',
    'ObDropQueueLimit',
    'ObDropWorkerUnavailable',
    'ObDropAllocationFailure',
    'ThreadCallbackCount',
    'ThreadCreateCallbackCount',
    'ThreadDropClaimedPendingCreate',
    'ThreadDropSystemProcess',
    'ThreadDropSystemThread',
    'ThreadDropSelfTarget',
    'ThreadEventPublishedCount',
    'ThreadLastSourceProcessId',
    'ThreadLastTargetProcessId',
    'ThreadLastThreadId',
    'ContextImageNotifyEnabled',
    'ContextImageLoadEventEnabled',
    'ContextHashingAlgorithm',
    'LastImageTargetEventId',
    'LastImageRuleRequirements',
    'LastImageFileInfoRequestMask',
    'LastImageCollectStatus',
    'LastImageHaveFileInfo',
    'LastImageHashValueState',
    'LastImageHashMaskUsed',
    'LastImageHashStatus',
    'LastImageAvailableMask',
    'LastImageFileContentMode',
    'ImageQueueDropCount',
    'LastImageDropReason',
    'EventQueueDropCount',
    'QueryQueueDropCount',
    'LastEventQueueDropReason',
    'LastQueryQueueDropReason',
    'LastEventQueueDropEventId',
    'LastQueryQueueDropType',
    'FileInfoCollectCallCount',
    'FileInfoCacheLookupCount',
    'FileInfoCacheHitCount',
    'FileInfoCacheStoreCount',
    'FileInfoMapAttemptCount',
    'FileInfoMapSuccessCount',
    'FileInfoReadFallbackCount',
    'FileInfoReadRetryCount',
    'FileInfoHashComputeCount',
    'FileInfoVersionParseCount',
    'FileInfoMapUsecTotal',
    'FileInfoReadUsecTotal',
    'FileInfoHashUsecTotal',
    'FileInfoVersionUsecTotal',
    'ImphashCallCount',
    'ImphashReadRvaCallCount',
    'ImphashImportDescriptorCount',
    'ImphashImportEntryCount',
    'ImphashHashedImportCount',
    'ImphashOrdinalImportCount',
    'ImphashSectionCachePoolAllocCount',
    'ImphashSectionCountTotal',
    'TamperTrackProcessCount',
    'TamperCheckCallCount',
    'TamperPendingHitCount',
    'TamperUntrackMissCount',
    'TamperReportCount',
    'TamperLastProcessId',
    'TamperLastStage',
    'TamperLastDecision',
    'TamperLastOpenProcessStatus',
    'TamperLastCaptureStatus',
    'TamperLastQueryImageStatus',
    'TamperLastNormalizeStatus',
    'TamperLastOpenFileStatus',
    'TamperLastReadFileStatus',
    'TamperLookupProcessFailCount',
    'TamperOpenProcessFailCount',
    'TamperCaptureFailCount',
    'TamperQueryImageFailCount',
    'TamperLastQueryFailProcessId',
    'TamperLastQueryFailStatus',
    'TamperPathMismatchCount',
    'TamperOpenFileDeletedCount',
    'TamperOpenFileLockedCount',
    'TamperHeaderMismatchCount',
    'TamperCleanCount',
    'TamperRecentTrackPid0',
    'TamperRecentTrackPid1',
    'TamperRecentTrackPid2',
    'TamperRecentTrackPid3',
    'TamperRecentDecisionPid0',
    'TamperRecentDecisionPid1',
    'TamperRecentDecisionPid2',
    'TamperRecentDecisionPid3',
    'TamperRecentDecisionCode0',
    'TamperRecentDecisionCode1',
    'TamperRecentDecisionCode2',
    'TamperRecentDecisionCode3'
)
$hexFields = @(
    'LastFileCreateStatus',
    'LastFileCreateReportStatus',
    'FileBlockLastFlags',
    'FileBlockLastActionStatus',
    'FileBlockLastReportStatus',
    'ObRegisterLastStatus',
    'LastImageCollectStatus',
    'LastImageHashStatus',
    'TamperLastOpenProcessStatus',
    'TamperLastCaptureStatus',
    'TamperLastQueryImageStatus',
    'TamperLastQueryFailStatus',
    'TamperLastNormalizeStatus',
    'TamperLastOpenFileStatus',
    'TamperLastReadFileStatus'
)

$handle = [SysmonNative]::CreateFileW(
    $devicePath,
    ($genericRead -bor $genericWrite),
    [uint32]0,
    [IntPtr]::Zero,
    $openExisting,
    $fileAttributeNormal,
    [IntPtr]::Zero)

if ($handle -eq [IntPtr]::Zero -or $handle.ToInt64() -eq -1) {
    throw "CreateFileW($devicePath) failed with $([SysmonNative]::GetLastError())"
}

try {
    $initBytes = [BitConverter]::GetBytes([UInt32]0x5f0)
    $initPtr = [Runtime.InteropServices.Marshal]::AllocHGlobal($initBytes.Length)
    $bytesReturned = [uint32]0

    try {
        [Runtime.InteropServices.Marshal]::Copy($initBytes, 0, $initPtr, $initBytes.Length)
        if (-not [SysmonNative]::DeviceIoControl(
                $handle,
                $ioctlInit,
                $initPtr,
                [uint32]$initBytes.Length,
                $null,
                [uint32]0,
                [ref]$bytesReturned,
                [IntPtr]::Zero)) {
            throw "INIT failed with $([SysmonNative]::GetLastError())"
        }
    }
    finally {
        [Runtime.InteropServices.Marshal]::FreeHGlobal($initPtr)
    }

    $outBuffer = New-Object byte[] 4096
    if (-not [SysmonNative]::DeviceIoControl(
            $handle,
            $ioctlStats,
            [IntPtr]::Zero,
            [uint32]0,
            $outBuffer,
            [uint32]$outBuffer.Length,
            [ref]$bytesReturned,
            [IntPtr]::Zero)) {
        throw "GET_STATS failed with $([SysmonNative]::GetLastError())"
    }

    $dwordCount = [int]($bytesReturned / 4)
    $result = [ordered]@{
        DevicePath = $devicePath
        BytesReturned = $bytesReturned
        DwordCount = $dwordCount
    }

    for ($index = 0; $index -lt [Math]::Min($fieldNames.Length, $dwordCount); $index++) {
        $result[$fieldNames[$index]] = [BitConverter]::ToUInt32($outBuffer, $index * 4)
    }

    foreach ($fieldName in $hexFields) {
        if ($result.Contains($fieldName)) {
            $result["$fieldName`Hex"] = ('0x{0:X8}' -f [uint32]$result[$fieldName])
        }
    }

    if ($dwordCount -lt $fieldNames.Length) {
        $result['Warning'] = "Driver returned only $dwordCount DWORDs; script knows $($fieldNames.Length) fields."
    } elseif ($dwordCount -gt $fieldNames.Length) {
        $result['ExtraDwords'] = $dwordCount - $fieldNames.Length
    }

    [pscustomobject]$result | Format-List
}
finally {
    [void][SysmonNative]::CloseHandle($handle)
}

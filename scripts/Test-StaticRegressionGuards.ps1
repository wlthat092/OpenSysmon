param(
    [string]$RepoRoot = (Split-Path $PSScriptRoot -Parent)
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Assert-True {
    param(
        [Parameter(Mandatory = $true)]
        [bool]$Condition,
        [Parameter(Mandatory = $true)]
        [string]$Message
    )

    if (-not $Condition) {
        throw "FAIL: $Message"
    }
}

function Get-SourceText {
    param(
        [Parameter(Mandatory = $true)]
        [string]$RelativePath
    )

    $path = Join-Path $RepoRoot $RelativePath
    Assert-True (Test-Path -LiteralPath $path) "Missing source file: $RelativePath"
    return [System.IO.File]::ReadAllText($path)
}

function Get-SourceSlice {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Text,
        [Parameter(Mandatory = $true)]
        [string]$StartMarker,
        [Parameter(Mandatory = $true)]
        [string]$EndMarker
    )

    $start = $Text.IndexOf($StartMarker, [System.StringComparison]::Ordinal)
    Assert-True ($start -ge 0) "Missing source marker: $StartMarker"
    $end = $Text.IndexOf($EndMarker, $start, [System.StringComparison]::Ordinal)
    Assert-True ($end -gt $start) "Missing source marker: $EndMarker"
    return $Text.Substring($start, $end - $start)
}

$outputCpp = Get-SourceText 'SysmonUser/src/output.cpp'
$installerCpp = Get-SourceText 'SysmonUser/src/installer.cpp'
$userCommonH = Get-SourceText 'SysmonUser/include/common.h'
$userConfigCpp = Get-SourceText 'SysmonUser/src/config.cpp'
$xmlConfigCpp = Get-SourceText 'SysmonUser/src/xml_config.cpp'
$providerMan = Get-SourceText 'SysmonUser/resources/sysmon_provider.man'
$providerH = Get-SourceText 'SysmonUser/resources/sysmon_provider.h'
$schemaEventsXml = Get-SourceText 'schema_events.xml'
$driverProcessH = Get-SourceText 'SysmonDrv/include/process.h'
$driverBuildPs1 = Get-SourceText 'SysmonDrv/build.ps1'
$driverC = Get-SourceText 'SysmonDrv/src/driver.c'
$driverHashH = Get-SourceText 'SysmonDrv/include/hash.h'
$driverHashC = Get-SourceText 'SysmonDrv/src/hash.c'
$driverHashOrdinalInl = Get-SourceText 'SysmonDrv/src/hash_ordinal_lookup.inl'
$driverHashCombined = $driverHashC + "`n" + $driverHashOrdinalInl
$driverImageC = Get-SourceText 'SysmonDrv/src/image.c'
$driverTamperingC = Get-SourceText 'SysmonDrv/src/tampering.c'
$driverFileInfoC = Get-SourceText 'SysmonDrv/src/fileinfo.c'
$driverMapFileByHandle = Get-SourceSlice `
    -Text $driverFileInfoC `
    -StartMarker 'SysmonMapFileByHandle(' `
    -EndMarker 'static VOID'
$probeSysmonStatsPs1 = Get-SourceText 'scripts/Probe-SysmonStats.ps1'
$registryDataC = Get-SourceText 'SysmonDrv/src/registry_data.c'
$minifilterC = Get-SourceText 'SysmonDrv/src/minifilter.c'
$driverRulesC = Get-SourceText 'SysmonDrv/src/rules.c'
$driverEventC = Get-SourceText 'SysmonDrv/src/event.c'
$driverQueueC = Get-SourceText 'SysmonDrv/src/queue.c'
$driverCommonH = Get-SourceText 'SysmonDrv/include/common.h'
$serviceCpp = Get-SourceText 'SysmonUser/src/service.cpp'
$pipelineCpp = Get-SourceText 'SysmonUser/src/pipeline.cpp'
$clipboardMonitorCpp = Get-SourceText 'SysmonUser/src/clipboard_monitor.cpp'
$archiveRootPath = Get-SourceSlice `
    -Text $minifilterC `
    -StartMarker 'SysmonBuildArchiveRootPath(' `
    -EndMarker 'static NTSTATUS'
$renameToArchive = Get-SourceSlice `
    -Text $minifilterC `
    -StartMarker 'SysmonTryRenameToArchive(' `
    -EndMarker 'static NTSTATUS'
$copyToArchiveAndDelete = Get-SourceSlice `
    -Text $minifilterC `
    -StartMarker 'SysmonTryCopyToArchiveAndDelete(' `
    -EndMarker 'static NTSTATUS'
$createArchiveFile = Get-SourceSlice `
    -Text $minifilterC `
    -StartMarker 'SysmonCreateArchiveFileHandle(' `
    -EndMarker 'static NTSTATUS'
$executeFileBlockCleanup = Get-SourceSlice `
    -Text $minifilterC `
    -StartMarker 'SysmonExecuteFileBlockCleanup(' `
    -EndMarker '/* ========================================================================'
$filterPreClose = Get-SourceSlice `
    -Text $minifilterC `
    -StartMarker 'FilterPreClose(' `
    -EndMarker 'static FLT_POSTOP_CALLBACK_STATUS FLTAPI'
$finalizeFileBlock = Get-SourceSlice `
    -Text $minifilterC `
    -StartMarker 'SysmonFinalizeFileBlockContext(' `
    -EndMarker 'static NTSTATUS'

Assert-True `
    (-not ($outputCpp -match '\(void\)\s*SysmonTryParseGuidString')) `
    'ETW GUID parsing result must not be ignored.'

Assert-True `
    ($outputCpp -match 'invalid GUID string field') `
    'ETW GUID descriptor build must report invalid GUID strings.'

Assert-True `
    (-not ($installerCpp -match 'static\s+const\s+WCHAR\s+g_SysmonManifest')) `
    'Installer must not keep a hand-written built-in manifest fallback.'

Assert-True `
    (-not ($installerCpp -match 'Falling back to built-in ETW manifest text resource write')) `
    'Installer must not fall back to hand-written manifest text.'

Assert-True `
    ($installerCpp -match 'SYSMON_EVENT_MANIFEST_RCDATA_ID') `
    'Installer must write the ETW manifest from the embedded RCDATA resource.'

Assert-True `
    ($archiveRootPath -match 'FltGetVolumeName') `
    'FileBlockExecutable archive root must be built from FltGetVolumeName, matching the original driver volume API pattern.'

Assert-True `
    (-not ($archiveRootPath -match 'wcschr\(OriginalPath')) `
    'FileBlockExecutable archive root must not infer the volume root by scanning OriginalPath separators.'

Assert-True `
    ($renameToArchive -match 'RootDirectory\s*=\s*ArchiveDirectoryHandle') `
    'FileBlockExecutable archive rename must use the verified archive directory handle as FILE_RENAME_INFORMATION.RootDirectory.'

Assert-True `
    ($createArchiveFile -match 'InitializeObjectAttributes[\s\S]*?ArchiveDirectoryHandle') `
    'FileBlockExecutable archive copy fallback must create the destination relative to the verified archive directory handle.'

Assert-True `
    ($createArchiveFile -match 'FILE_GENERIC_WRITE\s*\|\s*DELETE') `
    'FileBlockExecutable archive copy fallback must open the destination with DELETE access so untrusted partial samples can be removed.'

Assert-True `
    ($executeFileBlockCleanup -match 'SysmonRevalidateFileBlockExecutable[\s\S]*?FltObjects[\s\S]*?StreamContext') `
    'FileBlockExecutable cleanup must revalidate the current file object as PE immediately before deletion/archive.'

Assert-True `
    ($copyToArchiveAndDelete -match 'SysmonCaptureFileIdentity[\s\S]*?sourceIdentityBefore[\s\S]*?SysmonCaptureFileIdentity[\s\S]*?sourceIdentityAfter') `
    'FileBlockExecutable copy fallback must compare source identity before and after copying.'

Assert-True `
    ($copyToArchiveAndDelete -match 'SysmonFileIdentityMatches[\s\S]*?sourceIdentityBefore[\s\S]*?sourceIdentityAfter') `
    'FileBlockExecutable copy fallback must reject archive samples when source identity changes during copying.'

Assert-True `
    ($minifilterC -match 'if\s*\(\s*headerChecked\s*\)\s*\{[\s\S]*?SYSMON_FILE_BLOCK_CTX_HEADER_CHECKED') `
    'PostWrite must mark the PE header as checked whenever the header was decisively read, including non-PE files.'

Assert-True `
    ($filterPreClose -match 'BOOLEAN\s+deleteContext') `
    'FilterPreClose must use the finalize result before deleting the stream-handle context.'

Assert-True `
    ($filterPreClose -match 'if\s*\(\s*deleteContext\s*&&[\s\S]*?FltDeleteStreamHandleContext') `
    'FilterPreClose must delete the stream-handle context only when a found context is finalized.'

Assert-True `
    ($finalizeFileBlock -match 'FileBlockExecutable event preparation failed') `
    'FileBlockExecutable fallback rule evaluation must log event preparation failures.'

Assert-True `
    ($finalizeFileBlock -match 'FileExecutableDetected event preparation failed') `
    'FileExecutableDetected fallback rule evaluation must log event preparation failures.'

Assert-True `
    ($userCommonH -match 'SysmonIsSinglePathComponent') `
    'User-mode single path component validation must live in the common helper.'

Assert-True `
    (-not ($userConfigCpp -match 'SysmonConfigIsSinglePathComponent')) `
    'Config registry validation must not keep a duplicate single path component helper.'

Assert-True `
    (-not ($xmlConfigCpp -match 'SysmonXmlIsSinglePathComponent')) `
    'XML config validation must not keep a duplicate single path component helper.'

Assert-True `
    ($registryDataC -match 'NULL input is normalized to an empty MULTI_SZ') `
    'Kernel CSV-to-MULTI_SZ conversion must document the intentional NULL-input behavior.'

Assert-True `
    ($outputCpp -match 'g_EtwDriverLoadDescriptor\s*=\s*\{\s*6,\s*4,') `
    'DriverLoad ETW descriptor must stay aligned to event version 4.'

Assert-True `
    ($providerMan -match '<event[^>]+value="6"[^>]+version="4"') `
    'DriverLoad manifest event must stay at version 4.'

Assert-True `
    ($providerH -match 'SYSMONEVENT_DRIVER_LOAD_EVENT\s*=\s*\{\s*0x6,\s*0x4,') `
    'Generated DriverLoad provider header must stay at version 4.'

Assert-True `
    ($schemaEventsXml -match '<event[^>]+value="6"[^>]+rulename="DriverLoad"[^>]+version="4"') `
    'DriverLoad schema entry must stay at version 4.'

Assert-True `
    ($driverProcessH -match '#define\s+SYSMON_PROCESS_DEBUG_STATS_VERSION\s+\d+u') `
    'Debug stats ABI version must remain explicit when FileBlock stats fields are present.'

Assert-True `
    ($driverProcessH -match 'FileBlockContextCreateCount[\s\S]*FileBlockLastReportStatus') `
    'FileBlock debug stats fields must keep a stable ABI surface for Probe-SysmonStats.ps1.'

Assert-True `
    ($driverProcessH -match 'FileInfoCollectCallCount' -and
     $driverProcessH -match 'FileInfoHashUsecTotal' -and
     $driverProcessH -match 'ImphashReadRvaCallCount' -and
     $probeSysmonStatsPs1 -match 'FileInfoCollectCallCount' -and
     $probeSysmonStatsPs1 -match 'FileInfoHashUsecTotal' -and
     $probeSysmonStatsPs1 -match 'ImphashReadRvaCallCount') `
    'Debug stats ABI and local stats probe must expose the cumulative file-info counters plus import-level IMPHASH counters.'

Assert-True `
    ($driverHashH -match 'typedef struct _SYSMON_HASH_DIGEST_SET' -and
     $driverHashH -match 'SysmonComputeHashDigestsMasked' -and
     $driverHashH -match 'SysmonFormatHashDigestsMasked' -and
     $driverHashC -match 'SysmonComputeHashDigestsMasked' -and
     $driverHashC -match 'SysmonFormatHashDigestsMasked') `
    'Driver hash layer must expose the raw digest container and split compute/format APIs.'

Assert-True `
    ($driverFileInfoC -match 'HashDigests' -and
     $driverFileInfoC -match 'SysmonFormatHashDigestsMasked') `
    'File info cache must store raw hash digests and lazily format hash strings on lookup.'

Assert-True `
    ($driverHashC -match 'SysmonHashImportsFromReader' -and
     $driverHashC -match 'SysmonReadImportRvaFromBuffer' -and
     $driverHashC -match 'SysmonPeMapRvaToPointer') `
    'Kernel IMPHASH parsing must use the reader/cache-based RVA access path.'

Assert-True `
    ($driverHashCombined -match 'SysmonLookupImportOrdinalName' -and
     $driverHashCombined -match 'ws2_32\.dll' -and
     $driverHashCombined -match 'wsock32\.dll' -and
     $driverHashCombined -match 'oleaut32\.dll' -and
     $driverHashC -match 'SysmonHashImportsFromReader[\s\S]*?SysmonLookupImportOrdinalName') `
    'Kernel IMPHASH ordinal imports must resolve through DLL-specific ordinal lookup tables before falling back to ord<N>.'

Assert-True `
    ($driverHashCombined -match 'case\s+1u:\s*[\r\n\s]*result = "accept";' -and
     $driverHashCombined -match 'case\s+0x18u:\s*[\r\n\s]*result = "GetAddrInfoW";' -and
     $driverHashCombined -match 'case\s+2u:\s*[\r\n\s]*result = "SysAllocString";') `
    'Kernel IMPHASH ordinal lookup tables must pin representative original Sysmon name mappings for Winsock and OleAut32 imports.'

Assert-True `
    ($driverHashC -match 'SysmonAppendImportHashFragment' -and
     -not ($driverHashC -match 'SymCryptMd5Append\(&md5State,\s*\(PCBYTE\)",",\s*1\)[\s\S]*?SymCryptMd5Append\(&md5State,\s*\(PCBYTE\)dllName,\s*dllNameLen\)[\s\S]*?SymCryptMd5Append\(&md5State,\s*\(PCBYTE\)"\.",\s*1\)[\s\S]*?SymCryptMd5Append\(&md5State,\s*\(PCBYTE\)funcName,\s*funcNameLen\)')) `
    'Kernel IMPHASH hashing must assemble each import fragment once before a single MD5 append.'

Assert-True `
    ($driverHashC -match '#define\s+SYSMON_MAX_STACK_SECTIONS\s+16' -and
     $driverHashC -match 'SYSMON_PE_SECTION_INFO\s+stackSections\[SYSMON_MAX_STACK_SECTIONS\]' -and
     $driverHashC -match 'SysmonInitializeSectionCacheFromLayout[\s\S]*?StackSections' -and
     $driverHashC -match 'NumSections\s*<=\s*StackSectionCapacity') `
    'Kernel IMPHASH section caching must use stack-backed storage for small PE section tables before falling back to pool allocation.'

Assert-True `
    ($driverHashC -match 'section->Span = sectionRawSize;' -and
     -not ($driverHashC -match 'section->Span = \(sectionRawSize > sectionSize\) \? sectionRawSize : sectionSize;')) `
    'Kernel IMPHASH RVA section matching must stay raw-backed so virtual-only tail RVAs fall through to the original raw-offset fallback.'

Assert-True `
    ($driverHashC -match 'SysmonStripExtension[\s\S]*?_stricmp\(ext, "\.dll"\)\s*==\s*0[\s\S]*?_stricmp\(ext, "\.sys"\)\s*==\s*0[\s\S]*?_stricmp\(ext, "\.ocx"\)\s*==\s*0' -and
     -not ($driverHashC -match '_stricmp\(ext, "\.drv"\)') -and
     -not ($driverHashC -match 'dllNameLen == 0\)\s*\{\s*continue;')) `
    'Kernel IMPHASH DLL-name normalization must match the original strip-extension cases and allow empty prefixes after stripping.'

Assert-True `
    (-not ($driverHashC -match 'SysmonComputeHashDigestsMasked[\s\S]*?SysmonPeBufferLooksValid')) `
    'Kernel IMPHASH hashing must not do a redundant PE prevalidation pass before SysmonComputeImphash.'

Assert-True `
    ($driverHashC -match '#define\s+SYSMON_HASH_STAT_INC' -and
     $driverHashC -match '#define\s+SYSMON_HASH_STAT_ADD') `
    'Kernel IMPHASH debug counters must explicitly discard Interlocked return values through local stat macros.'

Assert-True `
    ($driverHashC -match 'SysmonInitializeSectionCacheFromLayout' -and
     -not ($driverHashC -match 'SysmonParseImportsAndHash[\s\S]*?SysmonInitializeSectionCache\s*\(\s*FileData\s*,\s*FileSize\s*,\s*&sectionCache\s*\)')) `
    'Kernel IMPHASH parsing must build the section cache from the already-parsed PE layout.'

Assert-True `
    ($driverFileInfoC -match 'if\s*\(\s*\(RequestMask & SYSMON_FILEINFO_REQUEST_VERSION_INFO\)\s*!=\s*0\s*\)\s*\{[\s\S]*?FileInfo->IsPeFile = SysmonIsPeFile\(fileContent\.Data, fileContent\.Size\);') `
    'File info collection must only classify PE layout when version-info enrichment actually needs it.'

Assert-True `
    ($driverMapFileByHandle -match 'FsRtlCreateSectionForDataScan' -and
     $driverMapFileByHandle -match 'ObReferenceObjectByHandle' -and
     $driverMapFileByHandle -match 'SECTION_MAP_READ\s*\|\s*SECTION_QUERY') `
    'Image-load file mapping must use the original-style FsRtlCreateSectionForDataScan path.'

Assert-True `
    (-not ($driverMapFileByHandle -match 'ZwCreateSection\s*\(')) `
    'Image-load file mapping must not create sections directly with ZwCreateSection.'

Assert-True `
    ($driverImageC -match 'SysmonCheckProcessTamperingOnImageLoadSynchronous\s*\(\s*effectiveProcessId\s*\)' -and
     $driverTamperingC -match 'ExQueueWorkItem\s*\(' -and
     $driverTamperingC -match 'KeWaitForSingleObject\s*\(') `
    'Event 25 must run from the load-image path using the original-style synchronous worker handoff so ghosting and doppelganging observe the post-create file state.'

Assert-True `
    ($driverImageC -match 'effectiveProcessId\s*=\s*ProcessId' -and
     $driverImageC -match 'if\s*\(\s*effectiveProcessId\s*==\s*NULL\s*\)\s*\{\s*effectiveProcessId\s*=\s*PsGetCurrentProcessId\s*\(\s*\)\s*;\s*\}') `
    'Image notify must fall back to PsGetCurrentProcessId when the callback ProcessId is NULL, matching original Sysmon image-load bookkeeping.'

Assert-True `
    ($driverImageC -match 'SYSMON_FLAG_TAMPERING_NOTIFY' -and
     $driverImageC -match '!\s*driverLoad\s*&&\s*!SysmonIsProducerEnabled\(\s*SYSMON_FLAG_IMAGE_LOAD_EVENT\s*\)\s*&&\s*!SysmonIsProducerEnabled\(\s*SYSMON_FLAG_TAMPERING_NOTIFY\s*\)') `
    'Image notify must keep queuing user-mode loads when Event 25 is enabled even if Event 7 itself is disabled.'

Assert-True `
    ($driverC -match 'if\s*\(\s*SysmonIsProducerEnabled\(\s*SYSMON_FLAG_TAMPERING_NOTIFY\s*\)\s*\)\s*\{[\s\S]*?SysmonRegisterTamperingDetection') `
    'Live config sync must register tampering detection when Event 25 becomes enabled after driver startup.'

Assert-True `
    (-not ($driverTamperingC -match 'ImageVerified') -and
     -not ($driverTamperingC -match 'PsCreateSystemThread') -and
     -not ($driverTamperingC -match 'SysmonTamperingCheckThread')) `
    'Event 25 must not rely on the clone-only periodic verifier thread or ImageVerified state.'

Assert-True `
    ($driverTamperingC -match 'FILE_SHARE_READ\s*\|\s*FILE_SHARE_DELETE' -and
     -not ($driverTamperingC -match 'FILE_SHARE_READ\s*\|\s*FILE_SHARE_WRITE\s*\|\s*FILE_SHARE_DELETE') -and
     $driverTamperingC -match 'FILE_SYNCHRONOUS_IO_ALERT' -and
     -not ($driverTamperingC -match 'FILE_SYNCHRONOUS_IO_NONALERT')) `
    'Event 25 image reopen must match original Sysmon share/create options so ghosting and doppelganging failures surface as open/read mismatches.'

Assert-True `
    (-not ($driverTamperingC -match 'ProcessImageFileName\s*,\s*NULL\s*,\s*0\s*,\s*&returnLength') -and
     $driverTamperingC -match 'returnLength\s*=\s*SYSMON_TAMPER_PROCESS_IMAGE_QUERY_BYTES' -and
     $driverTamperingC -match 'status\s*==\s*STATUS_INFO_LENGTH_MISMATCH') `
    'Event 25 process image queries must follow the original fixed-buffer ProcessImageFileName retry pattern, including the original STATUS_INFO_LENGTH_MISMATCH reallocation path.'

Assert-True `
    ($driverTamperingC -match 'ProcessImageFileNameWin32' -and
     $driverTamperingC -match 'status\s*==\s*STATUS_NOT_FOUND[\s\S]*?ProcessImageFileNameWin32') `
    'Event 25 process image queries must fall back to ProcessImageFileNameWin32 when the native ProcessImageFileName class is transiently absent for ghosted children.'

Assert-True `
    (-not ($driverTamperingC -match 'currentImagePath->Buffer\s*==\s*NULL') -and
     -not ($driverTamperingC -match 'currentImagePath->Length\s*==\s*0')) `
    'Event 25 must not treat a successful ProcessImageFileName query as a hard failure solely because the returned UNICODE_STRING looks empty; original Sysmon still falls through to normalize/reopen handling.'

Assert-True `
    ($driverProcessH -match 'TamperLastQueryFailProcessId' -and
     $driverProcessH -match 'TamperLastQueryFailStatus' -and
     $probeSysmonStatsPs1 -match 'TamperLastQueryFailProcessId' -and
     $probeSysmonStatsPs1 -match 'TamperLastQueryFailStatus') `
    'Event 25 debug stats must preserve the last ProcessImageFileName query-failure PID and NTSTATUS so ghosting repros do not get overwritten by later clean image loads.'

Assert-True `
    ($registryDataC -match '#define\s+SYSMON_DEFAULT_HASH_ALG\s+0\b') `
    'Kernel HashingAlgorithm default must keep 0 as the shared None value used by user mode.'

Assert-True `
    (-not ($driverTamperingC -match 'CreateInfo\s*==\s*NULL[\s\S]*?SysmonUntrackProcess\s*\(\s*ProcessId\s*\)')) `
    'Event 25 pending checks must not be dropped on process-terminate callbacks before the image-load worker consumes them.'

Assert-True `
    ($driverTamperingC -match '#define\s+SYSMON_TAMPER_PENDING_RETRY_BUDGET\s+\d+u' -and
     $driverTamperingC -match 'typedef struct _SYSMON_PROCESS_TRACK \{[\s\S]*?ULONG\s+RetryBudget;' -and
     $driverTamperingC -match 'SysmonTrackProcessWithRetryBudget\s*\(' -and
     $driverTamperingC -match 'SysmonUntrackProcess\s*\([\s\S]*?PULONG\s+RetryBudget' -and
     $driverTamperingC -match 'SysmonQueueDelayedTamperRetry\s*\(' -and
     $driverTamperingC -match 'SysmonTamperRetryWorkItemRoutine\s*\(' -and
     $driverTamperingC -match 'queryFailureStatus\s*==\s*STATUS_NOT_FOUND[\s\S]*?remainingRetryBudget\s*!=\s*0[\s\S]*?SysmonTrackProcessWithRetryBudget[\s\S]*?SysmonQueueDelayedTamperRetry') `
    'Event 25 must retain a bounded retry budget and self-queue delayed retries for transient ProcessImageFileName STATUS_NOT_FOUND failures so ghosting does not depend on a later image-load callback arriving in time.'

Assert-True `
    ($driverTamperingC -match 'SysmonTrackProcessWithRetryBudget[\s\S]*?SYSMON_MAX_TRACKED_PROCESSES[\s\S]*?return FALSE;' -and
     $driverTamperingC -match 'track\s*=\s*\(PSYSMON_PROCESS_TRACK\)SysmonAllocatePool\(sizeof\(\*track\)\);[\s\S]*?if\s*\(\s*track\s*==\s*NULL\s*\)\s*\{[\s\S]*?return FALSE;') `
    'Event 25 retry-budget tracking must return FALSE on bounded-capacity or pool-allocation failures rather than falling through with an undefined BOOLEAN value.'

Assert-True `
    (-not ($driverTamperingC -match 'SysmonCheckProcessTamperingOnImageLoadSynchronous[\s\S]*?if\s*\(\s*workItem\s*==\s*NULL\s*\)\s*\{[\s\S]*?SysmonCheckProcessTamperingOnImageLoad\s*\(\s*ProcessId\s*\)\s*;')) `
    'Event 25 synchronous image-load handoff must not inline the heavyweight tampering check when work-item allocation fails; it should drop the check like the original driver.'

Assert-True `
    ($driverTamperingC -match 'SysmonSkipDriveLetterPrefix\s*\(' -and
     $driverTamperingC -match 'path\[1\]\s*==\s*L'':''\s*&&\s*path\[2\]\s*==\s*L''\\\\''' -and
     $driverTamperingC -match 'SysmonPathsEqualCaseInsensitive[\s\S]*?SysmonSkipDriveLetterPrefix' -and
     $driverTamperingC -match 'Right\[0\]\s*==\s*L''\\\\''' ) `
    'Event 25 path comparison must tolerate root-anchored vs drive-anchored DOS aliases for the same image so ghosted temp paths can reach the reopen check instead of being forced into Image is replaced.'

Assert-True `
    ($minifilterC -match '#if\s+DBG[\s\S]*g_FileCreateCandidateCount[\s\S]*g_FileBlockLastReportStatus[\s\S]*#endif') `
    'Minifilter debug counters must be compiled only in DBG builds.'

Assert-True `
    ($minifilterC -match 'SYSMON_FILE_CREATE_STAT_INC' -and
     $minifilterC -match 'SYSMON_FILE_CREATE_STAT_SET' -and
     $minifilterC -match 'SYSMON_FILE_CREATE_STAT_READ' -and
     $minifilterC -match 'SYSMON_FILE_BLOCK_STAT_INC' -and
     $minifilterC -match 'SYSMON_FILE_BLOCK_STAT_SET' -and
     $minifilterC -match 'SYSMON_FILE_BLOCK_STAT_READ') `
    'Minifilter debug counter access must go through DBG-gated helpers.'

Assert-True `
    (-not ($minifilterC -match 'Interlocked(?:Increment|Exchange)\s*\(\s*&g_(?:FileCreate|LastFileCreate|FileBlock)')) `
    'Minifilter hot paths must not call Interlocked* on debug counters directly.'

Assert-True `
    ($driverBuildPs1 -match '\$defines\s*=\s*"\$commonDefines\s+/D DBG=1"') `
    'Driver Debug builds must define DBG=1 so FileBlock debug counters remain observable during investigation.'

Assert-True `
    (-not ($driverBuildPs1 -match '\$defines\s*=\s*"\$commonDefines\s+/D NDEBUG\s+/D DBG=1"')) `
    'Driver Release builds must not define DBG=1.'

Assert-True `
    ($minifilterC -match '#define\s+SYSMON_FILE_BLOCK_CTX_SAW_WRITE\s+0x00000008UL') `
    'FileBlock stream context saw-write bit must match original Sysmon bit 0x08.'

Assert-True `
    ($minifilterC -match '#define\s+SYSMON_FILE_BLOCK_CTX_HEADER_CHECKED\s+0x00000010UL') `
    'FileBlock stream context header-cache bit must match original Sysmon bit 0x10.'

Assert-True `
    ($minifilterC -match '#define\s+SYSMON_FILE_BLOCK_CTX_IS_PE\s+0x00000020UL') `
    'FileBlock stream context confirmed executable bit must match original Sysmon bit 0x20.'

Assert-True `
    (-not ($minifilterC -match '#define\s+SYSMON_FILE_BLOCK_CTX_EVENT_REPORTED\s+0x00000020UL')) `
    'FileBlock private event-reported state must not reuse original Sysmon bit 0x20.'

# --- Driver-core invariant guards (P3 in the 2026-08-04 review) ---

Assert-True `
    ($driverRulesC -match 'header->Signature\s*!=\s*SYSMON_RULES_BLOB_SIGNATURE' -and
     $driverRulesC -match 'header->MajorVersion\s*!=\s*SYSMON_RULES_BLOB_MAJOR_VERSION') `
    'Rule blob validation must reject an unknown signature or major version.'

Assert-True `
    ($driverEventC -match 'if\s*\(\s*truncated\s*\)[\s\S]*?return\s+STATUS_BUFFER_OVERFLOW') `
    'Event payload builder must mark over-capacity string fields as truncated and return STATUS_BUFFER_OVERFLOW.'

Assert-True `
    ($driverQueueC -match 'Queue->Count\s*>=\s*Queue->MaxEvents' -and
     $driverQueueC -match 'Queue->TotalSize\s*\+\s*BlobSize\s*>\s*Queue->MaxTotalSize') `
    'Event queue must enforce both the count and total-size bounds and evict the oldest entry when full.'

Assert-True `
    ($driverCommonH -match 'SYSMON_MAX_QUEUE_EVENTS\s+8192' -and
     $driverCommonH -match 'SYSMON_EVENT_DATA_SIZE\s+0x1000') `
    'Event queue must remain bounded by 8192 events of 0x1000-byte buffers.'

# --- User-mode lifecycle and RPC guards ---

$workerJoinCount = [regex]::Matches(
    $serviceCpp,
    'WaitForSingleObject\s*\(\s*hWorkerThread\s*,\s*INFINITE\s*\)').Count
$configJoinCount = [regex]::Matches(
    $serviceCpp,
    'WaitForSingleObject\s*\(\s*hConfigThread\s*,\s*INFINITE\s*\)').Count

Assert-True `
    ($workerJoinCount -eq 2 -and $configJoinCount -eq 2 -and
     -not ($serviceCpp -match 'WaitForSingleObject\s*\(\s*hWorkerThread\s*,\s*(?:5000|10000)\s*\)') -and
     -not ($serviceCpp -match 'WaitForSingleObject\s*\(\s*hConfigThread\s*,\s*(?:5000|10000)\s*\)')) `
    'Service and direct-mode wrappers must join worker/config threads without a finite timeout before destroying shared state.'

$networkTraceCpp = Get-SourceText 'SysmonUser/src/network_trace.cpp'
$dnsTraceCpp = Get-SourceText 'SysmonUser/src/dns_trace.cpp'
$wmiTraceCpp = Get-SourceText 'SysmonUser/src/wmi_trace.cpp'

Assert-True `
    ($networkTraceCpp -match 'Wnode\.ClientContext\s*=\s*2' -and
     $dnsTraceCpp -match 'Wnode\.ClientContext\s*=\s*2') `
    'Network and DNS ETW sessions must use system-time timestamps because event/process correlation consumes FILETIME values.'

Assert-True `
    ($clipboardMonitorCpp -match 'CreateFileW\s*\([\s\S]*?FILE_SHARE_READ\s*\|\s*FILE_SHARE_WRITE\s*\|\s*FILE_SHARE_DELETE[\s\S]*?FILE_FLAG_OPEN_REPARSE_POINT') `
    'Clipboard archive files must permit the follow-up security validation open while retaining reparse-point protection.'

Assert-True `
    (-not ($serviceCpp -match 'WaitForSingleObject\s*\(\s*queryThreads\[[^\]]+\]\s*,\s*(?:5000|10000)\s*\)') -and
     $networkTraceCpp -match 'WaitForSingleObject\s*\(\s*Context->ThreadHandle\s*,\s*INFINITE\s*\)' -and
     $dnsTraceCpp -match 'WaitForSingleObject\s*\(\s*Context->ThreadHandle\s*,\s*INFINITE\s*\)' -and
     $clipboardMonitorCpp -match 'WaitForSingleObject\s*\(\s*Context->ManagerThread\s*,\s*INFINITE\s*\)' -and
     $wmiTraceCpp -match 'WaitForSingleObject\s*\(\s*Context->ThreadHandle\s*,\s*INFINITE\s*\)') `
    'Optional source and query worker cleanup must confirm thread exit before freeing source contexts or transport state.'

Assert-True `
    ($pipelineCpp -match 'g_SigningPipelineInitialized' -and
     $pipelineCpp -match 'SysmonPipelineCleanup\s*\(\s*(?:void)?\s*\)[\s\S]*?g_SigningPipelineInitialized' -and
     $pipelineCpp -match 'if\s*\(\s*InterlockedCompareExchange\s*\(\s*&g_SigningPipelineInitialized') `
    'Pipeline cleanup must be guarded by an explicit initialized state so failed initialization cannot enter deleted locks.'

$pipelineInitSlice = Get-SourceSlice `
    -Text $serviceCpp `
    -StartMarker '/* Initialize pipeline */' `
    -EndMarker '/* Initialize output */'
Assert-True `
    ($pipelineInitSlice -match 'status\s*!=\s*SYSMON_SUCCESS[\s\S]*?goto\s+cleanup\s*;') `
    'Service startup must abort through cleanup when pipeline initialization fails.'

Assert-True `
    ($clipboardMonitorCpp -match 'callAttributes\.Flags\s*=\s*RPC_QUERY_CLIENT_PID') `
    'Clipboard RPC security callback must request the client PID before authorizing helper processes.'

Write-Host 'PASS: static regression guards verified.'

/*
 * output_enrichment.inc - extracted output enrichment and cache helpers
 *
 * Included by output_enrichment.cpp so output.cpp can stay focused on
 * schemas, ETW serialization, and channel dispatch as a separate unit.
 */

static DWORD
SysmonSelectSidDisplayCacheBucket(
    _In_ DWORD SidHash)
{
    return SidHash % SYSMON_SID_DISPLAY_CACHE_BUCKET_COUNT;
}

static DWORD
SysmonSelectVersionInfoCacheBucket(
    _In_ DWORD PathHash)
{
    return PathHash % SYSMON_VERSION_INFO_CACHE_BUCKET_COUNT;
}

static VOID
SysmonUnlinkSidDisplayCacheSlot(
    _In_ DWORD Slot)
{
    DWORD bucket;
    LONG current;
    LONG previous;

    if (Slot >= SYSMON_SID_DISPLAY_CACHE_CAPACITY ||
        !g_SidDisplayCache[Slot].InUse) {
        return;
    }

    bucket = SysmonSelectSidDisplayCacheBucket(g_SidDisplayCache[Slot].SidHash);
    current = g_SidDisplayCacheBuckets[bucket];
    previous = -1;
    while (current >= 0) {
        if ((DWORD)current == Slot) {
            if (previous < 0) {
                g_SidDisplayCacheBuckets[bucket] = g_SidDisplayCache[Slot].NextInBucket;
            } else {
                g_SidDisplayCache[previous].NextInBucket = g_SidDisplayCache[Slot].NextInBucket;
            }
            break;
        }

        previous = current;
        current = g_SidDisplayCache[current].NextInBucket;
    }

    g_SidDisplayCache[Slot].NextInBucket = -1;
}

static VOID
SysmonLinkSidDisplayCacheSlot(
    _In_ DWORD Slot)
{
    DWORD bucket;

    if (Slot >= SYSMON_SID_DISPLAY_CACHE_CAPACITY ||
        !g_SidDisplayCache[Slot].InUse) {
        return;
    }

    bucket = SysmonSelectSidDisplayCacheBucket(g_SidDisplayCache[Slot].SidHash);
    g_SidDisplayCache[Slot].NextInBucket = g_SidDisplayCacheBuckets[bucket];
    g_SidDisplayCacheBuckets[bucket] = (LONG)Slot;
}

static VOID
SysmonUnlinkVersionInfoCacheSlot(
    _In_ DWORD Slot)
{
    DWORD bucket;
    LONG current;
    LONG previous;

    if (Slot >= SYSMON_VERSION_INFO_CACHE_CAPACITY ||
        !g_VersionInfoCache[Slot].InUse) {
        return;
    }

    bucket = SysmonSelectVersionInfoCacheBucket(g_VersionInfoCache[Slot].PathHash);
    current = g_VersionInfoCacheBuckets[bucket];
    previous = -1;
    while (current >= 0) {
        if ((DWORD)current == Slot) {
            if (previous < 0) {
                g_VersionInfoCacheBuckets[bucket] = g_VersionInfoCache[Slot].NextInBucket;
            } else {
                g_VersionInfoCache[previous].NextInBucket = g_VersionInfoCache[Slot].NextInBucket;
            }
            break;
        }

        previous = current;
        current = g_VersionInfoCache[current].NextInBucket;
    }

    g_VersionInfoCache[Slot].NextInBucket = -1;
}

static VOID
SysmonLinkVersionInfoCacheSlot(
    _In_ DWORD Slot)
{
    DWORD bucket;

    if (Slot >= SYSMON_VERSION_INFO_CACHE_CAPACITY ||
        !g_VersionInfoCache[Slot].InUse) {
        return;
    }

    bucket = SysmonSelectVersionInfoCacheBucket(g_VersionInfoCache[Slot].PathHash);
    g_VersionInfoCache[Slot].NextInBucket = g_VersionInfoCacheBuckets[bucket];
    g_VersionInfoCacheBuckets[bucket] = (LONG)Slot;
}

static BOOL
SysmonLookupSidDisplayCache(
    _In_z_ PCWSTR SidText,
    _Out_writes_(BufferChars) PWCHAR Buffer,
    _In_ size_t BufferChars)
{
    DWORD sidHash;
    DWORD sidLength;
    DWORD bucket;
    LONG index;
    CriticalSectionGuard cacheLock(&g_SidDisplayCacheLock);

    if (SidText == NULL || Buffer == NULL || BufferChars == 0) {
        return FALSE;
    }

    sidHash = SysmonComputeInsensitiveWideHash(SidText, &sidLength);
    bucket = SysmonSelectSidDisplayCacheBucket(sidHash);
    for (index = g_SidDisplayCacheBuckets[bucket];
         index >= 0;
         index = g_SidDisplayCache[index].NextInBucket) {
        if (!SysmonInsensitiveWideTextMatches(
                g_SidDisplayCache[index].SidHash,
                g_SidDisplayCache[index].SidLength,
                g_SidDisplayCache[index].SidText,
                sidHash,
                sidLength,
                SidText)) {
            continue;
        }

        return SysmonCopyWideText(Buffer, BufferChars, g_SidDisplayCache[index].Display);
    }

    return FALSE;
}

static VOID
SysmonStoreSidDisplayCache(
    _In_z_ PCWSTR SidText,
    _In_z_ PCWSTR Display)
{
    DWORD sidHash;
    DWORD sidLength;
    DWORD bucket;
    LONG index;
    CriticalSectionGuard cacheLock(&g_SidDisplayCacheLock);

    if (SidText == NULL || SidText[0] == L'\0' ||
        Display == NULL || Display[0] == L'\0') {
        return;
    }

    sidHash = SysmonComputeInsensitiveWideHash(SidText, &sidLength);
    bucket = SysmonSelectSidDisplayCacheBucket(sidHash);
    for (index = g_SidDisplayCacheBuckets[bucket];
         index >= 0;
         index = g_SidDisplayCache[index].NextInBucket) {
        if (SysmonInsensitiveWideTextMatches(
                g_SidDisplayCache[index].SidHash,
                g_SidDisplayCache[index].SidLength,
                g_SidDisplayCache[index].SidText,
                sidHash,
                sidLength,
                SidText)) {
            (void)SysmonCopyWideText(
                g_SidDisplayCache[index].Display,
                _countof(g_SidDisplayCache[index].Display),
                Display);
            return;
        }
    }

    index = (LONG)(g_SidDisplayCacheVictim++ % SYSMON_SID_DISPLAY_CACHE_CAPACITY);
    SysmonUnlinkSidDisplayCacheSlot((DWORD)index);
    ZeroMemory(&g_SidDisplayCache[index], sizeof(g_SidDisplayCache[index]));
    g_SidDisplayCache[index].InUse = TRUE;
    g_SidDisplayCache[index].SidHash = sidHash;
    g_SidDisplayCache[index].SidLength = sidLength;
    g_SidDisplayCache[index].NextInBucket = -1;
    (void)SysmonCopyWideText(
        g_SidDisplayCache[index].SidText,
        _countof(g_SidDisplayCache[index].SidText),
        SidText);
    (void)SysmonCopyWideText(
        g_SidDisplayCache[index].Display,
        _countof(g_SidDisplayCache[index].Display),
        Display);
    SysmonLinkSidDisplayCacheSlot((DWORD)index);
}

static BOOL CALLBACK
SysmonInitializeVersionInfoCache(
    PINIT_ONCE InitOnce,
    PVOID Parameter,
    PVOID *Context)
{
    UNREFERENCED_PARAMETER(InitOnce);
    UNREFERENCED_PARAMETER(Parameter);
    UNREFERENCED_PARAMETER(Context);

    InitializeCriticalSection(&g_VersionInfoCacheLock);
    InterlockedExchange(&g_VersionInfoCacheLockInitialized, TRUE);
    ZeroMemory(g_VersionInfoCache, sizeof(g_VersionInfoCache));
    g_VersionInfoCacheVictim = 0;
    SysmonInitializeBucketHeads(
        g_VersionInfoCacheBuckets,
        RTL_NUMBER_OF(g_VersionInfoCacheBuckets));
    return TRUE;
}

static BOOL
SysmonEnsureVersionInfoCacheInitialized(VOID)
{
    return InitOnceExecuteOnce(
        &g_VersionInfoCacheInitOnce,
        SysmonInitializeVersionInfoCache,
        NULL,
        NULL);
}

static BOOL
SysmonQueryFileVersionCacheKey(
    _In_z_ PCWSTR FilePath,
    _Out_ PULONGLONG FileSize,
    _Out_ PFILETIME LastWriteTime)
{
    WIN32_FILE_ATTRIBUTE_DATA attributes;
    ULARGE_INTEGER size;

    if (FilePath == NULL || FileSize == NULL || LastWriteTime == NULL) {
        return FALSE;
    }

    if (!GetFileAttributesExW(FilePath, GetFileExInfoStandard, &attributes)) {
        return FALSE;
    }

    size.LowPart = attributes.nFileSizeLow;
    size.HighPart = attributes.nFileSizeHigh;
    *FileSize = size.QuadPart;
    *LastWriteTime = attributes.ftLastWriteTime;
    return TRUE;
}

static VOID
SysmonCopyVersionInfoCacheValue(
    _Out_ SYSMON_PROCESS_CREATE_ENRICHMENT *Enrichment,
    _In_ const SYSMON_VERSION_INFO_CACHE_VALUE *Value)
{
    if (Enrichment == NULL || Value == NULL) {
        return;
    }

    (void)SysmonCopyWideText(Enrichment->FileVersion, _countof(Enrichment->FileVersion), Value->FileVersion);
    (void)SysmonCopyWideText(Enrichment->Description, _countof(Enrichment->Description), Value->Description);
    (void)SysmonCopyWideText(Enrichment->Product, _countof(Enrichment->Product), Value->Product);
    (void)SysmonCopyWideText(Enrichment->Company, _countof(Enrichment->Company), Value->Company);
    (void)SysmonCopyWideText(Enrichment->OriginalFileName, _countof(Enrichment->OriginalFileName), Value->OriginalFileName);
}

static VOID
SysmonCaptureVersionInfoCacheValue(
    _Out_ SYSMON_VERSION_INFO_CACHE_VALUE *Value,
    _In_ const SYSMON_PROCESS_CREATE_ENRICHMENT *Enrichment)
{
    if (Value == NULL || Enrichment == NULL) {
        return;
    }

    ZeroMemory(Value, sizeof(*Value));
    (void)SysmonCopyWideText(Value->FileVersion, _countof(Value->FileVersion), Enrichment->FileVersion);
    (void)SysmonCopyWideText(Value->Description, _countof(Value->Description), Enrichment->Description);
    (void)SysmonCopyWideText(Value->Product, _countof(Value->Product), Enrichment->Product);
    (void)SysmonCopyWideText(Value->Company, _countof(Value->Company), Enrichment->Company);
    (void)SysmonCopyWideText(Value->OriginalFileName, _countof(Value->OriginalFileName), Enrichment->OriginalFileName);
}

static BOOL
SysmonLookupVersionInfoCache(
    _In_z_ PCWSTR FilePath,
    _Out_ SYSMON_PROCESS_CREATE_ENRICHMENT *Enrichment)
{
    DWORD pathHash;
    DWORD pathLength;
    DWORD bucket;
    LONG index;
    ULONGLONG fileSize;
    FILETIME lastWriteTime;
    BOOL found = FALSE;

    if (FilePath == NULL || Enrichment == NULL) {
        return FALSE;
    }

    if (!SysmonEnsureVersionInfoCacheInitialized() ||
        !SysmonQueryFileVersionCacheKey(FilePath, &fileSize, &lastWriteTime)) {
        return FALSE;
    }

    pathHash = SysmonComputeInsensitiveWideHash(FilePath, &pathLength);
    bucket = SysmonSelectVersionInfoCacheBucket(pathHash);

    CriticalSectionGuard cacheLock(&g_VersionInfoCacheLock);
    for (index = g_VersionInfoCacheBuckets[bucket];
         index >= 0;
         index = g_VersionInfoCache[index].NextInBucket) {
        const SYSMON_VERSION_INFO_CACHE_ENTRY *entry = &g_VersionInfoCache[index];

        if (!entry->InUse ||
            entry->FileSize != fileSize ||
            entry->LastWriteTime.dwLowDateTime != lastWriteTime.dwLowDateTime ||
            entry->LastWriteTime.dwHighDateTime != lastWriteTime.dwHighDateTime) {
            continue;
        }

        if (!SysmonInsensitiveWideTextMatches(
                entry->PathHash,
                entry->PathLength,
                entry->FilePath,
                pathHash,
                pathLength,
                FilePath)) {
            continue;
        }

        SysmonCopyVersionInfoCacheValue(Enrichment, &entry->Value);
        found = TRUE;
        break;
    }

    return found;
}

static VOID
SysmonStoreVersionInfoCache(
    _In_z_ PCWSTR FilePath,
    _In_ const SYSMON_PROCESS_CREATE_ENRICHMENT *Enrichment)
{
    DWORD pathHash;
    DWORD pathLength;
    DWORD bucket;
    LONG index;
    ULONGLONG fileSize;
    FILETIME lastWriteTime;
    SYSMON_VERSION_INFO_CACHE_VALUE cachedValue;

    if (FilePath == NULL || Enrichment == NULL ||
        !SysmonEnsureVersionInfoCacheInitialized() ||
        !SysmonQueryFileVersionCacheKey(FilePath, &fileSize, &lastWriteTime)) {
        return;
    }

    SysmonCaptureVersionInfoCacheValue(&cachedValue, Enrichment);
    pathHash = SysmonComputeInsensitiveWideHash(FilePath, &pathLength);
    bucket = SysmonSelectVersionInfoCacheBucket(pathHash);

    CriticalSectionGuard cacheLock(&g_VersionInfoCacheLock);
    for (index = g_VersionInfoCacheBuckets[bucket];
         index >= 0;
         index = g_VersionInfoCache[index].NextInBucket) {
        if (g_VersionInfoCache[index].InUse &&
            g_VersionInfoCache[index].FileSize == fileSize &&
            g_VersionInfoCache[index].LastWriteTime.dwLowDateTime == lastWriteTime.dwLowDateTime &&
            g_VersionInfoCache[index].LastWriteTime.dwHighDateTime == lastWriteTime.dwHighDateTime &&
            SysmonInsensitiveWideTextMatches(
                g_VersionInfoCache[index].PathHash,
                g_VersionInfoCache[index].PathLength,
                g_VersionInfoCache[index].FilePath,
                pathHash,
                pathLength,
                FilePath)) {
            g_VersionInfoCache[index].Value = cachedValue;
            return;
        }
    }

    index = (LONG)(g_VersionInfoCacheVictim++ % SYSMON_VERSION_INFO_CACHE_CAPACITY);
    SysmonUnlinkVersionInfoCacheSlot((DWORD)index);
    ZeroMemory(&g_VersionInfoCache[index], sizeof(g_VersionInfoCache[index]));
    g_VersionInfoCache[index].InUse = TRUE;
    g_VersionInfoCache[index].PathHash = pathHash;
    g_VersionInfoCache[index].PathLength = pathLength;
    g_VersionInfoCache[index].NextInBucket = -1;
    g_VersionInfoCache[index].FileSize = fileSize;
    g_VersionInfoCache[index].LastWriteTime = lastWriteTime;
    (void)SysmonCopyWideText(
        g_VersionInfoCache[index].FilePath,
        _countof(g_VersionInfoCache[index].FilePath),
        FilePath);
    g_VersionInfoCache[index].Value = cachedValue;
    SysmonLinkVersionInfoCacheSlot((DWORD)index);
}

static BOOL
SysmonPathNeedsNormalization(
    _In_opt_z_ PCWSTR Path)
{
    if (Path == NULL || Path[0] == L'\0') {
        return FALSE;
    }

    if (((Path[0] >= L'A' && Path[0] <= L'Z') ||
         (Path[0] >= L'a' && Path[0] <= L'z')) &&
        Path[1] == L':') {
        return FALSE;
    }

    if (_wcsnicmp(Path, L"\\\\", 2) == 0) {
        return FALSE;
    }

    if (_wcsnicmp(Path, L"\\??\\UNC\\", 8) == 0 ||
        _wcsnicmp(Path, L"\\\\?\\UNC\\", 8) == 0 ||
        _wcsnicmp(Path, L"\\??\\", 4) == 0 ||
        _wcsnicmp(Path, L"\\\\?\\", 4) == 0 ||
        _wcsnicmp(Path, L"\\SystemRoot\\", 12) == 0 ||
        _wcsnicmp(Path, L"\\Device\\", 8) == 0) {
        return TRUE;
    }

    return FALSE;
}

static BOOL
SysmonResolveSidDisplay(
    _In_z_ PCWSTR SidText,
    _Out_writes_(BufferChars) PWCHAR Buffer,
    _In_ size_t BufferChars);

static BOOL
SysmonResolveSidDisplay(
    _In_z_ PCWSTR SidText,
    _Out_writes_(BufferChars) PWCHAR Buffer,
    _In_ size_t BufferChars)
{
    PSID sid = NULL;
    WCHAR accountName[256];
    WCHAR domainName[256];
    DWORD accountChars = _countof(accountName);
    DWORD domainChars = _countof(domainName);
    SID_NAME_USE sidType;
    BOOL success = FALSE;

    if (Buffer == NULL || BufferChars == 0 || SysmonIsPlaceholderString(SidText)) {
        return FALSE;
    }

    Buffer[0] = L'\0';
    if (SysmonLookupSidDisplayCache(SidText, Buffer, BufferChars)) {
        return TRUE;
    }

    if (!ConvertStringSidToSidW(SidText, &sid)) {
        return FALSE;
    }

    accountName[0] = L'\0';
    domainName[0] = L'\0';
    success = LookupAccountSidW(
        NULL,
        sid,
        accountName,
        &accountChars,
        domainName,
        &domainChars,
        &sidType);
    LocalFree(sid);

    if (!success || accountName[0] == L'\0') {
        return FALSE;
    }

    if (domainName[0] != L'\0') {
        success = SUCCEEDED(_snwprintf_s(
            Buffer,
            BufferChars,
            _TRUNCATE,
            L"%ls\\%ls",
            domainName,
            accountName));
        if (success) {
            SysmonStoreSidDisplayCache(SidText, Buffer);
        }
        return success;
    }

    success = SysmonCopyWideText(Buffer, BufferChars, accountName);
    if (success) {
        SysmonStoreSidDisplayCache(SidText, Buffer);
    }
    return success;
}

static BOOL
SysmonQueryVersionField(
    _In_reads_bytes_(BlockSize) const BYTE *VersionBlock,
    _In_ DWORD BlockSize,
    _In_ WORD Language,
    _In_ WORD CodePage,
    _In_z_ PCWSTR Key,
    _Out_writes_(BufferChars) PWCHAR Buffer,
    _In_ size_t BufferChars)
{
    WCHAR subBlock[128];
    LPWSTR value = NULL;
    UINT valueBytes = 0;

    UNREFERENCED_PARAMETER(BlockSize);

    if (Buffer == NULL || BufferChars == 0) {
        return FALSE;
    }

    Buffer[0] = L'\0';
    if (VersionBlock == NULL || Key == NULL) {
        return FALSE;
    }

    if (!SUCCEEDED(_snwprintf_s(
            subBlock,
            _countof(subBlock),
            _TRUNCATE,
            L"\\StringFileInfo\\%04x%04x\\%ls",
            Language,
            CodePage,
            Key))) {
        return FALSE;
    }

    if (!VerQueryValueW((LPVOID)VersionBlock, subBlock, (LPVOID *)&value, &valueBytes) ||
        value == NULL || valueBytes == 0 || value[0] == L'\0') {
        return FALSE;
    }

    return SysmonCopyWideText(Buffer, BufferChars, value);
}

static void
SysmonLoadVersionStrings(
    _In_z_ PCWSTR Win32Path,
    _Out_ SYSMON_PROCESS_CREATE_ENRICHMENT *Enrichment)
{
    DWORD handle = 0;
    DWORD versionSize;
    BYTE *versionBlock = NULL;
    SYSMON_VERSION_TRANSLATION *translation = NULL;
    UINT translationBytes = 0;
    WORD language = 0x0409;
    WORD codePage = 0x04b0;

    if (Enrichment == NULL || SysmonIsPlaceholderString(Win32Path)) {
        return;
    }

    if (SysmonLookupVersionInfoCache(Win32Path, Enrichment)) {
        return;
    }

    versionSize = GetFileVersionInfoSizeW(Win32Path, &handle);
    if (versionSize == 0) {
        SysmonStoreVersionInfoCache(Win32Path, Enrichment);
        return;
    }

    versionBlock = (BYTE *)SYSMON_ALLOC(versionSize);
    if (versionBlock == NULL) {
        return;
    }

    if (!GetFileVersionInfoW(Win32Path, handle, versionSize, versionBlock)) {
        SYSMON_FREE(versionBlock);
        SysmonStoreVersionInfoCache(Win32Path, Enrichment);
        return;
    }

    if (VerQueryValueW(
            versionBlock,
            L"\\VarFileInfo\\Translation",
            (LPVOID *)&translation,
            &translationBytes) &&
        translation != NULL &&
        translationBytes >= sizeof(*translation)) {
        language = translation[0].Language;
        codePage = translation[0].CodePage;
    }

    SysmonQueryVersionField(versionBlock, versionSize, language, codePage, L"FileVersion", Enrichment->FileVersion, _countof(Enrichment->FileVersion));
    SysmonQueryVersionField(versionBlock, versionSize, language, codePage, L"FileDescription", Enrichment->Description, _countof(Enrichment->Description));
    SysmonQueryVersionField(versionBlock, versionSize, language, codePage, L"ProductName", Enrichment->Product, _countof(Enrichment->Product));
    SysmonQueryVersionField(versionBlock, versionSize, language, codePage, L"CompanyName", Enrichment->Company, _countof(Enrichment->Company));
    SysmonQueryVersionField(versionBlock, versionSize, language, codePage, L"OriginalFilename", Enrichment->OriginalFileName, _countof(Enrichment->OriginalFileName));
    SYSMON_FREE(versionBlock);
    SysmonStoreVersionInfoCache(Win32Path, Enrichment);
}

VOID
SysmonResolveCurrentModuleFileVersion(
    _Out_writes_(BufferChars) PWCHAR Buffer,
    _In_ size_t BufferChars)
{
    WCHAR modulePath[MAX_PATH];
    SYSMON_PROCESS_CREATE_ENRICHMENT enrichment;
    DWORD pathLength;

    if (Buffer == NULL || BufferChars == 0) {
        return;
    }

    Buffer[0] = L'\0';
    pathLength = GetModuleFileNameW(NULL, modulePath, _countof(modulePath));
    if (pathLength == 0 || pathLength >= _countof(modulePath)) {
        SysmonFormatProductVersion(Buffer, BufferChars);
        return;
    }

    ZeroMemory(&enrichment, sizeof(enrichment));
    SysmonLoadVersionStrings(modulePath, &enrichment);
    if (enrichment.FileVersion[0] != L'\0') {
        wcscpy_s(Buffer, BufferChars, enrichment.FileVersion);
        return;
    }

    SysmonFormatProductVersion(Buffer, BufferChars);
}

static void
SysmonBuildProcessCreateEnrichment(
    _In_reads_bytes_(PayloadSize) const UCHAR *PayloadBase,
    _In_ DWORD PayloadSize,
    _Out_ SYSMON_PROCESS_CREATE_ENRICHMENT *Enrichment)
{
    const SYSMON_EVENT_PROCESS_CREATE_PAYLOAD *payload;
    WCHAR rawValue[1024];
    DWORD hashMask = 0;
    BOOL needsVersionInfo = FALSE;

    if (Enrichment == NULL) {
        return;
    }

    ZeroMemory(Enrichment, sizeof(*Enrichment));
    if (PayloadBase == NULL || !HasPayloadBytes(PayloadSize, 0, sizeof(*payload))) {
        return;
    }

    payload = (const SYSMON_EVENT_PROCESS_CREATE_PAYLOAD *)PayloadBase;

    if (CopyStringRefValue(PayloadBase, PayloadSize, &payload->Image, rawValue, _countof(rawValue)) &&
        !SysmonIsPlaceholderString(rawValue)) {
        WCHAR versionProbe[256];

        if (!SysmonPathNeedsNormalization(rawValue) ||
            !SysmonConvertNtPathToWin32Path(rawValue, Enrichment->Image, _countof(Enrichment->Image))) {
            SysmonCopyWideText(Enrichment->Image, _countof(Enrichment->Image), rawValue);
        }

        versionProbe[0] = L'\0';
        if (!CopyStringRefValue(PayloadBase, PayloadSize, &payload->FileVersion, versionProbe, _countof(versionProbe)) ||
            SysmonIsPlaceholderString(versionProbe)) {
            needsVersionInfo = TRUE;
        }
        if (!needsVersionInfo &&
            (!CopyStringRefValue(PayloadBase, PayloadSize, &payload->Description, versionProbe, _countof(versionProbe)) ||
             SysmonIsPlaceholderString(versionProbe))) {
            needsVersionInfo = TRUE;
        }
        if (!needsVersionInfo &&
            (!CopyStringRefValue(PayloadBase, PayloadSize, &payload->Product, versionProbe, _countof(versionProbe)) ||
             SysmonIsPlaceholderString(versionProbe))) {
            needsVersionInfo = TRUE;
        }
        if (!needsVersionInfo &&
            (!CopyStringRefValue(PayloadBase, PayloadSize, &payload->Company, versionProbe, _countof(versionProbe)) ||
             SysmonIsPlaceholderString(versionProbe))) {
            needsVersionInfo = TRUE;
        }
        if (!needsVersionInfo &&
            (!CopyStringRefValue(PayloadBase, PayloadSize, &payload->OriginalFileName, versionProbe, _countof(versionProbe)) ||
             SysmonIsPlaceholderString(versionProbe))) {
            needsVersionInfo = TRUE;
        }

        if (needsVersionInfo) {
            SysmonLoadVersionStrings(Enrichment->Image, Enrichment);
        }

        if (CopyStringRefValue(PayloadBase, PayloadSize, &payload->Hashes, rawValue, _countof(rawValue)) &&
            SysmonIsPlaceholderString(rawValue)) {
            EnterCriticalSection(&g_ServiceCtx.ConfigLock);
            hashMask = g_ServiceCtx.Config.HashingAlgorithm;
            LeaveCriticalSection(&g_ServiceCtx.ConfigLock);

            if (hashMask != 0) {
                (void)SysmonComputeFileHashes(
                    Enrichment->Image,
                    hashMask,
                    Enrichment->Hashes,
                    _countof(Enrichment->Hashes));
            }
        }
    }

    if (CopyStringRefValue(PayloadBase, PayloadSize, &payload->ParentImage, rawValue, _countof(rawValue)) &&
        !SysmonIsPlaceholderString(rawValue)) {
        if (!SysmonPathNeedsNormalization(rawValue) ||
            !SysmonConvertNtPathToWin32Path(rawValue, Enrichment->ParentImage, _countof(Enrichment->ParentImage))) {
            SysmonCopyWideText(Enrichment->ParentImage, _countof(Enrichment->ParentImage), rawValue);
        }
    }

    if (CopyStringRefValue(PayloadBase, PayloadSize, &payload->User, rawValue, _countof(rawValue)) &&
        !SysmonIsPlaceholderString(rawValue)) {
        if (!SysmonResolveSidDisplay(rawValue, Enrichment->User, _countof(Enrichment->User))) {
            SysmonCopyWideText(Enrichment->User, _countof(Enrichment->User), rawValue);
        }
    }

    if (CopyStringRefValue(PayloadBase, PayloadSize, &payload->ParentUser, rawValue, _countof(rawValue)) &&
        !SysmonIsPlaceholderString(rawValue)) {
        if (!SysmonResolveSidDisplay(rawValue, Enrichment->ParentUser, _countof(Enrichment->ParentUser))) {
            SysmonCopyWideText(Enrichment->ParentUser, _countof(Enrichment->ParentUser), rawValue);
        }
    }
}

static BOOL
SysmonResolveProcessUserByPid(
    _In_ DWORD ProcessId,
    _Out_writes_(BufferChars) PWCHAR Buffer,
    _In_ size_t BufferChars)
{
    SYSMON_PROCESS_CACHE_RESPONSE cachedMetadata;
    ScopedHandle processHandle;
    ScopedHandle tokenHandle;
    DWORD sidSize = 0;
    PTOKEN_USER tokenUser = NULL;
    BOOL success = FALSE;

    if (Buffer == NULL || BufferChars == 0 || ProcessId == 0) {
        return FALSE;
    }

    Buffer[0] = L'\0';
    ZeroMemory(&cachedMetadata, sizeof(cachedMetadata));
    if (g_ServiceCtx.Transport.Connected &&
        SysmonQueryProcessCache(
            &g_ServiceCtx.Transport,
            ProcessId,
            &cachedMetadata) == SYSMON_SUCCESS &&
        !SysmonIsPlaceholderString(cachedMetadata.UserSid)) {
        if (SysmonResolveSidStringToAccountName(
                cachedMetadata.UserSid,
                Buffer,
                BufferChars)) {
            return !SysmonIsPlaceholderString(Buffer);
        }

        if (SysmonCopyWideText(Buffer, BufferChars, cachedMetadata.UserSid)) {
            return !SysmonIsPlaceholderString(Buffer);
        }
    }

    processHandle.reset(OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, ProcessId));
    if (!processHandle.valid()) {
        processHandle.reset(OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, ProcessId));
    }
    if (!processHandle.valid()) {
        return FALSE;
    }

    if (OpenProcessToken(processHandle.get(), TOKEN_QUERY, tokenHandle.put())) {
        GetTokenInformation(tokenHandle.get(), TokenUser, NULL, 0, &sidSize);
        if (sidSize != 0) {
            tokenUser = (PTOKEN_USER)SYSMON_ALLOC(sidSize);
            if (tokenUser != NULL &&
                GetTokenInformation(tokenHandle.get(), TokenUser, tokenUser, sidSize, &sidSize)) {
                LPWSTR sidText = NULL;

                if (ConvertSidToStringSidW(tokenUser->User.Sid, &sidText) && sidText != NULL) {
                    success = SysmonResolveSidDisplay(sidText, Buffer, BufferChars);
                    if (!success) {
                        success = SysmonCopyWideText(Buffer, BufferChars, sidText);
                    }
                    LocalFree(sidText);
                }
            }
        }
    }

    if (tokenUser != NULL) {
        SYSMON_FREE(tokenUser);
    }
    return success && !SysmonIsPlaceholderString(Buffer);
}

static void
SysmonBuildImageLoadEnrichment(
    _In_reads_bytes_(PayloadSize) const UCHAR *PayloadBase,
    _In_ DWORD PayloadSize,
    _Out_ SYSMON_PROCESS_CREATE_ENRICHMENT *Enrichment)
{
    const SYSMON_EVENT_IMAGE_LOAD_PAYLOAD *payload;
    WCHAR rawValue[1024];
    BOOL needsVersionInfo = FALSE;

    if (Enrichment == NULL) {
        return;
    }

    ZeroMemory(Enrichment, sizeof(*Enrichment));
    if (PayloadBase == NULL || !HasPayloadBytes(PayloadSize, 0, sizeof(*payload))) {
        return;
    }

    payload = (const SYSMON_EVENT_IMAGE_LOAD_PAYLOAD *)PayloadBase;
    if (CopyStringRefValue(PayloadBase, PayloadSize, &payload->ImageLoaded, rawValue, _countof(rawValue)) &&
        !SysmonIsPlaceholderString(rawValue)) {
        WCHAR versionProbe[256];

        versionProbe[0] = L'\0';
        if (!CopyStringRefValue(PayloadBase, PayloadSize, &payload->FileVersion, versionProbe, _countof(versionProbe)) ||
            SysmonIsPlaceholderString(versionProbe)) {
            needsVersionInfo = TRUE;
        }
        if (!needsVersionInfo &&
            (!CopyStringRefValue(PayloadBase, PayloadSize, &payload->Description, versionProbe, _countof(versionProbe)) ||
             SysmonIsPlaceholderString(versionProbe))) {
            needsVersionInfo = TRUE;
        }
        if (!needsVersionInfo &&
            (!CopyStringRefValue(PayloadBase, PayloadSize, &payload->Product, versionProbe, _countof(versionProbe)) ||
             SysmonIsPlaceholderString(versionProbe))) {
            needsVersionInfo = TRUE;
        }
        if (!needsVersionInfo &&
            (!CopyStringRefValue(PayloadBase, PayloadSize, &payload->Company, versionProbe, _countof(versionProbe)) ||
             SysmonIsPlaceholderString(versionProbe))) {
            needsVersionInfo = TRUE;
        }
        if (!needsVersionInfo &&
            (!CopyStringRefValue(PayloadBase, PayloadSize, &payload->OriginalFileName, versionProbe, _countof(versionProbe)) ||
             SysmonIsPlaceholderString(versionProbe))) {
            needsVersionInfo = TRUE;
        }

        if (needsVersionInfo) {
            if (!SysmonPathNeedsNormalization(rawValue) ||
                !SysmonConvertNtPathToWin32Path(rawValue, Enrichment->Image, _countof(Enrichment->Image))) {
                SysmonCopyWideText(Enrichment->Image, _countof(Enrichment->Image), rawValue);
            }
        } else if (!SysmonPathNeedsNormalization(rawValue) ||
                   !SysmonConvertNtPathToWin32Path(rawValue, Enrichment->Image, _countof(Enrichment->Image))) {
            SysmonCopyWideText(Enrichment->Image, _countof(Enrichment->Image), rawValue);
        }
        Enrichment->NeedsVersionInfo = needsVersionInfo;

    }

    if (CopyStringRefValue(PayloadBase, PayloadSize, &payload->User, rawValue, _countof(rawValue)) &&
        !SysmonIsPlaceholderString(rawValue)) {
        if (!SysmonResolveSidDisplay(rawValue, Enrichment->User, _countof(Enrichment->User))) {
            SysmonCopyWideText(Enrichment->User, _countof(Enrichment->User), rawValue);
        }
    } else {
        (void)SysmonResolveProcessUserByPid(payload->ProcessId, Enrichment->User, _countof(Enrichment->User));
    }
}

static VOID
SysmonEnsureImageLoadVersionInfo(
    _Inout_ SYSMON_PROCESS_CREATE_ENRICHMENT *Enrichment)
{
    if (Enrichment == NULL ||
        !Enrichment->NeedsVersionInfo ||
        Enrichment->VersionInfoLoaded ||
        SysmonIsPlaceholderString(Enrichment->Image)) {
        return;
    }

    SysmonLoadVersionStrings(Enrichment->Image, Enrichment);
    Enrichment->VersionInfoLoaded = TRUE;
}

void
SysmonResolveImageVersionInfo(
    _In_opt_z_ LPCWSTR ModulePath,
    _Out_ PSYSMON_IMAGE_VERSION_INFO VersionInfo)
{
    SYSMON_PROCESS_CREATE_ENRICHMENT enrichment;

    if (VersionInfo == NULL) {
        return;
    }

    ZeroMemory(VersionInfo, sizeof(*VersionInfo));
    if (SysmonIsPlaceholderString(ModulePath)) {
        return;
    }

    ZeroMemory(&enrichment, sizeof(enrichment));
    SysmonLoadVersionStrings(ModulePath, &enrichment);
    (void)SysmonCopyWideText(VersionInfo->FileVersion, _countof(VersionInfo->FileVersion), enrichment.FileVersion);
    (void)SysmonCopyWideText(VersionInfo->Description, _countof(VersionInfo->Description), enrichment.Description);
    (void)SysmonCopyWideText(VersionInfo->Product, _countof(VersionInfo->Product), enrichment.Product);
    (void)SysmonCopyWideText(VersionInfo->Company, _countof(VersionInfo->Company), enrichment.Company);
    (void)SysmonCopyWideText(VersionInfo->OriginalFileName, _countof(VersionInfo->OriginalFileName), enrichment.OriginalFileName);
}

static BOOL
SysmonTryFormatProcessCreateEnrichedField(
    _In_ LPCWSTR FieldName,
    _In_ const SYSMON_PROCESS_CREATE_ENRICHMENT *Enrichment,
    _In_opt_z_ PCWSTR RawValue,
    _Out_writes_(BufferChars) PWCHAR Buffer,
    _In_ size_t BufferChars)
{
    PCWSTR replacement = NULL;

    if (FieldName == NULL || Enrichment == NULL || Buffer == NULL || BufferChars == 0) {
        return FALSE;
    }

    if (_wcsicmp(FieldName, EVT_FIELD_IMAGE) == 0) {
        replacement = Enrichment->Image;
    } else if (_wcsicmp(FieldName, EVT_FIELD_PARENT_IMAGE) == 0) {
        replacement = Enrichment->ParentImage;
    } else if (_wcsicmp(FieldName, EVT_FIELD_USER) == 0) {
        replacement = Enrichment->User;
    } else if (_wcsicmp(FieldName, EVT_FIELD_PARENT_USER) == 0) {
        replacement = Enrichment->ParentUser;
    } else if (_wcsicmp(FieldName, EVT_FIELD_FILE_VERSION) == 0 && SysmonIsPlaceholderString(RawValue)) {
        replacement = Enrichment->FileVersion;
    } else if (_wcsicmp(FieldName, EVT_FIELD_DESCRIPTION) == 0 && SysmonIsPlaceholderString(RawValue)) {
        replacement = Enrichment->Description;
    } else if (_wcsicmp(FieldName, EVT_FIELD_PRODUCT) == 0 && SysmonIsPlaceholderString(RawValue)) {
        replacement = Enrichment->Product;
    } else if (_wcsicmp(FieldName, EVT_FIELD_COMPANY) == 0 && SysmonIsPlaceholderString(RawValue)) {
        replacement = Enrichment->Company;
    } else if (_wcsicmp(FieldName, EVT_FIELD_ORIGINAL_FILENAME) == 0 && SysmonIsPlaceholderString(RawValue)) {
        replacement = Enrichment->OriginalFileName;
    } else if (_wcsicmp(FieldName, EVT_FIELD_HASHES) == 0 && SysmonIsPlaceholderString(RawValue)) {
        replacement = Enrichment->Hashes;
    }

    if (SysmonIsPlaceholderString(replacement)) {
        return FALSE;
    }

    return SysmonCopyWideText(Buffer, BufferChars, replacement);
}

static BOOL
SysmonTryFormatImageLoadEnrichedField(
    _In_ LPCWSTR FieldName,
    _Inout_ SYSMON_PROCESS_CREATE_ENRICHMENT *Enrichment,
    _In_opt_z_ PCWSTR RawValue,
    _Out_writes_(BufferChars) PWCHAR Buffer,
    _In_ size_t BufferChars)
{
    PCWSTR replacement = NULL;

    if (FieldName == NULL || Enrichment == NULL || Buffer == NULL || BufferChars == 0) {
        return FALSE;
    }

    if (_wcsicmp(FieldName, EVT_FIELD_USER) == 0) {
        replacement = Enrichment->User;
    } else if (_wcsicmp(FieldName, EVT_FIELD_FILE_VERSION) == 0 && SysmonIsPlaceholderString(RawValue)) {
        SysmonEnsureImageLoadVersionInfo(Enrichment);
        replacement = Enrichment->FileVersion;
    } else if (_wcsicmp(FieldName, EVT_FIELD_DESCRIPTION) == 0 && SysmonIsPlaceholderString(RawValue)) {
        SysmonEnsureImageLoadVersionInfo(Enrichment);
        replacement = Enrichment->Description;
    } else if (_wcsicmp(FieldName, EVT_FIELD_PRODUCT) == 0 && SysmonIsPlaceholderString(RawValue)) {
        SysmonEnsureImageLoadVersionInfo(Enrichment);
        replacement = Enrichment->Product;
    } else if (_wcsicmp(FieldName, EVT_FIELD_COMPANY) == 0 && SysmonIsPlaceholderString(RawValue)) {
        SysmonEnsureImageLoadVersionInfo(Enrichment);
        replacement = Enrichment->Company;
    } else if (_wcsicmp(FieldName, EVT_FIELD_ORIGINAL_FILENAME) == 0 && SysmonIsPlaceholderString(RawValue)) {
        SysmonEnsureImageLoadVersionInfo(Enrichment);
        replacement = Enrichment->OriginalFileName;
    }

    if (SysmonIsPlaceholderString(replacement)) {
        return FALSE;
    }

    return SysmonCopyWideText(Buffer, BufferChars, replacement);
}

static BOOL
SysmonIsPathLikeField(
    _In_opt_ LPCWSTR FieldName)
{
    return FieldName != NULL &&
        (_wcsicmp(FieldName, EVT_FIELD_IMAGE) == 0 ||
         _wcsicmp(FieldName, EVT_FIELD_PARENT_IMAGE) == 0 ||
         _wcsicmp(FieldName, EVT_FIELD_IMAGE_LOADED) == 0 ||
         _wcsicmp(FieldName, EVT_FIELD_TARGET_FILENAME) == 0 ||
         _wcsicmp(FieldName, EVT_FIELD_CURRENT_DIRECTORY) == 0 ||
         _wcsicmp(FieldName, EVT_FIELD_SOURCE_IMAGE) == 0 ||
         _wcsicmp(FieldName, EVT_FIELD_TARGET_IMAGE) == 0);
}

static BOOL
SysmonIsUserLikeField(
    _In_opt_ LPCWSTR FieldName)
{
    return FieldName != NULL &&
        (_wcsicmp(FieldName, EVT_FIELD_USER) == 0 ||
         _wcsicmp(FieldName, EVT_FIELD_PARENT_USER) == 0 ||
         _wcsicmp(FieldName, EVT_FIELD_SOURCE_USER) == 0 ||
         _wcsicmp(FieldName, EVT_FIELD_TARGET_USER) == 0);
}

static BOOL
SysmonTryFormatGenericEnrichedField(
    _In_ LPCWSTR FieldName,
    _In_opt_z_ PCWSTR RawValue,
    _Out_writes_(BufferChars) PWCHAR Buffer,
    _In_ size_t BufferChars)
{
    WCHAR transformed[2048];

    if (FieldName == NULL || Buffer == NULL || BufferChars == 0 ||
        SysmonIsPlaceholderString(RawValue)) {
        return FALSE;
    }

    if (SysmonIsUserLikeField(FieldName)) {
        if (SysmonResolveSidDisplay(RawValue, transformed, _countof(transformed))) {
            return SysmonCopyWideText(Buffer, BufferChars, transformed);
        }

        return SysmonCopyWideText(Buffer, BufferChars, RawValue);
    }

    if (SysmonIsPathLikeField(FieldName)) {
        if (!SysmonPathNeedsNormalization(RawValue)) {
            return SysmonCopyWideText(Buffer, BufferChars, RawValue);
        }

        if (SysmonConvertNtPathToWin32Path(RawValue, transformed, _countof(transformed))) {
            return SysmonCopyWideText(Buffer, BufferChars, transformed);
        }

        return SysmonCopyWideText(Buffer, BufferChars, RawValue);
    }

    return FALSE;
}

BOOL
FormatFieldValueForEvent(
    _In_ SYSMON_EVENT_ID EventId,
    _In_reads_bytes_(PayloadSize) const UCHAR *PayloadBase,
    _In_ DWORD PayloadSize,
    _In_ const SYSMON_EVENT_FIELD_DESCRIPTOR *Field,
    _In_opt_ const SYSMON_PROCESS_CREATE_ENRICHMENT *ProcessCreateEnrichment,
    _Inout_opt_ SYSMON_PROCESS_CREATE_ENRICHMENT *ImageLoadEnrichment,
    _Out_writes_(BufferChars) PWCHAR Buffer,
    _In_ size_t BufferChars)
{
    BOOL rawResult;

    rawResult = FormatFieldValue(PayloadBase, PayloadSize, Field, Buffer, BufferChars);
    if (Field != NULL &&
        Field->Kind == SysmonRenderStringRef &&
        rawResult) {
        WCHAR rawValue[2048];

        SysmonCopyWideText(rawValue, _countof(rawValue), Buffer);

        if (EventId == SysmonEventProcessCreate &&
            ProcessCreateEnrichment != NULL &&
            SysmonTryFormatProcessCreateEnrichedField(
                Field->Name,
                ProcessCreateEnrichment,
                rawValue,
                Buffer,
                BufferChars)) {
            SysmonApplyConfiguredFieldSize(Field, Buffer, BufferChars);
            return TRUE;
        }

        if (EventId == SysmonEventImageLoad &&
            ImageLoadEnrichment != NULL &&
            SysmonTryFormatImageLoadEnrichedField(
                Field->Name,
                ImageLoadEnrichment,
                rawValue,
                Buffer,
                BufferChars)) {
            SysmonApplyConfiguredFieldSize(Field, Buffer, BufferChars);
            return TRUE;
        }

        if (SysmonTryFormatGenericEnrichedField(
                Field->Name,
                rawValue,
                Buffer,
                BufferChars)) {
            SysmonApplyConfiguredFieldSize(Field, Buffer, BufferChars);
            return TRUE;
        }
    }

    if (rawResult) {
        SysmonApplyConfiguredFieldSize(Field, Buffer, BufferChars);
    }
    return rawResult;
}

static BOOL
SysmonProcessCreateFieldNeedsEnrichment(
    _In_ LPCWSTR FieldName,
    _In_opt_z_ PCWSTR RawValue,
    _In_opt_ const SYSMON_PROCESS_CREATE_ENRICHMENT *Enrichment)
{
    if (FieldName == NULL) {
        return FALSE;
    }

    if (_wcsicmp(FieldName, EVT_FIELD_IMAGE) == 0 ||
        _wcsicmp(FieldName, EVT_FIELD_PARENT_IMAGE) == 0 ||
        _wcsicmp(FieldName, EVT_FIELD_USER) == 0 ||
        _wcsicmp(FieldName, EVT_FIELD_PARENT_USER) == 0) {
        return TRUE;
    }

    if (Enrichment == NULL || !SysmonIsPlaceholderString(RawValue)) {
        return FALSE;
    }

    return ((_wcsicmp(FieldName, EVT_FIELD_FILE_VERSION) == 0 && !SysmonIsPlaceholderString(Enrichment->FileVersion)) ||
            (_wcsicmp(FieldName, EVT_FIELD_DESCRIPTION) == 0 && !SysmonIsPlaceholderString(Enrichment->Description)) ||
            (_wcsicmp(FieldName, EVT_FIELD_PRODUCT) == 0 && !SysmonIsPlaceholderString(Enrichment->Product)) ||
            (_wcsicmp(FieldName, EVT_FIELD_COMPANY) == 0 && !SysmonIsPlaceholderString(Enrichment->Company)) ||
            (_wcsicmp(FieldName, EVT_FIELD_ORIGINAL_FILENAME) == 0 && !SysmonIsPlaceholderString(Enrichment->OriginalFileName)) ||
            (_wcsicmp(FieldName, EVT_FIELD_HASHES) == 0 && !SysmonIsPlaceholderString(Enrichment->Hashes)));
}

static BOOL
SysmonImageLoadFieldNeedsEnrichment(
    _In_ LPCWSTR FieldName,
    _In_opt_z_ PCWSTR RawValue,
    _In_opt_ const SYSMON_PROCESS_CREATE_ENRICHMENT *Enrichment)
{
    if (FieldName == NULL) {
        return FALSE;
    }

    if (_wcsicmp(FieldName, EVT_FIELD_IMAGE) == 0 ||
        _wcsicmp(FieldName, EVT_FIELD_IMAGE_LOADED) == 0 ||
        _wcsicmp(FieldName, EVT_FIELD_USER) == 0) {
        return TRUE;
    }

    if (Enrichment == NULL || !SysmonIsPlaceholderString(RawValue)) {
        return FALSE;
    }

    return (((_wcsicmp(FieldName, EVT_FIELD_FILE_VERSION) == 0 ||
              _wcsicmp(FieldName, EVT_FIELD_DESCRIPTION) == 0 ||
              _wcsicmp(FieldName, EVT_FIELD_PRODUCT) == 0 ||
              _wcsicmp(FieldName, EVT_FIELD_COMPANY) == 0 ||
              _wcsicmp(FieldName, EVT_FIELD_ORIGINAL_FILENAME) == 0) &&
             Enrichment->NeedsVersionInfo));
}

BOOL
SysmonCanUseDirectEtwStringRef(
    _In_ SYSMON_EVENT_ID EventId,
    _In_ const SYSMON_EVENT_FIELD_DESCRIPTOR *Field,
    _In_opt_z_ PCWSTR RawValue,
    _In_opt_ const SYSMON_PROCESS_CREATE_ENRICHMENT *ProcessCreateEnrichment,
    _In_opt_ const SYSMON_PROCESS_CREATE_ENRICHMENT *ImageLoadEnrichment)
{
    if (Field == NULL || Field->Name == NULL) {
        return FALSE;
    }

    if (ShouldPreserveEmptyEtwString(EventId, Field)) {
        return TRUE;
    }

    if (SysmonIsUserLikeField(Field->Name)) {
        return FALSE;
    }

    if (SysmonIsPathLikeField(Field->Name)) {
        return RawValue != NULL && !SysmonPathNeedsNormalization(RawValue);
    }

    if (EventId == SysmonEventProcessCreate) {
        return !SysmonProcessCreateFieldNeedsEnrichment(Field->Name, RawValue, ProcessCreateEnrichment);
    }

    if (EventId == SysmonEventImageLoad) {
        return !SysmonImageLoadFieldNeedsEnrichment(Field->Name, RawValue, ImageLoadEnrichment);
    }

    return TRUE;
}

VOID
SysmonPrepareOutputEventContext(
    _In_ SYSMON_EVENT_ID EventId,
    _In_reads_bytes_(PayloadSize) const UCHAR *PayloadBase,
    _In_ DWORD PayloadSize,
    _Out_ PSYSMON_OUTPUT_EVENT_CONTEXT Context)
{
    if (Context == NULL) {
        return;
    }

    ZeroMemory(Context, sizeof(*Context));
    Context->Schema = GetEventSchema(EventId);
    Context->PayloadBase = PayloadBase;
    Context->PayloadSize = PayloadSize;

    if (PayloadBase == NULL) {
        return;
    }

    if (EventId == SysmonEventProcessCreate) {
        SysmonBuildProcessCreateEnrichment(
            PayloadBase,
            PayloadSize,
            &Context->ProcessCreateStorage);
        Context->ProcessCreateEnrichment = &Context->ProcessCreateStorage;
    } else if (EventId == SysmonEventImageLoad) {
        SysmonBuildImageLoadEnrichment(
            PayloadBase,
            PayloadSize,
            &Context->ImageLoadStorage);
        Context->ImageLoadEnrichment = &Context->ImageLoadStorage;
    }
}


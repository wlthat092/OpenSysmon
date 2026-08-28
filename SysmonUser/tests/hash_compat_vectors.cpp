#include "../include/hash_compat.h"

#include <iostream>
#include <string>

static int
ExpectWideEquals(
    const wchar_t *label,
    const wchar_t *actual,
    const wchar_t *expected)
{
    if (actual == nullptr || expected == nullptr) {
        std::wcerr << L"[FAIL] " << label << L": null string input" << std::endl;
        return 1;
    }

    if (wcscmp(actual, expected) != 0) {
        std::wcerr << L"[FAIL] " << label << std::endl;
        std::wcerr << L"  expected: " << expected << std::endl;
        std::wcerr << L"  actual:   " << actual << std::endl;
        return 1;
    }

    std::wcout << L"[PASS] " << label << std::endl;
    return 0;
}

int
wmain()
{
    static const UCHAR buffer[] = { 'a', 'b', 'c' };
    static const WCHAR expectedBufferHashes[] =
        L"SHA1=a9993e364706816aba3e25717850c26c9cd0d89d,"
        L"MD5=900150983cd24fb0d6963f7d28e17f72,"
        L"SHA256=ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad,"
        L"IMPHASH=00000000000000000000000000000000";
    static const WCHAR expectedFileHashes[] =
        L"SHA1=a9993e364706816aba3e25717850c26c9cd0d89d,"
        L"MD5=900150983cd24fb0d6963f7d28e17f72,"
        L"SHA256=ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";

    WCHAR hashString[256];
    WCHAR tempPath[MAX_PATH];
    WCHAR tempFile[MAX_PATH];
    int failures = 0;

    ZeroMemory(hashString, sizeof(hashString));
    if (!NT_SUCCESS(SysmonComputeHashes(buffer, (ULONG)sizeof(buffer), hashString, RTL_NUMBER_OF(hashString)))) {
        std::wcerr << L"[FAIL] SysmonComputeHashes returned failure" << std::endl;
        return 1;
    }

    failures += ExpectWideEquals(L"buffer hashes", hashString, expectedBufferHashes);

    if (GetTempPathW(RTL_NUMBER_OF(tempPath), tempPath) == 0 ||
        GetTempFileNameW(tempPath, L"sch", 0, tempFile) == 0) {
        std::wcerr << L"[FAIL] failed to create temp file" << std::endl;
        return 1;
    }

    {
        HANDLE fileHandle;
        DWORD bytesWritten = 0;

        fileHandle = CreateFileW(
            tempFile,
            GENERIC_WRITE,
            0,
            NULL,
            CREATE_ALWAYS,
            FILE_ATTRIBUTE_NORMAL,
            NULL);
        if (fileHandle == INVALID_HANDLE_VALUE) {
            std::wcerr << L"[FAIL] failed to open temp file for writing" << std::endl;
            DeleteFileW(tempFile);
            return 1;
        }

        if (!WriteFile(fileHandle, buffer, sizeof(buffer), &bytesWritten, NULL) ||
            bytesWritten != sizeof(buffer)) {
            std::wcerr << L"[FAIL] failed to write temp file" << std::endl;
            CloseHandle(fileHandle);
            DeleteFileW(tempFile);
            return 1;
        }

        CloseHandle(fileHandle);
    }

    ZeroMemory(hashString, sizeof(hashString));
    if (!SysmonComputeFileHashes(
            tempFile,
            SYSMON_HASH_MD5 | SYSMON_HASH_SHA1 | SYSMON_HASH_SHA256,
            hashString,
            RTL_NUMBER_OF(hashString))) {
        std::wcerr << L"[FAIL] SysmonComputeFileHashes returned failure" << std::endl;
        DeleteFileW(tempFile);
        return 1;
    }

    failures += ExpectWideEquals(L"file hashes", hashString, expectedFileHashes);
    DeleteFileW(tempFile);
    return failures == 0 ? 0 : 1;
}

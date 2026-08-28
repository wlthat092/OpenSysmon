#include <iostream>

#include "../src/hash_compat.cpp"

static int
ExpectDigestEquals(
    const wchar_t *label,
    const UCHAR *actual,
    const UCHAR *expected,
    size_t length)
{
    if (memcmp(actual, expected, length) != 0) {
        char actualHex[65];
        char expectedHex[65];

        ZeroMemory(actualHex, sizeof(actualHex));
        ZeroMemory(expectedHex, sizeof(expectedHex));
        SysmonBytesToHex(actual, (ULONG)length, actualHex, sizeof(actualHex));
        SysmonBytesToHex(expected, (ULONG)length, expectedHex, sizeof(expectedHex));

        std::wcerr << L"[FAIL] " << label << std::endl;
        std::cerr << "  expected: " << expectedHex << std::endl;
        std::cerr << "  actual:   " << actualHex << std::endl;
        return 1;
    }

    std::wcout << L"[PASS] " << label << std::endl;
    return 0;
}

int
wmain()
{
    static const UCHAR chunk1[] = { 'a' };
    static const UCHAR chunk2[] = { 'b', 'c' };
    static const UCHAR expectedMd5[16] = {
        0x90, 0x01, 0x50, 0x98, 0x3c, 0xd2, 0x4f, 0xb0,
        0xd6, 0x96, 0x3f, 0x7d, 0x28, 0xe1, 0x7f, 0x72
    };
    static const UCHAR expectedSha1[20] = {
        0xa9, 0x99, 0x3e, 0x36, 0x47, 0x06, 0x81, 0x6a, 0xba, 0x3e,
        0x25, 0x71, 0x78, 0x50, 0xc2, 0x6c, 0x9c, 0xd0, 0xd8, 0x9d
    };
    static const UCHAR expectedSha256[32] = {
        0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea,
        0x41, 0x41, 0x40, 0xde, 0x5d, 0xae, 0x22, 0x23,
        0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c,
        0xb4, 0x10, 0xff, 0x61, 0xf2, 0x00, 0x15, 0xad
    };

    int failures = 0;
    UCHAR digest[32];
    SYSMON_HASH_INSTANCE instance;

    ZeroMemory(&instance, sizeof(instance));
    if (!SysmonCreateHashInstance(&instance, &g_Md5HashDescriptor, 16) ||
        !SysmonUpdateHashInstance(&instance, chunk1, sizeof(chunk1)) ||
        !SysmonUpdateHashInstance(&instance, chunk2, sizeof(chunk2)) ||
        !SysmonFinishHashInstance(&instance, digest, 16)) {
        std::wcerr << L"[FAIL] incremental MD5 state flow" << std::endl;
        return 1;
    }
    failures += ExpectDigestEquals(L"incremental MD5", digest, expectedMd5, 16);
    SysmonDestroyHashInstance(&instance);

    ZeroMemory(&instance, sizeof(instance));
    if (!SysmonCreateHashInstance(&instance, &g_Sha1HashDescriptor, 20) ||
        !SysmonUpdateHashInstance(&instance, chunk1, sizeof(chunk1)) ||
        !SysmonUpdateHashInstance(&instance, chunk2, sizeof(chunk2)) ||
        !SysmonFinishHashInstance(&instance, digest, 20)) {
        std::wcerr << L"[FAIL] incremental SHA1 state flow" << std::endl;
        return 1;
    }
    failures += ExpectDigestEquals(L"incremental SHA1", digest, expectedSha1, 20);
    SysmonDestroyHashInstance(&instance);

    ZeroMemory(&instance, sizeof(instance));
    if (!SysmonCreateHashInstance(&instance, &g_Sha256HashDescriptor, 32) ||
        !SysmonUpdateHashInstance(&instance, chunk1, sizeof(chunk1)) ||
        !SysmonUpdateHashInstance(&instance, chunk2, sizeof(chunk2)) ||
        !SysmonFinishHashInstance(&instance, digest, 32)) {
        std::wcerr << L"[FAIL] incremental SHA256 state flow" << std::endl;
        return 1;
    }
    failures += ExpectDigestEquals(L"incremental SHA256", digest, expectedSha256, 32);
    SysmonDestroyHashInstance(&instance);

    return failures == 0 ? 0 : 1;
}

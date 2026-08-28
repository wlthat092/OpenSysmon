// rules_match_vectors.cpp - runnable test of the Sysmon rule-matching engine.
//
// Compiles the real user-mode rule engine (../src/rules.cpp), which is the
// parity implementation of the kernel rules.c matching semantics, and drives the
// full serialize -> validate -> load -> match pipeline. It covers include/exclude
// semantics, condition operators, and malformed-blob rejection (P3 in the
// 2026-08-04 review).
//
// The only external dependency of rules.cpp is SysmonExtractEventField, which is
// stubbed below to serve controlled field values per test case.

#include <windows.h>
#include <cstdio>
#include <cwchar>

#include "../src/rules.cpp"

// ---------------------------------------------------------------------------
// Fake event fields: SysmonExtractEventField reads these per test case.
// ---------------------------------------------------------------------------
struct FakeEventFields {
    const wchar_t *Image;
    const wchar_t *CommandLine;
};

static FakeEventFields g_fakeFields = { L"", L"" };

BOOL
SysmonExtractEventField(
    _In_reads_bytes_(EventSize) const BYTE *EventData,
    _In_ DWORD EventSize,
    _In_ SYSMON_EVENT_ID EventId,
    _In_ LPCWSTR FieldName,
    _Out_writes_(BufferChars) PWCHAR Buffer,
    _In_ size_t BufferChars)
{
    const wchar_t *value = L"";

    UNREFERENCED_PARAMETER(EventData);
    UNREFERENCED_PARAMETER(EventSize);
    UNREFERENCED_PARAMETER(EventId);

    if (wcscmp(FieldName, L"Image") == 0) {
        value = g_fakeFields.Image;
    } else if (wcscmp(FieldName, L"CommandLine") == 0) {
        value = g_fakeFields.CommandLine;
    }

    if (value == NULL || Buffer == NULL || BufferChars == 0) {
        return FALSE;
    }

    wcsncpy_s(Buffer, BufferChars, value, _TRUNCATE);
    return TRUE;
}

// ---------------------------------------------------------------------------
// Assertion helpers
// ---------------------------------------------------------------------------
static int g_failures = 0;
static int g_checks = 0;

static void Check(bool cond, const char *what)
{
    g_checks++;
    if (cond) {
        printf("[PASS] %s\n", what);
    } else {
        g_failures++;
        printf("[FAIL] %s\n", what);
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------
static void SetFakeFields(const wchar_t *image, const wchar_t *commandLine)
{
    g_fakeFields.Image = image != NULL ? image : L"";
    g_fakeFields.CommandLine = commandLine != NULL ? commandLine : L"";
}

static PSYSMON_RULE_RUNTIME
LoadRuntime(const SYSMON_RULE_SET *ruleSet, PBYTE *outBlob, DWORD *outBlobSize)
{
    PBYTE blob = NULL;
    DWORD blobSize = 0;
    PSYSMON_RULE_RUNTIME runtime = NULL;
    SYSMON_STATUS status;

    status = SysmonSerializeRules(ruleSet, &blob, &blobSize);
    if (status != SYSMON_SUCCESS || blob == NULL || blobSize == 0) {
        return NULL;
    }

    status = SysmonLoadRuleRuntime(blob, blobSize, &runtime);
    if (status != SYSMON_SUCCESS || runtime == NULL) {
        SYSMON_FREE(blob);
        return NULL;
    }

    *outBlob = blob;
    *outBlobSize = blobSize;
    return runtime;
}

static bool MatchesEvent(PSYSMON_RULE_RUNTIME runtime, SYSMON_EVENT_ID eventId)
{
    BYTE dummyEvent[128];
    ZeroMemory(dummyEvent, sizeof(dummyEvent));
    return SysmonShouldCaptureEvent(
        runtime,
        eventId,
        dummyEvent,
        (DWORD)sizeof(dummyEvent)) != FALSE;
}

// ---------------------------------------------------------------------------
// Test cases
// ---------------------------------------------------------------------------
static void TestIncludeOnlyRule(void)
{
    wchar_t fieldImage[] = L"Image";
    wchar_t valCmdExe[] = L"cmd.exe";
    SYSMON_RULE_EXPRESSION exprs[] = {
        { fieldImage, valCmdExe, SysmonRuleConditionContains },
    };
    SYSMON_RULE rules[] = {
        { L"rule-cmd", SysmonRuleRelationAnd, 1, exprs },
    };
    SYSMON_EVENT_RULE eventRules[] = {
        { SysmonEventProcessCreate, SysmonRuleMatchTypeInclude, SysmonRuleRelationAnd, 1, rules },
    };
    SYSMON_RULE_GROUP groups[] = {
        { L"groupA", SysmonRuleRelationOr, 1, eventRules },
    };
    SYSMON_RULE_SET ruleSet = { 1, groups };
    PBYTE blob = NULL;
    DWORD blobSize = 0;
    PSYSMON_RULE_RUNTIME runtime = LoadRuntime(&ruleSet, &blob, &blobSize);

    Check(runtime != NULL, "serialize+load include-only rule set");
    if (runtime != NULL) {
        SetFakeFields(L"C:\\Windows\\System32\\cmd.exe", L"cmd.exe /c whoami");
        Check(MatchesEvent(runtime, SysmonEventProcessCreate),"include: Image contains 'cmd.exe' -> captured");

        SetFakeFields(L"C:\\Windows\\System32\\notepad.exe", L"notepad.exe");
        Check(!MatchesEvent(runtime, SysmonEventProcessCreate), "include: Image without 'cmd.exe' -> filtered");

        SysmonFreeRuleRuntime(runtime);
    }
    SYSMON_FREE(blob);
}

static void TestExcludeOverridesInclude(void)
{
    wchar_t fieldImage[] = L"Image";
    wchar_t fieldCmd[] = L"CommandLine";
    wchar_t valDashC[] = L"-c";
    wchar_t valSafe[] = L"safe";
    SYSMON_RULE_EXPRESSION incExpr[] = { { fieldCmd, valDashC, SysmonRuleConditionContains } };
    SYSMON_RULE_EXPRESSION excExpr[] = { { fieldImage, valSafe, SysmonRuleConditionContains } };
    SYSMON_RULE rules[] = {
        { L"r-include", SysmonRuleRelationAnd, 1, incExpr },
        { L"r-exclude", SysmonRuleRelationAnd, 1, excExpr },
    };
    SYSMON_EVENT_RULE eventRules[] = {
        { SysmonEventProcessCreate, SysmonRuleMatchTypeInclude, SysmonRuleRelationAnd, 1, &rules[0] },
        { SysmonEventProcessCreate, SysmonRuleMatchTypeExclude, SysmonRuleRelationAnd, 1, &rules[1] },
    };
    SYSMON_RULE_GROUP groups[] = {
        { L"groupB", SysmonRuleRelationOr, 2, eventRules },
    };
    SYSMON_RULE_SET ruleSet = { 1, groups };
    PBYTE blob = NULL;
    DWORD blobSize = 0;
    PSYSMON_RULE_RUNTIME runtime = LoadRuntime(&ruleSet, &blob, &blobSize);

    Check(runtime != NULL, "serialize+load include+exclude rule set");
    if (runtime != NULL) {
        /* include matches (-c) and exclude matches (safe) -> dropped */
        SetFakeFields(L"C:\\safe\\tool.exe", L"tool.exe -c x");
        Check(!MatchesEvent(runtime, SysmonEventProcessCreate), "exclude: include matches but exclude overrides -> filtered");

        /* include matches, exclude does not -> captured */
        SetFakeFields(L"C:\\other\\tool.exe", L"tool.exe -c x");
        Check(MatchesEvent(runtime, SysmonEventProcessCreate),"exclude: include matches, no exclude -> captured");

        /* neither include nor exclude matches -> filtered */
        SetFakeFields(L"C:\\other\\tool.exe", L"tool.exe plain");
        Check(!MatchesEvent(runtime, SysmonEventProcessCreate), "exclude: no include match -> filtered");

        SysmonFreeRuleRuntime(runtime);
    }
    SYSMON_FREE(blob);
}

static void TestIsAnyOperator(void)
{
    wchar_t fieldImage[] = L"Image";
    SYSMON_RULE_EXPRESSION exprs[] = {
        { fieldImage, L"cmd.exe;powershell.exe", SysmonRuleConditionIsAny },
    };
    SYSMON_RULE rules[] = {
        { L"rule-any", SysmonRuleRelationAnd, 1, exprs },
    };
    SYSMON_EVENT_RULE eventRules[] = {
        { SysmonEventProcessCreate, SysmonRuleMatchTypeInclude, SysmonRuleRelationAnd, 1, rules },
    };
    SYSMON_RULE_GROUP groups[] = {
        { L"groupC", SysmonRuleRelationOr, 1, eventRules },
    };
    SYSMON_RULE_SET ruleSet = { 1, groups };
    PBYTE blob = NULL;
    DWORD blobSize = 0;
    PSYSMON_RULE_RUNTIME runtime = LoadRuntime(&ruleSet, &blob, &blobSize);

    Check(runtime != NULL, "serialize+load 'is any' rule set");
    if (runtime != NULL) {
        SetFakeFields(L"cmd.exe", L"");
        Check(MatchesEvent(runtime, SysmonEventProcessCreate),"is any: exact token matches");

        SetFakeFields(L"notepad.exe", L"");
        Check(!MatchesEvent(runtime, SysmonEventProcessCreate), "is any: non-token does not match");

        SysmonFreeRuleRuntime(runtime);
    }
    SYSMON_FREE(blob);
}

static void TestEmptyRuleSetSemantics(void)
{
    SYSMON_RULE_SET ruleSet = { 0, NULL };
    PBYTE blob = NULL;
    DWORD blobSize = 0;
    PSYSMON_RULE_RUNTIME runtime = LoadRuntime(&ruleSet, &blob, &blobSize);

    Check(runtime != NULL, "serialize+load empty rule set");
    if (runtime != NULL) {
        /* Config-rules events (e.g. ProcessCreate) require an explicit rule. */
        Check(!MatchesEvent(runtime, SysmonEventProcessCreate),
            "empty rule set: config-rules event is dropped");
        /* Non-config-rules events (service state) are captured by default. */
        Check(MatchesEvent(runtime, SysmonEventServiceState),
            "empty rule set: service-state event is captured");

        SysmonFreeRuleRuntime(runtime);
    }
    SYSMON_FREE(blob);
}

static void TestMalformedBlobRejected(void)
{
    wchar_t fieldImage[] = L"Image";
    SYSMON_RULE_EXPRESSION exprs[] = {
        { fieldImage, L"cmd.exe", SysmonRuleConditionContains },
    };
    SYSMON_RULE rules[] = {
        { L"rule-cmd", SysmonRuleRelationAnd, 1, exprs },
    };
    SYSMON_EVENT_RULE eventRules[] = {
        { SysmonEventProcessCreate, SysmonRuleMatchTypeInclude, SysmonRuleRelationAnd, 1, rules },
    };
    SYSMON_RULE_GROUP groups[] = {
        { L"groupD", SysmonRuleRelationOr, 1, eventRules },
    };
    SYSMON_RULE_SET ruleSet = { 1, groups };
    PBYTE blob = NULL;
    DWORD blobSize = 0;
    PSYSMON_RULE_RUNTIME runtime = LoadRuntime(&ruleSet, &blob, &blobSize);

    Check(blob != NULL && blobSize > 0, "serialize produced a blob to corrupt");
    if (blob != NULL && blobSize > 0) {
        PSYSMON_RULE_RUNTIME badRuntime = NULL;
        PBYTE corrupt = (PBYTE)SYSMON_ALLOC(blobSize);
        if (corrupt != NULL) {
            CopyMemory(corrupt, blob, blobSize);
            corrupt[0] ^= 0xFF; /* flip a signature byte */
            Check(SysmonLoadRuleRuntime(corrupt, blobSize, &badRuntime) != SYSMON_SUCCESS,
                "corrupt blob signature rejected");
            SYSMON_FREE(corrupt);
        }

        badRuntime = NULL;
        Check(SysmonLoadRuleRuntime(blob, 4, &badRuntime) != SYSMON_SUCCESS,
            "truncated blob rejected");

        /* Corrupt an internal offset so validation must fail. */
        badRuntime = NULL;
        corrupt = (PBYTE)SYSMON_ALLOC(blobSize);
        if (corrupt != NULL) {
            CopyMemory(corrupt, blob, blobSize);
            /* GroupOffset sits at offset 40 in the blob header (10 ULONGs in). */
            if (blobSize >= 44) {
                ULONG badOffset = 0x0FFFFFFFUL;
                CopyMemory(corrupt + 40, &badOffset, sizeof(badOffset));
            }
            Check(SysmonLoadRuleRuntime(corrupt, blobSize, &badRuntime) != SYSMON_SUCCESS,
                "out-of-range blob offset rejected");
            SYSMON_FREE(corrupt);
        }
    }

    if (runtime != NULL) {
        SysmonFreeRuleRuntime(runtime);
    }
    SYSMON_FREE(blob);
}

static void TestOverLongToken(void)
{
    wchar_t fieldImage[] = L"Image";
    wchar_t fieldCmd[] = L"CommandLine";
    wchar_t longToken[320];
    LONG i;

    for (i = 0; i < 300; i++) {
        longToken[i] = L'x';
    }
    longToken[300] = L'\0';

    /* ContainsAny with an over-long token must compare at full length. */
    {
        SYSMON_RULE_EXPRESSION exprs[] = {
            { fieldImage, longToken, SysmonRuleConditionContainsAny },
        };
        SYSMON_RULE rules[] = {
            { L"rule-long", SysmonRuleRelationAnd, 1, exprs },
        };
        SYSMON_EVENT_RULE eventRules[] = {
            { SysmonEventProcessCreate, SysmonRuleMatchTypeInclude, SysmonRuleRelationAnd, 1, rules },
        };
        SYSMON_RULE_GROUP groups[] = {
            { L"groupD", SysmonRuleRelationOr, 1, eventRules },
        };
        SYSMON_RULE_SET ruleSet = { 1, groups };
        PBYTE blob = NULL;
        DWORD blobSize = 0;
        PSYSMON_RULE_RUNTIME runtime = LoadRuntime(&ruleSet, &blob, &blobSize);

        Check(runtime != NULL, "serialize+load over-long-token rule set");
        if (runtime != NULL) {
            SetFakeFields(longToken, L"");
            Check(MatchesEvent(runtime, SysmonEventProcessCreate),
                "over-long token: field contains it -> captured");

            SetFakeFields(L"C:\\Windows\\System32\\cmd.exe", L"");
            Check(!MatchesEvent(runtime, SysmonEventProcessCreate),
                "over-long token: field does not contain it -> filtered");

            SysmonFreeRuleRuntime(runtime);
        }
        SYSMON_FREE(blob);
    }

    /* ExcludesAny with a single over-long token: a field that does NOT contain
       the token must still be excluded. This regressed when long tokens were
       skipped (P2 in the review). */
    {
        SYSMON_RULE_EXPRESSION incExpr[] = {
            { fieldCmd, L"-c", SysmonRuleConditionContains },
        };
        SYSMON_RULE_EXPRESSION excExpr[] = {
            { fieldImage, longToken, SysmonRuleConditionExcludesAny },
        };
        SYSMON_RULE rules[] = {
            { L"r-inc", SysmonRuleRelationAnd, 1, incExpr },
            { L"r-exc", SysmonRuleRelationAnd, 1, excExpr },
        };
        SYSMON_EVENT_RULE eventRules[] = {
            { SysmonEventProcessCreate, SysmonRuleMatchTypeInclude, SysmonRuleRelationAnd, 1, &rules[0] },
            { SysmonEventProcessCreate, SysmonRuleMatchTypeExclude, SysmonRuleRelationAnd, 1, &rules[1] },
        };
        SYSMON_RULE_GROUP groups[] = {
            { L"groupE", SysmonRuleRelationOr, 2, eventRules },
        };
        SYSMON_RULE_SET ruleSet = { 1, groups };
        PBYTE blob = NULL;
        DWORD blobSize = 0;
        PSYSMON_RULE_RUNTIME runtime = LoadRuntime(&ruleSet, &blob, &blobSize);

        Check(runtime != NULL, "serialize+load excludes-any over-long-token rule set");
        if (runtime != NULL) {
            /* Include matches (-c); the exclude also matches because the image
               does not contain the long token, so the event is dropped. */
            SetFakeFields(L"C:\\Windows\\System32\\cmd.exe", L"cmd.exe -c x");
            Check(!MatchesEvent(runtime, SysmonEventProcessCreate),
                "over-long token: excludes-any still excludes a field that lacks it");

            SysmonFreeRuleRuntime(runtime);
        }
        SYSMON_FREE(blob);
    }
}

int main(void)
{
    TestIncludeOnlyRule();
    TestExcludeOverridesInclude();
    TestIsAnyOperator();
    TestEmptyRuleSetSemantics();
    TestMalformedBlobRejected();
    TestOverLongToken();

    printf("\n%d/%d checks passed\n", g_checks - g_failures, g_checks);
    return g_failures == 0 ? 0 : 1;
}

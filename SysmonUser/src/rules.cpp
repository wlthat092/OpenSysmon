/*
 * rules.c - Rule model helpers and deterministic blob serializer
 */

#include "../include/rules.h"

#include <errno.h>

typedef struct _SYSMON_RULE_NAME_ENTRY {
    LPCWSTR Name;
    DWORD Value;
} SYSMON_RULE_NAME_ENTRY, *PSYSMON_RULE_NAME_ENTRY;

static const SYSMON_RULE_NAME_ENTRY g_SysmonConditionNames[] = {
    { L"is", SysmonRuleConditionIs },
    { L"is not", SysmonRuleConditionIsNot },
    { L"contains", SysmonRuleConditionContains },
    { L"contains any", SysmonRuleConditionContainsAny },
    { L"is any", SysmonRuleConditionIsAny },
    { L"contains all", SysmonRuleConditionContainsAll },
    { L"excludes", SysmonRuleConditionExcludes },
    { L"excludes any", SysmonRuleConditionExcludesAny },
    { L"excludes all", SysmonRuleConditionExcludesAll },
    { L"begin with", SysmonRuleConditionBeginWith },
    { L"end with", SysmonRuleConditionEndWith },
    { L"not begin with", SysmonRuleConditionNotBeginWith },
    { L"not end with", SysmonRuleConditionNotEndWith },
    { L"less than", SysmonRuleConditionLessThan },
    { L"more than", SysmonRuleConditionMoreThan },
    { L"image", SysmonRuleConditionImage }
};

static const SYSMON_RULE_NAME_ENTRY g_SysmonRelationNames[] = {
    { L"or", SysmonRuleRelationOr },
    { L"and", SysmonRuleRelationAnd }
};

#define SYSMON_MAX_ULONG_VALUE ((ULONG)0xFFFFFFFFUL)

typedef struct _SYSMON_RULE_BLOB_COUNTS {
    ULONG GroupCount;
    ULONG EventRuleCount;
    ULONG RuleCount;
    ULONG ExpressionCount;
    ULONG StringBytes;
} SYSMON_RULE_BLOB_COUNTS, *PSYSMON_RULE_BLOB_COUNTS;

typedef struct _SYSMON_RULE_BLOB_WRITER {
    PBYTE Blob;
    ULONG TotalSize;
    ULONG NextGroupIndex;
    ULONG NextEventRuleIndex;
    ULONG NextRuleIndex;
    ULONG NextExpressionIndex;
    ULONG NextStringOffset;
    PSYSMON_RULES_BLOB_GROUP Groups;
    PSYSMON_RULES_BLOB_EVENT_RULE EventRules;
    PSYSMON_RULES_BLOB_RULE Rules;
    PSYSMON_RULES_BLOB_EXPRESSION Expressions;
} SYSMON_RULE_BLOB_WRITER, *PSYSMON_RULE_BLOB_WRITER;

typedef struct _SYSMON_RULE_BLOB_LAYOUT {
    const SYSMON_RULES_BLOB_HEADER *Header;
    const SYSMON_RULES_BLOB_GROUP *Groups;
    const SYSMON_RULES_BLOB_EVENT_RULE *EventRules;
    const SYSMON_RULES_BLOB_RULE *Rules;
    const SYSMON_RULES_BLOB_EXPRESSION *Expressions;
    const WCHAR *StringTable;
} SYSMON_RULE_BLOB_LAYOUT, *PSYSMON_RULE_BLOB_LAYOUT;

static SYSMON_STATUS
SysmonRuleAddUlong(
    _Inout_ PULONG Total,
    _In_ ULONG Value)
{
    if (*Total > (SYSMON_MAX_ULONG_VALUE - Value)) {
        return ERROR_ARITHMETIC_OVERFLOW;
    }

    *Total += Value;
    return SYSMON_SUCCESS;
}

static SYSMON_STATUS
SysmonRuleMultiplyUlong(
    _In_ ULONG Left,
    _In_ ULONG Right,
    _Out_ PULONG Result)
{
    ULONGLONG value;

    if (Result == NULL) {
        return SYSMON_ERROR_INVALID_PARAM;
    }

    value = ((ULONGLONG)Left) * ((ULONGLONG)Right);
    if (value > SYSMON_MAX_ULONG_VALUE) {
        return ERROR_ARITHMETIC_OVERFLOW;
    }

    *Result = (ULONG)value;
    return SYSMON_SUCCESS;
}

static ULONG
SysmonRuleMeasureStringBytes(
    _In_opt_ LPCWSTR Text)
{
    SIZE_T charCount;
    SIZE_T byteCount;

    if (Text == NULL) {
        return 0;
    }

    charCount = wcslen(Text) + 1;
    byteCount = charCount * sizeof(WCHAR);
    if (byteCount > SYSMON_MAX_ULONG_VALUE) {
        return SYSMON_MAX_ULONG_VALUE;
    }

    return (ULONG)byteCount;
}

static SYSMON_STATUS
SysmonRuleCountSet(
    _In_ const SYSMON_RULE_SET *RuleSet,
    _Out_ PSYSMON_RULE_BLOB_COUNTS Counts)
{
    ULONG groupIndex;

    ZeroMemory(Counts, sizeof(*Counts));

    if (RuleSet == NULL) {
        return SYSMON_ERROR_INVALID_PARAM;
    }

    Counts->GroupCount = RuleSet->GroupCount;

    for (groupIndex = 0; groupIndex < RuleSet->GroupCount; groupIndex++) {
        const SYSMON_RULE_GROUP *group = &RuleSet->Groups[groupIndex];
        ULONG eventIndex;
        SYSMON_STATUS status;

        status = SysmonRuleAddUlong(&Counts->StringBytes, SysmonRuleMeasureStringBytes(group->Name));
        if (status != SYSMON_SUCCESS) {
            return status;
        }

        status = SysmonRuleAddUlong(&Counts->EventRuleCount, group->EventRuleCount);
        if (status != SYSMON_SUCCESS) {
            return status;
        }

        for (eventIndex = 0; eventIndex < group->EventRuleCount; eventIndex++) {
            const SYSMON_EVENT_RULE *eventRule = &group->EventRules[eventIndex];
            ULONG ruleIndex;

            status = SysmonRuleAddUlong(&Counts->RuleCount, eventRule->RuleCount);
            if (status != SYSMON_SUCCESS) {
                return status;
            }

            for (ruleIndex = 0; ruleIndex < eventRule->RuleCount; ruleIndex++) {
                const SYSMON_RULE *rule = &eventRule->Rules[ruleIndex];
                ULONG expressionIndex;

                status = SysmonRuleAddUlong(&Counts->StringBytes, SysmonRuleMeasureStringBytes(rule->Name));
                if (status != SYSMON_SUCCESS) {
                    return status;
                }

                status = SysmonRuleAddUlong(&Counts->ExpressionCount, rule->ExpressionCount);
                if (status != SYSMON_SUCCESS) {
                    return status;
                }

                for (expressionIndex = 0; expressionIndex < rule->ExpressionCount; expressionIndex++) {
                    const SYSMON_RULE_EXPRESSION *expression = &rule->Expressions[expressionIndex];

                    status = SysmonRuleAddUlong(&Counts->StringBytes, SysmonRuleMeasureStringBytes(expression->FieldName));
                    if (status != SYSMON_SUCCESS) {
                        return status;
                    }

                    status = SysmonRuleAddUlong(&Counts->StringBytes, SysmonRuleMeasureStringBytes(expression->Value));
                    if (status != SYSMON_SUCCESS) {
                        return status;
                    }
                }
            }
        }
    }

    return SYSMON_SUCCESS;
}

static SYSMON_STATUS
SysmonRuleBlobWriteString(
    _Inout_ PSYSMON_RULE_BLOB_WRITER Writer,
    _In_opt_ LPCWSTR Text,
    _Out_ PULONG Offset)
{
    ULONG byteCount;

    if (Text == NULL) {
        *Offset = SYSMON_RULES_BLOB_OFFSET_NONE;
        return SYSMON_SUCCESS;
    }

    byteCount = SysmonRuleMeasureStringBytes(Text);
    if (byteCount == SYSMON_MAX_ULONG_VALUE) {
        return ERROR_ARITHMETIC_OVERFLOW;
    }

    if (Writer->NextStringOffset > Writer->TotalSize ||
        byteCount > (Writer->TotalSize - Writer->NextStringOffset)) {
        return ERROR_INVALID_DATA;
    }

    memcpy(Writer->Blob + Writer->NextStringOffset, Text, byteCount);
    *Offset = Writer->NextStringOffset;
    Writer->NextStringOffset += byteCount;
    return SYSMON_SUCCESS;
}

static SYSMON_STATUS
SysmonValidateRuleBlobHeader(
    _In_reads_bytes_(BlobSize) const BYTE *Blob,
    _In_ DWORD BlobSize,
    _Out_opt_ const SYSMON_RULES_BLOB_HEADER **HeaderOut)
{
    const SYSMON_RULES_BLOB_HEADER *header;
    ULONG groupBytes;
    ULONG eventRuleBytes;
    ULONG ruleBytes;
    ULONG expressionBytes;
    ULONG expectedEventRuleOffset;
    ULONG expectedRuleOffset;
    ULONG expectedExpressionOffset;
    ULONG expectedStringOffset;
    ULONG expectedTotalSize;
    SYSMON_STATUS status;

    if (Blob == NULL || BlobSize < sizeof(SYSMON_RULES_BLOB_HEADER)) {
        return ERROR_INVALID_DATA;
    }

    header = (const SYSMON_RULES_BLOB_HEADER *)Blob;
    if (header->Signature != SYSMON_RULES_BLOB_SIGNATURE) {
        return ERROR_INVALID_DATA;
    }

    if (header->TotalSize < sizeof(SYSMON_RULES_BLOB_HEADER) ||
        header->TotalSize > BlobSize) {
        return ERROR_INVALID_DATA;
    }

    if (header->GroupOffset < sizeof(SYSMON_RULES_BLOB_HEADER) ||
        header->EventRuleOffset < header->GroupOffset ||
        header->RuleOffset < header->EventRuleOffset ||
        header->ExpressionOffset < header->RuleOffset ||
        header->StringOffset < header->ExpressionOffset ||
        header->StringOffset > header->TotalSize) {
        return ERROR_INVALID_DATA;
    }

    status = SysmonRuleMultiplyUlong(header->GroupCount, sizeof(SYSMON_RULES_BLOB_GROUP), &groupBytes);
    if (status != SYSMON_SUCCESS) {
        return ERROR_INVALID_DATA;
    }

    status = SysmonRuleMultiplyUlong(header->EventRuleCount, sizeof(SYSMON_RULES_BLOB_EVENT_RULE), &eventRuleBytes);
    if (status != SYSMON_SUCCESS) {
        return ERROR_INVALID_DATA;
    }

    status = SysmonRuleMultiplyUlong(header->RuleCount, sizeof(SYSMON_RULES_BLOB_RULE), &ruleBytes);
    if (status != SYSMON_SUCCESS) {
        return ERROR_INVALID_DATA;
    }

    status = SysmonRuleMultiplyUlong(header->ExpressionCount, sizeof(SYSMON_RULES_BLOB_EXPRESSION), &expressionBytes);
    if (status != SYSMON_SUCCESS) {
        return ERROR_INVALID_DATA;
    }

    expectedEventRuleOffset = header->GroupOffset;
    status = SysmonRuleAddUlong(&expectedEventRuleOffset, groupBytes);
    if (status != SYSMON_SUCCESS || expectedEventRuleOffset != header->EventRuleOffset) {
        return ERROR_INVALID_DATA;
    }

    expectedRuleOffset = header->EventRuleOffset;
    status = SysmonRuleAddUlong(&expectedRuleOffset, eventRuleBytes);
    if (status != SYSMON_SUCCESS || expectedRuleOffset != header->RuleOffset) {
        return ERROR_INVALID_DATA;
    }

    expectedExpressionOffset = header->RuleOffset;
    status = SysmonRuleAddUlong(&expectedExpressionOffset, ruleBytes);
    if (status != SYSMON_SUCCESS || expectedExpressionOffset != header->ExpressionOffset) {
        return ERROR_INVALID_DATA;
    }

    expectedStringOffset = header->ExpressionOffset;
    status = SysmonRuleAddUlong(&expectedStringOffset, expressionBytes);
    if (status != SYSMON_SUCCESS || expectedStringOffset != header->StringOffset) {
        return ERROR_INVALID_DATA;
    }

    expectedTotalSize = header->StringOffset;
    status = SysmonRuleAddUlong(&expectedTotalSize, header->StringBytes);
    if (status != SYSMON_SUCCESS || expectedTotalSize != header->TotalSize) {
        return ERROR_INVALID_DATA;
    }

    if (header->StringBytes != (header->TotalSize - header->StringOffset)) {
        return ERROR_INVALID_DATA;
    }

    if (HeaderOut != NULL) {
        *HeaderOut = header;
    }

    return SYSMON_SUCCESS;
}

static BOOL
SysmonRuleParseNameValue(
    _In_ LPCWSTR Text,
    _In_reads_(EntryCount) const SYSMON_RULE_NAME_ENTRY *Entries,
    _In_ DWORD EntryCount,
    _Out_ PDWORD Value)
{
    DWORD index;

    if (Text == NULL || Value == NULL) {
        return FALSE;
    }

    for (index = 0; index < EntryCount; index++) {
        if (_wcsicmp(Text, Entries[index].Name) == 0) {
            *Value = Entries[index].Value;
            return TRUE;
        }
    }

    return FALSE;
}

BOOL
SysmonRuleParseCondition(
    LPCWSTR Text,
    PSYSMON_RULE_CONDITION Condition)
{
    DWORD value;

    if (Condition == NULL) {
        return FALSE;
    }

    *Condition = SysmonRuleConditionInvalid;

    if (!SysmonRuleParseNameValue(
            Text,
            g_SysmonConditionNames,
            (DWORD)_countof(g_SysmonConditionNames),
            &value)) {
        return FALSE;
    }

    *Condition = (SYSMON_RULE_CONDITION)value;
    return TRUE;
}

BOOL
SysmonRuleParseRelation(
    LPCWSTR Text,
    PSYSMON_RULE_RELATION Relation)
{
    DWORD value;

    if (Relation == NULL) {
        return FALSE;
    }

    *Relation = SysmonRuleRelationInvalid;

    if (!SysmonRuleParseNameValue(
            Text,
            g_SysmonRelationNames,
            (DWORD)_countof(g_SysmonRelationNames),
            &value)) {
        return FALSE;
    }

    *Relation = (SYSMON_RULE_RELATION)value;
    return TRUE;
}

SYSMON_STATUS
SysmonSerializeRules(
    const SYSMON_RULE_SET *RuleSet,
    PBYTE *Blob,
    PDWORD BlobSize)
{
    SYSMON_RULE_BLOB_COUNTS counts;
    SYSMON_RULE_BLOB_WRITER writer;
    SYSMON_RULES_BLOB_HEADER *header;
    ULONG totalSize;
    ULONG groupBytes;
    ULONG eventRuleBytes;
    ULONG ruleBytes;
    ULONG expressionBytes;
    ULONG groupIndex;
    SYSMON_STATUS status;

    if (RuleSet == NULL || Blob == NULL || BlobSize == NULL) {
        return SYSMON_ERROR_INVALID_PARAM;
    }

    *Blob = NULL;
    *BlobSize = 0;

    status = SysmonRuleCountSet(RuleSet, &counts);
    if (status != SYSMON_SUCCESS) {
        return status;
    }

    status = SysmonRuleMultiplyUlong(counts.GroupCount, sizeof(SYSMON_RULES_BLOB_GROUP), &groupBytes);
    if (status != SYSMON_SUCCESS) {
        return status;
    }

    status = SysmonRuleMultiplyUlong(counts.EventRuleCount, sizeof(SYSMON_RULES_BLOB_EVENT_RULE), &eventRuleBytes);
    if (status != SYSMON_SUCCESS) {
        return status;
    }

    status = SysmonRuleMultiplyUlong(counts.RuleCount, sizeof(SYSMON_RULES_BLOB_RULE), &ruleBytes);
    if (status != SYSMON_SUCCESS) {
        return status;
    }

    status = SysmonRuleMultiplyUlong(counts.ExpressionCount, sizeof(SYSMON_RULES_BLOB_EXPRESSION), &expressionBytes);
    if (status != SYSMON_SUCCESS) {
        return status;
    }

    totalSize = sizeof(SYSMON_RULES_BLOB_HEADER);
    status = SysmonRuleAddUlong(&totalSize, groupBytes);
    if (status != SYSMON_SUCCESS) {
        return status;
    }

    status = SysmonRuleAddUlong(&totalSize, eventRuleBytes);
    if (status != SYSMON_SUCCESS) {
        return status;
    }

    status = SysmonRuleAddUlong(&totalSize, ruleBytes);
    if (status != SYSMON_SUCCESS) {
        return status;
    }

    status = SysmonRuleAddUlong(&totalSize, expressionBytes);
    if (status != SYSMON_SUCCESS) {
        return status;
    }

    status = SysmonRuleAddUlong(&totalSize, counts.StringBytes);
    if (status != SYSMON_SUCCESS) {
        return status;
    }

    *Blob = (PBYTE)SYSMON_ALLOC(totalSize);
    if (*Blob == NULL) {
        return SYSMON_ERROR_OUT_OF_MEMORY;
    }

    ZeroMemory(*Blob, totalSize);
    *BlobSize = totalSize;

    header = (SYSMON_RULES_BLOB_HEADER *)(*Blob);
    header->Signature = SYSMON_RULES_BLOB_SIGNATURE;
    header->MajorVersion = SYSMON_RULES_BLOB_MAJOR_VERSION;
    header->MinorVersion = SYSMON_RULES_BLOB_MINOR_VERSION;
    header->TotalSize = totalSize;
    header->GroupCount = counts.GroupCount;
    header->EventRuleCount = counts.EventRuleCount;
    header->RuleCount = counts.RuleCount;
    header->ExpressionCount = counts.ExpressionCount;
    header->StringBytes = counts.StringBytes;
    header->GroupOffset = sizeof(SYSMON_RULES_BLOB_HEADER);
    header->EventRuleOffset = header->GroupOffset;
    status = SysmonRuleAddUlong(&header->EventRuleOffset, groupBytes);
    if (status != SYSMON_SUCCESS) {
        goto cleanup;
    }

    header->RuleOffset = header->EventRuleOffset;
    status = SysmonRuleAddUlong(&header->RuleOffset, eventRuleBytes);
    if (status != SYSMON_SUCCESS) {
        goto cleanup;
    }

    header->ExpressionOffset = header->RuleOffset;
    status = SysmonRuleAddUlong(&header->ExpressionOffset, ruleBytes);
    if (status != SYSMON_SUCCESS) {
        goto cleanup;
    }

    header->StringOffset = header->ExpressionOffset;
    status = SysmonRuleAddUlong(&header->StringOffset, expressionBytes);
    if (status != SYSMON_SUCCESS) {
        goto cleanup;
    }

    ZeroMemory(&writer, sizeof(writer));
    writer.Blob = *Blob;
    writer.TotalSize = totalSize;
    writer.NextStringOffset = header->StringOffset;
    writer.Groups = (PSYSMON_RULES_BLOB_GROUP)(*Blob + header->GroupOffset);
    writer.EventRules = (PSYSMON_RULES_BLOB_EVENT_RULE)(*Blob + header->EventRuleOffset);
    writer.Rules = (PSYSMON_RULES_BLOB_RULE)(*Blob + header->RuleOffset);
    writer.Expressions = (PSYSMON_RULES_BLOB_EXPRESSION)(*Blob + header->ExpressionOffset);

    for (groupIndex = 0; groupIndex < RuleSet->GroupCount; groupIndex++) {
        const SYSMON_RULE_GROUP *group = &RuleSet->Groups[groupIndex];
        PSYSMON_RULES_BLOB_GROUP groupBlob = &writer.Groups[writer.NextGroupIndex++];
        ULONG eventIndex;

        status = SysmonRuleBlobWriteString(&writer, group->Name, &groupBlob->NameOffset);
        if (status != SYSMON_SUCCESS) {
            goto cleanup;
        }

        groupBlob->Relation = group->Relation;
        groupBlob->EventRuleStart = writer.NextEventRuleIndex;
        groupBlob->EventRuleCount = group->EventRuleCount;

        for (eventIndex = 0; eventIndex < group->EventRuleCount; eventIndex++) {
            const SYSMON_EVENT_RULE *eventRule = &group->EventRules[eventIndex];
            PSYSMON_RULES_BLOB_EVENT_RULE eventBlob = &writer.EventRules[writer.NextEventRuleIndex++];
            ULONG ruleIndex;

            eventBlob->EventId = eventRule->EventId;
            eventBlob->MatchType = eventRule->MatchType;
            eventBlob->Relation = eventRule->Relation;
            eventBlob->RuleStart = writer.NextRuleIndex;
            eventBlob->RuleCount = eventRule->RuleCount;

            for (ruleIndex = 0; ruleIndex < eventRule->RuleCount; ruleIndex++) {
                const SYSMON_RULE *rule = &eventRule->Rules[ruleIndex];
                PSYSMON_RULES_BLOB_RULE ruleBlob = &writer.Rules[writer.NextRuleIndex++];
                ULONG expressionIndex;

                status = SysmonRuleBlobWriteString(&writer, rule->Name, &ruleBlob->NameOffset);
                if (status != SYSMON_SUCCESS) {
                    goto cleanup;
                }

                ruleBlob->Relation = rule->Relation;
                ruleBlob->ExpressionStart = writer.NextExpressionIndex;
                ruleBlob->ExpressionCount = rule->ExpressionCount;

                for (expressionIndex = 0; expressionIndex < rule->ExpressionCount; expressionIndex++) {
                    const SYSMON_RULE_EXPRESSION *expression = &rule->Expressions[expressionIndex];
                    PSYSMON_RULES_BLOB_EXPRESSION expressionBlob = &writer.Expressions[writer.NextExpressionIndex++];

                    status = SysmonRuleBlobWriteString(&writer, expression->FieldName, &expressionBlob->FieldNameOffset);
                    if (status != SYSMON_SUCCESS) {
                        goto cleanup;
                    }

                    status = SysmonRuleBlobWriteString(&writer, expression->Value, &expressionBlob->ValueOffset);
                    if (status != SYSMON_SUCCESS) {
                        goto cleanup;
                    }

                    expressionBlob->Condition = expression->Condition;
                }
            }
        }
    }

    if (writer.NextStringOffset != totalSize) {
        status = ERROR_INVALID_DATA;
        goto cleanup;
    }

    return SYSMON_SUCCESS;

cleanup:
    SYSMON_FREE(*Blob);
    *Blob = NULL;
    *BlobSize = 0;
    return status;
}

SYSMON_STATUS
SysmonQueryRuleBlobInfo(
    const BYTE *Blob,
    DWORD BlobSize,
    PSYSMON_RULES_BLOB_INFO BlobInfo)
{
    const SYSMON_RULES_BLOB_HEADER *header;
    SYSMON_STATUS status;

    if (BlobInfo == NULL) {
        return SYSMON_ERROR_INVALID_PARAM;
    }

    ZeroMemory(BlobInfo, sizeof(*BlobInfo));

    status = SysmonValidateRuleBlobHeader(Blob, BlobSize, &header);
    if (status != SYSMON_SUCCESS) {
        return status;
    }

    BlobInfo->MajorVersion = header->MajorVersion;
    BlobInfo->MinorVersion = header->MinorVersion;
    BlobInfo->TotalSize = header->TotalSize;
    BlobInfo->GroupCount = header->GroupCount;
    BlobInfo->EventRuleCount = header->EventRuleCount;
    BlobInfo->RuleCount = header->RuleCount;
    BlobInfo->ExpressionCount = header->ExpressionCount;
    BlobInfo->StringBytes = header->StringBytes;
    return SYSMON_SUCCESS;
}

static SYSMON_STATUS
SysmonValidateStringOffset(
    _In_ const SYSMON_RULES_BLOB_HEADER *Header,
    _In_reads_bytes_(BlobSize) const BYTE *Blob,
    _In_ DWORD BlobSize,
    _In_ ULONG Offset)
{
    ULONG stringStart;
    ULONG stringEnd;
    ULONG currentOffset;

    UNREFERENCED_PARAMETER(BlobSize);

    if (Header == NULL || Blob == NULL) {
        return SYSMON_ERROR_INVALID_PARAM;
    }

    if (Offset == SYSMON_RULES_BLOB_OFFSET_NONE) {
        return SYSMON_SUCCESS;
    }

    stringStart = Header->StringOffset;
    stringEnd = Header->TotalSize;
    if (Offset < stringStart || Offset >= stringEnd) {
        return ERROR_INVALID_DATA;
    }

    currentOffset = Offset;
    while (currentOffset + sizeof(WCHAR) <= stringEnd) {
        if (*(const WCHAR *)(Blob + currentOffset) == L'\0') {
            return SYSMON_SUCCESS;
        }

        currentOffset += sizeof(WCHAR);
    }

    return ERROR_INVALID_DATA;
}

static SYSMON_STATUS
SysmonValidateRuleBlob(
    _In_reads_bytes_(BlobSize) const BYTE *Blob,
    _In_ DWORD BlobSize,
    _Out_ PSYSMON_RULE_BLOB_LAYOUT Layout)
{
    const SYSMON_RULES_BLOB_HEADER *header;
    ULONG groupBytes;
    ULONG eventRuleBytes;
    ULONG ruleBytes;
    ULONG expressionBytes;
    ULONG expectedOffset;
    ULONG groupIndex;
    ULONG eventRuleIndex;
    ULONG ruleIndex;
    ULONG expressionIndex;
    SYSMON_STATUS status;

    if (Blob == NULL || Layout == NULL || BlobSize < sizeof(SYSMON_RULES_BLOB_HEADER)) {
        return SYSMON_ERROR_INVALID_PARAM;
    }

    ZeroMemory(Layout, sizeof(*Layout));

    status = SysmonValidateRuleBlobHeader(Blob, BlobSize, &header);
    if (status != SYSMON_SUCCESS) {
        return status;
    }

    if (header->MajorVersion != SYSMON_RULES_BLOB_MAJOR_VERSION) {
        return ERROR_REVISION_MISMATCH;
    }

    status = SysmonRuleMultiplyUlong(header->GroupCount, sizeof(SYSMON_RULES_BLOB_GROUP), &groupBytes);
    if (status != SYSMON_SUCCESS) {
        return ERROR_INVALID_DATA;
    }

    status = SysmonRuleMultiplyUlong(header->EventRuleCount, sizeof(SYSMON_RULES_BLOB_EVENT_RULE), &eventRuleBytes);
    if (status != SYSMON_SUCCESS) {
        return ERROR_INVALID_DATA;
    }

    status = SysmonRuleMultiplyUlong(header->RuleCount, sizeof(SYSMON_RULES_BLOB_RULE), &ruleBytes);
    if (status != SYSMON_SUCCESS) {
        return ERROR_INVALID_DATA;
    }

    status = SysmonRuleMultiplyUlong(header->ExpressionCount, sizeof(SYSMON_RULES_BLOB_EXPRESSION), &expressionBytes);
    if (status != SYSMON_SUCCESS) {
        return ERROR_INVALID_DATA;
    }

    expectedOffset = header->GroupOffset;
    status = SysmonRuleAddUlong(&expectedOffset, groupBytes);
    if (status != SYSMON_SUCCESS || expectedOffset != header->EventRuleOffset) {
        return ERROR_INVALID_DATA;
    }

    expectedOffset = header->EventRuleOffset;
    status = SysmonRuleAddUlong(&expectedOffset, eventRuleBytes);
    if (status != SYSMON_SUCCESS || expectedOffset != header->RuleOffset) {
        return ERROR_INVALID_DATA;
    }

    expectedOffset = header->RuleOffset;
    status = SysmonRuleAddUlong(&expectedOffset, ruleBytes);
    if (status != SYSMON_SUCCESS || expectedOffset != header->ExpressionOffset) {
        return ERROR_INVALID_DATA;
    }

    expectedOffset = header->ExpressionOffset;
    status = SysmonRuleAddUlong(&expectedOffset, expressionBytes);
    if (status != SYSMON_SUCCESS || expectedOffset != header->StringOffset) {
        return ERROR_INVALID_DATA;
    }

    Layout->Header = header;
    Layout->Groups = (const SYSMON_RULES_BLOB_GROUP *)(Blob + header->GroupOffset);
    Layout->EventRules = (const SYSMON_RULES_BLOB_EVENT_RULE *)(Blob + header->EventRuleOffset);
    Layout->Rules = (const SYSMON_RULES_BLOB_RULE *)(Blob + header->RuleOffset);
    Layout->Expressions = (const SYSMON_RULES_BLOB_EXPRESSION *)(Blob + header->ExpressionOffset);
    Layout->StringTable = (const WCHAR *)(Blob + header->StringOffset);

    for (groupIndex = 0; groupIndex < header->GroupCount; groupIndex++) {
        const SYSMON_RULES_BLOB_GROUP *group = &Layout->Groups[groupIndex];

        if (group->Relation <= SysmonRuleRelationInvalid ||
            group->Relation > SysmonRuleRelationAnd ||
            group->EventRuleStart > header->EventRuleCount ||
            group->EventRuleCount > (header->EventRuleCount - group->EventRuleStart)) {
            return ERROR_INVALID_DATA;
        }

        status = SysmonValidateStringOffset(header, Blob, BlobSize, group->NameOffset);
        if (status != SYSMON_SUCCESS) {
            return status;
        }
    }

    for (eventRuleIndex = 0; eventRuleIndex < header->EventRuleCount; eventRuleIndex++) {
        const SYSMON_RULES_BLOB_EVENT_RULE *eventRule = &Layout->EventRules[eventRuleIndex];

        if (eventRule->MatchType <= SysmonRuleMatchTypeInvalid ||
            eventRule->MatchType > SysmonRuleMatchTypeExclude ||
            eventRule->Relation <= SysmonRuleRelationInvalid ||
            eventRule->Relation > SysmonRuleRelationAnd ||
            eventRule->RuleStart > header->RuleCount ||
            eventRule->RuleCount > (header->RuleCount - eventRule->RuleStart)) {
            return ERROR_INVALID_DATA;
        }
    }

    for (ruleIndex = 0; ruleIndex < header->RuleCount; ruleIndex++) {
        const SYSMON_RULES_BLOB_RULE *rule = &Layout->Rules[ruleIndex];

        if (rule->Relation <= SysmonRuleRelationInvalid ||
            rule->Relation > SysmonRuleRelationAnd ||
            rule->ExpressionStart > header->ExpressionCount ||
            rule->ExpressionCount > (header->ExpressionCount - rule->ExpressionStart)) {
            return ERROR_INVALID_DATA;
        }

        status = SysmonValidateStringOffset(header, Blob, BlobSize, rule->NameOffset);
        if (status != SYSMON_SUCCESS) {
            return status;
        }
    }

    for (expressionIndex = 0; expressionIndex < header->ExpressionCount; expressionIndex++) {
        const SYSMON_RULES_BLOB_EXPRESSION *expression = &Layout->Expressions[expressionIndex];

        if (expression->Condition <= SysmonRuleConditionInvalid ||
            expression->Condition > SysmonRuleConditionIsAny) {
            return ERROR_INVALID_DATA;
        }

        status = SysmonValidateStringOffset(header, Blob, BlobSize, expression->FieldNameOffset);
        if (status != SYSMON_SUCCESS) {
            return status;
        }

        status = SysmonValidateStringOffset(header, Blob, BlobSize, expression->ValueOffset);
        if (status != SYSMON_SUCCESS) {
            return status;
        }
    }

    return SYSMON_SUCCESS;
}

SYSMON_STATUS
SysmonLoadRuleRuntime(
    const BYTE *Blob,
    DWORD BlobSize,
    PSYSMON_RULE_RUNTIME *Runtime)
{
    SYSMON_RULE_BLOB_LAYOUT layout;
    PSYSMON_RULE_RUNTIME runtime;

    if (Runtime == NULL) {
        return SYSMON_ERROR_INVALID_PARAM;
    }

    *Runtime = NULL;

    if (Blob == NULL || BlobSize == 0) {
        return SYSMON_SUCCESS;
    }

    if (SysmonValidateRuleBlob(Blob, BlobSize, &layout) != SYSMON_SUCCESS) {
        return ERROR_INVALID_DATA;
    }

    runtime = (PSYSMON_RULE_RUNTIME)SYSMON_ALLOC(sizeof(*runtime));
    if (runtime == NULL) {
        return SYSMON_ERROR_OUT_OF_MEMORY;
    }

    ZeroMemory(runtime, sizeof(*runtime));
    runtime->BlobStorage = (PBYTE)SYSMON_ALLOC(layout.Header->TotalSize);
    if (runtime->BlobStorage == NULL) {
        SYSMON_FREE(runtime);
        return SYSMON_ERROR_OUT_OF_MEMORY;
    }

    CopyMemory(runtime->BlobStorage, Blob, layout.Header->TotalSize);
    runtime->BlobSize = layout.Header->TotalSize;
    runtime->Header = (const SYSMON_RULES_BLOB_HEADER *)runtime->BlobStorage;
    runtime->Groups = (const SYSMON_RULES_BLOB_GROUP *)(runtime->BlobStorage + runtime->Header->GroupOffset);
    runtime->EventRules = (const SYSMON_RULES_BLOB_EVENT_RULE *)(runtime->BlobStorage + runtime->Header->EventRuleOffset);
    runtime->Rules = (const SYSMON_RULES_BLOB_RULE *)(runtime->BlobStorage + runtime->Header->RuleOffset);
    runtime->Expressions = (const SYSMON_RULES_BLOB_EXPRESSION *)(runtime->BlobStorage + runtime->Header->ExpressionOffset);
    runtime->StringTable = (const WCHAR *)(runtime->BlobStorage + runtime->Header->StringOffset);

    *Runtime = runtime;
    return SYSMON_SUCCESS;
}

void
SysmonFreeRuleRuntime(
    PSYSMON_RULE_RUNTIME Runtime)
{
    if (Runtime == NULL) {
        return;
    }

    SYSMON_FREE(Runtime->BlobStorage);
    SYSMON_FREE(Runtime);
}

BOOL
SysmonRuleRuntimeHasEvent(
    PSYSMON_RULE_RUNTIME Runtime,
    SYSMON_EVENT_ID EventId)
{
    DWORD eventRuleIndex;

    if (Runtime == NULL || Runtime->Header == NULL) {
        return FALSE;
    }

    for (eventRuleIndex = 0; eventRuleIndex < Runtime->Header->EventRuleCount; eventRuleIndex++) {
        if (Runtime->EventRules[eventRuleIndex].EventId == (ULONG)EventId) {
            return TRUE;
        }
    }

    return FALSE;
}

BOOL
SysmonRuleRuntimeEventCanProduceLogs(
    _In_opt_ PSYSMON_RULE_RUNTIME Runtime,
    _In_ SYSMON_EVENT_ID EventId)
{
    DWORD eventRuleIndex;
    BOOL hasInclude = FALSE;
    BOOL hasNonEmptyInclude = FALSE;
    BOOL hasRuleForEvent = FALSE;

    if (Runtime == NULL || Runtime->Header == NULL) {
        return FALSE;
    }

    for (eventRuleIndex = 0; eventRuleIndex < Runtime->Header->EventRuleCount; eventRuleIndex++) {
        const SYSMON_RULES_BLOB_EVENT_RULE *eventRule = &Runtime->EventRules[eventRuleIndex];

        if (eventRule->EventId != (ULONG)EventId) {
            continue;
        }

        hasRuleForEvent = TRUE;
        if (eventRule->MatchType == SysmonRuleMatchTypeInclude) {
            hasInclude = TRUE;
            if (eventRule->RuleCount != 0) {
                hasNonEmptyInclude = TRUE;
            }
        }
    }

    if (!hasRuleForEvent) {
        return FALSE;
    }

    return hasInclude ? hasNonEmptyInclude : TRUE;
}

BOOL
SysmonRuleRuntimeHasAnyEvent(
    PSYSMON_RULE_RUNTIME Runtime,
    const SYSMON_EVENT_ID *EventIds,
    DWORD EventIdCount)
{
    DWORD index;

    if (EventIds == NULL || EventIdCount == 0) {
        return FALSE;
    }

    for (index = 0; index < EventIdCount; index++) {
        if (SysmonRuleRuntimeHasEvent(Runtime, EventIds[index])) {
            return TRUE;
        }
    }

    return FALSE;
}

BOOL
SysmonRuleRuntimeEventHasIncludeRules(
    PSYSMON_RULE_RUNTIME Runtime,
    SYSMON_EVENT_ID EventId)
{
    DWORD eventRuleIndex;

    if (Runtime == NULL || Runtime->Header == NULL) {
        return FALSE;
    }

    for (eventRuleIndex = 0; eventRuleIndex < Runtime->Header->EventRuleCount; eventRuleIndex++) {
        if (Runtime->EventRules[eventRuleIndex].EventId == (ULONG)EventId &&
            Runtime->EventRules[eventRuleIndex].MatchType == SysmonRuleMatchTypeInclude) {
            return TRUE;
        }
    }

    return FALSE;
}

static BOOL
SysmonIsWhitespace(
    _In_ WCHAR Character)
{
    return Character == L' ' ||
        Character == L'\t' ||
        Character == L'\r' ||
        Character == L'\n';
}

static void
SysmonTrimSpan(
    _In_reads_(Length) PCWSTR Text,
    _Inout_ size_t *Start,
    _Inout_ size_t *Length)
{
    size_t start;
    size_t length;

    if (Text == NULL || Start == NULL || Length == NULL) {
        return;
    }

    start = *Start;
    length = *Length;

    while (length != 0 && SysmonIsWhitespace(Text[start])) {
        start++;
        length--;
    }

    while (length != 0 && SysmonIsWhitespace(Text[start + length - 1])) {
        length--;
    }

    *Start = start;
    *Length = length;
}

static BOOL
SysmonEqualsInsensitive(
    _In_ PCWSTR Left,
    _In_ PCWSTR Right)
{
    return Left != NULL &&
        Right != NULL &&
        _wcsicmp(Left, Right) == 0;
}

static BOOL
SysmonContainsInsensitive(
    _In_ PCWSTR Haystack,
    _In_ PCWSTR Needle)
{
    size_t haystackLength;
    size_t needleLength;
    size_t index;

    if (Haystack == NULL || Needle == NULL) {
        return FALSE;
    }

    haystackLength = wcslen(Haystack);
    needleLength = wcslen(Needle);

    if (needleLength == 0) {
        return TRUE;
    }

    if (needleLength > haystackLength) {
        return FALSE;
    }

    for (index = 0; index <= haystackLength - needleLength; index++) {
        if (_wcsnicmp(Haystack + index, Needle, needleLength) == 0) {
            return TRUE;
        }
    }

    return FALSE;
}

static BOOL
SysmonMatchExactAnyToken(
    _In_ PCWSTR FieldValue,
    _In_ PCWSTR RuleValue)
{
    size_t start;
    size_t length;
    size_t totalLength;

    if (FieldValue == NULL || RuleValue == NULL) {
        return FALSE;
    }

    totalLength = wcslen(RuleValue);
    if (totalLength > 0xFFFFu) {
        return FALSE;
    }
    start = 0;

    while (start <= totalLength) {
        size_t tokenStart = start;

        while (start < totalLength && RuleValue[start] != L';') {
            start++;
        }

        length = start - tokenStart;
        SysmonTrimSpan(RuleValue, &tokenStart, &length);
        if (length != 0) {
            WCHAR stackBuffer[260];
            PWCHAR token = stackBuffer;

            if (length < _countof(stackBuffer)) {
                CopyMemory(stackBuffer, RuleValue + tokenStart, length * sizeof(WCHAR));
                stackBuffer[length] = L'\0';
            } else {
                /* Token longer than the stack buffer: compare at full length via
                   a heap copy (rare), instead of truncating or skipping, which
                   would change the matching semantics (P2 in the review). */
                token = (PWCHAR)SYSMON_ALLOC((length + 1) * sizeof(WCHAR));
                if (token != NULL) {
                    CopyMemory(token, RuleValue + tokenStart, length * sizeof(WCHAR));
                    token[length] = L'\0';
                }
            }

            if (token != NULL) {
                BOOL matched = SysmonEqualsInsensitive(FieldValue, token);

                if (token != stackBuffer) {
                    SYSMON_FREE(token);
                }
                if (matched) {
                    return TRUE;
                }
            }
        }

        if (start == totalLength) {
            break;
        }

        start++;
    }

    return FALSE;
}

static BOOL
SysmonMatchAnyToken(
    _In_ PCWSTR FieldValue,
    _In_ PCWSTR RuleValue,
    _In_ BOOL RequireAll,
    _In_ BOOL InvertMatch)
{
    size_t start;
    size_t length;
    size_t totalLength;
    BOOL sawToken;
    BOOL matchedAny;

    if (FieldValue == NULL || RuleValue == NULL) {
        return FALSE;
    }

    totalLength = wcslen(RuleValue);
    if (totalLength > 0xFFFFu) {
        return FALSE;
    }
    start = 0;
    sawToken = FALSE;
    matchedAny = FALSE;

    while (start <= totalLength) {
        size_t tokenStart = start;
        BOOL contains;

        while (start < totalLength && RuleValue[start] != L';') {
            start++;
        }

        length = start - tokenStart;
        SysmonTrimSpan(RuleValue, &tokenStart, &length);
        if (length != 0) {
            WCHAR stackBuffer[260];
            PWCHAR token = stackBuffer;

            sawToken = TRUE;

            if (length < _countof(stackBuffer)) {
                CopyMemory(stackBuffer, RuleValue + tokenStart, length * sizeof(WCHAR));
                stackBuffer[length] = L'\0';
            } else {
                /* Token longer than the stack buffer: compare at full length via
                   a heap copy (rare), instead of truncating or skipping, which
                   would change the matching semantics (P2 in the review). */
                token = (PWCHAR)SYSMON_ALLOC((length + 1) * sizeof(WCHAR));
                if (token != NULL) {
                    CopyMemory(token, RuleValue + tokenStart, length * sizeof(WCHAR));
                    token[length] = L'\0';
                }
            }

            if (token != NULL) {
                contains = SysmonContainsInsensitive(FieldValue, token);
                if (token != stackBuffer) {
                    SYSMON_FREE(token);
                }

                if (InvertMatch) {
                    contains = !contains;
                }

                if (RequireAll) {
                    if (!contains) {
                        return FALSE;
                    }
                } else if (contains) {
                    return TRUE;
                }

                matchedAny = matchedAny || contains;
            } else if (RequireAll) {
                /* Heap allocation failed for an over-long token: cannot confirm
                   all tokens match. */
                return FALSE;
            }
        }

        if (start == totalLength) {
            break;
        }

        start++;
    }

    if (!sawToken) {
        return FALSE;
    }

    return RequireAll ? TRUE : matchedAny;
}

static BOOL
SysmonEvaluateRuleCondition(
    _In_ ULONG Condition,
    _In_ PCWSTR FieldValue,
    _In_ PCWSTR RuleValue)
{
    switch (Condition) {
    case SysmonRuleConditionIs:
        return _wcsicmp(FieldValue, RuleValue) == 0;

    case SysmonRuleConditionIsNot:
        return _wcsicmp(FieldValue, RuleValue) != 0;

    case SysmonRuleConditionContains:
        return SysmonContainsInsensitive(FieldValue, RuleValue);

    case SysmonRuleConditionContainsAny:
        return SysmonMatchAnyToken(FieldValue, RuleValue, FALSE, FALSE);

    case SysmonRuleConditionIsAny:
        return SysmonMatchExactAnyToken(FieldValue, RuleValue);

    case SysmonRuleConditionContainsAll:
        return SysmonMatchAnyToken(FieldValue, RuleValue, TRUE, FALSE);

    case SysmonRuleConditionExcludes:
        return !SysmonContainsInsensitive(FieldValue, RuleValue);

    case SysmonRuleConditionExcludesAny:
        return SysmonMatchAnyToken(FieldValue, RuleValue, FALSE, TRUE);

    case SysmonRuleConditionExcludesAll:
        return SysmonMatchAnyToken(FieldValue, RuleValue, TRUE, TRUE);

    case SysmonRuleConditionBeginWith:
        return _wcsnicmp(FieldValue, RuleValue, wcslen(RuleValue)) == 0;

    case SysmonRuleConditionEndWith:
    case SysmonRuleConditionImage:
    {
        size_t fieldLength = wcslen(FieldValue);
        size_t ruleLength = wcslen(RuleValue);

        return ruleLength <= fieldLength &&
            _wcsicmp(FieldValue + (fieldLength - ruleLength), RuleValue) == 0;
    }

    case SysmonRuleConditionNotBeginWith:
        return _wcsnicmp(FieldValue, RuleValue, wcslen(RuleValue)) != 0;

    case SysmonRuleConditionNotEndWith:
    {
        size_t fieldLength = wcslen(FieldValue);
        size_t ruleLength = wcslen(RuleValue);

        return ruleLength > fieldLength ||
            _wcsicmp(FieldValue + (fieldLength - ruleLength), RuleValue) != 0;
    }

    case SysmonRuleConditionLessThan:
        return _wcsicmp(FieldValue, RuleValue) < 0;

    case SysmonRuleConditionMoreThan:
        return _wcsicmp(FieldValue, RuleValue) > 0;
    }

    return FALSE;
}

static LPCWSTR
SysmonGetRuleString(
    _In_ PSYSMON_RULE_RUNTIME Runtime,
    _In_ ULONG Offset)
{
    if (Runtime == NULL || Runtime->BlobStorage == NULL || Offset == SYSMON_RULES_BLOB_OFFSET_NONE) {
        return L"";
    }

    return (LPCWSTR)(Runtime->BlobStorage + Offset);
}

static BOOL
SysmonEvaluateEventExpression(
    _In_ PSYSMON_RULE_RUNTIME Runtime,
    _In_ const SYSMON_RULES_BLOB_EXPRESSION *Expression,
    _In_reads_bytes_(EventSize) const BYTE *EventData,
    _In_ DWORD EventSize,
    _In_ SYSMON_EVENT_ID EventId)
{
    WCHAR fieldValue[2048];
    LPCWSTR fieldName;
    LPCWSTR ruleValue;

    fieldName = SysmonGetRuleString(Runtime, Expression->FieldNameOffset);
    ruleValue = SysmonGetRuleString(Runtime, Expression->ValueOffset);

    if (!SysmonExtractEventField(EventData, EventSize, EventId, fieldName, fieldValue, _countof(fieldValue))) {
        return FALSE;
    }

    return SysmonEvaluateRuleCondition(Expression->Condition, fieldValue, ruleValue);
}

static BOOL
SysmonIsUserModeEnrichedImageField(
    _In_opt_ PCWSTR FieldName);

static BOOL
SysmonIsDriverImageVersionField(
    _In_opt_ PCWSTR FieldName);

typedef enum _SYSMON_PARTIAL_MATCH_RESULT {
    SysmonPartialMatchFalse = 0,
    SysmonPartialMatchTrue = 1,
    SysmonPartialMatchUnknown = 2
} SYSMON_PARTIAL_MATCH_RESULT;

static SYSMON_PARTIAL_MATCH_RESULT
SysmonAccumulatePartialMatch(
    _In_ ULONG Relation,
    _In_ SYSMON_PARTIAL_MATCH_RESULT CurrentValue,
    _In_ SYSMON_PARTIAL_MATCH_RESULT NextValue,
    _In_ BOOL IsFirst)
{
    if (IsFirst) {
        return NextValue;
    }

    if (Relation == SysmonRuleRelationAnd) {
        if (CurrentValue == SysmonPartialMatchFalse ||
            NextValue == SysmonPartialMatchFalse) {
            return SysmonPartialMatchFalse;
        }
        if (CurrentValue == SysmonPartialMatchTrue &&
            NextValue == SysmonPartialMatchTrue) {
            return SysmonPartialMatchTrue;
        }
        return SysmonPartialMatchUnknown;
    }

    if (CurrentValue == SysmonPartialMatchTrue ||
        NextValue == SysmonPartialMatchTrue) {
        return SysmonPartialMatchTrue;
    }
    if (CurrentValue == SysmonPartialMatchFalse &&
        NextValue == SysmonPartialMatchFalse) {
        return SysmonPartialMatchFalse;
    }
    return SysmonPartialMatchUnknown;
}

static SYSMON_PARTIAL_MATCH_RESULT
SysmonEvaluateEventExpressionPartial(
    _In_ PSYSMON_RULE_RUNTIME Runtime,
    _In_ const SYSMON_RULES_BLOB_EXPRESSION *Expression,
    _In_reads_bytes_(EventSize) const BYTE *EventData,
    _In_ DWORD EventSize,
    _In_ SYSMON_EVENT_ID EventId)
{
    WCHAR fieldValue[2048];
    LPCWSTR fieldName;
    LPCWSTR ruleValue;

    fieldName = SysmonGetRuleString(Runtime, Expression->FieldNameOffset);
    ruleValue = SysmonGetRuleString(Runtime, Expression->ValueOffset);

    if ((EventId == SysmonEventImageLoad || EventId == SysmonEventDriverLoad) &&
        (SysmonIsUserModeEnrichedImageField(fieldName) ||
         SysmonIsDriverImageVersionField(fieldName))) {
        return SysmonPartialMatchUnknown;
    }

    if (!SysmonExtractEventField(EventData, EventSize, EventId, fieldName, fieldValue, _countof(fieldValue))) {
        return SysmonPartialMatchFalse;
    }

    return SysmonEvaluateRuleCondition(Expression->Condition, fieldValue, ruleValue)
        ? SysmonPartialMatchTrue
        : SysmonPartialMatchFalse;
}

static BOOL
SysmonEvaluateEventRule(
    _In_ PSYSMON_RULE_RUNTIME Runtime,
    _In_ const SYSMON_RULES_BLOB_RULE *Rule,
    _In_reads_bytes_(EventSize) const BYTE *EventData,
    _In_ DWORD EventSize,
    _In_ SYSMON_EVENT_ID EventId)
{
    DWORD expressionIndex;
    BOOL result;

    if (Rule->ExpressionCount == 0) {
        return TRUE;
    }

    result = (Rule->Relation == SysmonRuleRelationAnd) ? TRUE : FALSE;

    for (expressionIndex = 0; expressionIndex < Rule->ExpressionCount; expressionIndex++) {
        BOOL expressionResult = SysmonEvaluateEventExpression(
            Runtime,
            &Runtime->Expressions[Rule->ExpressionStart + expressionIndex],
            EventData,
            EventSize,
            EventId);

        if (Rule->Relation == SysmonRuleRelationAnd) {
            result = result && expressionResult;
            if (!result) {
                return FALSE;
            }
        } else {
            result = result || expressionResult;
            if (result) {
                return TRUE;
            }
        }
    }

    return result;
}

static SYSMON_PARTIAL_MATCH_RESULT
SysmonEvaluateEventRulePartial(
    _In_ PSYSMON_RULE_RUNTIME Runtime,
    _In_ const SYSMON_RULES_BLOB_RULE *Rule,
    _In_reads_bytes_(EventSize) const BYTE *EventData,
    _In_ DWORD EventSize,
    _In_ SYSMON_EVENT_ID EventId)
{
    DWORD expressionIndex;
    SYSMON_PARTIAL_MATCH_RESULT result;

    if (Rule->ExpressionCount == 0) {
        return SysmonPartialMatchTrue;
    }

    result = (Rule->Relation == SysmonRuleRelationAnd)
        ? SysmonPartialMatchTrue
        : SysmonPartialMatchFalse;

    for (expressionIndex = 0; expressionIndex < Rule->ExpressionCount; expressionIndex++) {
        SYSMON_PARTIAL_MATCH_RESULT expressionResult = SysmonEvaluateEventExpressionPartial(
            Runtime,
            &Runtime->Expressions[Rule->ExpressionStart + expressionIndex],
            EventData,
            EventSize,
            EventId);

        result = SysmonAccumulatePartialMatch(
            Rule->Relation,
            result,
            expressionResult,
            (expressionIndex == 0));

        if ((Rule->Relation == SysmonRuleRelationAnd && result == SysmonPartialMatchFalse) ||
            (Rule->Relation != SysmonRuleRelationAnd && result == SysmonPartialMatchTrue)) {
            break;
        }
    }

    return result;
}

static BOOL
SysmonAccumulateMatch(
    _In_ ULONG Relation,
    _In_ BOOL CurrentValue,
    _In_ BOOL NextValue,
    _In_ BOOL IsFirst)
{
    if (IsFirst) {
        return NextValue;
    }

    if (Relation == SysmonRuleRelationAnd) {
        return CurrentValue && NextValue;
    }

    return CurrentValue || NextValue;
}

static BOOL
SysmonIsUserModeEnrichedImageField(
    _In_opt_ PCWSTR FieldName)
{
    return FieldName != NULL &&
        (_wcsicmp(FieldName, L"Signed") == 0 ||
         _wcsicmp(FieldName, L"Signature") == 0 ||
         _wcsicmp(FieldName, L"SignatureStatus") == 0);
}

static BOOL
SysmonIsDriverImageVersionField(
    _In_opt_ PCWSTR FieldName)
{
    return FieldName != NULL &&
        (_wcsicmp(FieldName, L"FileVersion") == 0 ||
         _wcsicmp(FieldName, L"Description") == 0 ||
         _wcsicmp(FieldName, L"Product") == 0 ||
         _wcsicmp(FieldName, L"Company") == 0 ||
         _wcsicmp(FieldName, L"OriginalFileName") == 0);
}

static BOOL
SysmonEventUsesConfigRules(
    _In_ SYSMON_EVENT_ID EventId)
{
    return EventId != SysmonEventServiceState &&
        EventId != SysmonEventConfigChange;
}

BOOL
SysmonEventFilterRequiresUserModeEnrichment(
    _In_opt_ PSYSMON_RULE_RUNTIME Runtime,
    _In_ SYSMON_EVENT_ID EventId)
{
    return (SysmonGetImageRuleRequirements(Runtime, EventId) &
        SysmonImageRuleRequirementUserModeFields) != 0;
}

DWORD
SysmonGetImageRuleRequirements(
    _In_opt_ PSYSMON_RULE_RUNTIME Runtime,
    _In_ SYSMON_EVENT_ID EventId)
{
    DWORD groupIndex;
    DWORD requirements = SysmonImageRuleRequirementNone;

    if (Runtime == NULL || Runtime->Header == NULL) {
        return SysmonImageRuleRequirementNone;
    }

    if (EventId != SysmonEventDriverLoad &&
        EventId != SysmonEventImageLoad) {
        return SysmonImageRuleRequirementNone;
    }

    for (groupIndex = 0; groupIndex < Runtime->Header->GroupCount; groupIndex++) {
        const SYSMON_RULES_BLOB_GROUP *group = &Runtime->Groups[groupIndex];
        DWORD eventRuleIndex;

        for (eventRuleIndex = 0; eventRuleIndex < group->EventRuleCount; eventRuleIndex++) {
            const SYSMON_RULES_BLOB_EVENT_RULE *eventRule =
                &Runtime->EventRules[group->EventRuleStart + eventRuleIndex];
            DWORD ruleIndex;

            if (eventRule->EventId != (DWORD)EventId || eventRule->RuleCount == 0) {
                continue;
            }

            for (ruleIndex = 0; ruleIndex < eventRule->RuleCount; ruleIndex++) {
                const SYSMON_RULES_BLOB_RULE *rule =
                    &Runtime->Rules[eventRule->RuleStart + ruleIndex];
                DWORD expressionIndex;

                for (expressionIndex = 0; expressionIndex < rule->ExpressionCount; expressionIndex++) {
                    const SYSMON_RULES_BLOB_EXPRESSION *expression =
                        &Runtime->Expressions[rule->ExpressionStart + expressionIndex];
                    PCWSTR fieldName = SysmonGetRuleString(Runtime, expression->FieldNameOffset);

                    if (_wcsicmp(fieldName, L"Hashes") == 0) {
                        requirements |= SysmonImageRuleRequirementHashes;
                    } else if (SysmonIsUserModeEnrichedImageField(fieldName)) {
                        requirements |= SysmonImageRuleRequirementUserModeFields;
                    } else if (SysmonIsDriverImageVersionField(fieldName)) {
                        requirements |= SysmonImageRuleRequirementVersionInfo;
                    }
                }
            }
        }
    }

    return requirements;
}

BOOL
SysmonShouldCaptureEvent(
    PSYSMON_RULE_RUNTIME Runtime,
    SYSMON_EVENT_ID EventId,
    const BYTE *EventData,
    DWORD EventSize)
{
    DWORD groupIndex;
    BOOL hasIncludeRule = FALSE;
    BOOL includeMatched = FALSE;

    if (Runtime == NULL || Runtime->Header == NULL) {
        return TRUE;
    }

    if (SysmonEventUsesConfigRules(EventId) &&
        !SysmonRuleRuntimeHasEvent(Runtime, EventId)) {
        return FALSE;
    }

    for (groupIndex = 0; groupIndex < Runtime->Header->GroupCount; groupIndex++) {
        const SYSMON_RULES_BLOB_GROUP *group = &Runtime->Groups[groupIndex];
        DWORD eventRuleIndex;
        BOOL groupHasInclude = FALSE;
        BOOL groupIncludeMatched = FALSE;
        BOOL groupHasExclude = FALSE;
        BOOL groupExcludeMatched = FALSE;
        BOOL firstIncludeRule = TRUE;
        BOOL firstExcludeRule = TRUE;

        for (eventRuleIndex = 0; eventRuleIndex < group->EventRuleCount; eventRuleIndex++) {
            const SYSMON_RULES_BLOB_EVENT_RULE *eventRule =
                &Runtime->EventRules[group->EventRuleStart + eventRuleIndex];
            DWORD ruleIndex;
            BOOL matched;

            if (eventRule->EventId != (ULONG)EventId) {
                continue;
            }

            if (eventRule->RuleCount == 0) {
                /*
                 * Empty include means "log nothing"; empty exclude means
                 * "exclude nothing". Model both as "no match".
                 */
                matched = FALSE;
            } else {
                matched = (eventRule->Relation == SysmonRuleRelationAnd) ? TRUE : FALSE;
                for (ruleIndex = 0; ruleIndex < eventRule->RuleCount; ruleIndex++) {
                    BOOL ruleMatched = SysmonEvaluateEventRule(
                        Runtime,
                        &Runtime->Rules[eventRule->RuleStart + ruleIndex],
                        EventData,
                        EventSize,
                        EventId);

                    if (eventRule->Relation == SysmonRuleRelationAnd) {
                        matched = matched && ruleMatched;
                        if (!matched) {
                            break;
                        }
                    } else {
                        matched = matched || ruleMatched;
                        if (matched) {
                            break;
                        }
                    }
                }
            }

            if (eventRule->MatchType == SysmonRuleMatchTypeInclude) {
                groupHasInclude = TRUE;
                groupIncludeMatched = SysmonAccumulateMatch(
                    group->Relation,
                    groupIncludeMatched,
                    matched,
                    firstIncludeRule);
                firstIncludeRule = FALSE;
            } else if (eventRule->MatchType == SysmonRuleMatchTypeExclude) {
                groupHasExclude = TRUE;
                groupExcludeMatched = SysmonAccumulateMatch(
                    group->Relation,
                    groupExcludeMatched,
                    matched,
                    firstExcludeRule);
                firstExcludeRule = FALSE;
            }
        }

        if (groupHasExclude && groupExcludeMatched) {
            return FALSE;
        }

        if (groupHasInclude) {
            hasIncludeRule = TRUE;
            includeMatched = includeMatched || groupIncludeMatched;
        }
    }

    return !hasIncludeRule || includeMatched;
}

BOOL
SysmonCanEarlyRejectImageEvent(
    _In_opt_ PSYSMON_RULE_RUNTIME Runtime,
    _In_ SYSMON_EVENT_ID EventId,
    _In_reads_bytes_(EventSize) const BYTE *EventData,
    _In_ DWORD EventSize)
{
    DWORD groupIndex;
    BOOL hasIncludeRule;
    BOOL includeMayStillMatch;

    if (Runtime == NULL || Runtime->Header == NULL ||
        (EventId != SysmonEventImageLoad && EventId != SysmonEventDriverLoad)) {
        return FALSE;
    }

    hasIncludeRule = FALSE;
    includeMayStillMatch = FALSE;

    for (groupIndex = 0; groupIndex < Runtime->Header->GroupCount; groupIndex++) {
        const SYSMON_RULES_BLOB_GROUP *group = &Runtime->Groups[groupIndex];
        DWORD eventRuleIndex;
        BOOL firstIncludeRule = TRUE;
        BOOL firstExcludeRule = TRUE;
        SYSMON_PARTIAL_MATCH_RESULT groupIncludeResult = SysmonPartialMatchFalse;
        SYSMON_PARTIAL_MATCH_RESULT groupExcludeResult = SysmonPartialMatchFalse;
        BOOL groupHasInclude = FALSE;
        BOOL groupHasExclude = FALSE;

        for (eventRuleIndex = 0; eventRuleIndex < group->EventRuleCount; eventRuleIndex++) {
            const SYSMON_RULES_BLOB_EVENT_RULE *eventRule =
                &Runtime->EventRules[group->EventRuleStart + eventRuleIndex];
            DWORD ruleIndex;
            SYSMON_PARTIAL_MATCH_RESULT matched;

            if (eventRule->EventId != (ULONG)EventId) {
                continue;
            }

            if (eventRule->RuleCount == 0) {
                matched = SysmonPartialMatchFalse;
            } else {
                matched = (eventRule->Relation == SysmonRuleRelationAnd)
                    ? SysmonPartialMatchTrue
                    : SysmonPartialMatchFalse;

                for (ruleIndex = 0; ruleIndex < eventRule->RuleCount; ruleIndex++) {
                    SYSMON_PARTIAL_MATCH_RESULT ruleMatched = SysmonEvaluateEventRulePartial(
                        Runtime,
                        &Runtime->Rules[eventRule->RuleStart + ruleIndex],
                        EventData,
                        EventSize,
                        EventId);

                    matched = SysmonAccumulatePartialMatch(
                        eventRule->Relation,
                        matched,
                        ruleMatched,
                        (ruleIndex == 0));

                    if ((eventRule->Relation == SysmonRuleRelationAnd && matched == SysmonPartialMatchFalse) ||
                        (eventRule->Relation != SysmonRuleRelationAnd && matched == SysmonPartialMatchTrue)) {
                        break;
                    }
                }
            }

            if (eventRule->MatchType == SysmonRuleMatchTypeInclude) {
                groupHasInclude = TRUE;
                groupIncludeResult = SysmonAccumulatePartialMatch(
                    group->Relation,
                    groupIncludeResult,
                    matched,
                    firstIncludeRule);
                firstIncludeRule = FALSE;
            } else if (eventRule->MatchType == SysmonRuleMatchTypeExclude) {
                groupHasExclude = TRUE;
                groupExcludeResult = SysmonAccumulatePartialMatch(
                    group->Relation,
                    groupExcludeResult,
                    matched,
                    firstExcludeRule);
                firstExcludeRule = FALSE;
            }
        }

        if (groupHasExclude && groupExcludeResult == SysmonPartialMatchTrue) {
            return TRUE;
        }

        if (groupHasInclude) {
            hasIncludeRule = TRUE;
            if (groupIncludeResult != SysmonPartialMatchFalse) {
                includeMayStillMatch = TRUE;
            }
        }
    }

    return hasIncludeRule && !includeMayStillMatch;
}

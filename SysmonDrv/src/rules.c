#include "rules.h"

typedef struct _SYSMON_RULE_BLOB_LAYOUT {
    const SYSMON_RULES_BLOB_HEADER *Header;
    const SYSMON_RULES_BLOB_GROUP *Groups;
    const SYSMON_RULES_BLOB_EVENT_RULE *EventRules;
    const SYSMON_RULES_BLOB_RULE *Rules;
    const SYSMON_RULES_BLOB_EXPRESSION *Expressions;
    const WCHAR *StringTable;
} SYSMON_RULE_BLOB_LAYOUT, *PSYSMON_RULE_BLOB_LAYOUT;

#define SYSMON_RULE_EVENT_RULE_INDEX_GROUP_NONE MAXULONG

static PCWSTR
SysmonGetRuleString(
    _In_ PSYSMON_RULE_RUNTIME Runtime,
    _In_ ULONG Offset);

NTSTATUS
SysmonCreateEmptyRuleRuntime(
    _Outptr_ PSYSMON_RULE_RUNTIME *Runtime)
{
    PSYSMON_RULE_RUNTIME runtime;

    if (Runtime == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    *Runtime = NULL;

    runtime = (PSYSMON_RULE_RUNTIME)SysmonAllocatePool(sizeof(*runtime));
    if (runtime == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    RtlZeroMemory(runtime, sizeof(*runtime));
    ExInitializeRundownProtection(&runtime->RundownRef);

    *Runtime = runtime;
    return STATUS_SUCCESS;
}

static NTSTATUS
SysmonRuleMultiplyUlong(
    _In_ ULONG Left,
    _In_ ULONG Right,
    _Out_ PULONG Result)
{
    ULONGLONG value;

    if (Result == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    value = ((ULONGLONG)Left) * ((ULONGLONG)Right);
    if (value > MAXULONG) {
        return STATUS_INTEGER_OVERFLOW;
    }

    *Result = (ULONG)value;
    return STATUS_SUCCESS;
}

static NTSTATUS
SysmonRuleAddUlong(
    _Inout_ PULONG Total,
    _In_ ULONG Value)
{
    if (Total == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    if (*Total > (MAXULONG - Value)) {
        return STATUS_INTEGER_OVERFLOW;
    }

    *Total += Value;
    return STATUS_SUCCESS;
}

static NTSTATUS
SysmonValidateStringOffset(
    _In_ const SYSMON_RULES_BLOB_HEADER *Header,
    _In_ const UCHAR *Blob,
    _In_ ULONG Offset)
{
    ULONG stringStart;
    ULONG stringEnd;
    ULONG currentOffset;

    if (Offset == SYSMON_RULES_BLOB_OFFSET_NONE) {
        return STATUS_SUCCESS;
    }

    stringStart = Header->StringOffset;
    stringEnd = Header->TotalSize;

    if (Offset < stringStart || Offset >= stringEnd) {
        return STATUS_INVALID_PARAMETER;
    }

    currentOffset = Offset;
    while (currentOffset + sizeof(WCHAR) <= stringEnd) {
        if (*(const WCHAR *)(Blob + currentOffset) == L'\0') {
            return STATUS_SUCCESS;
        }

        currentOffset += sizeof(WCHAR);
    }

    return STATUS_INVALID_PARAMETER;
}

static NTSTATUS
SysmonValidateRuleBlob(
    _In_reads_bytes_(BlobSize) const UCHAR *Blob,
    _In_ ULONG BlobSize,
    _Out_ SYSMON_RULE_BLOB_LAYOUT *Layout)
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
    NTSTATUS status;

    if (Blob == NULL || Layout == NULL || BlobSize < sizeof(SYSMON_RULES_BLOB_HEADER)) {
        return STATUS_INVALID_PARAMETER;
    }

    RtlZeroMemory(Layout, sizeof(*Layout));

    header = (const SYSMON_RULES_BLOB_HEADER *)Blob;
    if (header->Signature != SYSMON_RULES_BLOB_SIGNATURE ||
        header->MajorVersion != SYSMON_RULES_BLOB_MAJOR_VERSION) {
        return STATUS_REVISION_MISMATCH;
    }

    if (header->TotalSize < sizeof(*header) || header->TotalSize > BlobSize) {
        return STATUS_INVALID_BUFFER_SIZE;
    }

    if (header->GroupOffset < sizeof(*header) ||
        header->EventRuleOffset < header->GroupOffset ||
        header->RuleOffset < header->EventRuleOffset ||
        header->ExpressionOffset < header->RuleOffset ||
        header->StringOffset < header->ExpressionOffset ||
        header->StringOffset > header->TotalSize) {
        return STATUS_INVALID_PARAMETER;
    }

    status = SysmonRuleMultiplyUlong(header->GroupCount, sizeof(SYSMON_RULES_BLOB_GROUP), &groupBytes);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    status = SysmonRuleMultiplyUlong(header->EventRuleCount, sizeof(SYSMON_RULES_BLOB_EVENT_RULE), &eventRuleBytes);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    status = SysmonRuleMultiplyUlong(header->RuleCount, sizeof(SYSMON_RULES_BLOB_RULE), &ruleBytes);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    status = SysmonRuleMultiplyUlong(header->ExpressionCount, sizeof(SYSMON_RULES_BLOB_EXPRESSION), &expressionBytes);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    expectedOffset = header->GroupOffset;
    status = SysmonRuleAddUlong(&expectedOffset, groupBytes);
    if (!NT_SUCCESS(status) || expectedOffset != header->EventRuleOffset) {
        return STATUS_INVALID_PARAMETER;
    }

    expectedOffset = header->EventRuleOffset;
    status = SysmonRuleAddUlong(&expectedOffset, eventRuleBytes);
    if (!NT_SUCCESS(status) || expectedOffset != header->RuleOffset) {
        return STATUS_INVALID_PARAMETER;
    }

    expectedOffset = header->RuleOffset;
    status = SysmonRuleAddUlong(&expectedOffset, ruleBytes);
    if (!NT_SUCCESS(status) || expectedOffset != header->ExpressionOffset) {
        return STATUS_INVALID_PARAMETER;
    }

    expectedOffset = header->ExpressionOffset;
    status = SysmonRuleAddUlong(&expectedOffset, expressionBytes);
    if (!NT_SUCCESS(status) || expectedOffset != header->StringOffset) {
        return STATUS_INVALID_PARAMETER;
    }

    expectedOffset = header->StringOffset;
    status = SysmonRuleAddUlong(&expectedOffset, header->StringBytes);
    if (!NT_SUCCESS(status) || expectedOffset != header->TotalSize) {
        return STATUS_INVALID_PARAMETER;
    }

    if (header->StringBytes != (header->TotalSize - header->StringOffset)) {
        return STATUS_INVALID_PARAMETER;
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
            group->Relation > SysmonRuleRelationAnd) {
            return STATUS_INVALID_PARAMETER;
        }

        if (group->EventRuleStart > header->EventRuleCount ||
            group->EventRuleCount > (header->EventRuleCount - group->EventRuleStart)) {
            return STATUS_INVALID_PARAMETER;
        }

        status = SysmonValidateStringOffset(header, Blob, group->NameOffset);
        if (!NT_SUCCESS(status)) {
            return status;
        }
    }

    /*
     * The rule blob serializer is expected to partition EventRules across
     * groups exactly once. Reject overlapping ranges and orphan EventRules so
     * runtime indexing and group semantics cannot silently diverge.
     */
    for (eventRuleIndex = 0; eventRuleIndex < header->EventRuleCount; eventRuleIndex++) {
        ULONG ownerCount = 0;

        for (groupIndex = 0; groupIndex < header->GroupCount; groupIndex++) {
            const SYSMON_RULES_BLOB_GROUP *group = &Layout->Groups[groupIndex];

            if (eventRuleIndex >= group->EventRuleStart &&
                eventRuleIndex < group->EventRuleStart + group->EventRuleCount) {
                ownerCount++;
                if (ownerCount > 1) {
                    return STATUS_INVALID_PARAMETER;
                }
            }
        }

        if (ownerCount != 1) {
            return STATUS_INVALID_PARAMETER;
        }
    }

    for (eventRuleIndex = 0; eventRuleIndex < header->EventRuleCount; eventRuleIndex++) {
        const SYSMON_RULES_BLOB_EVENT_RULE *eventRule = &Layout->EventRules[eventRuleIndex];

        if (eventRule->MatchType <= SysmonRuleMatchTypeInvalid ||
            eventRule->MatchType > SysmonRuleMatchTypeExclude ||
            eventRule->Relation <= SysmonRuleRelationInvalid ||
            eventRule->Relation > SysmonRuleRelationAnd) {
            return STATUS_INVALID_PARAMETER;
        }

        if (eventRule->RuleStart > header->RuleCount ||
            eventRule->RuleCount > (header->RuleCount - eventRule->RuleStart)) {
            return STATUS_INVALID_PARAMETER;
        }
    }

    for (ruleIndex = 0; ruleIndex < header->RuleCount; ruleIndex++) {
        const SYSMON_RULES_BLOB_RULE *rule = &Layout->Rules[ruleIndex];

        if (rule->Relation <= SysmonRuleRelationInvalid ||
            rule->Relation > SysmonRuleRelationAnd) {
            return STATUS_INVALID_PARAMETER;
        }

        if (rule->ExpressionStart > header->ExpressionCount ||
            rule->ExpressionCount > (header->ExpressionCount - rule->ExpressionStart)) {
            return STATUS_INVALID_PARAMETER;
        }

        status = SysmonValidateStringOffset(header, Blob, rule->NameOffset);
        if (!NT_SUCCESS(status)) {
            return status;
        }
    }

    for (expressionIndex = 0; expressionIndex < header->ExpressionCount; expressionIndex++) {
        const SYSMON_RULES_BLOB_EXPRESSION *expression = &Layout->Expressions[expressionIndex];

        if (expression->Condition <= SysmonRuleConditionInvalid ||
            expression->Condition > SysmonRuleConditionIsAny) {
            return STATUS_INVALID_PARAMETER;
        }

        status = SysmonValidateStringOffset(header, Blob, expression->FieldNameOffset);
        if (!NT_SUCCESS(status)) {
            return status;
        }

        status = SysmonValidateStringOffset(header, Blob, expression->ValueOffset);
        if (!NT_SUCCESS(status)) {
            return status;
        }
    }

    return STATUS_SUCCESS;
}

static VOID
SysmonRecordResolvedExpressionField(
    _In_ PSYSMON_RULE_RUNTIME Runtime,
    _In_ ULONG ExpressionIndex,
    _In_ SYSMON_EVENT_ID EventId)
{
    SYSMON_RULE_RESOLVED_EXPRESSION *entry;
    SYSMON_RESOLVED_EVENT_FIELD resolvedField;
    PCWSTR fieldName;

    if (Runtime == NULL ||
        Runtime->ResolvedExpressions == NULL ||
        ExpressionIndex >= Runtime->Header->ExpressionCount) {
        return;
    }

    fieldName = SysmonGetRuleString(
        Runtime,
        Runtime->Expressions[ExpressionIndex].FieldNameOffset);
    if (fieldName[0] == L'\0' ||
        !SysmonResolveEventField(EventId, fieldName, &resolvedField)) {
        return;
    }

    entry = &Runtime->ResolvedExpressions[ExpressionIndex];
    if ((entry->Flags & SYSMON_RULE_RESOLVED_EXPRESSION_AMBIGUOUS) != 0) {
        return;
    }

    if ((entry->Flags & SYSMON_RULE_RESOLVED_EXPRESSION_FIELD_VALID) == 0) {
        entry->Field = resolvedField;
        entry->Flags = SYSMON_RULE_RESOLVED_EXPRESSION_FIELD_VALID;
        return;
    }

    if (entry->Field.EventId == resolvedField.EventId &&
        entry->Field.FieldIndex == resolvedField.FieldIndex) {
        return;
    }

    entry->Field.EventId = SysmonEventNull;
    entry->Field.FieldIndex = SYSMON_EVENT_FIELD_INDEX_UNRESOLVED;
    entry->Flags = SYSMON_RULE_RESOLVED_EXPRESSION_AMBIGUOUS;
}

static NTSTATUS
SysmonPrecompileRuleRuntimeExpressions(
    _Inout_ PSYSMON_RULE_RUNTIME Runtime)
{
    ULONG resolvedBytes;
    ULONG groupIndex;
    NTSTATUS status;

    if (Runtime == NULL || Runtime->Header == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    if (Runtime->Header->ExpressionCount == 0) {
        return STATUS_SUCCESS;
    }

    status = SysmonRuleMultiplyUlong(
        Runtime->Header->ExpressionCount,
        sizeof(SYSMON_RULE_RESOLVED_EXPRESSION),
        &resolvedBytes);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    Runtime->ResolvedExpressions =
        (SYSMON_RULE_RESOLVED_EXPRESSION *)SysmonAllocatePool(resolvedBytes);
    if (Runtime->ResolvedExpressions == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    for (groupIndex = 0; groupIndex < Runtime->Header->GroupCount; groupIndex++) {
        const SYSMON_RULES_BLOB_GROUP *group = &Runtime->Groups[groupIndex];
        ULONG eventRuleIndex;

        for (eventRuleIndex = 0; eventRuleIndex < group->EventRuleCount; eventRuleIndex++) {
            const SYSMON_RULES_BLOB_EVENT_RULE *eventRule =
                &Runtime->EventRules[group->EventRuleStart + eventRuleIndex];
            ULONG ruleIndex;

            for (ruleIndex = 0; ruleIndex < eventRule->RuleCount; ruleIndex++) {
                const SYSMON_RULES_BLOB_RULE *rule =
                    &Runtime->Rules[eventRule->RuleStart + ruleIndex];
                ULONG expressionIndex;

                for (expressionIndex = 0; expressionIndex < rule->ExpressionCount; expressionIndex++) {
                    SysmonRecordResolvedExpressionField(
                        Runtime,
                        rule->ExpressionStart + expressionIndex,
                        (SYSMON_EVENT_ID)eventRule->EventId);
                }
            }
        }
    }

    return STATUS_SUCCESS;
}

static LONG
SysmonFindEventRuleBucketIndexLinear(
    _In_reads_(BucketCount) const SYSMON_RULE_EVENT_RULE_INDEX_BUCKET *Buckets,
    _In_ ULONG BucketCount,
    _In_ ULONG EventId)
{
    ULONG index;

    if (Buckets == NULL) {
        return -1;
    }

    for (index = 0; index < BucketCount; index++) {
        if (Buckets[index].EventId == EventId) {
            return (LONG)index;
        }
    }

    return -1;
}

static const SYSMON_RULE_EVENT_RULE_INDEX_BUCKET *
SysmonFindEventRuleBucket(
    _In_opt_ PSYSMON_RULE_RUNTIME Runtime,
    _In_ SYSMON_EVENT_ID EventId)
{
    LONG left;
    LONG right;
    ULONG targetEventId;

    if (Runtime == NULL ||
        Runtime->EventRuleBuckets == NULL ||
        Runtime->EventRuleBucketCount == 0) {
        return NULL;
    }

    left = 0;
    right = (LONG)Runtime->EventRuleBucketCount - 1;
    targetEventId = (ULONG)EventId;

    while (left <= right) {
        LONG middle = left + ((right - left) / 2);
        const SYSMON_RULE_EVENT_RULE_INDEX_BUCKET *bucket =
            &Runtime->EventRuleBuckets[middle];

        if (bucket->EventId == targetEventId) {
            return bucket;
        }

        if (bucket->EventId < targetEventId) {
            left = middle + 1;
        } else {
            right = middle - 1;
        }
    }

    return NULL;
}

static VOID
SysmonSortEventRuleBuckets(
    _Inout_updates_(BucketCount) SYSMON_RULE_EVENT_RULE_INDEX_BUCKET *Buckets,
    _In_ ULONG BucketCount)
{
    ULONG outerIndex;

    if (Buckets == NULL) {
        return;
    }

    for (outerIndex = 1; outerIndex < BucketCount; outerIndex++) {
        SYSMON_RULE_EVENT_RULE_INDEX_BUCKET currentBucket = Buckets[outerIndex];
        ULONG insertIndex = outerIndex;

        while (insertIndex > 0 &&
               Buckets[insertIndex - 1].EventId > currentBucket.EventId) {
            Buckets[insertIndex] = Buckets[insertIndex - 1];
            insertIndex--;
        }

        Buckets[insertIndex] = currentBucket;
    }
}

static NTSTATUS
SysmonAppendEventRuleRefToBucket(
    _Inout_updates_(BucketCount) SYSMON_RULE_EVENT_RULE_INDEX_BUCKET *Buckets,
    _In_ ULONG BucketCount,
    _Inout_updates_(BucketCount) ULONG *BucketFillCounts,
    _Inout_updates_(TotalRefCount) SYSMON_RULE_EVENT_RULE_INDEX_REF *Refs,
    _In_ ULONG TotalRefCount,
    _In_ ULONG EventId,
    _In_ ULONG GroupIndex,
    _In_ ULONG EventRuleIndex)
{
    LONG bucketIndex;
    ULONG slot;

    bucketIndex = SysmonFindEventRuleBucketIndexLinear(Buckets, BucketCount, EventId);
    if (bucketIndex < 0) {
        return STATUS_NOT_FOUND;
    }

    if ((ULONG)bucketIndex >= BucketCount) {
        return STATUS_INVALID_PARAMETER;
    }

    if (BucketFillCounts[bucketIndex] >= Buckets[bucketIndex].Count) {
        return STATUS_INVALID_PARAMETER;
    }

    slot = Buckets[bucketIndex].Start + BucketFillCounts[bucketIndex];
    if (slot >= TotalRefCount) {
        return STATUS_INVALID_PARAMETER;
    }

    Refs[slot].GroupIndex = GroupIndex;
    Refs[slot].EventRuleIndex = EventRuleIndex;
    BucketFillCounts[bucketIndex]++;
    return STATUS_SUCCESS;
}

static NTSTATUS
SysmonBuildRuleRuntimeEventIndex(
    _Inout_ PSYSMON_RULE_RUNTIME Runtime)
{
    SYSMON_RULE_EVENT_RULE_INDEX_BUCKET *buckets;
    SYSMON_RULE_EVENT_RULE_INDEX_REF *refs;
    ULONG *bucketFillCounts;
    UCHAR *referencedEventRules;
    ULONG eventRuleBytes;
    ULONG bucketBytes;
    ULONG bucketFillBytes;
    ULONG bucketCount;
    ULONG totalRefCount;
    ULONG groupIndex;
    ULONG eventRuleIndex;
    ULONG prefixStart;
    NTSTATUS status;

    if (Runtime == NULL || Runtime->Header == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    if (Runtime->Header->EventRuleCount == 0) {
        return STATUS_SUCCESS;
    }

    buckets = NULL;
    refs = NULL;
    bucketFillCounts = NULL;
    referencedEventRules = NULL;
    bucketCount = 0;
    totalRefCount = 0;

    status = SysmonRuleMultiplyUlong(
        Runtime->Header->EventRuleCount,
        sizeof(*buckets),
        &bucketBytes);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    status = SysmonRuleMultiplyUlong(
        Runtime->Header->EventRuleCount,
        sizeof(*referencedEventRules),
        &eventRuleBytes);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    buckets = (SYSMON_RULE_EVENT_RULE_INDEX_BUCKET *)SysmonAllocatePool(bucketBytes);
    referencedEventRules = (UCHAR *)SysmonAllocatePool(eventRuleBytes);
    if (buckets == NULL || referencedEventRules == NULL) {
        status = STATUS_INSUFFICIENT_RESOURCES;
        goto Cleanup;
    }

    RtlZeroMemory(buckets, bucketBytes);
    RtlZeroMemory(referencedEventRules, eventRuleBytes);

    for (groupIndex = 0; groupIndex < Runtime->Header->GroupCount; groupIndex++) {
        const SYSMON_RULES_BLOB_GROUP *group = &Runtime->Groups[groupIndex];

        for (eventRuleIndex = 0; eventRuleIndex < group->EventRuleCount; eventRuleIndex++) {
            ULONG runtimeEventRuleIndex = group->EventRuleStart + eventRuleIndex;
            const SYSMON_RULES_BLOB_EVENT_RULE *eventRule =
                &Runtime->EventRules[runtimeEventRuleIndex];
            LONG bucketIndex = SysmonFindEventRuleBucketIndexLinear(
                buckets,
                bucketCount,
                eventRule->EventId);

            if (bucketIndex < 0) {
                bucketIndex = (LONG)bucketCount;
                buckets[bucketCount].EventId = eventRule->EventId;
                buckets[bucketCount].Start = 0;
                buckets[bucketCount].Count = 0;
                bucketCount++;
            }

            buckets[bucketIndex].Count++;
            referencedEventRules[runtimeEventRuleIndex] = 1;

            status = SysmonRuleAddUlong(&totalRefCount, 1);
            if (!NT_SUCCESS(status)) {
                goto Cleanup;
            }
        }
    }

    for (eventRuleIndex = 0; eventRuleIndex < Runtime->Header->EventRuleCount; eventRuleIndex++) {
        const SYSMON_RULES_BLOB_EVENT_RULE *eventRule;
        LONG bucketIndex;

        if (referencedEventRules[eventRuleIndex] != 0) {
            continue;
        }

        eventRule = &Runtime->EventRules[eventRuleIndex];
        bucketIndex = SysmonFindEventRuleBucketIndexLinear(
            buckets,
            bucketCount,
            eventRule->EventId);
        if (bucketIndex < 0) {
            bucketIndex = (LONG)bucketCount;
            buckets[bucketCount].EventId = eventRule->EventId;
            buckets[bucketCount].Start = 0;
            buckets[bucketCount].Count = 0;
            bucketCount++;
        }

        buckets[bucketIndex].Count++;

        status = SysmonRuleAddUlong(&totalRefCount, 1);
        if (!NT_SUCCESS(status)) {
            goto Cleanup;
        }
    }

    SysmonSortEventRuleBuckets(buckets, bucketCount);

    prefixStart = 0;
    for (eventRuleIndex = 0; eventRuleIndex < bucketCount; eventRuleIndex++) {
        ULONG bucketCountForEvent = buckets[eventRuleIndex].Count;

        buckets[eventRuleIndex].Start = prefixStart;
        status = SysmonRuleAddUlong(&prefixStart, bucketCountForEvent);
        if (!NT_SUCCESS(status)) {
            goto Cleanup;
        }
    }

    if (prefixStart != totalRefCount) {
        status = STATUS_INVALID_PARAMETER;
        goto Cleanup;
    }

    status = SysmonRuleMultiplyUlong(
        bucketCount,
        sizeof(*bucketFillCounts),
        &bucketFillBytes);
    if (!NT_SUCCESS(status)) {
        goto Cleanup;
    }

    status = SysmonRuleMultiplyUlong(
        totalRefCount,
        sizeof(*refs),
        &eventRuleBytes);
    if (!NT_SUCCESS(status)) {
        goto Cleanup;
    }

    bucketFillCounts = (ULONG *)SysmonAllocatePool(bucketFillBytes);
    refs = (SYSMON_RULE_EVENT_RULE_INDEX_REF *)SysmonAllocatePool(eventRuleBytes);
    if (bucketFillCounts == NULL || refs == NULL) {
        status = STATUS_INSUFFICIENT_RESOURCES;
        goto Cleanup;
    }

    RtlZeroMemory(bucketFillCounts, bucketFillBytes);
    RtlZeroMemory(refs, eventRuleBytes);

    /*
     * Blob validation guarantees each runtime EventRule belongs to exactly one
     * group. Appending refs in outer group order makes GroupIndex monotonic
     * within every EventId bucket, which the capture path relies on.
     */
    for (groupIndex = 0; groupIndex < Runtime->Header->GroupCount; groupIndex++) {
        const SYSMON_RULES_BLOB_GROUP *group = &Runtime->Groups[groupIndex];

        for (eventRuleIndex = 0; eventRuleIndex < group->EventRuleCount; eventRuleIndex++) {
            ULONG runtimeEventRuleIndex = group->EventRuleStart + eventRuleIndex;
            const SYSMON_RULES_BLOB_EVENT_RULE *eventRule =
                &Runtime->EventRules[runtimeEventRuleIndex];

            status = SysmonAppendEventRuleRefToBucket(
                buckets,
                bucketCount,
                bucketFillCounts,
                refs,
                totalRefCount,
                eventRule->EventId,
                groupIndex,
                runtimeEventRuleIndex);
            if (!NT_SUCCESS(status)) {
                goto Cleanup;
            }
        }
    }

    for (eventRuleIndex = 0; eventRuleIndex < Runtime->Header->EventRuleCount; eventRuleIndex++) {
        const SYSMON_RULES_BLOB_EVENT_RULE *eventRule;

        if (referencedEventRules[eventRuleIndex] != 0) {
            continue;
        }

        eventRule = &Runtime->EventRules[eventRuleIndex];
        status = SysmonAppendEventRuleRefToBucket(
            buckets,
            bucketCount,
            bucketFillCounts,
            refs,
            totalRefCount,
            eventRule->EventId,
            SYSMON_RULE_EVENT_RULE_INDEX_GROUP_NONE,
            eventRuleIndex);
        if (!NT_SUCCESS(status)) {
            goto Cleanup;
        }
    }

    for (eventRuleIndex = 0; eventRuleIndex < bucketCount; eventRuleIndex++) {
        if (bucketFillCounts[eventRuleIndex] != buckets[eventRuleIndex].Count) {
            status = STATUS_INVALID_PARAMETER;
            goto Cleanup;
        }
    }

    Runtime->EventRuleBuckets = buckets;
    Runtime->EventRuleBucketCount = bucketCount;
    Runtime->EventRuleRefs = refs;
    status = STATUS_SUCCESS;

Cleanup:
    if (!NT_SUCCESS(status)) {
        SysmonFreePool(refs);
        SysmonFreePool(buckets);
    }

    SysmonFreePool(bucketFillCounts);
    SysmonFreePool(referencedEventRules);
    return status;
}

NTSTATUS
SysmonLoadRuleRuntime(
    _In_reads_bytes_(BlobSize) const UCHAR *Blob,
    _In_ ULONG BlobSize,
    _Outptr_ PSYSMON_RULE_RUNTIME *Runtime)
{
    SYSMON_RULE_BLOB_LAYOUT layout;
    PSYSMON_RULE_RUNTIME runtime;
    PUCHAR blobCopy;
    NTSTATUS status;

    if (Runtime == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    *Runtime = NULL;

    status = SysmonValidateRuleBlob(Blob, BlobSize, &layout);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    status = SysmonCreateEmptyRuleRuntime(&runtime);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    blobCopy = (PUCHAR)SysmonAllocatePool(layout.Header->TotalSize);
    if (blobCopy == NULL) {
        SysmonFreeRuleRuntime(runtime);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    RtlCopyMemory(blobCopy, Blob, layout.Header->TotalSize);

    runtime->BlobSize = layout.Header->TotalSize;
    runtime->BlobStorage = blobCopy;
    runtime->Header = (const SYSMON_RULES_BLOB_HEADER *)blobCopy;
    runtime->Groups = (const SYSMON_RULES_BLOB_GROUP *)(blobCopy + runtime->Header->GroupOffset);
    runtime->EventRules = (const SYSMON_RULES_BLOB_EVENT_RULE *)(blobCopy + runtime->Header->EventRuleOffset);
    runtime->Rules = (const SYSMON_RULES_BLOB_RULE *)(blobCopy + runtime->Header->RuleOffset);
    runtime->Expressions = (const SYSMON_RULES_BLOB_EXPRESSION *)(blobCopy + runtime->Header->ExpressionOffset);
    runtime->StringTable = (const WCHAR *)(blobCopy + runtime->Header->StringOffset);

    status = SysmonPrecompileRuleRuntimeExpressions(runtime);
    if (!NT_SUCCESS(status)) {
        SysmonFreeRuleRuntime(runtime);
        return status;
    }

    status = SysmonBuildRuleRuntimeEventIndex(runtime);
    if (!NT_SUCCESS(status)) {
        SysmonFreeRuleRuntime(runtime);
        return status;
    }

    *Runtime = runtime;
    return STATUS_SUCCESS;
}

VOID
SysmonFreeRuleRuntime(
    _In_opt_ PSYSMON_RULE_RUNTIME Runtime)
{
    if (Runtime == NULL) {
        return;
    }

    if (Runtime->ArchiveDirectoryComponent.Buffer != NULL) {
        SysmonFreePool(Runtime->ArchiveDirectoryComponent.Buffer);
    }

    SysmonFreePool(Runtime->BlobStorage);
    SysmonFreePool(Runtime->ResolvedExpressions);
    SysmonFreePool(Runtime->EventRuleBuckets);
    SysmonFreePool(Runtime->EventRuleRefs);
    SysmonFreePool(Runtime->CopyOnDeleteSIDsMultiSz);
    SysmonFreePool(Runtime->CopyOnDeleteExtensionsMultiSz);
    SysmonFreePool(Runtime->CopyOnDeleteProcessesMultiSz);
    RtlZeroMemory(Runtime, sizeof(*Runtime));
    SysmonFreePool(Runtime);
}

BOOLEAN
SysmonRuleRuntimeHasEvent(
    _In_opt_ PSYSMON_RULE_RUNTIME Runtime,
    _In_ SYSMON_EVENT_ID EventId)
{
    return SysmonFindEventRuleBucket(Runtime, EventId) != NULL;
}

BOOLEAN
SysmonRuleRuntimeEventCanProduceLogs(
    _In_opt_ PSYSMON_RULE_RUNTIME Runtime,
    _In_ SYSMON_EVENT_ID EventId)
{
    const SYSMON_RULE_EVENT_RULE_INDEX_BUCKET *bucket;
    ULONG bucketOffset;
    BOOLEAN hasInclude = FALSE;
    BOOLEAN hasMatchAllExclude = FALSE;

    if (Runtime == NULL || Runtime->Header == NULL) {
        return FALSE;
    }

    bucket = SysmonFindEventRuleBucket(Runtime, EventId);
    if (bucket == NULL) {
        return FALSE;
    }

    for (bucketOffset = 0; bucketOffset < bucket->Count; bucketOffset++) {
        const SYSMON_RULE_EVENT_RULE_INDEX_REF *eventRuleRef =
            &Runtime->EventRuleRefs[bucket->Start + bucketOffset];
        const SYSMON_RULES_BLOB_EVENT_RULE *eventRule =
            &Runtime->EventRules[eventRuleRef->EventRuleIndex];

        if (eventRule->MatchType == SysmonRuleMatchTypeInclude) {
            hasInclude = TRUE;
        } else if (eventRule->MatchType == SysmonRuleMatchTypeExclude &&
                   eventRule->RuleCount == 0) {
            hasMatchAllExclude = TRUE;
        }
    }

    if (hasMatchAllExclude && !hasInclude) {
        return FALSE;
    }

    return TRUE;
}

BOOLEAN
SysmonRuleRuntimeHasAnyEvent(
    _In_opt_ PSYSMON_RULE_RUNTIME Runtime,
    _In_reads_(EventIdCount) const SYSMON_EVENT_ID *EventIds,
    _In_ ULONG EventIdCount)
{
    ULONG index;

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

static BOOLEAN
SysmonIsUserModeEnrichedImageField(
    _In_opt_ PCWSTR FieldName)
{
    return FieldName != NULL &&
        (_wcsicmp(FieldName, L"Signed") == 0 ||
         _wcsicmp(FieldName, L"Signature") == 0 ||
         _wcsicmp(FieldName, L"SignatureStatus") == 0);
}

static BOOLEAN
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

static PCWSTR
SysmonGetRuleString(
    _In_ PSYSMON_RULE_RUNTIME Runtime,
    _In_ ULONG Offset);

ULONG
SysmonGetImageRuleRequirements(
    _In_opt_ PSYSMON_RULE_RUNTIME Runtime,
    _In_ SYSMON_EVENT_ID EventId);

static BOOLEAN
SysmonEventUsesConfigRules(
    _In_ SYSMON_EVENT_ID EventId)
{
    return EventId != SysmonEventServiceState &&
        EventId != SysmonEventConfigChange;
}

BOOLEAN
SysmonEventFilterRequiresUserModeEnrichment(
    _In_opt_ PSYSMON_RULE_RUNTIME Runtime,
    _In_ SYSMON_EVENT_ID EventId)
{
    return (SysmonGetImageRuleRequirements(Runtime, EventId) &
        SysmonImageRuleRequirementUserModeFields) != 0;
}

ULONG
SysmonGetImageRuleRequirements(
    _In_opt_ PSYSMON_RULE_RUNTIME Runtime,
    _In_ SYSMON_EVENT_ID EventId)
{
    const SYSMON_RULE_EVENT_RULE_INDEX_BUCKET *bucket;
    ULONG bucketOffset;
    ULONG requirements = SysmonImageRuleRequirementNone;

    if (Runtime == NULL || Runtime->Header == NULL) {
        return SysmonImageRuleRequirementNone;
    }

    if (EventId != SysmonEventDriverLoad &&
        EventId != SysmonEventImageLoad) {
        return SysmonImageRuleRequirementNone;
    }

    bucket = SysmonFindEventRuleBucket(Runtime, EventId);
    if (bucket == NULL) {
        return SysmonImageRuleRequirementNone;
    }

    for (bucketOffset = 0; bucketOffset < bucket->Count; bucketOffset++) {
        const SYSMON_RULE_EVENT_RULE_INDEX_REF *eventRuleRef =
            &Runtime->EventRuleRefs[bucket->Start + bucketOffset];
        const SYSMON_RULES_BLOB_EVENT_RULE *eventRule;
        ULONG ruleIndex;

        if (eventRuleRef->GroupIndex == SYSMON_RULE_EVENT_RULE_INDEX_GROUP_NONE) {
            continue;
        }

        eventRule = &Runtime->EventRules[eventRuleRef->EventRuleIndex];
        if (eventRule->RuleCount == 0) {
            continue;
        }

        for (ruleIndex = 0; ruleIndex < eventRule->RuleCount; ruleIndex++) {
            const SYSMON_RULES_BLOB_RULE *rule =
                &Runtime->Rules[eventRule->RuleStart + ruleIndex];
            ULONG expressionIndex;

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

    return requirements;
}

ULONG
SysmonGetProcessAccessRuleRequirements(
    _In_opt_ PSYSMON_RULE_RUNTIME Runtime)
{
    const SYSMON_RULE_EVENT_RULE_INDEX_BUCKET *bucket;
    ULONG bucketOffset;
    ULONG requirements = SysmonProcessAccessRuleRequirementNone;

    if (Runtime == NULL || Runtime->Header == NULL) {
        return SysmonProcessAccessRuleRequirementNone;
    }

    bucket = SysmonFindEventRuleBucket(Runtime, SysmonEventProcessAccess);
    if (bucket == NULL) {
        return SysmonProcessAccessRuleRequirementNone;
    }

    for (bucketOffset = 0; bucketOffset < bucket->Count; bucketOffset++) {
        const SYSMON_RULE_EVENT_RULE_INDEX_REF *eventRuleRef =
            &Runtime->EventRuleRefs[bucket->Start + bucketOffset];
        const SYSMON_RULES_BLOB_EVENT_RULE *eventRule;
        ULONG ruleIndex;

        if (eventRuleRef->GroupIndex == SYSMON_RULE_EVENT_RULE_INDEX_GROUP_NONE) {
            continue;
        }

        eventRule = &Runtime->EventRules[eventRuleRef->EventRuleIndex];
        if (eventRule->RuleCount == 0) {
            continue;
        }

        for (ruleIndex = 0; ruleIndex < eventRule->RuleCount; ruleIndex++) {
            const SYSMON_RULES_BLOB_RULE *rule =
                &Runtime->Rules[eventRule->RuleStart + ruleIndex];
            ULONG expressionIndex;

            for (expressionIndex = 0; expressionIndex < rule->ExpressionCount; expressionIndex++) {
                const SYSMON_RULES_BLOB_EXPRESSION *expression =
                    &Runtime->Expressions[rule->ExpressionStart + expressionIndex];
                PCWSTR fieldName = SysmonGetRuleString(Runtime, expression->FieldNameOffset);

                if (_wcsicmp(fieldName, L"SourceUser") == 0) {
                    requirements |= SysmonProcessAccessRuleRequirementSourceUser;
                } else if (_wcsicmp(fieldName, L"TargetUser") == 0) {
                    requirements |= SysmonProcessAccessRuleRequirementTargetUser;
                } else if (_wcsicmp(fieldName, L"CallTrace") == 0) {
                    requirements |= SysmonProcessAccessRuleRequirementCallTrace;
                }

                if (requirements ==
                    (SysmonProcessAccessRuleRequirementSourceUser |
                     SysmonProcessAccessRuleRequirementTargetUser |
                     SysmonProcessAccessRuleRequirementCallTrace)) {
                    return requirements;
                }
            }
        }
    }

    return requirements;
}

static BOOLEAN
SysmonIsWhitespace(
    _In_ WCHAR Character)
{
    return Character == L' ' ||
        Character == L'\t' ||
        Character == L'\r' ||
        Character == L'\n';
}

static VOID
SysmonTrimSpan(
    _In_reads_(Length) PCWSTR Text,
    _Inout_ PUSHORT Start,
    _Inout_ PUSHORT Length)
{
    USHORT start;
    USHORT length;

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

static BOOLEAN
SysmonEqualsInsensitive(
    _In_ PCWSTR Left,
    _In_ PCWSTR Right)
{
    return Left != NULL &&
        Right != NULL &&
        _wcsicmp(Left, Right) == 0;
}

static BOOLEAN
SysmonContainsInsensitive(
    _In_ PCWSTR Haystack,
    _In_ PCWSTR Needle)
{
    SIZE_T haystackLength;
    SIZE_T needleLength;
    SIZE_T index;

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

static BOOLEAN
SysmonMatchExactAnyToken(
    _In_ PCWSTR FieldValue,
    _In_ PCWSTR RuleValue)
{
    USHORT start;
    USHORT length;
    USHORT totalLength;

    if (FieldValue == NULL || RuleValue == NULL) {
        return FALSE;
    }

    totalLength = (USHORT)wcslen(RuleValue);
    start = 0;

    while (start <= totalLength) {
        USHORT tokenStart = start;
        WCHAR tokenBuffer[260];

        while (start < totalLength && RuleValue[start] != L';') {
            start++;
        }

        length = start - tokenStart;
        SysmonTrimSpan(RuleValue, &tokenStart, &length);
        if (length != 0) {
            if (length >= RTL_NUMBER_OF(tokenBuffer)) {
                length = (USHORT)(RTL_NUMBER_OF(tokenBuffer) - 1);
            }

            RtlCopyMemory(tokenBuffer, RuleValue + tokenStart, length * sizeof(WCHAR));
            tokenBuffer[length] = L'\0';
            if (SysmonEqualsInsensitive(FieldValue, tokenBuffer)) {
                return TRUE;
            }
        }

        if (start == totalLength) {
            break;
        }

        start++;
    }

    return FALSE;
}

static BOOLEAN
SysmonMatchAnyToken(
    _In_ PCWSTR FieldValue,
    _In_ PCWSTR RuleValue,
    _In_ BOOLEAN RequireAll,
    _In_ BOOLEAN InvertMatch)
{
    USHORT start;
    USHORT length;
    USHORT totalLength;
    BOOLEAN sawToken;
    BOOLEAN matchedAny;

    if (FieldValue == NULL || RuleValue == NULL) {
        return FALSE;
    }

    totalLength = (USHORT)wcslen(RuleValue);
    start = 0;
    sawToken = FALSE;
    matchedAny = FALSE;

    while (start <= totalLength) {
        USHORT tokenStart = start;

        while (start < totalLength && RuleValue[start] != L';') {
            start++;
        }

        length = start - tokenStart;
        SysmonTrimSpan(RuleValue, &tokenStart, &length);
        if (length != 0) {
            BOOLEAN contains;
            WCHAR tokenBuffer[260];

            sawToken = TRUE;

            if (length >= RTL_NUMBER_OF(tokenBuffer)) {
                length = (USHORT)(RTL_NUMBER_OF(tokenBuffer) - 1);
            }

            RtlCopyMemory(tokenBuffer, RuleValue + tokenStart, length * sizeof(WCHAR));
            tokenBuffer[length] = L'\0';

            contains = SysmonContainsInsensitive(FieldValue, tokenBuffer);
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
        }

        if (start == totalLength) {
            break;
        }

        start++;
    }

    if (!sawToken) {
        return FALSE;
    }

    if (RequireAll) {
        return TRUE;
    }

    return matchedAny;
}

static BOOLEAN
SysmonEvaluateRuleCondition(
    _In_ ULONG Condition,
    _In_ PCWSTR FieldValue,
    _In_ PCWSTR RuleValue,
    _In_ SIZE_T RuleValueChars)
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
    case SysmonRuleConditionNotBeginWith:
    {
        BOOLEAN matches = _wcsnicmp(FieldValue, RuleValue, RuleValueChars) == 0;

        return (Condition == SysmonRuleConditionBeginWith) ? matches : !matches;
    }

    case SysmonRuleConditionEndWith:
    case SysmonRuleConditionImage:
    case SysmonRuleConditionNotEndWith:
    {
        SIZE_T fieldLength = wcslen(FieldValue);
        BOOLEAN matches = RuleValueChars <= fieldLength &&
            _wcsicmp(FieldValue + (fieldLength - RuleValueChars), RuleValue) == 0;

        return (Condition == SysmonRuleConditionNotEndWith) ? !matches : matches;
    }

    case SysmonRuleConditionLessThan:
        return _wcsicmp(FieldValue, RuleValue) < 0;

    case SysmonRuleConditionMoreThan:
        return _wcsicmp(FieldValue, RuleValue) > 0;

    default:
        break;
    }

    return FALSE;
}

static PCWSTR
SysmonGetRuleString(
    _In_ PSYSMON_RULE_RUNTIME Runtime,
    _In_ ULONG Offset)
{
    ULONG remainingBytes;
    const WCHAR *value;

    if (Runtime == NULL ||
        Runtime->BlobStorage == NULL ||
        Offset == SYSMON_RULES_BLOB_OFFSET_NONE) {
        return L"";
    }

    if (Offset > Runtime->BlobSize ||
        Runtime->BlobSize - Offset < sizeof(WCHAR) ||
        (Offset % sizeof(WCHAR)) != 0) {
        return L"";
    }

    remainingBytes = Runtime->BlobSize - Offset;
    value = (const WCHAR *)((const UCHAR *)Runtime->BlobStorage + Offset);
    while (remainingBytes >= sizeof(WCHAR)) {
        if (*value == L'\0') {
            return (PCWSTR)((const UCHAR *)Runtime->BlobStorage + Offset);
        }

        value++;
        remainingBytes -= sizeof(WCHAR);
    }

    return L"";
}

static BOOLEAN
SysmonEvaluateEventExpression(
    _In_ PSYSMON_RULE_RUNTIME Runtime,
    _In_ ULONG ExpressionIndex,
    _In_ PSYSMON_EVENT_UNION Event)
{
    const SYSMON_RULES_BLOB_EXPRESSION *expression;
    const SYSMON_RULE_RESOLVED_EXPRESSION *resolvedExpression;
    WCHAR fieldValue[SYSMON_MAX_CMDLINE];
    PCWSTR fieldName;
    PCWSTR ruleValue;
    SIZE_T ruleValueChars;

    if (Runtime == NULL ||
        Runtime->Header == NULL ||
        ExpressionIndex >= Runtime->Header->ExpressionCount) {
        return FALSE;
    }

    expression = &Runtime->Expressions[ExpressionIndex];
    ruleValue = SysmonGetRuleString(Runtime, expression->ValueOffset);
    if (ruleValue[0] == L'\0') {
        return FALSE;
    }

    /*
     * RuleValue is immutable during rule evaluation — compute its length once
     * so BeginWith/EndWith/NotEndWith conditions can skip a redundant wcslen.
     */
    ruleValueChars = wcslen(ruleValue);

    resolvedExpression = NULL;
    if (Runtime->ResolvedExpressions != NULL) {
        resolvedExpression = &Runtime->ResolvedExpressions[ExpressionIndex];
    }

    if (resolvedExpression != NULL &&
        (resolvedExpression->Flags & SYSMON_RULE_RESOLVED_EXPRESSION_FIELD_VALID) != 0 &&
        resolvedExpression->Field.EventId == (SYSMON_EVENT_ID)Event->Header.EventId) {
        if (SysmonExtractResolvedEventField(
                Event,
                &resolvedExpression->Field,
                fieldValue,
                RTL_NUMBER_OF(fieldValue))) {
            return SysmonEvaluateRuleCondition(
                expression->Condition,
                fieldValue,
                ruleValue,
                ruleValueChars);
        }
    }

    fieldName = SysmonGetRuleString(Runtime, expression->FieldNameOffset);
    if (fieldName[0] == L'\0' ||
        !SysmonExtractEventField(
            Event,
            fieldName,
            fieldValue,
            RTL_NUMBER_OF(fieldValue))) {
        return FALSE;
    }

    return SysmonEvaluateRuleCondition(
        expression->Condition,
        fieldValue,
        ruleValue,
        ruleValueChars);
}

static BOOLEAN
SysmonEvaluateEventRule(
    _In_ PSYSMON_RULE_RUNTIME Runtime,
    _In_ const SYSMON_RULES_BLOB_RULE *Rule,
    _In_ PSYSMON_EVENT_UNION Event)
{
    ULONG expressionIndex;
    BOOLEAN result;

    if (Rule->ExpressionCount == 0) {
        return TRUE;
    }

    result = (Rule->Relation == SysmonRuleRelationAnd) ? TRUE : FALSE;

    for (expressionIndex = 0; expressionIndex < Rule->ExpressionCount; expressionIndex++) {
        BOOLEAN expressionResult = SysmonEvaluateEventExpression(
            Runtime,
            Rule->ExpressionStart + expressionIndex,
            Event);

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

static BOOLEAN
SysmonRuleContainsDriverImageVersionField(
    _In_ PSYSMON_RULE_RUNTIME Runtime,
    _In_ const SYSMON_RULES_BLOB_RULE *Rule)
{
    ULONG expressionIndex;

    if (Runtime == NULL || Rule == NULL) {
        return FALSE;
    }

    for (expressionIndex = 0; expressionIndex < Rule->ExpressionCount; expressionIndex++) {
        ULONG resolvedExpressionIndex = Rule->ExpressionStart + expressionIndex;
        const SYSMON_RULES_BLOB_EXPRESSION *expression =
            &Runtime->Expressions[resolvedExpressionIndex];
        PCWSTR fieldName = SysmonGetRuleString(Runtime, expression->FieldNameOffset);

        if (SysmonIsDriverImageVersionField(fieldName)) {
            return TRUE;
        }
    }

    return FALSE;
}

static BOOLEAN
SysmonMayNeedImageVersionInfoForRule(
    _In_ PSYSMON_RULE_RUNTIME Runtime,
    _In_ const SYSMON_RULES_BLOB_RULE *Rule,
    _In_ PSYSMON_EVENT_UNION Event)
{
    ULONG expressionIndex;
    BOOLEAN hasVersionField = FALSE;
    BOOLEAN hasNonVersionField = FALSE;

    if (Runtime == NULL || Rule == NULL || Event == NULL) {
        return FALSE;
    }

    /*
     * Only prune the common "ruleRelation=and" shape safely. More complex
     * relations fall back to version collection to preserve behavior.
     */
    if (Rule->Relation != SysmonRuleRelationAnd) {
        return SysmonRuleContainsDriverImageVersionField(Runtime, Rule);
    }

    for (expressionIndex = 0; expressionIndex < Rule->ExpressionCount; expressionIndex++) {
        ULONG resolvedExpressionIndex = Rule->ExpressionStart + expressionIndex;
        const SYSMON_RULES_BLOB_EXPRESSION *expression =
            &Runtime->Expressions[resolvedExpressionIndex];
        PCWSTR fieldName = SysmonGetRuleString(Runtime, expression->FieldNameOffset);

        if (SysmonIsDriverImageVersionField(fieldName)) {
            hasVersionField = TRUE;
            continue;
        }

        hasNonVersionField = TRUE;
        if (!SysmonEvaluateEventExpression(Runtime, resolvedExpressionIndex, Event)) {
            return FALSE;
        }
    }

    return hasVersionField && (hasNonVersionField || Rule->ExpressionCount != 0);
}

BOOLEAN
SysmonShouldCollectImageVersionInfoForEvent(
    _In_opt_ PSYSMON_RULE_RUNTIME Runtime,
    _In_ SYSMON_EVENT_ID EventId,
    _In_ PSYSMON_EVENT_UNION Event)
{
    const SYSMON_RULE_EVENT_RULE_INDEX_BUCKET *bucket;
    ULONG bucketOffset;

    if (Runtime == NULL || Runtime->Header == NULL || Event == NULL) {
        return FALSE;
    }

    if (EventId != SysmonEventImageLoad &&
        EventId != SysmonEventDriverLoad) {
        return FALSE;
    }

    bucket = SysmonFindEventRuleBucket(Runtime, EventId);
    if (bucket == NULL) {
        return FALSE;
    }

    for (bucketOffset = 0; bucketOffset < bucket->Count; bucketOffset++) {
        const SYSMON_RULE_EVENT_RULE_INDEX_REF *eventRuleRef =
            &Runtime->EventRuleRefs[bucket->Start + bucketOffset];
        const SYSMON_RULES_BLOB_EVENT_RULE *eventRule;
        ULONG ruleIndex;

        if (eventRuleRef->GroupIndex == SYSMON_RULE_EVENT_RULE_INDEX_GROUP_NONE) {
            continue;
        }

        eventRule = &Runtime->EventRules[eventRuleRef->EventRuleIndex];
        if (eventRule->RuleCount == 0) {
            continue;
        }

        /*
         * OR-across-rules is the common Sysmon shape and can be pruned by
         * checking each rule's cheap fields first. For AND-across-rules,
         * keep the conservative behavior.
         */
        if (eventRule->Relation != SysmonRuleRelationOr) {
            for (ruleIndex = 0; ruleIndex < eventRule->RuleCount; ruleIndex++) {
                if (SysmonRuleContainsDriverImageVersionField(
                        Runtime,
                        &Runtime->Rules[eventRule->RuleStart + ruleIndex])) {
                    return TRUE;
                }
            }
            continue;
        }

        for (ruleIndex = 0; ruleIndex < eventRule->RuleCount; ruleIndex++) {
            if (SysmonMayNeedImageVersionInfoForRule(
                    Runtime,
                    &Runtime->Rules[eventRule->RuleStart + ruleIndex],
                    Event)) {
                return TRUE;
            }
        }
    }

    return FALSE;
}

static BOOLEAN
SysmonAccumulateMatch(
    _In_ ULONG Relation,
    _In_ BOOLEAN CurrentValue,
    _In_ BOOLEAN NextValue,
    _In_ BOOLEAN IsFirst)
{
    if (IsFirst) {
        return NextValue;
    }

    if (Relation == SysmonRuleRelationAnd) {
        return CurrentValue && NextValue;
    }

    return CurrentValue || NextValue;
}

static BOOLEAN
SysmonFinalizeCaptureGroupResult(
    _In_ BOOLEAN GroupHasInclude,
    _In_ BOOLEAN GroupIncludeMatched,
    _In_ BOOLEAN GroupHasExclude,
    _In_ BOOLEAN GroupExcludeMatched,
    _Inout_ PBOOLEAN HasIncludeRule,
    _Inout_ PBOOLEAN IncludeMatched)
{
    if (HasIncludeRule == NULL || IncludeMatched == NULL) {
        return FALSE;
    }

    if (GroupHasExclude && GroupExcludeMatched) {
        return FALSE;
    }

    if (GroupHasInclude) {
        *HasIncludeRule = TRUE;
        *IncludeMatched = *IncludeMatched || GroupIncludeMatched;
    }

    return TRUE;
}

BOOLEAN
SysmonShouldCaptureEvent(
    _In_opt_ PSYSMON_RULE_RUNTIME Runtime,
    _In_ SYSMON_EVENT_ID EventId,
    _In_ PSYSMON_EVENT_UNION Event)
{
    const SYSMON_RULE_EVENT_RULE_INDEX_BUCKET *bucket;
    ULONG bucketOffset;
    ULONG currentGroupIndex;
    BOOLEAN hasIncludeRule = FALSE;
    BOOLEAN includeMatched = FALSE;

    if (Runtime == NULL || Runtime->Header == NULL) {
        return TRUE;
    }

    bucket = SysmonFindEventRuleBucket(Runtime, EventId);
    if (SysmonEventUsesConfigRules(EventId) && bucket == NULL) {
        return FALSE;
    }

    if (bucket == NULL) {
        return TRUE;
    }

    currentGroupIndex = SYSMON_RULE_EVENT_RULE_INDEX_GROUP_NONE;

    {
        BOOLEAN groupHasInclude = FALSE;
        BOOLEAN groupIncludeMatched = FALSE;
        BOOLEAN groupHasExclude = FALSE;
        BOOLEAN groupExcludeMatched = FALSE;
        BOOLEAN firstIncludeRule = TRUE;
        BOOLEAN firstExcludeRule = TRUE;

        for (bucketOffset = 0; bucketOffset < bucket->Count; bucketOffset++) {
            const SYSMON_RULE_EVENT_RULE_INDEX_REF *eventRuleRef =
                &Runtime->EventRuleRefs[bucket->Start + bucketOffset];
            const SYSMON_RULES_BLOB_EVENT_RULE *eventRule;
            const SYSMON_RULES_BLOB_GROUP *group;
            ULONG ruleIndex;
            BOOLEAN matched;

            if (eventRuleRef->GroupIndex == SYSMON_RULE_EVENT_RULE_INDEX_GROUP_NONE) {
                continue;
            }

            if (currentGroupIndex != SYSMON_RULE_EVENT_RULE_INDEX_GROUP_NONE &&
                eventRuleRef->GroupIndex < currentGroupIndex) {
                return FALSE;
            }

            if (currentGroupIndex != eventRuleRef->GroupIndex) {
                if (currentGroupIndex != SYSMON_RULE_EVENT_RULE_INDEX_GROUP_NONE &&
                    !SysmonFinalizeCaptureGroupResult(
                        groupHasInclude,
                        groupIncludeMatched,
                        groupHasExclude,
                        groupExcludeMatched,
                        &hasIncludeRule,
                        &includeMatched)) {
                    return FALSE;
                }

                currentGroupIndex = eventRuleRef->GroupIndex;
                groupHasInclude = FALSE;
                groupIncludeMatched = FALSE;
                groupHasExclude = FALSE;
                groupExcludeMatched = FALSE;
                firstIncludeRule = TRUE;
                firstExcludeRule = TRUE;
            }

            eventRule = &Runtime->EventRules[eventRuleRef->EventRuleIndex];
            group = &Runtime->Groups[currentGroupIndex];

            if (eventRule->RuleCount == 0) {
                /*
                 * Match original Sysmon semantics: an empty event node such as
                 * `<Event onmatch="include" />` or `<Event onmatch="exclude" />`
                 * applies to every occurrence of that event.
                 */
                matched = TRUE;
            } else {
                matched = (eventRule->Relation == SysmonRuleRelationAnd) ? TRUE : FALSE;
                for (ruleIndex = 0; ruleIndex < eventRule->RuleCount; ruleIndex++) {
                    BOOLEAN ruleMatched = SysmonEvaluateEventRule(
                        Runtime,
                        &Runtime->Rules[eventRule->RuleStart + ruleIndex],
                        Event);

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

        if (currentGroupIndex != SYSMON_RULE_EVENT_RULE_INDEX_GROUP_NONE &&
            !SysmonFinalizeCaptureGroupResult(
                groupHasInclude,
                groupIncludeMatched,
                groupHasExclude,
                groupExcludeMatched,
                &hasIncludeRule,
                &includeMatched)) {
            return FALSE;
        }
    }

    return !hasIncludeRule || includeMatched;
}

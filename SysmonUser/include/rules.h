#pragma once
/*
 * rules.h - Shared user-mode Sysmon rule model skeleton
 */

#include "common.h"
#include "event.h"

typedef enum _SYSMON_RULE_CONDITION {
    SysmonRuleConditionInvalid = 0,
    SysmonRuleConditionIs = 1,
    SysmonRuleConditionIsNot,
    SysmonRuleConditionContains,
    SysmonRuleConditionContainsAny,
    SysmonRuleConditionContainsAll,
    SysmonRuleConditionExcludes,
    SysmonRuleConditionExcludesAny,
    SysmonRuleConditionExcludesAll,
    SysmonRuleConditionBeginWith,
    SysmonRuleConditionEndWith,
    SysmonRuleConditionNotBeginWith,
    SysmonRuleConditionNotEndWith,
    SysmonRuleConditionLessThan,
    SysmonRuleConditionMoreThan,
    SysmonRuleConditionImage,
    SysmonRuleConditionIsAny
} SYSMON_RULE_CONDITION, *PSYSMON_RULE_CONDITION;

typedef enum _SYSMON_RULE_RELATION {
    SysmonRuleRelationInvalid = 0,
    SysmonRuleRelationOr = 1,
    SysmonRuleRelationAnd = 2
} SYSMON_RULE_RELATION, *PSYSMON_RULE_RELATION;

typedef enum _SYSMON_RULE_MATCH_TYPE {
    SysmonRuleMatchTypeInvalid = 0,
    SysmonRuleMatchTypeInclude = 1,
    SysmonRuleMatchTypeExclude = 2
} SYSMON_RULE_MATCH_TYPE, *PSYSMON_RULE_MATCH_TYPE;

typedef struct _SYSMON_RULE_EXPRESSION {
    LPWSTR FieldName;
    LPWSTR Value;
    SYSMON_RULE_CONDITION Condition;
} SYSMON_RULE_EXPRESSION, *PSYSMON_RULE_EXPRESSION;

typedef struct _SYSMON_RULE {
    LPWSTR Name;
    SYSMON_RULE_RELATION Relation;
    DWORD ExpressionCount;
    PSYSMON_RULE_EXPRESSION Expressions;
} SYSMON_RULE, *PSYSMON_RULE;

typedef struct _SYSMON_EVENT_RULE {
    SYSMON_EVENT_ID EventId;
    SYSMON_RULE_MATCH_TYPE MatchType;
    SYSMON_RULE_RELATION Relation;
    DWORD RuleCount;
    PSYSMON_RULE Rules;
} SYSMON_EVENT_RULE, *PSYSMON_EVENT_RULE;

typedef struct _SYSMON_RULE_GROUP {
    LPWSTR Name;
    SYSMON_RULE_RELATION Relation;
    DWORD EventRuleCount;
    PSYSMON_EVENT_RULE EventRules;
} SYSMON_RULE_GROUP, *PSYSMON_RULE_GROUP;

typedef struct _SYSMON_RULE_SET {
    DWORD GroupCount;
    PSYSMON_RULE_GROUP Groups;
} SYSMON_RULE_SET, *PSYSMON_RULE_SET;

#define SYSMON_RULES_BLOB_SIGNATURE       0x4C555253UL
#define SYSMON_RULES_BLOB_MAJOR_VERSION   1
#define SYSMON_RULES_BLOB_MINOR_VERSION   0
#define SYSMON_RULES_BLOB_OFFSET_NONE     0xFFFFFFFFUL

typedef struct _SYSMON_RULES_BLOB_HEADER {
    ULONG Signature;
    USHORT MajorVersion;
    USHORT MinorVersion;
    ULONG TotalSize;
    ULONG GroupCount;
    ULONG EventRuleCount;
    ULONG RuleCount;
    ULONG ExpressionCount;
    ULONG StringBytes;
    ULONG GroupOffset;
    ULONG EventRuleOffset;
    ULONG RuleOffset;
    ULONG ExpressionOffset;
    ULONG StringOffset;
} SYSMON_RULES_BLOB_HEADER, *PSYSMON_RULES_BLOB_HEADER;

typedef struct _SYSMON_RULES_BLOB_GROUP {
    ULONG NameOffset;
    ULONG Relation;
    ULONG EventRuleStart;
    ULONG EventRuleCount;
} SYSMON_RULES_BLOB_GROUP, *PSYSMON_RULES_BLOB_GROUP;

typedef struct _SYSMON_RULES_BLOB_EVENT_RULE {
    ULONG EventId;
    ULONG MatchType;
    ULONG Relation;
    ULONG RuleStart;
    ULONG RuleCount;
} SYSMON_RULES_BLOB_EVENT_RULE, *PSYSMON_RULES_BLOB_EVENT_RULE;

typedef struct _SYSMON_RULES_BLOB_RULE {
    ULONG NameOffset;
    ULONG Relation;
    ULONG ExpressionStart;
    ULONG ExpressionCount;
} SYSMON_RULES_BLOB_RULE, *PSYSMON_RULES_BLOB_RULE;

typedef struct _SYSMON_RULES_BLOB_EXPRESSION {
    ULONG FieldNameOffset;
    ULONG ValueOffset;
    ULONG Condition;
} SYSMON_RULES_BLOB_EXPRESSION, *PSYSMON_RULES_BLOB_EXPRESSION;

typedef struct _SYSMON_RULES_BLOB_INFO {
    USHORT MajorVersion;
    USHORT MinorVersion;
    ULONG TotalSize;
    ULONG GroupCount;
    ULONG EventRuleCount;
    ULONG RuleCount;
    ULONG ExpressionCount;
    ULONG StringBytes;
} SYSMON_RULES_BLOB_INFO, *PSYSMON_RULES_BLOB_INFO;

typedef struct _SYSMON_RULE_RUNTIME {
    DWORD BlobSize;
    PBYTE BlobStorage;
    const SYSMON_RULES_BLOB_HEADER *Header;
    const SYSMON_RULES_BLOB_GROUP *Groups;
    const SYSMON_RULES_BLOB_EVENT_RULE *EventRules;
    const SYSMON_RULES_BLOB_RULE *Rules;
    const SYSMON_RULES_BLOB_EXPRESSION *Expressions;
    const WCHAR *StringTable;
} SYSMON_RULE_RUNTIME, *PSYSMON_RULE_RUNTIME;

typedef enum _SYSMON_IMAGE_RULE_REQUIREMENTS {
    SysmonImageRuleRequirementNone            = 0x00000000UL,
    SysmonImageRuleRequirementHashes          = 0x00000001UL,
    SysmonImageRuleRequirementVersionInfo     = 0x00000002UL,
    SysmonImageRuleRequirementUserModeFields  = 0x00000004UL
} SYSMON_IMAGE_RULE_REQUIREMENTS;

BOOL
SysmonRuleParseCondition(
    _In_ LPCWSTR Text,
    _Out_ PSYSMON_RULE_CONDITION Condition);

BOOL
SysmonRuleParseRelation(
    _In_ LPCWSTR Text,
    _Out_ PSYSMON_RULE_RELATION Relation);

SYSMON_STATUS
SysmonSerializeRules(
    _In_ const SYSMON_RULE_SET *RuleSet,
    _Outptr_result_bytebuffer_(*BlobSize) PBYTE *Blob,
    _Out_ PDWORD BlobSize);

SYSMON_STATUS
SysmonQueryRuleBlobInfo(
    _In_reads_bytes_(BlobSize) const BYTE *Blob,
    _In_ DWORD BlobSize,
    _Out_ PSYSMON_RULES_BLOB_INFO BlobInfo);

SYSMON_STATUS
SysmonLoadRuleRuntime(
    _In_reads_bytes_(BlobSize) const BYTE *Blob,
    _In_ DWORD BlobSize,
    _Outptr_ PSYSMON_RULE_RUNTIME *Runtime);

void
SysmonFreeRuleRuntime(
    _In_opt_ PSYSMON_RULE_RUNTIME Runtime);

BOOL
SysmonRuleRuntimeHasEvent(
    _In_opt_ PSYSMON_RULE_RUNTIME Runtime,
    _In_ SYSMON_EVENT_ID EventId);

BOOL
SysmonRuleRuntimeEventCanProduceLogs(
    _In_opt_ PSYSMON_RULE_RUNTIME Runtime,
    _In_ SYSMON_EVENT_ID EventId);

BOOL
SysmonRuleRuntimeHasAnyEvent(
    _In_opt_ PSYSMON_RULE_RUNTIME Runtime,
    _In_reads_(EventIdCount) const SYSMON_EVENT_ID *EventIds,
    _In_ DWORD EventIdCount);

BOOL
SysmonRuleRuntimeEventHasIncludeRules(
    _In_opt_ PSYSMON_RULE_RUNTIME Runtime,
    _In_ SYSMON_EVENT_ID EventId);

BOOL
SysmonCanEarlyRejectImageEvent(
    _In_opt_ PSYSMON_RULE_RUNTIME Runtime,
    _In_ SYSMON_EVENT_ID EventId,
    _In_reads_bytes_(EventSize) const BYTE *EventData,
    _In_ DWORD EventSize);

BOOL
SysmonShouldCaptureEvent(
    _In_opt_ PSYSMON_RULE_RUNTIME Runtime,
    _In_ SYSMON_EVENT_ID EventId,
    _In_reads_bytes_(EventSize) const BYTE *EventData,
    _In_ DWORD EventSize);

BOOL
SysmonEventFilterRequiresUserModeEnrichment(
    _In_opt_ PSYSMON_RULE_RUNTIME Runtime,
    _In_ SYSMON_EVENT_ID EventId);

DWORD
SysmonGetImageRuleRequirements(
    _In_opt_ PSYSMON_RULE_RUNTIME Runtime,
    _In_ SYSMON_EVENT_ID EventId);

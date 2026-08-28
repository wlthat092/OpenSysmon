#pragma once

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

#define SYSMON_RULE_RESOLVED_EXPRESSION_FIELD_VALID 0x0001
#define SYSMON_RULE_RESOLVED_EXPRESSION_AMBIGUOUS   0x0002

typedef struct _SYSMON_RULE_RESOLVED_EXPRESSION {
    SYSMON_RESOLVED_EVENT_FIELD Field;
    USHORT Flags;
    USHORT Reserved;
} SYSMON_RULE_RESOLVED_EXPRESSION, *PSYSMON_RULE_RESOLVED_EXPRESSION;

typedef struct _SYSMON_RULE_EVENT_RULE_INDEX_BUCKET {
    ULONG EventId;
    ULONG Start;
    ULONG Count;
} SYSMON_RULE_EVENT_RULE_INDEX_BUCKET, *PSYSMON_RULE_EVENT_RULE_INDEX_BUCKET;

typedef struct _SYSMON_RULE_EVENT_RULE_INDEX_REF {
    ULONG GroupIndex;
    ULONG EventRuleIndex;
} SYSMON_RULE_EVENT_RULE_INDEX_REF, *PSYSMON_RULE_EVENT_RULE_INDEX_REF;

typedef struct _SYSMON_RULE_RUNTIME {
    EX_RUNDOWN_REF RundownRef;
    ULONG Options;
    ULONG HashingAlgorithm;
    BOOLEAN CheckRevocation;
    BOOLEAN DnsLookup;
    ULONG DriverQueueSize;
    ULONG SigningQueueSize;
    BOOLEAN CopyOnDeletePE;
    UNICODE_STRING ArchiveDirectoryComponent;
    PWCHAR CopyOnDeleteSIDsMultiSz;
    ULONG CopyOnDeleteSIDsBytes;
    PWCHAR CopyOnDeleteExtensionsMultiSz;
    ULONG CopyOnDeleteExtensionsBytes;
    PWCHAR CopyOnDeleteProcessesMultiSz;
    ULONG CopyOnDeleteProcessesBytes;
    ULONG BlobSize;
    PVOID BlobStorage;
    const SYSMON_RULES_BLOB_HEADER *Header;
    const SYSMON_RULES_BLOB_GROUP *Groups;
    const SYSMON_RULES_BLOB_EVENT_RULE *EventRules;
    const SYSMON_RULES_BLOB_RULE *Rules;
    const SYSMON_RULES_BLOB_EXPRESSION *Expressions;
    SYSMON_RULE_RESOLVED_EXPRESSION *ResolvedExpressions;
    SYSMON_RULE_EVENT_RULE_INDEX_BUCKET *EventRuleBuckets;
    ULONG EventRuleBucketCount;
    SYSMON_RULE_EVENT_RULE_INDEX_REF *EventRuleRefs;
    const WCHAR *StringTable;
} SYSMON_RULE_RUNTIME, *PSYSMON_RULE_RUNTIME;

typedef enum _SYSMON_IMAGE_RULE_REQUIREMENTS {
    SysmonImageRuleRequirementNone            = 0x00000000UL,
    SysmonImageRuleRequirementHashes          = 0x00000001UL,
    SysmonImageRuleRequirementVersionInfo     = 0x00000002UL,
    SysmonImageRuleRequirementUserModeFields  = 0x00000004UL
} SYSMON_IMAGE_RULE_REQUIREMENTS;

typedef enum _SYSMON_PROCESS_ACCESS_RULE_REQUIREMENTS {
    SysmonProcessAccessRuleRequirementNone       = 0x00000000UL,
    SysmonProcessAccessRuleRequirementSourceUser = 0x00000001UL,
    SysmonProcessAccessRuleRequirementTargetUser = 0x00000002UL,
    SysmonProcessAccessRuleRequirementCallTrace  = 0x00000004UL
} SYSMON_PROCESS_ACCESS_RULE_REQUIREMENTS;

NTSTATUS
SysmonCreateEmptyRuleRuntime(
    _Outptr_ PSYSMON_RULE_RUNTIME *Runtime);

NTSTATUS
SysmonLoadRuleRuntime(
    _In_reads_bytes_(BlobSize) const UCHAR *Blob,
    _In_ ULONG BlobSize,
    _Outptr_ PSYSMON_RULE_RUNTIME *Runtime);

VOID
SysmonFreeRuleRuntime(
    _In_opt_ PSYSMON_RULE_RUNTIME Runtime);

BOOLEAN
SysmonRuleRuntimeHasEvent(
    _In_opt_ PSYSMON_RULE_RUNTIME Runtime,
    _In_ SYSMON_EVENT_ID EventId);

BOOLEAN
SysmonRuleRuntimeEventCanProduceLogs(
    _In_opt_ PSYSMON_RULE_RUNTIME Runtime,
    _In_ SYSMON_EVENT_ID EventId);

BOOLEAN
SysmonRuleRuntimeHasAnyEvent(
    _In_opt_ PSYSMON_RULE_RUNTIME Runtime,
    _In_reads_(EventIdCount) const SYSMON_EVENT_ID *EventIds,
    _In_ ULONG EventIdCount);

BOOLEAN
SysmonShouldCaptureEvent(
    _In_opt_ PSYSMON_RULE_RUNTIME Runtime,
    _In_ SYSMON_EVENT_ID EventId,
    _In_ PSYSMON_EVENT_UNION Event);

BOOLEAN
SysmonEventFilterRequiresUserModeEnrichment(
    _In_opt_ PSYSMON_RULE_RUNTIME Runtime,
    _In_ SYSMON_EVENT_ID EventId);

BOOLEAN
SysmonShouldCollectImageVersionInfoForEvent(
    _In_opt_ PSYSMON_RULE_RUNTIME Runtime,
    _In_ SYSMON_EVENT_ID EventId,
    _In_ PSYSMON_EVENT_UNION Event);

ULONG
SysmonGetImageRuleRequirements(
    _In_opt_ PSYSMON_RULE_RUNTIME Runtime,
    _In_ SYSMON_EVENT_ID EventId);

ULONG
SysmonGetProcessAccessRuleRequirements(
    _In_opt_ PSYSMON_RULE_RUNTIME Runtime);

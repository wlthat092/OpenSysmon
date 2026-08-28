/*
 * xml_config.c - Sysmon XML config parsing into the shared rule model
 */

#define COBJMACROS
#include <xmllite.h>
#include <ole2.h>
#include <sddl.h>
#include <wctype.h>

#include "../include/config.h"
#include "../include/event_schema.h"

static BOOL
SysmonXmlFieldNameIsKnown(
    _In_reads_(NameChars) LPCWSTR Name,
    _In_ size_t NameChars)
{
    DWORD eventId;

    if (Name == NULL || NameChars == 0 || NameChars >= 128) {
        return FALSE;
    }
    for (eventId = 1; eventId <= SysmonEventFileExecutableDetected; eventId++) {
        const SYSMON_EVENT_SCHEMA *schema = GetEventSchema((SYSMON_EVENT_ID)eventId);
        DWORD fieldIndex;
        if (schema == NULL) {
            continue;
        }
        for (fieldIndex = 0; fieldIndex < schema->FieldCount; fieldIndex++) {
            if (wcslen(schema->Fields[fieldIndex].Name) == NameChars &&
                _wcsnicmp(schema->Fields[fieldIndex].Name, Name, NameChars) == 0) {
                return TRUE;
            }
        }
    }
    return FALSE;
}

BOOL
SysmonValidateFieldSizesText(
    _In_opt_z_ LPCWSTR Text)
{
    const WCHAR *cursor;

    if (Text == NULL || Text[0] == L'\0') {
        return TRUE;
    }
    cursor = Text;
    while (*cursor != L'\0') {
        const WCHAR *tokenEnd = wcschr(cursor, L',');
        const WCHAR *colon;
        const WCHAR *nameEnd;
        const WCHAR *value;
        ULONGLONG number = 0;

        if (tokenEnd == NULL) {
            tokenEnd = cursor + wcslen(cursor);
        }
        while (cursor < tokenEnd && iswspace(*cursor)) {
            cursor++;
        }
        if (cursor == tokenEnd) {
            return FALSE;
        }
        colon = wcschr(cursor, L':');
        if (colon == NULL || colon >= tokenEnd) {
            return FALSE;
        }
        nameEnd = colon;
        while (nameEnd > cursor && iswspace(*(nameEnd - 1))) {
            nameEnd--;
        }
        if (!SysmonXmlFieldNameIsKnown(cursor, (size_t)(nameEnd - cursor))) {
            return FALSE;
        }
        value = colon + 1;
        while (value < tokenEnd && iswspace(*value)) {
            value++;
        }
        if (value == tokenEnd) {
            return FALSE;
        }
        while (value < tokenEnd && *value >= L'0' && *value <= L'9') {
            number = number * 10 + (ULONG)(*value - L'0');
            if (number > 1024 * 1024) {
                return FALSE;
            }
            value++;
        }
        while (value < tokenEnd && iswspace(*value)) {
            value++;
        }
        if (value != tokenEnd || number == 0) {
            return FALSE;
        }
        if (*tokenEnd == L',') {
            cursor = tokenEnd + 1;
            if (*cursor == L'\0') {
                return FALSE;
            }
        } else {
            cursor = tokenEnd;
        }
    }
    return TRUE;
}

typedef struct _SYSMON_XML_ATTRIBUTE {
    LPWSTR Name;
    LPWSTR Value;
} SYSMON_XML_ATTRIBUTE, *PSYSMON_XML_ATTRIBUTE;

typedef struct _SYSMON_XML_NODE {
    LPWSTR Name;
    LPWSTR Text;
    DWORD AttributeCount;
    SYSMON_XML_ATTRIBUTE *Attributes;
    DWORD ChildCount;
    struct _SYSMON_XML_NODE **Children;
} SYSMON_XML_NODE, *PSYSMON_XML_NODE;

typedef struct _SYSMON_EVENT_NODE_MAPPING {
    LPCWSTR XmlName;
    DWORD EventCount;
    SYSMON_EVENT_ID EventIds[3];
} SYSMON_EVENT_NODE_MAPPING, *PSYSMON_EVENT_NODE_MAPPING;

static const SYSMON_EVENT_NODE_MAPPING g_SysmonEventNodeMappings[] = {
    { L"ProcessCreate", 1, { SysmonEventProcessCreate } },
    { L"FileCreateTime", 1, { SysmonEventFileCreateTime } },
    { L"NetworkConnect", 1, { SysmonEventNetworkConnect } },
    { L"ProcessTerminate", 1, { SysmonEventProcessTerminate } },
    { L"DriverLoad", 1, { SysmonEventDriverLoad } },
    { L"ImageLoad", 1, { SysmonEventImageLoad } },
    { L"CreateRemoteThread", 1, { SysmonEventCreateRemoteThread } },
    { L"RawAccessRead", 1, { SysmonEventRawAccessRead } },
    { L"ProcessAccess", 1, { SysmonEventProcessAccess } },
    { L"FileCreate", 1, { SysmonEventFileCreate } },
    { L"RegistryEvent", 3, { SysmonEventRegistryEvent, SysmonEventRegistryValueSet, SysmonEventRegistryRename } },
    { L"RegistryValueSet", 1, { SysmonEventRegistryValueSet } },
    { L"RegistryRename", 1, { SysmonEventRegistryRename } },
    { L"FileCreateStreamHash", 1, { SysmonEventFileCreateStreamHash } },
    { L"PipeEvent", 2, { SysmonEventPipeCreated, SysmonEventPipeConnected } },
    { L"WmiEvent", 3, { SysmonEventWmiFilter, SysmonEventWmiConsumer, SysmonEventWmiConsumerToFilter } },
    { L"DnsQuery", 1, { SysmonEventDnsQuery } },
    { L"FileDelete", 1, { SysmonEventFileDelete } },
    { L"ClipboardChange", 1, { SysmonEventClipboardChange } },
    { L"ProcessTampering", 1, { SysmonEventProcessTampering } },
    { L"FileDeleteDetected", 1, { SysmonEventFileDeleteDetected } },
    { L"FileBlockExecutable", 1, { SysmonEventFileBlockExecutable } },
    { L"FileBlockShredding", 1, { SysmonEventFileBlockShredding } },
    { L"FileExecutableDetected", 1, { SysmonEventFileExecutableDetected } }
};

static LPWSTR
SysmonXmlDuplicateString(
    _In_reads_(Length) const WCHAR *Text,
    _In_ UINT Length)
{
    SIZE_T size;
    LPWSTR copy;

    if ((SIZE_T)Length > ((((SIZE_T)-1) / sizeof(WCHAR)) - 1)) {
        return NULL;
    }

    size = ((SIZE_T)Length + 1) * sizeof(WCHAR);
    copy = (LPWSTR)SYSMON_ALLOC(size);
    if (copy == NULL) {
        return NULL;
    }

    if (Length != 0) {
        memcpy(copy, Text, (SIZE_T)Length * sizeof(WCHAR));
    }

    copy[Length] = L'\0';
    return copy;
}

static BOOL
SysmonXmlIsWhitespaceOnly(
    _In_reads_(Length) const WCHAR *Text,
    _In_ UINT Length)
{
    UINT index;

    for (index = 0; index < Length; index++) {
        if (!iswspace(Text[index])) {
            return FALSE;
        }
    }

    return TRUE;
}

static LPWSTR
SysmonXmlDuplicateTrimmedString(
    _In_opt_ LPCWSTR Text)
{
    const WCHAR *start;
    const WCHAR *end;

    if (Text == NULL) {
        return NULL;
    }

    start = Text;
    while (*start != L'\0' && iswspace(*start)) {
        start++;
    }

    end = start + wcslen(start);
    while (end > start && iswspace(*(end - 1))) {
        end--;
    }

    return SysmonXmlDuplicateString(start, (UINT)(end - start));
}

static LPWSTR
SysmonXmlDuplicateTrimmedRange(
    _In_reads_(Length) const WCHAR *Text,
    _In_ UINT Length)
{
    const WCHAR *start;
    const WCHAR *end;

    if (Text == NULL) {
        return NULL;
    }

    start = Text;
    end = Text + Length;

    while (start < end && iswspace(*start)) {
        start++;
    }

    while (end > start && iswspace(*(end - 1))) {
        end--;
    }

    return SysmonXmlDuplicateString(start, (UINT)(end - start));
}

static SYSMON_STATUS
SysmonXmlAppendBuffer(
    _Inout_ LPWSTR *Buffer,
    _In_ UINT ExistingLength,
    _In_reads_(AppendLength) const WCHAR *AppendText,
    _In_ UINT AppendLength)
{
    SIZE_T size;
    LPWSTR merged;

    size = ((SIZE_T)ExistingLength + AppendLength + 1) * sizeof(WCHAR);
    merged = (LPWSTR)SYSMON_ALLOC(size);
    if (merged == NULL) {
        return SYSMON_ERROR_OUT_OF_MEMORY;
    }

    if (*Buffer != NULL && ExistingLength != 0) {
        memcpy(merged, *Buffer, (SIZE_T)ExistingLength * sizeof(WCHAR));
    }

    if (AppendLength != 0) {
        memcpy(merged + ExistingLength, AppendText, (SIZE_T)AppendLength * sizeof(WCHAR));
    }

    merged[ExistingLength + AppendLength] = L'\0';
    SYSMON_FREE(*Buffer);
    *Buffer = merged;
    return SYSMON_SUCCESS;
}

static SYSMON_STATUS
SysmonXmlGrowArray(
    _Inout_ PVOID *Array,
    _In_ SIZE_T OldCount,
    _In_ SIZE_T NewCount,
    _In_ SIZE_T ElementSize)
{
    PBYTE grown;

    grown = (PBYTE)SYSMON_ALLOC(NewCount * ElementSize);
    if (grown == NULL) {
        return SYSMON_ERROR_OUT_OF_MEMORY;
    }

    if (*Array != NULL && OldCount != 0) {
        memcpy(grown, *Array, OldCount * ElementSize);
    }

    SYSMON_FREE(*Array);
    *Array = grown;
    return SYSMON_SUCCESS;
}

static void
SysmonXmlFreeNode(
    _In_opt_ PSYSMON_XML_NODE Node)
{
    DWORD index;

    if (Node == NULL) {
        return;
    }

    for (index = 0; index < Node->ChildCount; index++) {
        SysmonXmlFreeNode(Node->Children[index]);
    }

    for (index = 0; index < Node->AttributeCount; index++) {
        SYSMON_FREE(Node->Attributes[index].Name);
        SYSMON_FREE(Node->Attributes[index].Value);
    }

    SYSMON_FREE(Node->Name);
    SYSMON_FREE(Node->Text);
    SYSMON_FREE(Node->Attributes);
    SYSMON_FREE(Node->Children);
    SYSMON_FREE(Node);
}

static void
SysmonFreeRule(
    _Inout_ PSYSMON_RULE Rule)
{
    DWORD index;

    if (Rule == NULL) {
        return;
    }

    SYSMON_FREE(Rule->Name);

    for (index = 0; index < Rule->ExpressionCount; index++) {
        LPWSTR fieldName = const_cast<LPWSTR>(Rule->Expressions[index].FieldName);
        SYSMON_FREE(fieldName);
        SYSMON_FREE(Rule->Expressions[index].Value);
    }

    SYSMON_FREE(Rule->Expressions);
    ZeroMemory(Rule, sizeof(*Rule));
}

static void
SysmonFreeEventRule(
    _Inout_ PSYSMON_EVENT_RULE EventRule)
{
    DWORD index;

    if (EventRule == NULL) {
        return;
    }

    for (index = 0; index < EventRule->RuleCount; index++) {
        SysmonFreeRule(&EventRule->Rules[index]);
    }

    SYSMON_FREE(EventRule->Rules);
    ZeroMemory(EventRule, sizeof(*EventRule));
}

static void
SysmonFreeRuleGroupContents(
    _Inout_ PSYSMON_RULE_GROUP Group)
{
    DWORD eventIndex;

    if (Group == NULL) {
        return;
    }

    SYSMON_FREE(Group->Name);

    for (eventIndex = 0; eventIndex < Group->EventRuleCount; eventIndex++) {
        SysmonFreeEventRule(&Group->EventRules[eventIndex]);
    }

    SYSMON_FREE(Group->EventRules);
    ZeroMemory(Group, sizeof(*Group));
}

void
SysmonFreeParsedXmlConfig(
    PSYSMON_CONFIG Config)
{
    SysmonConfigFree(Config);
}

static SYSMON_STATUS
SysmonXmlCreateNode(
    _In_reads_(NameLength) const WCHAR *Name,
    _In_ UINT NameLength,
    _Out_ PSYSMON_XML_NODE *Node)
{
    PSYSMON_XML_NODE created;

    *Node = NULL;

    created = (PSYSMON_XML_NODE)SYSMON_ALLOC(sizeof(*created));
    if (created == NULL) {
        return SYSMON_ERROR_OUT_OF_MEMORY;
    }

    ZeroMemory(created, sizeof(*created));
    created->Name = SysmonXmlDuplicateString(Name, NameLength);
    if (created->Name == NULL) {
        SysmonXmlFreeNode(created);
        return SYSMON_ERROR_OUT_OF_MEMORY;
    }

    *Node = created;
    return SYSMON_SUCCESS;
}

static SYSMON_STATUS
SysmonXmlAddAttribute(
    _Inout_ PSYSMON_XML_NODE Node,
    _In_reads_(NameLength) const WCHAR *Name,
    _In_ UINT NameLength,
    _In_reads_(ValueLength) const WCHAR *Value,
    _In_ UINT ValueLength)
{
    SYSMON_STATUS status;
    PSYSMON_XML_ATTRIBUTE attribute;

    status = SysmonXmlGrowArray(
        (PVOID*)&Node->Attributes,
        Node->AttributeCount,
        Node->AttributeCount + 1,
        sizeof(Node->Attributes[0]));
    if (status != SYSMON_SUCCESS) {
        return status;
    }

    attribute = &Node->Attributes[Node->AttributeCount];
    ZeroMemory(attribute, sizeof(*attribute));

    attribute->Name = SysmonXmlDuplicateString(Name, NameLength);
    attribute->Value = SysmonXmlDuplicateString(Value, ValueLength);
    if (attribute->Name == NULL || attribute->Value == NULL) {
        SYSMON_FREE(attribute->Name);
        SYSMON_FREE(attribute->Value);
        return SYSMON_ERROR_OUT_OF_MEMORY;
    }

    Node->AttributeCount++;
    return SYSMON_SUCCESS;
}

static SYSMON_STATUS
SysmonXmlAddChild(
    _Inout_ PSYSMON_XML_NODE Parent,
    _Inout_ PSYSMON_XML_NODE Child)
{
    SYSMON_STATUS status;

    status = SysmonXmlGrowArray(
        (PVOID*)&Parent->Children,
        Parent->ChildCount,
        Parent->ChildCount + 1,
        sizeof(Parent->Children[0]));
    if (status != SYSMON_SUCCESS) {
        return status;
    }

    Parent->Children[Parent->ChildCount] = Child;
    Parent->ChildCount++;
    return SYSMON_SUCCESS;
}

static SYSMON_STATUS
SysmonXmlAppendText(
    _Inout_ PSYSMON_XML_NODE Node,
    _In_reads_(TextLength) const WCHAR *Text,
    _In_ UINT TextLength)
{
    UINT existingLength = 0;

    if (Node->Text != NULL) {
        existingLength = (UINT)wcslen(Node->Text);
    }

    return SysmonXmlAppendBuffer(&Node->Text, existingLength, Text, TextLength);
}

static LPCWSTR
SysmonXmlGetAttribute(
    _In_ const SYSMON_XML_NODE *Node,
    _In_ LPCWSTR Name)
{
    DWORD index;

    if (Node == NULL || Name == NULL) {
        return NULL;
    }

    for (index = 0; index < Node->AttributeCount; index++) {
        if (_wcsicmp(Node->Attributes[index].Name, Name) == 0) {
            return Node->Attributes[index].Value;
        }
    }

    return NULL;
}

static const SYSMON_XML_NODE *
SysmonXmlFindChild(
    _In_ const SYSMON_XML_NODE *Node,
    _In_ LPCWSTR Name)
{
    DWORD index;

    if (Node == NULL || Name == NULL) {
        return NULL;
    }

    for (index = 0; index < Node->ChildCount; index++) {
        if (_wcsicmp(Node->Children[index]->Name, Name) == 0) {
            return Node->Children[index];
        }
    }

    return NULL;
}

static BOOL
SysmonXmlTryParseBoolean(
    _In_opt_ LPCWSTR Text,
    _Out_ PBOOL Value)
{
    LPWSTR trimmed;
    BOOL success = FALSE;

    if (Value == NULL) {
        return FALSE;
    }

    trimmed = SysmonXmlDuplicateTrimmedString(Text);
    if (trimmed == NULL) {
        return FALSE;
    }

    if (_wcsicmp(trimmed, L"true") == 0 ||
        _wcsicmp(trimmed, L"yes") == 0 ||
        wcscmp(trimmed, L"1") == 0) {
        *Value = TRUE;
        success = TRUE;
    } else if (_wcsicmp(trimmed, L"false") == 0 ||
        _wcsicmp(trimmed, L"no") == 0 ||
        wcscmp(trimmed, L"0") == 0) {
        *Value = FALSE;
        success = TRUE;
    }

    SYSMON_FREE(trimmed);
    return success;
}

static BOOL
SysmonXmlTryParseDword(
    _In_opt_ LPCWSTR Text,
    _Out_ PDWORD Value)
{
    LPWSTR trimmed;
    WCHAR *end = NULL;
    unsigned long parsed;

    if (Value == NULL) {
        return FALSE;
    }

    trimmed = SysmonXmlDuplicateTrimmedString(Text);
    if (trimmed == NULL || trimmed[0] == L'\0') {
        SYSMON_FREE(trimmed);
        return FALSE;
    }

    parsed = wcstoul(trimmed, &end, 10);
    if (end == NULL || *end != L'\0') {
        SYSMON_FREE(trimmed);
        return FALSE;
    }

    *Value = (DWORD)parsed;
    SYSMON_FREE(trimmed);
    return TRUE;
}

static SYSMON_STATUS
SysmonParseHashAlgorithmsText(
    _In_opt_ LPCWSTR Text,
    _Out_ PDWORD HashingAlgorithm)
{
    LPWSTR trimmed;
    LPWSTR cursor;
    DWORD mask = 0;

    if (HashingAlgorithm == NULL) {
        return SYSMON_ERROR_INVALID_PARAM;
    }

    *HashingAlgorithm = SYSMON_HASH_DEFAULT;

    trimmed = SysmonXmlDuplicateTrimmedString(Text);
    if (trimmed == NULL || trimmed[0] == L'\0') {
        SYSMON_FREE(trimmed);
        return SYSMON_SUCCESS;
    }

    if (wcscmp(trimmed, L"*") == 0 || _wcsicmp(trimmed, L"all") == 0) {
        *HashingAlgorithm = SYSMON_HASH_MD5 | SYSMON_HASH_SHA1 | SYSMON_HASH_SHA256 | SYSMON_HASH_IMPHASH;
        SYSMON_FREE(trimmed);
        return SYSMON_SUCCESS;
    }

    cursor = trimmed;
    while (*cursor != L'\0') {
        LPWSTR token = cursor;

        while (*cursor != L'\0' && *cursor != L',' && *cursor != L';') {
            cursor++;
        }

        if (*cursor != L'\0') {
            *cursor = L'\0';
            cursor++;
        }

        while (*token != L'\0' && iswspace(*token)) {
            token++;
        }

        {
            WCHAR *end = token + wcslen(token);
            while (end > token && iswspace(*(end - 1))) {
                end--;
            }
            *end = L'\0';
        }

        if (*token == L'\0') {
            continue;
        }

        if (_wcsicmp(token, L"md5") == 0) {
            mask |= SYSMON_HASH_MD5;
        } else if (_wcsicmp(token, L"sha1") == 0) {
            mask |= SYSMON_HASH_SHA1;
        } else if (_wcsicmp(token, L"sha256") == 0) {
            mask |= SYSMON_HASH_SHA256;
        } else if (_wcsicmp(token, L"imphash") == 0) {
            mask |= SYSMON_HASH_IMPHASH;
        } else if (_wcsicmp(token, L"*") == 0) {
            mask |= SYSMON_HASH_MD5 |
                SYSMON_HASH_SHA1 |
                SYSMON_HASH_SHA256 |
                SYSMON_HASH_IMPHASH;
        } else {
            SysmonLogWarning(SYSMON_COMPONENT_CONFIG,
                "Ignoring unknown HashAlgorithms token '%ls'", token);
        }
    }

    if (mask != 0) {
        *HashingAlgorithm = mask;
    }

    SYSMON_FREE(trimmed);
    return SYSMON_SUCCESS;
}

static SYSMON_RULE_RELATION
SysmonParseRelationOrDefault(
    _In_opt_ LPCWSTR Text,
    _In_ SYSMON_RULE_RELATION DefaultValue)
{
    SYSMON_RULE_RELATION relation;

    if (Text != NULL && SysmonRuleParseRelation(Text, &relation)) {
        return relation;
    }

    return DefaultValue;
}

static SYSMON_STATUS
SysmonParseMatchTypeAttributes(
    _In_ const SYSMON_XML_NODE *Node,
    _Out_ PSYSMON_RULE_MATCH_TYPE MatchType)
{
    LPCWSTR onMatchText;
    LPCWSTR defaultText;
    LPCWSTR effectiveText;

    if (Node == NULL || MatchType == NULL) {
        return SYSMON_ERROR_INVALID_PARAM;
    }

    onMatchText = SysmonXmlGetAttribute(Node, L"onmatch");
    defaultText = SysmonXmlGetAttribute(Node, L"default");
    if (onMatchText != NULL && defaultText != NULL) {
        SysmonLogError(
            SYSMON_COMPONENT_CONFIG,
            ERROR_INVALID_DATA,
            "Can't specify both onmatch and default on %ls",
            Node->Name);
        return ERROR_INVALID_DATA;
    }

    effectiveText = (onMatchText != NULL) ? onMatchText : defaultText;
    if (effectiveText == NULL) {
        SysmonLogError(
            SYSMON_COMPONENT_CONFIG,
            ERROR_INVALID_DATA,
            "You need to specify onmatch or default on %ls",
            Node->Name);
        return ERROR_INVALID_DATA;
    }

    if (_wcsicmp(effectiveText, L"exclude") == 0) {
        *MatchType = SysmonRuleMatchTypeExclude;
        return SYSMON_SUCCESS;
    }

    if (_wcsicmp(effectiveText, L"include") == 0) {
        *MatchType = SysmonRuleMatchTypeInclude;
        return SYSMON_SUCCESS;
    }

    SysmonLogError(
        SYSMON_COMPONENT_CONFIG,
        ERROR_INVALID_DATA,
        "Unsupported match type '%ls' on %ls",
        effectiveText,
        Node->Name);
    return ERROR_INVALID_DATA;
}

static BOOL
SysmonXmlIsPathLikeField(
    _In_opt_ LPCWSTR FieldName)
{
    return FieldName != NULL &&
        (_wcsicmp(FieldName, L"Image") == 0 ||
         _wcsicmp(FieldName, L"ParentImage") == 0 ||
         _wcsicmp(FieldName, L"ImageLoaded") == 0 ||
         _wcsicmp(FieldName, L"TargetFilename") == 0 ||
         _wcsicmp(FieldName, L"CurrentDirectory") == 0 ||
         _wcsicmp(FieldName, L"SourceImage") == 0 ||
         _wcsicmp(FieldName, L"TargetImage") == 0);
}

static BOOL
SysmonXmlIsUserLikeField(
    _In_opt_ LPCWSTR FieldName)
{
    return FieldName != NULL &&
        (_wcsicmp(FieldName, L"User") == 0 ||
         _wcsicmp(FieldName, L"ParentUser") == 0);
}

static BOOL
SysmonXmlConditionUsesTextTokens(
    _In_ SYSMON_RULE_CONDITION Condition)
{
    switch (Condition) {
    case SysmonRuleConditionIs:
    case SysmonRuleConditionIsNot:
    case SysmonRuleConditionContains:
    case SysmonRuleConditionContainsAny:
    case SysmonRuleConditionIsAny:
    case SysmonRuleConditionContainsAll:
    case SysmonRuleConditionExcludes:
    case SysmonRuleConditionExcludesAny:
    case SysmonRuleConditionExcludesAll:
    case SysmonRuleConditionBeginWith:
    case SysmonRuleConditionEndWith:
    case SysmonRuleConditionNotBeginWith:
    case SysmonRuleConditionNotEndWith:
    case SysmonRuleConditionImage:
        return TRUE;

    default:
        break;
    }

    return FALSE;
}

static BOOL
SysmonXmlConditionUsesTokenList(
    _In_ SYSMON_RULE_CONDITION Condition)
{
    return Condition == SysmonRuleConditionContainsAny ||
        Condition == SysmonRuleConditionIsAny ||
        Condition == SysmonRuleConditionContainsAll ||
        Condition == SysmonRuleConditionExcludesAny ||
        Condition == SysmonRuleConditionExcludesAll;
}

static BOOL
SysmonXmlLooksLikeDrivePath(
    _In_ LPCWSTR Text)
{
    return Text != NULL &&
        wcslen(Text) >= 3 &&
        iswalpha(Text[0]) &&
        Text[1] == L':' &&
        (Text[2] == L'\\' || Text[2] == L'/');
}

static BOOL
SysmonXmlLooksLikeQualifiedPath(
    _In_opt_ LPCWSTR Text)
{
    if (Text == NULL || Text[0] == L'\0') {
        return FALSE;
    }

    if (SysmonXmlLooksLikeDrivePath(Text)) {
        return TRUE;
    }

    return _wcsnicmp(Text, L"\\\\", 2) == 0 ||
        _wcsnicmp(Text, L"\\??\\", 4) == 0 ||
        _wcsnicmp(Text, L"\\\\?\\", 4) == 0 ||
        _wcsnicmp(Text, L"\\Device\\", 8) == 0 ||
        _wcsnicmp(Text, L"\\SystemRoot\\", 12) == 0;
}

static void
SysmonXmlCanonicalizePathSeparators(
    _Inout_ LPWSTR Text)
{
    while (Text != NULL && *Text != L'\0') {
        if (*Text == L'/') {
            *Text = L'\\';
        }
        Text++;
    }
}

static SYSMON_STATUS
SysmonXmlBuildConcatenatedString(
    _In_ LPCWSTR Prefix,
    _In_ LPCWSTR Suffix,
    _Out_ LPWSTR *Combined)
{
    SIZE_T prefixChars;
    SIZE_T suffixChars;
    LPWSTR buffer;

    *Combined = NULL;

    prefixChars = (Prefix != NULL) ? wcslen(Prefix) : 0;
    suffixChars = (Suffix != NULL) ? wcslen(Suffix) : 0;

    buffer = (LPWSTR)SYSMON_ALLOC((prefixChars + suffixChars + 1) * sizeof(WCHAR));
    if (buffer == NULL) {
        return SYSMON_ERROR_OUT_OF_MEMORY;
    }

    if (prefixChars != 0) {
        memcpy(buffer, Prefix, prefixChars * sizeof(WCHAR));
    }

    if (suffixChars != 0) {
        memcpy(buffer + prefixChars, Suffix, suffixChars * sizeof(WCHAR));
    }

    buffer[prefixChars + suffixChars] = L'\0';
    *Combined = buffer;
    return SYSMON_SUCCESS;
}

static BOOL
SysmonXmlIsRegistryLikeField(
    _In_opt_ LPCWSTR FieldName)
{
    return FieldName != NULL &&
        (_wcsicmp(FieldName, L"TargetObject") == 0 ||
         _wcsicmp(FieldName, L"NewName") == 0);
}

static BOOL
SysmonXmlQueryCurrentControlSetName(
    _Out_writes_(BufferChars) PWCHAR Buffer,
    _In_ size_t BufferChars)
{
    HKEY key = NULL;
    DWORD current = 0;
    DWORD type = REG_DWORD;
    DWORD size = sizeof(current);
    LONG result;

    if (Buffer == NULL || BufferChars < 14) {
        return FALSE;
    }

    Buffer[0] = L'\0';
    result = RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"SYSTEM\\Select", 0, KEY_QUERY_VALUE, &key);
    if (result != ERROR_SUCCESS) {
        return FALSE;
    }

    result = RegQueryValueExW(key, L"Current", NULL, &type, (LPBYTE)&current, &size);
    RegCloseKey(key);
    if (result != ERROR_SUCCESS || type != REG_DWORD) {
        return FALSE;
    }

    _snwprintf_s(Buffer, BufferChars, _TRUNCATE, L"ControlSet%03lu", (unsigned long)current);
    return TRUE;
}

static SYSMON_STATUS
SysmonXmlReplaceRegistryCurrentControlSet(
    _Inout_ LPWSTR *Text)
{
    static const WCHAR g_HardwareProfilesPrefix[] =
        L"\\REGISTRY\\MACHINE\\SYSTEM\\CurrentControlSet\\Hardware Profiles\\Current";
    static const WCHAR g_CurrentControlSetPrefix[] =
        L"\\REGISTRY\\MACHINE\\SYSTEM\\CurrentControlSet";
    WCHAR controlSetName[16];
    LPCWSTR suffix;
    LPWSTR replaced;
    size_t prefixChars;

    if (Text == NULL || *Text == NULL) {
        return SYSMON_ERROR_INVALID_PARAM;
    }

    if (_wcsnicmp(*Text, g_HardwareProfilesPrefix, _countof(g_HardwareProfilesPrefix) - 1) == 0) {
        return SYSMON_SUCCESS;
    }

    if (_wcsnicmp(*Text, g_CurrentControlSetPrefix, _countof(g_CurrentControlSetPrefix) - 1) != 0) {
        return SYSMON_SUCCESS;
    }

    if (!SysmonXmlQueryCurrentControlSetName(controlSetName, _countof(controlSetName))) {
        return SYSMON_SUCCESS;
    }

    prefixChars = wcslen(L"\\REGISTRY\\MACHINE\\SYSTEM\\");
    suffix = *Text + (_countof(g_CurrentControlSetPrefix) - 1);
    replaced = (LPWSTR)SYSMON_ALLOC((prefixChars + wcslen(controlSetName) + wcslen(suffix) + 1) * sizeof(WCHAR));
    if (replaced == NULL) {
        return SYSMON_ERROR_OUT_OF_MEMORY;
    }

    memcpy(replaced, L"\\REGISTRY\\MACHINE\\SYSTEM\\", prefixChars * sizeof(WCHAR));
    memcpy(replaced + prefixChars, controlSetName, wcslen(controlSetName) * sizeof(WCHAR));
    wcscpy_s(replaced + prefixChars + wcslen(controlSetName), wcslen(suffix) + 1, suffix);

    SYSMON_FREE(*Text);
    *Text = replaced;
    return SYSMON_SUCCESS;
}

static SYSMON_STATUS
SysmonXmlNormalizeRegistryToken(
    _In_opt_ LPCWSTR ValueText,
    _Out_ LPWSTR *NormalizedValue)
{
    typedef struct _SYSMON_REGISTRY_ALIAS {
        LPCWSTR Alias;
        LPCWSTR NativeRoot;
    } SYSMON_REGISTRY_ALIAS;

    static const SYSMON_REGISTRY_ALIAS g_Aliases[] = {
        { L"HKLM", L"\\REGISTRY\\MACHINE" },
        { L"HKEY_LOCAL_MACHINE", L"\\REGISTRY\\MACHINE" },
        { L"HKCR", L"\\REGISTRY\\MACHINE\\SOFTWARE\\Classes" },
        { L"HKEY_CLASSES_ROOT", L"\\REGISTRY\\MACHINE\\SOFTWARE\\Classes" },
        { L"HKCC", L"\\REGISTRY\\MACHINE\\SYSTEM\\CurrentControlSet\\Hardware Profiles\\Current" },
        { L"HKEY_CURRENT_CONFIG", L"\\REGISTRY\\MACHINE\\SYSTEM\\CurrentControlSet\\Hardware Profiles\\Current" },
        { L"HKU", L"\\REGISTRY\\USER" },
        { L"HKEY_USERS", L"\\REGISTRY\\USER" }
    };

    LPWSTR normalized;
    DWORD aliasIndex;

    *NormalizedValue = NULL;

    normalized = SysmonXmlDuplicateTrimmedString(ValueText);
    if (normalized == NULL) {
        return SYSMON_ERROR_OUT_OF_MEMORY;
    }

    if (normalized[0] == L'\0') {
        *NormalizedValue = normalized;
        return SYSMON_SUCCESS;
    }

    SysmonXmlCanonicalizePathSeparators(normalized);

    if (_wcsnicmp(normalized, L"\\REGISTRY\\", 10) == 0) {
        SYSMON_STATUS status = SysmonXmlReplaceRegistryCurrentControlSet(&normalized);
        if (status != SYSMON_SUCCESS) {
            SYSMON_FREE(normalized);
            return status;
        }

        *NormalizedValue = normalized;
        return SYSMON_SUCCESS;
    }

    for (aliasIndex = 0; aliasIndex < _countof(g_Aliases); aliasIndex++) {
        size_t aliasChars = wcslen(g_Aliases[aliasIndex].Alias);

        if (_wcsnicmp(normalized, g_Aliases[aliasIndex].Alias, aliasChars) != 0) {
            continue;
        }

        if (normalized[aliasChars] != L'\0' && normalized[aliasChars] != L'\\') {
            continue;
        }

        {
            SYSMON_STATUS status;
            LPWSTR converted;

            status = SysmonXmlBuildConcatenatedString(
                g_Aliases[aliasIndex].NativeRoot,
                normalized + aliasChars,
                &converted);
            SYSMON_FREE(normalized);
            if (status != SYSMON_SUCCESS) {
                return status;
            }

            normalized = converted;
            status = SysmonXmlReplaceRegistryCurrentControlSet(&normalized);
            if (status != SYSMON_SUCCESS) {
                SYSMON_FREE(normalized);
                return status;
            }

            *NormalizedValue = normalized;
            return SYSMON_SUCCESS;
        }
    }

    *NormalizedValue = normalized;
    return SYSMON_SUCCESS;
}

static SYSMON_STATUS
SysmonXmlNormalizePathToken(
    _In_ SYSMON_EVENT_ID EventId,
    _In_ LPCWSTR FieldName,
    _In_opt_ LPCWSTR ValueText,
    _Out_ LPWSTR *NormalizedValue)
{
    WCHAR devicePath[512];
    LPWSTR normalized;
    LPCWSTR pathText;
    DWORD deviceChars;
    BOOL useDosDeviceStylePath;

    *NormalizedValue = NULL;

    normalized = SysmonXmlDuplicateTrimmedString(ValueText);
    if (normalized == NULL) {
        return SYSMON_ERROR_OUT_OF_MEMORY;
    }

    if (normalized[0] == L'\0' || !SysmonXmlLooksLikeQualifiedPath(normalized)) {
        *NormalizedValue = normalized;
        return SYSMON_SUCCESS;
    }

    SysmonXmlCanonicalizePathSeparators(normalized);
    pathText = normalized;
    useDosDeviceStylePath =
        (EventId == SysmonEventProcessCreate &&
         FieldName != NULL &&
         _wcsicmp(FieldName, L"Image") == 0);

    if (useDosDeviceStylePath) {
        if (_wcsnicmp(pathText, L"\\??\\", 4) == 0) {
            *NormalizedValue = normalized;
            return SYSMON_SUCCESS;
        }

        if (_wcsnicmp(pathText, L"\\\\?\\", 4) == 0) {
            LPWSTR converted;
            SYSMON_STATUS status = SysmonXmlBuildConcatenatedString(L"\\??\\", pathText + 4, &converted);
            SYSMON_FREE(normalized);
            *NormalizedValue = converted;
            return status;
        }

        if (_wcsnicmp(pathText, L"\\\\", 2) == 0) {
            LPWSTR converted;
            SYSMON_STATUS status = SysmonXmlBuildConcatenatedString(L"\\??\\UNC\\", pathText + 2, &converted);
            SYSMON_FREE(normalized);
            *NormalizedValue = converted;
            return status;
        }

        if (SysmonXmlLooksLikeDrivePath(pathText)) {
            LPWSTR converted;
            SYSMON_STATUS status = SysmonXmlBuildConcatenatedString(L"\\??\\", pathText, &converted);
            SYSMON_FREE(normalized);
            *NormalizedValue = converted;
            return status;
        }
    }

    if (_wcsnicmp(pathText, L"\\Device\\", 8) == 0 ||
        _wcsnicmp(pathText, L"\\SystemRoot\\", 12) == 0) {
        *NormalizedValue = normalized;
        return SYSMON_SUCCESS;
    }

    if (_wcsnicmp(pathText, L"\\??\\UNC\\", 8) == 0 ||
        _wcsnicmp(pathText, L"\\\\?\\UNC\\", 8) == 0) {
        LPWSTR converted;
        SYSMON_STATUS status = SysmonXmlBuildConcatenatedString(L"\\Device\\Mup\\", pathText + 8, &converted);
        SYSMON_FREE(normalized);
        *NormalizedValue = converted;
        return status;
    }

    if (_wcsnicmp(pathText, L"\\??\\", 4) == 0 ||
        _wcsnicmp(pathText, L"\\\\?\\", 4) == 0) {
        pathText += 4;
    }

    if (_wcsnicmp(pathText, L"\\\\", 2) == 0) {
        LPWSTR converted;
        SYSMON_STATUS status = SysmonXmlBuildConcatenatedString(L"\\Device\\Mup\\", pathText + 2, &converted);
        SYSMON_FREE(normalized);
        *NormalizedValue = converted;
        return status;
    }

    if (!SysmonXmlLooksLikeDrivePath(pathText)) {
        *NormalizedValue = normalized;
        return SYSMON_SUCCESS;
    }

    {
        WCHAR driveName[3];
        LPWSTR converted;
        SYSMON_STATUS status;

        driveName[0] = pathText[0];
        driveName[1] = L':';
        driveName[2] = L'\0';
        deviceChars = QueryDosDeviceW(driveName, devicePath, _countof(devicePath));
        if (deviceChars == 0 || deviceChars >= _countof(devicePath)) {
            *NormalizedValue = normalized;
            return SYSMON_SUCCESS;
        }

        status = SysmonXmlBuildConcatenatedString(devicePath, pathText + 2, &converted);
        if (status != SYSMON_SUCCESS) {
            SYSMON_FREE(normalized);
            return status;
        }

        SYSMON_FREE(normalized);
        *NormalizedValue = converted;
        return SYSMON_SUCCESS;
    }
}

static SYSMON_STATUS
SysmonXmlNormalizeUserToken(
    _In_opt_ LPCWSTR ValueText,
    _Out_ LPWSTR *NormalizedValue)
{
    LPWSTR trimmed;
    DWORD sidBytes = 0;
    DWORD domainChars = 0;
    SID_NAME_USE sidUse;
    PSID sid = NULL;
    LPWSTR domain = NULL;
    LPWSTR sidText = NULL;
    LPWSTR converted = NULL;
    BOOL lookupSuccess;
    DWORD lookupError;

    *NormalizedValue = NULL;

    trimmed = SysmonXmlDuplicateTrimmedString(ValueText);
    if (trimmed == NULL) {
        return SYSMON_ERROR_OUT_OF_MEMORY;
    }

    if (trimmed[0] == L'\0' ||
        _wcsnicmp(trimmed, L"S-1-", 4) == 0) {
        *NormalizedValue = trimmed;
        return SYSMON_SUCCESS;
    }

    lookupSuccess = LookupAccountNameW(NULL, trimmed, NULL, &sidBytes, NULL, &domainChars, &sidUse);
    lookupError = GetLastError();
    if (lookupSuccess || lookupError != ERROR_INSUFFICIENT_BUFFER || sidBytes == 0) {
        *NormalizedValue = trimmed;
        return SYSMON_SUCCESS;
    }

    sid = (PSID)SYSMON_ALLOC(sidBytes);
    domain = (LPWSTR)SYSMON_ALLOC((SIZE_T)(domainChars + 1) * sizeof(WCHAR));
    if (sid == NULL || domain == NULL) {
        SYSMON_FREE(sid);
        SYSMON_FREE(domain);
        SYSMON_FREE(trimmed);
        return SYSMON_ERROR_OUT_OF_MEMORY;
    }

    lookupSuccess = LookupAccountNameW(NULL, trimmed, sid, &sidBytes, domain, &domainChars, &sidUse);
    if (!lookupSuccess || !ConvertSidToStringSidW(sid, &sidText)) {
        SYSMON_FREE(sid);
        SYSMON_FREE(domain);
        *NormalizedValue = trimmed;
        return SYSMON_SUCCESS;
    }

    converted = SysmonXmlDuplicateTrimmedString(sidText);
    LocalFree(sidText);
    SYSMON_FREE(sid);
    SYSMON_FREE(domain);
    if (converted == NULL) {
        SYSMON_FREE(trimmed);
        return SYSMON_ERROR_OUT_OF_MEMORY;
    }

    SYSMON_FREE(trimmed);
    *NormalizedValue = converted;
    return SYSMON_SUCCESS;
}

static SYSMON_STATUS
SysmonXmlNormalizeTokenForField(
    _In_ SYSMON_EVENT_ID EventId,
    _In_ LPCWSTR FieldName,
    _In_ SYSMON_RULE_CONDITION Condition,
    _In_opt_ LPCWSTR ValueText,
    _Out_ LPWSTR *NormalizedValue)
{
    *NormalizedValue = NULL;

    if (!SysmonXmlConditionUsesTextTokens(Condition)) {
        *NormalizedValue = SysmonXmlDuplicateTrimmedString(ValueText);
        return (*NormalizedValue != NULL) ? SYSMON_SUCCESS : SYSMON_ERROR_OUT_OF_MEMORY;
    }

    if (SysmonXmlIsRegistryLikeField(FieldName)) {
        return SysmonXmlNormalizeRegistryToken(ValueText, NormalizedValue);
    }

    if (SysmonXmlIsPathLikeField(FieldName)) {
        return SysmonXmlNormalizePathToken(EventId, FieldName, ValueText, NormalizedValue);
    }

    if (SysmonXmlIsUserLikeField(FieldName)) {
        return SysmonXmlNormalizeUserToken(ValueText, NormalizedValue);
    }

    *NormalizedValue = SysmonXmlDuplicateTrimmedString(ValueText);
    return (*NormalizedValue != NULL) ? SYSMON_SUCCESS : SYSMON_ERROR_OUT_OF_MEMORY;
}

static SYSMON_STATUS
SysmonXmlNormalizeExpressionValue(
    _In_ SYSMON_EVENT_ID EventId,
    _In_ LPCWSTR FieldName,
    _In_ SYSMON_RULE_CONDITION Condition,
    _In_opt_ LPCWSTR ValueText,
    _Out_ LPWSTR *NormalizedValue)
{
    LPWSTR normalizedList = NULL;
    UINT normalizedLength = 0;
    const WCHAR *cursor;

    *NormalizedValue = NULL;

    if (!SysmonXmlConditionUsesTokenList(Condition)) {
        return SysmonXmlNormalizeTokenForField(
            EventId,
            FieldName,
            Condition,
            ValueText,
            NormalizedValue);
    }

    cursor = ValueText;
    while (cursor != NULL && *cursor != L'\0') {
        const WCHAR *tokenStart = cursor;
        const WCHAR *tokenEnd;
        LPWSTR token;
        LPWSTR normalizedToken;
        SYSMON_STATUS status;
        UINT tokenLength;

        while (*cursor != L'\0' && *cursor != L';') {
            cursor++;
        }

        tokenEnd = cursor;
        token = SysmonXmlDuplicateTrimmedRange(tokenStart, (UINT)(tokenEnd - tokenStart));
        if (token == NULL) {
            SYSMON_FREE(normalizedList);
            return SYSMON_ERROR_OUT_OF_MEMORY;
        }

        if (token[0] != L'\0') {
            status = SysmonXmlNormalizeTokenForField(
                EventId,
                FieldName,
                Condition,
                token,
                &normalizedToken);
            SYSMON_FREE(token);
            if (status != SYSMON_SUCCESS) {
                SYSMON_FREE(normalizedList);
                return status;
            }

            if (normalizedList != NULL) {
                status = SysmonXmlAppendBuffer(&normalizedList, normalizedLength, L";", 1);
                if (status != SYSMON_SUCCESS) {
                    SYSMON_FREE(normalizedToken);
                    SYSMON_FREE(normalizedList);
                    return status;
                }
                normalizedLength++;
            }

            tokenLength = (UINT)wcslen(normalizedToken);
            status = SysmonXmlAppendBuffer(&normalizedList, normalizedLength, normalizedToken, tokenLength);
            SYSMON_FREE(normalizedToken);
            if (status != SYSMON_SUCCESS) {
                SYSMON_FREE(normalizedList);
                return status;
            }

            normalizedLength += tokenLength;
        } else {
            SYSMON_FREE(token);
        }

        if (*cursor == L';') {
            cursor++;
        }
    }

    if (normalizedList == NULL) {
        normalizedList = SysmonXmlDuplicateString(L"", 0);
        if (normalizedList == NULL) {
            return SYSMON_ERROR_OUT_OF_MEMORY;
        }
    }

    *NormalizedValue = normalizedList;
    return SYSMON_SUCCESS;
}

static const SYSMON_EVENT_NODE_MAPPING *
SysmonFindEventNodeMapping(
    _In_ LPCWSTR Name)
{
    DWORD index;

    for (index = 0; index < _countof(g_SysmonEventNodeMappings); index++) {
        if (_wcsicmp(Name, g_SysmonEventNodeMappings[index].XmlName) == 0) {
            return &g_SysmonEventNodeMappings[index];
        }
    }

    return NULL;
}

static SYSMON_STATUS
SysmonAppendExpressionToRule(
    _Inout_ PSYSMON_RULE Rule,
    _In_ SYSMON_EVENT_ID EventId,
    _In_ LPCWSTR FieldName,
    _In_opt_ LPCWSTR ValueText,
    _In_ SYSMON_RULE_CONDITION DefaultCondition,
    _In_opt_ LPCWSTR ConditionText)
{
    SYSMON_STATUS status;
    PSYSMON_RULE_EXPRESSION expression;
    LPWSTR fieldCopy;
    LPWSTR valueCopy;
    SYSMON_RULE_CONDITION condition;

    status = SysmonXmlGrowArray(
        (PVOID*)&Rule->Expressions,
        Rule->ExpressionCount,
        Rule->ExpressionCount + 1,
        sizeof(Rule->Expressions[0]));
    if (status != SYSMON_SUCCESS) {
        return status;
    }

    expression = &Rule->Expressions[Rule->ExpressionCount];
    ZeroMemory(expression, sizeof(*expression));

    condition = DefaultCondition;
    if (ConditionText != NULL && !SysmonRuleParseCondition(ConditionText, &condition)) {
        SysmonLogError(
            SYSMON_COMPONENT_CONFIG,
            ERROR_INVALID_DATA,
            "Unknown rule condition '%ls' on field '%ls'",
            ConditionText,
            FieldName);
        return ERROR_INVALID_DATA;
    }

    fieldCopy = SysmonXmlDuplicateTrimmedString(FieldName);
    if (fieldCopy == NULL) {
        SYSMON_FREE(fieldCopy);
        return SYSMON_ERROR_OUT_OF_MEMORY;
    }

    status = SysmonXmlNormalizeExpressionValue(
        EventId,
        fieldCopy,
        condition,
        ValueText,
        &valueCopy);
    if (status != SYSMON_SUCCESS) {
        SYSMON_FREE(fieldCopy);
        return status;
    }

    expression->FieldName = fieldCopy;
    expression->Value = valueCopy;
    expression->Condition = condition;
    Rule->ExpressionCount++;
    return SYSMON_SUCCESS;
}

static SYSMON_STATUS
SysmonParseRuleNode(
    _In_ const SYSMON_XML_NODE *Node,
    _In_ SYSMON_EVENT_ID EventId,
    _In_ SYSMON_RULE_RELATION DefaultRelation,
    _Out_ PSYSMON_RULE Rule)
{
    DWORD childIndex;
    LPCWSTR nameText;
    LPCWSTR relationText;

    ZeroMemory(Rule, sizeof(*Rule));

    nameText = SysmonXmlGetAttribute(Node, L"name");
    relationText = SysmonXmlGetAttribute(Node, L"groupRelation");
    Rule->Relation = SysmonParseRelationOrDefault(relationText, DefaultRelation);

    if (nameText != NULL) {
        Rule->Name = SysmonXmlDuplicateTrimmedString(nameText);
        if (Rule->Name == NULL) {
            return SYSMON_ERROR_OUT_OF_MEMORY;
        }
    }

    for (childIndex = 0; childIndex < Node->ChildCount; childIndex++) {
        const SYSMON_XML_NODE *child = Node->Children[childIndex];
        SYSMON_STATUS status;

        if (_wcsicmp(child->Name, L"Rule") == 0) {
            continue;
        }

        status = SysmonAppendExpressionToRule(
            Rule,
            EventId,
            child->Name,
            child->Text,
            SysmonRuleConditionIs,
            SysmonXmlGetAttribute(child, L"condition"));
        if (status != SYSMON_SUCCESS) {
            return status;
        }
    }

    return SYSMON_SUCCESS;
}

static SYSMON_STATUS
SysmonAppendCopiedExpressionToRule(
    _Inout_ PSYSMON_RULE Rule,
    _In_ const SYSMON_RULE_EXPRESSION *ExpressionTemplate)
{
    SYSMON_STATUS status;
    PSYSMON_RULE_EXPRESSION destination;

    status = SysmonXmlGrowArray(
        (PVOID*)&Rule->Expressions,
        Rule->ExpressionCount,
        Rule->ExpressionCount + 1,
        sizeof(Rule->Expressions[0]));
    if (status != SYSMON_SUCCESS) {
        return status;
    }

    destination = &Rule->Expressions[Rule->ExpressionCount];
    ZeroMemory(destination, sizeof(*destination));

    destination->FieldName = SysmonXmlDuplicateTrimmedString(ExpressionTemplate->FieldName);
    destination->Value = SysmonXmlDuplicateTrimmedString(ExpressionTemplate->Value);
    if (destination->FieldName == NULL || destination->Value == NULL) {
        LPWSTR fieldName = const_cast<LPWSTR>(destination->FieldName);
        SYSMON_FREE(fieldName);
        SYSMON_FREE(destination->Value);
        return SYSMON_ERROR_OUT_OF_MEMORY;
    }

    destination->Condition = ExpressionTemplate->Condition;
    Rule->ExpressionCount++;
    return SYSMON_SUCCESS;
}

static SYSMON_STATUS
SysmonAppendRuleToEventRule(
    _Inout_ PSYSMON_EVENT_RULE EventRule,
    _In_ SYSMON_EVENT_ID EventId,
    _In_ const SYSMON_RULE *RuleTemplate)
{
    SYSMON_STATUS status;
    PSYSMON_RULE destination;
    DWORD index;

    status = SysmonXmlGrowArray(
        (PVOID*)&EventRule->Rules,
        EventRule->RuleCount,
        EventRule->RuleCount + 1,
        sizeof(EventRule->Rules[0]));
    if (status != SYSMON_SUCCESS) {
        return status;
    }

    destination = &EventRule->Rules[EventRule->RuleCount];
    ZeroMemory(destination, sizeof(*destination));
    destination->Relation = RuleTemplate->Relation;

    if (RuleTemplate->Name != NULL) {
        destination->Name = SysmonXmlDuplicateTrimmedString(RuleTemplate->Name);
        if (destination->Name == NULL) {
            return SYSMON_ERROR_OUT_OF_MEMORY;
        }
    }

    for (index = 0; index < RuleTemplate->ExpressionCount; index++) {
        status = SysmonAppendCopiedExpressionToRule(
            destination,
            &RuleTemplate->Expressions[index]);
        if (status != SYSMON_SUCCESS) {
            return status;
        }
    }

    EventRule->RuleCount++;
    return SYSMON_SUCCESS;
}

static SYSMON_STATUS
SysmonPopulateEventRuleFromNode(
    _In_ const SYSMON_XML_NODE *Node,
    _In_ SYSMON_EVENT_ID EventId,
    _Out_ PSYSMON_EVENT_RULE EventRule)
{
    DWORD childIndex;
    SYSMON_RULE implicitRule;
    BOOL hasImplicitRule = FALSE;

    ZeroMemory(EventRule, sizeof(*EventRule));
    ZeroMemory(&implicitRule, sizeof(implicitRule));

    EventRule->EventId = EventId;
    {
        SYSMON_STATUS status = SysmonParseMatchTypeAttributes(Node, &EventRule->MatchType);
        if (status != SYSMON_SUCCESS) {
            return status;
        }
    }
    EventRule->Relation = SysmonParseRelationOrDefault(
        SysmonXmlGetAttribute(Node, L"groupRelation"),
        SysmonRuleRelationOr);

    implicitRule.Relation = EventRule->Relation;

    for (childIndex = 0; childIndex < Node->ChildCount; childIndex++) {
        const SYSMON_XML_NODE *child = Node->Children[childIndex];
        SYSMON_STATUS status;

        if (_wcsicmp(child->Name, L"Rule") == 0) {
            SYSMON_RULE nestedRule;

            status = SysmonParseRuleNode(child, EventId, EventRule->Relation, &nestedRule);
            if (status != SYSMON_SUCCESS) {
                SysmonFreeRule(&implicitRule);
                return status;
            }

            status = SysmonAppendRuleToEventRule(EventRule, EventId, &nestedRule);
            SysmonFreeRule(&nestedRule);
            if (status != SYSMON_SUCCESS) {
                SysmonFreeRule(&implicitRule);
                return status;
            }
            continue;
        }

        status = SysmonAppendExpressionToRule(
            &implicitRule,
            EventId,
            child->Name,
            child->Text,
            SysmonRuleConditionIs,
            SysmonXmlGetAttribute(child, L"condition"));
        if (status != SYSMON_SUCCESS) {
            SysmonFreeRule(&implicitRule);
            return status;
        }

        hasImplicitRule = TRUE;
    }

    if (hasImplicitRule) {
        SYSMON_STATUS status = SysmonAppendRuleToEventRule(EventRule, EventId, &implicitRule);
        SysmonFreeRule(&implicitRule);
        if (status != SYSMON_SUCCESS) {
            return status;
        }
    } else {
        SysmonFreeRule(&implicitRule);
    }

    return SYSMON_SUCCESS;
}

static SYSMON_STATUS
SysmonAppendEventRuleToGroup(
    _Inout_ PSYSMON_RULE_GROUP Group,
    _In_ const SYSMON_EVENT_RULE *EventRuleTemplate)
{
    SYSMON_STATUS status;
    PSYSMON_EVENT_RULE destination;
    DWORD ruleIndex;

    status = SysmonXmlGrowArray(
        (PVOID*)&Group->EventRules,
        Group->EventRuleCount,
        Group->EventRuleCount + 1,
        sizeof(Group->EventRules[0]));
    if (status != SYSMON_SUCCESS) {
        return status;
    }

    destination = &Group->EventRules[Group->EventRuleCount];
    ZeroMemory(destination, sizeof(*destination));
    destination->EventId = EventRuleTemplate->EventId;
    destination->MatchType = EventRuleTemplate->MatchType;
    destination->Relation = EventRuleTemplate->Relation;

    for (ruleIndex = 0; ruleIndex < EventRuleTemplate->RuleCount; ruleIndex++) {
        status = SysmonAppendRuleToEventRule(
            destination,
            EventRuleTemplate->EventId,
            &EventRuleTemplate->Rules[ruleIndex]);
        if (status != SYSMON_SUCCESS) {
            return status;
        }
    }

    Group->EventRuleCount++;
    return SYSMON_SUCCESS;
}

static SYSMON_STATUS
SysmonParseEventNodeIntoGroup(
    _In_ const SYSMON_XML_NODE *Node,
    _Inout_ PSYSMON_RULE_GROUP Group)
{
    const SYSMON_EVENT_NODE_MAPPING *mapping;
    DWORD eventIndex;

    mapping = SysmonFindEventNodeMapping(Node->Name);
    if (mapping == NULL) {
        SysmonLogWarning(SYSMON_COMPONENT_CONFIG,
            "Ignoring unsupported EventFiltering node '%ls'", Node->Name);
        return SYSMON_SUCCESS;
    }

    for (eventIndex = 0; eventIndex < mapping->EventCount; eventIndex++) {
        SYSMON_EVENT_RULE eventRule;
        SYSMON_STATUS status;

        status = SysmonPopulateEventRuleFromNode(Node, mapping->EventIds[eventIndex], &eventRule);
        if (status != SYSMON_SUCCESS) {
            return status;
        }

        status = SysmonAppendEventRuleToGroup(Group, &eventRule);
        SysmonFreeEventRule(&eventRule);
        if (status != SYSMON_SUCCESS) {
            return status;
        }
    }

    return SYSMON_SUCCESS;
}

static SYSMON_STATUS
SysmonParseRuleGroupNode(
    _In_ const SYSMON_XML_NODE *Node,
    _Out_ PSYSMON_RULE_GROUP Group)
{
    DWORD childIndex;
    LPCWSTR relationText;
    LPCWSTR nameText;

    ZeroMemory(Group, sizeof(*Group));

    relationText = SysmonXmlGetAttribute(Node, L"groupRelation");
    nameText = SysmonXmlGetAttribute(Node, L"name");
    Group->Relation = SysmonParseRelationOrDefault(relationText, SysmonRuleRelationOr);

    if (nameText != NULL) {
        Group->Name = SysmonXmlDuplicateTrimmedString(nameText);
        if (Group->Name == NULL) {
            return SYSMON_ERROR_OUT_OF_MEMORY;
        }
    }

    for (childIndex = 0; childIndex < Node->ChildCount; childIndex++) {
        SYSMON_STATUS status = SysmonParseEventNodeIntoGroup(Node->Children[childIndex], Group);
        if (status != SYSMON_SUCCESS) {
            return status;
        }
    }

    return SYSMON_SUCCESS;
}

static SYSMON_STATUS
SysmonAppendGroupToRuleSet(
    _Inout_ PSYSMON_RULE_SET RuleSet,
    _In_ const SYSMON_RULE_GROUP *GroupTemplate)
{
    SYSMON_STATUS status;
    PSYSMON_RULE_GROUP destination;
    DWORD eventIndex;

    status = SysmonXmlGrowArray(
        (PVOID*)&RuleSet->Groups,
        RuleSet->GroupCount,
        RuleSet->GroupCount + 1,
        sizeof(RuleSet->Groups[0]));
    if (status != SYSMON_SUCCESS) {
        return status;
    }

    destination = &RuleSet->Groups[RuleSet->GroupCount];
    ZeroMemory(destination, sizeof(*destination));
    destination->Relation = GroupTemplate->Relation;

    if (GroupTemplate->Name != NULL) {
        destination->Name = SysmonXmlDuplicateTrimmedString(GroupTemplate->Name);
        if (destination->Name == NULL) {
            return SYSMON_ERROR_OUT_OF_MEMORY;
        }
    }

    for (eventIndex = 0; eventIndex < GroupTemplate->EventRuleCount; eventIndex++) {
        status = SysmonAppendEventRuleToGroup(destination, &GroupTemplate->EventRules[eventIndex]);
        if (status != SYSMON_SUCCESS) {
            return status;
        }
    }

    RuleSet->GroupCount++;
    return SYSMON_SUCCESS;
}

static SYSMON_STATUS
SysmonParseEventFiltering(
    _In_ const SYSMON_XML_NODE *EventFilteringNode,
    _Out_ PSYSMON_RULE_SET RuleSet)
{
    DWORD childIndex;

    ZeroMemory(RuleSet, sizeof(*RuleSet));

    if (EventFilteringNode == NULL) {
        return SYSMON_SUCCESS;
    }

    for (childIndex = 0; childIndex < EventFilteringNode->ChildCount; childIndex++) {
        const SYSMON_XML_NODE *child = EventFilteringNode->Children[childIndex];
        SYSMON_RULE_GROUP group;
        SYSMON_STATUS status;

        ZeroMemory(&group, sizeof(group));

        if (_wcsicmp(child->Name, L"RuleGroup") == 0) {
            status = SysmonParseRuleGroupNode(child, &group);
        } else {
            group.Relation = SysmonRuleRelationOr;
            status = SysmonParseEventNodeIntoGroup(child, &group);
        }

        if (status != SYSMON_SUCCESS) {
            SysmonConfigFreeRuleSet(RuleSet);
            return status;
        }

        if (group.EventRuleCount != 0) {
            status = SysmonAppendGroupToRuleSet(RuleSet, &group);
        }

        SysmonFreeRuleGroupContents(&group);

        if (status != SYSMON_SUCCESS) {
            return status;
        }
    }

    return SYSMON_SUCCESS;
}

static VOID
SysmonDeriveOptionsFromRuleSet(
    _Inout_ PSYSMON_CONFIG Config)
{
    DWORD groupIndex;
    auto eventCanProduceLogs = [](_In_ const SYSMON_RULE_SET *ruleSet, _In_ SYSMON_EVENT_ID eventId) -> BOOL {
        DWORD groupIndexLocal;
        BOOL hasInclude = FALSE;
        BOOL hasRuleForEvent = FALSE;
        BOOL hasMatchAllExclude = FALSE;

        if (ruleSet == NULL) {
            return FALSE;
        }

        for (groupIndexLocal = 0; groupIndexLocal < ruleSet->GroupCount; groupIndexLocal++) {
            const SYSMON_RULE_GROUP *group = &ruleSet->Groups[groupIndexLocal];
            DWORD eventIndexLocal;

            for (eventIndexLocal = 0; eventIndexLocal < group->EventRuleCount; eventIndexLocal++) {
                const SYSMON_EVENT_RULE *eventRule = &group->EventRules[eventIndexLocal];

                if (eventRule->EventId != eventId) {
                    continue;
                }

                hasRuleForEvent = TRUE;
                if (eventRule->MatchType == SysmonRuleMatchTypeInclude) {
                    hasInclude = TRUE;
                } else if (eventRule->MatchType == SysmonRuleMatchTypeExclude &&
                           eventRule->RuleCount == 0) {
                    hasMatchAllExclude = TRUE;
                }
            }
        }

        if (!hasRuleForEvent) {
            return FALSE;
        }

        if (hasMatchAllExclude && !hasInclude) {
            return FALSE;
        }

        return TRUE;
    };

    if (Config == NULL) {
        return;
    }

    for (groupIndex = 0; groupIndex < Config->RuleSet.GroupCount; groupIndex++) {
        const SYSMON_RULE_GROUP *group = &Config->RuleSet.Groups[groupIndex];
        DWORD eventIndex;

        for (eventIndex = 0; eventIndex < group->EventRuleCount; eventIndex++) {
            const SYSMON_EVENT_RULE *eventRule = &group->EventRules[eventIndex];

            if (!eventCanProduceLogs(&Config->RuleSet, eventRule->EventId)) {
                continue;
            }

            if (eventRule->EventId == SysmonEventNetworkConnect) {
                Config->Options |= SYSMON_OPTION_NETWORK_CONNECT;
            } else if (eventRule->EventId == SysmonEventImageLoad) {
                Config->Options |= SYSMON_OPTION_IMAGE_LOAD;
            } else if (eventRule->EventId == SysmonEventPipeCreated ||
                       eventRule->EventId == SysmonEventPipeConnected) {
                Config->Options |= SYSMON_OPTION_PIPE_MONITORING;
            }
        }
    }
}

static SYSMON_STATUS
SysmonLoadXmlTree(
    _In_ LPCWSTR XmlPath,
    _Out_ PSYSMON_XML_NODE *RootNode)
{
    HANDLE fileHandle = INVALID_HANDLE_VALUE;
    LARGE_INTEGER fileSize;
    HGLOBAL globalBuffer = NULL;
    void *bufferView = NULL;
    DWORD bytesRead = 0;
    HRESULT hr;
    IStream *stream = NULL;
    IXmlReader *reader = NULL;
    XmlNodeType nodeType;
    PSYSMON_XML_NODE root = NULL;
    PSYSMON_XML_NODE *nodeStack = NULL;
    DWORD stackDepth = 0;
    DWORD stackCapacity = 0;
    BOOL coInitialized = FALSE;
    SYSMON_STATUS status = SYSMON_SUCCESS;

    *RootNode = NULL;

    fileHandle = CreateFileW(
        XmlPath,
        GENERIC_READ,
        FILE_SHARE_READ,
        NULL,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        NULL);
    if (fileHandle == INVALID_HANDLE_VALUE) {
        return GetLastError();
    }

    if (!GetFileSizeEx(fileHandle, &fileSize) || fileSize.QuadPart <= 0 || fileSize.HighPart != 0) {
        status = GetLastError();
        if (status == SYSMON_SUCCESS) {
            status = ERROR_BAD_FORMAT;
        }
        goto cleanup;
    }

    globalBuffer = GlobalAlloc(GMEM_MOVEABLE, (SIZE_T)fileSize.LowPart);
    if (globalBuffer == NULL) {
        status = SYSMON_ERROR_OUT_OF_MEMORY;
        goto cleanup;
    }

    bufferView = GlobalLock(globalBuffer);
    if (bufferView == NULL) {
        status = GetLastError();
        goto cleanup;
    }

    if (!ReadFile(fileHandle, bufferView, fileSize.LowPart, &bytesRead, NULL) || bytesRead != fileSize.LowPart) {
        status = GetLastError();
        goto cleanup;
    }

    GlobalUnlock(globalBuffer);
    bufferView = NULL;

    hr = CoInitializeEx(NULL, COINIT_MULTITHREADED);
    if (SUCCEEDED(hr) || hr == RPC_E_CHANGED_MODE) {
        coInitialized = (hr != RPC_E_CHANGED_MODE);
    } else {
        status = HRESULT_CODE(hr);
        goto cleanup;
    }

    hr = CreateStreamOnHGlobal(globalBuffer, TRUE, &stream);
    if (FAILED(hr)) {
        status = HRESULT_CODE(hr);
        goto cleanup;
    }
    globalBuffer = NULL;

    hr = CreateXmlReader(IID_IXmlReader, reinterpret_cast<void **>(&reader), NULL);
    if (FAILED(hr)) {
        status = HRESULT_CODE(hr);
        goto cleanup;
    }

    hr = reader->SetInput(stream);
    if (FAILED(hr)) {
        status = HRESULT_CODE(hr);
        goto cleanup;
    }

    for (;;) {
        hr = reader->Read(&nodeType);
        if (hr == S_FALSE) {
            break;
        }
        if (FAILED(hr)) {
            status = HRESULT_CODE(hr);
            goto cleanup;
        }

        if (nodeType == XmlNodeType_Element) {
            const WCHAR *name = NULL;
            UINT nameLength = 0;
            BOOL isEmpty = FALSE;
            PSYSMON_XML_NODE node = NULL;

            hr = reader->GetLocalName(&name, &nameLength);
            if (FAILED(hr)) {
                status = HRESULT_CODE(hr);
                goto cleanup;
            }

            status = SysmonXmlCreateNode(name, nameLength, &node);
            if (status != SYSMON_SUCCESS) {
                goto cleanup;
            }

            if (S_OK == reader->MoveToFirstAttribute()) {
                do {
                    const WCHAR *attrName = NULL;
                    const WCHAR *attrValue = NULL;
                    UINT attrNameLength = 0;
                    UINT attrValueLength = 0;

                    hr = reader->GetLocalName(&attrName, &attrNameLength);
                    if (FAILED(hr)) {
                        SysmonXmlFreeNode(node);
                        status = HRESULT_CODE(hr);
                        goto cleanup;
                    }

                    hr = reader->GetValue(&attrValue, &attrValueLength);
                    if (FAILED(hr)) {
                        SysmonXmlFreeNode(node);
                        status = HRESULT_CODE(hr);
                        goto cleanup;
                    }

                    status = SysmonXmlAddAttribute(node, attrName, attrNameLength, attrValue, attrValueLength);
                    if (status != SYSMON_SUCCESS) {
                        SysmonXmlFreeNode(node);
                        goto cleanup;
                    }
                } while (S_OK == reader->MoveToNextAttribute());

                reader->MoveToElement();
            }

            isEmpty = reader->IsEmptyElement();

            if (stackDepth != 0) {
                status = SysmonXmlAddChild(nodeStack[stackDepth - 1], node);
                if (status != SYSMON_SUCCESS) {
                    SysmonXmlFreeNode(node);
                    goto cleanup;
                }
            } else {
                root = node;
            }

            if (!isEmpty) {
                if (stackDepth == stackCapacity) {
                    DWORD newCapacity = (stackCapacity == 0) ? 8 : stackCapacity * 2;
                    status = SysmonXmlGrowArray(
                        (PVOID*)&nodeStack,
                        stackCapacity,
                        newCapacity,
                        sizeof(nodeStack[0]));
                    if (status != SYSMON_SUCCESS) {
                        goto cleanup;
                    }
                    stackCapacity = newCapacity;
                }

                nodeStack[stackDepth] = node;
                stackDepth++;
            }
        } else if (nodeType == XmlNodeType_EndElement) {
            if (stackDepth != 0) {
                stackDepth--;
            }
        } else if (nodeType == XmlNodeType_Text || nodeType == XmlNodeType_CDATA || nodeType == XmlNodeType_Whitespace) {
            const WCHAR *value = NULL;
            UINT valueLength = 0;

            if (stackDepth == 0) {
                continue;
            }

            hr = reader->GetValue(&value, &valueLength);
            if (FAILED(hr)) {
                status = HRESULT_CODE(hr);
                goto cleanup;
            }

            if (valueLength == 0 || SysmonXmlIsWhitespaceOnly(value, valueLength)) {
                continue;
            }

            status = SysmonXmlAppendText(nodeStack[stackDepth - 1], value, valueLength);
            if (status != SYSMON_SUCCESS) {
                goto cleanup;
            }
        }
    }

    *RootNode = root;
    root = NULL;

cleanup:
    SYSMON_FREE(nodeStack);
    if (reader != NULL) {
        reader->Release();
    }
    if (stream != NULL) {
        stream->Release();
    }
    if (bufferView != NULL) {
        GlobalUnlock(globalBuffer);
    }
    if (globalBuffer != NULL) {
        GlobalFree(globalBuffer);
    }
    if (fileHandle != INVALID_HANDLE_VALUE) {
        CloseHandle(fileHandle);
    }
    if (coInitialized) {
        CoUninitialize();
    }
    if (status != SYSMON_SUCCESS) {
        SysmonXmlFreeNode(root);
    }

    return status;
}

SYSMON_STATUS
SysmonParseXmlConfig(
    LPCWSTR XmlPath,
    PSYSMON_CONFIG Config)
{
    PSYSMON_XML_NODE root = NULL;
    const SYSMON_XML_NODE *eventFilteringNode;
    const SYSMON_XML_NODE *child;
    SYSMON_STATUS status;

    if (XmlPath == NULL || Config == NULL) {
        return SYSMON_ERROR_INVALID_PARAM;
    }

    ZeroMemory(Config, sizeof(*Config));
    Config->HashingAlgorithm = SYSMON_HASH_DEFAULT;
    Config->CheckRevocation = TRUE;
    Config->DnsLookup = TRUE;
    Config->CopyOnDeletePE = FALSE;
    Config->SigningQueueSize = 1000;
    Config->SigningWorkerCount = 0;

    status = SysmonLoadXmlTree(XmlPath, &root);
    if (status != SYSMON_SUCCESS) {
        return status;
    }

    if (root == NULL || _wcsicmp(root->Name, L"Sysmon") != 0) {
        status = ERROR_BAD_FORMAT;
        goto cleanup;
    }

    child = SysmonXmlFindChild(root, L"HashAlgorithms");
    if (child != NULL) {
        status = SysmonParseHashAlgorithmsText(child->Text, &Config->HashingAlgorithm);
        if (status != SYSMON_SUCCESS) {
            goto cleanup;
        }
    }

    child = SysmonXmlFindChild(root, L"CheckRevocation");
    if (child != NULL && child->Text != NULL) {
        BOOL value;
        if (SysmonXmlTryParseBoolean(child->Text, &value)) {
            Config->CheckRevocation = value;
        }
    }

    child = SysmonXmlFindChild(root, L"DnsLookup");
    if (child != NULL && child->Text != NULL) {
        BOOL value;
        if (SysmonXmlTryParseBoolean(child->Text, &value)) {
            Config->DnsLookup = value;
        }
    }

    child = SysmonXmlFindChild(root, L"ArchiveDirectory");
    if (child != NULL && child->Text != NULL) {
        Config->ArchiveDirectory = SysmonXmlDuplicateTrimmedString(child->Text);
        if (Config->ArchiveDirectory == NULL) {
            status = SYSMON_ERROR_OUT_OF_MEMORY;
            goto cleanup;
        }
        if (!SysmonIsSinglePathComponent(Config->ArchiveDirectory)) {
            status = ERROR_INVALID_DATA;
            goto cleanup;
        }
    }

    child = SysmonXmlFindChild(root, L"CopyOnDeletePE");
    if (child != NULL && child->Text != NULL) {
        BOOL value;
        if (!SysmonXmlTryParseBoolean(child->Text, &value)) {
            status = ERROR_INVALID_DATA;
            goto cleanup;
        }
        Config->CopyOnDeletePE = value;
    }

    child = SysmonXmlFindChild(root, L"CopyOnDeleteSIDs");
    if (child != NULL && child->Text != NULL) {
        Config->CopyOnDeleteSIDs = SysmonXmlDuplicateTrimmedString(child->Text);
        if (Config->CopyOnDeleteSIDs == NULL) {
            status = SYSMON_ERROR_OUT_OF_MEMORY;
            goto cleanup;
        }
    }

    child = SysmonXmlFindChild(root, L"CopyOnDeleteExtensions");
    if (child != NULL && child->Text != NULL) {
        Config->CopyOnDeleteExtensions = SysmonXmlDuplicateTrimmedString(child->Text);
        if (Config->CopyOnDeleteExtensions == NULL) {
            status = SYSMON_ERROR_OUT_OF_MEMORY;
            goto cleanup;
        }
    }

    child = SysmonXmlFindChild(root, L"CopyOnDeleteProcesses");
    if (child != NULL && child->Text != NULL) {
        Config->CopyOnDeleteProcesses = SysmonXmlDuplicateTrimmedString(child->Text);
        if (Config->CopyOnDeleteProcesses == NULL) {
            status = SYSMON_ERROR_OUT_OF_MEMORY;
            goto cleanup;
        }
    }

    child = SysmonXmlFindChild(root, L"FieldSizes");
    if (child != NULL && child->Text != NULL) {
        if (!SysmonValidateFieldSizesText(child->Text)) {
            status = ERROR_INVALID_DATA;
            goto cleanup;
        }
        Config->FieldSizes = SysmonXmlDuplicateTrimmedString(child->Text);
        if (Config->FieldSizes == NULL) {
            status = SYSMON_ERROR_OUT_OF_MEMORY;
            goto cleanup;
        }
    }

    child = SysmonXmlFindChild(root, L"DriverQueueSize");
    if (child != NULL && child->Text != NULL) {
        DWORD value;
        if (!SysmonXmlTryParseDword(child->Text, &value)) {
            status = ERROR_INVALID_DATA;
            goto cleanup;
        }
        Config->DriverQueueSize = value;
    }

    child = SysmonXmlFindChild(root, L"SigningQueueSize");
    if (child != NULL && child->Text != NULL) {
        DWORD value;
        if (!SysmonXmlTryParseDword(child->Text, &value)) {
            status = ERROR_INVALID_DATA;
            goto cleanup;
        }
        Config->SigningQueueSize = value;
    }

    child = SysmonXmlFindChild(root, L"SigningWorkerCount");
    if (child != NULL && child->Text != NULL) {
        DWORD value;
        if (!SysmonXmlTryParseDword(child->Text, &value)) {
            status = ERROR_INVALID_DATA;
            goto cleanup;
        }
        Config->SigningWorkerCount = value;
    }

    eventFilteringNode = SysmonXmlFindChild(root, L"EventFiltering");
    status = SysmonParseEventFiltering(eventFilteringNode, &Config->RuleSet);
    if (status != SYSMON_SUCCESS) {
        goto cleanup;
    }
    SysmonDeriveOptionsFromRuleSet(Config);

cleanup:
    SysmonXmlFreeNode(root);
    if (status != SYSMON_SUCCESS) {
        SysmonFreeParsedXmlConfig(Config);
        ZeroMemory(Config, sizeof(*Config));
    }

    return status;
}

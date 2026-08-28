#pragma once

template <typename TValue>
inline TValue
SysmonReadPackedValue(
    _In_ const void *Address)
{
    TValue value;

    ZeroMemory(&value, sizeof(value));
    CopyMemory(&value, Address, sizeof(value));
    return value;
}

template <typename TValue>
inline void
SysmonWritePackedValue(
    _Out_writes_bytes_(sizeof(TValue)) void *Address,
    _In_ TValue Value)
{
    CopyMemory(Address, &Value, sizeof(Value));
}

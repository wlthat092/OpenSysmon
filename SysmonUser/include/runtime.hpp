#pragma once

#include "common.h"

class ScopedHandle {
public:
    ScopedHandle() noexcept
        : handle_(NULL) {
    }

    explicit ScopedHandle(HANDLE handle) noexcept
        : handle_(handle) {
    }

    ~ScopedHandle() noexcept {
        reset();
    }

    ScopedHandle(const ScopedHandle&) = delete;
    ScopedHandle& operator=(const ScopedHandle&) = delete;

    ScopedHandle(ScopedHandle&& other) noexcept
        : handle_(other.release()) {
    }

    ScopedHandle& operator=(ScopedHandle&& other) noexcept {
        if (this != &other) {
            reset(other.release());
        }
        return *this;
    }

    HANDLE get() const noexcept {
        return handle_;
    }

    bool valid() const noexcept {
        return handle_ != NULL && handle_ != INVALID_HANDLE_VALUE;
    }

    HANDLE release() noexcept {
        HANDLE handle = handle_;
        handle_ = NULL;
        return handle;
    }

    void reset(HANDLE handle = NULL) noexcept {
        if (valid()) {
            CloseHandle(handle_);
        }
        handle_ = handle;
    }

    HANDLE* put() noexcept {
        reset();
        return &handle_;
    }

private:
    HANDLE handle_;
};

class ScopedRegKey {
public:
    ScopedRegKey() noexcept
        : key_(NULL) {
    }

    explicit ScopedRegKey(HKEY key) noexcept
        : key_(key) {
    }

    ~ScopedRegKey() noexcept {
        reset();
    }

    ScopedRegKey(const ScopedRegKey&) = delete;
    ScopedRegKey& operator=(const ScopedRegKey&) = delete;

    ScopedRegKey(ScopedRegKey&& other) noexcept
        : key_(other.release()) {
    }

    ScopedRegKey& operator=(ScopedRegKey&& other) noexcept {
        if (this != &other) {
            reset(other.release());
        }
        return *this;
    }

    HKEY get() const noexcept {
        return key_;
    }

    HKEY release() noexcept {
        HKEY key = key_;
        key_ = NULL;
        return key;
    }

    void reset(HKEY key = NULL) noexcept {
        if (key_ != NULL) {
            RegCloseKey(key_);
        }
        key_ = key;
    }

    HKEY* put() noexcept {
        reset();
        return &key_;
    }

private:
    HKEY key_;
};

class CriticalSectionGuard {
public:
    explicit CriticalSectionGuard(CRITICAL_SECTION* criticalSection) noexcept
        : criticalSection_(criticalSection) {
        if (criticalSection_ != NULL) {
            EnterCriticalSection(criticalSection_);
        }
    }

    ~CriticalSectionGuard() noexcept {
        if (criticalSection_ != NULL) {
            LeaveCriticalSection(criticalSection_);
        }
    }

    CriticalSectionGuard(const CriticalSectionGuard&) = delete;
    CriticalSectionGuard& operator=(const CriticalSectionGuard&) = delete;

private:
    CRITICAL_SECTION* criticalSection_;
};

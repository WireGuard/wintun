/* SPDX-License-Identifier: GPL-2.0
 *
 * Copyright (C) 2018-2021 WireGuard LLC. All Rights Reserved.
 */

#pragma once

#include "wintun.h"
#include "entry.h"
#include "registry.h"
#include <Windows.h>
#include <stdarg.h>
#include <wchar.h>

extern WINTUN_LOGGER_CALLBACK Logger;

/**
 * @copydoc WINTUN_SET_LOGGER_FUNC
 */
void WINAPI
WintunSetLogger(_In_ WINTUN_LOGGER_CALLBACK NewLogger);

_Post_equals_last_error_ DWORD
LoggerLog(_In_ WINTUN_LOGGER_LEVEL Level, _In_z_ const WCHAR *Function, _In_z_ const WCHAR *LogLine);

_Post_equals_last_error_ DWORD
LoggerLogV(_In_ WINTUN_LOGGER_LEVEL Level, _In_z_ const WCHAR *Function, _In_z_ const WCHAR *Format, _In_ va_list Args);

static inline _Post_equals_last_error_ DWORD
LoggerLogFmt(_In_ WINTUN_LOGGER_LEVEL Level, _In_z_ const WCHAR *Function, _In_z_ const WCHAR *Format, ...)
{
    va_list Args;
    va_start(Args, Format);
    DWORD LastError = LoggerLogV(Level, Function, Format, Args);
    va_end(Args);
    return LastError;
}

_Post_equals_last_error_ DWORD
LoggerError(_In_ DWORD Error, _In_z_ const WCHAR *Function, _In_z_ const WCHAR *Prefix);

_Post_equals_last_error_ DWORD
LoggerErrorV(_In_ DWORD Error, _In_z_ const WCHAR *Function, _In_z_ const WCHAR *Format, _In_ va_list Args);

static inline _Post_equals_last_error_ DWORD
LoggerErrorFmt(_In_ DWORD Error, _In_z_ const WCHAR *Function, _In_z_ const WCHAR *Format, ...)
{
    va_list Args;
    va_start(Args, Format);
    DWORD LastError = LoggerErrorV(Error, Function, Format, Args);
    va_end(Args);
    return LastError;
}

static inline _Post_equals_last_error_ DWORD
LoggerLastErrorV(_In_z_ const WCHAR *Function, _In_z_ const WCHAR *Format, _In_ va_list Args)
{
    DWORD LastError = GetLastError();
    LoggerErrorV(LastError, Function, Format, Args);
    SetLastError(LastError);
    return LastError;
}

static inline _Post_equals_last_error_ DWORD
LoggerLastErrorFmt(_In_z_ const WCHAR *Function, _In_z_ const WCHAR *Format, ...)
{
    va_list Args;
    va_start(Args, Format);
    DWORD LastError = LoggerLastErrorV(Function, Format, Args);
    va_end(Args);
    return LastError;
}

VOID
LoggerGetRegistryKeyPath(_In_ HKEY Key, _Out_cap_c_(MAX_REG_PATH) WCHAR *Path);

#define __L(x) L##x
#define _L(x) __L(x)
#define LOG(lvl, msg, ...) (LoggerLogFmt((lvl), _L(__FUNCTION__), msg, __VA_ARGS__))
#define LOG_ERROR(err, msg, ...) (LoggerErrorFmt((err), _L(__FUNCTION__), msg, __VA_ARGS__))
#define LOG_LAST_ERROR(msg, ...) (LoggerLastErrorFmt(_L(__FUNCTION__), msg, __VA_ARGS__))

#define RET_ERROR(Ret, Error) ((Error) == ERROR_SUCCESS ? (Ret) : (SetLastError(Error), 0))

static inline _Return_type_success_(return != NULL) _Ret_maybenull_
    _Post_writable_byte_size_(Size) void *LoggerAlloc(_In_z_ const WCHAR *Function, _In_ DWORD Flags, _In_ SIZE_T Size)
{
    void *Data = HeapAlloc(ModuleHeap, Flags, Size);
    if (!Data)
    {
        LoggerLogFmt(WINTUN_LOG_ERR, Function, L"Out of memory (flags: 0x%x, requested size: 0x%zx)", Flags, Size);
        SetLastError(ERROR_OUTOFMEMORY);
    }
    return Data;
}
#define Alloc(Size) LoggerAlloc(_L(__FUNCTION__), 0, Size)
#define Zalloc(Size) LoggerAlloc(_L(__FUNCTION__), HEAP_ZERO_MEMORY, Size)

static inline void
Free(void *Ptr)
{
    if (!Ptr)
        return;
    DWORD LastError = GetLastError();
    HeapFree(ModuleHeap, 0, Ptr);
    SetLastError(LastError);
}
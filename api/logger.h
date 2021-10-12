/* SPDX-License-Identifier: GPL-2.0
 *
 * Copyright (C) 2018-2021 WireGuard LLC. All Rights Reserved.
 */

#pragma once

#include "wintun.h"
#include "main.h"
#include "registry.h"
#include <Windows.h>
#include <intsafe.h>
#include <stdarg.h>
#include <wchar.h>

extern WINTUN_LOGGER_CALLBACK Logger;

/**
 * @copydoc WINTUN_SET_LOGGER_FUNC
 */
WINTUN_SET_LOGGER_FUNC WintunSetLogger;

_Post_equals_last_error_
DWORD
LoggerLog(_In_ WINTUN_LOGGER_LEVEL Level, _In_z_ LPCWSTR LogLine);

_Post_equals_last_error_
DWORD
LoggerLogV(_In_ WINTUN_LOGGER_LEVEL Level, _In_z_ _Printf_format_string_ LPCWSTR Format, _In_ va_list Args);

_Post_equals_last_error_
static inline DWORD
LoggerLogFmt(_In_ WINTUN_LOGGER_LEVEL Level, _In_z_ _Printf_format_string_ LPCWSTR Format, ...)
{
    va_list Args;
    va_start(Args, Format);
    DWORD LastError = LoggerLogV(Level, Format, Args);
    va_end(Args);
    return LastError;
}

_Post_equals_last_error_
DWORD
LoggerError(_In_ DWORD Error, _In_z_ LPCWSTR Prefix);

_Post_equals_last_error_
DWORD
LoggerErrorV(_In_ DWORD Error, _In_z_ _Printf_format_string_ LPCWSTR Format, _In_ va_list Args);

_Post_equals_last_error_
static inline DWORD
LoggerErrorFmt(_In_ DWORD Error, _In_z_ _Printf_format_string_ LPCWSTR Format, ...)
{
    va_list Args;
    va_start(Args, Format);
    DWORD LastError = LoggerErrorV(Error, Format, Args);
    va_end(Args);
    return LastError;
}

_Post_equals_last_error_
static inline DWORD
LoggerLastErrorV(_In_z_ _Printf_format_string_ LPCWSTR Format, _In_ va_list Args)
{
    DWORD LastError = GetLastError();
    LoggerErrorV(LastError, Format, Args);
    SetLastError(LastError);
    return LastError;
}

_Post_equals_last_error_
static inline DWORD
LoggerLastErrorFmt(_In_z_ _Printf_format_string_ LPCWSTR Format, ...)
{
    va_list Args;
    va_start(Args, Format);
    DWORD LastError = LoggerLastErrorV(Format, Args);
    va_end(Args);
    return LastError;
}

VOID
LoggerGetRegistryKeyPath(_In_ HKEY Key, _Out_writes_z_(MAX_REG_PATH) LPWSTR Path);

#define LOG(lvl, msg, ...) (LoggerLogFmt((lvl), msg, __VA_ARGS__))
#define LOG_ERROR(err, msg, ...) (LoggerErrorFmt((err), msg, __VA_ARGS__))
#define LOG_LAST_ERROR(msg, ...) (LoggerLastErrorFmt(msg, __VA_ARGS__))

#define RET_ERROR(Ret, Error) ((Error) == ERROR_SUCCESS ? (Ret) : (SetLastError(Error), 0))

_Must_inspect_result_
DECLSPEC_ALLOCATOR
static inline _Return_type_success_(return != NULL)
_Post_maybenull_
_Post_writable_byte_size_(Size)
VOID *
LoggerAlloc(_In_z_ LPCWSTR Function, _In_ DWORD Flags, _In_ SIZE_T Size)
{
    VOID *Data = HeapAlloc(ModuleHeap, Flags, Size);
    if (!Data)
    {
        LoggerLogFmt(WINTUN_LOG_ERR, Function, L"Out of memory (flags: 0x%x, requested size: 0x%zx)", Flags, Size);
        SetLastError(ERROR_OUTOFMEMORY);
    }
    return Data;
}
_Must_inspect_result_
DECLSPEC_ALLOCATOR
static inline _Return_type_success_(return != NULL)
_Post_maybenull_
_Post_writable_byte_size_(Size)
VOID *
LoggerReAlloc(_In_z_ LPCWSTR Function, _In_ DWORD Flags, _Frees_ptr_opt_ LPVOID Mem, _In_ SIZE_T Size)
{
    VOID *Data = Mem ? HeapReAlloc(ModuleHeap, Flags, Mem, Size) : HeapAlloc(ModuleHeap, Flags, Size);
    if (!Data)
    {
        LoggerLogFmt(WINTUN_LOG_ERR, Function, L"Out of memory (flags: 0x%x, requested size: 0x%zx)", Flags, Size);
        SetLastError(ERROR_OUTOFMEMORY);
    }
    return Data;
}

#define __L(x) L##x
#define _L(x) __L(x)
#define Alloc(Size) LoggerAlloc(_L(__FUNCTION__), 0, Size)
#define ReAlloc(Mem, Size) LoggerReAlloc(_L(__FUNCTION__), 0, Mem, Size)
#define Zalloc(Size) LoggerAlloc(_L(__FUNCTION__), HEAP_ZERO_MEMORY, Size)
#define ReZalloc(Mem, Size) LoggerReAlloc(_L(__FUNCTION__), HEAP_ZERO_MEMORY, Mem, Size)

_Must_inspect_result_
DECLSPEC_ALLOCATOR
static inline _Return_type_success_(return != NULL)
_Post_maybenull_
_Post_writable_byte_size_((NumberOfElements) * (SizeOfOneElement))
VOID *
LoggerAllocArray(_In_z_ LPCWSTR Function, _In_ DWORD Flags, _In_ SIZE_T NumberOfElements, _In_ SIZE_T SizeOfOneElement)
{
    SIZE_T Size;
    if (FAILED(SIZETMult(NumberOfElements, SizeOfOneElement, &Size)))
        return NULL;
    return LoggerAlloc(Function, Flags, Size);
}
_Must_inspect_result_
DECLSPEC_ALLOCATOR
static inline _Return_type_success_(return != NULL)
_Post_maybenull_
_Post_writable_byte_size_((NumberOfElements) * (SizeOfOneElement))
VOID *
LoggerReAllocArray(
    _In_z_ LPCWSTR Function,
    _In_ DWORD Flags,
    _Frees_ptr_opt_ LPVOID Mem,
    _In_ SIZE_T NumberOfElements,
    _In_ SIZE_T SizeOfOneElement)
{
    SIZE_T Size;
    if (FAILED(SIZETMult(NumberOfElements, SizeOfOneElement, &Size)))
        return NULL;
    return LoggerReAlloc(Function, Flags, Mem, Size);
}
#define AllocArray(Count, Size) LoggerAllocArray(_L(__FUNCTION__), 0, Count, Size)
#define ReAllocArray(Mem, Count, Size) LoggerReAllocArray(_L(__FUNCTION__), 0, Mem, Count, Size)
#define ZallocArray(Count, Size) LoggerAllocArray(_L(__FUNCTION__), HEAP_ZERO_MEMORY, Count, Size)
#define ReZallocArray(Mem, Count, Size) LoggerReAllocArray(_L(__FUNCTION__), HEAP_ZERO_MEMORY, Mem, Count, Size)

static inline VOID
Free(_Frees_ptr_opt_ VOID *Ptr)
{
    if (!Ptr)
        return;
    DWORD LastError = GetLastError();
    HeapFree(ModuleHeap, 0, Ptr);
    SetLastError(LastError);
}

/* SPDX-License-Identifier: GPL-2.0
 *
 * Copyright (C) 2018-2021 WireGuard LLC. All Rights Reserved.
 */

#pragma once

#include "wintun.h"
#include <Windows.h>

#define MAX_REG_PATH \
    256 /* Maximum registry path length \
           https://support.microsoft.com/en-us/help/256986/windows-registry-information-for-advanced-users */

/**
 * Validates and/or sanitizes string value read from registry.
 *
 * @param Buf           On input, it contains a pointer to pointer where the data is stored. The data must be allocated
 *                      using HeapAlloc(ModuleHeap, 0). On output, it contains a pointer to pointer where the sanitized
 *                      data is stored. It must be released with HeapFree(ModuleHeap, 0, *Buf) after use.
 *
 * @param Len           Length of data string in wide characters.
 *
 * @param ValueType     Type of data. Must be either REG_SZ or REG_EXPAND_SZ. REG_MULTI_SZ is treated like REG_SZ; only
 *                      the first string of a multi-string is to be used.
 *
 * @return If the function succeeds, the return value is nonzero. If the function fails, the return value is zero. To
 *         get extended error information, call GetLastError.
 */
_Must_inspect_result_
_Return_type_success_(return != FALSE)
BOOL
RegistryGetString(_Inout_ LPWSTR *Buf, _In_ DWORD Len, _In_ DWORD ValueType);

/**
 * Reads string value from registry key.
 *
 * @param Key           Handle of the registry key to read from. Must be opened with read access.
 *
 * @param Name          Name of the value to read.
 *
 * @param Value         Pointer to string to retrieve registry value. If the value type is REG_EXPAND_SZ the value is
 *                      expanded using ExpandEnvironmentStrings(). If the value type is REG_MULTI_SZ, only the first
 *                      string from the multi-string is returned. The string must be released with
 *                      HeapFree(ModuleHeap, 0, Value) after use.
 *
 * @Log                 Set to TRUE to log all failures; FALSE to skip logging the innermost errors. Skipping innermost
 *                      errors reduces log clutter when we are using RegistryQueryString() from
 *                      RegistryQueryStringWait() and some errors are expected to occur.
 *
 * @return String with registry value on success; If the function fails, the return value is zero. To get extended error
 *         information, call GetLastError.
 */
_Must_inspect_result_
_Return_type_success_(return != NULL)
_Post_maybenull_
LPWSTR
RegistryQueryString(_In_ HKEY Key, _In_opt_z_ LPCWSTR Name, _In_ BOOL Log);

/**
 * Reads a 32-bit DWORD value from registry key.
 *
 * @param Key           Handle of the registry key to read from. Must be opened with read access.
 *
 * @param Name          Name of the value to read.
 *
 * @param Value         Pointer to DWORD to retrieve registry value.
 *
 * @Log                 Set to TRUE to log all failures; FALSE to skip logging the innermost errors. Skipping innermost
 *                      errors reduces log clutter when we are using RegistryQueryDWORD() from
 *                      RegistryQueryDWORDWait() and some errors are expected to occur.
 *
 * @return If the function succeeds, the return value is nonzero. If the function fails, the return value is zero. To
 *         get extended error information, call GetLastError.
 */
_Must_inspect_result_
_Return_type_success_(return != FALSE)
BOOL
RegistryQueryDWORD(_In_ HKEY Key, _In_opt_z_ LPCWSTR Name, _Out_ DWORD *Value, _In_ BOOL Log);

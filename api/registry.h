/* SPDX-License-Identifier: GPL-2.0
 *
 * Copyright (C) 2018-2020 WireGuard LLC. All Rights Reserved.
 */

#pragma once

#include "wintun.h"

#define MAX_REG_PATH \
    256 /* Maximum registry path length \
           https://support.microsoft.com/en-us/help/256986/windows-registry-information-for-advanced-users */

/**
 * Opens the specified registry key. It waits for the registry key to become available.
 *
 * @param Key           Handle of the parent registry key. Must be opened with notify access.
 *
 * @param Path          Subpath of the registry key to open.
 *
 * @param Access        A mask that specifies the desired access rights to the key to be opened.
 *
 * @param Timeout       Timeout to wait for the value in milliseconds.
 *
 * @param KeyOut        Pointer to a variable to receive the key handle.
 *
 * @return ERROR_SUCCESS on success; WAIT_TIMEOUT on timeout; Win32 error code otherwise.
 */
WINTUN_STATUS
RegistryOpenKeyWait(
    _In_ HKEY Key,
    _In_z_count_c_(MAX_REG_PATH) const WCHAR *Path,
    _In_ DWORD Access,
    _In_ DWORD Timeout,
    _Out_ HKEY *KeyOut);

/**
 * Validates and/or sanitizes string value read from registry.
 *
 * @param Buf           On input, it contains a pointer to pointer where the data is stored. The data must be allocated
 *                      using HeapAlloc(GetProcessHeap(), 0). On output, it contains a pointer to pointer where the
 *                      sanitized data is stored. It must be released with HeapFree(GetProcessHeap(), 0, *Buf) after
 *                      use.
 *
 * @param Len           Length of data string in wide characters.
 *
 * @param ValueType     Type of data. Must be either REG_SZ or REG_EXPAND_SZ. REG_MULTI_SZ is treated like REG_SZ; only
 *                      the first string of a multi-string is to be used.
 *
 * @return ERROR_SUCCESS on success; Win32 error code otherwise.
 */
WINTUN_STATUS
RegistryGetString(_Inout_ WCHAR **Buf, _In_ DWORD Len, _In_ DWORD ValueType);

/**
 * Validates and/or sanitizes multi-string value read from registry.
 *
 * @param Buf           On input, it contains a pointer to pointer where the data is stored. The data must be allocated
 *                      using HeapAlloc(GetProcessHeap(), 0). On output, it contains a pointer to pointer where the
 *                      sanitized data is stored. It must be released with HeapFree(GetProcessHeap(), 0, *Buf) after
 *                      use.
 *
 * @param Len           Length of data string in wide characters.
 *
 * @param ValueType     Type of data. Must be one of REG_MULTI_SZ, REG_SZ or REG_EXPAND_SZ.
 *
 * @return ERROR_SUCCESS on success; Win32 error code otherwise.
 */
WINTUN_STATUS
RegistryGetMultiString(_Inout_ WCHAR **Buf, _In_ DWORD Len, _In_ DWORD ValueType);

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
 *                      HeapFree(GetProcessHeap(), 0, Value) after use.
 *
 * @return ERROR_SUCCESS on success; ERROR_INVALID_DATATYPE when the registry value is not a string; Win32 error code
 * otherwise.
 */
WINTUN_STATUS
RegistryQueryString(_In_ HKEY Key, _In_opt_z_ const WCHAR *Name, _Out_ WCHAR **Value);

/**
 * Reads string value from registry key. It waits for the registry value to become available.
 *
 * @param Key           Handle of the registry key to read from. Must be opened with read and notify access.
 *
 * @param Name          Name of the value to read.
 *
 * @param Timeout       Timeout to wait for the value in milliseconds.
 *
 * @param Value         Pointer to string to retrieve registry value. If the value type is REG_EXPAND_SZ the value is
 *                      expanded using ExpandEnvironmentStrings(). If the value type is REG_MULTI_SZ, only the first
 *                      string from the multi-string is returned. The string must be released with
 *                      HeapFree(GetProcessHeap(), 0, Value) after use.
 *
 * @return ERROR_SUCCESS on success; WAIT_TIMEOUT on timeout; ERROR_INVALID_DATATYPE when the registry value is not a
 * string; Win32 error code otherwise.
 */
WINTUN_STATUS
RegistryQueryStringWait(_In_ HKEY Key, _In_opt_z_ const WCHAR *Name, _In_ DWORD Timeout, _Out_ WCHAR **Value);

/**
 * Reads a 32-bit DWORD value from registry key.
 *
 * @param Key           Handle of the registry key to read from. Must be opened with read access.
 *
 * @param Name          Name of the value to read.
 *
 * @param Value         Pointer to DWORD to retrieve registry value.
 *
 * @return ERROR_SUCCESS on success; ERROR_INVALID_DATATYPE when registry value exist but not REG_DWORD type;
 * ERROR_INVALID_DATA when registry value size is not 4 bytes; Win32 error code otherwise.
 */
WINTUN_STATUS
RegistryQueryDWORD(_In_ HKEY Key, _In_opt_z_ const WCHAR *Name, _Out_ DWORD *Value);

/**
 * Reads a 32-bit DWORD value from registry key. It waits for the registry value to become available.
 *
 * @param Key           Handle of the registry key to read from. Must be opened with read access.
 *
 * @param Name          Name of the value to read.
 *
 * @param Timeout       Timeout to wait for the value in milliseconds.
 *
 * @param Value         Pointer to DWORD to retrieve registry value.
 *
 * @return ERROR_SUCCESS on success; WAIT_TIMEOUT on timeout; ERROR_INVALID_DATATYPE when registry value exist but not
 * REG_DWORD type; ERROR_INVALID_DATA when registry value size is not 4 bytes; Win32 error code otherwise.
 */
WINTUN_STATUS
RegistryQueryDWORDWait(_In_ HKEY Key, _In_opt_z_ const WCHAR *Name, _In_ DWORD Timeout, _Out_ DWORD *Value);

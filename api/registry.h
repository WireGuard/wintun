/* SPDX-License-Identifier: GPL-2.0
 *
 * Copyright (C) 2018-2020 WireGuard LLC. All Rights Reserved.
 */

#pragma once

#include "api.h"

#define MAX_REG_PATH \
    256 /* Maximum registry path length \
           https://support.microsoft.com/en-us/help/256986/windows-registry-information-for-advanced-users */

WINTUN_STATUS
RegistryOpenKeyWait(
    _In_ HKEY Key,
    _In_z_count_c_(MAX_REG_PATH) const WCHAR *Path,
    _In_ DWORD Access,
    _In_ DWORD Timeout,
    _Out_ HKEY *KeyOut);

WINTUN_STATUS
RegistryGetString(_Inout_ WCHAR **Buf, _In_ DWORD Len, _In_ DWORD ValueType);

WINTUN_STATUS
RegistryGetMultiString(_Inout_ WCHAR **Buf, _In_ DWORD Len, _In_ DWORD ValueType);

WINTUN_STATUS
RegistryQueryString(_In_ HKEY Key, _In_opt_z_ const WCHAR *Name, _Out_ WCHAR **Value);

WINTUN_STATUS
RegistryQueryStringWait(_In_ HKEY Key, _In_opt_z_ const WCHAR *Name, _In_ DWORD Timeout, _Out_ WCHAR **Value);

WINTUN_STATUS
RegistryQueryDWORD(_In_ HKEY Key, _In_opt_z_ const WCHAR *Name, _Out_ DWORD *Value);

WINTUN_STATUS
RegistryQueryDWORDWait(_In_ HKEY Key, _In_opt_z_ const WCHAR *Name, _In_ DWORD Timeout, _Out_ DWORD *Value);

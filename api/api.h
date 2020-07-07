/* SPDX-License-Identifier: GPL-2.0
 *
 * Copyright (C) 2018-2020 WireGuard LLC. All Rights Reserved.
 */

#pragma once

#include <Windows.h>

extern HINSTANCE ResourceModule;

_Check_return_
HANDLE
TakeNameMutex(_In_z_ LPCWSTR Pool);

void
ReleaseNameMutex(_In_ HANDLE Mutex);

void
NamespaceInit();

void
NamespaceCleanup();

_Return_type_success_(return ==
                             0) extern DWORD(WINAPI *NciSetConnectionName)(_In_ LPCGUID Guid, _In_z_ LPCWSTR NewName);

_Return_type_success_(return == 0) extern DWORD(WINAPI *NciGetConnectionName)(
    _In_ LPCGUID Guid,
    _Out_z_bytecap_(InDestNameBytes) LPWSTR Name,
    _In_ DWORD InDestNameBytes,
    _Out_opt_ DWORD *OutDestNameBytes);

void
NciInit();

void
NciCleanup();

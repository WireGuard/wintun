/* SPDX-License-Identifier: GPL-2.0
 *
 * Copyright (C) 2018-2020 WireGuard LLC. All Rights Reserved.
 */

#pragma once

#include <Windows.h>

extern DWORD(WINAPI *NciSetConnectionName)(_In_ const GUID *Guid, _In_z_ const WCHAR *NewName);

extern DWORD(WINAPI *NciGetConnectionName)(
    _In_ const GUID *Guid,
    _Out_z_bytecap_(InDestNameBytes) WCHAR *Name,
    _In_ DWORD InDestNameBytes,
    _Out_opt_ DWORD *OutDestNameBytes);

void
NciInit(void);

void
NciCleanup(void);

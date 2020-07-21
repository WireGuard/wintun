/* SPDX-License-Identifier: GPL-2.0
 *
 * Copyright (C) 2018-2020 WireGuard LLC. All Rights Reserved.
 */

#include "api.h"

static HMODULE NciModule;

WINSTATUS(WINAPI *NciSetConnectionName)(_In_ LPCGUID Guid, _In_z_ LPCWSTR NewName);

WINSTATUS(WINAPI *NciGetConnectionName)
(_In_ LPCGUID Guid,
 _Out_z_bytecap_(InDestNameBytes) LPWSTR Name,
 _In_ DWORD InDestNameBytes,
 _Out_opt_ DWORD *OutDestNameBytes);

void
NciInit()
{
    NciModule = LoadLibraryW(L"nci.dll");
    if (!NciModule)
        return;
    NciSetConnectionName = (DWORD(WINAPI *)(LPCGUID, LPCWSTR))GetProcAddress(NciModule, "NciSetConnectionName");
    NciGetConnectionName =
        (DWORD(WINAPI *)(LPCGUID, LPWSTR, DWORD, DWORD *))GetProcAddress(NciModule, "NciGetConnectionName");
}

void
NciCleanup()
{
    if (NciModule)
        FreeLibrary(NciModule);
}

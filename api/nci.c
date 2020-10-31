/* SPDX-License-Identifier: GPL-2.0
 *
 * Copyright (C) 2018-2020 WireGuard LLC. All Rights Reserved.
 */

#include "pch.h"

static HMODULE NciModule;

DWORD(WINAPI *NciSetConnectionName)(_In_ const GUID *Guid, _In_z_ const WCHAR *NewName);

DWORD(WINAPI *NciGetConnectionName)
(_In_ const GUID *Guid,
 _Out_z_bytecap_(InDestNameBytes) WCHAR *Name,
 _In_ DWORD InDestNameBytes,
 _Out_opt_ DWORD *OutDestNameBytes);

WINTUN_STATUS
NciInit(void)
{
    NciModule = LoadLibraryExW(L"nci.dll", NULL, LOAD_LIBRARY_SEARCH_SYSTEM32);
    if (!NciModule)
        return GetLastError();
    NciSetConnectionName =
        (DWORD(WINAPI *)(const GUID *, const WCHAR *))GetProcAddress(NciModule, "NciSetConnectionName");
    if (!NciSetConnectionName)
        return GetLastError();
    NciGetConnectionName =
        (DWORD(WINAPI *)(const GUID *, WCHAR *, DWORD, DWORD *))GetProcAddress(NciModule, "NciGetConnectionName");
    if (!NciGetConnectionName)
        return GetLastError();
    return ERROR_SUCCESS;
}

void
NciCleanup(void)
{
    if (NciModule)
        FreeLibrary(NciModule);
}

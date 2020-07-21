/* SPDX-License-Identifier: GPL-2.0
 *
 * Copyright (C) 2018-2020 WireGuard LLC. All Rights Reserved.
 */

#include "pch.h"

HINSTANCE ResourceModule;

/**
 * Returns the version of the Wintun driver and NDIS system currently loaded.
 */
WINTUN_STATUS WINAPI
WintunGetVersion(
    _Out_ DWORD *DriverVersionMaj,
    _Out_ DWORD *DriverVersionMin,
    _Out_ DWORD *NdisVersionMaj,
    _Out_ DWORD *NdisVersionMin)
{
    HKEY Key;
    DWORD Result =
        RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Services\\Wintun", 0, KEY_QUERY_VALUE, &Key);
    if (Result != ERROR_SUCCESS)
        return Result;
    Result = RegistryQueryDWORD(Key, L"DriverMajorVersion", DriverVersionMaj);
    if (Result != ERROR_SUCCESS)
        goto cleanupKey;
    Result = RegistryQueryDWORD(Key, L"DriverMinorVersion", DriverVersionMin);
    if (Result != ERROR_SUCCESS)
        goto cleanupKey;
    Result = RegistryQueryDWORD(Key, L"NdisMajorVersion", NdisVersionMaj);
    if (Result != ERROR_SUCCESS)
        goto cleanupKey;
    Result = RegistryQueryDWORD(Key, L"NdisMinorVersion", NdisVersionMin);
cleanupKey:
    RegCloseKey(Key);
    return Result;
}

BOOL APIENTRY
DllMain(_In_ HINSTANCE hinstDLL, _In_ DWORD fdwReason, _In_ LPVOID lpvReserved)
{
    UNREFERENCED_PARAMETER(lpvReserved);

    switch (fdwReason)
    {
    case DLL_PROCESS_ATTACH:
        ResourceModule = hinstDLL;
        NamespaceInit();
        NciInit();
        break;

    case DLL_PROCESS_DETACH:
        NciCleanup();
        NamespaceCleanup();
        break;
    }
    return TRUE;
}

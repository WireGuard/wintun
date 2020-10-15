/* SPDX-License-Identifier: GPL-2.0
 *
 * Copyright (C) 2018-2020 WireGuard LLC. All Rights Reserved.
 */

#include "pch.h"

HINSTANCE ResourceModule;

/**
 * Returns the version of the Wintun driver and NDIS system currently loaded.
 *
 * @param DriverVersionMaj  Pointer to a DWORD to receive the Wintun driver major version number.
 *
 * @param DriverVersionMin  Pointer to a DWORD to receive the Wintun driver minor version number.
 *
 * @param NdisVersionMaj  Pointer to a DWORD to receive the NDIS major version number.
 *
 * @param NdisVersionMin  Pointer to a DWORD to receive the NDIS minor version number.
 *
 * @return ERROR_SUCCESS on success; Win32 error code otherwise.
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
        return LOG_ERROR(L"Failed to open registry key", Result);
    Result = RegistryQueryDWORD(Key, L"DriverMajorVersion", DriverVersionMaj);
    if (Result != ERROR_SUCCESS)
    {
        LOG_ERROR(L"Failed to query DriverMajorVersion value", Result);
        goto cleanupKey;
    }
    Result = RegistryQueryDWORD(Key, L"DriverMinorVersion", DriverVersionMin);
    if (Result != ERROR_SUCCESS)
    {
        LOG_ERROR(L"Failed to query DriverMinorVersion value", Result);
        goto cleanupKey;
    }
    Result = RegistryQueryDWORD(Key, L"NdisMajorVersion", NdisVersionMaj);
    if (Result != ERROR_SUCCESS)
    {
        LOG_ERROR(L"Failed to query NdisMajorVersion value", Result);
        goto cleanupKey;
    }
    Result = RegistryQueryDWORD(Key, L"NdisMinorVersion", NdisVersionMin);
    if (Result != ERROR_SUCCESS)
        LOG_ERROR(L"Failed to query NdisMinorVersion value", Result);
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
        AdapterInit();
        NamespaceInit();
        NciInit();
        break;

    case DLL_PROCESS_DETACH:
        NciCleanup();
        NamespaceCleanup();
        AdapterCleanup();
        break;
    }
    return TRUE;
}

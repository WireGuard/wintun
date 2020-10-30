/* SPDX-License-Identifier: GPL-2.0
 *
 * Copyright (C) 2018-2020 WireGuard LLC. All Rights Reserved.
 */

#include "pch.h"

HINSTANCE ResourceModule;
HANDLE ModuleHeap;
static SECURITY_ATTRIBUTES SecurityAttributesSystem = { .nLength = sizeof(SECURITY_ATTRIBUTES) };
SECURITY_ATTRIBUTES *SecurityAttributes;

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
    if (RegistryQueryDWORD(Key, L"DriverMajorVersion", DriverVersionMaj, FALSE) != ERROR_SUCCESS ||
        RegistryQueryDWORD(Key, L"DriverMinorVersion", DriverVersionMin, FALSE) != ERROR_SUCCESS)
    {
        *DriverVersionMaj = WINTUN_VERSION_MAJ;
        *DriverVersionMin = WINTUN_VERSION_MIN;
    }
    Result = RegistryQueryDWORD(Key, L"NdisMajorVersion", NdisVersionMaj, TRUE);
    if (Result != ERROR_SUCCESS)
    {
        LOG(WINTUN_LOG_ERR, L"Failed to query NdisMajorVersion value");
        goto cleanupKey;
    }
    Result = RegistryQueryDWORD(Key, L"NdisMinorVersion", NdisVersionMin, TRUE);
    if (Result != ERROR_SUCCESS)
        LOG(WINTUN_LOG_ERR, L"Failed to query NdisMinorVersion value");
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
        ModuleHeap = HeapCreate(0, 0, 0);
#ifndef _DEBUG
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            L"O:SYD:P(A;;GA;;;SY)", SDDL_REVISION_1, &SecurityAttributesSystem.lpSecurityDescriptor, NULL);
        SecurityAttributes = &SecurityAttributesSystem;
#endif
        AdapterInit();
        NamespaceInit();
        NciInit();
        break;

    case DLL_PROCESS_DETACH:
        NciCleanup();
        NamespaceCleanup();
#ifndef _DEBUG
        LocalFree(SecurityAttributesSystem.lpSecurityDescriptor);
#endif
        HeapDestroy(ModuleHeap);
        break;
    }
    return TRUE;
}

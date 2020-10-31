/* SPDX-License-Identifier: GPL-2.0
 *
 * Copyright (C) 2018-2020 WireGuard LLC. All Rights Reserved.
 */

#include "adapter.h"
#include "entry.h"
#include "logger.h"
#include "registry.h"
#include "namespace.h"
#include "nci.h"
#include "wintun.h"

#include <Windows.h>
#pragma warning(push)
#pragma warning(disable : 4201)
/* nonstandard extension used: nameless struct/union */
#include <delayimp.h>
#pragma warning(pop)
#include <sddl.h>

HINSTANCE ResourceModule;
HANDLE ModuleHeap;
SECURITY_ATTRIBUTES SecurityAttributes = { .nLength = sizeof(SECURITY_ATTRIBUTES) };

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
        /* TODO: Drop the fallback to WINTUN_VERSION_MAJ & WINTUN_VERSION_MIN when Windows 7 support is discontinued. */
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

static FARPROC WINAPI DelayedLoadLibraryHook(unsigned dliNotify, PDelayLoadInfo pdli)
{
    if (dliNotify != dliNotePreLoadLibrary)
        return NULL;
    HMODULE Library = LoadLibraryExA(pdli->szDll, NULL, LOAD_LIBRARY_SEARCH_SYSTEM32);
    if (!Library)
        abort();
    return (FARPROC)Library;
}

const PfnDliHook __pfnDliNotifyHook2 = DelayedLoadLibraryHook;

BOOL APIENTRY
DllMain(_In_ HINSTANCE hinstDLL, _In_ DWORD fdwReason, _In_ LPVOID lpvReserved)
{
    UNREFERENCED_PARAMETER(lpvReserved);

    switch (fdwReason)
    {
    case DLL_PROCESS_ATTACH:
        ResourceModule = hinstDLL;
        ModuleHeap = HeapCreate(0, 0, 0);
        if (!ModuleHeap)
            return FALSE;
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            L"O:SYD:P(A;;GA;;;SY)", SDDL_REVISION_1, &SecurityAttributes.lpSecurityDescriptor, NULL);
        AdapterInit();
        NamespaceInit();
        if (NciInit() != ERROR_SUCCESS)
            return FALSE;
        break;

    case DLL_PROCESS_DETACH:
        NciCleanup();
        NamespaceCleanup();
        LocalFree(SecurityAttributes.lpSecurityDescriptor);
        HeapDestroy(ModuleHeap);
        break;
    }
    return TRUE;
}

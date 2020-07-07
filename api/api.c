/* SPDX-License-Identifier: GPL-2.0
 *
 * Copyright (C) 2018-2020 WireGuard LLC. All Rights Reserved.
 */

#include "api.h"

HINSTANCE ResourceModule;

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

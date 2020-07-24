/* SPDX-License-Identifier: GPL-2.0
 *
 * Copyright (C) 2018-2020 WireGuard LLC. All Rights Reserved.
 */

#include "pch.h"

#if defined(_M_AMD64) || defined(_M_ARM64)

__declspec(dllexport) VOID __stdcall CreateAdapter(HWND hwnd, HINSTANCE hinst, LPSTR lpszCmdLine, int nCmdShow)
{
    UNREFERENCED_PARAMETER(hwnd);
    UNREFERENCED_PARAMETER(hinst);
    UNREFERENCED_PARAMETER(lpszCmdLine);
    UNREFERENCED_PARAMETER(nCmdShow);

    int Argc;
    LPWSTR *Argv = CommandLineToArgvW(GetCommandLineW(), &Argc);
    if (Argc < 4)
        goto cleanupArgv;

    if (wcslen(Argv[2]) >= MAX_POOL)
        goto cleanupArgv;
    if (wcslen(Argv[3]) >= MAX_ADAPTER_NAME)
        goto cleanupArgv;
    GUID RequestedGUID;
    if (Argc > 4 && FAILED(CLSIDFromString(Argv[4], &RequestedGUID)))
        goto cleanupArgv;
    WINTUN_ADAPTER *Adapter;
    BOOL RebootRequired = FALSE;
    DWORD Result = WintunCreateAdapter(Argv[2], Argv[3], Argc > 4 ? &RequestedGUID : NULL, &Adapter, &RebootRequired);
    if (Result != ERROR_SUCCESS)
        goto cleanupArgv;

    WintunFreeAdapter(Adapter);
cleanupArgv:
    LocalFree(Argv);
}

__declspec(dllexport) VOID __stdcall DeleteAdapter(HWND hwnd, HINSTANCE hinst, LPSTR lpszCmdLine, int nCmdShow)
{
    UNREFERENCED_PARAMETER(hwnd);
    UNREFERENCED_PARAMETER(hinst);
    UNREFERENCED_PARAMETER(lpszCmdLine);
    UNREFERENCED_PARAMETER(nCmdShow);

    int Argc;
    LPWSTR *Argv = CommandLineToArgvW(GetCommandLineW(), &Argc);
    if (Argc < 3)
        goto cleanupArgv;

    WINTUN_ADAPTER Adapter = { 0 };
    if (FAILED(CLSIDFromString(Argv[2], &Adapter.CfgInstanceID)))
        goto cleanupArgv;
    BOOL RebootRequired = FALSE;
    WintunDeleteAdapter(&Adapter, &RebootRequired);

cleanupArgv:
    LocalFree(Argv);
}

#endif

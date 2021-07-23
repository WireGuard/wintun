/* SPDX-License-Identifier: GPL-2.0
 *
 * Copyright (C) 2018-2021 WireGuard LLC. All Rights Reserved.
 */

#include "adapter.h"
#include "entry.h"
#include "logger.h"
#include "registry.h"
#include "namespace.h"
#include "wintun.h"

#include <Windows.h>
#pragma warning(push)
#pragma warning(disable : 4201)
/* nonstandard extension used: nameless struct/union */
#include <delayimp.h>
#pragma warning(pop)
#include <sddl.h>
#include <winefs.h>
#include <stdlib.h>

HINSTANCE ResourceModule;
HANDLE ModuleHeap;
SECURITY_ATTRIBUTES SecurityAttributes = { .nLength = sizeof(SECURITY_ATTRIBUTES) };
BOOL IsLocalSystem;

static FARPROC WINAPI
DelayedLoadLibraryHook(unsigned dliNotify, PDelayLoadInfo pdli)
{
    if (dliNotify != dliNotePreLoadLibrary)
        return NULL;
    HMODULE Library = LoadLibraryExA(pdli->szDll, NULL, LOAD_LIBRARY_SEARCH_SYSTEM32);
    if (!Library)
        abort();
    return (FARPROC)Library;
}

const PfnDliHook __pfnDliNotifyHook2 = DelayedLoadLibraryHook;

static BOOL
InitializeSecurityObjects(void)
{
    BYTE LocalSystemSid[MAX_SID_SIZE];
    DWORD RequiredBytes = sizeof(LocalSystemSid);
    HANDLE CurrentProcessToken;
    struct
    {
        TOKEN_USER MaybeLocalSystem;
        CHAR LargeEnoughForLocalSystem[MAX_SID_SIZE];
    } TokenUserBuffer;
    BOOL Ret = FALSE;

    if (!CreateWellKnownSid(WinLocalSystemSid, NULL, LocalSystemSid, &RequiredBytes))
        return FALSE;

    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &CurrentProcessToken))
        return FALSE;

    if (!GetTokenInformation(CurrentProcessToken, TokenUser, &TokenUserBuffer, sizeof(TokenUserBuffer), &RequiredBytes))
        goto cleanupProcessToken;

    IsLocalSystem = EqualSid(TokenUserBuffer.MaybeLocalSystem.User.Sid, LocalSystemSid);
    Ret = ConvertStringSecurityDescriptorToSecurityDescriptorW(
        IsLocalSystem ? L"O:SYD:P(A;;GA;;;SY)(A;;GA;;;BA)S:(ML;;NWNRNX;;;HI)"
                      : L"O:BAD:P(A;;GA;;;SY)(A;;GA;;;BA)S:(ML;;NWNRNX;;;HI)",
        SDDL_REVISION_1,
        &SecurityAttributes.lpSecurityDescriptor,
        NULL);

cleanupProcessToken:
    CloseHandle(CurrentProcessToken);
    return Ret;
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
        if (!ModuleHeap)
            return FALSE;
        if (!InitializeSecurityObjects())
        {
            HeapDestroy(ModuleHeap);
            return FALSE;
        }
        AdapterInit();
        NamespaceInit();
        break;

    case DLL_PROCESS_DETACH:
        NamespaceDone();
        LocalFree(SecurityAttributes.lpSecurityDescriptor);
        HeapDestroy(ModuleHeap);
        break;
    }
    return TRUE;
}

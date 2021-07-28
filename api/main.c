/* SPDX-License-Identifier: GPL-2.0
 *
 * Copyright (C) 2018-2021 WireGuard LLC. All Rights Reserved.
 */

#include "logger.h"
#include "adapter.h"
#include "main.h"
#include "namespace.h"
#include "registry.h"
#include "ntdll.h"

#include <Windows.h>
#include <delayimp.h>
#include <sddl.h>
#include <winefs.h>
#include <stdlib.h>

HINSTANCE ResourceModule;
HANDLE ModuleHeap;
SECURITY_ATTRIBUTES SecurityAttributes = { .nLength = sizeof(SECURITY_ATTRIBUTES) };
BOOL IsLocalSystem;
USHORT NativeMachine = IMAGE_FILE_PROCESS;
BOOL IsWindows10;

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

static BOOL InitializeSecurityObjects(VOID)
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

static VOID EnvInit(VOID)
{
    DWORD MajorVersion;
    RtlGetNtVersionNumbers(&MajorVersion, NULL, NULL);
    IsWindows10 = MajorVersion >= 10;

#ifdef MAYBE_WOW64
    typedef BOOL(WINAPI * IsWow64Process2_t)(
        _In_ HANDLE hProcess, _Out_ USHORT * pProcessMachine, _Out_opt_ USHORT * pNativeMachine);
    HANDLE Kernel32;
    IsWow64Process2_t IsWow64Process2;
    USHORT ProcessMachine;
    if ((Kernel32 = GetModuleHandleW(L"kernel32.dll")) == NULL ||
        (IsWow64Process2 = (IsWow64Process2_t)GetProcAddress(Kernel32, "IsWow64Process2")) == NULL ||
        !IsWow64Process2(GetCurrentProcess(), &ProcessMachine, &NativeMachine))
    {
        BOOL IsWoW64;
        NativeMachine =
            IsWow64Process(GetCurrentProcess(), &IsWoW64) && IsWoW64 ? IMAGE_FILE_MACHINE_AMD64 : IMAGE_FILE_PROCESS;
    }
#endif
}

BOOL APIENTRY
DllMain(_In_ HINSTANCE hinstDLL, _In_ DWORD fdwReason, _In_ LPVOID lpvReserved)
{
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
        EnvInit();
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

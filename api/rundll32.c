/* SPDX-License-Identifier: GPL-2.0
 *
 * Copyright (C) 2018-2020 WireGuard LLC. All Rights Reserved.
 */

#include "pch.h"

#if defined(_M_AMD64) || defined(_M_ARM64)

static BOOL ElevateToSystem(VOID)
{
    HANDLE CurrentProcessToken, ThreadToken, ProcessSnapshot, WinlogonProcess, WinlogonToken, DuplicatedToken;
    PROCESSENTRY32W ProcessEntry = { .dwSize = sizeof(PROCESSENTRY32W) };
    BOOL Ret;
    DWORD LastError = ERROR_SUCCESS;
    TOKEN_PRIVILEGES Privileges = { .PrivilegeCount = 1, .Privileges = { { .Attributes = SE_PRIVILEGE_ENABLED } } };
    CHAR LocalSystemSid[0x400];
    DWORD RequiredBytes = sizeof(LocalSystemSid);
    struct
    {
        TOKEN_USER MaybeLocalSystem;
        CHAR LargeEnoughForLocalSystem[0x400];
    } TokenUserBuffer;

    Ret = CreateWellKnownSid(WinLocalSystemSid, NULL, &LocalSystemSid, &RequiredBytes);
    LastError = GetLastError();
    if (!Ret)
        goto cleanup;
    Ret = OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &CurrentProcessToken);
    LastError = GetLastError();
    if (!Ret)
        goto cleanup;
    Ret =
        GetTokenInformation(CurrentProcessToken, TokenUser, &TokenUserBuffer, sizeof(TokenUserBuffer), &RequiredBytes);
    LastError = GetLastError();
    CloseHandle(CurrentProcessToken);
    if (!Ret)
        goto cleanup;
    if (EqualSid(TokenUserBuffer.MaybeLocalSystem.User.Sid, LocalSystemSid))
        return TRUE;
    Ret = LookupPrivilegeValueW(NULL, SE_DEBUG_NAME, &Privileges.Privileges[0].Luid);
    LastError = GetLastError();
    if (!Ret)
        goto cleanup;
    ProcessSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    LastError = GetLastError();
    if (ProcessSnapshot == INVALID_HANDLE_VALUE)
        goto cleanup;
    for (Ret = Process32FirstW(ProcessSnapshot, &ProcessEntry); Ret;
         Ret = Process32NextW(ProcessSnapshot, &ProcessEntry))
    {
        if (_wcsicmp(ProcessEntry.szExeFile, L"winlogon.exe"))
            continue;
        RevertToSelf();
        Ret = ImpersonateSelf(SecurityImpersonation);
        LastError = GetLastError();
        if (!Ret)
            continue;
        Ret = OpenThreadToken(GetCurrentThread(), TOKEN_ADJUST_PRIVILEGES, FALSE, &ThreadToken);
        LastError = GetLastError();
        if (!Ret)
            continue;
        Ret = AdjustTokenPrivileges(ThreadToken, FALSE, &Privileges, sizeof(Privileges), NULL, NULL);
        LastError = GetLastError();
        CloseHandle(ThreadToken);
        if (!Ret)
            continue;

        WinlogonProcess = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, ProcessEntry.th32ProcessID);
        LastError = GetLastError();
        if (!WinlogonProcess)
            continue;
        Ret = OpenProcessToken(WinlogonProcess, TOKEN_IMPERSONATE | TOKEN_DUPLICATE, &WinlogonToken);
        LastError = GetLastError();
        CloseHandle(WinlogonProcess);
        if (!Ret)
            continue;
        Ret = DuplicateToken(WinlogonToken, SecurityImpersonation, &DuplicatedToken);
        LastError = GetLastError();
        CloseHandle(WinlogonToken);
        if (!Ret)
            continue;
        if (!GetTokenInformation(DuplicatedToken, TokenUser, &TokenUserBuffer, sizeof(TokenUserBuffer), &RequiredBytes))
            goto next;
        if (SetLastError(ERROR_ACCESS_DENIED), !EqualSid(TokenUserBuffer.MaybeLocalSystem.User.Sid, LocalSystemSid))
            goto next;
        if (!SetThreadToken(NULL, DuplicatedToken))
            goto next;
        CloseHandle(DuplicatedToken);
        CloseHandle(ProcessSnapshot);
        SetLastError(ERROR_SUCCESS);
        return TRUE;
    next:
        LastError = GetLastError();
        CloseHandle(DuplicatedToken);
    }
    RevertToSelf();
    CloseHandle(ProcessSnapshot);
cleanup:
    SetLastError(LastError);
    return FALSE;
}

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
    ElevateToSystem();
    DWORD Result = WintunCreateAdapter(Argv[2], Argv[3], Argc > 4 ? &RequestedGUID : NULL, &Adapter, &RebootRequired);
    RevertToSelf();
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
    ElevateToSystem();
    WintunDeleteAdapter(&Adapter, &RebootRequired);
    RevertToSelf();

cleanupArgv:
    LocalFree(Argv);
}

#endif

/* SPDX-License-Identifier: GPL-2.0
 *
 * Copyright (C) 2018-2020 WireGuard LLC. All Rights Reserved.
 */

#include "pch.h"

#define EXPORT comment(linker, "/EXPORT:" __FUNCTION__ "=" __FUNCDNAME__)

#ifdef ACCEPT_WOW64

static DWORD
WriteFormatted(_In_ DWORD StdHandle, _In_z_ const WCHAR *Template, ...)
{
    WCHAR *FormattedMessage = NULL;
    DWORD SizeWritten;
    va_list Arguments;
    va_start(Arguments, Template);
    WriteFile(
        GetStdHandle(StdHandle),
        FormattedMessage,
        sizeof(WCHAR) * FormatMessageW(
                            FORMAT_MESSAGE_FROM_STRING | FORMAT_MESSAGE_ALLOCATE_BUFFER,
                            Template,
                            0,
                            0,
                            (void *)&FormattedMessage,
                            0,
                            &Arguments),
        &SizeWritten,
        NULL);
    LocalFree(FormattedMessage);
    va_end(Arguments);
    return SizeWritten / sizeof(WCHAR);
}

static BOOL CALLBACK
ConsoleLogger(_In_ WINTUN_LOGGER_LEVEL Level, _In_ const WCHAR *LogLine)
{
    const WCHAR *Template;
    switch (Level)
    {
    case WINTUN_LOG_INFO:
        Template = L"[+] %1\n";
        break;
    case WINTUN_LOG_WARN:
        Template = L"[-] %1\n";
        break;
    case WINTUN_LOG_ERR:
        Template = L"[!] %1\n";
        break;
    default:
        return FALSE;
    }
    WriteFormatted(STD_ERROR_HANDLE, Template, LogLine);
    return TRUE;
}

static BOOL
ElevateToSystem(void)
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

static int Argc;
static WCHAR **Argv;

static void
Init(void)
{
    WintunSetLogger(ConsoleLogger);
    Argv = CommandLineToArgvW(GetCommandLineW(), &Argc);
    ElevateToSystem();
}

static void
Done(void)
{
    RevertToSelf();
    LocalFree(Argv);
}

VOID __stdcall CreateAdapter(HWND hwnd, HINSTANCE hinst, LPSTR lpszCmdLine, int nCmdShow)
{
#    pragma EXPORT
    UNREFERENCED_PARAMETER(hwnd);
    UNREFERENCED_PARAMETER(hinst);
    UNREFERENCED_PARAMETER(lpszCmdLine);
    UNREFERENCED_PARAMETER(nCmdShow);

    Init();
    if (Argc < 4)
        goto cleanup;
    if (wcslen(Argv[2]) >= MAX_POOL)
        goto cleanup;
    if (wcslen(Argv[3]) >= MAX_ADAPTER_NAME)
        goto cleanup;
    GUID RequestedGUID;
    if (Argc > 4 && FAILED(CLSIDFromString(Argv[4], &RequestedGUID)))
        goto cleanup;

    WINTUN_ADAPTER *Adapter;
    BOOL RebootRequired = FALSE;
    DWORD Result = WintunCreateAdapter(Argv[2], Argv[3], Argc > 4 ? &RequestedGUID : NULL, &Adapter, &RebootRequired);
    WCHAR GuidStr[MAX_GUID_STRING_LEN];
    WriteFormatted(
        STD_OUTPUT_HANDLE,
        L"%1!X! %2!.*s! %3!X!",
        Result,
        StringFromGUID2(Result == ERROR_SUCCESS ? &Adapter->CfgInstanceID : &GUID_NULL, GuidStr, _countof(GuidStr)),
        GuidStr,
        RebootRequired);
    WintunFreeAdapter(Adapter);

cleanup:
    Done();
}

VOID __stdcall DeleteAdapter(HWND hwnd, HINSTANCE hinst, LPSTR lpszCmdLine, int nCmdShow)
{
#    pragma EXPORT
    UNREFERENCED_PARAMETER(hwnd);
    UNREFERENCED_PARAMETER(hinst);
    UNREFERENCED_PARAMETER(lpszCmdLine);
    UNREFERENCED_PARAMETER(nCmdShow);

    Init();
    if (Argc < 3)
        goto cleanup;

    WINTUN_ADAPTER Adapter = { 0 };
    if (FAILED(CLSIDFromString(Argv[2], &Adapter.CfgInstanceID)))
        goto cleanup;
    BOOL RebootRequired = FALSE;
    WriteFormatted(STD_OUTPUT_HANDLE, L"%1!X! %2!X!", WintunDeleteAdapter(&Adapter, &RebootRequired), RebootRequired);

cleanup:
    Done();
}

#endif

/* SPDX-License-Identifier: GPL-2.0
 *
 * Copyright (C) 2018-2021 WireGuard LLC. All Rights Reserved.
 */

#include "elevate.h"
#include "logger.h"

#include <Windows.h>
#include <TlHelp32.h>

static _Return_type_success_(return != FALSE) BOOL ElevateToSystem(void)
{
    HANDLE CurrentProcessToken, ThreadToken, ProcessSnapshot, WinlogonProcess, WinlogonToken, DuplicatedToken;
    PROCESSENTRY32W ProcessEntry = { .dwSize = sizeof(PROCESSENTRY32W) };
    BOOL Ret;
    DWORD LastError = ERROR_SUCCESS;
    TOKEN_PRIVILEGES Privileges = { .PrivilegeCount = 1, .Privileges = { { .Attributes = SE_PRIVILEGE_ENABLED } } };
    CHAR LocalSystemSid[MAX_SID_SIZE];
    DWORD RequiredBytes = sizeof(LocalSystemSid);
    struct
    {
        TOKEN_USER MaybeLocalSystem;
        CHAR LargeEnoughForLocalSystem[MAX_SID_SIZE];
    } TokenUserBuffer;

    Ret = CreateWellKnownSid(WinLocalSystemSid, NULL, &LocalSystemSid, &RequiredBytes);
    if (!Ret)
    {
        LastError = LOG_LAST_ERROR(L"Failed to create SID");
        goto cleanup;
    }
    Ret = OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &CurrentProcessToken);
    if (!Ret)
    {
        LastError = LOG_LAST_ERROR(L"Failed to open process token");
        goto cleanup;
    }
    Ret =
        GetTokenInformation(CurrentProcessToken, TokenUser, &TokenUserBuffer, sizeof(TokenUserBuffer), &RequiredBytes);
    LastError = GetLastError();
    CloseHandle(CurrentProcessToken);
    if (!Ret)
    {
        LOG_ERROR(LastError, L"Failed to get token information");
        goto cleanup;
    }
    if (EqualSid(TokenUserBuffer.MaybeLocalSystem.User.Sid, LocalSystemSid))
        return ImpersonateSelf(SecurityImpersonation);
    Ret = LookupPrivilegeValueW(NULL, SE_DEBUG_NAME, &Privileges.Privileges[0].Luid);
    if (!Ret)
    {
        LastError = LOG_LAST_ERROR(L"Failed to lookup privilege value");
        goto cleanup;
    }
    ProcessSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (ProcessSnapshot == INVALID_HANDLE_VALUE)
    {
        LastError = LOG_LAST_ERROR(L"Failed to create toolhelp snapshot");
        goto cleanup;
    }
    for (Ret = Process32FirstW(ProcessSnapshot, &ProcessEntry); Ret;
         Ret = Process32NextW(ProcessSnapshot, &ProcessEntry))
    {
        if (_wcsicmp(ProcessEntry.szExeFile, L"winlogon.exe"))
            continue;
        RevertToSelf();
        Ret = ImpersonateSelf(SecurityImpersonation);
        if (!Ret)
        {
            LastError = GetLastError();
            continue;
        }
        Ret = OpenThreadToken(GetCurrentThread(), TOKEN_ADJUST_PRIVILEGES, FALSE, &ThreadToken);
        if (!Ret)
        {
            LastError = GetLastError();
            continue;
        }
        Ret = AdjustTokenPrivileges(ThreadToken, FALSE, &Privileges, 0, NULL, NULL);
        LastError = GetLastError();
        CloseHandle(ThreadToken);
        if (!Ret)
            continue;

        WinlogonProcess = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, ProcessEntry.th32ProcessID);
        if (!WinlogonProcess)
        {
            LastError = GetLastError();
            continue;
        }
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
        if (!EqualSid(TokenUserBuffer.MaybeLocalSystem.User.Sid, LocalSystemSid))
        {
            SetLastError(ERROR_ACCESS_DENIED);
            goto next;
        }
        if (!SetThreadToken(NULL, DuplicatedToken))
            goto next;
        CloseHandle(DuplicatedToken);
        CloseHandle(ProcessSnapshot);
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

_Return_type_success_(return != FALSE) BOOL ImpersonateService(_In_z_ WCHAR *ServiceName, _In_ HANDLE *OriginalToken)
{
    HANDLE ThreadToken, ServiceProcess, ServiceToken, DuplicatedToken;
    SC_HANDLE Scm, ServiceHandle;
    DWORD LastError = ERROR_SUCCESS;
    TOKEN_PRIVILEGES Privileges = { .PrivilegeCount = 1, .Privileges = { { .Attributes = SE_PRIVILEGE_ENABLED } } };
    SERVICE_STATUS_PROCESS ServiceStatus;
    DWORD RequiredBytes;
    BOOL Ret = FALSE;

    *OriginalToken = NULL;
    if (!OpenThreadToken(GetCurrentThread(), TOKEN_IMPERSONATE, FALSE, OriginalToken) &&
        GetLastError() != ERROR_NO_TOKEN)
        return FALSE;

    if (!ElevateToSystem())
        goto cleanup;

    if (!LookupPrivilegeValueW(NULL, SE_DEBUG_NAME, &Privileges.Privileges[0].Luid))
    {
        LastError = LOG_LAST_ERROR(L"Failed to lookup privilege value");
        goto cleanup;
    }
    if (!OpenThreadToken(GetCurrentThread(), TOKEN_ADJUST_PRIVILEGES, FALSE, &ThreadToken))
    {
        LastError = LOG_LAST_ERROR(L"Failed to open thread token");
        goto cleanup;
    }
    if (!AdjustTokenPrivileges(ThreadToken, FALSE, &Privileges, 0, NULL, NULL))
    {
        LastError = LOG_LAST_ERROR(L"Failed to enable SE_DEBUG_NAME");
        goto cleanupThreadToken;
    }

    Scm = OpenSCManagerW(NULL, NULL, SC_MANAGER_CONNECT);
    if (!Scm)
    {
        LastError = LOG_LAST_ERROR(L"Failed to open SCM");
        goto cleanupThreadToken;
    }
    ServiceHandle = OpenServiceW(Scm, ServiceName, SERVICE_START | SERVICE_QUERY_STATUS);
    if (!ServiceHandle)
    {
        LastError = LOG_LAST_ERROR(L"Failed to open service %s", ServiceName);
        goto cleanupScm;
    }
    if (!StartServiceW(ServiceHandle, 0, NULL) && GetLastError() != ERROR_SERVICE_ALREADY_RUNNING)
    {
        LastError = LOG_LAST_ERROR(L"Failed to start service %s", ServiceName);
        goto cleanupService;
    }
    for (int i = 0; i < 1000; ++i)
    {
        if (!QueryServiceStatusEx(
                ServiceHandle, SC_STATUS_PROCESS_INFO, (BYTE *)&ServiceStatus, sizeof(ServiceStatus), &RequiredBytes))
        {
            LastError = LOG_LAST_ERROR(L"Failed to query service %s", ServiceName);
            goto cleanupService;
        }
        if (ServiceStatus.dwProcessId)
            break;

        if (i != 999)
            Sleep(4);
    }
    ServiceProcess = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, ServiceStatus.dwProcessId);
    if (!ServiceProcess)
    {
        LastError = LOG_LAST_ERROR(L"Failed to open service %s process %u", ServiceName, ServiceStatus.dwProcessId);
        goto cleanupService;
    }
    if (!OpenProcessToken(ServiceProcess, TOKEN_IMPERSONATE | TOKEN_DUPLICATE, &ServiceToken))
    {
        LastError =
            LOG_LAST_ERROR(L"Failed to open token of service %s process %u", ServiceName, ServiceStatus.dwProcessId);
        goto cleanupServiceProcess;
    }
    if (!DuplicateToken(ServiceToken, SecurityImpersonation, &DuplicatedToken))
    {
        LastError = LOG_LAST_ERROR(
            L"Failed to duplicate token of service %s process %u", ServiceName, ServiceStatus.dwProcessId);
        goto cleanupServiceToken;
    }
    if (!SetThreadToken(NULL, DuplicatedToken))
    {
        LastError = LOG_LAST_ERROR(
            L"Failed to set thread token to service %s process %u token", ServiceName, ServiceStatus.dwProcessId);
        goto cleanupDuplicatedToken;
    }
    Ret = TRUE;

cleanupDuplicatedToken:
    CloseHandle(DuplicatedToken);
cleanupServiceToken:
    CloseHandle(ServiceToken);
cleanupServiceProcess:
    CloseHandle(ServiceProcess);
cleanupService:
    CloseServiceHandle(ServiceHandle);
cleanupScm:
    CloseServiceHandle(Scm);
cleanupThreadToken:
    CloseHandle(ThreadToken);
cleanup:
    if (!Ret)
    {
        RestoreToken(*OriginalToken);
        *OriginalToken = NULL;
    }
    SetLastError(LastError);
    return Ret;
}

_Return_type_success_(return != FALSE) BOOL RestoreToken(_In_ HANDLE OriginalToken)
{
    RevertToSelf();
    if (!OriginalToken)
        return TRUE;
    BOOL Ret = SetThreadToken(NULL, OriginalToken);
    DWORD LastError = Ret ? ERROR_SUCCESS : LOG_LAST_ERROR(L"Failed to restore original token");
    CloseHandle(OriginalToken);
    SetLastError(LastError);
    return Ret;
}

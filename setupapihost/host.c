/* SPDX-License-Identifier: GPL-2.0
 *
 * Copyright (C) 2018-2021 WireGuard LLC. All Rights Reserved.
 */

#include <windows.h>
#include <delayimp.h>
#include <setupapi.h>
#include <devguid.h>
#include <shellapi.h>
#include <intsafe.h>
#include <stdlib.h>

#define EXPORT comment(linker, "/EXPORT:" __FUNCTION__ "=" __FUNCDNAME__)

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

static DWORD
WriteFormatted(_In_ DWORD StdHandle, _In_z_ LPCWSTR Template, ...)
{
    LPWSTR FormattedMessage = NULL;
    DWORD Size;
    va_list Arguments;
    va_start(Arguments, Template);
    DWORD Len = FormatMessageW(
        FORMAT_MESSAGE_FROM_STRING | FORMAT_MESSAGE_ALLOCATE_BUFFER,
        Template,
        0,
        0,
        (VOID *)&FormattedMessage,
        0,
        &Arguments);
    if (SUCCEEDED(DWordMult(Len, sizeof(*FormattedMessage), &Size)))
        WriteFile(GetStdHandle(StdHandle), FormattedMessage, Size, &Size, NULL);
    else
        Size = 0;
    LocalFree(FormattedMessage);
    va_end(Arguments);
    return Size / sizeof(*FormattedMessage);
}

VOID __stdcall RemoveInstance(HWND hwnd, HINSTANCE hinst, LPSTR lpszCmdLine, int nCmdShow)
{
#pragma EXPORT

    DWORD LastError = ERROR_SUCCESS;
    int Argc;
    LPWSTR *Argv = CommandLineToArgvW(GetCommandLineW(), &Argc);

    if (Argc < 3)
        goto cleanup;
    WCHAR *InstanceId = Argv[2];

    HDEVINFO DevInfo = SetupDiCreateDeviceInfoListExW(&GUID_DEVCLASS_NET, NULL, NULL, NULL);
    if (DevInfo == INVALID_HANDLE_VALUE)
    {
        LastError = GetLastError();
        goto cleanup;
    }
    SP_DEVINFO_DATA DevInfoData = { .cbSize = sizeof(DevInfoData) };
    if (!SetupDiOpenDeviceInfoW(DevInfo, InstanceId, NULL, DIOD_INHERIT_CLASSDRVS, &DevInfoData))
    {
        LastError = GetLastError();
        goto cleanupDevInfo;
    }
    SP_REMOVEDEVICE_PARAMS RemoveDeviceParams = { .ClassInstallHeader = { .cbSize = sizeof(SP_CLASSINSTALL_HEADER),
                                                                          .InstallFunction = DIF_REMOVE },
                                                  .Scope = DI_REMOVEDEVICE_GLOBAL };
    if (!SetupDiSetClassInstallParamsW(
            DevInfo, &DevInfoData, &RemoveDeviceParams.ClassInstallHeader, sizeof(RemoveDeviceParams)) ||
        !SetupDiCallClassInstaller(DIF_REMOVE, DevInfo, &DevInfoData))
    {
        LastError = GetLastError();
        goto cleanupDevInfo;
    }

cleanupDevInfo:
    SetupDiDestroyDeviceInfoList(DevInfo);
cleanup:
    LocalFree(Argv);

    WriteFormatted(STD_OUTPUT_HANDLE, L"%1!X!", LastError);
}

VOID __stdcall EnableInstance(HWND hwnd, HINSTANCE hinst, LPSTR lpszCmdLine, int nCmdShow)
{
#pragma EXPORT

    DWORD LastError = ERROR_SUCCESS;
    int Argc;
    LPWSTR *Argv = CommandLineToArgvW(GetCommandLineW(), &Argc);

    if (Argc < 3)
        goto cleanup;
    WCHAR *InstanceId = Argv[2];

    HDEVINFO DevInfo = SetupDiCreateDeviceInfoListExW(&GUID_DEVCLASS_NET, NULL, NULL, NULL);
    if (DevInfo == INVALID_HANDLE_VALUE)
    {
        LastError = GetLastError();
        goto cleanup;
    }
    SP_DEVINFO_DATA DevInfoData = { .cbSize = sizeof(DevInfoData) };
    if (!SetupDiOpenDeviceInfoW(DevInfo, InstanceId, NULL, DIOD_INHERIT_CLASSDRVS, &DevInfoData))
    {
        LastError = GetLastError();
        goto cleanupDevInfo;
    }
    SP_PROPCHANGE_PARAMS Params = { .ClassInstallHeader = { .cbSize = sizeof(SP_CLASSINSTALL_HEADER),
                                                            .InstallFunction = DIF_PROPERTYCHANGE },
                                    .StateChange = DICS_ENABLE,
                                    .Scope = DICS_FLAG_GLOBAL };
    if (!SetupDiSetClassInstallParamsW(DevInfo, &DevInfoData, &Params.ClassInstallHeader, sizeof(Params)) ||
        !SetupDiCallClassInstaller(DIF_PROPERTYCHANGE, DevInfo, &DevInfoData))
    {
        LastError = GetLastError();
        goto cleanupDevInfo;
    }

cleanupDevInfo:
    SetupDiDestroyDeviceInfoList(DevInfo);
cleanup:
    LocalFree(Argv);

    WriteFormatted(STD_OUTPUT_HANDLE, L"%1!X!", LastError);
}

VOID __stdcall DisableInstance(HWND hwnd, HINSTANCE hinst, LPSTR lpszCmdLine, int nCmdShow)
{
#pragma EXPORT

    DWORD LastError = ERROR_SUCCESS;
    int Argc;
    LPWSTR *Argv = CommandLineToArgvW(GetCommandLineW(), &Argc);

    if (Argc < 3)
        goto cleanup;
    WCHAR *InstanceId = Argv[2];

    HDEVINFO DevInfo = SetupDiCreateDeviceInfoListExW(&GUID_DEVCLASS_NET, NULL, NULL, NULL);
    if (DevInfo == INVALID_HANDLE_VALUE)
    {
        LastError = GetLastError();
        goto cleanup;
    }
    SP_DEVINFO_DATA DevInfoData = { .cbSize = sizeof(DevInfoData) };
    if (!SetupDiOpenDeviceInfoW(DevInfo, InstanceId, NULL, DIOD_INHERIT_CLASSDRVS, &DevInfoData))
    {
        LastError = GetLastError();
        goto cleanupDevInfo;
    }
    SP_PROPCHANGE_PARAMS Params = { .ClassInstallHeader = { .cbSize = sizeof(SP_CLASSINSTALL_HEADER),
                                                            .InstallFunction = DIF_PROPERTYCHANGE },
                                    .StateChange = DICS_DISABLE,
                                    .Scope = DICS_FLAG_GLOBAL };
    if (!SetupDiSetClassInstallParamsW(DevInfo, &DevInfoData, &Params.ClassInstallHeader, sizeof(Params)) ||
        !SetupDiCallClassInstaller(DIF_PROPERTYCHANGE, DevInfo, &DevInfoData))
    {
        LastError = GetLastError();
        goto cleanupDevInfo;
    }

cleanupDevInfo:
    SetupDiDestroyDeviceInfoList(DevInfo);
cleanup:
    LocalFree(Argv);

    WriteFormatted(STD_OUTPUT_HANDLE, L"%1!X!", LastError);
}

#if NTDDI_VERSION == NTDDI_WIN7
#include "host_win7.h"
#endif

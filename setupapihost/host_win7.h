/* SPDX-License-Identifier: GPL-2.0
 *
 * Copyright (C) 2018-2021 WireGuard LLC. All Rights Reserved.
 */

#include <devguid.h>
#include <cfgmgr32.h>

#define WINTUN_HWID L"Wintun"

VOID __stdcall CreateInstanceWin7(HWND hwnd, HINSTANCE hinst, LPSTR lpszCmdLine, int nCmdShow)
{
#pragma EXPORT

    DWORD LastError = ERROR_SUCCESS;
    WCHAR InstanceId[MAX_DEVICE_ID_LEN] = { 0 };

    HDEVINFO DevInfo = SetupDiCreateDeviceInfoListExW(&GUID_DEVCLASS_NET, NULL, NULL, NULL);
    if (DevInfo == INVALID_HANDLE_VALUE)
    {
        LastError = GetLastError();
        goto cleanup;
    }
    SP_DEVINFO_DATA DevInfoData = { .cbSize = sizeof(DevInfoData) };
    if (!SetupDiCreateDeviceInfoW(
            DevInfo, WINTUN_HWID, &GUID_DEVCLASS_NET, NULL, NULL, DICD_GENERATE_ID, &DevInfoData))
    {
        LastError = GetLastError();
        goto cleanupDevInfo;
    }
    SP_DEVINSTALL_PARAMS_W DevInstallParams = { .cbSize = sizeof(DevInstallParams) };
    if (!SetupDiGetDeviceInstallParamsW(DevInfo, &DevInfoData, &DevInstallParams))
    {
        LastError = GetLastError();
        goto cleanupDevInfo;
    }
    DevInstallParams.Flags |= DI_QUIETINSTALL;
    if (!SetupDiSetDeviceInstallParamsW(DevInfo, &DevInfoData, &DevInstallParams))
    {
        LastError = GetLastError();
        goto cleanupDevInfo;
    }
    if (!SetupDiSetSelectedDevice(DevInfo, &DevInfoData))
    {
        LastError = GetLastError();
        goto cleanupDevInfo;
    }
    static const WCHAR Hwids[_countof(WINTUN_HWID) + 1 /*Multi-string terminator*/] = WINTUN_HWID;
    if (!SetupDiSetDeviceRegistryPropertyW(DevInfo, &DevInfoData, SPDRP_HARDWAREID, (const BYTE *)Hwids, sizeof(Hwids)))
    {
        LastError = GetLastError();
        goto cleanupDevInfo;
    }
    if (!SetupDiBuildDriverInfoList(DevInfo, &DevInfoData, SPDIT_COMPATDRIVER))
    {
        LastError = GetLastError();
        goto cleanupDevInfo;
    }
    SP_DRVINFO_DATA_W DrvInfoData = { .cbSize = sizeof(SP_DRVINFO_DATA_W) };
    if (!SetupDiEnumDriverInfoW(DevInfo, &DevInfoData, SPDIT_COMPATDRIVER, 0, &DrvInfoData) ||
        !SetupDiSetSelectedDriverW(DevInfo, &DevInfoData, &DrvInfoData))
    {
        LastError = GetLastError();
        goto cleanupDriverInfo;
    }

    if (!SetupDiCallClassInstaller(DIF_REGISTERDEVICE, DevInfo, &DevInfoData))
    {
        LastError = GetLastError();
        goto cleanupDevInfo;
    }
    SetupDiCallClassInstaller(DIF_REGISTER_COINSTALLERS, DevInfo, &DevInfoData);
    SetupDiCallClassInstaller(DIF_INSTALLINTERFACES, DevInfo, &DevInfoData);
    if (!SetupDiCallClassInstaller(DIF_INSTALLDEVICE, DevInfo, &DevInfoData))
    {
        LastError = GetLastError();
        goto cleanupDevice;
    }
    DWORD RequiredChars = _countof(InstanceId);
    if (!SetupDiGetDeviceInstanceIdW(DevInfo, &DevInfoData, InstanceId, RequiredChars, &RequiredChars))
    {
        LastError = GetLastError();
        goto cleanupDevice;
    }

cleanupDevice:
    if (LastError != ERROR_SUCCESS)
    {
        SP_REMOVEDEVICE_PARAMS RemoveDeviceParams = { .ClassInstallHeader = { .cbSize = sizeof(SP_CLASSINSTALL_HEADER),
                                                                              .InstallFunction = DIF_REMOVE },
                                                      .Scope = DI_REMOVEDEVICE_GLOBAL };
        if (SetupDiSetClassInstallParamsW(
                DevInfo, &DevInfoData, &RemoveDeviceParams.ClassInstallHeader, sizeof(RemoveDeviceParams)))
            SetupDiCallClassInstaller(DIF_REMOVE, DevInfo, &DevInfoData);
    }
cleanupDriverInfo:
    SetupDiDestroyDriverInfoList(DevInfo, &DevInfoData, SPDIT_COMPATDRIVER);
cleanupDevInfo:
    SetupDiDestroyDeviceInfoList(DevInfo);
cleanup:
    WriteFormatted(STD_OUTPUT_HANDLE, L"%1!X! %2!s!", LastError, LastError == ERROR_SUCCESS ? InstanceId : L"\"\"");
}

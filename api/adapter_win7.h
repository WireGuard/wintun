/* SPDX-License-Identifier: GPL-2.0
 *
 * Copyright (C) 2018-2021 WireGuard LLC. All Rights Reserved.
 */

static const DEVPROPKEY DEVPKEY_Wintun_OwningProcess = {
    { 0x3361c968, 0x2f2e, 0x4660, { 0xb4, 0x7e, 0x69, 0x9c, 0xdc, 0x4c, 0x32, 0xb9 } },
    DEVPROPID_FIRST_USABLE + 3
};

typedef struct _OWNING_PROCESS
{
    DWORD ProcessId;
    FILETIME CreationTime;
} OWNING_PROCESS;

_Must_inspect_result_
static _Return_type_success_(return != FALSE)
BOOL
WaitForInterfaceWin7(_In_ HDEVINFO DevInfo, _In_ SP_DEVINFO_DATA *DevInfoData, _In_ LPCWSTR DevInstanceId)
{
    ULONG Status, Number;
    DWORD ValType, Zero;
    WCHAR *FileName = NULL;
    HKEY Key = INVALID_HANDLE_VALUE;
    HANDLE FileHandle = INVALID_HANDLE_VALUE;
    BOOLEAN Ret = FALSE;
    for (DWORD Tries = 0; Tries < 1500; ++Tries)
    {
        if (Tries)
            Sleep(10);
        if (Key == INVALID_HANDLE_VALUE)
            Key = SetupDiOpenDevRegKey(DevInfo, DevInfoData, DICS_FLAG_GLOBAL, 0, DIREG_DRV, KEY_QUERY_VALUE);
        if (!FileName)
            FileName = AdapterGetDeviceObjectFileName(DevInstanceId);
        if (FileName && FileHandle == INVALID_HANDLE_VALUE)
            FileHandle = CreateFileW(
                FileName,
                GENERIC_READ | GENERIC_WRITE,
                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                NULL,
                OPEN_EXISTING,
                0,
                NULL);
        Zero = 0;
        if (FileName && FileHandle != INVALID_HANDLE_VALUE && Key != INVALID_HANDLE_VALUE && Key &&
            RegQueryValueExW(Key, L"NetCfgInstanceId", NULL, &ValType, NULL, &Zero) != ERROR_MORE_DATA &&
            CM_Get_DevNode_Status(&Status, &Number, DevInfoData->DevInst, 0) == CR_SUCCESS &&
            !(Status & DN_HAS_PROBLEM) && !Number)
        {
            Ret = TRUE;
            break;
        }
    }
    if (Key != INVALID_HANDLE_VALUE && Key)
        RegCloseKey(Key);
    if (FileHandle != INVALID_HANDLE_VALUE)
        CloseHandle(FileHandle);
    Free(FileName);
    return Ret;
}

_Must_inspect_result_
static _Return_type_success_(return != FALSE)
BOOL
CreateAdapterWin7(_Inout_ WINTUN_ADAPTER *Adapter, _In_z_ LPCWSTR Name, _In_z_ LPCWSTR TunnelTypeName)
{
    DWORD LastError = ERROR_SUCCESS;

    HDEVINFO DevInfo = SetupDiCreateDeviceInfoListExW(&GUID_DEVCLASS_NET, NULL, NULL, NULL);
    if (DevInfo == INVALID_HANDLE_VALUE)
    {
        LastError = LOG_LAST_ERROR(L"Failed to create empty device information set");
        goto cleanup;
    }
    SP_DEVINFO_DATA DevInfoData = { .cbSize = sizeof(DevInfoData) };

#ifdef MAYBE_WOW64
    if (NativeMachine != IMAGE_FILE_PROCESS)
    {
        if (!CreateInstanceWin7ViaRundll32(Adapter->DevInstanceID))
        {
            LastError = LOG_LAST_ERROR(L"Failed to create device instance");
            goto cleanup;
        }
        if (!SetupDiOpenDeviceInfoW(DevInfo, Adapter->DevInstanceID, NULL, DIOD_INHERIT_CLASSDRVS, &DevInfoData))
        {
            LastError = GetLastError();
            goto cleanupDevInfo;
        }
        goto resumeAfterInstance;
    }
#endif

    if (!SetupDiCreateDeviceInfoW(
            DevInfo, WINTUN_HWID, &GUID_DEVCLASS_NET, TunnelTypeName, NULL, DICD_GENERATE_ID, &DevInfoData))
    {
        LastError = LOG_LAST_ERROR(L"Failed to create new device information element");
        goto cleanupDevInfo;
    }
    SP_DEVINSTALL_PARAMS_W DevInstallParams = { .cbSize = sizeof(DevInstallParams) };
    if (!SetupDiGetDeviceInstallParamsW(DevInfo, &DevInfoData, &DevInstallParams))
    {
        LastError = LOG_LAST_ERROR(L"Failed to retrieve adapter device installation parameters");
        goto cleanupDevInfo;
    }
    DevInstallParams.Flags |= DI_QUIETINSTALL;
    if (!SetupDiSetDeviceInstallParamsW(DevInfo, &DevInfoData, &DevInstallParams))
    {
        LastError = LOG_LAST_ERROR(L"Failed to set adapter device installation parameters");
        goto cleanupDevInfo;
    }
    if (!SetupDiSetSelectedDevice(DevInfo, &DevInfoData))
    {
        LastError = LOG_LAST_ERROR(L"Failed to select adapter device");
        goto cleanupDevInfo;
    }
    static const WCHAR Hwids[_countof(WINTUN_HWID) + 1 /*Multi-string terminator*/] = WINTUN_HWID;
    if (!SetupDiSetDeviceRegistryPropertyW(DevInfo, &DevInfoData, SPDRP_HARDWAREID, (const BYTE *)Hwids, sizeof(Hwids)))
    {
        LastError = LOG_LAST_ERROR(L"Failed to set adapter hardware ID");
        goto cleanupDevInfo;
    }
    if (!SetupDiBuildDriverInfoList(DevInfo, &DevInfoData, SPDIT_COMPATDRIVER))
    {
        LastError = LOG_LAST_ERROR(L"Failed building adapter driver info list");
        goto cleanupDevInfo;
    }
    SP_DRVINFO_DATA_W DrvInfoData = { .cbSize = sizeof(SP_DRVINFO_DATA_W) };
    if (!SetupDiEnumDriverInfoW(DevInfo, &DevInfoData, SPDIT_COMPATDRIVER, 0, &DrvInfoData) ||
        !SetupDiSetSelectedDriverW(DevInfo, &DevInfoData, &DrvInfoData))
    {
        LastError = LOG_ERROR(ERROR_DRIVER_INSTALL_BLOCKED, L"Failed to select a driver");
        goto cleanupDriverInfo;
    }

    if (!SetupDiCallClassInstaller(DIF_REGISTERDEVICE, DevInfo, &DevInfoData))
    {
        LastError = LOG_LAST_ERROR(L"Failed to register adapter device");
        goto cleanupDevInfo;
    }
    if (!SetupDiCallClassInstaller(DIF_REGISTER_COINSTALLERS, DevInfo, &DevInfoData))
        LOG_LAST_ERROR(L"Failed to register adapter coinstallers");
    if (!SetupDiCallClassInstaller(DIF_INSTALLINTERFACES, DevInfo, &DevInfoData))
        LOG_LAST_ERROR(L"Failed to install adapter interfaces");
    if (!SetupDiCallClassInstaller(DIF_INSTALLDEVICE, DevInfo, &DevInfoData))
    {
        LastError = LOG_LAST_ERROR(L"Failed to install adapter device");
        goto cleanupDevice;
    }

#ifdef MAYBE_WOW64
resumeAfterInstance:;
#endif

    OWNING_PROCESS OwningProcess = { .ProcessId = GetCurrentProcessId() };
    FILETIME Unused;
    if (!GetProcessTimes(GetCurrentProcess(), &OwningProcess.CreationTime, &Unused, &Unused, &Unused))
    {
        LastError = LOG_LAST_ERROR(L"Failed to get process creation time");
        goto cleanupDevice;
    }

    if (!SetupDiSetDeviceRegistryPropertyW(
            DevInfo,
            &DevInfoData,
            SPDRP_FRIENDLYNAME,
            (PBYTE)TunnelTypeName,
            (DWORD)((wcslen(TunnelTypeName) + 1) * sizeof(TunnelTypeName[0]))) ||
        !SetupDiSetDeviceRegistryPropertyW(
            DevInfo,
            &DevInfoData,
            SPDRP_DEVICEDESC,
            (PBYTE)TunnelTypeName,
            (DWORD)((wcslen(TunnelTypeName) + 1) * sizeof(TunnelTypeName[0]))) ||
        !SetupDiSetDevicePropertyW(
            DevInfo,
            &DevInfoData,
            &DEVPKEY_Wintun_Name,
            DEVPROP_TYPE_STRING,
            (PBYTE)Name,
            (DWORD)((wcslen(Name) + 1) * sizeof(Name[0])),
            0) ||
        !SetupDiSetDevicePropertyW(
            DevInfo,
            &DevInfoData,
            &DEVPKEY_Wintun_OwningProcess,
            DEVPROP_TYPE_BINARY,
            (PBYTE)&OwningProcess,
            sizeof(OwningProcess),
            0))
    {
        LastError = LOG_LAST_ERROR(L"Failed to set device properties");
        goto cleanupDevice;
    }

    DWORD RequiredChars = _countof(Adapter->DevInstanceID);
    if (!SetupDiGetDeviceInstanceIdW(DevInfo, &DevInfoData, Adapter->DevInstanceID, RequiredChars, &RequiredChars))
    {
        LastError = LOG_LAST_ERROR(L"Failed to get adapter instance ID");
        goto cleanupDevice;
    }

    if (!WaitForInterfaceWin7(DevInfo, &DevInfoData, Adapter->DevInstanceID))
    {
        DEVPROPTYPE PropertyType = 0;
        INT32 ProblemCode = 0;
        if (!SetupDiGetDevicePropertyW(
                DevInfo,
                &DevInfoData,
                &DEVPKEY_Device_ProblemCode,
                &PropertyType,
                (PBYTE)&ProblemCode,
                sizeof(ProblemCode),
                NULL,
                0) ||
            (PropertyType != DEVPROP_TYPE_INT32 && PropertyType != DEVPROP_TYPE_UINT32))
            ProblemCode = 0;
        LastError = LOG_ERROR(
            ERROR_DEVICE_REINITIALIZATION_NEEDED, L"Failed to setup adapter (problem code: 0x%x)", ProblemCode);
        goto cleanupDevice;
    }

cleanupDevice:
    if (LastError != ERROR_SUCCESS)
        AdapterRemoveInstance(DevInfo, &DevInfoData);
cleanupDriverInfo:
    SetupDiDestroyDriverInfoList(DevInfo, &DevInfoData, SPDIT_COMPATDRIVER);
cleanupDevInfo:
    SetupDiDestroyDeviceInfoList(DevInfo);
cleanup:
    return RET_ERROR(TRUE, LastError);
}

static VOID
CreateAdapterPostWin7(_Inout_ WINTUN_ADAPTER *Adapter, _In_z_ LPCWSTR TunnelTypeName)
{
    SetupDiSetDeviceRegistryPropertyW(
        Adapter->DevInfo,
        &Adapter->DevInfoData,
        SPDRP_FRIENDLYNAME,
        (PBYTE)TunnelTypeName,
        (DWORD)((wcslen(TunnelTypeName) + 1) * sizeof(TunnelTypeName[0])));
    SetupDiSetDeviceRegistryPropertyW(
        Adapter->DevInfo,
        &Adapter->DevInfoData,
        SPDRP_DEVICEDESC,
        (PBYTE)TunnelTypeName,
        (DWORD)((wcslen(TunnelTypeName) + 1) * sizeof(TunnelTypeName[0])));
}

static BOOL
ProcessIsStale(_In_ OWNING_PROCESS *OwningProcess)
{
    HANDLE Process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, OwningProcess->ProcessId);
    if (!Process)
        return TRUE;
    FILETIME CreationTime, Unused;
    BOOL Ret = GetProcessTimes(Process, &CreationTime, &Unused, &Unused, &Unused);
    CloseHandle(Process);
    if (!Ret)
        return FALSE;
    return !!memcmp(&CreationTime, &OwningProcess->CreationTime, sizeof(CreationTime));
}

VOID AdapterCleanupOrphanedDevicesWin7(VOID)
{
    HDEVINFO DevInfo = SetupDiGetClassDevsExW(&GUID_DEVCLASS_NET, WINTUN_ENUMERATOR, NULL, 0, NULL, NULL, NULL);
    if (DevInfo == INVALID_HANDLE_VALUE)
    {
        if (GetLastError() != ERROR_INVALID_DATA)
            LOG_LAST_ERROR(L"Failed to get adapters");
        return;
    }

    SP_DEVINFO_DATA DevInfoData = { .cbSize = sizeof(DevInfoData) };
    for (DWORD EnumIndex = 0;; ++EnumIndex)
    {
        if (!SetupDiEnumDeviceInfo(DevInfo, EnumIndex, &DevInfoData))
        {
            if (GetLastError() == ERROR_NO_MORE_ITEMS)
                break;
            continue;
        }

        OWNING_PROCESS OwningProcess;
        DEVPROPTYPE PropType;
        if (SetupDiGetDevicePropertyW(
                DevInfo,
                &DevInfoData,
                &DEVPKEY_Wintun_OwningProcess,
                &PropType,
                (PBYTE)&OwningProcess,
                sizeof(OwningProcess),
                NULL,
                0) &&
            PropType == DEVPROP_TYPE_BINARY && !ProcessIsStale(&OwningProcess))
            continue;

        WCHAR Name[MAX_ADAPTER_NAME] = L"<unknown>";
        SetupDiGetDevicePropertyW(
            DevInfo,
            &DevInfoData,
            &DEVPKEY_Wintun_Name,
            &PropType,
            (PBYTE)Name,
            MAX_ADAPTER_NAME * sizeof(Name[0]),
            NULL,
            0);
        if (!AdapterRemoveInstance(DevInfo, &DevInfoData))
        {
            LOG_LAST_ERROR(L"Failed to remove orphaned adapter \"%s\"", Name);
            continue;
        }
        LOG(WINTUN_LOG_INFO, L"Removed orphaned adapter \"%s\"", Name);
    }
    SetupDiDestroyDeviceInfoList(DevInfo);
}

VOID AdapterCleanupLegacyDevices(VOID)
{
    HDEVINFO DevInfo = SetupDiGetClassDevsExW(&GUID_DEVCLASS_NET, L"ROOT\\NET", NULL, 0, NULL, NULL, NULL);
    if (DevInfo == INVALID_HANDLE_VALUE)
        return;
    SP_DEVINFO_DATA DevInfoData = { .cbSize = sizeof(DevInfoData) };
    for (DWORD EnumIndex = 0;; ++EnumIndex)
    {
        if (!SetupDiEnumDeviceInfo(DevInfo, EnumIndex, &DevInfoData))
        {
            if (GetLastError() == ERROR_NO_MORE_ITEMS)
                break;
            continue;
        }
        WCHAR HardwareIDs[0x400] = { 0 };
        DWORD ValueType, Size = sizeof(HardwareIDs) - sizeof(HardwareIDs[0]);
        if (!SetupDiGetDeviceRegistryPropertyW(
                DevInfo, &DevInfoData, SPDRP_HARDWAREID, &ValueType, (PBYTE)HardwareIDs, Size, &Size) ||
            Size > sizeof(HardwareIDs) - sizeof(HardwareIDs[0]))
            continue;
        Size /= sizeof(HardwareIDs[0]);
        for (WCHAR *P = HardwareIDs; P < HardwareIDs + Size; P += wcslen(P) + 1)
        {
            if (!_wcsicmp(P, WINTUN_HWID))
            {
                AdapterRemoveInstance(DevInfo, &DevInfoData);
                break;
            }
        }
    }
    SetupDiDestroyDeviceInfoList(DevInfo);
}
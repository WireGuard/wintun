/* SPDX-License-Identifier: GPL-2.0
 *
 * Copyright (C) 2018-2020 WireGuard LLC. All Rights Reserved.
 */

#include "pch.h"

#define WAIT_FOR_REGISTRY_TIMEOUT 10000     /* ms */
#define MAX_POOL_DEVICE_TYPE (MAX_POOL + 8) /* Should accommodate a pool name with " Tunnel" appended */

static _locale_t Locale;

/**
 * Retrieves driver information detail for a device information set or a particular device information element in the
 * device information set.
 *
 * @param DevInfo       A handle to the device information set that contains a device information element that
 *                      represents the device for which to retrieve driver information.
 *
 * @param DevInfoData   A pointer to a structure that specifies the device information element in DevInfo.
 *
 * @param DrvInfoData   A pointer to a structure that specifies the driver information element that represents the
 *                      driver for which to retrieve details.
 *
 * @param DrvInfoDetailData  A pointer to a structure that receives detailed information about the specified driver.
 *                      Must be released with HeapFree(GetProcessHeap(), 0, *DrvInfoDetailData) after use.
 *
 * @return ERROR_SUCCESS on success; Win32 error code otherwise.
 */
WINTUN_STATUS
AdapterGetDrvInfoDetail(
    _In_ HDEVINFO DevInfo,
    _In_opt_ SP_DEVINFO_DATA *DevInfoData,
    _In_ SP_DRVINFO_DATA_W *DrvInfoData,
    _Out_ SP_DRVINFO_DETAIL_DATA_W **DrvInfoDetailData)
{
    HANDLE Heap = GetProcessHeap();
    DWORD Size = sizeof(SP_DRVINFO_DETAIL_DATA_W) + 0x100;
    for (;;)
    {
        *DrvInfoDetailData = HeapAlloc(Heap, 0, Size);
        if (!*DrvInfoDetailData)
            return LOG(WINTUN_LOG_ERR, L"Out of memory"), ERROR_OUTOFMEMORY;
        (*DrvInfoDetailData)->cbSize = sizeof(SP_DRVINFO_DETAIL_DATA_W);
        if (SetupDiGetDriverInfoDetailW(DevInfo, DevInfoData, DrvInfoData, *DrvInfoDetailData, Size, &Size))
            return ERROR_SUCCESS;
        DWORD Result = GetLastError();
        HeapFree(Heap, 0, *DrvInfoDetailData);
        if (Result != ERROR_INSUFFICIENT_BUFFER)
            return LOG_ERROR(L"Failed", Result);
    }
}

/**
 * Retrieves a specified Plug and Play device property.
 *
 * @param DevInfo       A handle to the device information set that contains a device information element that
 *                      represents the device for which to open a registry key.
 *
 * @param DevInfoData   A pointer to a structure that specifies the device information element in DevInfo.
 *
 * @param Property      The property to be retrieved. One of the SPDRP_* constants.
 *
 * @param ValueType     A pointer to a variable that receives the data type of the property that is being retrieved.
 *                      This is one of the standard registry data types.
 *
 * @param Buf           A pointer to a buffer that receives the property that is being retrieved. Must be released with
 *                      HeapFree(GetProcessHeap(), 0, *Buf) after use.
 *
 * @param BufLen        On input, a hint of expected registry value size in bytes; on output, actual registry value size
 *                      in bytes.
 *
 * @return ERROR_SUCCESS on success; Win32 error code otherwise.
 */
static WINTUN_STATUS
GetDeviceRegistryProperty(
    _In_ HDEVINFO DevInfo,
    _In_ SP_DEVINFO_DATA *DevInfoData,
    _In_ DWORD Property,
    _Out_opt_ DWORD *ValueType,
    _Out_ void **Buf,
    _Inout_ DWORD *BufLen)
{
    HANDLE Heap = GetProcessHeap();
    for (;;)
    {
        *Buf = HeapAlloc(Heap, 0, *BufLen);
        if (!*Buf)
            return LOG(WINTUN_LOG_ERR, L"Out of memory"), ERROR_OUTOFMEMORY;
        if (SetupDiGetDeviceRegistryPropertyW(DevInfo, DevInfoData, Property, ValueType, *Buf, *BufLen, BufLen))
            return ERROR_SUCCESS;
        DWORD Result = GetLastError();
        HeapFree(Heap, 0, *Buf);
        if (Result != ERROR_INSUFFICIENT_BUFFER)
            return LOG_ERROR(L"Querying property failed", Result);
    }
}

/**
 * Retrieves a specified Plug and Play device property string.
 *
 * @param DevInfo       A handle to the device information set that contains a device information element that
 *                      represents the device for which to open a registry key.
 *
 * @param DevInfoData   A pointer to a structure that specifies the device information element in DevInfo.
 *
 * @param Property      The property to be retrieved. One of the SPDRP_* constants.
 *
 * @param Buf           A pointer to a string that receives the string that is being retrieved. Must be released with
 *                      HeapFree(GetProcessHeap(), 0, *Buf) after use.
 *
 * @return ERROR_SUCCESS on success; Win32 error code otherwise.
 */
static WINTUN_STATUS
GetDeviceRegistryString(
    _In_ HDEVINFO DevInfo,
    _In_ SP_DEVINFO_DATA *DevInfoData,
    _In_ DWORD Property,
    _Out_ WCHAR **Buf)
{
    DWORD Result, ValueType, Size = 256 * sizeof(WCHAR);
    Result = GetDeviceRegistryProperty(DevInfo, DevInfoData, Property, &ValueType, Buf, &Size);
    if (Result != ERROR_SUCCESS)
        return Result;
    switch (ValueType)
    {
    case REG_SZ:
    case REG_EXPAND_SZ:
    case REG_MULTI_SZ:
        Result = RegistryGetString(Buf, Size / sizeof(WCHAR), ValueType);
        if (Result != ERROR_SUCCESS)
            HeapFree(GetProcessHeap(), 0, *Buf);
        return Result;
    default:
        LOG(WINTUN_LOG_ERR, L"Property is not a string");
        HeapFree(GetProcessHeap(), 0, *Buf);
        return ERROR_INVALID_DATATYPE;
    }
}

/**
 * Retrieves a specified Plug and Play device property multi-string.
 *
 * @param DevInfo       A handle to the device information set that contains a device information element that
 *                      represents the device for which to open a registry key.
 *
 * @param DevInfoData   A pointer to a structure that specifies the device information element in DevInfo.
 *
 * @param Property      The property to be retrieved. One of the SPDRP_* constants.
 *
 * @param Buf           A pointer to a multi-string that receives the string that is being retrieved. Must be released
 *                      with HeapFree(GetProcessHeap(), 0, *Buf) after use.
 *
 * @return ERROR_SUCCESS on success; Win32 error code otherwise.
 */
static WINTUN_STATUS
GetDeviceRegistryMultiString(
    _In_ HDEVINFO DevInfo,
    _In_ SP_DEVINFO_DATA *DevInfoData,
    _In_ DWORD Property,
    _Out_ WCHAR **Buf)
{
    DWORD Result, ValueType, Size = 256 * sizeof(WCHAR);
    Result = GetDeviceRegistryProperty(DevInfo, DevInfoData, Property, &ValueType, Buf, &Size);
    if (Result != ERROR_SUCCESS)
        return Result;
    switch (ValueType)
    {
    case REG_SZ:
    case REG_EXPAND_SZ:
    case REG_MULTI_SZ:
        Result = RegistryGetMultiString(Buf, Size / sizeof(WCHAR), ValueType);
        if (Result != ERROR_SUCCESS)
            HeapFree(GetProcessHeap(), 0, *Buf);
        return Result;
    default:
        LOG(WINTUN_LOG_ERR, L"Property is not a string");
        HeapFree(GetProcessHeap(), 0, *Buf);
        return ERROR_INVALID_DATATYPE;
    }
}

/**
 * Tests if any of device compatible hardware IDs match ours.
 *
 * @param DevInfo       A handle to the device information set that contains a device information element that
 *                      represents the device.
 *
 * @param DevInfoData   A pointer to a structure that specifies the device information element in DevInfo.
 *
 * @return ERROR_SUCCESS on success; Win32 error code otherwise.
 */
static WINTUN_STATUS
IsOurAdapter(_In_ HDEVINFO DevInfo, _In_ SP_DEVINFO_DATA *DevInfoData, _Out_ BOOL *IsOur)
{
    WCHAR *Hwids;
    DWORD Result = GetDeviceRegistryMultiString(DevInfo, DevInfoData, SPDRP_HARDWAREID, &Hwids);
    if (Result != ERROR_SUCCESS)
        return LOG(WINTUN_LOG_ERR, L"Failed to query hardware ID"), Result;
    *IsOur = DriverIsOurHardwareID(Hwids);
    return ERROR_SUCCESS;
}

/**
 * Returns a handle to the adapter device object.
 *
 * @param InstanceId    Adapter device instance ID.
 *
 * @param Handle        Pointer to receive the adapter device object handle. Must be released with CloseHandle.
 *
 * @return ERROR_SUCCESS on success; Win32 error code otherwise.
 */
static WINTUN_STATUS
GetDeviceObject(_In_opt_z_ const WCHAR *InstanceId, _Out_ HANDLE *Handle)
{
    HANDLE Heap = GetProcessHeap();
    ULONG InterfacesLen;
    DWORD Result = CM_Get_Device_Interface_List_SizeW(
        &InterfacesLen, (GUID *)&GUID_DEVINTERFACE_NET, (DEVINSTID_W)InstanceId, CM_GET_DEVICE_INTERFACE_LIST_PRESENT);
    if (Result != CR_SUCCESS)
    {
        LOG(WINTUN_LOG_ERR, L"Failed to get device associated device instances size");
        return ERROR_GEN_FAILURE;
    }
    WCHAR *Interfaces = HeapAlloc(Heap, 0, InterfacesLen * sizeof(WCHAR));
    if (!Interfaces)
        return LOG(WINTUN_LOG_ERR, L"Out of memory"), ERROR_OUTOFMEMORY;
    Result = CM_Get_Device_Interface_ListW(
        (GUID *)&GUID_DEVINTERFACE_NET,
        (DEVINSTID_W)InstanceId,
        Interfaces,
        InterfacesLen,
        CM_GET_DEVICE_INTERFACE_LIST_PRESENT);
    if (Result != CR_SUCCESS)
    {
        LOG(WINTUN_LOG_ERR, L"Failed to get device associated device instances");
        Result = ERROR_GEN_FAILURE;
        goto cleanupBuf;
    }
    *Handle = CreateFileW(
        Interfaces,
        GENERIC_READ | GENERIC_WRITE,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        NULL,
        OPEN_EXISTING,
        0,
        NULL);
    Result = *Handle != INVALID_HANDLE_VALUE ? ERROR_SUCCESS : LOG_LAST_ERROR(L"Failed to connect to device");
cleanupBuf:
    HeapFree(Heap, 0, Interfaces);
    return Result;
}

#define TUN_IOCTL_FORCE_CLOSE_HANDLES CTL_CODE(51820U, 0x971U, METHOD_NEITHER, FILE_READ_DATA | FILE_WRITE_DATA)

/**
 * Closes all client handles to the Wintun adapter.
 *
 * @param DevInfo       A handle to the device information set that contains a device information element that
 *                      represents the device.
 *
 * @param DevInfoData   A pointer to a structure that specifies the device information element in DevInfo.
 *
 * @return ERROR_SUCCESS on success; Win32 error code otherwise.
 */
static WINTUN_STATUS
ForceCloseWintunAdapterHandle(_In_ HDEVINFO DevInfo, _In_ SP_DEVINFO_DATA *DevInfoData)
{
    DWORD Result = ERROR_SUCCESS;
    DWORD RequiredBytes;
    if (SetupDiGetDeviceInstanceIdW(DevInfo, DevInfoData, NULL, 0, &RequiredBytes) ||
        (Result = GetLastError()) != ERROR_INSUFFICIENT_BUFFER)
        return LOG_ERROR(L"Failed to query device instance ID size", Result);
    HANDLE Heap = GetProcessHeap();
    WCHAR *InstanceId = HeapAlloc(Heap, HEAP_ZERO_MEMORY, sizeof(*InstanceId) * RequiredBytes);
    if (!InstanceId)
        return LOG(WINTUN_LOG_ERR, L"Out of memory"), ERROR_OUTOFMEMORY;
    if (!SetupDiGetDeviceInstanceIdW(DevInfo, DevInfoData, InstanceId, RequiredBytes, &RequiredBytes))
    {
        Result = LOG_LAST_ERROR(L"Failed to get device instance ID");
        goto out;
    }
    HANDLE NdisHandle;
    Result = GetDeviceObject(InstanceId, &NdisHandle);
    if (Result != ERROR_SUCCESS)
    {
        LOG(WINTUN_LOG_ERR, L"Failed to get adapter device object");
        goto out;
    }
    Result = DeviceIoControl(NdisHandle, TUN_IOCTL_FORCE_CLOSE_HANDLES, NULL, 0, NULL, 0, &RequiredBytes, NULL)
                 ? ERROR_SUCCESS
                 : LOG_LAST_ERROR(L"Failed to perform ioctl");
    CloseHandle(NdisHandle);
out:
    HeapFree(Heap, 0, InstanceId);
    return Result;
}

/**
 * Disables all Wintun adapters.
 *
 * @param DevInfo       A handle to the device information set.
 *
 * @param DisabledAdapters  Output list of disabled adapters. The adapters disabled are inserted in the list head.
 *
 * @return ERROR_SUCCESS on success; Win32 error code otherwise.
 */
WINTUN_STATUS
AdapterDisableAllOurs(_In_ HDEVINFO DevInfo, _Inout_ SP_DEVINFO_DATA_LIST **DisabledAdapters)
{
    SP_PROPCHANGE_PARAMS Params = { .ClassInstallHeader = { .cbSize = sizeof(SP_CLASSINSTALL_HEADER),
                                                            .InstallFunction = DIF_PROPERTYCHANGE },
                                    .StateChange = DICS_DISABLE,
                                    .Scope = DICS_FLAG_GLOBAL };
    DWORD Result = ERROR_SUCCESS;
    HANDLE Heap = GetProcessHeap();
    for (DWORD EnumIndex = 0;; ++EnumIndex)
    {
        SP_DEVINFO_DATA_LIST *DeviceNode = HeapAlloc(Heap, 0, sizeof(SP_DEVINFO_DATA_LIST));
        if (!DeviceNode)
            return LOG(WINTUN_LOG_ERR, L"Out of memory"), ERROR_OUTOFMEMORY;
        DeviceNode->Data.cbSize = sizeof(SP_DEVINFO_DATA);
        if (!SetupDiEnumDeviceInfo(DevInfo, EnumIndex, &DeviceNode->Data))
        {
            if (GetLastError() == ERROR_NO_MORE_ITEMS)
            {
                HeapFree(Heap, 0, DeviceNode);
                break;
            }
            goto cleanupDeviceInfoData;
        }
        BOOL IsOur;
        if (IsOurAdapter(DevInfo, &DeviceNode->Data, &IsOur) != ERROR_SUCCESS || !IsOur)
            goto cleanupDeviceInfoData;

        ULONG Status, ProblemCode;
        if (CM_Get_DevNode_Status(&Status, &ProblemCode, DeviceNode->Data.DevInst, 0) != CR_SUCCESS ||
            ((Status & DN_HAS_PROBLEM) && ProblemCode == CM_PROB_DISABLED))
            goto cleanupDeviceInfoData;

        LOG(WINTUN_LOG_INFO, L"Force closing all open handles for existing adapter");
        if (ForceCloseWintunAdapterHandle(DevInfo, &DeviceNode->Data) != ERROR_SUCCESS)
            LOG(WINTUN_LOG_WARN, L"Failed to force close adapter handles");
        Sleep(200);

        LOG(WINTUN_LOG_INFO, L"Disabling existing adapter");
        if (!SetupDiSetClassInstallParamsW(DevInfo, &DeviceNode->Data, &Params.ClassInstallHeader, sizeof(Params)) ||
            !SetupDiCallClassInstaller(DIF_PROPERTYCHANGE, DevInfo, &DeviceNode->Data))
        {
            LOG_LAST_ERROR(L"Unable to disable existing adapter");
            Result = Result != ERROR_SUCCESS ? Result : GetLastError();
            goto cleanupDeviceInfoData;
        }

        DeviceNode->Next = *DisabledAdapters;
        *DisabledAdapters = DeviceNode;
        continue;

    cleanupDeviceInfoData:
        HeapFree(Heap, 0, &DeviceNode->Data);
    }
    return Result;
}

/**
 * Enables all adapters.
 *
 * @param DevInfo       A handle to the device information set.
 *
 * @param AdaptersToEnable  Input list of adapters to enable.
 *
 * @return ERROR_SUCCESS on success; Win32 error code otherwise.
 */
WINTUN_STATUS
AdapterEnableAll(_In_ HDEVINFO DevInfo, _In_ SP_DEVINFO_DATA_LIST *AdaptersToEnable)
{
    SP_PROPCHANGE_PARAMS Params = { .ClassInstallHeader = { .cbSize = sizeof(SP_CLASSINSTALL_HEADER),
                                                            .InstallFunction = DIF_PROPERTYCHANGE },
                                    .StateChange = DICS_ENABLE,
                                    .Scope = DICS_FLAG_GLOBAL };
    DWORD Result = ERROR_SUCCESS;
    for (SP_DEVINFO_DATA_LIST *DeviceNode = AdaptersToEnable; DeviceNode; DeviceNode = DeviceNode->Next)
    {
        LOG(WINTUN_LOG_INFO, L"Enabling existing adapter");
        if (!SetupDiSetClassInstallParamsW(DevInfo, &DeviceNode->Data, &Params.ClassInstallHeader, sizeof(Params)) ||
            !SetupDiCallClassInstaller(DIF_PROPERTYCHANGE, DevInfo, &DeviceNode->Data))
        {
            LOG_LAST_ERROR(L"Unable to enable existing adapter");
            Result = Result != ERROR_SUCCESS ? Result : GetLastError();
        }
    }
    return Result;
}

/**
 * Removes all Wintun adapters.
 *
 * @return ERROR_SUCCESS on success; Win32 error code otherwise.
 */
WINTUN_STATUS
AdapterDeleteAllOurs()
{
    DWORD Result = ERROR_SUCCESS;
    HDEVINFO DevInfo = SetupDiGetClassDevsExW(&GUID_DEVCLASS_NET, NULL, NULL, DIGCF_PRESENT, NULL, NULL, NULL);
    if (DevInfo == INVALID_HANDLE_VALUE)
        return LOG_LAST_ERROR(L"Failed to get present class devices");
    SP_REMOVEDEVICE_PARAMS Params = { .ClassInstallHeader = { .cbSize = sizeof(SP_CLASSINSTALL_HEADER),
                                                              .InstallFunction = DIF_REMOVE },
                                      .Scope = DI_REMOVEDEVICE_GLOBAL };
    for (DWORD EnumIndex = 0;; ++EnumIndex)
    {
        SP_DEVINFO_DATA DevInfoData = { .cbSize = sizeof(SP_DEVINFO_DATA) };
        if (!SetupDiEnumDeviceInfo(DevInfo, EnumIndex, &DevInfoData))
        {
            if (GetLastError() == ERROR_NO_MORE_ITEMS)
                break;
            continue;
        }

        BOOL IsOur;
        if (IsOurAdapter(DevInfo, &DevInfoData, &IsOur) != ERROR_SUCCESS || !IsOur)
            continue;

        LOG(WINTUN_LOG_INFO, L"Force closing all open handles for existing adapter");
        if (ForceCloseWintunAdapterHandle(DevInfo, &DevInfoData) != ERROR_SUCCESS)
            LOG(WINTUN_LOG_WARN, L"Failed to force close adapter handles");
        Sleep(200);

        LOG(WINTUN_LOG_INFO, L"Removing existing adapter");
        if (!SetupDiSetClassInstallParamsW(DevInfo, &DevInfoData, &Params.ClassInstallHeader, sizeof(Params)) ||
            !SetupDiCallClassInstaller(DIF_REMOVE, DevInfo, &DevInfoData))
        {
            LOG_LAST_ERROR(L"Unable to remove existing adapter");
            Result = Result != ERROR_SUCCESS ? Result : GetLastError();
        }
    }
    SetupDiDestroyDeviceInfoList(DevInfo);
    return Result;
}

void
AdapterInit()
{
    Locale = _wcreate_locale(LC_ALL, L"");
}

void
AdapterCleanup()
{
    _free_locale(Locale);
}

/**
 * Checks device install parameters if a system reboot is required.
 */
static BOOL
CheckReboot(_In_ HDEVINFO DevInfo, _In_ SP_DEVINFO_DATA *DevInfoData)
{
    SP_DEVINSTALL_PARAMS_W DevInstallParams = { .cbSize = sizeof(SP_DEVINSTALL_PARAMS_W) };
    if (!SetupDiGetDeviceInstallParamsW(DevInfo, DevInfoData, &DevInstallParams))
    {
        LOG_LAST_ERROR(L"Retrieving device installation parameters failed");
        return FALSE;
    }
    return (DevInstallParams.Flags & (DI_NEEDREBOOT | DI_NEEDRESTART)) != 0;
}

/**
 * Sets device install parameters for a quiet installation.
 */
static WINTUN_STATUS
SetQuietInstall(_In_ HDEVINFO DevInfo, _In_ SP_DEVINFO_DATA *DevInfoData)
{
    SP_DEVINSTALL_PARAMS_W DevInstallParams = { .cbSize = sizeof(SP_DEVINSTALL_PARAMS_W) };
    if (!SetupDiGetDeviceInstallParamsW(DevInfo, DevInfoData, &DevInstallParams))
        return LOG_LAST_ERROR(L"Retrieving device installation parameters failed");
    DevInstallParams.Flags |= DI_QUIETINSTALL;
    if (!SetupDiSetDeviceInstallParamsW(DevInfo, DevInfoData, &DevInstallParams))
        return LOG_LAST_ERROR(L"Setting device installation parameters failed");
    return ERROR_SUCCESS;
}

/**
 * Returns adapter GUID associated with device.
 *
 * @param DevInfo       A handle to the device information set that contains a device information element that
 *                      represents the device for which to open a registry key.
 *
 * @param DevInfoData   A pointer to a structure that specifies the device information element in DevInfo.
 *
 * @param CfgInstanceID  Pointer to a GUID to receive the adapter GUID.
 *
 * @return ERROR_SUCCESS on success; Win32 error code otherwise.
 */
static WINTUN_STATUS
GetNetCfgInstanceId(_In_ HDEVINFO DevInfo, _In_ SP_DEVINFO_DATA *DevInfoData, _Out_ GUID *CfgInstanceID)
{
    HKEY Key = SetupDiOpenDevRegKey(DevInfo, DevInfoData, DICS_FLAG_GLOBAL, 0, DIREG_DRV, KEY_QUERY_VALUE);
    if (Key == INVALID_HANDLE_VALUE)
        return LOG_LAST_ERROR(L"Opening device registry key failed");
    WCHAR *ValueStr;
    DWORD Result = RegistryQueryString(Key, L"NetCfgInstanceId", &ValueStr);
    if (Result != ERROR_SUCCESS)
    {
        LOG_ERROR(L"Failed to query NetCfgInstanceId value", Result);
        goto cleanupKey;
    }
    if (FAILED(CLSIDFromString(ValueStr, CfgInstanceID)))
    {
        LOG(WINTUN_LOG_ERR, L"NetCfgInstanceId is not a GUID");
        Result = ERROR_INVALID_DATA;
    }
    else
        Result = ERROR_SUCCESS;
    HeapFree(GetProcessHeap(), 0, ValueStr);
cleanupKey:
    RegCloseKey(Key);
    return Result;
}

/**
 * Returns device info list handle and adapter device info data.
 *
 * @param CfgInstanceID  The adapter GUID.
 *
 * @param DevInfo       A pointer to receive the handle of the device information set that contains a device information
 *                      element that represents the device. Must be released with SetupDiDestroyDeviceInfoList(*DevInfo)
 *                      after use.
 *
 * @param DevInfoData   A pointer to a structure that receives specification of the device information element in
 *                      DevInfo.
 *
 * @return ERROR_SUCCESS on success; ERROR_FILE_NOT_FOUND if the device is not found; Win32 error code otherwise.
 */
static WINTUN_STATUS
GetDevInfoData(_In_ const GUID *CfgInstanceID, _Out_ HDEVINFO *DevInfo, _Out_ SP_DEVINFO_DATA *DevInfoData)
{
    *DevInfo = SetupDiGetClassDevsExW(&GUID_DEVCLASS_NET, NULL, NULL, DIGCF_PRESENT, NULL, NULL, NULL);
    if (!*DevInfo)
        return LOG_LAST_ERROR(L"Failed to get present class devices");
    for (DWORD EnumIndex = 0;; ++EnumIndex)
    {
        DevInfoData->cbSize = sizeof(SP_DEVINFO_DATA);
        if (!SetupDiEnumDeviceInfo(*DevInfo, EnumIndex, DevInfoData))
        {
            if (GetLastError() == ERROR_NO_MORE_ITEMS)
                break;
            continue;
        }
        GUID CfgInstanceID2;
        if (GetNetCfgInstanceId(*DevInfo, DevInfoData, &CfgInstanceID2) == ERROR_SUCCESS &&
            !memcmp(CfgInstanceID, &CfgInstanceID2, sizeof(GUID)))
            return ERROR_SUCCESS;
    }
    SetupDiDestroyDeviceInfoList(*DevInfo);
    return ERROR_FILE_NOT_FOUND;
}

/**
 * Removes numbered suffix from adapter name.
 */
static void
RemoveNumberedSuffix(_In_z_ const WCHAR *Name, _Out_ WCHAR *Removed)
{
    size_t Len = wcslen(Name);
    if (Len && (Name[Len - 1] < L'0' || Name[Len - 1] > L'9'))
    {
        wmemcpy(Removed, Name, Len + 1);
        return;
    }
    for (size_t i = Len; i--;)
    {
        if (Name[i] >= L'0' && Name[i] <= L'9')
            continue;
        if (Name[i] == L' ')
        {
            wmemcpy(Removed, Name, i);
            Removed[i] = 0;
            return;
        }
        break;
    }
    wmemcpy(Removed, Name, Len + 1);
}

/**
 * Returns pool-specific device type name.
 */
static void
GetPoolDeviceTypeName(_In_z_count_c_(MAX_POOL) const WCHAR *Pool, _Out_cap_c_(MAX_POOL_DEVICE_TYPE) WCHAR *Name)
{
    _snwprintf_s(Name, MAX_POOL_DEVICE_TYPE, _TRUNCATE, L"%.*s Tunnel", MAX_POOL, Pool);
}

/**
 * Checks if SPDRP_DEVICEDESC or SPDRP_FRIENDLYNAME match device type name.
 */
static WINTUN_STATUS
IsPoolMember(
    _In_z_count_c_(MAX_POOL) const WCHAR *Pool,
    _In_ HDEVINFO DevInfo,
    _In_ SP_DEVINFO_DATA *DevInfoData,
    _Out_ BOOL *IsMember)
{
    HANDLE Heap = GetProcessHeap();
    WCHAR *DeviceDesc, *FriendlyName;
    DWORD Result = GetDeviceRegistryString(DevInfo, DevInfoData, SPDRP_DEVICEDESC, &DeviceDesc);
    if (Result != ERROR_SUCCESS)
    {
        LOG(WINTUN_LOG_ERR, L"Failed to query device description property");
        return Result;
    }
    Result = GetDeviceRegistryString(DevInfo, DevInfoData, SPDRP_FRIENDLYNAME, &FriendlyName);
    if (Result != ERROR_SUCCESS)
    {
        LOG(WINTUN_LOG_ERR, L"Failed to query friendly name property");
        goto cleanupDeviceDesc;
    }
    WCHAR PoolDeviceTypeName[MAX_POOL_DEVICE_TYPE];
    GetPoolDeviceTypeName(Pool, PoolDeviceTypeName);
    if (!_wcsicmp_l(FriendlyName, PoolDeviceTypeName, Locale) || !_wcsicmp_l(DeviceDesc, PoolDeviceTypeName, Locale))
    {
        *IsMember = TRUE;
        goto cleanupFriendlyName;
    }
    RemoveNumberedSuffix(FriendlyName, FriendlyName);
    RemoveNumberedSuffix(DeviceDesc, DeviceDesc);
    if (!_wcsicmp_l(FriendlyName, PoolDeviceTypeName, Locale) || !_wcsicmp_l(DeviceDesc, PoolDeviceTypeName, Locale))
    {
        *IsMember = TRUE;
        goto cleanupFriendlyName;
    }
    *IsMember = FALSE;
cleanupFriendlyName:
    HeapFree(Heap, 0, FriendlyName);
cleanupDeviceDesc:
    HeapFree(Heap, 0, DeviceDesc);
    return Result;
}

/**
 * Creates a Wintun adapter descriptor and populates it from the device's registry key.
 *
 * @param DevInfo       A handle to the device information set that contains a device information element that
 *                      represents the device for which to open a registry key.
 *
 * @param DevInfoData   A pointer to a structure that specifies the device information element in DevInfo.
 *
 * @param Pool          Name of the adapter pool.
 *
 * @param Adapter       Pointer to a handle to receive the adapter descriptor. Must be released with
 *                      HeapFree(GetProcessHeap(), 0, *Adapter).
 *
 * @return ERROR_SUCCESS on success; ERROR_INVALID_DATATYPE or ERROR_INVALID_DATA on any invalid registry values; Win32
 * error code otherwise.
 */
static WINTUN_STATUS
CreateAdapterData(
    _In_z_count_c_(MAX_POOL) const WCHAR *Pool,
    _In_ HDEVINFO DevInfo,
    _In_ SP_DEVINFO_DATA *DevInfoData,
    _Out_ WINTUN_ADAPTER **Adapter)
{
    DWORD Result;

    /* Open HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\<class>\<id> registry key. */
    HKEY Key = SetupDiOpenDevRegKey(DevInfo, DevInfoData, DICS_FLAG_GLOBAL, 0, DIREG_DRV, KEY_QUERY_VALUE);
    if (Key == INVALID_HANDLE_VALUE)
        return LOG_LAST_ERROR(L"Opening device registry key failed");

    HANDLE Heap = GetProcessHeap();
    *Adapter = HeapAlloc(Heap, 0, sizeof(WINTUN_ADAPTER));
    if (!*Adapter)
    {
        LOG(WINTUN_LOG_ERR, L"Out of memory");
        Result = ERROR_OUTOFMEMORY;
        goto cleanupKey;
    }

    /* Read the NetCfgInstanceId value and convert to GUID. */
    WCHAR *ValueStr;
    Result = RegistryQueryString(Key, L"NetCfgInstanceId", &ValueStr);
    if (Result != ERROR_SUCCESS)
    {
        LOG_ERROR(L"Failed to query NetCfgInstanceId value", Result);
        goto cleanupAdapter;
    }
    if (FAILED(CLSIDFromString(ValueStr, &(*Adapter)->CfgInstanceID)))
    {
        LOG(WINTUN_LOG_ERR, L"NetCfgInstanceId is not a GUID");
        HeapFree(Heap, 0, ValueStr);
        Result = ERROR_INVALID_DATA;
        goto cleanupAdapter;
    }
    HeapFree(Heap, 0, ValueStr);

    /* Read the NetLuidIndex value. */
    Result = RegistryQueryDWORD(Key, L"NetLuidIndex", &(*Adapter)->LuidIndex);
    if (Result != ERROR_SUCCESS)
    {
        LOG(WINTUN_LOG_ERR, L"Failed to query NetLuidIndex value");
        goto cleanupAdapter;
    }

    /* Read the NetLuidIndex value. */
    Result = RegistryQueryDWORD(Key, L"*IfType", &(*Adapter)->IfType);
    if (Result != ERROR_SUCCESS)
    {
        LOG(WINTUN_LOG_ERR, L"Failed to query *IfType value");
        goto cleanupAdapter;
    }

    DWORD Size;
    if (!SetupDiGetDeviceInstanceIdW(
            DevInfo, DevInfoData, (*Adapter)->DevInstanceID, _countof((*Adapter)->DevInstanceID), &Size))
    {
        Result = LOG_LAST_ERROR(L"Failed to get device instance ID");
        goto cleanupAdapter;
    }

    wcsncpy_s((*Adapter)->Pool, _countof((*Adapter)->Pool), Pool, _TRUNCATE);
    Result = ERROR_SUCCESS;

cleanupAdapter:
    if (Result != ERROR_SUCCESS)
        HeapFree(Heap, 0, *Adapter);
cleanupKey:
    RegCloseKey(Key);
    return Result;
}

/**
 * Returns the device-level registry key path.
 */
static void
GetDeviceRegPath(_In_ const WINTUN_ADAPTER *Adapter, _Out_cap_c_(MAX_REG_PATH) WCHAR *Path)
{
    _snwprintf_s(
        Path,
        MAX_REG_PATH,
        _TRUNCATE,
        L"SYSTEM\\CurrentControlSet\\Enum\\%.*s",
        MAX_INSTANCE_ID,
        Adapter->DevInstanceID);
}

/**
 * Returns the adapter-specific TCP/IP network registry key path.
 */
static void
GetTcpipAdapterRegPath(_In_ const WINTUN_ADAPTER *Adapter, _Out_cap_c_(MAX_REG_PATH) WCHAR *Path)
{
    WCHAR Guid[MAX_GUID_STRING_LEN];
    _snwprintf_s(
        Path,
        MAX_REG_PATH,
        _TRUNCATE,
        L"SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters\\Adapters\\%.*s",
        StringFromGUID2(&Adapter->CfgInstanceID, Guid, _countof(Guid)),
        Guid);
}

/**
 * Returns the interface-specific TCP/IP network registry key path.
 */
static WINTUN_STATUS
GetTcpipInterfaceRegPath(_In_ const WINTUN_ADAPTER *Adapter, _Out_cap_c_(MAX_REG_PATH) WCHAR *Path)
{
    DWORD Result;
    HKEY TcpipAdapterRegKey;
    WCHAR TcpipAdapterRegPath[MAX_REG_PATH];
    GetTcpipAdapterRegPath(Adapter, TcpipAdapterRegPath);
    Result = RegOpenKeyExW(HKEY_LOCAL_MACHINE, TcpipAdapterRegPath, 0, KEY_QUERY_VALUE, &TcpipAdapterRegKey);
    if (Result != ERROR_SUCCESS)
        return LOG_ERROR(L"Failed to open registry key", Result);
    WCHAR *Paths;
    Result = RegistryQueryString(TcpipAdapterRegKey, L"IpConfig", &Paths);
    if (Result != ERROR_SUCCESS)
    {
        LOG_ERROR(L"Failed to query IpConfig value", Result);
        goto cleanupTcpipAdapterRegKey;
    }
    if (!Paths[0])
    {
        LOG(WINTUN_LOG_ERR, L"IpConfig is empty");
        Result = ERROR_INVALID_DATA;
        goto cleanupPaths;
    }
    _snwprintf_s(Path, MAX_REG_PATH, _TRUNCATE, L"SYSTEM\\CurrentControlSet\\Services\\%s", Paths);
cleanupPaths:
    HeapFree(GetProcessHeap(), 0, Paths);
cleanupTcpipAdapterRegKey:
    RegCloseKey(TcpipAdapterRegKey);
    return Result;
}

/**
 * Releases Wintun adapter resources.
 *
 * @param Adapter       Adapter handle obtained with WintunGetAdapter or WintunCreateAdapter.
 */
void WINAPI
WintunFreeAdapter(_In_ WINTUN_ADAPTER *Adapter)
{
    HeapFree(GetProcessHeap(), 0, Adapter);
}

/**
 * Finds a Wintun adapter by its name.
 *
 * @param Pool          Name of the adapter pool.
 *
 * @param Name          Adapter name.
 *
 * @param Adapter       Pointer to a handle to receive the adapter handle. Must be released with WintunFreeAdapter.
 *
 * @return ERROR_SUCCESS on success; ERROR_FILE_NOT_FOUND if adapter with given name is not found; ERROR_ALREADY_EXISTS
 * if adapter is found but not a Wintun-class or not a member of the pool; Win32 error code otherwise
 */
WINTUN_STATUS WINAPI
WintunGetAdapter(
    _In_z_count_c_(MAX_POOL) const WCHAR *Pool,
    _In_z_count_c_(MAX_ADAPTER_NAME) const WCHAR *Name,
    _Out_ WINTUN_ADAPTER **Adapter)
{
    DWORD Result;
    HANDLE Mutex = NamespaceTakeMutex(Pool);
    if (!Mutex)
        return ERROR_INVALID_HANDLE;

    HDEVINFO DevInfo = SetupDiGetClassDevsExW(&GUID_DEVCLASS_NET, NULL, NULL, DIGCF_PRESENT, NULL, NULL, NULL);
    if (DevInfo == INVALID_HANDLE_VALUE)
    {
        Result = LOG_LAST_ERROR(L"Failed to get present class devices");
        goto cleanupMutex;
    }

    for (DWORD EnumIndex = 0;; ++EnumIndex)
    {
        SP_DEVINFO_DATA DevInfoData = { .cbSize = sizeof(SP_DEVINFO_DATA) };
        if (!SetupDiEnumDeviceInfo(DevInfo, EnumIndex, &DevInfoData))
        {
            if (GetLastError() == ERROR_NO_MORE_ITEMS)
                break;
            continue;
        }

        GUID CfgInstanceID;
        if (GetNetCfgInstanceId(DevInfo, &DevInfoData, &CfgInstanceID) != ERROR_SUCCESS)
            continue;

        /* TODO: is there a better way than comparing ifnames? */
        WCHAR Name2[MAX_ADAPTER_NAME];
        if (NciGetConnectionName(&CfgInstanceID, Name2, sizeof(Name2), NULL) != ERROR_SUCCESS)
            continue;
        Name2[_countof(Name2) - 1] = 0;
        if (_wcsicmp_l(Name, Name2, Locale))
        {
            RemoveNumberedSuffix(Name2, Name2);
            if (_wcsicmp_l(Name, Name2, Locale))
                continue;
        }

        /* Check the Hardware ID to make sure it's a real Wintun device. */
        BOOL IsOur;
        Result = IsOurAdapter(DevInfo, &DevInfoData, &IsOur);
        if (Result != ERROR_SUCCESS)
        {
            LOG(WINTUN_LOG_ERR, L"Failed to determine hardware ID");
            goto cleanupDevInfo;
        }
        if (!IsOur)
        {
            LOG(WINTUN_LOG_ERR, L"Foreign adapter with the same name exists");
            Result = ERROR_ALREADY_EXISTS;
            goto cleanupDevInfo;
        }

        BOOL IsMember;
        Result = IsPoolMember(Pool, DevInfo, &DevInfoData, &IsMember);
        if (Result != ERROR_SUCCESS)
        {
            LOG(WINTUN_LOG_ERR, L"Failed to determine pool membership");
            goto cleanupDevInfo;
        }
        if (!IsMember)
        {
            LOG(WINTUN_LOG_ERR, L"Wintun adapter with the same name exists in another pool");
            Result = ERROR_ALREADY_EXISTS;
            goto cleanupDevInfo;
        }

        Result = CreateAdapterData(Pool, DevInfo, &DevInfoData, Adapter);
        if (Result != ERROR_SUCCESS)
            LOG(WINTUN_LOG_ERR, L"Failed to create adapter data");

        goto cleanupDevInfo;
    }
    Result = ERROR_FILE_NOT_FOUND;
cleanupDevInfo:
    SetupDiDestroyDeviceInfoList(DevInfo);
cleanupMutex:
    NamespaceReleaseMutex(Mutex);
    return Result;
}

/**
 * Returns the name of the Wintun adapter.
 */
WINTUN_STATUS WINAPI
WintunGetAdapterName(_In_ const WINTUN_ADAPTER *Adapter, _Out_cap_c_(MAX_ADAPTER_NAME) WCHAR *Name)
{
    return NciGetConnectionName(&Adapter->CfgInstanceID, Name, MAX_ADAPTER_NAME * sizeof(WCHAR), NULL);
}

static WINTUN_STATUS
ConvertInterfaceAliasToGuid(_In_z_ const WCHAR *Name, _Out_ GUID *Guid)
{
    NET_LUID Luid;
    DWORD Result = ConvertInterfaceAliasToLuid(Name, &Luid);
    if (Result != NO_ERROR)
        return LOG_ERROR(L"Failed convert interface alias name to the locally unique identifier", Result);
    return ConvertInterfaceLuidToGuid(&Luid, Guid);
}

/**
 * Sets name of the Wintun adapter.
 */
WINTUN_STATUS WINAPI
WintunSetAdapterName(_In_ const WINTUN_ADAPTER *Adapter, _In_z_count_c_(MAX_ADAPTER_NAME) const WCHAR *Name)
{
    DWORD Result;
    const int MaxSuffix = 1000;
    WCHAR AvailableName[MAX_ADAPTER_NAME];
    wcsncpy_s(AvailableName, _countof(AvailableName), Name, _TRUNCATE);
    for (int i = 0;; ++i)
    {
        Result = NciSetConnectionName(&Adapter->CfgInstanceID, AvailableName);
        if (Result == ERROR_DUP_NAME)
        {
            GUID Guid2;
            DWORD Result2 = ConvertInterfaceAliasToGuid(AvailableName, &Guid2);
            if (Result2 == ERROR_SUCCESS)
            {
                for (int j = 0; j < MaxSuffix; ++j)
                {
                    WCHAR Proposal[MAX_ADAPTER_NAME];
                    _snwprintf_s(Proposal, _countof(Proposal), _TRUNCATE, L"%.*s %d", MAX_ADAPTER_NAME, Name, j + 1);
                    if (_wcsnicmp(Proposal, AvailableName, MAX_ADAPTER_NAME) == 0)
                        continue;
                    Result2 = NciSetConnectionName(&Guid2, Proposal);
                    if (Result2 == ERROR_DUP_NAME)
                        continue;
                    if (Result2 == ERROR_SUCCESS)
                    {
                        Result = NciSetConnectionName(&Adapter->CfgInstanceID, AvailableName);
                        if (Result == ERROR_SUCCESS)
                            break;
                    }
                    break;
                }
            }
        }
        if (Result == ERROR_SUCCESS)
            break;
        if (i > MaxSuffix || Result != ERROR_DUP_NAME)
            return LOG_ERROR(L"Setting adapter name failed", Result);
        _snwprintf_s(AvailableName, _countof(AvailableName), _TRUNCATE, L"%.*s %d", MAX_ADAPTER_NAME, Name, i + 1);
    }

    /* TODO: This should use NetSetup2 so that it doesn't get unset. */
    HKEY DeviceRegKey;
    WCHAR DeviceRegPath[MAX_REG_PATH];
    GetDeviceRegPath(Adapter, DeviceRegPath);
    Result = RegOpenKeyExW(HKEY_LOCAL_MACHINE, DeviceRegPath, 0, KEY_SET_VALUE, &DeviceRegKey);
    if (Result != ERROR_SUCCESS)
        return LOG_ERROR(L"Failed to open registry key", Result);
    WCHAR PoolDeviceTypeName[MAX_POOL_DEVICE_TYPE];
    GetPoolDeviceTypeName(Adapter->Pool, PoolDeviceTypeName);
    Result = RegSetKeyValueW(
        DeviceRegKey,
        NULL,
        L"FriendlyName",
        REG_SZ,
        PoolDeviceTypeName,
        (DWORD)((wcslen(PoolDeviceTypeName) + 1) * sizeof(WCHAR)));
    RegCloseKey(DeviceRegKey);
    return Result;
}

/**
 * Returns the GUID of the adapter.
 *
 * @param Adapter       Adapter handle obtained with WintunGetAdapter or WintunCreateAdapter
 *
 * @param Guid          Pointer to GUID to receive adapter ID.
 */
void WINAPI
WintunGetAdapterGUID(_In_ const WINTUN_ADAPTER *Adapter, _Out_ GUID *Guid)
{
    memcpy(Guid, &Adapter->CfgInstanceID, sizeof(GUID));
}

/**
 * Returns the LUID of the adapter.
 *
 * @param Adapter       Adapter handle obtained with WintunGetAdapter or WintunCreateAdapter
 *
 * @param Luid          Pointer to LUID to receive adapter LUID.
 */
void WINAPI
WintunGetAdapterLUID(_In_ const WINTUN_ADAPTER *Adapter, _Out_ LUID *Luid)
{
    *(LONGLONG *)Luid = (((LONGLONG)Adapter->LuidIndex & ((1 << 24) - 1)) << 24) |
                        (((LONGLONG)Adapter->IfType & ((1 << 16) - 1)) << 48);
}

/**
 * Returns a handle to the adapter device object.
 *
 * @param Adapter       Adapter handle obtained with WintunGetAdapter or WintunCreateAdapter.
 *
 * @param Handle        Pointer to receive the adapter device object handle. Must be released with CloseHandle.
 *
 * @return ERROR_SUCCESS on success; Win32 error code otherwise.
 */
WINTUN_STATUS WINAPI
WintunGetAdapterDeviceObject(_In_ const WINTUN_ADAPTER *Adapter, _Out_ HANDLE *Handle)
{
    return GetDeviceObject(Adapter->DevInstanceID, Handle);
}

/**
 * @return TRUE if DrvInfoData date and version is newer than supplied parameters.
 */
static BOOL
IsNewer(_In_ const SP_DRVINFO_DATA_W *DrvInfoData, _In_ const FILETIME *DriverDate, _In_ DWORDLONG DriverVersion)
{
    if (DrvInfoData->DriverDate.dwHighDateTime > DriverDate->dwHighDateTime)
        return TRUE;
    if (DrvInfoData->DriverDate.dwHighDateTime < DriverDate->dwHighDateTime)
        return FALSE;

    if (DrvInfoData->DriverDate.dwLowDateTime > DriverDate->dwLowDateTime)
        return TRUE;
    if (DrvInfoData->DriverDate.dwLowDateTime < DriverDate->dwLowDateTime)
        return FALSE;

    if (DrvInfoData->DriverVersion > DriverVersion)
        return TRUE;
    if (DrvInfoData->DriverVersion < DriverVersion)
        return FALSE;

    return FALSE;
}

/**
 * Creates a Wintun adapter.
 *
 * @param Pool          Name of the adapter pool.
 *
 * @param Name          The requested name of the adapter.
 *
 * @param RequestedGUID  The GUID of the created network adapter, which then influences NLA generation
 *                      deterministically. If it is set to NULL, the GUID is chosen by the system at random, and hence
 *                      a new NLA entry is created for each new adapter. It is called "requested" GUID because the API
 *                      it uses is completely undocumented, and so there could be minor interesting complications with
 *                      its usage.
 *
 * @param Adapter       Pointer to a handle to receive the adapter handle. Must be released with
 *                      WintunFreeAdapter.
 *
 * @param RebootRequired  Pointer to a boolean flag to be set to TRUE in case SetupAPI suggests a reboot. Must be
 *                      initialised to FALSE manually before this function is called.
 *
 * @return ERROR_SUCCESS on success; Win32 error code otherwise.
 */
WINTUN_STATUS WINAPI
WintunCreateAdapter(
    _In_z_count_c_(MAX_POOL) const WCHAR *Pool,
    _In_z_count_c_(MAX_ADAPTER_NAME) const WCHAR *Name,
    _In_opt_ const GUID *RequestedGUID,
    _Out_ WINTUN_ADAPTER **Adapter,
    _Inout_ BOOL *RebootRequired)
{
    DWORD Result;
    HANDLE Mutex = NamespaceTakeMutex(Pool);
    if (!Mutex)
        return ERROR_INVALID_HANDLE;

    HDEVINFO DevInfo = SetupDiCreateDeviceInfoListExW(&GUID_DEVCLASS_NET, NULL, NULL, NULL);
    if (DevInfo == INVALID_HANDLE_VALUE)
    {
        Result = LOG_LAST_ERROR(L"Creating empty device information set failed");
        goto cleanupMutex;
    }

    WCHAR ClassName[MAX_CLASS_NAME_LEN];
    if (!SetupDiClassNameFromGuidExW(&GUID_DEVCLASS_NET, ClassName, _countof(ClassName), NULL, NULL, NULL))
    {
        Result = LOG_LAST_ERROR(L"Retrieving class name associated with class GUID failed");
        goto cleanupDevInfo;
    }

    HANDLE Heap = GetProcessHeap();
    WCHAR PoolDeviceTypeName[MAX_POOL_DEVICE_TYPE];
    GetPoolDeviceTypeName(Pool, PoolDeviceTypeName);
    SP_DEVINFO_DATA DevInfoData = { .cbSize = sizeof(SP_DEVINFO_DATA) };
    if (!SetupDiCreateDeviceInfoW(
            DevInfo, ClassName, &GUID_DEVCLASS_NET, PoolDeviceTypeName, NULL, DICD_GENERATE_ID, &DevInfoData))
    {
        Result = LOG_LAST_ERROR(L"Creating new device information element failed");
        goto cleanupDevInfo;
    }
    SetQuietInstall(DevInfo, &DevInfoData);

    if (!SetupDiSetSelectedDevice(DevInfo, &DevInfoData))
    {
        Result = LOG_LAST_ERROR(L"Failed selecting device");
        goto cleanupDevInfo;
    }

    static const WCHAR Hwids[_countof(WINTUN_HWID) + 1 /*Multi-string terminator*/] = WINTUN_HWID;
    if (!SetupDiSetDeviceRegistryPropertyW(DevInfo, &DevInfoData, SPDRP_HARDWAREID, (const BYTE *)Hwids, sizeof(Hwids)))
    {
        Result = LOG_LAST_ERROR(L"Failed setting hardware ID");
        goto cleanupDevInfo;
    }
    if (!SetupDiBuildDriverInfoList(DevInfo, &DevInfoData, SPDIT_COMPATDRIVER)) /* TODO: This takes ~510ms */
    {
        Result = LOG_LAST_ERROR(L"Failed building driver info list");
        goto cleanupDevInfo;
    }

    FILETIME DriverDate = { 0, 0 };
    DWORDLONG DriverVersion = 0;
    for (DWORD EnumIndex = 0;; ++EnumIndex) /* TODO: This loop takes ~600ms */
    {
        SP_DRVINFO_DATA_W DrvInfoData = { .cbSize = sizeof(SP_DRVINFO_DATA_W) };
        if (!SetupDiEnumDriverInfoW(DevInfo, &DevInfoData, SPDIT_COMPATDRIVER, EnumIndex, &DrvInfoData))
        {
            if (GetLastError() == ERROR_NO_MORE_ITEMS)
                break;
            continue;
        }

        /* Check the driver version first, since the check is trivial and will save us iterating over hardware IDs for
         * any driver versioned prior our best match. */
        if (!IsNewer(&DrvInfoData, &DriverDate, DriverVersion))
            continue;

        SP_DRVINFO_DETAIL_DATA_W *DrvInfoDetailData;
        if (AdapterGetDrvInfoDetail(DevInfo, &DevInfoData, &DrvInfoData, &DrvInfoDetailData) != ERROR_SUCCESS)
        {
            LOG(WINTUN_LOG_WARN, L"Failed getting driver info detail");
            continue;
        }
        if (!DriverIsOurDrvInfoDetail(DrvInfoDetailData))
        {
            HeapFree(Heap, 0, DrvInfoDetailData);
            continue;
        }
        HeapFree(Heap, 0, DrvInfoDetailData);

        if (!SetupDiSetSelectedDriverW(DevInfo, &DevInfoData, &DrvInfoData))
            continue;

        DriverDate = DrvInfoData.DriverDate;
        DriverVersion = DrvInfoData.DriverVersion;
    }

    if (!DriverVersion)
    {
        LOG(WINTUN_LOG_ERR, L"No appropriate drivers found");
        Result = ERROR_FILE_NOT_FOUND;
        goto cleanupDriverInfoList;
    }

    if (!SetupDiCallClassInstaller(DIF_REGISTERDEVICE, DevInfo, &DevInfoData))
    {
        Result = LOG_LAST_ERROR(L"Registering device failed");
        goto cleanupDevice;
    }
    if (!SetupDiCallClassInstaller(DIF_REGISTER_COINSTALLERS, DevInfo, &DevInfoData))
        LOG_LAST_ERROR(L"Registering coinstallers failed");

    HKEY NetDevRegKey = INVALID_HANDLE_VALUE;
    const int PollTimeout = 50 /* ms */;
    for (int i = 0; NetDevRegKey == INVALID_HANDLE_VALUE && i < WAIT_FOR_REGISTRY_TIMEOUT / PollTimeout; ++i)
    {
        if (i)
            Sleep(PollTimeout);
        NetDevRegKey = SetupDiOpenDevRegKey(
            DevInfo, &DevInfoData, DICS_FLAG_GLOBAL, 0, DIREG_DRV, KEY_SET_VALUE | KEY_QUERY_VALUE | KEY_NOTIFY);
    }
    if (NetDevRegKey == INVALID_HANDLE_VALUE)
    {
        Result = LOG_LAST_ERROR(L"Failed to open device-specific registry key");
        goto cleanupDevice;
    }
    if (RequestedGUID)
    {
        WCHAR RequestedGUIDStr[MAX_GUID_STRING_LEN];
        Result = RegSetValueExW(
            NetDevRegKey,
            L"NetSetupAnticipatedInstanceId",
            0,
            REG_SZ,
            (const BYTE *)RequestedGUIDStr,
            StringFromGUID2(RequestedGUID, RequestedGUIDStr, _countof(RequestedGUIDStr)) * sizeof(WCHAR));
        if (Result != ERROR_SUCCESS)
        {
            LOG_LAST_ERROR(L"Failed to set NetSetupAnticipatedInstanceId");
            goto cleanupNetDevRegKey;
        }
    }

    if (!SetupDiCallClassInstaller(DIF_INSTALLINTERFACES, DevInfo, &DevInfoData))
        LOG_LAST_ERROR(L"Installing interfaces failed");

    if (!SetupDiCallClassInstaller(DIF_INSTALLDEVICE, DevInfo, &DevInfoData))
    {
        Result = LOG_LAST_ERROR(L"Installing device failed");
        goto cleanupNetDevRegKey;
    }
    *RebootRequired = *RebootRequired || CheckReboot(DevInfo, &DevInfoData);

    if (!SetupDiSetDeviceRegistryPropertyW(
            DevInfo,
            &DevInfoData,
            SPDRP_DEVICEDESC,
            (const BYTE *)PoolDeviceTypeName,
            (DWORD)((wcslen(PoolDeviceTypeName) + 1) * sizeof(WCHAR))))
    {
        Result = LOG_LAST_ERROR(L"Failed to set device description");
        goto cleanupNetDevRegKey;
    }

    /* DIF_INSTALLDEVICE returns almost immediately, while the device installation continues in the background. It might
     * take a while, before all registry keys and values are populated. */
    WCHAR *DummyStr;
    Result = RegistryQueryStringWait(NetDevRegKey, L"NetCfgInstanceId", WAIT_FOR_REGISTRY_TIMEOUT, &DummyStr);
    if (Result != ERROR_SUCCESS)
    {
        LOG(WINTUN_LOG_ERR, L"Failed to query NetCfgInstanceId value");
        goto cleanupNetDevRegKey;
    }
    HeapFree(Heap, 0, DummyStr);
    DWORD DummyDWORD;
    Result = RegistryQueryDWORDWait(NetDevRegKey, L"NetLuidIndex", WAIT_FOR_REGISTRY_TIMEOUT, &DummyDWORD);
    if (Result != ERROR_SUCCESS)
    {
        LOG(WINTUN_LOG_ERR, L"Failed to query NetLuidIndex value");
        goto cleanupNetDevRegKey;
    }
    Result = RegistryQueryDWORDWait(NetDevRegKey, L"*IfType", WAIT_FOR_REGISTRY_TIMEOUT, &DummyDWORD);
    if (Result != ERROR_SUCCESS)
    {
        LOG(WINTUN_LOG_ERR, L"Failed to query *IfType value");
        goto cleanupNetDevRegKey;
    }

    Result = CreateAdapterData(Pool, DevInfo, &DevInfoData, Adapter);
    if (Result != ERROR_SUCCESS)
    {
        LOG(WINTUN_LOG_ERR, L"Failed to create adapter data");
        goto cleanupNetDevRegKey;
    }

    HKEY TcpipAdapterRegKey;
    WCHAR TcpipAdapterRegPath[MAX_REG_PATH];
    GetTcpipAdapterRegPath(*Adapter, TcpipAdapterRegPath);
    Result = RegistryOpenKeyWait(
        HKEY_LOCAL_MACHINE,
        TcpipAdapterRegPath,
        KEY_QUERY_VALUE | KEY_NOTIFY,
        WAIT_FOR_REGISTRY_TIMEOUT,
        &TcpipAdapterRegKey);
    if (Result != ERROR_SUCCESS)
    {
        LOG(WINTUN_LOG_ERR, L"Failed to open adapter-specific TCP/IP adapter registry key");
        goto cleanupAdapter;
    }
    Result = RegistryQueryStringWait(TcpipAdapterRegKey, L"IpConfig", WAIT_FOR_REGISTRY_TIMEOUT, &DummyStr);
    if (Result != ERROR_SUCCESS)
    {
        LOG(WINTUN_LOG_ERR, L"Failed to query IpConfig value");
        goto cleanupTcpipAdapterRegKey;
    }
    HeapFree(Heap, 0, DummyStr);

    HKEY TcpipInterfaceRegKey;
    WCHAR TcpipInterfaceRegPath[MAX_REG_PATH];
    Result = GetTcpipInterfaceRegPath(*Adapter, TcpipInterfaceRegPath);
    if (Result != ERROR_SUCCESS)
    {
        LOG(WINTUN_LOG_ERR, L"Failed to determine interface-specific TCP/IP network registry key path");
        goto cleanupTcpipAdapterRegKey;
    }
    Result = RegistryOpenKeyWait(
        HKEY_LOCAL_MACHINE,
        TcpipInterfaceRegPath,
        KEY_QUERY_VALUE | KEY_SET_VALUE,
        WAIT_FOR_REGISTRY_TIMEOUT,
        &TcpipInterfaceRegKey);
    if (Result != ERROR_SUCCESS)
    {
        LOG(WINTUN_LOG_ERR, L"Failed to open interface-specific TCP/IP network registry key");
        goto cleanupTcpipAdapterRegKey;
    }

    static const DWORD EnableDeadGWDetect = 0;
    Result = RegSetKeyValueW(
        TcpipInterfaceRegKey, NULL, L"EnableDeadGWDetect", REG_DWORD, &EnableDeadGWDetect, sizeof(EnableDeadGWDetect));
    if (Result != ERROR_SUCCESS)
        LOG_ERROR(L"Failed to set EnableDeadGWDetect", Result);

    Result = WintunSetAdapterName(*Adapter, Name);
    if (Result != ERROR_SUCCESS)
        LOG_ERROR(L"Failed to set adapter name", Result);
    RegCloseKey(TcpipInterfaceRegKey);
cleanupTcpipAdapterRegKey:
    RegCloseKey(TcpipAdapterRegKey);
cleanupAdapter:
    if (Result != ERROR_SUCCESS)
        HeapFree(Heap, 0, *Adapter);
cleanupNetDevRegKey:
    RegCloseKey(NetDevRegKey);
cleanupDevice:
    if (Result != ERROR_SUCCESS)
    {
        /* The adapter failed to install, or the adapter ID was unobtainable. Clean-up. */
        SP_REMOVEDEVICE_PARAMS RemoveDeviceParams = { .ClassInstallHeader = { .cbSize = sizeof(SP_CLASSINSTALL_HEADER),
                                                                              .InstallFunction = DIF_REMOVE },
                                                      .Scope = DI_REMOVEDEVICE_GLOBAL };
        if (SetupDiSetClassInstallParamsW(
                DevInfo, &DevInfoData, &RemoveDeviceParams.ClassInstallHeader, sizeof(RemoveDeviceParams)) &&
            SetupDiCallClassInstaller(DIF_REMOVE, DevInfo, &DevInfoData))
            *RebootRequired = *RebootRequired || CheckReboot(DevInfo, &DevInfoData);
    }
cleanupDriverInfoList:
    SetupDiDestroyDriverInfoList(DevInfo, &DevInfoData, SPDIT_COMPATDRIVER);
cleanupDevInfo:
    SetupDiDestroyDeviceInfoList(DevInfo);
cleanupMutex:
    NamespaceReleaseMutex(Mutex);
    return Result;
}

/**
 * Deletes a Wintun adapter.
 *
 * @param Adapter       Adapter handle obtained with WintunGetAdapter or WintunCreateAdapter.
 *
 * @param RebootRequired  Pointer to a boolean flag to be set to TRUE in case SetupAPI suggests a reboot. Must be
 *                      initialised to FALSE manually before this function is called.
 *
 * @return ERROR_SUCCESS on success or the adapter was not found; Win32 error code otherwise.
 */
WINTUN_STATUS WINAPI
WintunDeleteAdapter(_In_ const WINTUN_ADAPTER *Adapter, _Inout_ BOOL *RebootRequired)
{
    HDEVINFO DevInfo;
    SP_DEVINFO_DATA DevInfoData;
    DWORD Result = GetDevInfoData(&Adapter->CfgInstanceID, &DevInfo, &DevInfoData);
    if (Result == ERROR_FILE_NOT_FOUND)
        return ERROR_SUCCESS;
    if (Result != ERROR_SUCCESS)
    {
        LOG(WINTUN_LOG_ERR, L"Failed to get device info data");
        return Result;
    }
    SetQuietInstall(DevInfo, &DevInfoData);
    SP_REMOVEDEVICE_PARAMS RemoveDeviceParams = { .ClassInstallHeader = { .cbSize = sizeof(SP_CLASSINSTALL_HEADER),
                                                                          .InstallFunction = DIF_REMOVE },
                                                  .Scope = DI_REMOVEDEVICE_GLOBAL };
    if (SetupDiSetClassInstallParamsW(
            DevInfo, &DevInfoData, &RemoveDeviceParams.ClassInstallHeader, sizeof(RemoveDeviceParams)) &&
        SetupDiCallClassInstaller(DIF_REMOVE, DevInfo, &DevInfoData))
        *RebootRequired = *RebootRequired || CheckReboot(DevInfo, &DevInfoData);
    else
        Result = LOG_LAST_ERROR(L"Unable to remove existing adapter");
    SetupDiDestroyDeviceInfoList(DevInfo);
    return Result;
}

/**
 * Enumerates all Wintun adapters.
 *
 * @param Pool          Name of the adapter pool.
 *
 * @param Func          Callback function. To continue enumeration, the callback function must return TRUE; to stop
 *                      enumeration, it must return FALSE.
 *
 * @param Param         An application-defined value to be passed to the callback function.
 *
 * @return ERROR_SUCCESS on success; Win32 error code otherwise.
 */
WINTUN_STATUS WINAPI
WintunEnumAdapters(_In_z_count_c_(MAX_POOL) const WCHAR *Pool, _In_ WINTUN_ENUM_FUNC Func, _In_ LPARAM Param)
{
    HANDLE Mutex = NamespaceTakeMutex(Pool);
    if (!Mutex)
        return ERROR_INVALID_HANDLE;
    DWORD Result = ERROR_SUCCESS;
    HDEVINFO DevInfo = SetupDiGetClassDevsExW(&GUID_DEVCLASS_NET, NULL, NULL, DIGCF_PRESENT, NULL, NULL, NULL);
    if (DevInfo == INVALID_HANDLE_VALUE)
    {
        Result = LOG_LAST_ERROR(L"Failed to get present class devices");
        goto cleanupMutex;
    }
    HANDLE Heap = GetProcessHeap();
    BOOL Continue = TRUE;
    for (DWORD EnumIndex = 0; Continue; ++EnumIndex)
    {
        SP_DEVINFO_DATA DevInfoData = { .cbSize = sizeof(SP_DEVINFO_DATA) };
        if (!SetupDiEnumDeviceInfo(DevInfo, EnumIndex, &DevInfoData))
        {
            if (GetLastError() == ERROR_NO_MORE_ITEMS)
                break;
            continue;
        }

        BOOL IsOur;
        if (IsOurAdapter(DevInfo, &DevInfoData, &IsOur) != ERROR_SUCCESS || !IsOur)
            continue;

        BOOL IsMember;
        Result = IsPoolMember(Pool, DevInfo, &DevInfoData, &IsMember);
        if (Result != ERROR_SUCCESS)
        {
            LOG(WINTUN_LOG_ERR, L"Failed to determine pool membership");
            break;
        }
        if (!IsMember)
            continue;

        WINTUN_ADAPTER *Adapter;
        Result = CreateAdapterData(Pool, DevInfo, &DevInfoData, &Adapter);
        if (Result != ERROR_SUCCESS)
        {
            LOG(WINTUN_LOG_ERR, L"Failed to create adapter data");
            break;
        }
        Continue = Func(Adapter, Param);
        HeapFree(Heap, 0, Adapter);
    }
    SetupDiDestroyDeviceInfoList(DevInfo);
cleanupMutex:
    NamespaceReleaseMutex(Mutex);
    return Result;
}

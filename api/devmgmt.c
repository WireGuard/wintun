/* SPDX-License-Identifier: GPL-2.0
 *
 * Copyright (C) 2018-2020 WireGuard LLC. All Rights Reserved.
 */

#include "pch.h"

#define WINTUN_HWID L"Wintun"
#define WAIT_FOR_REGISTRY_TIMEOUT 10000     /* ms */
#define MAX_POOL_DEVICE_TYPE (MAX_POOL + 8) /* Should accommodate a pool name with " Tunnel" appended */

const static GUID CLASS_NET_GUID = { 0x4d36e972L, 0xe325, 0x11ce, { 0xbf, 0xc1, 0x08, 0x00, 0x2b, 0xe1, 0x03, 0x18 } };
const static GUID ADAPTER_NET_GUID = { 0xcac88484L,
                                       0x7515,
                                       0x4c03,
                                       { 0x82, 0xe6, 0x71, 0xa8, 0x7a, 0xba, 0xc3, 0x61 } };

/**
 * Retrieves a specified Plug and Play device property.
 *
 * @param DevInfo       A handle to the device information set that contains a device information element that
 *                      represents the device for which to open a registry key.
 *
 * @param DevInfoData   A pointer to a structure that specifies the device information element in DeviceInfoSet.
 *
 * @param Property      The property to be retrieved. One of the SPDRP_* constants.
 *
 * @param PropertyRegDataType  A pointer to a variable that receives the data type of the property that is being
 *                      retrieved. This is one of the standard registry data types. This parameter is optional
 *                      and can be NULL.
 *
 * @param PropertyBuffer  A pointer to a buffer that receives the property that is being retrieved. Must be
 *                      released with HeapFree(GetProcessHeap(), 0, Value) after use.
 *
 * @param PropertySize  A pointer to a variable of type DWORD that receives the property size, in bytes, of the
 *                      PropertyBuffer buffer. This parameter is optional and can be NULL.
 *
 * @return ERROR_SUCCESS on success; Win32 error code otherwise
 */
static WINTUN_STATUS
GetDeviceRegistryProperty(
    _In_ HDEVINFO DevInfo,
    _In_ SP_DEVINFO_DATA *DevInfoData,
    _In_ DWORD Property,
    _Out_opt_ DWORD *PropertyRegDataType,
    _Out_ void **PropertyBuffer,
    _Out_opt_ DWORD *PropertySize)
{
    HANDLE Heap = GetProcessHeap();
    DWORD Result, Size = 256;
    for (;;)
    {
        void *Buf = HeapAlloc(Heap, 0, Size);
        if (!Buf)
            return ERROR_OUTOFMEMORY;
        DWORD ValueType;
        if (!SetupDiGetDeviceRegistryPropertyW(DevInfo, DevInfoData, Property, &ValueType, Buf, Size, &Size))
        {
            Result = GetLastError();
            HeapFree(Heap, 0, Buf);
            if (Result == ERROR_INSUFFICIENT_BUFFER)
                continue;
            return Result;
        }

        if (PropertyRegDataType)
            *PropertyRegDataType = ValueType;
        *PropertyBuffer = Buf;
        if (PropertySize)
            *PropertySize = Size;
        return ERROR_SUCCESS;
    }
}

/**
 * Retrieves a specified Plug and Play device property string.
 *
 * @param DevInfo       A handle to the device information set that contains a device information element that
 *                      represents the device for which to open a registry key.
 *
 * @param DevInfoData   A pointer to a structure that specifies the device information element in DeviceInfoSet.
 *
 * @param Property      The property to be retrieved. One of the SPDRP_* constants.
 *
 * @param PropertyBuffer  A pointer to a string that receives the string that is being retrieved. Must be
 *                      released with HeapFree(GetProcessHeap(), 0, Value) after use.
 *
 * @return ERROR_SUCCESS on success; Win32 error code otherwise
 */
static WINTUN_STATUS
GetDeviceRegistryString(
    _In_ HDEVINFO DevInfo,
    _In_ SP_DEVINFO_DATA *DevInfoData,
    _In_ DWORD Property,
    _Out_ WCHAR **PropertyBuffer)
{
    DWORD Result, ValueType, Size;
    Result = GetDeviceRegistryProperty(DevInfo, DevInfoData, Property, &ValueType, PropertyBuffer, &Size);
    if (Result != ERROR_SUCCESS)
        return Result;

    switch (ValueType)
    {
    case REG_SZ:
    case REG_EXPAND_SZ:
    case REG_MULTI_SZ:
        Result = RegistryGetString(PropertyBuffer, Size / sizeof(WCHAR), ValueType);
        if (Result != ERROR_SUCCESS)
            HeapFree(GetProcessHeap(), 0, *PropertyBuffer);
        return Result;
    default:
        HeapFree(GetProcessHeap(), 0, *PropertyBuffer);
        return ERROR_INVALID_DATATYPE;
    }
}

/**
 * Retrieves a specified Plug and Play device property multi-string.
 *
 * @param DevInfo       A handle to the device information set that contains a device information element that
 *                      represents the device for which to open a registry key.
 *
 * @param DevInfoData   A pointer to a structure that specifies the device information element in DeviceInfoSet.
 *
 * @param Property      The property to be retrieved. One of the SPDRP_* constants.
 *
 * @param PropertyBuffer  A pointer to a multi-string that receives the string that is being retrieved. Must be
 *                      released with HeapFree(GetProcessHeap(), 0, Value) after use.
 *
 * @return ERROR_SUCCESS on success; Win32 error code otherwise
 */
static WINTUN_STATUS
GetDeviceRegistryMultiString(
    _In_ HDEVINFO DevInfo,
    _In_ SP_DEVINFO_DATA *DevInfoData,
    _In_ DWORD Property,
    _Out_ WCHAR **PropertyBuffer)
{
    DWORD Result, ValueType, Size;
    Result = GetDeviceRegistryProperty(DevInfo, DevInfoData, Property, &ValueType, PropertyBuffer, &Size);
    if (Result != ERROR_SUCCESS)
        return Result;

    switch (ValueType)
    {
    case REG_SZ:
    case REG_EXPAND_SZ:
    case REG_MULTI_SZ:
        Result = RegistryGetMultiString(PropertyBuffer, Size / sizeof(WCHAR), ValueType);
        if (Result != ERROR_SUCCESS)
            HeapFree(GetProcessHeap(), 0, *PropertyBuffer);
        return Result;
    default:
        HeapFree(GetProcessHeap(), 0, *PropertyBuffer);
        return ERROR_INVALID_DATATYPE;
    }
}

/**
 * Retrieves driver information detail for a device information set or a particular device information element in the
 * device information set.
 *
 * @param DevInfo       A handle to the device information set that contains a device information element that
 *                      represents the device for which to open a registry key.
 *
 * @param DevInfoData   A pointer to a structure that specifies the device information element in DeviceInfoSet.
 *
 * @param DriverData    A pointer to a structure that specifies the driver information element that represents the
 *                      driver for which to retrieve details.
 *
 * @param DriverDetailData  A pointer to a structure that receives detailed information about the specified driver.
 *                      Must be released with HeapFree(GetProcessHeap(), 0, Value) after use.
 *
 * @return ERROR_SUCCESS on success; Win32 error code otherwise
 */
static WINTUN_STATUS
GetDriverInfoDetail(
    _In_ HDEVINFO DevInfo,
    _In_ SP_DEVINFO_DATA *DevInfoData,
    _In_ SP_DRVINFO_DATA_W *DriverData,
    _Out_ SP_DRVINFO_DETAIL_DATA_W **DriverDetailData)
{
    HANDLE Heap = GetProcessHeap();
    DWORD Size = sizeof(SP_DRVINFO_DETAIL_DATA_W) + 0x100;
    for (;;)
    {
        *DriverDetailData = HeapAlloc(Heap, 0, Size);
        if (!*DriverDetailData)
            return ERROR_OUTOFMEMORY;
        (*DriverDetailData)->cbSize = sizeof(SP_DRVINFO_DETAIL_DATA_W);
        if (!SetupDiGetDriverInfoDetailW(DevInfo, DevInfoData, DriverData, *DriverDetailData, Size, &Size))
        {
            DWORD Result = GetLastError();
            HeapFree(Heap, 0, *DriverDetailData);
            if (Result == ERROR_INSUFFICIENT_BUFFER)
                continue;
            return Result;
        }
        return ERROR_SUCCESS;
    }
}

/**
 * Tests if any of the hardware IDs match ours.
 *
 * @param Hwids         Multi-string containing a list of hardware IDs
 *
 * @return TRUE on match; FALSE otherwise.
 */
static BOOL
IsOurHardwareID(_In_z_ WCHAR *Hwids)
{
    for (; Hwids[0]; Hwids += wcslen(Hwids) + 1)
        if (!_wcsicmp(Hwids, WINTUN_HWID))
            return TRUE;
    return FALSE;
}

/**
 * Check if the device is using Wintun driver.
 */
static WINTUN_STATUS
IsUsingOurDriver(_In_ HDEVINFO DevInfo, _In_ SP_DEVINFO_DATA *DevInfoData, _Out_ BOOL *IsOurDriver)
{
    if (!SetupDiBuildDriverInfoList(DevInfo, DevInfoData, SPDIT_COMPATDRIVER))
        return GetLastError();
    *IsOurDriver = FALSE;
    HANDLE Heap = GetProcessHeap();
    for (DWORD DriverIndex = 0;; ++DriverIndex)
    {
        SP_DRVINFO_DATA_W DriverData = { .cbSize = sizeof(SP_DRVINFO_DATA_W) };
        if (!SetupDiEnumDriverInfoW(DevInfo, DevInfoData, SPDIT_COMPATDRIVER, DriverIndex, &DriverData))
        {
            if (GetLastError() == ERROR_NO_MORE_ITEMS)
                break;
            continue;
        }
        SP_DRVINFO_DETAIL_DATA_W *DriverDetailData;
        if (GetDriverInfoDetail(DevInfo, DevInfoData, &DriverData, &DriverDetailData) != ERROR_SUCCESS)
            continue;
        if (DriverDetailData->CompatIDsOffset > 1 && !_wcsicmp(DriverDetailData->HardwareID, WINTUN_HWID) ||
            DriverDetailData->CompatIDsLength &&
                IsOurHardwareID(DriverDetailData->HardwareID + DriverDetailData->CompatIDsOffset))
        {
            HeapFree(Heap, 0, DriverDetailData);
            *IsOurDriver = TRUE;
            break;
        }
        HeapFree(Heap, 0, DriverDetailData);
    }
    SetupDiDestroyDriverInfoList(DevInfo, DevInfoData, SPDIT_COMPATDRIVER);
    return ERROR_SUCCESS;
}

/**
 * Checks device install parameters if a system reboot is required.
 */
static BOOL
CheckReboot(_In_ HDEVINFO DevInfo, _In_ SP_DEVINFO_DATA *DevInfoData)
{
    SP_DEVINSTALL_PARAMS_W DevInstallParams = { .cbSize = sizeof(SP_DEVINSTALL_PARAMS_W) };
    if (!SetupDiGetDeviceInstallParamsW(DevInfo, DevInfoData, &DevInstallParams))
        return FALSE;
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
        return GetLastError();
    DevInstallParams.Flags |= DI_QUIETINSTALL;
    if (!SetupDiSetDeviceInstallParamsW(DevInfo, DevInfoData, &DevInstallParams))
        return GetLastError();
    return ERROR_SUCCESS;
}

/**
 * Returns adapter GUID associated with device.
 *
 * @param DevInfo       A handle to the device information set that contains a device information element that
 *                      represents the device for which to open a registry key.
 *
 * @param DevInfoData   A pointer to a structure that specifies the device information element in DeviceInfoSet.
 *
 * @param CfgInstanceID  Pointer to a GUID to receive the adapter GUID.
 *
 * @return ERROR_SUCCESS on success; Win32 error code otherwise
 */
static WINTUN_STATUS
GetNetCfgInstanceId(_In_ HDEVINFO DevInfo, _In_ SP_DEVINFO_DATA *DevInfoData, _Out_ GUID *CfgInstanceID)
{
    HKEY Key = SetupDiOpenDevRegKey(DevInfo, DevInfoData, DICS_FLAG_GLOBAL, 0, DIREG_DRV, KEY_QUERY_VALUE);
    if (Key == INVALID_HANDLE_VALUE)
        return GetLastError();
    WCHAR *ValueStr;
    DWORD Result = RegistryQueryString(Key, L"NetCfgInstanceId", &ValueStr);
    if (Result != ERROR_SUCCESS)
        goto cleanupKey;
    Result = SUCCEEDED(CLSIDFromString(ValueStr, CfgInstanceID)) ? ERROR_SUCCESS : ERROR_INVALID_DATA;
    HeapFree(GetProcessHeap(), 0, ValueStr);
cleanupKey:
    RegCloseKey(Key);
    return Result;
}

/**
 * Returns device info list handle and adapter device info data.
 *
 * @param CfgInstanceID  The adapter GUID
 *
 * @param DevInfo       A pointer to receive the handle of the device information set that contains a device information
 *                      element that represents the device. Must be released with SetupDiDestroyDeviceInfoList(*DevInfo)
 *                      after use.
 *
 * @param DevInfoData   A pointer to a structure that receives specification of the device information element in
 *                      DeviceInfoSet.
 *
 * @return ERROR_SUCCESS on success; ERROR_FILE_NOT_FOUND if the device is not found; Win32 error code otherwise
 */
static WINTUN_STATUS
GetDevInfoData(_In_ const GUID *CfgInstanceID, _Out_ HDEVINFO *DevInfo, _Out_ SP_DEVINFO_DATA *DevInfoData)
{
    DWORD Result;
    *DevInfo = SetupDiGetClassDevsExW(&CLASS_NET_GUID, NULL, NULL, DIGCF_PRESENT, NULL, NULL, NULL);
    if (!*DevInfo)
        return GetLastError();
    for (DWORD MemberIndex = 0;; ++MemberIndex)
    {
        DevInfoData->cbSize = sizeof(SP_DEVINFO_DATA);
        if (!SetupDiEnumDeviceInfo(*DevInfo, MemberIndex, DevInfoData))
        {
            Result = GetLastError();
            if (Result == ERROR_NO_MORE_ITEMS)
                break;
            continue;
        }

        GUID CfgInstanceID2;
        Result = GetNetCfgInstanceId(*DevInfo, DevInfoData, &CfgInstanceID2);
        if (Result != ERROR_SUCCESS || memcmp(CfgInstanceID, &CfgInstanceID2, sizeof(GUID)) != 0)
            continue;

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
    if (Len && Name[Len - 1] < L'0' || Name[Len - 1] > L'9')
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
        return Result;
    Result = GetDeviceRegistryString(DevInfo, DevInfoData, SPDRP_FRIENDLYNAME, &FriendlyName);
    if (Result != ERROR_SUCCESS)
        goto cleanupDeviceDesc;
    WCHAR PoolDeviceTypeName[MAX_POOL_DEVICE_TYPE];
    GetPoolDeviceTypeName(Pool, PoolDeviceTypeName);
    if (!_wcsicmp(FriendlyName, PoolDeviceTypeName) || !_wcsicmp(DeviceDesc, PoolDeviceTypeName))
    {
        *IsMember = TRUE;
        goto cleanupFriendlyName;
    }
    RemoveNumberedSuffix(FriendlyName, FriendlyName);
    RemoveNumberedSuffix(DeviceDesc, DeviceDesc);
    if (!_wcsicmp(FriendlyName, PoolDeviceTypeName) || !_wcsicmp(DeviceDesc, PoolDeviceTypeName))
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
 * @param DevInfoData   A pointer to a structure that specifies the device information element in DeviceInfoSet.
 *
 * @param Pool          Name of the adapter pool
 *
 * @param Adapter       Pointer to a handle to receive the adapter descriptor. Must be released with
 *                      HeapFree(GetProcessHeap(), 0, *Adapter).
 *
 * @return ERROR_SUCCESS on success; Win32 error code otherwise
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
        return GetLastError();

    HANDLE Heap = GetProcessHeap();
    *Adapter = HeapAlloc(Heap, 0, sizeof(WINTUN_ADAPTER));
    if (!*Adapter)
    {
        Result = ERROR_OUTOFMEMORY;
        goto cleanupKey;
    }

    /* Read the NetCfgInstanceId value and convert to GUID. */
    WCHAR *ValueStr;
    Result = RegistryQueryString(Key, L"NetCfgInstanceId", &ValueStr);
    if (Result != ERROR_SUCCESS)
        goto cleanupAdapter;
    if (FAILED(CLSIDFromString(ValueStr, &(*Adapter)->CfgInstanceID)))
    {
        HeapFree(GetProcessHeap(), 0, ValueStr);
        Result = ERROR_INVALID_DATA;
        goto cleanupAdapter;
    }
    HeapFree(GetProcessHeap(), 0, ValueStr);

    /* Read the NetLuidIndex value. */
    Result = RegistryQueryDWORD(Key, L"NetLuidIndex", &(*Adapter)->LuidIndex);
    if (Result != ERROR_SUCCESS)
        goto cleanupAdapter;

    /* Read the NetLuidIndex value. */
    Result = RegistryQueryDWORD(Key, L"*IfType", &(*Adapter)->IfType);
    if (Result != ERROR_SUCCESS)
        goto cleanupAdapter;

    DWORD Size;
    if (!SetupDiGetDeviceInstanceIdW(
            DevInfo, DevInfoData, (*Adapter)->DevInstanceID, _countof((*Adapter)->DevInstanceID), &Size))
    {
        Result = GetLastError();
        goto cleanupAdapter;
    }

    wcscpy_s((*Adapter)->Pool, _countof((*Adapter)->Pool), Pool);
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
        return Result;
    WCHAR *Paths;
    Result = RegistryQueryString(TcpipAdapterRegKey, L"IpConfig", &Paths);
    if (Result != ERROR_SUCCESS)
        goto cleanupTcpipAdapterRegKey;
    if (!Paths[0])
    {
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
 * @param Adapter       Adapter handle obtained with WintunGetAdapter or WintunCreateAdapter
 */
void WINAPI
WintunFreeAdapter(_In_ WINTUN_ADAPTER *Adapter)
{
    HeapFree(GetProcessHeap(), 0, Adapter);
}

/**
 * Finds a Wintun adapter by its name.
 *
 * @param Pool          Name of the adapter pool
 *
 * @param Name          Adapter name
 *
 * @param Adapter       Pointer to a handle to receive the adapter handle. Must be released with
 *                      WintunFreeAdapter.
 *
 * @return ERROR_SUCCESS on success; Win32 error code otherwise;
 * ERROR_FILE_NOT_FOUND if adapter with given name is not found;
 * ERROR_ALREADY_EXISTS if adapter is found but not a Wintun-class or not a member of the pool
 */
WINTUN_STATUS WINAPI
WintunGetAdapter(_In_z_count_c_(MAX_POOL) const WCHAR *Pool, _In_z_ const WCHAR *Name, _Out_ WINTUN_ADAPTER **Adapter)
{
    DWORD Result;
    HANDLE Mutex = TakeNameMutex(Pool);
    if (!Mutex)
        return ERROR_INVALID_HANDLE;

    HDEVINFO DevInfo = SetupDiGetClassDevsExW(&CLASS_NET_GUID, NULL, NULL, DIGCF_PRESENT, NULL, NULL, NULL);
    if (DevInfo == INVALID_HANDLE_VALUE)
    {
        Result = GetLastError();
        goto cleanupMutex;
    }

    HANDLE Heap = GetProcessHeap();
    for (DWORD MemberIndex = 0;; ++MemberIndex)
    {
        SP_DEVINFO_DATA DevInfoData = { .cbSize = sizeof(SP_DEVINFO_DATA) };
        if (!SetupDiEnumDeviceInfo(DevInfo, MemberIndex, &DevInfoData))
        {
            if (GetLastError() == ERROR_NO_MORE_ITEMS)
                break;
            continue;
        }

        GUID CfgInstanceID;
        Result = GetNetCfgInstanceId(DevInfo, &DevInfoData, &CfgInstanceID);
        if (Result != ERROR_SUCCESS)
            continue;

        /* TODO: is there a better way than comparing ifnames? */
        WCHAR Name2[MAX_ADAPTER_NAME], Name3[MAX_ADAPTER_NAME];
        if (NciGetConnectionName(&CfgInstanceID, Name2, sizeof(Name2), NULL) != ERROR_SUCCESS)
            continue;
        Name2[_countof(Name2) - 1] = 0;
        RemoveNumberedSuffix(Name2, Name3);
        if (_wcsicmp(Name, Name2) && _wcsicmp(Name, Name3))
            continue;

        /* Check the Hardware ID to make sure it's a real Wintun device. This avoids doing slow operations on non-Wintun
         * devices. */
        WCHAR *Hwids;
        Result = GetDeviceRegistryMultiString(DevInfo, &DevInfoData, SPDRP_HARDWAREID, &Hwids);
        if (Result != ERROR_SUCCESS)
            goto cleanupDevInfo;
        if (!IsOurHardwareID(Hwids))
        {
            HeapFree(Heap, 0, Hwids);
            Result = ERROR_ALREADY_EXISTS;
            goto cleanupDevInfo;
        }
        HeapFree(Heap, 0, Hwids);

        BOOL IsOurDriver;
        Result = IsUsingOurDriver(DevInfo, &DevInfoData, &IsOurDriver);
        if (Result != ERROR_SUCCESS)
            goto cleanupDevInfo;
        if (!IsOurDriver)
        {
            Result = ERROR_ALREADY_EXISTS;
            goto cleanupDevInfo;
        }

        BOOL IsMember;
        Result = IsPoolMember(Pool, DevInfo, &DevInfoData, &IsMember);
        if (Result != ERROR_SUCCESS)
            goto cleanupDevInfo;
        if (!IsMember)
        {
            Result = ERROR_ALREADY_EXISTS;
            goto cleanupDevInfo;
        }

        Result = CreateAdapterData(Pool, DevInfo, &DevInfoData, Adapter);
        goto cleanupDevInfo;
    }
    Result = ERROR_FILE_NOT_FOUND;
cleanupDevInfo:
    SetupDiDestroyDeviceInfoList(DevInfo);
cleanupMutex:
    ReleaseNameMutex(Mutex);
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
        return Result;
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
    wcscpy_s(AvailableName, _countof(AvailableName), Name);
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
            return Result;
        _snwprintf_s(AvailableName, _countof(AvailableName), _TRUNCATE, L"%.*s %d", MAX_ADAPTER_NAME, Name, i + 1);
    }

    /* TODO: This should use NetSetup2 so that it doesn't get unset. */
    HKEY DeviceRegKey;
    WCHAR DeviceRegPath[MAX_REG_PATH];
    GetDeviceRegPath(Adapter, DeviceRegPath);
    Result = RegOpenKeyExW(HKEY_LOCAL_MACHINE, DeviceRegPath, 0, KEY_SET_VALUE, &DeviceRegKey);
    if (Result != ERROR_SUCCESS)
        return Result;
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
    memcpy_s(Guid, sizeof(*Guid), &Adapter->CfgInstanceID, sizeof(Adapter->CfgInstanceID));
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
 * @param Adapter       Adapter handle obtained with WintunGetAdapter or WintunCreateAdapter
 *
 * @param Handle        Pointer to receive the adapter device object handle. Must be released with CloseHandle.
 *
 * @return ERROR_SUCCESS on success; Win32 error code otherwise
 */
WINTUN_STATUS WINAPI
WintunGetAdapterDeviceObject(_In_ const WINTUN_ADAPTER *Adapter, _Out_ HANDLE *Handle)
{
    HANDLE Heap = GetProcessHeap();
    ULONG InterfacesLen;
    DWORD Result = CM_Get_Device_Interface_List_SizeW(
        &InterfacesLen,
        (GUID *)&ADAPTER_NET_GUID,
        (DEVINSTID_W)Adapter->DevInstanceID,
        CM_GET_DEVICE_INTERFACE_LIST_PRESENT);
    if (Result != CR_SUCCESS)
        return Result;
    WCHAR *Interfaces = HeapAlloc(Heap, 0, InterfacesLen * sizeof(WCHAR));
    if (!Interfaces)
        return ERROR_OUTOFMEMORY;
    Result = CM_Get_Device_Interface_ListW(
        (GUID *)&ADAPTER_NET_GUID,
        (DEVINSTID_W)Adapter->DevInstanceID,
        Interfaces,
        InterfacesLen,
        CM_GET_DEVICE_INTERFACE_LIST_PRESENT);
    if (Result != CR_SUCCESS)
        goto cleanupBuf;
    *Handle = CreateFileW(
        Interfaces,
        GENERIC_READ | GENERIC_WRITE,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        NULL,
        OPEN_EXISTING,
        0,
        NULL);
    if (*Handle == INVALID_HANDLE_VALUE)
        Result = GetLastError();
cleanupBuf:
    HeapFree(Heap, 0, Interfaces);
    return Result;
}

/**
 * @return TRUE if DriverData date and version is newer than supplied parameters.
 */
static BOOL
IsNewer(_In_ const SP_DRVINFO_DATA_W *DriverData, _In_ const FILETIME *DriverDate, _In_ DWORDLONG DriverVersion)
{
    if (DriverData->DriverDate.dwHighDateTime > DriverDate->dwHighDateTime)
        return TRUE;
    if (DriverData->DriverDate.dwHighDateTime < DriverDate->dwHighDateTime)
        return FALSE;

    if (DriverData->DriverDate.dwLowDateTime > DriverDate->dwLowDateTime)
        return TRUE;
    if (DriverData->DriverDate.dwLowDateTime < DriverDate->dwLowDateTime)
        return FALSE;

    if (DriverData->DriverVersion > DriverVersion)
        return TRUE;
    if (DriverData->DriverVersion < DriverVersion)
        return FALSE;

    return FALSE;
}

/**
 * Creates a Wintun adapter.
 *
 * @param Pool          Name of the adapter pool
 *
 * @param Name          The requested name of the adapter
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
 * @return ERROR_SUCCESS on success; Win32 error code otherwise
 */
WINTUN_STATUS WINAPI
WintunCreateAdapter(
    _In_z_count_c_(MAX_POOL) const WCHAR *Pool,
    _In_z_ const WCHAR *Name,
    _In_opt_ const GUID *RequestedGUID,
    _Out_ WINTUN_ADAPTER **Adapter,
    _Inout_ BOOL *RebootRequired)
{
    DWORD Result;
    HANDLE Mutex = TakeNameMutex(Pool);
    if (!Mutex)
        return ERROR_INVALID_HANDLE;

    HDEVINFO DevInfo = SetupDiCreateDeviceInfoListExW(&CLASS_NET_GUID, NULL, NULL, NULL);
    if (DevInfo == INVALID_HANDLE_VALUE)
    {
        Result = GetLastError();
        goto cleanupMutex;
    }

    WCHAR ClassName[MAX_CLASS_NAME_LEN];
    if (!SetupDiClassNameFromGuidExW(&CLASS_NET_GUID, ClassName, _countof(ClassName), NULL, NULL, NULL))
    {
        Result = GetLastError();
        goto cleanupDevInfo;
    }

    HANDLE Heap = GetProcessHeap();
    WCHAR PoolDeviceTypeName[MAX_POOL_DEVICE_TYPE];
    GetPoolDeviceTypeName(Pool, PoolDeviceTypeName);
    SP_DEVINFO_DATA DevInfoData = { .cbSize = sizeof(SP_DEVINFO_DATA) };
    if (!SetupDiCreateDeviceInfoW(
            DevInfo, ClassName, &CLASS_NET_GUID, PoolDeviceTypeName, NULL, DICD_GENERATE_ID, &DevInfoData))
    {
        Result = GetLastError();
        goto cleanupDevInfo;
    }
    Result = SetQuietInstall(DevInfo, &DevInfoData);
    if (Result != ERROR_SUCCESS)
        goto cleanupDevInfo;

    if (!SetupDiSetSelectedDevice(DevInfo, &DevInfoData))
    {
        Result = GetLastError();
        goto cleanupDevInfo;
    }

    static const WCHAR Hwids[_countof(WINTUN_HWID) + 1 /*Multi-string terminator*/] = WINTUN_HWID;
    if (!SetupDiSetDeviceRegistryPropertyW(DevInfo, &DevInfoData, SPDRP_HARDWAREID, (const BYTE *)Hwids, sizeof(Hwids)))
    {
        Result = GetLastError();
        goto cleanupDevInfo;
    }
    if (!SetupDiBuildDriverInfoList(DevInfo, &DevInfoData, SPDIT_COMPATDRIVER)) /* TODO: This takes ~510ms */
    {
        Result = GetLastError();
        goto cleanupDevInfo;
    }

    FILETIME DriverDate = { 0, 0 };
    DWORDLONG DriverVersion = 0;
    for (DWORD DriverIndex = 0;; ++DriverIndex) /* TODO: This loop takes ~600ms */
    {
        SP_DRVINFO_DATA_W DriverData = { .cbSize = sizeof(SP_DRVINFO_DATA_W) };
        if (!SetupDiEnumDriverInfoW(DevInfo, &DevInfoData, SPDIT_COMPATDRIVER, DriverIndex, &DriverData))
        {
            if (GetLastError() == ERROR_NO_MORE_ITEMS)
                break;
            continue;
        }

        /* Check the driver version first, since the check is trivial and will save us iterating over hardware IDs for
         * any driver versioned prior our best match. */
        if (!IsNewer(&DriverData, &DriverDate, DriverVersion))
            continue;

        SP_DRVINFO_DETAIL_DATA_W *DriverDetailData;
        if (GetDriverInfoDetail(DevInfo, &DevInfoData, &DriverData, &DriverDetailData) != ERROR_SUCCESS)
            continue;
        if ((DriverDetailData->CompatIDsOffset <= 1 || _wcsicmp(DriverDetailData->HardwareID, WINTUN_HWID)) &&
            (!DriverDetailData->CompatIDsLength ||
             !IsOurHardwareID(DriverDetailData->HardwareID + DriverDetailData->CompatIDsOffset)))
        {
            HeapFree(Heap, 0, DriverDetailData);
            continue;
        }
        HeapFree(Heap, 0, DriverDetailData);

        if (!SetupDiSetSelectedDriverW(DevInfo, &DevInfoData, &DriverData))
            continue;

        DriverDate = DriverData.DriverDate;
        DriverVersion = DriverData.DriverVersion;
    }

    if (!DriverVersion)
    {
        Result = ERROR_FILE_NOT_FOUND;
        goto cleanupDriverInfoList;
    }

    if (!SetupDiCallClassInstaller(DIF_REGISTERDEVICE, DevInfo, &DevInfoData))
    {
        Result = GetLastError();
        goto cleanupDevice;
    }
    SetupDiCallClassInstaller(DIF_REGISTER_COINSTALLERS, DevInfo, &DevInfoData); /* Ignore errors */

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
        Result = GetLastError();
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
            goto cleanupNetDevRegKey;
    }

    SetupDiCallClassInstaller(DIF_INSTALLINTERFACES, DevInfo, &DevInfoData); /* Ignore errors */

    if (!SetupDiCallClassInstaller(DIF_INSTALLDEVICE, DevInfo, &DevInfoData))
    {
        Result = GetLastError();
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
        Result = GetLastError();
        goto cleanupNetDevRegKey;
    }

    /* DIF_INSTALLDEVICE returns almost immediately, while the device installation continues in the background. It might
     * take a while, before all registry keys and values are populated. */
    WCHAR *DummyStr;
    Result = RegistryQueryStringWait(NetDevRegKey, L"NetCfgInstanceId", WAIT_FOR_REGISTRY_TIMEOUT, &DummyStr);
    if (Result != ERROR_SUCCESS)
        goto cleanupNetDevRegKey;
    HeapFree(Heap, 0, DummyStr);
    DWORD DummyDWORD;
    Result = RegistryQueryDWORDWait(NetDevRegKey, L"NetLuidIndex", WAIT_FOR_REGISTRY_TIMEOUT, &DummyDWORD);
    if (Result != ERROR_SUCCESS)
        goto cleanupNetDevRegKey;
    Result = RegistryQueryDWORDWait(NetDevRegKey, L"*IfType", WAIT_FOR_REGISTRY_TIMEOUT, &DummyDWORD);
    if (Result != ERROR_SUCCESS)
        goto cleanupNetDevRegKey;

    Result = CreateAdapterData(Pool, DevInfo, &DevInfoData, Adapter);
    if (Result != ERROR_SUCCESS)
        goto cleanupNetDevRegKey;

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
        goto cleanupAdapter;
    Result = RegistryQueryStringWait(TcpipAdapterRegKey, L"IpConfig", WAIT_FOR_REGISTRY_TIMEOUT, &DummyStr);
    if (Result != ERROR_SUCCESS)
        goto cleanupTcpipAdapterRegKey;
    HeapFree(Heap, 0, DummyStr);

    HKEY TcpipInterfaceRegKey;
    WCHAR TcpipInterfaceRegPath[MAX_REG_PATH];
    Result = GetTcpipInterfaceRegPath(*Adapter, TcpipInterfaceRegPath);
    if (Result != ERROR_SUCCESS)
        goto cleanupTcpipAdapterRegKey;
    Result = RegistryOpenKeyWait(
        HKEY_LOCAL_MACHINE,
        TcpipInterfaceRegPath,
        KEY_QUERY_VALUE | KEY_SET_VALUE,
        WAIT_FOR_REGISTRY_TIMEOUT,
        &TcpipInterfaceRegKey);
    if (Result != ERROR_SUCCESS)
        goto cleanupTcpipAdapterRegKey;

    const static DWORD EnableDeadGWDetect = 0;
    RegSetKeyValueW(
        TcpipInterfaceRegKey,
        NULL,
        L"EnableDeadGWDetect",
        REG_DWORD,
        &EnableDeadGWDetect,
        sizeof(EnableDeadGWDetect)); /* Ignore errors */

    Result = WintunSetAdapterName(*Adapter, Name);
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
    ReleaseNameMutex(Mutex);
    return Result;
}

/**
 * Deletes a Wintun adapter.
 *
 * @param Adapter       Adapter handle obtained with WintunGetAdapter or WintunCreateAdapter
 *
 * @param RebootRequired  Pointer to a boolean flag to be set to TRUE in case SetupAPI suggests a reboot. Must be
 *                      initialised to FALSE manually before this function is called.
 *
 * @return ERROR_SUCCESS on success; Win32 error code otherwise. This function succeeds if the adapter was not found.
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
        return Result;
    Result = SetQuietInstall(DevInfo, &DevInfoData);
    if (Result != ERROR_SUCCESS)
        goto cleanupDevInfo;
    SP_REMOVEDEVICE_PARAMS RemoveDeviceParams = { .ClassInstallHeader = { .cbSize = sizeof(SP_CLASSINSTALL_HEADER),
                                                                          .InstallFunction = DIF_REMOVE },
                                                  .Scope = DI_REMOVEDEVICE_GLOBAL };
    if (SetupDiSetClassInstallParamsW(
            DevInfo, &DevInfoData, &RemoveDeviceParams.ClassInstallHeader, sizeof(RemoveDeviceParams)) &&
        SetupDiCallClassInstaller(DIF_REMOVE, DevInfo, &DevInfoData))
        *RebootRequired = *RebootRequired || CheckReboot(DevInfo, &DevInfoData);
    else
        Result = GetLastError();
cleanupDevInfo:
    SetupDiDestroyDeviceInfoList(DevInfo);
    return Result;
}

/**
 * Enumerates all Wintun adapters.
 *
 * @param Pool          Name of the adapter pool
 *
 * @param Func          Callback function. To continue enumeration, the callback function must return TRUE; to stop
 *                      enumeration, it must return FALSE.
 *
 * @param Param         An application-defined value to be passed to the callback function
 *
 * @return ERROR_SUCCESS on success; Win32 error code otherwise
 */
WINTUN_STATUS WINAPI
WintunEnumAdapters(_In_z_count_c_(MAX_POOL) const WCHAR *Pool, _In_ WINTUN_ENUMPROC Func, _In_ LPARAM Param)
{
    DWORD Result;
    HANDLE Mutex = TakeNameMutex(Pool);
    if (!Mutex)
        return ERROR_INVALID_HANDLE;
    HDEVINFO DevInfo = SetupDiGetClassDevsExW(&CLASS_NET_GUID, NULL, NULL, DIGCF_PRESENT, NULL, NULL, NULL);
    if (DevInfo == INVALID_HANDLE_VALUE)
    {
        Result = GetLastError();
        goto cleanupMutex;
    }
    HANDLE Heap = GetProcessHeap();
    for (DWORD MemberIndex = 0;; ++MemberIndex)
    {
        SP_DEVINFO_DATA DevInfoData = { .cbSize = sizeof(SP_DEVINFO_DATA) };
        if (!SetupDiEnumDeviceInfo(DevInfo, MemberIndex, &DevInfoData))
        {
            if (GetLastError() == ERROR_NO_MORE_ITEMS)
            {
                Result = ERROR_SUCCESS;
                break;
            }
            continue;
        }

        /* Check the Hardware ID to make sure it's a real Wintun device. This avoids doing slow operations on non-Wintun
         * devices. */
        WCHAR *Hwids;
        Result = GetDeviceRegistryMultiString(DevInfo, &DevInfoData, SPDRP_HARDWAREID, &Hwids);
        if (Result != ERROR_SUCCESS)
            break;
        if (!IsOurHardwareID(Hwids))
        {
            HeapFree(Heap, 0, Hwids);
            continue;
        }
        HeapFree(Heap, 0, Hwids);

        BOOL IsOurDriver;
        Result = IsUsingOurDriver(DevInfo, &DevInfoData, &IsOurDriver);
        if (Result != ERROR_SUCCESS)
            break;
        if (!IsOurDriver)
            continue;

        BOOL IsMember;
        Result = IsPoolMember(Pool, DevInfo, &DevInfoData, &IsMember);
        if (Result != ERROR_SUCCESS)
            break;
        if (!IsMember)
            continue;

        WINTUN_ADAPTER *Adapter;
        Result = CreateAdapterData(Pool, DevInfo, &DevInfoData, &Adapter);
        if (Result != ERROR_SUCCESS)
            break;
        if (Func(Adapter, Param))
            HeapFree(Heap, 0, Adapter);
        else
        {
            HeapFree(Heap, 0, Adapter);
            break;
        }
    }
    SetupDiDestroyDeviceInfoList(DevInfo);
cleanupMutex:
    ReleaseNameMutex(Mutex);
    return Result;
}

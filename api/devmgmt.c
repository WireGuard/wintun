/* SPDX-License-Identifier: GPL-2.0
 *
 * Copyright (C) 2018-2020 WireGuard LLC. All Rights Reserved.
 */

#include "api.h"
#include <objbase.h>
#include <SetupAPI.h>
#include <wchar.h>

#define WINTUN_HWID L"Wintun"
#define WAIT_FOR_REGISTRY_TIMEOUT 10000 /* ms */

const static GUID CLASS_NET_GUID = { 0x4d36e972L, 0xe325, 0x11ce, { 0xbf, 0xc1, 0x08, 0x00, 0x2b, 0xe1, 0x03, 0x18 } };
const static GUID ADAPTER_NET_GUID = { 0xcac88484L,
                                       0x7515,
                                       0x4c03,
                                       { 0x82, 0xe6, 0x71, 0xa8, 0x7a, 0xba, 0xc3, 0x61 } };

/**
 * Validate and/or sanitize string value read from registry.
 *
 * @param Buf           On input, it contains pointer to pointer where the data is stored. The data must be
 *                      allocated using HeapAlloc(GetProcessHeap(), 0).
 *                      On output, it contains pointer to pointer where the sanitized data is stored. It must be
 *                      released with HeapFree(GetProcessHeap(), 0, *Buf) after use.
 *
 * @param Len           Length of data string in wide characters
 *
 * @param ValueType     Type of data. Must be either REG_SZ or REG_EXPAND_SZ.
 *
 * @return ERROR_SUCCESS on success; Win32 error code otherwise
 */
static WINSTATUS
GetRegString(_Inout_ LPWSTR *Buf, _In_ DWORD Len, _In_ DWORD ValueType)
{
    HANDLE Heap = GetProcessHeap();

    if (wcsnlen(*Buf, Len) >= Len)
    {
        /* String is missing zero-terminator. */
        LPWSTR BufZ = HeapAlloc(Heap, 0, ((size_t)Len + 1) * sizeof(WCHAR));
        if (!BufZ)
            return ERROR_OUTOFMEMORY;
        wmemcpy(BufZ, *Buf, Len);
        BufZ[Len] = 0;
        HeapFree(Heap, 0, *Buf);
        *Buf = BufZ;
    }

    if (ValueType != REG_EXPAND_SZ)
        return ERROR_SUCCESS;

    /* ExpandEnvironmentStringsW() returns strlen on success or 0 on error. Bail out on empty input strings to
     * disambiguate. */
    if (!(*Buf)[0])
        return ERROR_SUCCESS;

    Len = Len * 2 + 64;
    for (;;)
    {
        LPWSTR Expanded = HeapAlloc(Heap, 0, Len * sizeof(WCHAR));
        if (!Expanded)
            return ERROR_OUTOFMEMORY;
        DWORD Result = ExpandEnvironmentStringsW(*Buf, Expanded, Len);
        if (!Result)
        {
            Result = GetLastError();
            HeapFree(Heap, 0, Expanded);
            return Result;
        }
        if (Result > Len)
        {
            HeapFree(Heap, 0, Expanded);
            Len = Result;
            continue;
        }
        HeapFree(Heap, 0, *Buf);
        *Buf = Expanded;
        return ERROR_SUCCESS;
    }
}

/**
 * Validate and/or sanitize multi-string value read from registry.
 *
 * @param Buf           On input, it contains pointer to pointer where the data is stored. The data must be
 *                      allocated using HeapAlloc(GetProcessHeap(), 0).
 *                      On output, it contains pointer to pointer where the sanitized data is stored. It must be
 *                      released with HeapFree(GetProcessHeap(), 0, *Buf) after use.
 *
 * @param Len           Length of data string in wide characters
 *
 * @param ValueType     Type of data. Must be one of REG_MULTI_SZ, REG_SZ or REG_EXPAND_SZ.
 *
 * @return ERROR_SUCCESS on success; Win32 error code otherwise
 */
static WINSTATUS
GetRegMultiString(_Inout_ LPWSTR *Buf, _In_ DWORD Len, _In_ DWORD ValueType)
{
    HANDLE Heap = GetProcessHeap();

    if (ValueType == REG_MULTI_SZ)
    {
        for (size_t i = 0;; i += wcsnlen(*Buf + i, Len - i) + 1)
        {
            if (i > Len)
            {
                /* Missing string and list terminators. */
                LPWSTR BufZ = HeapAlloc(Heap, 0, ((size_t)Len + 2) * sizeof(WCHAR));
                if (!BufZ)
                    return ERROR_OUTOFMEMORY;
                wmemcpy(BufZ, *Buf, Len);
                BufZ[Len] = 0;
                BufZ[Len + 1] = 0;
                HeapFree(Heap, 0, *Buf);
                *Buf = BufZ;
                return ERROR_SUCCESS;
            }
            if (i == Len)
            {
                /* Missing list terminator. */
                LPWSTR BufZ = HeapAlloc(Heap, 0, ((size_t)Len + 1) * sizeof(WCHAR));
                if (!BufZ)
                    return ERROR_OUTOFMEMORY;
                wmemcpy(BufZ, *Buf, Len);
                BufZ[Len] = 0;
                HeapFree(Heap, 0, *Buf);
                *Buf = BufZ;
                return ERROR_SUCCESS;
            }
            if (!(*Buf)[i])
                return ERROR_SUCCESS;
        }
    }

    /* Sanitize REG_SZ/REG_EXPAND_SZ and append a list terminator to make a multi-string. */
    DWORD Result = GetRegString(Buf, Len, ValueType);
    if (Result != ERROR_SUCCESS)
        return Result;
    Len = (DWORD)wcslen(*Buf) + 1;
    LPWSTR BufZ = HeapAlloc(Heap, 0, ((size_t)Len + 1) * sizeof(WCHAR));
    if (!BufZ)
        return ERROR_OUTOFMEMORY;
    wmemcpy(BufZ, *Buf, Len);
    BufZ[Len] = 0;
    HeapFree(Heap, 0, *Buf);
    *Buf = BufZ;
    return ERROR_SUCCESS;
}

/**
 * Reads string value from registry key.
 *
 * @param Key           Handle of the registry key to read from. Must be opened with read
 *                      access.
 *
 * @param Name          Name of the value to read
 *
 * @param Value         Pointer to string to retrieve registry value. If the value type is
 *                      REG_EXPAND_SZ the value is expanded using ExpandEnvironmentStrings().
 *                      The string must be released with HeapFree(GetProcessHeap(), 0, Value)
 *                      after use.
 *
 * @return ERROR_SUCCESS on success; Win32 error code otherwise
 */
static WINSTATUS
RegQueryString(_In_ HKEY Key, _In_opt_z_ LPCWSTR Name, _Out_ LPWSTR *Value)
{
    HANDLE Heap = GetProcessHeap();
    DWORD Size = 256;
    for (;;)
    {
        *Value = HeapAlloc(Heap, 0, Size);
        if (!*Value)
            return ERROR_OUTOFMEMORY;
        DWORD ValueType;
        DWORD Result = RegQueryValueExW(Key, Name, NULL, &ValueType, (BYTE *)*Value, &Size);
        if (Result == ERROR_MORE_DATA)
        {
            HeapFree(Heap, 0, *Value);
            continue;
        }
        if (Result != ERROR_SUCCESS)
        {
            HeapFree(Heap, 0, *Value);
            return Result;
        }

        switch (ValueType)
        {
        case REG_SZ:
        case REG_EXPAND_SZ:
            Result = GetRegString(Value, Size / sizeof(WCHAR), ValueType);
            if (Result != ERROR_SUCCESS)
                HeapFree(Heap, 0, *Value);
            return Result;
        default:
            HeapFree(Heap, 0, *Value);
            return ERROR_INVALID_DATATYPE;
        }
    }
}

/**
 * Reads a 32-bit DWORD value from registry key.
 *
 * @param Key           Handle of the registry key to read from. Must be opened with read
 *                      access.
 *
 * @param Name          Name of the value to read
 *
 * @param Value         Pointer to DWORD to retrieve registry value
 *
 * @return ERROR_SUCCESS on success; Win32 error code otherwise
 */
static WINSTATUS
RegQueryDWORD(_In_ HKEY Key, _In_opt_z_ LPCWSTR Name, _Out_ DWORD *Value)
{
    DWORD ValueType, Size = sizeof(DWORD);
    DWORD Result = RegQueryValueExW(Key, Name, NULL, &ValueType, (BYTE *)Value, &Size);
    if (Result != ERROR_SUCCESS)
        return Result;
    if (ValueType != REG_DWORD)
        return ERROR_INVALID_DATATYPE;
    if (Size != sizeof(DWORD))
        return ERROR_INVALID_DATA;
    return ERROR_SUCCESS;
}

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
static WINSTATUS
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
static WINSTATUS
GetDeviceRegistryString(
    _In_ HDEVINFO DevInfo,
    _In_ SP_DEVINFO_DATA *DevInfoData,
    _In_ DWORD Property,
    _Out_ LPWSTR *PropertyBuffer)
{
    DWORD Result, ValueType, Size;
    Result = GetDeviceRegistryProperty(DevInfo, DevInfoData, Property, &ValueType, PropertyBuffer, &Size);
    if (Result != ERROR_SUCCESS)
        return Result;

    switch (ValueType)
    {
    case REG_SZ:
    case REG_EXPAND_SZ:
        Result = GetRegString(PropertyBuffer, Size / sizeof(WCHAR), ValueType);
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
static WINSTATUS
GetDeviceRegistryMultiString(
    _In_ HDEVINFO DevInfo,
    _In_ SP_DEVINFO_DATA *DevInfoData,
    _In_ DWORD Property,
    _Out_ LPWSTR *PropertyBuffer)
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
        Result = GetRegMultiString(PropertyBuffer, Size / sizeof(WCHAR), ValueType);
        if (Result != ERROR_SUCCESS)
            HeapFree(GetProcessHeap(), 0, *PropertyBuffer);
        return Result;
    default:
        HeapFree(GetProcessHeap(), 0, *PropertyBuffer);
        return ERROR_INVALID_DATATYPE;
    }
}

/**
 * Removes numbered suffix from adapter name.
 */
static void
RemoveNumberedSuffix(_In_z_ LPCWSTR IfName, _Out_ LPWSTR Removed)
{
    size_t Len = wcslen(IfName);
    if (Len && IfName[Len - 1] < L'0' || IfName[Len - 1] > L'9')
    {
        wmemcpy(Removed, IfName, Len + 1);
        return;
    }
    for (size_t i = Len; i--;)
    {
        if (IfName[i] >= L'0' && IfName[i] <= L'9')
            continue;
        if (IfName[i] == L' ')
        {
            wmemcpy(Removed, IfName, i);
            Removed[i] = 0;
            return;
        }
        break;
    }
    wmemcpy(Removed, IfName, Len + 1);
}

/**
 * Tests if any of the hardware IDs match ours.
 *
 * @param Hwids         Multi-string containing a list of hardware IDs
 *
 * @return TRUE on match; FALSE otherwise.
 */
static BOOL
IsOurHardwareID(_In_z_ LPWSTR Hwids)
{
    for (; Hwids[0]; Hwids += wcslen(Hwids) + 1)
        if (!_wcsicmp(Hwids, WINTUN_HWID))
            return TRUE;
    return FALSE;
}

/**
 * Returns pool-specific device type name.
 */
static WINSTATUS
GetPoolDeviceTypeName(_In_z_count_c_(MAX_POOL) LPCWSTR Pool, _Out_ LPWSTR *Name)
{
    HANDLE Heap = GetProcessHeap();
    int Len = 256;
    for (;;)
    {
        *Name = HeapAlloc(Heap, 0, Len * sizeof(WCHAR));
        if (!*Name)
            return ERROR_OUTOFMEMORY;
        if (_snwprintf_s(*Name, Len, _TRUNCATE, L"%s Tunnel", Pool) < 0)
        {
            HeapFree(Heap, 0, *Name);
            Len *= 2;
            continue;
        }
        return ERROR_SUCCESS;
    }
}

/**
 * Checks if SPDRP_DEVICEDESC or SPDRP_FRIENDLYNAME match device type name.
 */
static WINSTATUS
IsPoolMember(
    _In_z_count_c_(MAX_POOL) LPCWSTR Pool,
    _In_ HDEVINFO DevInfo,
    _In_ SP_DEVINFO_DATA *DevInfoData,
    _Out_ BOOL *IsMember)
{
    HANDLE Heap = GetProcessHeap();
    LPWSTR DeviceDesc, FriendlyName, PoolDeviceTypeName;
    DWORD Result = GetDeviceRegistryString(DevInfo, DevInfoData, SPDRP_DEVICEDESC, &DeviceDesc);
    if (Result != ERROR_SUCCESS)
        return Result;
    Result = GetDeviceRegistryString(DevInfo, DevInfoData, SPDRP_FRIENDLYNAME, &FriendlyName);
    if (Result != ERROR_SUCCESS)
        goto cleanupDeviceDesc;
    Result = GetPoolDeviceTypeName(Pool, &PoolDeviceTypeName);
    if (Result != ERROR_SUCCESS)
        goto cleanupFriendlyName;
    if (!_wcsicmp(FriendlyName, PoolDeviceTypeName) || !_wcsicmp(DeviceDesc, PoolDeviceTypeName))
    {
        *IsMember = TRUE;
        goto cleanupPoolDeviceTypeName;
    }
    RemoveNumberedSuffix(FriendlyName, FriendlyName);
    RemoveNumberedSuffix(DeviceDesc, DeviceDesc);
    if (!_wcsicmp(FriendlyName, PoolDeviceTypeName) || !_wcsicmp(DeviceDesc, PoolDeviceTypeName))
    {
        *IsMember = TRUE;
        goto cleanupPoolDeviceTypeName;
    }
    *IsMember = FALSE;
cleanupPoolDeviceTypeName:
    HeapFree(Heap, 0, PoolDeviceTypeName);
cleanupFriendlyName:
    HeapFree(Heap, 0, FriendlyName);
cleanupDeviceDesc:
    HeapFree(Heap, 0, DeviceDesc);
    return Result;
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
static WINSTATUS
GetDriverInfoDetail(
    _In_ HDEVINFO DevInfo,
    _In_ SP_DEVINFO_DATA *DevInfoData,
    _In_ SP_DRVINFO_DATA_W *DriverData,
    _Out_ SP_DRVINFO_DETAIL_DATA_W **DriverDetailData)
{
    HANDLE Heap = GetProcessHeap();
    DWORD Size = 2048;
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
 * Check if the device is using Wintun driver.
 */
static WINSTATUS
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
 * Creates a Wintun interface descriptor and populates it from the device's registry key.
 *
 * @param DevInfo       A handle to the device information set that contains a device information element that
 *                      represents the device for which to open a registry key.
 *
 * @param DevInfoData   A pointer to a structure that specifies the device information element in DeviceInfoSet.
 *
 * @param Pool          Name of the adapter pool
 *
 * @param Adapter       A pointer to a Wintun adapter descriptor
 *
 * @return ERROR_SUCCESS on success; Win32 error code otherwise
 */
static WINSTATUS
InitAdapterData(
    _In_ HDEVINFO DevInfo,
    _In_ SP_DEVINFO_DATA *DevInfoData,
    _In_z_count_c_(MAX_POOL) LPCWSTR Pool,
    _Out_ WINTUN_ADAPTER *Adapter)
{
    DWORD Result;

    /* Open HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\<class>\<id> registry key. */
    HKEY Key = SetupDiOpenDevRegKey(DevInfo, DevInfoData, DICS_FLAG_GLOBAL, 0, DIREG_DRV, KEY_QUERY_VALUE);
    if (Key == INVALID_HANDLE_VALUE)
        return GetLastError();

    /* Read the NetCfgInstanceId value and convert to GUID. */
    LPWSTR ValueStr;
    Result = RegQueryString(Key, L"NetCfgInstanceId", &ValueStr);
    if (Result != ERROR_SUCCESS)
        goto cleanupKey;
    if (FAILED(CLSIDFromString(ValueStr, &Adapter->CfgInstanceID)))
    {
        HeapFree(GetProcessHeap(), 0, ValueStr);
        Result = ERROR_INVALID_DATA;
        goto cleanupKey;
    }
    HeapFree(GetProcessHeap(), 0, ValueStr);

    /* Read the NetLuidIndex value. */
    Result = RegQueryDWORD(Key, L"NetLuidIndex", &Adapter->LuidIndex);
    if (Result != ERROR_SUCCESS)
        goto cleanupKey;

    /* Read the NetLuidIndex value. */
    Result = RegQueryDWORD(Key, L"*IfType", &Adapter->IfType);
    if (Result != ERROR_SUCCESS)
        goto cleanupKey;

    DWORD Size;
    if (!SetupDiGetDeviceInstanceIdW(
            DevInfo, DevInfoData, Adapter->DevInstanceID, _countof(Adapter->DevInstanceID), &Size))
    {
        Result = GetLastError();
        goto cleanupKey;
    }

    wcscpy_s(Adapter->Pool, _countof(Adapter->Pool), Pool);
    Result = ERROR_SUCCESS;

cleanupKey:
    RegCloseKey(Key);
    return Result;
}

/**
 * Releases Wintun adapter resources.
 *
 * @param Adapter       Adapter handle obtained with WintunGetAdapter or WintunCreateAdapter
 */
VOID WINAPI
WintunFreeAdapter(_In_ WINTUN_ADAPTER *Adapter)
{
    HeapFree(GetProcessHeap(), 0, Adapter);
}

/**
 * Finds a Wintun adapter by its name.
 *
 * @param Pool          Name of the adapter pool
 *
 * @param IfName        Adapter name
 *
 * @param Adapter       Pointer to a handle to receive the adapter handle. Must be released with
 *                      WintunFreeAdapter.
 *
 * @return ERROR_SUCCESS on success; Win32 error code otherwise;
 * ERROR_FILE_NOT_FOUND if adapter with given name is not found;
 * ERROR_ALREADY_EXISTS if adapter is found but not a Wintun-class or not a member of the pool
 */
WINSTATUS WINAPI
WintunGetAdapter(_In_z_count_c_(MAX_POOL) LPCWSTR Pool, _In_z_ LPCWSTR IfName, _Out_ WINTUN_ADAPTER **Adapter)
{
    DWORD Result;
    HANDLE Mutex = TakeNameMutex(Pool);
    if (!Mutex)
        return ERROR_GEN_FAILURE;

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
        HKEY Key = SetupDiOpenDevRegKey(DevInfo, &DevInfoData, DICS_FLAG_GLOBAL, 0, DIREG_DRV, KEY_QUERY_VALUE);
        if (Key != INVALID_HANDLE_VALUE)
        {
            LPWSTR CfgInstanceIDStr;
            Result = RegQueryString(Key, L"NetCfgInstanceId", &CfgInstanceIDStr);
            if (Result == ERROR_SUCCESS)
            {
                Result =
                    SUCCEEDED(CLSIDFromString(CfgInstanceIDStr, &CfgInstanceID)) ? ERROR_SUCCESS : ERROR_INVALID_DATA;
                HeapFree(Heap, 0, CfgInstanceIDStr);
            }
            RegCloseKey(Key);
        }
        else
            Result = GetLastError();
        if (Result != ERROR_SUCCESS)
            continue;

        /* TODO: is there a better way than comparing ifnames? */
        WCHAR IfName2[0x400], IfName3[0x400]; /* TODO: Make dynamic. */
        if (NciGetConnectionName(&CfgInstanceID, IfName2, sizeof(IfName2), NULL) != ERROR_SUCCESS)
            continue;
        IfName2[_countof(IfName2) - 1] = 0;
        RemoveNumberedSuffix(IfName2, IfName3);
        if (_wcsicmp(IfName, IfName2) && _wcsicmp(IfName, IfName3))
            continue;

        /* Check the Hardware ID to make sure it's a real Wintun device. This avoids doing slow operations on non-Wintun
         * devices. */
        LPWSTR Hwids;
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

        *Adapter = HeapAlloc(Heap, 0, sizeof(WINTUN_ADAPTER));
        if (!*Adapter)
        {
            Result = ERROR_OUTOFMEMORY;
            goto cleanupDevInfo;
        }
        Result = InitAdapterData(DevInfo, &DevInfoData, Pool, *Adapter);
        if (Result != ERROR_SUCCESS)
            HeapFree(Heap, 0, *Adapter);
        goto cleanupDevInfo;
    }
    Result = ERROR_FILE_NOT_FOUND;
cleanupDevInfo:
    SetupDiDestroyDeviceInfoList(DevInfo);
cleanupMutex:
    ReleaseNameMutex(Mutex);
    return Result;
}

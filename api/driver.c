/* SPDX-License-Identifier: GPL-2.0
 *
 * Copyright (C) 2018-2020 WireGuard LLC. All Rights Reserved.
 */

#include "pch.h"

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
 * @return non-zero on success; zero otherwise - use GetLastError().
 */
_Return_type_success_(return != NULL) SP_DRVINFO_DETAIL_DATA_W *DriverGetDrvInfoDetail(
    _In_ HDEVINFO DevInfo,
    _In_opt_ SP_DEVINFO_DATA *DevInfoData,
    _In_ SP_DRVINFO_DATA_W *DrvInfoData)
{
    HANDLE Heap = GetProcessHeap();
    DWORD Size = sizeof(SP_DRVINFO_DETAIL_DATA_W) + 0x100;
    DWORD Result;
    for (;;)
    {
        SP_DRVINFO_DETAIL_DATA_W *DrvInfoDetailData = HeapAlloc(Heap, 0, Size);
        if (!DrvInfoDetailData)
        {
            Result = ERROR_OUTOFMEMORY;
            goto out;
        }
        DrvInfoDetailData->cbSize = sizeof(SP_DRVINFO_DETAIL_DATA_W);
        if (SetupDiGetDriverInfoDetailW(DevInfo, DevInfoData, DrvInfoData, DrvInfoDetailData, Size, &Size))
            return DrvInfoDetailData;
        Result = GetLastError();
        HeapFree(Heap, 0, DrvInfoDetailData);
        if (Result != ERROR_INSUFFICIENT_BUFFER)
        {
            WINTUN_LOGGER_ERROR(L"Failed", Result);
            goto out;
        }
    }
out:
    SetLastError(Result);
    return NULL;
}

/**
 * Checks if the device (i.e. network adapter) is using Wintun driver.
 *
 * @param DevInfo       A handle to the device information set that contains a device information element that
 *                      represents the device.
 *
 * @param DevInfoData   A pointer to a structure that specifies the device information element in DevInfo.
 *
 * @return non-zero when using Wintun driver; zero when not or error - use GetLastError().
 */
BOOL
DriverIsWintunAdapter(_In_ HDEVINFO DevInfo, _In_opt_ SP_DEVINFO_DATA *DevInfoData)
{
    BOOL Found = FALSE;
    if (!SetupDiBuildDriverInfoList(DevInfo, DevInfoData, SPDIT_COMPATDRIVER))
    {
        WINTUN_LOGGER_LAST_ERROR(L"Failed to build list of drivers");
        return FALSE;
    }
    HANDLE Heap = GetProcessHeap();
    for (DWORD EnumIndex = 0; !Found; ++EnumIndex)
    {
        SP_DRVINFO_DATA_W DrvInfoData = { .cbSize = sizeof(SP_DRVINFO_DATA_W) };
        if (!SetupDiEnumDriverInfoW(DevInfo, DevInfoData, SPDIT_COMPATDRIVER, EnumIndex, &DrvInfoData))
        {
            if (GetLastError() == ERROR_NO_MORE_ITEMS)
                break;
            continue;
        }
        SP_DRVINFO_DETAIL_DATA_W *DrvInfoDetailData = DriverGetDrvInfoDetail(DevInfo, DevInfoData, &DrvInfoData);
        if (!DrvInfoDetailData)
            continue;
        Found = !_wcsicmp(DrvInfoDetailData->HardwareID, L"wintun");
        HeapFree(Heap, 0, DrvInfoDetailData);
    }
    SetupDiDestroyDriverInfoList(DevInfo, DevInfoData, SPDIT_COMPATDRIVER);
    SetLastError(ERROR_SUCCESS);
    return Found;
}

/**
 * Returns a handle to the adapter device object.
 *
 * @param InstanceId    Adapter device instance ID.
 *
 * @return device handle on success; INVALID_HANDLE_VALUE otherwise - use GetLastError().
 */
_Return_type_success_(return != INVALID_HANDLE_VALUE) HANDLE
    DriverGetAdapterDeviceObject(_In_opt_z_ const WCHAR *InstanceId)
{
    HANDLE Heap = GetProcessHeap();
    ULONG InterfacesLen;
    HANDLE Handle = INVALID_HANDLE_VALUE;
    DWORD Result = CM_Get_Device_Interface_List_SizeW(
        &InterfacesLen, (GUID *)&GUID_DEVINTERFACE_NET, (DEVINSTID_W)InstanceId, CM_GET_DEVICE_INTERFACE_LIST_PRESENT);
    if (Result != CR_SUCCESS)
    {
        WINTUN_LOGGER(WINTUN_LOG_ERR, L"Failed to get device associated device instances size");
        SetLastError(ERROR_GEN_FAILURE);
        return INVALID_HANDLE_VALUE;
    }
    WCHAR *Interfaces = HeapAlloc(Heap, 0, InterfacesLen * sizeof(WCHAR));
    if (!Interfaces)
    {
        SetLastError(ERROR_OUTOFMEMORY);
        return INVALID_HANDLE_VALUE;
    }
    Result = CM_Get_Device_Interface_ListW(
        (GUID *)&GUID_DEVINTERFACE_NET,
        (DEVINSTID_W)InstanceId,
        Interfaces,
        InterfacesLen,
        CM_GET_DEVICE_INTERFACE_LIST_PRESENT);
    if (Result != CR_SUCCESS)
    {
        WINTUN_LOGGER(WINTUN_LOG_ERR, L"Failed to get device associated device instances");
        Result = ERROR_GEN_FAILURE;
        goto cleanupBuf;
    }
    Handle = CreateFileW(
        Interfaces,
        GENERIC_READ | GENERIC_WRITE,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        NULL,
        OPEN_EXISTING,
        0,
        NULL);
    Result = Handle != INVALID_HANDLE_VALUE ? ERROR_SUCCESS : WINTUN_LOGGER_LAST_ERROR(L"Failed to connect to device");
cleanupBuf:
    HeapFree(Heap, 0, Interfaces);
    SetLastError(Result);
    return Handle;
}

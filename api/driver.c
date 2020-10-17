/* SPDX-License-Identifier: GPL-2.0
 *
 * Copyright (C) 2018-2020 WireGuard LLC. All Rights Reserved.
 */

#include "pch.h"

#pragma warning(disable : 4221) /* nonstandard: address of automatic in initializer */

BOOL
DriverIsOurHardwareID(_In_z_ const WCHAR *Hwids)
{
    for (; Hwids[0]; Hwids += wcslen(Hwids) + 1)
        if (!_wcsicmp(Hwids, WINTUN_HWID))
            return TRUE;
    return FALSE;
}

BOOL
DriverIsOurDrvInfoDetail(_In_ const SP_DRVINFO_DETAIL_DATA_W *DrvInfoDetailData)
{
    return DrvInfoDetailData->CompatIDsOffset > 1 && !_wcsicmp(DrvInfoDetailData->HardwareID, WINTUN_HWID) ||
           DrvInfoDetailData->CompatIDsLength &&
               DriverIsOurHardwareID(DrvInfoDetailData->HardwareID + DrvInfoDetailData->CompatIDsOffset);
}

#if defined(HAVE_EV) || defined(HAVE_WHQL)

WINTUN_STATUS
DriverRemoveAllOurs(void)
{
    HDEVINFO DevInfo = SetupDiGetClassDevsW(&GUID_DEVCLASS_NET, NULL, NULL, 0);
    if (!DevInfo)
        return LOG_LAST_ERROR(L"Failed to request device information");
    DWORD Result = ERROR_SUCCESS;
    if (!SetupDiBuildDriverInfoList(DevInfo, NULL, SPDIT_CLASSDRIVER))
    {
        Result = LOG_LAST_ERROR(L"Failed to build list of drivers");
        goto cleanupDeviceInfoSet;
    }
    HANDLE Heap = GetProcessHeap();
    for (DWORD EnumIndex = 0;; ++EnumIndex)
    {
        SP_DRVINFO_DATA_W DrvInfoData = { .cbSize = sizeof(DrvInfoData) };
        if (!SetupDiEnumDriverInfoW(DevInfo, NULL, SPDIT_CLASSDRIVER, EnumIndex, &DrvInfoData))
        {
            if (GetLastError() == ERROR_NO_MORE_ITEMS)
                break;
            continue;
        }
        SP_DRVINFO_DETAIL_DATA_W *DrvInfoDetailData;
        if (AdapterGetDrvInfoDetail(DevInfo, NULL, &DrvInfoData, &DrvInfoDetailData) != ERROR_SUCCESS)
        {
            LOG(WINTUN_LOG_WARN, L"Failed getting driver info detail");
            continue;
        }
        if (!DriverIsOurDrvInfoDetail(DrvInfoDetailData))
        {
            HeapFree(Heap, 0, DrvInfoDetailData);
            continue;
        }
        PathStripPathW(DrvInfoDetailData->InfFileName);
        LOG(WINTUN_LOG_INFO, L"Removing existing driver");
        if (!SetupUninstallOEMInfW(DrvInfoDetailData->InfFileName, SUOI_FORCEDELETE, NULL))
        {
            LOG_LAST_ERROR(L"Unable to remove existing driver");
            Result = Result != ERROR_SUCCESS ? Result : GetLastError();
        }
        HeapFree(Heap, 0, DrvInfoDetailData);
    }
    SetupDiDestroyDriverInfoList(DevInfo, NULL, SPDIT_CLASSDRIVER);
cleanupDeviceInfoSet:
    SetupDiDestroyDeviceInfoList(DevInfo);
    return Result;
}

#endif

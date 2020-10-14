/* SPDX-License-Identifier: GPL-2.0
 *
 * Copyright (C) 2018-2020 WireGuard LLC. All Rights Reserved.
 */

#pragma once

#include "api.h"
#include <Windows.h>
#include <SetupAPI.h>

#define WINTUN_HWID L"Wintun"

_Return_type_success_(return != NULL) SP_DRVINFO_DETAIL_DATA_W *DriverGetDrvInfoDetail(
    _In_ HDEVINFO DevInfo,
    _In_opt_ SP_DEVINFO_DATA *DevInfoData,
    _In_ SP_DRVINFO_DATA_W *DrvInfoData);

BOOL
DriverIsWintunAdapter(_In_ HDEVINFO DevInfo, _In_opt_ SP_DEVINFO_DATA *DevInfoData);

_Return_type_success_(return != INVALID_HANDLE_VALUE) HANDLE
    DriverGetAdapterDeviceObject(_In_opt_z_ const WCHAR *InstanceId);

#if defined(HAVE_EV) || defined(HAVE_WHQL)

WINTUN_STATUS DriverInstallOrUpdate(VOID);

WINTUN_STATUS DriverUninstall(VOID);

#endif
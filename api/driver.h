/* SPDX-License-Identifier: GPL-2.0
 *
 * Copyright (C) 2018-2020 WireGuard LLC. All Rights Reserved.
 */

#pragma once

#include "api.h"
#include <Windows.h>

#define WINTUN_HWID L"Wintun"

BOOL
DriverIsOurHardwareID(_In_z_ const WCHAR *Hwids);

BOOL
DriverIsOurDrvInfoDetail(_In_ const SP_DRVINFO_DETAIL_DATA_W *DrvInfoDetailData);

#if defined(HAVE_EV) || defined(HAVE_WHQL)

WINTUN_STATUS DriverGetVersion(_Out_ FILETIME *DriverDate, _Out_ DWORDLONG *DriverVersion);

WINTUN_STATUS DriverInstallOrUpdate(VOID);

WINTUN_STATUS DriverUninstall(VOID);

#endif
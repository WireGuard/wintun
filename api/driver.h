/* SPDX-License-Identifier: GPL-2.0
 *
 * Copyright (C) 2018-2020 WireGuard LLC. All Rights Reserved.
 */

#pragma once

#include "api.h"
#include <Windows.h>

#define WINTUN_HWID L"Wintun"

/**
 * Tests if any of the hardware IDs match ours.
 *
 * @param Hwids         Multi-string containing a list of hardware IDs.
 *
 * @return TRUE on match; FALSE otherwise.
 */
BOOL
DriverIsOurHardwareID(_In_z_ const WCHAR *Hwids);

/**
 * Tests if hardware ID or any of the compatible IDs match ours.
 *
 * @param DrvInfoDetailData  Detailed information about a particular driver information structure.
 *
 * @return TRUE on match; FALSE otherwise.
 */
BOOL
DriverIsOurDrvInfoDetail(_In_ const SP_DRVINFO_DETAIL_DATA_W *DrvInfoDetailData);

#if defined(HAVE_EV) || defined(HAVE_WHQL)

/**
 * Queries the version of the driver this wintun.dll is packing.
 *
 * DriverDate           Pointer to a variable to receive the driver date.
 *
 * DriverVersion        Pointer to a variable to receive the driver version.
 *
 * @return ERROR_SUCCESS on success; Win32 error code otherwise.
 */
WINTUN_STATUS
DriverGetVersion(_Out_ FILETIME *DriverDate, _Out_ DWORDLONG *DriverVersion);

/**
 * Installs or updates Wintun driver.
 *
 * @return ERROR_SUCCESS on success; Win32 error code otherwise.
 */
WINTUN_STATUS DriverInstallOrUpdate(VOID);

/**
 * Uninstalls Wintun driver.
 *
 * @return ERROR_SUCCESS on success; Win32 error code otherwise.
 */
WINTUN_STATUS DriverUninstall(VOID);

#endif

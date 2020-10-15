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

/**
 * Removes all Wintun drivers from the driver store.
 *
 * @return ERROR_SUCCESS on success or the adapter was not found; Win32 error code otherwise.
 */
WINTUN_STATUS DriverRemoveAllOurs(VOID);

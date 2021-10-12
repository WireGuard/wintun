/* SPDX-License-Identifier: GPL-2.0
 *
 * Copyright (C) 2018-2021 WireGuard LLC. All Rights Reserved.
 */

#pragma once

#include "wintun.h"
#include <Windows.h>
#include <SetupAPI.h>

#define WINTUN_HWID L"Wintun"

typedef struct _SP_DEVINFO_DATA_LIST SP_DEVINFO_DATA_LIST;

VOID
DriverInstallDeferredCleanup(_In_ HDEVINFO DevInfoExistingAdapters, _In_opt_ SP_DEVINFO_DATA_LIST *ExistingAdapters);

_Must_inspect_result_
_Return_type_success_(return != FALSE)
BOOL
DriverInstall(
    _Out_ HDEVINFO *DevInfoExistingAdaptersForCleanup,
    _Out_ SP_DEVINFO_DATA_LIST **ExistingAdaptersForCleanup);

/**
 * @copydoc WINTUN_DELETE_DRIVER_FUNC
 */
WINTUN_DELETE_DRIVER_FUNC WintunDeleteDriver;

/**
 * @copydoc WINTUN_GET_RUNNING_DRIVER_VERSION_FUNC
 */
WINTUN_GET_RUNNING_DRIVER_VERSION_FUNC WintunGetRunningDriverVersion;

/* SPDX-License-Identifier: GPL-2.0
 *
 * Copyright (C) 2018-2020 WireGuard LLC. All Rights Reserved.
 */

#pragma once

#include "api.h"
#include <Windows.h>

WINTUN_STATUS
ResourceGetAddress(_In_z_ const WCHAR *ResourceName, _Out_ const VOID **Address, _Out_ DWORD *Size);

WINTUN_STATUS
ResourceCopyToFile(
    _In_z_ const WCHAR *DestinationPath,
    _In_opt_ SECURITY_ATTRIBUTES *SecurityAttributes,
    _In_z_ const WCHAR *ResourceName);

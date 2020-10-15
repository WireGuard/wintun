/* SPDX-License-Identifier: GPL-2.0
 *
 * Copyright (C) 2018-2020 WireGuard LLC. All Rights Reserved.
 */

#pragma once

#include "api.h"
#include <Windows.h>

/**
 * Locates RT_RCDATA resource memory address and size.
 *
 * ResourceName         Name of the RT_RCDATA resource. Use MAKEINTRESOURCEW to locate resource by ID.
 *
 * Address              Pointer to a pointer variable to receive resource address.
 *
 * Size                 Pointer to a variable to receive resource size.
 *
 * @return ERROR_SUCCESS on success; Win32 error code otherwise.
 */
WINTUN_STATUS
ResourceGetAddress(_In_z_ const WCHAR *ResourceName, _Out_ const VOID **Address, _Out_ DWORD *Size);

/**
 * Copies resource to a file.
 *
 * DestinationPath      File path
 *
 * ResourceName         Name of the RT_RCDATA resource. Use MAKEINTRESOURCEW to locate resource by ID.
 *
 * @return ERROR_SUCCESS on success; Win32 error code otherwise.
 */
WINTUN_STATUS
ResourceCopyToFile(_In_z_ const WCHAR *DestinationPath, _In_z_ const WCHAR *ResourceName);

/* SPDX-License-Identifier: GPL-2.0
 *
 * Copyright (C) 2018-2021 WireGuard LLC. All Rights Reserved.
 */

#pragma once

#include "wintun.h"
#include <Windows.h>

/**
 * Locates RT_RCDATA resource memory address and size.
 *
 * @param ResourceName         Name of the RT_RCDATA resource. Use MAKEINTRESOURCEW to locate resource by ID.
 *
 * @param Size                 Pointer to a variable to receive resource size.
 *
 * @return Resource address on success. If the function fails, the return value is NULL. To get extended error
 *         information, call GetLastError.
 */
_Must_inspect_result_
_Return_type_success_(return != NULL)
_Post_maybenull_
_Post_readable_byte_size_(*Size) const VOID *ResourceGetAddress(_In_z_ LPCWSTR ResourceName, _Out_ DWORD *Size);

/**
 * Copies resource to a file.
 *
 * @param DestinationPath   File path
 *
 * @param ResourceName      Name of the RT_RCDATA resource. Use MAKEINTRESOURCEW to locate resource by ID.
 *
 * @return If the function succeeds, the return value is nonzero. If the function fails, the return value is zero. To
 *         get extended error information, call GetLastError.
 */
_Return_type_success_(return != FALSE)
BOOL
ResourceCopyToFile(_In_z_ LPCWSTR DestinationPath, _In_z_ LPCWSTR ResourceName);

/**
 * Creates a temporary directory.
 *
 * @param RandomTempSubDirectory    Name of random temporary directory.
 *
 * @return If the function succeeds, the return value is nonzero. If the function fails, the return value is zero. To
 *         get extended error information, call GetLastError.
 */
_Return_type_success_(return != FALSE)
BOOL
ResourceCreateTemporaryDirectory(_Out_writes_z_(MAX_PATH) LPWSTR RandomTempSubDirectory);

/* SPDX-License-Identifier: GPL-2.0
 *
 * Copyright (C) 2018-2021 WireGuard LLC. All Rights Reserved.
 */

#pragma once

#include <Windows.h>

_Return_type_success_(return != FALSE) BOOL ElevateToSystem(void);

_Return_type_success_(return != NULL) HANDLE GetPrimarySystemTokenFromThread(void);

_Return_type_success_(return != FALSE) BOOL ImpersonateService(_In_z_ WCHAR *ServiceName, _In_ HANDLE *OriginalToken);

_Return_type_success_(return != FALSE) BOOL RestoreToken(_In_ HANDLE OriginalToken);

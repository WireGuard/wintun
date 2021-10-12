/* SPDX-License-Identifier: GPL-2.0
 *
 * Copyright (C) 2018-2021 WireGuard LLC. All Rights Reserved.
 */

#pragma once

#include <Windows.h>

_Must_inspect_result_
_Return_type_success_(return != NULL)
_Post_maybenull_
_Acquires_lock_(_Curr_)
HANDLE
NamespaceTakeDriverInstallationMutex(VOID);

_Must_inspect_result_
_Return_type_success_(return != NULL)
_Post_maybenull_
_Acquires_lock_(_Curr_)
HANDLE
NamespaceTakeDeviceInstallationMutex(VOID);

_Releases_lock_(Mutex)
VOID
NamespaceReleaseMutex(_In_ HANDLE Mutex);

VOID NamespaceInit(VOID);

VOID NamespaceDone(VOID);

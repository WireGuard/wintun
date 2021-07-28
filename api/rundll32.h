/* SPDX-License-Identifier: GPL-2.0
 *
 * Copyright (C) 2018-2021 WireGuard LLC. All Rights Reserved.
 */

#pragma once

#include "adapter.h"

_Must_inspect_result_
_Return_type_success_(return != NULL)
_Post_maybenull_
WINTUN_ADAPTER *
CreateAdapterViaRundll32(
    _In_z_ LPCWSTR Pool,
    _In_z_ LPCWSTR Name,
    _In_opt_ const GUID *RequestedGUID,
    _Inout_ BOOL *RebootRequired);

_Return_type_success_(return != FALSE)
BOOL
DeleteAdapterViaRundll32(
    _In_ const WINTUN_ADAPTER *Adapter,
    _In_ BOOL ForceCloseSessions,
    _Inout_ BOOL *RebootRequired);

_Return_type_success_(return != FALSE)
BOOL
DeletePoolDriverViaRundll32(_In_z_ LPCWSTR Pool, _Inout_ BOOL *RebootRequired);

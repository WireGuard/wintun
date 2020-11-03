/* SPDX-License-Identifier: GPL-2.0
 *
 * Copyright (C) 2018-2020 WireGuard LLC. All Rights Reserved.
 */

#pragma once

#include "wintun.h"
#include <IPExport.h>
#include <SetupAPI.h>
#include <Windows.h>

#define MAX_INSTANCE_ID MAX_PATH /* TODO: Is MAX_PATH always enough? */
#define WINTUN_HWID L"Wintun"

void
AdapterInit(void);

/**
 * Wintun adapter descriptor.
 */
typedef struct _WINTUN_ADAPTER
{
    GUID CfgInstanceID;
    WCHAR DevInstanceID[MAX_INSTANCE_ID];
    DWORD LuidIndex;
    DWORD IfType;
    WCHAR Pool[WINTUN_MAX_POOL];
} WINTUN_ADAPTER;

/**
 * @copydoc WINTUN_FREE_ADAPTER_FUNC
 */
void WINAPI
WintunFreeAdapter(_In_ WINTUN_ADAPTER *Adapter);

/**
 * @copydoc WINTUN_GET_ADAPTER_DEVICE_OBJECT_FUNC
 */
WINTUN_STATUS WINAPI
WintunGetAdapterDeviceObject(_In_ const WINTUN_ADAPTER *Adapter, _Out_ HANDLE *Handle);

/**
 * @copydoc WINTUN_CREATE_ADAPTER_FUNC
 */
WINTUN_STATUS WINAPI
WintunCreateAdapter(
    _In_z_ const WCHAR *Pool,
    _In_z_ const WCHAR *Name,
    _In_opt_ const GUID *RequestedGUID,
    _Out_ WINTUN_ADAPTER **Adapter,
    _Out_opt_ BOOL *RebootRequired);

/**
 * @copydoc WINTUN_DELETE_ADAPTER_FUNC
 */
WINTUN_STATUS WINAPI
WintunDeleteAdapter(_In_ const WINTUN_ADAPTER *Adapter, _In_ BOOL ForceCloseSessions, _Out_opt_ BOOL *RebootRequired);

/**
 * @copydoc WINTUN_DELETE_POOL_DRIVER_FUNC
 */
WINTUN_STATUS WINAPI
WintunDeletePoolDriver(_In_z_ WCHAR Pool[WINTUN_MAX_POOL], _Out_opt_ BOOL *RebootRequired);
/* SPDX-License-Identifier: GPL-2.0
 *
 * Copyright (C) 2018-2021 WireGuard LLC. All Rights Reserved.
 */

#pragma once

#include "wintun.h"
#include <IPExport.h>
#include <SetupAPI.h>
#include <Windows.h>

#define MAX_INSTANCE_ID MAX_PATH /* TODO: Is MAX_PATH always enough? */
#define WINTUN_HWID L"Wintun"

/**
 * Wintun adapter descriptor.
 */
typedef struct _WINTUN_ADAPTER
{
    HDEVINFO DevInfo;
    SP_DEVINFO_DATA DevInfoData;
    GUID CfgInstanceID;
    WCHAR DevInstanceID[MAX_INSTANCE_ID];
    DWORD LuidIndex;
    DWORD IfType;
    DWORD IfIndex;
    WCHAR Pool[WINTUN_MAX_POOL];
} WINTUN_ADAPTER;

/**
 * @copydoc WINTUN_FREE_ADAPTER_FUNC
 */
WINTUN_FREE_ADAPTER_FUNC_IMPL WintunFreeAdapter;

/**
 * @copydoc WINTUN_CREATE_ADAPTER_FUNC
 */
WINTUN_CREATE_ADAPTER_FUNC_IMPL WintunCreateAdapter;

/**
 * @copydoc WINTUN_OPEN_ADAPTER_FUNC
 */
WINTUN_OPEN_ADAPTER_FUNC_IMPL WintunOpenAdapter;

/**
 * @copydoc WINTUN_DELETE_ADAPTER_FUNC
 */
WINTUN_DELETE_ADAPTER_FUNC_IMPL WintunDeleteAdapter;

/**
 * @copydoc WINTUN_ENUM_ADAPTERS_FUNC
 */
WINTUN_ENUM_ADAPTERS_FUNC_IMPL WintunEnumAdapters;

/**
 * @copydoc WINTUN_DELETE_POOL_DRIVER_FUNC
 */
WINTUN_DELETE_POOL_DRIVER_FUNC_IMPL WintunDeletePoolDriver;

/**
 * @copydoc WINTUN_GET_ADAPTER_LUID_FUNC
 */
WINTUN_GET_ADAPTER_LUID_FUNC_IMPL WintunGetAdapterLUID;

/**
 * @copydoc WINTUN_GET_ADAPTER_NAME_FUNC
 */
WINTUN_GET_ADAPTER_NAME_FUNC_IMPL WintunGetAdapterName;

/**
 * @copydoc WINTUN_SET_ADAPTER_NAME_FUNC
 */
WINTUN_SET_ADAPTER_NAME_FUNC_IMPL WintunSetAdapterName;

/**
 * @copydoc WINTUN_GET_RUNNING_DRIVER_VERSION_FUNC
 */
WINTUN_GET_RUNNING_DRIVER_VERSION_FUNC_IMPL WintunGetRunningDriverVersion;

/**
 * Returns a handle to the adapter device object.
 *
 * @param Adapter       Adapter handle obtained with WintunOpenAdapter or WintunCreateAdapter.
 *
 * @return If the function succeeds, the return value is adapter device object handle.
 *         If the function fails, the return value is INVALID_HANDLE_VALUE. To get extended error
 *         information, call GetLastError.
 */
_Return_type_success_(return != INVALID_HANDLE_VALUE)
HANDLE WINAPI
AdapterOpenDeviceObject(_In_ const WINTUN_ADAPTER *Adapter);
/**
 * Returns an adapter object based on a devnode instance ID.
 *
 * @param Pool          Pool name of adapter object to be opened.
 *
 * @param DevInstanceID Instance ID of devnode for opening adapter.
 *
 * @return If the function succeeds, the return value is adapter object..
 *         If the function fails, the return value is NULL. To get extended error
 *         information, call GetLastError.
 */
_Must_inspect_result_
_Return_type_success_(return != NULL)
_Post_maybenull_
WINTUN_ADAPTER *
AdapterOpenFromDevInstanceId(_In_z_ LPCWSTR Pool, _In_z_ LPCWSTR DevInstanceID);

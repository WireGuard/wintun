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

typedef struct _SP_DEVINFO_DATA_LIST
{
    SP_DEVINFO_DATA Data;
    struct _SP_DEVINFO_DATA_LIST *Next;
} SP_DEVINFO_DATA_LIST;

/**
 * Retrieves driver information detail for a device information set or a particular device information element in the
 * device information set.
 *
 * @param DevInfo       A handle to the device information set that contains a device information element that
 *                      represents the device for which to retrieve driver information.
 *
 * @param DevInfoData   A pointer to a structure that specifies the device information element in DevInfo.
 *
 * @param DrvInfoData   A pointer to a structure that specifies the driver information element that represents the
 *                      driver for which to retrieve details.
 *
 * @param DrvInfoDetailData  A pointer to a structure that receives detailed information about the specified driver.
 *                      Must be released with HeapFree(ModuleHeap, 0, *DrvInfoDetailData) after use.
 *
 * @return ERROR_SUCCESS on success; Win32 error code otherwise.
 */
WINTUN_STATUS
AdapterGetDrvInfoDetail(
    _In_ HDEVINFO DevInfo,
    _In_opt_ SP_DEVINFO_DATA *DevInfoData,
    _In_ SP_DRVINFO_DATA_W *DrvInfoData,
    _Out_ SP_DRVINFO_DETAIL_DATA_W **DrvInfoDetailData);

/**
 * Disables all Wintun adapters.
 *
 * @param DevInfo       A handle to the device information set.
 *
 * @param DisabledAdapters  Output list of disabled adapters. The adapters disabled are inserted in the list head.
 *
 * @return ERROR_SUCCESS on success; Win32 error code otherwise.
 */
WINTUN_STATUS
AdapterDisableAllOurs(_In_ HDEVINFO DevInfo, _Inout_ SP_DEVINFO_DATA_LIST **DisabledAdapters);

/**
 * Enables all adapters.
 *
 * @param DevInfo       A handle to the device information set.
 *
 * @param AdaptersToEnable  Input list of adapters to enable.
 *
 * @return ERROR_SUCCESS on success; Win32 error code otherwise.
 */
WINTUN_STATUS
AdapterEnableAll(_In_ HDEVINFO DevInfo, _In_ SP_DEVINFO_DATA_LIST *AdaptersToEnable);

/**
 * Removes all Wintun adapters.
 *
 * @return ERROR_SUCCESS on success; Win32 error code otherwise.
 */
WINTUN_STATUS
AdapterDeleteAllOurs(void);

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
    _In_z_count_c_(WINTUN_MAX_POOL) const WCHAR *Pool,
    _In_z_count_c_(MAX_ADAPTER_NAME) const WCHAR *Name,
    _In_opt_ const GUID *RequestedGUID,
    _Out_ WINTUN_ADAPTER **Adapter,
    _Out_opt_ BOOL *RebootRequired);

/**
 * @copydoc WINTUN_DELETE_ADAPTER_FUNC
 */
WINTUN_STATUS WINAPI
WintunDeleteAdapter(_In_ const WINTUN_ADAPTER *Adapter, _In_ BOOL ForceCloseSessions, _Out_opt_ BOOL *RebootRequired);

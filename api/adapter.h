/* SPDX-License-Identifier: GPL-2.0
 *
 * Copyright (C) 2018-2020 WireGuard LLC. All Rights Reserved.
 */

#pragma once

#include "api.h"
#include <SetupAPI.h>
#include <IPExport.h>

#define MAX_POOL 256
#define MAX_INSTANCE_ID MAX_PATH /* TODO: Is MAX_PATH always enough? */

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
 *                      Must be released with HeapFree(GetProcessHeap(), 0, *DrvInfoDetailData) after use.
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
AdapterDeleteAllOurs();

void
AdapterInit();

void
AdapterCleanup();

typedef struct _WINTUN_ADAPTER
{
    GUID CfgInstanceID;
    WCHAR DevInstanceID[MAX_INSTANCE_ID];
    DWORD LuidIndex;
    DWORD IfType;
    WCHAR Pool[MAX_POOL];
} WINTUN_ADAPTER;

/**
 * Releases Wintun adapter resources.
 *
 * @param Adapter       Adapter handle obtained with WintunGetAdapter or WintunCreateAdapter.
 */
void WINAPI
WintunFreeAdapter(_In_ WINTUN_ADAPTER *Adapter);

/**
 * Finds a Wintun adapter by its name.
 *
 * @param Pool          Name of the adapter pool.
 *
 * @param Name          Adapter name.
 *
 * @param Adapter       Pointer to a handle to receive the adapter handle. Must be released with WintunFreeAdapter.
 *
 * @return ERROR_SUCCESS on success; ERROR_FILE_NOT_FOUND if adapter with given name is not found; ERROR_ALREADY_EXISTS
 * if adapter is found but not a Wintun-class or not a member of the pool; Win32 error code otherwise
 */
WINTUN_STATUS WINAPI
WintunGetAdapter(
    _In_z_count_c_(MAX_POOL) const WCHAR *Pool,
    _In_z_count_c_(MAX_ADAPTER_NAME) const WCHAR *Name,
    _Out_ WINTUN_ADAPTER **Adapter);

/**
 * Returns the name of the Wintun adapter.
 *
 * @param Adapter       Adapter handle obtained with WintunGetAdapter or WintunCreateAdapter
 *
 * @param Name          Pointer to a string to receive adapter name
 *
 * @return ERROR_SUCCESS on success; Win32 error code otherwise.
 */
WINTUN_STATUS WINAPI
WintunGetAdapterName(_In_ const WINTUN_ADAPTER *Adapter, _Out_cap_c_(MAX_ADAPTER_NAME) WCHAR *Name);

/**
 * Sets name of the Wintun adapter.
 *
 * @param Adapter       Adapter handle obtained with WintunGetAdapter or WintunCreateAdapter
 *
 * @param Name          Adapter name
 *
 * @return ERROR_SUCCESS on success; Win32 error code otherwise.
 */
WINTUN_STATUS WINAPI
WintunSetAdapterName(_In_ const WINTUN_ADAPTER *Adapter, _In_z_count_c_(MAX_ADAPTER_NAME) const WCHAR *Name);

/**
 * Returns the GUID of the adapter.
 *
 * @param Adapter       Adapter handle obtained with WintunGetAdapter or WintunCreateAdapter
 *
 * @param Guid          Pointer to GUID to receive adapter ID.
 */
void WINAPI
WintunGetAdapterGUID(_In_ const WINTUN_ADAPTER *Adapter, _Out_ GUID *Guid);

/**
 * Returns the LUID of the adapter.
 *
 * @param Adapter       Adapter handle obtained with WintunGetAdapter or WintunCreateAdapter
 *
 * @param Luid          Pointer to LUID to receive adapter LUID.
 */
void WINAPI
WintunGetAdapterLUID(_In_ const WINTUN_ADAPTER *Adapter, _Out_ LUID *Luid);

/**
 * Returns a handle to the adapter device object.
 *
 * @param Adapter       Adapter handle obtained with WintunGetAdapter or WintunCreateAdapter.
 *
 * @param Handle        Pointer to receive the adapter device object handle. Must be released with CloseHandle.
 *
 * @return ERROR_SUCCESS on success; Win32 error code otherwise.
 */
WINTUN_STATUS WINAPI
WintunGetAdapterDeviceObject(_In_ const WINTUN_ADAPTER *Adapter, _Out_ HANDLE *Handle);

/**
 * Creates a Wintun adapter.
 *
 * @param Pool          Name of the adapter pool.
 *
 * @param Name          The requested name of the adapter.
 *
 * @param RequestedGUID  The GUID of the created network adapter, which then influences NLA generation
 *                      deterministically. If it is set to NULL, the GUID is chosen by the system at random, and hence
 *                      a new NLA entry is created for each new adapter. It is called "requested" GUID because the API
 *                      it uses is completely undocumented, and so there could be minor interesting complications with
 *                      its usage.
 *
 * @param Adapter       Pointer to a handle to receive the adapter handle. Must be released with
 *                      WintunFreeAdapter.
 *
 * @param RebootRequired  Pointer to a boolean flag to be set to TRUE in case SetupAPI suggests a reboot. Must be
 *                      initialised to FALSE manually before this function is called.
 *
 * @return ERROR_SUCCESS on success; Win32 error code otherwise.
 */
WINTUN_STATUS WINAPI
WintunCreateAdapter(
    _In_z_count_c_(MAX_POOL) const WCHAR *Pool,
    _In_z_count_c_(MAX_ADAPTER_NAME) const WCHAR *Name,
    _In_opt_ const GUID *RequestedGUID,
    _Out_ WINTUN_ADAPTER **Adapter,
    _Inout_ BOOL *RebootRequired);

/**
 * Deletes a Wintun adapter.
 *
 * @param Adapter       Adapter handle obtained with WintunGetAdapter or WintunCreateAdapter.
 *
 * @param RebootRequired  Pointer to a boolean flag to be set to TRUE in case SetupAPI suggests a reboot. Must be
 *                      initialised to FALSE manually before this function is called.
 *
 * @return ERROR_SUCCESS on success or the adapter was not found; Win32 error code otherwise.
 */
WINTUN_STATUS WINAPI
WintunDeleteAdapter(_In_ const WINTUN_ADAPTER *Adapter, _Inout_ BOOL *RebootRequired);

typedef BOOL(CALLBACK *WINTUN_ENUM_FUNC)(_In_ const WINTUN_ADAPTER *Adapter, _In_ LPARAM Param);

/**
 * Enumerates all Wintun adapters.
 *
 * @param Pool          Name of the adapter pool.
 *
 * @param Func          Callback function. To continue enumeration, the callback function must return TRUE; to stop
 *                      enumeration, it must return FALSE.
 *
 * @param Param         An application-defined value to be passed to the callback function.
 *
 * @return ERROR_SUCCESS on success; Win32 error code otherwise.
 */
WINTUN_STATUS WINAPI
WintunEnumAdapters(_In_z_count_c_(MAX_POOL) const WCHAR *Pool, _In_ WINTUN_ENUM_FUNC Func, _In_ LPARAM Param);

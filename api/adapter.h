/* SPDX-License-Identifier: GPL-2.0
 *
 * Copyright (C) 2018-2021 WireGuard LLC. All Rights Reserved.
 */

#pragma once

#include "wintun.h"
#include <IPExport.h>
#include <SetupAPI.h>
#include <cfgmgr32.h>
#include <Windows.h>

#define WINTUN_HWID L"Wintun"
#define WINTUN_ENUMERATOR (IsWindows7 ? L"ROOT\\" WINTUN_HWID : L"SWD\\" WINTUN_HWID)

extern const DEVPROPKEY DEVPKEY_Wintun_Name;

typedef struct HSWDEVICE__ *HSWDEVICE;

/**
 * Wintun adapter descriptor.
 */
typedef struct _WINTUN_ADAPTER
{
    HSWDEVICE SwDevice;
    HDEVINFO DevInfo;
    SP_DEVINFO_DATA DevInfoData;
    WCHAR *InterfaceFilename;
    GUID CfgInstanceID;
    WCHAR DevInstanceID[MAX_DEVICE_ID_LEN];
    DWORD LuidIndex;
    DWORD IfType;
    DWORD IfIndex;
} WINTUN_ADAPTER;
/**
 * @copydoc WINTUN_CREATE_ADAPTER_FUNC
 */
WINTUN_CREATE_ADAPTER_FUNC WintunCreateAdapter;

/**
 * @copydoc WINTUN_OPEN_ADAPTER_FUNC
 */
WINTUN_OPEN_ADAPTER_FUNC WintunOpenAdapter;

/**
 * @copydoc WINTUN_CLOSE_ADAPTER_FUNC
 */
WINTUN_CLOSE_ADAPTER_FUNC WintunCloseAdapter;

/**
 * @copydoc WINTUN_GET_ADAPTER_LUID_FUNC
 */
WINTUN_GET_ADAPTER_LUID_FUNC WintunGetAdapterLUID;

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
 * Returns the device object file name for an adapter instance ID.
 *
 * @param InstanceID       The device instance ID of the adapter.
 *
 * @return If the function succeeds, the return value is the filename of the device object, which
 *         must be freed with Free(). If the function fails, the return value is INVALID_HANDLE_VALUE.
 *         To get extended error information, call GetLastError.
 */
_Must_inspect_result_
_Return_type_success_(return != NULL)
_Post_maybenull_
LPWSTR
AdapterGetDeviceObjectFileName(_In_z_ LPCWSTR InstanceId);

/**
 * Cleans up adapters with no attached process.
 */
VOID AdapterCleanupOrphanedDevices(VOID);

/**
 * Cleans up adapters that use the old enumerator.
 */
VOID AdapterCleanupLegacyDevices(VOID);

/**
 * Removes the specified device instance.
 *
 * @param DevInfo      Device info handle from SetupAPI.
 * @param DevInfoData  Device info data specifying which device.
 *
 * @return If the function succeeds, the return value is TRUE. If the
 *         function fails, the return value is FALSE. To get extended
 *         error information, call GetLastError.
 */

_Return_type_success_(return != FALSE)
BOOL
AdapterRemoveInstance(_In_ HDEVINFO DevInfo, _In_ SP_DEVINFO_DATA *DevInfoData);

/**
 * Enables the specified device instance.
 *
 * @param DevInfo      Device info handle from SetupAPI.
 * @param DevInfoData  Device info data specifying which device.
 *
 * @return If the function succeeds, the return value is TRUE. If the
 *         function fails, the return value is FALSE. To get extended
 *         error information, call GetLastError.
 */

_Return_type_success_(return != FALSE)
BOOL
AdapterEnableInstance(_In_ HDEVINFO DevInfo, _In_ SP_DEVINFO_DATA *DevInfoData);

/**
 * Disables the specified device instance.
 *
 * @param DevInfo      Device info handle from SetupAPI.
 * @param DevInfoData  Device info data specifying which device.
 *
 * @return If the function succeeds, the return value is TRUE. If the
 *         function fails, the return value is FALSE. To get extended
 *         error information, call GetLastError.
 */

_Return_type_success_(return != FALSE)
BOOL
AdapterDisableInstance(_In_ HDEVINFO DevInfo, _In_ SP_DEVINFO_DATA *DevInfoData);

/* SPDX-License-Identifier: GPL-2.0
 *
 * Copyright (C) 2018-2021 WireGuard LLC. All Rights Reserved.
 */

#include <WinSock2.h>
#include <Windows.h>
#include <winternl.h>
#include <cfgmgr32.h>
#include <devguid.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>
#include <ndisguid.h>
#include <SetupAPI.h>
#include <Shlwapi.h>
#include <shellapi.h>
#include <wchar.h>
#include <initguid.h> /* Keep these two at bottom in this order, so that we only generate extra GUIDs for devpkey. The other keys we'll get from uuid.lib like usual. */
#include <devpkey.h>
#include <devioctl.h>

#include "adapter.h"
#include "logger.h"
#include "main.h"
#include "namespace.h"
#include "nci.h"
#include "ntdll.h"
#include "registry.h"
#include "resource.h"
#include "rundll32.h"
#include "wintun-inf.h"

#pragma warning(disable : 4221) /* nonstandard: address of automatic in initializer */

#define WAIT_FOR_REGISTRY_TIMEOUT 10000            /* ms */
#define MAX_POOL_DEVICE_TYPE (WINTUN_MAX_POOL + 8) /* Should accommodate a pool name with " Tunnel" appended */

static const DEVPROPKEY DEVPKEY_Wintun_Pool = {
    { 0xaba51201, 0xdf7a, 0x3a38, { 0x0a, 0xd9, 0x90, 0x64, 0x42, 0xd2, 0x71, 0xae } },
    DEVPROPID_FIRST_USABLE + 0
};

static const DEVPROPKEY DEVPKEY_Wintun_Name = {
    { 0x3361c968, 0x2f2e, 0x4660, { 0xb4, 0x7e, 0x69, 0x9c, 0xdc, 0x4c, 0x32, 0xb9 } },
    DEVPROPID_FIRST_USABLE + 1
};

typedef struct _SP_DEVINFO_DATA_LIST
{
    SP_DEVINFO_DATA Data;
    struct _SP_DEVINFO_DATA_LIST *Next;
} SP_DEVINFO_DATA_LIST;

_Must_inspect_result_
static _Return_type_success_(return != NULL)
_Post_maybenull_
SP_DRVINFO_DETAIL_DATA_W *
GetAdapterDrvInfoDetail(
    _In_ HDEVINFO DevInfo,
    _In_opt_ SP_DEVINFO_DATA *DevInfoData,
    _In_ SP_DRVINFO_DATA_W *DrvInfoData)
{
    DWORD Size = sizeof(SP_DRVINFO_DETAIL_DATA_W) + 0x100;
    for (;;)
    {
        SP_DRVINFO_DETAIL_DATA_W *DrvInfoDetailData = Alloc(Size);
        if (!DrvInfoDetailData)
            return NULL;
        DrvInfoDetailData->cbSize = sizeof(SP_DRVINFO_DETAIL_DATA_W);
        if (SetupDiGetDriverInfoDetailW(DevInfo, DevInfoData, DrvInfoData, DrvInfoDetailData, Size, &Size))
            return DrvInfoDetailData;
        DWORD LastError = GetLastError();
        Free(DrvInfoDetailData);
        if (LastError != ERROR_INSUFFICIENT_BUFFER)
        {
            if (DevInfoData)
                LOG_ERROR(LastError, L"Failed for adapter %u", DevInfoData->DevInst);
            else
                LOG_ERROR(LastError, L"Failed");
            SetLastError(LastError);
            return NULL;
        }
    }
}

_Must_inspect_result_
static _Return_type_success_(return != NULL)
_Post_maybenull_
_Post_writable_byte_size_(*BufLen)
VOID *
GetDeviceRegistryProperty(
    _In_ HDEVINFO DevInfo,
    _In_ SP_DEVINFO_DATA *DevInfoData,
    _In_ DWORD Property,
    _Out_opt_ DWORD *ValueType,
    _Inout_ DWORD *BufLen)
{
    for (;;)
    {
        BYTE *Data = Alloc(*BufLen);
        if (!Data)
            return NULL;
        if (SetupDiGetDeviceRegistryPropertyW(DevInfo, DevInfoData, Property, ValueType, Data, *BufLen, BufLen))
            return Data;
        DWORD LastError = GetLastError();
        Free(Data);
        if (LastError != ERROR_INSUFFICIENT_BUFFER)
        {
            SetLastError(
                LOG_ERROR(LastError, L"Failed to query adapter %u property 0x%x", DevInfoData->DevInst, Property));
            return NULL;
        }
    }
}

_Must_inspect_result_
static _Return_type_success_(return != NULL)
_Post_maybenull_
LPWSTR
GetDeviceRegistryString(_In_ HDEVINFO DevInfo, _In_ SP_DEVINFO_DATA *DevInfoData, _In_ DWORD Property)
{
    DWORD LastError, ValueType, Size = 256 * sizeof(WCHAR);
    LPWSTR Buf = GetDeviceRegistryProperty(DevInfo, DevInfoData, Property, &ValueType, &Size);
    if (!Buf)
        return NULL;
    switch (ValueType)
    {
    case REG_SZ:
    case REG_EXPAND_SZ:
    case REG_MULTI_SZ:
        if (RegistryGetString(&Buf, Size / sizeof(*Buf), ValueType))
            return Buf;
        LastError = GetLastError();
        break;
    default:
        LOG(WINTUN_LOG_ERR,
            L"Adapter %u property 0x%x is not a string (type: %u)",
            DevInfoData->DevInst,
            Property,
            ValueType);
        LastError = ERROR_INVALID_DATATYPE;
    }
    Free(Buf);
    SetLastError(LastError);
    return NULL;
}

_Must_inspect_result_
static _Return_type_success_(return != NULL)
_Post_maybenull_
PZZWSTR
GetDeviceRegistryMultiString(_In_ HDEVINFO DevInfo, _In_ SP_DEVINFO_DATA *DevInfoData, _In_ DWORD Property)
{
    DWORD LastError, ValueType, Size = 256 * sizeof(WCHAR);
    PZZWSTR Buf = GetDeviceRegistryProperty(DevInfo, DevInfoData, Property, &ValueType, &Size);
    if (!Buf)
        return NULL;
    switch (ValueType)
    {
    case REG_SZ:
    case REG_EXPAND_SZ:
    case REG_MULTI_SZ:
        if (RegistryGetMultiString(&Buf, Size / sizeof(*Buf), ValueType))
            return Buf;
        LastError = GetLastError();
        break;
    default:
        LOG(WINTUN_LOG_ERR,
            L"Adapter %u property 0x%x is not a string (type: %u)",
            DevInfoData->DevInst,
            Property,
            ValueType);
        LastError = ERROR_INVALID_DATATYPE;
    }
    Free(Buf);
    SetLastError(LastError);
    return NULL;
}

static BOOL
IsOurHardwareID(_In_z_ PCZZWSTR Hwids)
{
    for (; Hwids[0]; Hwids += wcslen(Hwids) + 1)
        if (!_wcsicmp(Hwids, WINTUN_HWID))
            return TRUE;
    return FALSE;
}

static BOOL
IsOurAdapter(_In_ HDEVINFO DevInfo, _In_ SP_DEVINFO_DATA *DevInfoData)
{
    PZZWSTR Hwids = GetDeviceRegistryMultiString(DevInfo, DevInfoData, SPDRP_HARDWAREID);
    if (!Hwids)
    {
        LOG_LAST_ERROR(L"Failed to get adapter %u hardware ID", DevInfoData->DevInst);
        return FALSE;
    }
    BOOL IsOurs = IsOurHardwareID(Hwids);
    Free(Hwids);
    return IsOurs;
}

_Must_inspect_result_
static _Return_type_success_(return != NULL)
_Post_maybenull_
LPWSTR
GetDeviceObjectFileName(_In_z_ LPCWSTR InstanceId)
{
    ULONG InterfacesLen;
    DWORD LastError = CM_MapCrToWin32Err(
        CM_Get_Device_Interface_List_SizeW(
            &InterfacesLen,
            (GUID *)&GUID_DEVINTERFACE_NET,
            (DEVINSTID_W)InstanceId,
            CM_GET_DEVICE_INTERFACE_LIST_PRESENT),
        ERROR_GEN_FAILURE);
    if (LastError != ERROR_SUCCESS)
    {
        SetLastError(LOG_ERROR(LastError, L"Failed to query adapter %s associated instances size", InstanceId));
        return NULL;
    }
    LPWSTR Interfaces = AllocArray(InterfacesLen, sizeof(*Interfaces));
    if (!Interfaces)
        return NULL;
    LastError = CM_MapCrToWin32Err(
        CM_Get_Device_Interface_ListW(
            (GUID *)&GUID_DEVINTERFACE_NET,
            (DEVINSTID_W)InstanceId,
            Interfaces,
            InterfacesLen,
            CM_GET_DEVICE_INTERFACE_LIST_PRESENT),
        ERROR_GEN_FAILURE);
    if (LastError != ERROR_SUCCESS)
    {
        LOG_ERROR(LastError, L"Failed to get adapter %s associated instances", InstanceId);
        Free(Interfaces);
        SetLastError(LastError);
        return NULL;
    }
    if (!Interfaces[0])
    {
        Free(Interfaces);
        SetLastError(ERROR_DEVICE_NOT_AVAILABLE);
        return NULL;
    }
    return Interfaces;
}

_Must_inspect_result_
static _Return_type_success_(return != INVALID_HANDLE_VALUE)
HANDLE
OpenDeviceObject(_In_z_ LPCWSTR InstanceId)
{
    LPWSTR Filename = GetDeviceObjectFileName(InstanceId);
    if (!Filename)
        return INVALID_HANDLE_VALUE;
    HANDLE Handle = CreateFileW(
        Filename,
        GENERIC_READ | GENERIC_WRITE,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        NULL,
        OPEN_EXISTING,
        0,
        NULL);
    if (Handle == INVALID_HANDLE_VALUE)
        LOG_LAST_ERROR(L"Failed to connect to adapter %s associated instance %s", InstanceId, Filename);
    Free(Filename);
    return Handle;
}

static BOOL
EnsureDeviceObject(_In_z_ LPCWSTR InstanceId)
{
    LPWSTR Filename = GetDeviceObjectFileName(InstanceId);
    if (!Filename)
    {
        LOG_LAST_ERROR(L"Failed to determine adapter %s device object", InstanceId);
        return FALSE;
    }
    BOOL Exists = TRUE;
    const int Attempts = 100;
    for (int i = 0; i < Attempts; ++i)
    {
        HANDLE Handle = CreateFileW(Filename, 0, 0, NULL, OPEN_EXISTING, 0, NULL);
        if (Handle != INVALID_HANDLE_VALUE)
        {
            CloseHandle(Handle);
            goto out;
        }
        if (i != Attempts - 1)
            Sleep(50);
    }
    Exists = FALSE;
    LOG_LAST_ERROR(L"Failed to connect to adapter %s associated instance %s", InstanceId, Filename);
out:
    Free(Filename);
    return Exists;
}

#define TUN_IOCTL_FORCE_CLOSE_HANDLES CTL_CODE(51820U, 0x971U, METHOD_NEITHER, FILE_READ_DATA | FILE_WRITE_DATA)

static _Return_type_success_(return != FALSE)
BOOL
ForceCloseWintunAdapterHandle(_In_ HDEVINFO DevInfo, _In_ SP_DEVINFO_DATA *DevInfoData)
{
    DWORD LastError = ERROR_SUCCESS;
    DWORD RequiredBytes;
    if (SetupDiGetDeviceInstanceIdW(DevInfo, DevInfoData, NULL, 0, &RequiredBytes) ||
        (LastError = GetLastError()) != ERROR_INSUFFICIENT_BUFFER)
    {
        LOG_ERROR(LastError, L"Failed to query adapter %u instance ID size", DevInfoData->DevInst);
        return FALSE;
    }
    LastError = ERROR_SUCCESS;
    LPWSTR InstanceId = ZallocArray(RequiredBytes, sizeof(*InstanceId));
    if (!InstanceId)
        return FALSE;
    if (!SetupDiGetDeviceInstanceIdW(DevInfo, DevInfoData, InstanceId, RequiredBytes, &RequiredBytes))
    {
        LastError = LOG_LAST_ERROR(L"Failed to get adapter %u instance ID", DevInfoData->DevInst);
        goto cleanupInstanceId;
    }
    HANDLE NdisHandle = OpenDeviceObject(InstanceId);
    if (NdisHandle == INVALID_HANDLE_VALUE)
    {
        LastError = LOG(WINTUN_LOG_ERR, L"Failed to get adapter %u object", DevInfoData->DevInst);
        goto cleanupInstanceId;
    }
    if (DeviceIoControl(NdisHandle, TUN_IOCTL_FORCE_CLOSE_HANDLES, NULL, 0, NULL, 0, &RequiredBytes, NULL))
    {
        LastError = ERROR_SUCCESS;
        Sleep(200);
    }
    else if (GetLastError() == ERROR_NOTHING_TO_TERMINATE)
        LastError = ERROR_SUCCESS;
    else
        LastError = LOG_LAST_ERROR(L"Failed to perform ioctl on adapter %u", DevInfoData->DevInst);
    CloseHandle(NdisHandle);
cleanupInstanceId:
    Free(InstanceId);
    return RET_ERROR(TRUE, LastError);
}

static _Return_type_success_(return != FALSE)
BOOL
DisableAllOurAdapters(_In_ HDEVINFO DevInfo, _Inout_ SP_DEVINFO_DATA_LIST **DisabledAdapters)
{
    SP_PROPCHANGE_PARAMS Params = { .ClassInstallHeader = { .cbSize = sizeof(SP_CLASSINSTALL_HEADER),
                                                            .InstallFunction = DIF_PROPERTYCHANGE },
                                    .StateChange = DICS_DISABLE,
                                    .Scope = DICS_FLAG_GLOBAL };
    DWORD LastError = ERROR_SUCCESS;
    for (DWORD EnumIndex = 0;; ++EnumIndex)
    {
        SP_DEVINFO_DATA_LIST *DeviceNode = Zalloc(sizeof(*DeviceNode));
        if (!DeviceNode)
            return FALSE;
        DeviceNode->Data.cbSize = sizeof(SP_DEVINFO_DATA);
        if (!SetupDiEnumDeviceInfo(DevInfo, EnumIndex, &DeviceNode->Data))
        {
            if (GetLastError() == ERROR_NO_MORE_ITEMS)
            {
                Free(DeviceNode);
                break;
            }
            goto cleanupDeviceNode;
        }
        if (!IsOurAdapter(DevInfo, &DeviceNode->Data))
            goto cleanupDeviceNode;

        ULONG Status, ProblemCode;
        if (CM_Get_DevNode_Status(&Status, &ProblemCode, DeviceNode->Data.DevInst, 0) != CR_SUCCESS ||
            ((Status & DN_HAS_PROBLEM) && ProblemCode == CM_PROB_DISABLED))
            goto cleanupDeviceNode;

        LOG(WINTUN_LOG_INFO, L"Force closing all adapter %u open handles", DeviceNode->Data.DevInst);
        if (!ForceCloseWintunAdapterHandle(DevInfo, &DeviceNode->Data))
            LOG(WINTUN_LOG_WARN, L"Failed to force close adapter %u handles", DeviceNode->Data.DevInst);

        LOG(WINTUN_LOG_INFO, L"Disabling adapter %u", DeviceNode->Data.DevInst);
        if (!SetupDiSetClassInstallParamsW(DevInfo, &DeviceNode->Data, &Params.ClassInstallHeader, sizeof(Params)) ||
            !SetupDiCallClassInstaller(DIF_PROPERTYCHANGE, DevInfo, &DeviceNode->Data))
        {
            LOG_LAST_ERROR(L"Failed to disable adapter %u", DeviceNode->Data.DevInst);
            LastError = LastError != ERROR_SUCCESS ? LastError : GetLastError();
            goto cleanupDeviceNode;
        }

        DeviceNode->Next = *DisabledAdapters;
        *DisabledAdapters = DeviceNode;
        continue;

    cleanupDeviceNode:
        Free(DeviceNode);
    }
    return RET_ERROR(TRUE, LastError);
}

static _Return_type_success_(return != FALSE)
BOOL
EnableAllOurAdapters(_In_ HDEVINFO DevInfo, _In_ SP_DEVINFO_DATA_LIST *AdaptersToEnable)
{
    SP_PROPCHANGE_PARAMS Params = { .ClassInstallHeader = { .cbSize = sizeof(SP_CLASSINSTALL_HEADER),
                                                            .InstallFunction = DIF_PROPERTYCHANGE },
                                    .StateChange = DICS_ENABLE,
                                    .Scope = DICS_FLAG_GLOBAL };
    DWORD LastError = ERROR_SUCCESS;
    for (SP_DEVINFO_DATA_LIST *DeviceNode = AdaptersToEnable; DeviceNode; DeviceNode = DeviceNode->Next)
    {
        LOG(WINTUN_LOG_INFO, L"Enabling adapter %u", DeviceNode->Data.DevInst);
        if (!SetupDiSetClassInstallParamsW(DevInfo, &DeviceNode->Data, &Params.ClassInstallHeader, sizeof(Params)) ||
            !SetupDiCallClassInstaller(DIF_PROPERTYCHANGE, DevInfo, &DeviceNode->Data))
        {
            LOG_LAST_ERROR(L"Failed to enable adapter %u", DeviceNode->Data.DevInst);
            LastError = LastError != ERROR_SUCCESS ? LastError : GetLastError();
        }
    }
    return RET_ERROR(TRUE, LastError);
}

static BOOL
CheckReboot(_In_ HDEVINFO DevInfo, _In_ SP_DEVINFO_DATA *DevInfoData)
{
    SP_DEVINSTALL_PARAMS_W DevInstallParams = { .cbSize = sizeof(SP_DEVINSTALL_PARAMS_W) };
    if (!SetupDiGetDeviceInstallParamsW(DevInfo, DevInfoData, &DevInstallParams))
    {
        LOG_LAST_ERROR(L"Failed to retrieve adapter %u device installation parameters", DevInfoData->DevInst);
        return FALSE;
    }
    SetLastError(ERROR_SUCCESS);
    return (DevInstallParams.Flags & (DI_NEEDREBOOT | DI_NEEDRESTART)) != 0;
}

_Must_inspect_result_
static _Return_type_success_(return != FALSE)
BOOL
GetPoolDeviceTypeName(_In_z_ LPCWSTR Pool, _Out_writes_z_(MAX_POOL_DEVICE_TYPE) LPWSTR Name)
{
    if (_snwprintf_s(Name, MAX_POOL_DEVICE_TYPE, _TRUNCATE, L"%s Tunnel", Pool) == -1)
    {
        LOG(WINTUN_LOG_ERR, L"Pool name too long: %s", Pool);
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }
    return TRUE;
}

static BOOL
IsPoolMember(_In_z_ LPCWSTR Pool, _In_ HDEVINFO DevInfo, _In_ SP_DEVINFO_DATA *DevInfoData)
{
    WCHAR PoolProp[MAX_POOL_DEVICE_TYPE];
    DEVPROPTYPE PropType;
    if (!SetupDiGetDevicePropertyW(
            DevInfo, DevInfoData, &DEVPKEY_Wintun_Pool, &PropType, (PBYTE)PoolProp, sizeof(PoolProp), NULL, 0))
        return FALSE;
    if (PropType != DEVPROP_TYPE_STRING)
    {
        SetLastError(ERROR_BAD_DEVICE);
        return FALSE;
    }
    SetLastError(ERROR_SUCCESS);
    return !_wcsicmp(PoolProp, Pool);
}

_Must_inspect_result_
static _Return_type_success_(return != FALSE)
BOOL
PopulateAdapterData(_Inout_ WINTUN_ADAPTER *Adapter, _In_z_ LPCWSTR Pool)
{
    DWORD LastError = ERROR_SUCCESS;

    /* Open HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\<class>\<id> registry key. */
    HKEY Key =
        SetupDiOpenDevRegKey(Adapter->DevInfo, &Adapter->DevInfoData, DICS_FLAG_GLOBAL, 0, DIREG_DRV, KEY_QUERY_VALUE);
    if (Key == INVALID_HANDLE_VALUE)
    {
        LOG_LAST_ERROR(L"Failed to open adapter %u device registry key", Adapter->DevInfoData.DevInst);
        return FALSE;
    }

    LPWSTR ValueStr = RegistryQueryString(Key, L"NetCfgInstanceId", TRUE);
    if (!ValueStr)
    {
        WCHAR RegPath[MAX_REG_PATH];
        LoggerGetRegistryKeyPath(Key, RegPath);
        LastError = LOG(WINTUN_LOG_ERR, L"Failed to get %.*s\\NetCfgInstanceId", MAX_REG_PATH, RegPath);
        goto cleanupKey;
    }
    if (FAILED(CLSIDFromString(ValueStr, &Adapter->CfgInstanceID)))
    {
        WCHAR RegPath[MAX_REG_PATH];
        LoggerGetRegistryKeyPath(Key, RegPath);
        LastError = LOG(WINTUN_LOG_ERR, L"%.*s\\NetCfgInstanceId is not a GUID: %s", MAX_REG_PATH, RegPath, ValueStr);
        Free(ValueStr);
        goto cleanupKey;
    }
    Free(ValueStr);

    if (!RegistryQueryDWORD(Key, L"NetLuidIndex", &Adapter->LuidIndex, TRUE))
    {
        WCHAR RegPath[MAX_REG_PATH];
        LoggerGetRegistryKeyPath(Key, RegPath);
        LastError = LOG(WINTUN_LOG_ERR, L"Failed to get %.*s\\NetLuidIndex", MAX_REG_PATH, RegPath);
        goto cleanupKey;
    }

    if (!RegistryQueryDWORD(Key, L"*IfType", &Adapter->IfType, TRUE))
    {
        WCHAR RegPath[MAX_REG_PATH];
        LoggerGetRegistryKeyPath(Key, RegPath);
        LastError = LOG(WINTUN_LOG_ERR, L"Failed to get %.*s\\*IfType", MAX_REG_PATH, RegPath);
        goto cleanupKey;
    }

    DWORD Size;
    if (!SetupDiGetDeviceInstanceIdW(
            Adapter->DevInfo, &Adapter->DevInfoData, Adapter->DevInstanceID, _countof(Adapter->DevInstanceID), &Size))
    {
        LastError = LOG_LAST_ERROR(L"Failed to get adapter %u instance ID", Adapter->DevInfoData.DevInst);
        goto cleanupKey;
    }

    if (wcsncpy_s(Adapter->Pool, _countof(Adapter->Pool), Pool, _TRUNCATE) == STRUNCATE)
    {
        LOG(WINTUN_LOG_ERR, L"Pool name too long: %s", Pool);
        LastError = ERROR_INVALID_PARAMETER;
        goto cleanupKey;
    }

cleanupKey:
    RegCloseKey(Key);
    return RET_ERROR(TRUE, LastError);
}

_Use_decl_annotations_
VOID WINAPI
WintunFreeAdapter(WINTUN_ADAPTER *Adapter)
{
    if (!Adapter)
        return;
    if (Adapter->DevInfo)
        SetupDiDestroyDeviceInfoList(Adapter->DevInfo);
    Free(Adapter);
}

_Use_decl_annotations_
BOOL WINAPI
WintunGetAdapterName(WINTUN_ADAPTER *Adapter, LPWSTR Name)
{
    DEVPROPTYPE PropType;
    if (!SetupDiGetDevicePropertyW(
            Adapter->DevInfo,
            &Adapter->DevInfoData,
            &DEVPKEY_Wintun_Name,
            &PropType,
            (PBYTE)Name,
            MAX_ADAPTER_NAME * sizeof(*Name),
            NULL,
            0))
        return FALSE;
    if (PropType != DEVPROP_TYPE_STRING || !*Name)
    {
        SetLastError(ERROR_BAD_DEVICE);
        return FALSE;
    }
    return TRUE;
}

_Must_inspect_result_
static _Return_type_success_(return != FALSE)
BOOL
ConvertInterfaceAliasToGuid(_In_z_ LPCWSTR Name, _Out_ GUID *Guid)
{
    NET_LUID Luid;
    DWORD LastError = ConvertInterfaceAliasToLuid(Name, &Luid);
    if (LastError != NO_ERROR)
    {
        SetLastError(LOG_ERROR(LastError, L"Failed convert interface %s name to the locally unique identifier", Name));
        return FALSE;
    }
    LastError = ConvertInterfaceLuidToGuid(&Luid, Guid);
    if (LastError != NO_ERROR)
    {
        SetLastError(LOG_ERROR(LastError, L"Failed to convert interface %s LUID (%I64u) to GUID", Name, Luid.Value));
        return FALSE;
    }
    return TRUE;
}

_Use_decl_annotations_
BOOL WINAPI
WintunSetAdapterName(WINTUN_ADAPTER *Adapter, LPCWSTR Name)
{
    const int MaxSuffix = 1000;
    WCHAR AvailableName[MAX_ADAPTER_NAME];
    if (wcsncpy_s(AvailableName, _countof(AvailableName), Name, _TRUNCATE) == STRUNCATE)
    {
        LOG(WINTUN_LOG_ERR, L"Adapter name too long: %s", Name);
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }

    if (!SetupDiSetDevicePropertyW(
            Adapter->DevInfo,
            &Adapter->DevInfoData,
            &DEVPKEY_Wintun_Name,
            DEVPROP_TYPE_STRING,
#pragma warning(suppress : 4090)
            (const BYTE *)Name,
            (DWORD)((wcslen(Name) + 1) * sizeof(*Name)),
            0))
    {
        LOG_LAST_ERROR(L"Failed to set adapter %u name", Adapter->DevInfoData.DevInst);
        return FALSE;
    }

    for (int i = 0;; ++i)
    {
        DWORD LastError = NciSetConnectionName(&Adapter->CfgInstanceID, AvailableName);
        if (LastError == ERROR_DUP_NAME)
        {
            GUID Guid2;
            if (ConvertInterfaceAliasToGuid(AvailableName, &Guid2))
            {
                for (int j = 0; j < MaxSuffix; ++j)
                {
                    WCHAR Proposal[MAX_ADAPTER_NAME];
                    if (_snwprintf_s(Proposal, _countof(Proposal), _TRUNCATE, L"%s %d", Name, j + 1) == -1)
                    {
                        LOG(WINTUN_LOG_ERR, L"Adapter name too long: %s %d", Name, j + 1);
                        SetLastError(ERROR_INVALID_PARAMETER);
                        return FALSE;
                    }
                    if (_wcsnicmp(Proposal, AvailableName, MAX_ADAPTER_NAME) == 0)
                        continue;
                    DWORD LastError2 = NciSetConnectionName(&Guid2, Proposal);
                    if (LastError2 == ERROR_DUP_NAME)
                        continue;
                    if (LastError2 == ERROR_SUCCESS)
                    {
                        LastError = NciSetConnectionName(&Adapter->CfgInstanceID, AvailableName);
                        if (LastError == ERROR_SUCCESS)
                            break;
                    }
                    break;
                }
            }
        }
        if (LastError == ERROR_SUCCESS)
            break;
        if (i >= MaxSuffix || LastError != ERROR_DUP_NAME)
        {
            SetLastError(LOG_ERROR(LastError, L"Failed to set adapter name"));
            return FALSE;
        }
        if (_snwprintf_s(AvailableName, _countof(AvailableName), _TRUNCATE, L"%s %d", Name, i + 1) == -1)
        {
            LOG(WINTUN_LOG_ERR, L"Adapter name too long: %s %d", Name, i + 1);
            SetLastError(ERROR_INVALID_PARAMETER);
            return FALSE;
        }
    }

    if (!SetupDiSetDevicePropertyW(
            Adapter->DevInfo,
            &Adapter->DevInfoData,
            &DEVPKEY_Wintun_Pool,
            DEVPROP_TYPE_STRING,
#pragma warning(suppress : 4090)
            (const BYTE *)Adapter->Pool,
            (DWORD)((wcslen(Adapter->Pool) + 1) * sizeof(*Adapter->Pool)),
            0))
    {
        LOG_LAST_ERROR(L"Failed to set adapter %u pool", Adapter->DevInfoData.DevInst);
        return FALSE;
    }

    WCHAR PoolDeviceTypeName[MAX_POOL_DEVICE_TYPE];
    if (!GetPoolDeviceTypeName(Adapter->Pool, PoolDeviceTypeName))
        return FALSE;
    if (!SetupDiSetDeviceRegistryPropertyW(
            Adapter->DevInfo,
            &Adapter->DevInfoData,
            SPDRP_FRIENDLYNAME,
            (const BYTE *)PoolDeviceTypeName,
            (DWORD)((wcslen(PoolDeviceTypeName) + 1) * sizeof(*PoolDeviceTypeName))))
    {
        LOG_LAST_ERROR(L"Failed to set adapter %u friendly name", Adapter->DevInfoData.DevInst);
        return FALSE;
    }

    return TRUE;
}

_Use_decl_annotations_
WINTUN_ADAPTER_HANDLE WINAPI
WintunOpenAdapter(LPCWSTR Pool, LPCWSTR Name)
{
    WINTUN_ADAPTER *Adapter = Zalloc(sizeof(*Adapter));
    if (!Adapter)
        return FALSE;

    DWORD LastError = ERROR_SUCCESS;
    HANDLE Mutex = NamespaceTakePoolMutex(Pool);
    if (!Mutex)
    {
        LastError = LOG(WINTUN_LOG_ERR, L"Failed to take %s pool mutex", Pool);
        goto cleanup;
    }

    Adapter->DevInfo = SetupDiGetClassDevsExW(&GUID_DEVCLASS_NET, NULL, NULL, DIGCF_PRESENT, NULL, NULL, NULL);
    if (Adapter->DevInfo == INVALID_HANDLE_VALUE)
    {
        LastError = LOG_LAST_ERROR(L"Failed to get present adapters");
        goto cleanupMutex;
    }

    Adapter->DevInfoData.cbSize = sizeof(Adapter->DevInfoData);
    for (DWORD EnumIndex = 0;; ++EnumIndex)
    {
        if (!SetupDiEnumDeviceInfo(Adapter->DevInfo, EnumIndex, &Adapter->DevInfoData))
        {
            if (GetLastError() == ERROR_NO_MORE_ITEMS)
                break;
            continue;
        }

        WCHAR Name2[MAX_ADAPTER_NAME];
        if (!WintunGetAdapterName(Adapter, Name2))
            continue;
        if (_wcsicmp(Name, Name2))
            continue;

        /* Check the Hardware ID to make sure it's a real Wintun device. */
        if (!IsOurAdapter(Adapter->DevInfo, &Adapter->DevInfoData))
        {
            LOG(WINTUN_LOG_ERR, L"Foreign adapter %u named %s exists", Adapter->DevInfoData.DevInst, Name);
            LastError = ERROR_ALREADY_EXISTS;
            goto cleanupMutex;
        }

        if (!IsPoolMember(Pool, Adapter->DevInfo, &Adapter->DevInfoData))
        {
            if ((LastError = GetLastError()) == ERROR_SUCCESS)
            {
                LOG(WINTUN_LOG_ERR,
                    L"Adapter %u named %s is not a member of %s pool",
                    Adapter->DevInfoData.DevInst,
                    Name,
                    Pool);
                LastError = ERROR_ALREADY_EXISTS;
                goto cleanupMutex;
            }
            else
            {
                LOG(WINTUN_LOG_ERR, L"Failed to get adapter %u pool membership", Adapter->DevInfoData.DevInst);
                goto cleanupMutex;
            }
        }

        if (!PopulateAdapterData(Adapter, Pool))
        {
            LastError = LOG(WINTUN_LOG_ERR, L"Failed to populate adapter %u data", Adapter->DevInfoData.DevInst);
            goto cleanupMutex;
        }

        if (!EnsureDeviceObject(Adapter->DevInstanceID))
        {
            LastError = GetLastError();
            goto cleanupMutex;
        }

        /* Our comparison was case-insensitive, and we also might want to reenforce the NCI connection. */
        WintunSetAdapterName(Adapter, Name);

        LastError = ERROR_SUCCESS;
        goto cleanupMutex;
    }
    LastError = ERROR_FILE_NOT_FOUND;
cleanupMutex:
    NamespaceReleaseMutex(Mutex);
cleanup:
    if (LastError != ERROR_SUCCESS)
        WintunFreeAdapter(Adapter);
    return RET_ERROR(Adapter, LastError);
}

_Use_decl_annotations_
VOID WINAPI
WintunGetAdapterLUID(WINTUN_ADAPTER *Adapter, NET_LUID *Luid)
{
    Luid->Info.Reserved = 0;
    Luid->Info.NetLuidIndex = Adapter->LuidIndex;
    Luid->Info.IfType = Adapter->IfType;
}

_Use_decl_annotations_
HANDLE WINAPI
AdapterOpenDeviceObject(const WINTUN_ADAPTER *Adapter)
{
    return OpenDeviceObject(Adapter->DevInstanceID);
}

static BOOL
IsOurDrvInfoDetail(_In_ const SP_DRVINFO_DETAIL_DATA_W *DrvInfoDetailData)
{
    if (DrvInfoDetailData->CompatIDsOffset > 1 && !_wcsicmp(DrvInfoDetailData->HardwareID, WINTUN_HWID))
        return TRUE;
    if (DrvInfoDetailData->CompatIDsLength &&
        IsOurHardwareID(DrvInfoDetailData->HardwareID + DrvInfoDetailData->CompatIDsOffset))
        return TRUE;
    return FALSE;
}

static BOOL
IsNewer(
    _In_ const FILETIME *DriverDate1,
    _In_ DWORDLONG DriverVersion1,
    _In_ const FILETIME *DriverDate2,
    _In_ DWORDLONG DriverVersion2)
{
    if (DriverDate1->dwHighDateTime > DriverDate2->dwHighDateTime)
        return TRUE;
    if (DriverDate1->dwHighDateTime < DriverDate2->dwHighDateTime)
        return FALSE;

    if (DriverDate1->dwLowDateTime > DriverDate2->dwLowDateTime)
        return TRUE;
    if (DriverDate1->dwLowDateTime < DriverDate2->dwLowDateTime)
        return FALSE;

    if (DriverVersion1 > DriverVersion2)
        return TRUE;
    if (DriverVersion1 < DriverVersion2)
        return FALSE;

    return FALSE;
}

_Must_inspect_result_
static _Return_type_success_(return != FALSE)
BOOL
GetTcpipAdapterRegPath(_In_ const WINTUN_ADAPTER *Adapter, _Out_writes_z_(MAX_REG_PATH) LPWSTR Path)
{
    WCHAR Guid[MAX_GUID_STRING_LEN];
    if (_snwprintf_s(
            Path,
            MAX_REG_PATH,
            _TRUNCATE,
            L"SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters\\Adapters\\%.*s",
            StringFromGUID2(&Adapter->CfgInstanceID, Guid, _countof(Guid)),
            Guid) == -1)
    {
        LOG(WINTUN_LOG_ERR, L"Registry path too long");
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }
    return TRUE;
}

_Must_inspect_result_
static _Return_type_success_(return != FALSE)
BOOL
GetTcpipInterfaceRegPath(_In_ const WINTUN_ADAPTER *Adapter, _Out_writes_z_(MAX_REG_PATH) LPWSTR Path)
{
    HKEY TcpipAdapterRegKey;
    WCHAR TcpipAdapterRegPath[MAX_REG_PATH];
    if (!GetTcpipAdapterRegPath(Adapter, TcpipAdapterRegPath))
        return FALSE;
    DWORD LastError = RegOpenKeyExW(HKEY_LOCAL_MACHINE, TcpipAdapterRegPath, 0, KEY_QUERY_VALUE, &TcpipAdapterRegKey);
    if (LastError != ERROR_SUCCESS)
    {
        SetLastError(LOG_ERROR(LastError, L"Failed to open registry key %s", TcpipAdapterRegPath));
        return FALSE;
    }
    LPWSTR Paths = RegistryQueryString(TcpipAdapterRegKey, L"IpConfig", TRUE);
    if (!Paths)
    {
        LastError = LOG(WINTUN_LOG_ERR, L"Failed to get %s\\IpConfig", TcpipAdapterRegPath);
        goto cleanupTcpipAdapterRegKey;
    }
    if (!Paths[0])
    {
        LOG(WINTUN_LOG_ERR, L"%s\\IpConfig is empty", TcpipAdapterRegPath);
        LastError = ERROR_INVALID_DATA;
        goto cleanupPaths;
    }
    if (_snwprintf_s(Path, MAX_REG_PATH, _TRUNCATE, L"SYSTEM\\CurrentControlSet\\Services\\%s", Paths) == -1)
    {
        LOG(WINTUN_LOG_ERR, L"Registry path too long: %s", Paths);
        LastError = ERROR_INVALID_PARAMETER;
        goto cleanupPaths;
    }
cleanupPaths:
    Free(Paths);
cleanupTcpipAdapterRegKey:
    RegCloseKey(TcpipAdapterRegKey);
    return RET_ERROR(TRUE, LastError);
}

static _Return_type_success_(return != 0)
DWORD
VersionOfFile(_In_z_ LPCWSTR Filename)
{
    DWORD Zero;
    DWORD Len = GetFileVersionInfoSizeW(Filename, &Zero);
    if (!Len)
    {
        LOG_LAST_ERROR(L"Failed to query %s version info size", Filename);
        return 0;
    }
    VOID *VersionInfo = Alloc(Len);
    if (!VersionInfo)
        return 0;
    DWORD LastError = ERROR_SUCCESS, Version = 0;
    VS_FIXEDFILEINFO *FixedInfo;
    UINT FixedInfoLen = sizeof(*FixedInfo);
    if (!GetFileVersionInfoW(Filename, 0, Len, VersionInfo))
    {
        LastError = LOG_LAST_ERROR(L"Failed to get %s version info", Filename);
        goto out;
    }
    if (!VerQueryValueW(VersionInfo, L"\\", &FixedInfo, &FixedInfoLen))
    {
        LastError = LOG_LAST_ERROR(L"Failed to get %s version info root", Filename);
        goto out;
    }
    Version = FixedInfo->dwFileVersionMS;
    if (!Version)
    {
        LOG(WINTUN_LOG_WARN, L"Determined version of %s, but was v0.0, so returning failure", Filename);
        LastError = ERROR_VERSION_PARSE_ERROR;
    }
out:
    Free(VersionInfo);
    return RET_ERROR(Version, LastError);
}

static DWORD WINAPI
MaybeGetRunningDriverVersion(BOOL ReturnOneIfRunningInsteadOfVersion)
{
    PRTL_PROCESS_MODULES Modules;
    ULONG BufferSize = 128 * 1024;
    for (;;)
    {
        Modules = Alloc(BufferSize);
        if (!Modules)
            return 0;
        NTSTATUS Status = NtQuerySystemInformation(SystemModuleInformation, Modules, BufferSize, &BufferSize);
        if (NT_SUCCESS(Status))
            break;
        Free(Modules);
        if (Status == STATUS_INFO_LENGTH_MISMATCH)
            continue;
        LOG(WINTUN_LOG_ERR, L"Failed to enumerate drivers (status: 0x%x)", Status);
        SetLastError(RtlNtStatusToDosError(Status));
        return 0;
    }
    DWORD LastError = ERROR_SUCCESS, Version = 0;
    for (ULONG i = Modules->NumberOfModules; i-- > 0;)
    {
        LPCSTR NtPath = (LPCSTR)Modules->Modules[i].FullPathName;
        if (!_stricmp(&NtPath[Modules->Modules[i].OffsetToFileName], "wintun.sys"))
        {
            if (ReturnOneIfRunningInsteadOfVersion)
            {
                Version = 1;
                goto cleanupModules;
            }
            WCHAR FilePath[MAX_PATH * 3 + 15];
            if (_snwprintf_s(FilePath, _countof(FilePath), _TRUNCATE, L"\\\\?\\GLOBALROOT%S", NtPath) == -1)
                continue;
            Version = VersionOfFile(FilePath);
            if (!Version)
                LastError = GetLastError();
            goto cleanupModules;
        }
    }
    LastError = ERROR_FILE_NOT_FOUND;
cleanupModules:
    Free(Modules);
    return RET_ERROR(Version, LastError);
}

_Use_decl_annotations_
DWORD WINAPI WintunGetRunningDriverVersion(VOID)
{
    return MaybeGetRunningDriverVersion(FALSE);
}

static BOOL EnsureWintunUnloaded(VOID)
{
    BOOL Loaded;
    for (int i = 0; (Loaded = MaybeGetRunningDriverVersion(TRUE) != 0) != FALSE && i < 300; ++i)
        Sleep(50);
    return !Loaded;
}

static VOID
SelectDriverDeferredCleanup(_In_ HDEVINFO DevInfoExistingAdapters, _In_opt_ SP_DEVINFO_DATA_LIST *ExistingAdapters)
{
    if (ExistingAdapters)
    {
        EnableAllOurAdapters(DevInfoExistingAdapters, ExistingAdapters);
        while (ExistingAdapters)
        {
            SP_DEVINFO_DATA_LIST *Next = ExistingAdapters->Next;
            Free(ExistingAdapters);
            ExistingAdapters = Next;
        }
    }
    if (DevInfoExistingAdapters != INVALID_HANDLE_VALUE)
        SetupDiDestroyDeviceInfoList(DevInfoExistingAdapters);
}

_Must_inspect_result_
static _Return_type_success_(return != FALSE)
BOOL
SelectDriver(
    _In_ HDEVINFO DevInfo,
    _In_ SP_DEVINFO_DATA *DevInfoData,
    _Inout_ SP_DEVINSTALL_PARAMS_W *DevInstallParams,
    _Out_ HDEVINFO *DevInfoExistingAdaptersForCleanup,
    _Out_ SP_DEVINFO_DATA_LIST **ExistingAdaptersForCleanup)
{
    static const FILETIME OurDriverDate = WINTUN_INF_FILETIME;
    static const DWORDLONG OurDriverVersion = WINTUN_INF_VERSION;
    HANDLE DriverInstallationLock = NamespaceTakeDriverInstallationMutex();
    if (!DriverInstallationLock)
    {
        LOG(WINTUN_LOG_ERR, L"Failed to take driver installation mutex");
        return FALSE;
    }
    DWORD LastError;
    if (!SetupDiBuildDriverInfoList(DevInfo, DevInfoData, SPDIT_COMPATDRIVER))
    {
        LastError = LOG_LAST_ERROR(L"Failed building adapter %u driver info list", DevInfoData->DevInst);
        goto cleanupDriverInstallationLock;
    }
    BOOL DestroyDriverInfoListOnCleanup = TRUE;
    FILETIME DriverDate = { 0 };
    DWORDLONG DriverVersion = 0;
    HDEVINFO DevInfoExistingAdapters = INVALID_HANDLE_VALUE;
    SP_DEVINFO_DATA_LIST *ExistingAdapters = NULL;
    for (DWORD EnumIndex = 0;; ++EnumIndex)
    {
        SP_DRVINFO_DATA_W DrvInfoData = { .cbSize = sizeof(SP_DRVINFO_DATA_W) };
        if (!SetupDiEnumDriverInfoW(DevInfo, DevInfoData, SPDIT_COMPATDRIVER, EnumIndex, &DrvInfoData))
        {
            if (GetLastError() == ERROR_NO_MORE_ITEMS)
                break;
            continue;
        }
        SP_DRVINFO_DETAIL_DATA_W *DrvInfoDetailData = GetAdapterDrvInfoDetail(DevInfo, DevInfoData, &DrvInfoData);
        if (!DrvInfoDetailData)
        {
            LOG(WINTUN_LOG_WARN, L"Failed getting adapter %u driver info detail", DevInfoData->DevInst);
            continue;
        }
        if (!IsOurDrvInfoDetail(DrvInfoDetailData))
            goto next;
        if (IsNewer(&OurDriverDate, OurDriverVersion, &DrvInfoData.DriverDate, DrvInfoData.DriverVersion))
        {
            if (DevInfoExistingAdapters == INVALID_HANDLE_VALUE)
            {
                DevInfoExistingAdapters =
                    SetupDiGetClassDevsExW(&GUID_DEVCLASS_NET, NULL, NULL, DIGCF_PRESENT, NULL, NULL, NULL);
                if (DevInfoExistingAdapters == INVALID_HANDLE_VALUE)
                {
                    LastError = LOG_LAST_ERROR(L"Failed to get present adapters");
                    Free(DrvInfoDetailData);
                    goto cleanupExistingAdapters;
                }
                _Analysis_assume_(DevInfoExistingAdapters != NULL);
                DisableAllOurAdapters(DevInfoExistingAdapters, &ExistingAdapters);
                LOG(WINTUN_LOG_INFO, L"Waiting for existing driver to unload from kernel");
                if (!EnsureWintunUnloaded())
                    LOG(WINTUN_LOG_WARN,
                        L"Failed to unload existing driver, which means a reboot will likely be required");
            }
            LOG(WINTUN_LOG_INFO,
                L"Removing existing driver %u.%u",
                (DWORD)((DrvInfoData.DriverVersion & 0xffff000000000000) >> 48),
                (DWORD)((DrvInfoData.DriverVersion & 0x0000ffff00000000) >> 32));
            LPWSTR InfFileName = PathFindFileNameW(DrvInfoDetailData->InfFileName);
            if (!SetupUninstallOEMInfW(InfFileName, SUOI_FORCEDELETE, NULL))
                LOG_LAST_ERROR(L"Unable to remove existing driver %s", InfFileName);
            goto next;
        }
        if (!IsNewer(&DrvInfoData.DriverDate, DrvInfoData.DriverVersion, &DriverDate, DriverVersion))
            goto next;
        if (!SetupDiSetSelectedDriverW(DevInfo, DevInfoData, &DrvInfoData))
        {
            LOG_LAST_ERROR(
                L"Failed to select driver %s for adapter %u", DrvInfoDetailData->InfFileName, DevInfoData->DevInst);
            goto next;
        }
        DriverDate = DrvInfoData.DriverDate;
        DriverVersion = DrvInfoData.DriverVersion;
    next:
        Free(DrvInfoDetailData);
    }

    if (DriverVersion)
    {
        LOG(WINTUN_LOG_INFO,
            L"Using existing driver %u.%u",
            (DWORD)((DriverVersion & 0xffff000000000000) >> 48),
            (DWORD)((DriverVersion & 0x0000ffff00000000) >> 32));
        LastError = ERROR_SUCCESS;
        DestroyDriverInfoListOnCleanup = FALSE;
        goto cleanupExistingAdapters;
    }

    LOG(WINTUN_LOG_INFO,
        L"Installing driver %u.%u",
        (DWORD)((OurDriverVersion & 0xffff000000000000) >> 48),
        (DWORD)((OurDriverVersion & 0x0000ffff00000000) >> 32));
    WCHAR RandomTempSubDirectory[MAX_PATH];
    if (!ResourceCreateTemporaryDirectory(RandomTempSubDirectory))
    {
        LastError = LOG_LAST_ERROR(L"Failed to create temporary folder %s", RandomTempSubDirectory);
        goto cleanupExistingAdapters;
    }

    WCHAR CatPath[MAX_PATH] = { 0 };
    WCHAR SysPath[MAX_PATH] = { 0 };
    WCHAR InfPath[MAX_PATH] = { 0 };
    if (!PathCombineW(CatPath, RandomTempSubDirectory, L"wintun.cat") ||
        !PathCombineW(SysPath, RandomTempSubDirectory, L"wintun.sys") ||
        !PathCombineW(InfPath, RandomTempSubDirectory, L"wintun.inf"))
    {
        LastError = ERROR_BUFFER_OVERFLOW;
        goto cleanupDirectory;
    }

    LOG(WINTUN_LOG_INFO, L"Extracting driver");
    if (!ResourceCopyToFile(CatPath, L"wintun.cat") || !ResourceCopyToFile(SysPath, L"wintun.sys") ||
        !ResourceCopyToFile(InfPath, L"wintun.inf"))
    {
        LastError = LOG_LAST_ERROR(L"Failed to extract driver");
        goto cleanupDelete;
    }
    LOG(WINTUN_LOG_INFO, L"Installing driver");
    WCHAR InfStorePath[MAX_PATH];
    if (!SetupCopyOEMInfW(InfPath, NULL, SPOST_NONE, 0, InfStorePath, MAX_PATH, NULL, NULL))
    {
        LastError = LOG_LAST_ERROR(L"Could not install driver %s to store", InfPath);
        goto cleanupDelete;
    }
    _Analysis_assume_nullterminated_(InfStorePath);

    SetupDiDestroyDriverInfoList(DevInfo, DevInfoData, SPDIT_COMPATDRIVER);
    DestroyDriverInfoListOnCleanup = FALSE;
    DevInstallParams->Flags |= DI_ENUMSINGLEINF;
    if (wcsncpy_s(DevInstallParams->DriverPath, _countof(DevInstallParams->DriverPath), InfStorePath, _TRUNCATE) ==
        STRUNCATE)
    {
        LOG(WINTUN_LOG_ERR, L"Inf path too long: %s", InfStorePath);
        LastError = ERROR_INVALID_PARAMETER;
        goto cleanupDelete;
    }
    if (!SetupDiSetDeviceInstallParamsW(DevInfo, DevInfoData, DevInstallParams))
    {
        LastError = LOG_LAST_ERROR(L"Failed to set adapter %u device installation parameters", DevInfoData->DevInst);
        goto cleanupDelete;
    }
    if (!SetupDiBuildDriverInfoList(DevInfo, DevInfoData, SPDIT_COMPATDRIVER))
    {
        LastError = LOG_LAST_ERROR(L"Failed rebuilding adapter %u driver info list", DevInfoData->DevInst);
        goto cleanupDelete;
    }
    DestroyDriverInfoListOnCleanup = TRUE;
    SP_DRVINFO_DATA_W DrvInfoData = { .cbSize = sizeof(SP_DRVINFO_DATA_W) };
    if (!SetupDiEnumDriverInfoW(DevInfo, DevInfoData, SPDIT_COMPATDRIVER, 0, &DrvInfoData))
    {
        LastError = LOG_LAST_ERROR(L"Failed to get adapter %u driver", DevInfoData->DevInst);
        goto cleanupDelete;
    }
    if (!SetupDiSetSelectedDriverW(DevInfo, DevInfoData, &DrvInfoData))
    {
        LastError = LOG_LAST_ERROR(L"Failed to set adapter %u driver", DevInfoData->DevInst);
        goto cleanupDelete;
    }
    LastError = ERROR_SUCCESS;
    DestroyDriverInfoListOnCleanup = FALSE;

cleanupDelete:
    DeleteFileW(CatPath);
    DeleteFileW(SysPath);
    DeleteFileW(InfPath);
cleanupDirectory:
    RemoveDirectoryW(RandomTempSubDirectory);
cleanupExistingAdapters:
    if (LastError == ERROR_SUCCESS)
    {
        *DevInfoExistingAdaptersForCleanup = DevInfoExistingAdapters;
        *ExistingAdaptersForCleanup = ExistingAdapters;
    }
    else
        SelectDriverDeferredCleanup(DevInfoExistingAdapters, ExistingAdapters);
    if (DestroyDriverInfoListOnCleanup)
        SetupDiDestroyDriverInfoList(DevInfo, DevInfoData, SPDIT_COMPATDRIVER);
cleanupDriverInstallationLock:
    NamespaceReleaseMutex(DriverInstallationLock);
    return RET_ERROR(TRUE, LastError);
}

_Use_decl_annotations_
WINTUN_ADAPTER *
AdapterOpenFromDevInstanceId(LPCWSTR Pool, LPCWSTR DevInstanceID)
{
    WINTUN_ADAPTER *Adapter = Zalloc(sizeof(*Adapter));
    if (!Adapter)
        return FALSE;

    DWORD LastError = ERROR_SUCCESS;
    HANDLE Mutex = NamespaceTakePoolMutex(Pool);
    if (!Mutex)
    {
        LastError = LOG(WINTUN_LOG_ERR, L"Failed to take %s pool mutex", Pool);
        goto cleanup;
    }
    Adapter->DevInfo = SetupDiCreateDeviceInfoListExW(&GUID_DEVCLASS_NET, NULL, NULL, NULL);
    if (Adapter->DevInfo == INVALID_HANDLE_VALUE)
    {
        LastError = LOG_LAST_ERROR(L"Failed to get present adapters");
        goto cleanupMutex;
    }
    Adapter->DevInfoData.cbSize = sizeof(Adapter->DevInfoData);
    if (!SetupDiOpenDeviceInfoW(Adapter->DevInfo, DevInstanceID, NULL, 0, &Adapter->DevInfoData))
    {
        LastError = LOG_LAST_ERROR(L"Failed to open device instance ID %s", DevInstanceID);
        goto cleanupMutex;
    }
    if (!PopulateAdapterData(Adapter, Pool))
    {
        LastError = LOG(WINTUN_LOG_ERR, L"Failed to populate adapter %u data", Adapter->DevInfoData.DevInst);
        goto cleanupMutex;
    }
cleanupMutex:
    NamespaceReleaseMutex(Mutex);
cleanup:
    if (LastError != ERROR_SUCCESS)
        WintunFreeAdapter(Adapter);
    return RET_ERROR(Adapter, LastError);
}

_Use_decl_annotations_
WINTUN_ADAPTER_HANDLE WINAPI
WintunCreateAdapter(LPCWSTR Pool, LPCWSTR Name, const GUID *RequestedGUID, BOOL *RebootRequired)
{
    BOOL DummyRebootRequired;
    if (!RebootRequired)
        RebootRequired = &DummyRebootRequired;
    *RebootRequired = FALSE;

#ifdef MAYBE_WOW64
    if (NativeMachine != IMAGE_FILE_PROCESS)
        return CreateAdapterViaRundll32(Pool, Name, RequestedGUID, RebootRequired);
#endif

    DWORD LastError = ERROR_SUCCESS;
    LOG(WINTUN_LOG_INFO, L"Creating adapter");

    if (!IsWindows10)
        RequestedGUID = NULL;

    WINTUN_ADAPTER *Adapter = Zalloc(sizeof(*Adapter));
    if (!Adapter)
        return NULL;

    Adapter->DevInfo = SetupDiCreateDeviceInfoListExW(&GUID_DEVCLASS_NET, NULL, NULL, NULL);
    if (Adapter->DevInfo == INVALID_HANDLE_VALUE)
    {
        LastError = LOG_LAST_ERROR(L"Failed to create empty device information set");
        goto cleanupAdapter;
    }
    WCHAR ClassName[MAX_CLASS_NAME_LEN];
    if (!SetupDiClassNameFromGuidExW(&GUID_DEVCLASS_NET, ClassName, _countof(ClassName), NULL, NULL, NULL))
    {
        LastError = LOG_LAST_ERROR(L"Failed to retrieve class name associated with class GUID");
        goto cleanupAdapter;
    }

    WCHAR PoolDeviceTypeName[MAX_POOL_DEVICE_TYPE];
    if (!GetPoolDeviceTypeName(Pool, PoolDeviceTypeName))
    {
        LastError = GetLastError();
        goto cleanupAdapter;
    }
    Adapter->DevInfoData.cbSize = sizeof(Adapter->DevInfoData);
    if (!SetupDiCreateDeviceInfoW(
            Adapter->DevInfo,
            ClassName,
            &GUID_DEVCLASS_NET,
            PoolDeviceTypeName,
            NULL,
            DICD_GENERATE_ID,
            &Adapter->DevInfoData))
    {
        LastError = LOG_LAST_ERROR(L"Failed to create new device information element");
        goto cleanupAdapter;
    }
    SP_DEVINSTALL_PARAMS_W DevInstallParams = { .cbSize = sizeof(DevInstallParams) };
    if (!SetupDiGetDeviceInstallParamsW(Adapter->DevInfo, &Adapter->DevInfoData, &DevInstallParams))
    {
        LastError = LOG_LAST_ERROR(
            L"Failed to retrieve adapter %u device installation parameters", Adapter->DevInfoData.DevInst);
        goto cleanupAdapter;
    }
    DevInstallParams.Flags |= DI_QUIETINSTALL;
    if (!SetupDiSetDeviceInstallParamsW(Adapter->DevInfo, &Adapter->DevInfoData, &DevInstallParams))
    {
        LastError =
            LOG_LAST_ERROR(L"Failed to set adapter %u device installation parameters", Adapter->DevInfoData.DevInst);
        goto cleanupAdapter;
    }
    if (!SetupDiSetSelectedDevice(Adapter->DevInfo, &Adapter->DevInfoData))
    {
        LastError = LOG_LAST_ERROR(L"Failed to select adapter %u device", Adapter->DevInfoData.DevInst);
        goto cleanupAdapter;
    }
    static const WCHAR Hwids[_countof(WINTUN_HWID) + 1 /*Multi-string terminator*/] = WINTUN_HWID;
    if (!SetupDiSetDeviceRegistryPropertyW(
            Adapter->DevInfo, &Adapter->DevInfoData, SPDRP_HARDWAREID, (const BYTE *)Hwids, sizeof(Hwids)))
    {
        LastError = LOG_LAST_ERROR(L"Failed to set adapter %u hardware ID", Adapter->DevInfoData.DevInst);
        goto cleanupAdapter;
    }

    HDEVINFO DevInfoExistingAdapters;
    SP_DEVINFO_DATA_LIST *ExistingAdapters;
    if (!SelectDriver(
            Adapter->DevInfo, &Adapter->DevInfoData, &DevInstallParams, &DevInfoExistingAdapters, &ExistingAdapters))
    {
        LastError = LOG(WINTUN_LOG_ERR, L"Failed to select adapter %u driver", Adapter->DevInfoData.DevInst);
        goto cleanupAdapter;
    }

    HANDLE Mutex = NamespaceTakePoolMutex(Pool);
    if (!Mutex)
    {
        LastError = LOG(WINTUN_LOG_ERR, L"Failed to take %s pool mutex", Pool);
        goto cleanupDriverInfoList;
    }

    if (!SetupDiCallClassInstaller(DIF_REGISTERDEVICE, Adapter->DevInfo, &Adapter->DevInfoData))
    {
        LastError = LOG_LAST_ERROR(L"Failed to register adapter %u device", Adapter->DevInfoData.DevInst);
        goto cleanupDevice;
    }
    if (!SetupDiCallClassInstaller(DIF_REGISTER_COINSTALLERS, Adapter->DevInfo, &Adapter->DevInfoData))
        LOG_LAST_ERROR(L"Failed to register adapter %u coinstallers", Adapter->DevInfoData.DevInst);

    HKEY NetDevRegKey = INVALID_HANDLE_VALUE;
    const int PollTimeout = 50 /* ms */;
    for (int i = 0; NetDevRegKey == INVALID_HANDLE_VALUE && i < WAIT_FOR_REGISTRY_TIMEOUT / PollTimeout; ++i)
    {
        if (i)
            Sleep(PollTimeout);
        NetDevRegKey = SetupDiOpenDevRegKey(
            Adapter->DevInfo,
            &Adapter->DevInfoData,
            DICS_FLAG_GLOBAL,
            0,
            DIREG_DRV,
            KEY_SET_VALUE | KEY_QUERY_VALUE | KEY_NOTIFY);
    }
    if (NetDevRegKey == INVALID_HANDLE_VALUE)
    {
        LastError =
            LOG_LAST_ERROR(L"Failed to open adapter %u device-specific registry key", Adapter->DevInfoData.DevInst);
        goto cleanupDevice;
    }
    if (RequestedGUID)
    {
        LastError = RegSetValueExW(
            NetDevRegKey, L"SuggestedInstanceId", 0, REG_BINARY, (const BYTE *)RequestedGUID, sizeof(*RequestedGUID));
        if (LastError != ERROR_SUCCESS)
        {
            WCHAR RegPath[MAX_REG_PATH];
            LoggerGetRegistryKeyPath(NetDevRegKey, RegPath);
            LOG_ERROR(LastError, L"Failed to set %.*s\\SuggestedInstanceId", MAX_REG_PATH, RegPath);
            goto cleanupNetDevRegKey;
        }
    }

    if (!SetupDiCallClassInstaller(DIF_INSTALLINTERFACES, Adapter->DevInfo, &Adapter->DevInfoData))
        LOG_LAST_ERROR(L"Failed to install adapter %u interfaces", Adapter->DevInfoData.DevInst);

    if (!SetupDiCallClassInstaller(DIF_INSTALLDEVICE, Adapter->DevInfo, &Adapter->DevInfoData))
    {
        LastError = LOG_LAST_ERROR(L"Failed to install adapter %u device", Adapter->DevInfoData.DevInst);
        goto cleanupNetDevRegKey;
    }
    *RebootRequired = *RebootRequired || CheckReboot(Adapter->DevInfo, &Adapter->DevInfoData);

    if (!SetupDiSetDevicePropertyW(
            Adapter->DevInfo,
            &Adapter->DevInfoData,
            &DEVPKEY_Wintun_Pool,
            DEVPROP_TYPE_STRING,
#pragma warning(suppress : 4090)
            (const BYTE *)Pool,
            (DWORD)((wcslen(Pool) + 1) * sizeof(*Pool)),
            0))
    {
        LastError = LOG_LAST_ERROR(L"Failed to set adapter %u pool", Adapter->DevInfoData.DevInst);
        goto cleanupNetDevRegKey;
    }
    if (!SetupDiSetDeviceRegistryPropertyW(
            Adapter->DevInfo,
            &Adapter->DevInfoData,
            SPDRP_DEVICEDESC,
            (const BYTE *)PoolDeviceTypeName,
            (DWORD)((wcslen(PoolDeviceTypeName) + 1) * sizeof(*PoolDeviceTypeName))))
    {
        LastError = LOG_LAST_ERROR(L"Failed to set adapter %u description", Adapter->DevInfoData.DevInst);
        goto cleanupNetDevRegKey;
    }

    /* DIF_INSTALLDEVICE returns almost immediately, while the device installation continues in the background. It might
     * take a while, before all registry keys and values are populated. */
    LPWSTR DummyStr = RegistryQueryStringWait(NetDevRegKey, L"NetCfgInstanceId", WAIT_FOR_REGISTRY_TIMEOUT);
    if (!DummyStr)
    {
        WCHAR RegPath[MAX_REG_PATH];
        LoggerGetRegistryKeyPath(NetDevRegKey, RegPath);
        LastError = LOG(WINTUN_LOG_ERR, L"Failed to get %.*s\\NetCfgInstanceId", MAX_REG_PATH, RegPath);
        goto cleanupNetDevRegKey;
    }
    Free(DummyStr);
    DWORD DummyDWORD;
    if (!RegistryQueryDWORDWait(NetDevRegKey, L"NetLuidIndex", WAIT_FOR_REGISTRY_TIMEOUT, &DummyDWORD))
    {
        WCHAR RegPath[MAX_REG_PATH];
        LoggerGetRegistryKeyPath(NetDevRegKey, RegPath);
        LastError = LOG(WINTUN_LOG_ERR, L"Failed to get %.*s\\NetLuidIndex", MAX_REG_PATH, RegPath);
        goto cleanupNetDevRegKey;
    }
    if (!RegistryQueryDWORDWait(NetDevRegKey, L"*IfType", WAIT_FOR_REGISTRY_TIMEOUT, &DummyDWORD))
    {
        WCHAR RegPath[MAX_REG_PATH];
        LoggerGetRegistryKeyPath(NetDevRegKey, RegPath);
        LastError = LOG(WINTUN_LOG_ERR, L"Failed to get %.*s\\*IfType", MAX_REG_PATH, RegPath);
        goto cleanupNetDevRegKey;
    }

    if (!PopulateAdapterData(Adapter, Pool))
    {
        LastError = LOG(WINTUN_LOG_ERR, L"Failed to populate adapter %u data", Adapter->DevInfoData.DevInst);
        goto cleanupNetDevRegKey;
    }

    HKEY TcpipAdapterRegKey;
    WCHAR TcpipAdapterRegPath[MAX_REG_PATH];
    if (!GetTcpipAdapterRegPath(Adapter, TcpipAdapterRegPath))
    {
        LastError = GetLastError();
        goto cleanupAdapter;
    }
    TcpipAdapterRegKey = RegistryOpenKeyWait(
        HKEY_LOCAL_MACHINE, TcpipAdapterRegPath, KEY_QUERY_VALUE | KEY_NOTIFY, WAIT_FOR_REGISTRY_TIMEOUT);
    if (!TcpipAdapterRegKey)
    {
        LastError = LOG(
            WINTUN_LOG_ERR, L"Failed to open adapter-specific TCP/IP interface registry key %s", TcpipAdapterRegPath);
        goto cleanupAdapter;
    }
    DummyStr = RegistryQueryStringWait(TcpipAdapterRegKey, L"IpConfig", WAIT_FOR_REGISTRY_TIMEOUT);
    if (!DummyStr)
    {
        LastError = LOG(WINTUN_LOG_ERR, L"Failed to get %s\\IpConfig", TcpipAdapterRegPath);
        goto cleanupTcpipAdapterRegKey;
    }
    Free(DummyStr);

    WCHAR TcpipInterfaceRegPath[MAX_REG_PATH];
    if (!GetTcpipInterfaceRegPath(Adapter, TcpipInterfaceRegPath))
    {
        LastError = LOG(WINTUN_LOG_ERR, L"Failed to determine interface-specific TCP/IP network registry key path");
        goto cleanupTcpipAdapterRegKey;
    }
    for (int Tries = 0; Tries < 300; ++Tries)
    {
        HKEY TcpipInterfaceRegKey = RegistryOpenKeyWait(
            HKEY_LOCAL_MACHINE, TcpipInterfaceRegPath, KEY_QUERY_VALUE | KEY_SET_VALUE, WAIT_FOR_REGISTRY_TIMEOUT);
        if (!TcpipInterfaceRegKey)
        {
            LastError =
                LOG(WINTUN_LOG_ERR,
                    L"Failed to open interface-specific TCP/IP network registry key %s",
                    TcpipInterfaceRegPath);
            goto cleanupTcpipAdapterRegKey;
        }

        static const DWORD EnableDeadGWDetect = 0;
        LastError = RegSetKeyValueW(
            TcpipInterfaceRegKey,
            NULL,
            L"EnableDeadGWDetect",
            REG_DWORD,
            &EnableDeadGWDetect,
            sizeof(EnableDeadGWDetect));
        RegCloseKey(TcpipInterfaceRegKey);
        if (LastError == ERROR_SUCCESS)
            break;
        if (LastError != ERROR_TRANSACTION_NOT_ACTIVE)
        {
            LOG_ERROR(LastError, L"Failed to set %s\\EnableDeadGWDetect", TcpipInterfaceRegPath);
            goto cleanupTcpipAdapterRegKey;
        }
        Sleep(10);
    }

    if (!WintunSetAdapterName(Adapter, Name))
    {
        LastError = LOG(WINTUN_LOG_ERR, L"Failed to set adapter name %s", Name);
        goto cleanupTcpipAdapterRegKey;
    }

    for (int Tries = 0; Tries < 1000; ++Tries)
    {
        DEVPROPTYPE PropertyType;
        NTSTATUS ProblemStatus;
        if (SetupDiGetDevicePropertyW(
                Adapter->DevInfo,
                &Adapter->DevInfoData,
                &DEVPKEY_Device_ProblemStatus,
                &PropertyType,
                (PBYTE)&ProblemStatus,
                sizeof(ProblemStatus),
                NULL,
                0) &&
            PropertyType == DEVPROP_TYPE_NTSTATUS)
        {
            if (ProblemStatus != STATUS_PNP_DEVICE_CONFIGURATION_PENDING || Tries == 999)
            {
                INT32 ProblemCode;
                if (!SetupDiGetDevicePropertyW(
                        Adapter->DevInfo,
                        &Adapter->DevInfoData,
                        &DEVPKEY_Device_ProblemCode,
                        &PropertyType,
                        (PBYTE)&ProblemCode,
                        sizeof(ProblemCode),
                        NULL,
                        0) ||
                    PropertyType != DEVPROP_TYPE_INT32)
                    ProblemCode = 0;
                LastError = RtlNtStatusToDosError(ProblemStatus);
                if (LastError == ERROR_SUCCESS)
                    LastError = ERROR_NOT_READY;
                LOG_ERROR(LastError, L"Failed to setup adapter (code: 0x%x, status: 0x%x)", ProblemCode, ProblemStatus);
                goto cleanupTcpipAdapterRegKey;
            }
            Sleep(10);
        }
        else
            break;
    }
    if (!EnsureDeviceObject(Adapter->DevInstanceID))
    {
        LastError = LOG_LAST_ERROR(L"Device object file did not appear");
        goto cleanupTcpipAdapterRegKey;
    }
    LastError = ERROR_SUCCESS;

cleanupTcpipAdapterRegKey:
    RegCloseKey(TcpipAdapterRegKey);
cleanupNetDevRegKey:
    RegCloseKey(NetDevRegKey);
cleanupDevice:
    if (LastError != ERROR_SUCCESS)
    {
        SP_REMOVEDEVICE_PARAMS RemoveDeviceParams = { .ClassInstallHeader = { .cbSize = sizeof(SP_CLASSINSTALL_HEADER),
                                                                              .InstallFunction = DIF_REMOVE },
                                                      .Scope = DI_REMOVEDEVICE_GLOBAL };
        if (SetupDiSetClassInstallParamsW(
                Adapter->DevInfo,
                &Adapter->DevInfoData,
                &RemoveDeviceParams.ClassInstallHeader,
                sizeof(RemoveDeviceParams)) &&
            SetupDiCallClassInstaller(DIF_REMOVE, Adapter->DevInfo, &Adapter->DevInfoData))
            *RebootRequired = *RebootRequired || CheckReboot(Adapter->DevInfo, &Adapter->DevInfoData);
    }
    NamespaceReleaseMutex(Mutex);
cleanupDriverInfoList:
    SelectDriverDeferredCleanup(DevInfoExistingAdapters, ExistingAdapters);
    SetupDiDestroyDriverInfoList(Adapter->DevInfo, &Adapter->DevInfoData, SPDIT_COMPATDRIVER);
cleanupAdapter:
    if (LastError != ERROR_SUCCESS)
        WintunFreeAdapter(Adapter);
    return RET_ERROR(Adapter, LastError);
}

_Use_decl_annotations_
BOOL WINAPI
WintunDeleteAdapter(WINTUN_ADAPTER *Adapter, BOOL ForceCloseSessions, BOOL *RebootRequired)
{
    BOOL DummyRebootRequired;
    if (!RebootRequired)
        RebootRequired = &DummyRebootRequired;
    *RebootRequired = FALSE;
#ifdef MAYBE_WOW64
    if (NativeMachine != IMAGE_FILE_PROCESS)
        return DeleteAdapterViaRundll32(Adapter, ForceCloseSessions, RebootRequired);
#endif

    DWORD LastError = ERROR_SUCCESS;
    HANDLE Mutex = NamespaceTakePoolMutex(Adapter->Pool);
    if (!Mutex)
    {
        LastError = LOG(WINTUN_LOG_ERR, L"Failed to take %s pool mutex", Adapter->Pool);
        goto cleanup;
    }

    SP_DEVINSTALL_PARAMS_W DevInstallParams = { .cbSize = sizeof(DevInstallParams) };
    if (!SetupDiGetDeviceInstallParamsW(Adapter->DevInfo, &Adapter->DevInfoData, &DevInstallParams))
    {
        LastError = LOG_LAST_ERROR(
            L"Failed to retrieve adapter %u device installation parameters", Adapter->DevInfoData.DevInst);
        goto cleanupMutex;
    }
    DevInstallParams.Flags |= DI_QUIETINSTALL;
    if (!SetupDiSetDeviceInstallParamsW(Adapter->DevInfo, &Adapter->DevInfoData, &DevInstallParams))
    {
        LastError =
            LOG_LAST_ERROR(L"Failed to set adapter %u device installation parameters", Adapter->DevInfoData.DevInst);
        goto cleanupMutex;
    }

    if (ForceCloseSessions && !ForceCloseWintunAdapterHandle(Adapter->DevInfo, &Adapter->DevInfoData))
        LOG(WINTUN_LOG_WARN, L"Failed to force close adapter %u handles", Adapter->DevInfoData.DevInst);

    SP_REMOVEDEVICE_PARAMS Params = { .ClassInstallHeader = { .cbSize = sizeof(SP_CLASSINSTALL_HEADER),
                                                              .InstallFunction = DIF_REMOVE },
                                      .Scope = DI_REMOVEDEVICE_GLOBAL };
    if ((!SetupDiSetClassInstallParamsW(
             Adapter->DevInfo, &Adapter->DevInfoData, &Params.ClassInstallHeader, sizeof(Params)) ||
         !SetupDiCallClassInstaller(DIF_REMOVE, Adapter->DevInfo, &Adapter->DevInfoData)) &&
        GetLastError() != ERROR_NO_SUCH_DEVINST)
        LastError = LOG_LAST_ERROR(L"Failed to remove adapter %u", Adapter->DevInfoData.DevInst);

    *RebootRequired = *RebootRequired || CheckReboot(Adapter->DevInfo, &Adapter->DevInfoData);

cleanupMutex:
    NamespaceReleaseMutex(Mutex);
cleanup:
    return RET_ERROR(TRUE, LastError);
}

static _Return_type_success_(return != FALSE)
BOOL
DeleteAllOurAdapters(_In_z_ LPCWSTR Pool, _Inout_ BOOL *RebootRequired)
{
    HANDLE Mutex = NamespaceTakePoolMutex(Pool);
    if (!Mutex)
    {
        LOG(WINTUN_LOG_ERR, L"Failed to take %s pool mutex", Pool);
        return FALSE;
    }
    DWORD LastError = ERROR_SUCCESS;
    HDEVINFO DevInfo = SetupDiGetClassDevsExW(&GUID_DEVCLASS_NET, NULL, NULL, DIGCF_PRESENT, NULL, NULL, NULL);
    if (DevInfo == INVALID_HANDLE_VALUE)
    {
        LastError = LOG_LAST_ERROR(L"Failed to get present adapters");
        goto cleanupMutex;
    }
    SP_REMOVEDEVICE_PARAMS Params = { .ClassInstallHeader = { .cbSize = sizeof(SP_CLASSINSTALL_HEADER),
                                                              .InstallFunction = DIF_REMOVE },
                                      .Scope = DI_REMOVEDEVICE_GLOBAL };
    for (DWORD EnumIndex = 0;; ++EnumIndex)
    {
        SP_DEVINFO_DATA DevInfoData = { .cbSize = sizeof(SP_DEVINFO_DATA) };
        if (!SetupDiEnumDeviceInfo(DevInfo, EnumIndex, &DevInfoData))
        {
            if (GetLastError() == ERROR_NO_MORE_ITEMS)
                break;
            continue;
        }

        if (!IsOurAdapter(DevInfo, &DevInfoData) || !IsPoolMember(Pool, DevInfo, &DevInfoData))
            continue;

        LOG(WINTUN_LOG_INFO, L"Force closing all adapter %u open handles", DevInfoData.DevInst);
        if (!ForceCloseWintunAdapterHandle(DevInfo, &DevInfoData))
            LOG(WINTUN_LOG_WARN, L"Failed to force close adapter %u handles", DevInfoData.DevInst);

        LOG(WINTUN_LOG_INFO, L"Removing adapter %u", DevInfoData.DevInst);
        if ((!SetupDiSetClassInstallParamsW(DevInfo, &DevInfoData, &Params.ClassInstallHeader, sizeof(Params)) ||
             !SetupDiCallClassInstaller(DIF_REMOVE, DevInfo, &DevInfoData)) &&
            GetLastError() != ERROR_NO_SUCH_DEVINST)
        {
            LOG_LAST_ERROR(L"Failed to remove adapter %u", DevInfoData.DevInst);
            LastError = LastError != ERROR_SUCCESS ? LastError : GetLastError();
        }
        *RebootRequired = *RebootRequired || CheckReboot(DevInfo, &DevInfoData);
    }
    SetupDiDestroyDeviceInfoList(DevInfo);
cleanupMutex:
    NamespaceReleaseMutex(Mutex);
    return RET_ERROR(TRUE, LastError);
}

_Use_decl_annotations_
BOOL WINAPI
WintunDeletePoolDriver(LPCWSTR Pool, BOOL *RebootRequired)
{
    BOOL DummyRebootRequired;
    if (!RebootRequired)
        RebootRequired = &DummyRebootRequired;
    *RebootRequired = FALSE;

    DWORD LastError = ERROR_SUCCESS;
#ifdef MAYBE_WOW64
    if (NativeMachine != IMAGE_FILE_PROCESS)
    {
        LastError = DeletePoolDriverViaRundll32(Pool, RebootRequired) ? ERROR_SUCCESS : GetLastError();
        goto cleanup;
    }
#endif

    if (!DeleteAllOurAdapters(Pool, RebootRequired))
    {
        LastError = GetLastError();
        goto cleanup;
    }

    HANDLE DriverInstallationLock = NamespaceTakeDriverInstallationMutex();
    if (!DriverInstallationLock)
    {
        LastError = LOG(WINTUN_LOG_ERR, L"Failed to take driver installation mutex");
        goto cleanup;
    }
    HDEVINFO DeviceInfoSet = SetupDiGetClassDevsW(&GUID_DEVCLASS_NET, NULL, NULL, 0);
    if (!DeviceInfoSet)
    {
        LastError = LOG_LAST_ERROR(L"Failed to get adapter information");
        goto cleanupDriverInstallationLock;
    }
    if (!SetupDiBuildDriverInfoList(DeviceInfoSet, NULL, SPDIT_CLASSDRIVER))
    {
        LastError = LOG_LAST_ERROR(L"Failed building driver info list");
        goto cleanupDeviceInfoSet;
    }
    for (DWORD EnumIndex = 0;; ++EnumIndex)
    {
        SP_DRVINFO_DATA_W DriverInfo = { .cbSize = sizeof(DriverInfo) };
        if (!SetupDiEnumDriverInfoW(DeviceInfoSet, NULL, SPDIT_CLASSDRIVER, EnumIndex, &DriverInfo))
        {
            if (GetLastError() == ERROR_NO_MORE_ITEMS)
                break;
            continue;
        }
        SP_DRVINFO_DETAIL_DATA_W *DriverDetail = GetAdapterDrvInfoDetail(DeviceInfoSet, NULL, &DriverInfo);
        if (!DriverDetail)
            continue;
        if (!_wcsicmp(DriverDetail->HardwareID, WINTUN_HWID))
        {
            LPCWSTR Path = PathFindFileNameW(DriverDetail->InfFileName);
            LOG(WINTUN_LOG_INFO, L"Removing driver %s", Path);
            if (!SetupUninstallOEMInfW(Path, 0, NULL))
            {
                LOG_LAST_ERROR(L"Unable to remove driver %s", Path);
                LastError = LastError != ERROR_SUCCESS ? LastError : GetLastError();
            }
        }
        Free(DriverDetail);
    }
    SetupDiDestroyDriverInfoList(DeviceInfoSet, NULL, SPDIT_CLASSDRIVER);
cleanupDeviceInfoSet:
    SetupDiDestroyDeviceInfoList(DeviceInfoSet);
cleanupDriverInstallationLock:
    NamespaceReleaseMutex(DriverInstallationLock);
cleanup:
    return RET_ERROR(TRUE, LastError);
}

_Use_decl_annotations_
BOOL WINAPI
WintunEnumAdapters(LPCWSTR Pool, WINTUN_ENUM_CALLBACK Func, LPARAM Param)
{
    DWORD LastError = ERROR_SUCCESS;
    HANDLE Mutex = NamespaceTakePoolMutex(Pool);
    if (!Mutex)
    {
        LastError = LOG(WINTUN_LOG_ERR, L"Failed to take %s pool mutex", Pool);
        goto cleanup;
    }
    HDEVINFO DevInfo = SetupDiGetClassDevsExW(&GUID_DEVCLASS_NET, NULL, NULL, DIGCF_PRESENT, NULL, NULL, NULL);
    if (DevInfo == INVALID_HANDLE_VALUE)
    {
        LastError = LOG_LAST_ERROR(L"Failed to get present adapters");
        goto cleanupMutex;
    }
    BOOL Continue = TRUE;
    for (DWORD EnumIndex = 0; Continue; ++EnumIndex)
    {
        WINTUN_ADAPTER Adapter = { .DevInfo = DevInfo, .DevInfoData.cbSize = sizeof(Adapter.DevInfoData) };
        if (!SetupDiEnumDeviceInfo(DevInfo, EnumIndex, &Adapter.DevInfoData))
        {
            if (GetLastError() == ERROR_NO_MORE_ITEMS)
                break;
            continue;
        }

        if (!IsOurAdapter(DevInfo, &Adapter.DevInfoData) || !IsPoolMember(Pool, DevInfo, &Adapter.DevInfoData))
            continue;

        if (!PopulateAdapterData(&Adapter, Pool))
        {
            LastError = LOG(WINTUN_LOG_ERR, L"Failed to populate adapter %u data", Adapter.DevInfoData.DevInst);
            break;
        }
        Continue = Func(&Adapter, Param);
    }
    SetupDiDestroyDeviceInfoList(DevInfo);
cleanupMutex:
    NamespaceReleaseMutex(Mutex);
cleanup:
    return RET_ERROR(TRUE, LastError);
}

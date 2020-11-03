/* SPDX-License-Identifier: GPL-2.0
 *
 * Copyright (C) 2018-2020 WireGuard LLC. All Rights Reserved.
 */

#include "adapter.h"
#include "elevate.h"
#include "entry.h"
#include "logger.h"
#include "namespace.h"
#include "nci.h"
#include "ntldr.h"
#include "registry.h"
#include "resource.h"

#include <Windows.h>
#include <winternl.h>
#define _NTDEF_ /* TODO: figure out how to include ntsecapi and winternal together without requiring this */
#include <cfgmgr32.h>
#include <devguid.h>
#include <iphlpapi.h>
#include <ndisguid.h>
#include <newdev.h>
#include <NTSecAPI.h>
#include <SetupAPI.h>
#include <Shlwapi.h>
#include <wchar.h>
#include <initguid.h> /* Keep these two at bottom in this order, so that we only generate extra GUIDs for devpkey. The other keys we'll get from uuid.lib like usual. */
#include <devpkey.h>

#pragma warning(disable : 4221) /* nonstandard: address of automatic in initializer */

#define WAIT_FOR_REGISTRY_TIMEOUT 10000            /* ms */
#define MAX_POOL_DEVICE_TYPE (WINTUN_MAX_POOL + 8) /* Should accommodate a pool name with " Tunnel" appended */
#if defined(_M_IX86)
#    define IMAGE_FILE_PROCESS IMAGE_FILE_MACHINE_I386
#elif defined(_M_AMD64)
#    define IMAGE_FILE_PROCESS IMAGE_FILE_MACHINE_AMD64
#elif defined(_M_ARM)
#    define IMAGE_FILE_PROCESS IMAGE_FILE_MACHINE_ARMNT
#elif defined(_M_ARM64)
#    define IMAGE_FILE_PROCESS IMAGE_FILE_MACHINE_ARM64
#else
#    error Unsupported architecture
#endif

typedef struct _SP_DEVINFO_DATA_LIST
{
    SP_DEVINFO_DATA Data;
    struct _SP_DEVINFO_DATA_LIST *Next;
} SP_DEVINFO_DATA_LIST;

static USHORT NativeMachine = IMAGE_FILE_PROCESS;

static WINTUN_STATUS
GetAdapterDrvInfoDetail(
    _In_ HDEVINFO DevInfo,
    _In_opt_ SP_DEVINFO_DATA *DevInfoData,
    _In_ SP_DRVINFO_DATA_W *DrvInfoData,
    _Out_ SP_DRVINFO_DETAIL_DATA_W **DrvInfoDetailData)
{
    DWORD Size = sizeof(SP_DRVINFO_DETAIL_DATA_W) + 0x100;
    for (;;)
    {
        SP_DRVINFO_DETAIL_DATA_W *p = HeapAlloc(ModuleHeap, 0, Size);
        if (!p)
            return LOG(WINTUN_LOG_ERR, L"Out of memory"), ERROR_OUTOFMEMORY;
        p->cbSize = sizeof(SP_DRVINFO_DETAIL_DATA_W);
        if (SetupDiGetDriverInfoDetailW(DevInfo, DevInfoData, DrvInfoData, p, Size, &Size))
        {
            *DrvInfoDetailData = p;
            return ERROR_SUCCESS;
        }
        DWORD Result = GetLastError();
        HeapFree(ModuleHeap, 0, p);
        if (Result != ERROR_INSUFFICIENT_BUFFER)
            return LOG_ERROR(L"Failed", Result);
    }
}

static WINTUN_STATUS
GetDeviceRegistryProperty(
    _In_ HDEVINFO DevInfo,
    _In_ SP_DEVINFO_DATA *DevInfoData,
    _In_ DWORD Property,
    _Out_opt_ DWORD *ValueType,
    _Out_ void **Buf,
    _Inout_ DWORD *BufLen)
{
    for (;;)
    {
        BYTE *p = HeapAlloc(ModuleHeap, 0, *BufLen);
        if (!p)
            return LOG(WINTUN_LOG_ERR, L"Out of memory"), ERROR_OUTOFMEMORY;
        if (SetupDiGetDeviceRegistryPropertyW(DevInfo, DevInfoData, Property, ValueType, p, *BufLen, BufLen))
        {
            *Buf = p;
            return ERROR_SUCCESS;
        }
        DWORD Result = GetLastError();
        HeapFree(ModuleHeap, 0, p);
        if (Result != ERROR_INSUFFICIENT_BUFFER)
            return LOG_ERROR(L"Querying property failed", Result);
    }
}

static WINTUN_STATUS
GetDeviceRegistryString(
    _In_ HDEVINFO DevInfo,
    _In_ SP_DEVINFO_DATA *DevInfoData,
    _In_ DWORD Property,
    _Out_ WCHAR **Buf)
{
    DWORD Result, ValueType, Size = 256 * sizeof(WCHAR);
    Result = GetDeviceRegistryProperty(DevInfo, DevInfoData, Property, &ValueType, Buf, &Size);
    if (Result != ERROR_SUCCESS)
        return Result;
    switch (ValueType)
    {
    case REG_SZ:
    case REG_EXPAND_SZ:
    case REG_MULTI_SZ:
        Result = RegistryGetString(Buf, Size / sizeof(WCHAR), ValueType);
        if (Result != ERROR_SUCCESS)
            HeapFree(ModuleHeap, 0, *Buf);
        return Result;
    default:
        LOG(WINTUN_LOG_ERR, L"Property is not a string");
        HeapFree(ModuleHeap, 0, *Buf);
        return ERROR_INVALID_DATATYPE;
    }
}

static WINTUN_STATUS
GetDeviceRegistryMultiString(
    _In_ HDEVINFO DevInfo,
    _In_ SP_DEVINFO_DATA *DevInfoData,
    _In_ DWORD Property,
    _Out_ WCHAR **Buf)
{
    DWORD Result, ValueType, Size = 256 * sizeof(WCHAR);
    Result = GetDeviceRegistryProperty(DevInfo, DevInfoData, Property, &ValueType, Buf, &Size);
    if (Result != ERROR_SUCCESS)
        return Result;
    switch (ValueType)
    {
    case REG_SZ:
    case REG_EXPAND_SZ:
    case REG_MULTI_SZ:
        Result = RegistryGetMultiString(Buf, Size / sizeof(WCHAR), ValueType);
        if (Result != ERROR_SUCCESS)
            HeapFree(ModuleHeap, 0, *Buf);
        return Result;
    default:
        LOG(WINTUN_LOG_ERR, L"Property is not a string");
        HeapFree(ModuleHeap, 0, *Buf);
        return ERROR_INVALID_DATATYPE;
    }
}

static BOOL
IsOurHardwareID(_In_z_ const WCHAR *Hwids)
{
    for (; Hwids[0]; Hwids += wcslen(Hwids) + 1)
        if (!_wcsicmp(Hwids, WINTUN_HWID))
            return TRUE;
    return FALSE;
}

static WINTUN_STATUS
IsOurAdapter(_In_ HDEVINFO DevInfo, _In_ SP_DEVINFO_DATA *DevInfoData, _Out_ BOOL *IsOurs)
{
    WCHAR *Hwids;
    DWORD Result = GetDeviceRegistryMultiString(DevInfo, DevInfoData, SPDRP_HARDWAREID, &Hwids);
    if (Result != ERROR_SUCCESS)
        return LOG(WINTUN_LOG_ERR, L"Failed to get hardware ID"), Result;
    *IsOurs = IsOurHardwareID(Hwids);
    return ERROR_SUCCESS;
}

static WINTUN_STATUS
GetDeviceObject(_In_opt_z_ const WCHAR *InstanceId, _Out_ HANDLE *Handle)
{
    ULONG InterfacesLen;
    DWORD Result = CM_MapCrToWin32Err(
        CM_Get_Device_Interface_List_SizeW(
            &InterfacesLen,
            (GUID *)&GUID_DEVINTERFACE_NET,
            (DEVINSTID_W)InstanceId,
            CM_GET_DEVICE_INTERFACE_LIST_PRESENT),
        ERROR_GEN_FAILURE);
    if (Result != ERROR_SUCCESS)
        return LOG_ERROR(L"Failed to query associated instances size", Result);
    WCHAR *Interfaces = HeapAlloc(ModuleHeap, 0, InterfacesLen * sizeof(WCHAR));
    if (!Interfaces)
        return LOG(WINTUN_LOG_ERR, L"Out of memory"), ERROR_OUTOFMEMORY;
    Result = CM_MapCrToWin32Err(
        CM_Get_Device_Interface_ListW(
            (GUID *)&GUID_DEVINTERFACE_NET,
            (DEVINSTID_W)InstanceId,
            Interfaces,
            InterfacesLen,
            CM_GET_DEVICE_INTERFACE_LIST_PRESENT),
        ERROR_GEN_FAILURE);
    if (Result != ERROR_SUCCESS)
    {
        LOG_ERROR(L"Failed to get associated instances", Result);
        goto cleanupBuf;
    }
    *Handle = CreateFileW(
        Interfaces,
        GENERIC_READ | GENERIC_WRITE,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        NULL,
        OPEN_EXISTING,
        0,
        NULL);
    Result = *Handle != INVALID_HANDLE_VALUE ? ERROR_SUCCESS : LOG_LAST_ERROR(L"Failed to connect to adapter");
cleanupBuf:
    HeapFree(ModuleHeap, 0, Interfaces);
    return Result;
}

#define TUN_IOCTL_FORCE_CLOSE_HANDLES CTL_CODE(51820U, 0x971U, METHOD_NEITHER, FILE_READ_DATA | FILE_WRITE_DATA)

static WINTUN_STATUS
ForceCloseWintunAdapterHandle(_In_ HDEVINFO DevInfo, _In_ SP_DEVINFO_DATA *DevInfoData)
{
    DWORD Result = ERROR_SUCCESS;
    DWORD RequiredBytes;
    if (SetupDiGetDeviceInstanceIdW(DevInfo, DevInfoData, NULL, 0, &RequiredBytes) ||
        (Result = GetLastError()) != ERROR_INSUFFICIENT_BUFFER)
        return LOG_ERROR(L"Failed to query instance ID size", Result);
    WCHAR *InstanceId = HeapAlloc(ModuleHeap, HEAP_ZERO_MEMORY, sizeof(*InstanceId) * RequiredBytes);
    if (!InstanceId)
        return LOG(WINTUN_LOG_ERR, L"Out of memory"), ERROR_OUTOFMEMORY;
    if (!SetupDiGetDeviceInstanceIdW(DevInfo, DevInfoData, InstanceId, RequiredBytes, &RequiredBytes))
    {
        Result = LOG_LAST_ERROR(L"Failed to get instance ID");
        goto out;
    }
    HANDLE NdisHandle;
    Result = GetDeviceObject(InstanceId, &NdisHandle);
    if (Result != ERROR_SUCCESS)
    {
        LOG(WINTUN_LOG_ERR, L"Failed to get adapter object");
        goto out;
    }
    if (DeviceIoControl(NdisHandle, TUN_IOCTL_FORCE_CLOSE_HANDLES, NULL, 0, NULL, 0, &RequiredBytes, NULL))
    {
        Result = ERROR_SUCCESS;
        Sleep(200);
    }
    else if (GetLastError() == ERROR_NOTHING_TO_TERMINATE)
        Result = ERROR_SUCCESS;
    else
        Result = LOG_LAST_ERROR(L"Failed to perform ioctl");
    CloseHandle(NdisHandle);
out:
    HeapFree(ModuleHeap, 0, InstanceId);
    return Result;
}

static WINTUN_STATUS
DisableAllOurAdapters(_In_ HDEVINFO DevInfo, _Inout_ SP_DEVINFO_DATA_LIST **DisabledAdapters)
{
    SP_PROPCHANGE_PARAMS Params = { .ClassInstallHeader = { .cbSize = sizeof(SP_CLASSINSTALL_HEADER),
                                                            .InstallFunction = DIF_PROPERTYCHANGE },
                                    .StateChange = DICS_DISABLE,
                                    .Scope = DICS_FLAG_GLOBAL };
    DWORD Result = ERROR_SUCCESS;
    for (DWORD EnumIndex = 0;; ++EnumIndex)
    {
        SP_DEVINFO_DATA_LIST *DeviceNode = HeapAlloc(ModuleHeap, 0, sizeof(SP_DEVINFO_DATA_LIST));
        if (!DeviceNode)
            return LOG(WINTUN_LOG_ERR, L"Out of memory"), ERROR_OUTOFMEMORY;
        DeviceNode->Data.cbSize = sizeof(SP_DEVINFO_DATA);
        if (!SetupDiEnumDeviceInfo(DevInfo, EnumIndex, &DeviceNode->Data))
        {
            if (GetLastError() == ERROR_NO_MORE_ITEMS)
            {
                HeapFree(ModuleHeap, 0, DeviceNode);
                break;
            }
            goto cleanupDeviceNode;
        }
        BOOL IsOurs;
        if (IsOurAdapter(DevInfo, &DeviceNode->Data, &IsOurs) != ERROR_SUCCESS || !IsOurs)
            goto cleanupDeviceNode;

        ULONG Status, ProblemCode;
        if (CM_Get_DevNode_Status(&Status, &ProblemCode, DeviceNode->Data.DevInst, 0) != CR_SUCCESS ||
            ((Status & DN_HAS_PROBLEM) && ProblemCode == CM_PROB_DISABLED))
            goto cleanupDeviceNode;

        LOG(WINTUN_LOG_INFO, L"Force closing all open handles for existing adapter");
        if (ForceCloseWintunAdapterHandle(DevInfo, &DeviceNode->Data) != ERROR_SUCCESS)
            LOG(WINTUN_LOG_WARN, L"Failed to force close adapter handles");

        LOG(WINTUN_LOG_INFO, L"Disabling existing adapter");
        if (!SetupDiSetClassInstallParamsW(DevInfo, &DeviceNode->Data, &Params.ClassInstallHeader, sizeof(Params)) ||
            !SetupDiCallClassInstaller(DIF_PROPERTYCHANGE, DevInfo, &DeviceNode->Data))
        {
            LOG_LAST_ERROR(L"Failed to disable existing adapter");
            Result = Result != ERROR_SUCCESS ? Result : GetLastError();
            goto cleanupDeviceNode;
        }

        DeviceNode->Next = *DisabledAdapters;
        *DisabledAdapters = DeviceNode;
        continue;

    cleanupDeviceNode:
        HeapFree(ModuleHeap, 0, DeviceNode);
    }
    return Result;
}

static WINTUN_STATUS
EnableAllOurAdapters(_In_ HDEVINFO DevInfo, _In_ SP_DEVINFO_DATA_LIST *AdaptersToEnable)
{
    SP_PROPCHANGE_PARAMS Params = { .ClassInstallHeader = { .cbSize = sizeof(SP_CLASSINSTALL_HEADER),
                                                            .InstallFunction = DIF_PROPERTYCHANGE },
                                    .StateChange = DICS_ENABLE,
                                    .Scope = DICS_FLAG_GLOBAL };
    DWORD Result = ERROR_SUCCESS;
    for (SP_DEVINFO_DATA_LIST *DeviceNode = AdaptersToEnable; DeviceNode; DeviceNode = DeviceNode->Next)
    {
        LOG(WINTUN_LOG_INFO, L"Enabling existing adapter");
        if (!SetupDiSetClassInstallParamsW(DevInfo, &DeviceNode->Data, &Params.ClassInstallHeader, sizeof(Params)) ||
            !SetupDiCallClassInstaller(DIF_PROPERTYCHANGE, DevInfo, &DeviceNode->Data))
        {
            LOG_LAST_ERROR(L"Failed to enable existing adapter");
            Result = Result != ERROR_SUCCESS ? Result : GetLastError();
        }
    }
    return Result;
}

void
AdapterInit(void)
{
    if (!MAYBE_WOW64)
        return;
    typedef BOOL(WINAPI * IsWow64Process2_t)(
        _In_ HANDLE hProcess, _Out_ USHORT * pProcessMachine, _Out_opt_ USHORT * pNativeMachine);
    HANDLE Kernel32;
    IsWow64Process2_t IsWow64Process2;
    USHORT ProcessMachine;
    if ((Kernel32 = GetModuleHandleW(L"kernel32.dll")) == NULL ||
        (IsWow64Process2 = (IsWow64Process2_t)GetProcAddress(Kernel32, "IsWow64Process2")) == NULL ||
        !IsWow64Process2(GetCurrentProcess(), &ProcessMachine, &NativeMachine))
    {
        BOOL IsWoW64;
        NativeMachine =
            IsWow64Process(GetCurrentProcess(), &IsWoW64) && IsWoW64 ? IMAGE_FILE_MACHINE_AMD64 : IMAGE_FILE_PROCESS;
    }
}

static BOOL
CheckReboot(_In_ HDEVINFO DevInfo, _In_ SP_DEVINFO_DATA *DevInfoData)
{
    SP_DEVINSTALL_PARAMS_W DevInstallParams = { .cbSize = sizeof(SP_DEVINSTALL_PARAMS_W) };
    if (!SetupDiGetDeviceInstallParamsW(DevInfo, DevInfoData, &DevInstallParams))
    {
        LOG_LAST_ERROR(L"Retrieving device installation parameters failed");
        return FALSE;
    }
    return (DevInstallParams.Flags & (DI_NEEDREBOOT | DI_NEEDRESTART)) != 0;
}

static WINTUN_STATUS
SetQuietInstall(_In_ HDEVINFO DevInfo, _In_ SP_DEVINFO_DATA *DevInfoData)
{
    SP_DEVINSTALL_PARAMS_W DevInstallParams = { .cbSize = sizeof(SP_DEVINSTALL_PARAMS_W) };
    if (!SetupDiGetDeviceInstallParamsW(DevInfo, DevInfoData, &DevInstallParams))
        return LOG_LAST_ERROR(L"Retrieving device installation parameters failed");
    DevInstallParams.Flags |= DI_QUIETINSTALL;
    if (!SetupDiSetDeviceInstallParamsW(DevInfo, DevInfoData, &DevInstallParams))
        return LOG_LAST_ERROR(L"Setting device installation parameters failed");
    return ERROR_SUCCESS;
}

static WINTUN_STATUS
GetNetCfgInstanceId(_In_ HDEVINFO DevInfo, _In_ SP_DEVINFO_DATA *DevInfoData, _Out_ GUID *CfgInstanceID)
{
    HKEY Key = SetupDiOpenDevRegKey(DevInfo, DevInfoData, DICS_FLAG_GLOBAL, 0, DIREG_DRV, KEY_QUERY_VALUE);
    if (Key == INVALID_HANDLE_VALUE)
        return LOG_LAST_ERROR(L"Opening device registry key failed");
    WCHAR *ValueStr;
    DWORD Result = RegistryQueryString(Key, L"NetCfgInstanceId", &ValueStr, TRUE);
    if (Result != ERROR_SUCCESS)
    {
        LOG(WINTUN_LOG_ERR, L"Failed to get NetCfgInstanceId");
        goto cleanupKey;
    }
    if (FAILED(CLSIDFromString(ValueStr, CfgInstanceID)))
    {
        LOG(WINTUN_LOG_ERR, L"NetCfgInstanceId is not a GUID");
        Result = ERROR_INVALID_DATA;
    }
    else
        Result = ERROR_SUCCESS;
    HeapFree(ModuleHeap, 0, ValueStr);
cleanupKey:
    RegCloseKey(Key);
    return Result;
}

static WINTUN_STATUS
GetDevInfoData(_In_ const GUID *CfgInstanceID, _Out_ HDEVINFO *DevInfo, _Out_ SP_DEVINFO_DATA *DevInfoData)
{
    *DevInfo = SetupDiGetClassDevsExW(&GUID_DEVCLASS_NET, NULL, NULL, DIGCF_PRESENT, NULL, NULL, NULL);
    if (!*DevInfo)
        return LOG_LAST_ERROR(L"Failed to get present adapters");
    for (DWORD EnumIndex = 0;; ++EnumIndex)
    {
        DevInfoData->cbSize = sizeof(SP_DEVINFO_DATA);
        if (!SetupDiEnumDeviceInfo(*DevInfo, EnumIndex, DevInfoData))
        {
            if (GetLastError() == ERROR_NO_MORE_ITEMS)
                break;
            continue;
        }
        GUID CfgInstanceID2;
        if (GetNetCfgInstanceId(*DevInfo, DevInfoData, &CfgInstanceID2) == ERROR_SUCCESS &&
            !memcmp(CfgInstanceID, &CfgInstanceID2, sizeof(GUID)))
            return ERROR_SUCCESS;
    }
    SetupDiDestroyDeviceInfoList(*DevInfo);
    return ERROR_FILE_NOT_FOUND;
}

static void
RemoveNumberedSuffix(_Inout_z_ WCHAR *Name)
{
    for (size_t i = wcslen(Name); i--;)
    {
        if ((Name[i] < L'0' || Name[i] > L'9') && !iswspace(Name[i]))
            return;
        Name[i] = 0;
    }
}

static WINTUN_STATUS
GetPoolDeviceTypeName(_In_z_ const WCHAR *Pool, _Out_cap_c_(MAX_POOL_DEVICE_TYPE) WCHAR *Name)
{
    if (_snwprintf_s(Name, MAX_POOL_DEVICE_TYPE, _TRUNCATE, L"%s Tunnel", Pool) == -1)
        return LOG(WINTUN_LOG_ERR, L"Pool name too long"), ERROR_INVALID_PARAMETER;
    return ERROR_SUCCESS;
}

static WINTUN_STATUS
IsPoolMember(_In_z_ const WCHAR *Pool, _In_ HDEVINFO DevInfo, _In_ SP_DEVINFO_DATA *DevInfoData, _Out_ BOOL *IsMember)
{
    WCHAR *DeviceDesc, *FriendlyName;
    DWORD Result = GetDeviceRegistryString(DevInfo, DevInfoData, SPDRP_DEVICEDESC, &DeviceDesc);
    if (Result != ERROR_SUCCESS)
    {
        LOG(WINTUN_LOG_ERR, L"Failed to get adapter description");
        return Result;
    }
    Result = GetDeviceRegistryString(DevInfo, DevInfoData, SPDRP_FRIENDLYNAME, &FriendlyName);
    if (Result != ERROR_SUCCESS)
    {
        LOG(WINTUN_LOG_ERR, L"Failed to get adapter friendly name");
        goto cleanupDeviceDesc;
    }
    WCHAR PoolDeviceTypeName[MAX_POOL_DEVICE_TYPE];
    Result = GetPoolDeviceTypeName(Pool, PoolDeviceTypeName);
    if (Result != ERROR_SUCCESS)
        goto cleanupFriendlyName;
    if (!_wcsicmp(FriendlyName, PoolDeviceTypeName) || !_wcsicmp(DeviceDesc, PoolDeviceTypeName))
    {
        *IsMember = TRUE;
        goto cleanupFriendlyName;
    }
    RemoveNumberedSuffix(FriendlyName);
    RemoveNumberedSuffix(DeviceDesc);
    if (!_wcsicmp(FriendlyName, PoolDeviceTypeName) || !_wcsicmp(DeviceDesc, PoolDeviceTypeName))
    {
        *IsMember = TRUE;
        goto cleanupFriendlyName;
    }
    *IsMember = FALSE;
cleanupFriendlyName:
    HeapFree(ModuleHeap, 0, FriendlyName);
cleanupDeviceDesc:
    HeapFree(ModuleHeap, 0, DeviceDesc);
    return Result;
}

static WINTUN_STATUS
CreateAdapterData(
    _In_z_ const WCHAR *Pool,
    _In_ HDEVINFO DevInfo,
    _In_ SP_DEVINFO_DATA *DevInfoData,
    _Out_ WINTUN_ADAPTER **Adapter)
{
    DWORD Result;

    /* Open HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\<class>\<id> registry key. */
    HKEY Key = SetupDiOpenDevRegKey(DevInfo, DevInfoData, DICS_FLAG_GLOBAL, 0, DIREG_DRV, KEY_QUERY_VALUE);
    if (Key == INVALID_HANDLE_VALUE)
        return LOG_LAST_ERROR(L"Opening device registry key failed");

    WINTUN_ADAPTER *a = HeapAlloc(ModuleHeap, 0, sizeof(WINTUN_ADAPTER));
    if (!a)
    {
        LOG(WINTUN_LOG_ERR, L"Out of memory");
        Result = ERROR_OUTOFMEMORY;
        goto cleanupKey;
    }

    /* Read the NetCfgInstanceId value and convert to GUID. */
    WCHAR *ValueStr;
    Result = RegistryQueryString(Key, L"NetCfgInstanceId", &ValueStr, TRUE);
    if (Result != ERROR_SUCCESS)
    {
        LOG(WINTUN_LOG_ERR, L"Failed to get NetCfgInstanceId");
        goto cleanupAdapter;
    }
    if (FAILED(CLSIDFromString(ValueStr, &a->CfgInstanceID)))
    {
        LOG(WINTUN_LOG_ERR, L"NetCfgInstanceId is not a GUID");
        HeapFree(ModuleHeap, 0, ValueStr);
        Result = ERROR_INVALID_DATA;
        goto cleanupAdapter;
    }
    HeapFree(ModuleHeap, 0, ValueStr);

    /* Read the NetLuidIndex value. */
    Result = RegistryQueryDWORD(Key, L"NetLuidIndex", &a->LuidIndex, TRUE);
    if (Result != ERROR_SUCCESS)
    {
        LOG(WINTUN_LOG_ERR, L"Failed to get NetLuidIndex");
        goto cleanupAdapter;
    }

    /* Read the NetLuidIndex value. */
    Result = RegistryQueryDWORD(Key, L"*IfType", &a->IfType, TRUE);
    if (Result != ERROR_SUCCESS)
    {
        LOG(WINTUN_LOG_ERR, L"Failed to get *IfType");
        goto cleanupAdapter;
    }

    DWORD Size;
    if (!SetupDiGetDeviceInstanceIdW(DevInfo, DevInfoData, a->DevInstanceID, _countof(a->DevInstanceID), &Size))
    {
        Result = LOG_LAST_ERROR(L"Failed to get instance ID");
        goto cleanupAdapter;
    }

    if (wcsncpy_s(a->Pool, _countof(a->Pool), Pool, _TRUNCATE) == STRUNCATE)
    {
        LOG(WINTUN_LOG_ERR, L"Pool name too long");
        Result = ERROR_INVALID_PARAMETER;
        goto cleanupAdapter;
    }
    *Adapter = a;
    Result = ERROR_SUCCESS;

cleanupAdapter:
    if (Result != ERROR_SUCCESS)
        HeapFree(ModuleHeap, 0, a);
cleanupKey:
    RegCloseKey(Key);
    return Result;
}

static WINTUN_STATUS
GetDeviceRegPath(_In_ const WINTUN_ADAPTER *Adapter, _Out_cap_c_(MAX_REG_PATH) WCHAR *Path)
{
    if (_snwprintf_s(
            Path,
            MAX_REG_PATH,
            _TRUNCATE,
            L"SYSTEM\\CurrentControlSet\\Enum\\%.*s",
            MAX_INSTANCE_ID,
            Adapter->DevInstanceID) == -1)
        return LOG(WINTUN_LOG_ERR, L"Registry path too long"), ERROR_INVALID_PARAMETER;
    return ERROR_SUCCESS;
}

void WINAPI
WintunFreeAdapter(_In_ WINTUN_ADAPTER *Adapter)
{
    HeapFree(ModuleHeap, 0, Adapter);
}

WINTUN_STATUS WINAPI
WintunGetAdapter(_In_z_ const WCHAR *Pool, _In_z_ const WCHAR *Name, _Out_ WINTUN_ADAPTER **Adapter)
{
    if (!ElevateToSystem())
        return LOG_LAST_ERROR(L"Failed to impersonate SYSTEM user");
    DWORD Result;
    HANDLE Mutex = NamespaceTakePoolMutex(Pool);
    if (!Mutex)
    {
        Result = ERROR_INVALID_HANDLE;
        goto cleanupToken;
    }

    HDEVINFO DevInfo = SetupDiGetClassDevsExW(&GUID_DEVCLASS_NET, NULL, NULL, DIGCF_PRESENT, NULL, NULL, NULL);
    if (DevInfo == INVALID_HANDLE_VALUE)
    {
        Result = LOG_LAST_ERROR(L"Failed to get present adapters");
        goto cleanupMutex;
    }

    for (DWORD EnumIndex = 0;; ++EnumIndex)
    {
        SP_DEVINFO_DATA DevInfoData = { .cbSize = sizeof(SP_DEVINFO_DATA) };
        if (!SetupDiEnumDeviceInfo(DevInfo, EnumIndex, &DevInfoData))
        {
            if (GetLastError() == ERROR_NO_MORE_ITEMS)
                break;
            continue;
        }

        GUID CfgInstanceID;
        if (GetNetCfgInstanceId(DevInfo, &DevInfoData, &CfgInstanceID) != ERROR_SUCCESS)
            continue;

        /* TODO: is there a better way than comparing ifnames? */
        WCHAR Name2[MAX_ADAPTER_NAME];
        if (NciGetConnectionName(&CfgInstanceID, Name2, sizeof(Name2), NULL) != ERROR_SUCCESS)
            continue;
        Name2[_countof(Name2) - 1] = 0;
        if (_wcsicmp(Name, Name2))
        {
            RemoveNumberedSuffix(Name2);
            if (_wcsicmp(Name, Name2))
                continue;
        }

        /* Check the Hardware ID to make sure it's a real Wintun device. */
        BOOL IsOurs;
        Result = IsOurAdapter(DevInfo, &DevInfoData, &IsOurs);
        if (Result != ERROR_SUCCESS)
        {
            LOG(WINTUN_LOG_ERR, L"Failed to get hardware ID");
            goto cleanupDevInfo;
        }
        if (!IsOurs)
        {
            LOG(WINTUN_LOG_ERR, L"Foreign adapter with the same name exists");
            Result = ERROR_ALREADY_EXISTS;
            goto cleanupDevInfo;
        }

        BOOL IsMember;
        Result = IsPoolMember(Pool, DevInfo, &DevInfoData, &IsMember);
        if (Result != ERROR_SUCCESS)
        {
            LOG(WINTUN_LOG_ERR, L"Failed to get pool membership");
            goto cleanupDevInfo;
        }
        if (!IsMember)
        {
            LOG(WINTUN_LOG_ERR, L"Wintun adapter with the same name exists in another pool");
            Result = ERROR_ALREADY_EXISTS;
            goto cleanupDevInfo;
        }

        Result = CreateAdapterData(Pool, DevInfo, &DevInfoData, Adapter);
        if (Result != ERROR_SUCCESS)
            LOG(WINTUN_LOG_ERR, L"Failed to create adapter data");

        goto cleanupDevInfo;
    }
    Result = ERROR_FILE_NOT_FOUND;
cleanupDevInfo:
    SetupDiDestroyDeviceInfoList(DevInfo);
cleanupMutex:
    NamespaceReleaseMutex(Mutex);
cleanupToken:
    RevertToSelf();
    return Result;
}

WINTUN_STATUS WINAPI
WintunGetAdapterName(_In_ const WINTUN_ADAPTER *Adapter, _Out_cap_c_(MAX_ADAPTER_NAME) WCHAR *Name)
{
    return NciGetConnectionName(&Adapter->CfgInstanceID, Name, MAX_ADAPTER_NAME * sizeof(WCHAR), NULL);
}

static WINTUN_STATUS
ConvertInterfaceAliasToGuid(_In_z_ const WCHAR *Name, _Out_ GUID *Guid)
{
    NET_LUID Luid;
    DWORD Result = ConvertInterfaceAliasToLuid(Name, &Luid);
    if (Result != NO_ERROR)
        return LOG_ERROR(L"Failed convert interface alias name to the locally unique identifier", Result);
    return ConvertInterfaceLuidToGuid(&Luid, Guid);
}

WINTUN_STATUS WINAPI
WintunSetAdapterName(_In_ const WINTUN_ADAPTER *Adapter, _In_z_ const WCHAR *Name)
{
    DWORD Result;
    const int MaxSuffix = 1000;
    WCHAR AvailableName[MAX_ADAPTER_NAME];
    if (wcsncpy_s(AvailableName, _countof(AvailableName), Name, _TRUNCATE) == STRUNCATE)
        return LOG(WINTUN_LOG_ERR, L"Adapter name too long"), ERROR_INVALID_PARAMETER;
    for (int i = 0;; ++i)
    {
        Result = NciSetConnectionName(&Adapter->CfgInstanceID, AvailableName);
        if (Result == ERROR_DUP_NAME)
        {
            GUID Guid2;
            DWORD Result2 = ConvertInterfaceAliasToGuid(AvailableName, &Guid2);
            if (Result2 == ERROR_SUCCESS)
            {
                for (int j = 0; j < MaxSuffix; ++j)
                {
                    WCHAR Proposal[MAX_ADAPTER_NAME];
                    if (_snwprintf_s(Proposal, _countof(Proposal), _TRUNCATE, L"%s %d", Name, j + 1) == -1)
                        return LOG(WINTUN_LOG_ERR, L"Adapter name too long"), ERROR_INVALID_PARAMETER;
                    if (_wcsnicmp(Proposal, AvailableName, MAX_ADAPTER_NAME) == 0)
                        continue;
                    Result2 = NciSetConnectionName(&Guid2, Proposal);
                    if (Result2 == ERROR_DUP_NAME)
                        continue;
                    if (Result2 == ERROR_SUCCESS)
                    {
                        Result = NciSetConnectionName(&Adapter->CfgInstanceID, AvailableName);
                        if (Result == ERROR_SUCCESS)
                            break;
                    }
                    break;
                }
            }
        }
        if (Result == ERROR_SUCCESS)
            break;
        if (i >= MaxSuffix || Result != ERROR_DUP_NAME)
            return LOG_ERROR(L"Setting adapter name failed", Result);
        if (_snwprintf_s(AvailableName, _countof(AvailableName), _TRUNCATE, L"%s %d", Name, i + 1) == -1)
            return LOG(WINTUN_LOG_ERR, L"Adapter name too long"), ERROR_INVALID_PARAMETER;
    }

    /* TODO: This should use NetSetup2 so that it doesn't get unset. */
    HKEY DeviceRegKey;
    WCHAR DeviceRegPath[MAX_REG_PATH];
    Result = GetDeviceRegPath(Adapter, DeviceRegPath);
    if (Result != ERROR_SUCCESS)
        return Result;
    Result = RegOpenKeyExW(HKEY_LOCAL_MACHINE, DeviceRegPath, 0, KEY_SET_VALUE, &DeviceRegKey);
    if (Result != ERROR_SUCCESS)
        return LOG_ERROR(L"Failed to open registry key", Result);
    WCHAR PoolDeviceTypeName[MAX_POOL_DEVICE_TYPE];
    Result = GetPoolDeviceTypeName(Adapter->Pool, PoolDeviceTypeName);
    if (Result != ERROR_SUCCESS)
        goto cleanupDeviceRegKey;
    Result = RegSetKeyValueW(
        DeviceRegKey,
        NULL,
        L"FriendlyName",
        REG_SZ,
        PoolDeviceTypeName,
        (DWORD)((wcslen(PoolDeviceTypeName) + 1) * sizeof(WCHAR)));
cleanupDeviceRegKey:
    RegCloseKey(DeviceRegKey);
    return Result;
}

void WINAPI
WintunGetAdapterGUID(_In_ const WINTUN_ADAPTER *Adapter, _Out_ GUID *Guid)
{
    memcpy(Guid, &Adapter->CfgInstanceID, sizeof(GUID));
}

void WINAPI
WintunGetAdapterLUID(_In_ const WINTUN_ADAPTER *Adapter, _Out_ NET_LUID *Luid)
{
    Luid->Info.Reserved = 0;
    Luid->Info.NetLuidIndex = Adapter->LuidIndex;
    Luid->Info.IfType = Adapter->IfType;
}

WINTUN_STATUS WINAPI
WintunOpenAdapterDeviceObject(_In_ const WINTUN_ADAPTER *Adapter, _Out_ HANDLE *Handle)
{
    return GetDeviceObject(Adapter->DevInstanceID, Handle);
}

/* We can't use RtlGetVersion, because appcompat's aclayers.dll shims it to report Vista
 * when run from legacy contexts. So, we instead use the undocumented RtlGetNtVersionNumbers.
 *
 * Another way would be reading from the PEB directly:
 *   ((DWORD *)NtCurrentTeb()->ProcessEnvironmentBlock)[sizeof(void *) == 8 ? 70 : 41]
 * Or just read from KUSER_SHARED_DATA the same way on 32-bit and 64-bit:
 *    *(DWORD *)0x7FFE026C
 */
extern VOID NTAPI
RtlGetNtVersionNumbers(_Out_opt_ DWORD *MajorVersion, _Out_opt_ DWORD *MinorVersion, _Out_opt_ DWORD *BuildNumber);

static BOOL
HaveWHQL(void)
{
    if (HAVE_WHQL)
    {
        DWORD MajorVersion;
        RtlGetNtVersionNumbers(&MajorVersion, NULL, NULL);
        return MajorVersion >= 10;
    }
    return FALSE;
}

static WINTUN_STATUS
InstallCertificate(_In_z_ const WCHAR *SignedResource)
{
    LOG(WINTUN_LOG_INFO, L"Trusting code signing certificate");
    const void *LockedResource;
    DWORD SizeResource;
    DWORD Result = ResourceGetAddress(SignedResource, &LockedResource, &SizeResource);
    if (Result != ERROR_SUCCESS)
        return LOG(WINTUN_LOG_ERR, L"Failed to locate resource"), Result;
    const CERT_BLOB CertBlob = { .cbData = SizeResource, .pbData = (BYTE *)LockedResource };
    HCERTSTORE QueriedStore;
    if (!CryptQueryObject(
            CERT_QUERY_OBJECT_BLOB,
            &CertBlob,
            CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED_EMBED,
            CERT_QUERY_FORMAT_FLAG_ALL,
            0,
            0,
            0,
            0,
            &QueriedStore,
            0,
            NULL))
        return LOG_LAST_ERROR(L"Failed to find certificate");
    HCERTSTORE TrustedStore =
        CertOpenStore(CERT_STORE_PROV_SYSTEM, 0, 0, CERT_SYSTEM_STORE_LOCAL_MACHINE, L"TrustedPublisher");
    if (!TrustedStore)
    {
        Result = LOG_LAST_ERROR(L"Failed to open store");
        goto cleanupQueriedStore;
    }
    LPSTR CodeSigningOid[] = { szOID_PKIX_KP_CODE_SIGNING };
    CERT_ENHKEY_USAGE EnhancedUsage = { .cUsageIdentifier = 1, .rgpszUsageIdentifier = CodeSigningOid };
    for (const CERT_CONTEXT *CertContext = NULL; (CertContext = CertFindCertificateInStore(
                                                      QueriedStore,
                                                      X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
                                                      CERT_FIND_EXT_ONLY_ENHKEY_USAGE_FLAG,
                                                      CERT_FIND_ENHKEY_USAGE,
                                                      &EnhancedUsage,
                                                      CertContext)) != NULL;)
    {
        CERT_EXTENSION *Ext = CertFindExtension(
            szOID_BASIC_CONSTRAINTS2, CertContext->pCertInfo->cExtension, CertContext->pCertInfo->rgExtension);
        CERT_BASIC_CONSTRAINTS2_INFO Constraints;
        DWORD Size = sizeof(Constraints);
        if (Ext &&
            CryptDecodeObjectEx(
                X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
                szOID_BASIC_CONSTRAINTS2,
                Ext->Value.pbData,
                Ext->Value.cbData,
                0,
                NULL,
                &Constraints,
                &Size) &&
            !Constraints.fCA)
            if (!CertAddCertificateContextToStore(TrustedStore, CertContext, CERT_STORE_ADD_REPLACE_EXISTING, NULL))
            {
                LOG_LAST_ERROR(L"Failed to add certificate to store");
                Result = Result != ERROR_SUCCESS ? Result : GetLastError();
            }
    }
    CertCloseStore(TrustedStore, 0);
cleanupQueriedStore:
    CertCloseStore(QueriedStore, 0);
    return Result;
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

static DWORD
GetTcpipAdapterRegPath(_In_ const WINTUN_ADAPTER *Adapter, _Out_cap_c_(MAX_REG_PATH) WCHAR *Path)
{
    WCHAR Guid[MAX_GUID_STRING_LEN];
    if (_snwprintf_s(
            Path,
            MAX_REG_PATH,
            _TRUNCATE,
            L"SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters\\Adapters\\%.*s",
            StringFromGUID2(&Adapter->CfgInstanceID, Guid, _countof(Guid)),
            Guid) == -1)
        return LOG(WINTUN_LOG_ERR, L"Registry path too long"), ERROR_INVALID_PARAMETER;
    return ERROR_SUCCESS;
}

static WINTUN_STATUS
GetTcpipInterfaceRegPath(_In_ const WINTUN_ADAPTER *Adapter, _Out_cap_c_(MAX_REG_PATH) WCHAR *Path)
{
    DWORD Result;
    HKEY TcpipAdapterRegKey;
    WCHAR TcpipAdapterRegPath[MAX_REG_PATH];
    Result = GetTcpipAdapterRegPath(Adapter, TcpipAdapterRegPath);
    if (Result != ERROR_SUCCESS)
        return Result;
    Result = RegOpenKeyExW(HKEY_LOCAL_MACHINE, TcpipAdapterRegPath, 0, KEY_QUERY_VALUE, &TcpipAdapterRegKey);
    if (Result != ERROR_SUCCESS)
        return LOG_ERROR(L"Failed to open registry key", Result);
    WCHAR *Paths;
    Result = RegistryQueryString(TcpipAdapterRegKey, L"IpConfig", &Paths, TRUE);
    if (Result != ERROR_SUCCESS)
    {
        LOG(WINTUN_LOG_ERR, L"Failed to get IpConfig");
        goto cleanupTcpipAdapterRegKey;
    }
    if (!Paths[0])
    {
        LOG(WINTUN_LOG_ERR, L"IpConfig is empty");
        Result = ERROR_INVALID_DATA;
        goto cleanupPaths;
    }
    if (_snwprintf_s(Path, MAX_REG_PATH, _TRUNCATE, L"SYSTEM\\CurrentControlSet\\Services\\%s", Paths) == -1)
    {
        LOG(WINTUN_LOG_ERR, L"Registry path too long");
        Result = ERROR_INVALID_PARAMETER;
        goto cleanupPaths;
    }
    Result = ERROR_SUCCESS;
cleanupPaths:
    HeapFree(ModuleHeap, 0, Paths);
cleanupTcpipAdapterRegKey:
    RegCloseKey(TcpipAdapterRegKey);
    return Result;
}

static const CHAR *
SkipWSpace(_In_ const CHAR *Beg, _In_ const CHAR *End)
{
    for (; Beg < End && iswspace(*Beg); ++Beg)
        ;
    return Beg;
}

static const CHAR *
SkipNonLF(_In_ const CHAR *Beg, _In_ const CHAR *End)
{
    for (; Beg < End && *Beg != '\n'; ++Beg)
        ;
    return Beg;
}

static WINTUN_STATUS
VersionOfInf(_Out_ FILETIME *DriverDate, _Out_ DWORDLONG *DriverVersion)
{
    const VOID *LockedResource;
    DWORD SizeResource;
    DWORD Result = ResourceGetAddress(HaveWHQL() ? L"wintun-whql.inf" : L"wintun.inf", &LockedResource, &SizeResource);
    if (Result != ERROR_SUCCESS)
        return LOG(WINTUN_LOG_ERR, L"Failed to locate resource"), Result;
    enum
    {
        SectNone,
        SectUnknown,
        SectVersion
    } Section = SectNone;
    for (const char *Inf = (const char *)LockedResource, *InfEnd = Inf + SizeResource; Inf < InfEnd; ++Inf)
    {
        if (*Inf == ';')
        {
            Inf = SkipNonLF(Inf + 1, InfEnd);
            continue;
        }
        Inf = SkipWSpace(Inf, InfEnd);
        if (*Inf == '[')
        {
            Section = Inf + 9 <= InfEnd && !_strnicmp(Inf, "[Version]", 9) ? SectVersion : SectUnknown;
        }
        else if (Section == SectVersion)
        {
            if (Inf + 9 <= InfEnd && !_strnicmp(Inf, "DriverVer", 9))
            {
                Inf = SkipWSpace(Inf + 9, InfEnd);
                if (Inf < InfEnd && *Inf == '=')
                {
                    Inf = SkipWSpace(Inf + 1, InfEnd);
                    /* Duplicate buffer, as resource is not zero-terminated. */
                    char Buffer[0x100];
                    size_t BufferLen = InfEnd - Inf;
                    if (BufferLen >= _countof(Buffer))
                        BufferLen = _countof(Buffer) - 1;
                    strncpy_s(Buffer, _countof(Buffer), Inf, BufferLen);
                    Buffer[BufferLen] = 0;
                    const char *Ptr = Buffer;
                    unsigned long Date[3] = { 0 };
                    for (size_t i = 0;; ++i, ++Ptr)
                    {
                        char *PtrNext;
                        Date[i] = strtoul(Ptr, &PtrNext, 10);
                        Ptr = PtrNext;
                        if (i >= _countof(Date) - 1)
                            break;
                        if (*Ptr != '/' && *Ptr != '-')
                            return LOG(WINTUN_LOG_ERR, L"Unexpected date delimiter"), ERROR_INVALID_DATA;
                    }
                    if (Date[0] < 1 || Date[0] > 12 || Date[1] < 1 || Date[1] > 31 || Date[2] < 1601 || Date[2] > 30827)
                        return LOG(WINTUN_LOG_ERR, L"Invalid date"), ERROR_INVALID_DATA;
                    const SYSTEMTIME SystemTime = { .wYear = (WORD)Date[2], .wMonth = (WORD)Date[0], .wDay = (WORD)Date[1] };
                    if (!SystemTimeToFileTime(&SystemTime, DriverDate))
                        return LOG_LAST_ERROR(L"Failed to convert system time to file time");
                    Ptr = SkipWSpace(Ptr, Buffer + BufferLen);
                    ULONGLONG Version[4] = { 0 };
                    if (*Ptr == ',')
                    {
                        Ptr = SkipWSpace(Ptr + 1, Buffer + BufferLen);
                        for (size_t i = 0;; ++i, ++Ptr)
                        {
                            char *PtrNext;
                            Version[i] = strtoul(Ptr, &PtrNext, 10);
                            if (Version[i] > 0xffff)
                                return LOG(WINTUN_LOG_ERR, L"Version field may not exceed 65535"), ERROR_INVALID_DATA;
                            Ptr = PtrNext;
                            if (i >= _countof(Version) - 1 || !*Ptr || *Ptr == ';' || iswspace(*Ptr))
                                break;
                            if (*Ptr != '.')
                                return LOG(WINTUN_LOG_ERR, L"Unexpected version delimiter"), ERROR_INVALID_DATA;
                        }
                    }
                    *DriverVersion = (Version[0] << 48) | (Version[1] << 32) | (Version[2] << 16) | (Version[3] << 0);
                    return ERROR_SUCCESS;
                }
            }
        }
        Inf = SkipNonLF(Inf, InfEnd);
    }
    LOG(WINTUN_LOG_ERR, L"DriverVer not found in INF resource");
    return ERROR_FILE_NOT_FOUND;
}

static DWORD
VersionOfFile(_In_z_ const WCHAR *Filename)
{
    DWORD Version = 0;
    DWORD Zero;
    DWORD Len = GetFileVersionInfoSizeW(Filename, &Zero);
    if (!Len)
        return LOG_LAST_ERROR(L"Failed to query version info size"), Version;
    VOID *VersionInfo = HeapAlloc(ModuleHeap, 0, Len);
    if (!VersionInfo)
    {
        LOG(WINTUN_LOG_ERR, L"Out of memory");
        return Version;
    }
    VS_FIXEDFILEINFO *FixedInfo;
    UINT FixedInfoLen = sizeof(*FixedInfo);
    if (!GetFileVersionInfoW(Filename, 0, Len, VersionInfo))
    {
        LOG_LAST_ERROR(L"Failed to get version info");
        goto out;
    }
    if (!VerQueryValueW(VersionInfo, L"\\", &FixedInfo, &FixedInfoLen))
    {
        LOG_LAST_ERROR(L"Failed to get version info root");
        goto out;
    }
    Version = FixedInfo->dwFileVersionMS;
out:
    HeapFree(ModuleHeap, 0, VersionInfo);
    return Version;
}

static WINTUN_STATUS
CreateTemporaryDirectory(_Out_cap_c_(MAX_PATH) WCHAR *RandomTempSubDirectory)
{
    WCHAR WindowsDirectory[MAX_PATH];
    if (!GetWindowsDirectoryW(WindowsDirectory, _countof(WindowsDirectory)))
        return LOG_LAST_ERROR(L"Failed to get Windows folder");
    WCHAR WindowsTempDirectory[MAX_PATH];
    if (!PathCombineW(WindowsTempDirectory, WindowsDirectory, L"Temp"))
        return ERROR_BUFFER_OVERFLOW;
    UCHAR RandomBytes[32] = { 0 };
#pragma warning(suppress : 6387)
    if (!RtlGenRandom(RandomBytes, sizeof(RandomBytes)))
        return LOG_LAST_ERROR(L"Failed to generate random");
    WCHAR RandomSubDirectory[sizeof(RandomBytes) * 2 + 1];
    for (int i = 0; i < sizeof(RandomBytes); ++i)
        swprintf_s(&RandomSubDirectory[i * 2], 3, L"%02x", RandomBytes[i]);
    if (!PathCombineW(RandomTempSubDirectory, WindowsTempDirectory, RandomSubDirectory))
        return ERROR_BUFFER_OVERFLOW;
    if (!CreateDirectoryW(RandomTempSubDirectory, &SecurityAttributes))
        return LOG_LAST_ERROR(L"Failed to create temporary folder");
    return ERROR_SUCCESS;
}

DWORD
WintunGetVersion(void)
{
    DWORD Version = 0;
    PRTL_PROCESS_MODULES Modules;
    ULONG BufferSize = 128 * 1024;
    for (;;)
    {
        Modules = HeapAlloc(ModuleHeap, 0, BufferSize);
        if (!Modules)
        {
            LOG(WINTUN_LOG_ERR, L"Out of memory");
            return Version;
        }
        NTSTATUS Status = NtQuerySystemInformation(SystemModuleInformation, Modules, BufferSize, &BufferSize);
        if (NT_SUCCESS(Status))
            break;
        HeapFree(ModuleHeap, 0, Modules);
        if (Status == STATUS_INFO_LENGTH_MISMATCH)
            continue;
        LOG(WINTUN_LOG_ERR, L"Failed to enumerate drivers");
        return Version;
    }
    for (ULONG i = Modules->NumberOfModules; i-- > 0;)
    {
        const char *NtPath = (const char *)Modules->Modules[i].FullPathName;
        if (!_stricmp(&NtPath[Modules->Modules[i].OffsetToFileName], "wintun.sys"))
        {
            WCHAR FilePath[MAX_PATH * 3 + 15];
            if (_snwprintf_s(FilePath, _countof(FilePath), _TRUNCATE, L"\\\\?\\GLOBALROOT%S", NtPath) == -1)
                continue;
            Version = VersionOfFile(FilePath);
            goto out;
        }
    }
out:
    HeapFree(ModuleHeap, 0, Modules);
    return Version;
}

static BOOL
EnsureWintunUnloaded(void)
{
    BOOL Loaded;
    for (int i = 0; (Loaded = WintunGetVersion() != 0) != FALSE && i < 300; ++i)
        Sleep(50);
    return !Loaded;
}

static WINTUN_STATUS
SelectDriver(
    _In_ HDEVINFO DevInfo,
    _In_opt_ SP_DEVINFO_DATA *DevInfoData,
    _Inout_ SP_DEVINSTALL_PARAMS_W *DevInstallParams,
    _Inout_ BOOL *RebootRequired)
{
    FILETIME OurDriverDate;
    DWORDLONG OurDriverVersion;
    DWORD Result = VersionOfInf(&OurDriverDate, &OurDriverVersion);
    if (Result != ERROR_SUCCESS)
    {
        LOG(WINTUN_LOG_ERR, L"Failed to determine own driver version");
        return Result;
    }
    HANDLE DriverInstallationLock = NamespaceTakeDriverInstallationMutex();
    if (!DriverInstallationLock)
        return LOG_LAST_ERROR(L"Failed to take driver installation mutex");
    if (!SetupDiBuildDriverInfoList(DevInfo, DevInfoData, SPDIT_COMPATDRIVER))
    {
        Result = LOG_LAST_ERROR(L"Failed building driver info list");
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
        SP_DRVINFO_DETAIL_DATA_W *DrvInfoDetailData;
        if (GetAdapterDrvInfoDetail(DevInfo, DevInfoData, &DrvInfoData, &DrvInfoDetailData) != ERROR_SUCCESS)
        {
            LOG(WINTUN_LOG_WARN, L"Failed getting driver info detail");
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
                    Result = LOG_LAST_ERROR(L"Failed to get present adapters");
                    HeapFree(ModuleHeap, 0, DrvInfoDetailData);
                    goto cleanupExistingAdapters;
                }
                _Analysis_assume_(DevInfoExistingAdapters != NULL);
                DisableAllOurAdapters(DevInfoExistingAdapters, &ExistingAdapters);
                LOG(WINTUN_LOG_INFO, L"Waiting for existing driver to unload from kernel");
                if (!EnsureWintunUnloaded())
                    LOG(WINTUN_LOG_WARN,
                        L"Failed to unload existing driver, which means a reboot will likely be required");
            }
            LOG(WINTUN_LOG_INFO, TEXT("Removing existing driver"));
            if (!SetupUninstallOEMInfW(PathFindFileNameW(DrvInfoDetailData->InfFileName), SUOI_FORCEDELETE, NULL))
                LOG_LAST_ERROR(TEXT("Unable to remove existing driver"));
            goto next;
        }
        if (!IsNewer(&DrvInfoData.DriverDate, DrvInfoData.DriverVersion, &DriverDate, DriverVersion))
            goto next;
        if (!SetupDiSetSelectedDriverW(DevInfo, DevInfoData, &DrvInfoData))
        {
            LOG_ERROR(L"Failed to select driver", GetLastError());
            goto next;
        }
        DriverDate = DrvInfoData.DriverDate;
        DriverVersion = DrvInfoData.DriverVersion;
    next:
        HeapFree(ModuleHeap, 0, DrvInfoDetailData);
    }

    if (DriverVersion)
    {
        DestroyDriverInfoListOnCleanup = FALSE;
        goto cleanupExistingAdapters;
    }

    WCHAR RandomTempSubDirectory[MAX_PATH];
    if ((Result = CreateTemporaryDirectory(RandomTempSubDirectory)) != ERROR_SUCCESS)
    {
        LOG(WINTUN_LOG_ERR, L"Failed to create temporary folder");
        goto cleanupExistingAdapters;
    }

    WCHAR CatPath[MAX_PATH] = { 0 };
    WCHAR SysPath[MAX_PATH] = { 0 };
    WCHAR InfPath[MAX_PATH] = { 0 };
    if (!PathCombineW(CatPath, RandomTempSubDirectory, L"wintun.cat") ||
        !PathCombineW(SysPath, RandomTempSubDirectory, L"wintun.sys") ||
        !PathCombineW(InfPath, RandomTempSubDirectory, L"wintun.inf"))
    {
        Result = ERROR_BUFFER_OVERFLOW;
        goto cleanupDirectory;
    }

    BOOL UseWHQL = HaveWHQL();
    if (!UseWHQL && (Result = InstallCertificate(L"wintun.cat")) != ERROR_SUCCESS)
        LOG(WINTUN_LOG_WARN, L"Failed to install code signing certificate");

    LOG(WINTUN_LOG_INFO, L"Extracting driver");
    if ((Result = ResourceCopyToFile(CatPath, UseWHQL ? L"wintun-whql.cat" : L"wintun.cat")) != ERROR_SUCCESS ||
        (Result = ResourceCopyToFile(SysPath, UseWHQL ? L"wintun-whql.sys" : L"wintun.sys")) != ERROR_SUCCESS ||
        (Result = ResourceCopyToFile(InfPath, UseWHQL ? L"wintun-whql.inf" : L"wintun.inf")) != ERROR_SUCCESS)
    {
        LOG(WINTUN_LOG_ERR, L"Failed to extract driver");
        goto cleanupDelete;
    }
    LOG(WINTUN_LOG_INFO, L"Installing driver");
    WCHAR InfStorePath[MAX_PATH];
    if (!SetupCopyOEMInfW(InfPath, NULL, SPOST_NONE, 0, InfStorePath, MAX_PATH, NULL, NULL))
    {
        Result = LOG_LAST_ERROR(L"Could not install driver to store");
        goto cleanupDelete;
    }
    _Analysis_assume_nullterminated_(InfStorePath);
    BOOL UpdateRebootRequired = FALSE;
    if (ExistingAdapters &&
        !UpdateDriverForPlugAndPlayDevicesW(
            NULL, WINTUN_HWID, InfStorePath, INSTALLFLAG_FORCE | INSTALLFLAG_NONINTERACTIVE, &UpdateRebootRequired))
        LOG(WINTUN_LOG_WARN, L"Could not update existing adapters");
    *RebootRequired = *RebootRequired || UpdateRebootRequired;

    SetupDiDestroyDriverInfoList(DevInfo, DevInfoData, SPDIT_COMPATDRIVER);
    DestroyDriverInfoListOnCleanup = FALSE;
    DevInstallParams->Flags |= DI_ENUMSINGLEINF;
    if (wcsncpy_s(DevInstallParams->DriverPath, _countof(DevInstallParams->DriverPath), InfStorePath, _TRUNCATE) ==
        STRUNCATE)
    {
        LOG(WINTUN_LOG_ERR, L"Inf path too long");
        Result = ERROR_INVALID_PARAMETER;
        goto cleanupDelete;
    }
    if (!SetupDiSetDeviceInstallParamsW(DevInfo, DevInfoData, DevInstallParams))
    {
        Result = LOG_LAST_ERROR(L"Setting device installation parameters failed");
        goto cleanupDelete;
    }
    if (!SetupDiBuildDriverInfoList(DevInfo, DevInfoData, SPDIT_COMPATDRIVER))
    {
        Result = LOG_LAST_ERROR(L"Failed rebuilding driver info list");
        goto cleanupDelete;
    }
    DestroyDriverInfoListOnCleanup = TRUE;
    SP_DRVINFO_DATA_W DrvInfoData = { .cbSize = sizeof(SP_DRVINFO_DATA_W) };
    if (!SetupDiEnumDriverInfoW(DevInfo, DevInfoData, SPDIT_COMPATDRIVER, 0, &DrvInfoData))
    {
        Result = LOG_LAST_ERROR(L"Failed to get driver");
        goto cleanupDelete;
    }
    if (!SetupDiSetSelectedDriverW(DevInfo, DevInfoData, &DrvInfoData))
    {
        Result = LOG_LAST_ERROR(L"Failed to set driver");
        goto cleanupDelete;
    }
    Result = ERROR_SUCCESS;
    DestroyDriverInfoListOnCleanup = FALSE;

cleanupDelete:
    DeleteFileW(CatPath);
    DeleteFileW(SysPath);
    DeleteFileW(InfPath);
cleanupDirectory:
    RemoveDirectoryW(RandomTempSubDirectory);
cleanupExistingAdapters:
    if (ExistingAdapters)
    {
        EnableAllOurAdapters(DevInfoExistingAdapters, ExistingAdapters);
        while (ExistingAdapters)
        {
            SP_DEVINFO_DATA_LIST *Next = ExistingAdapters->Next;
            HeapFree(ModuleHeap, 0, ExistingAdapters);
            ExistingAdapters = Next;
        }
    }
    if (DevInfoExistingAdapters != INVALID_HANDLE_VALUE)
        SetupDiDestroyDeviceInfoList(DevInfoExistingAdapters);
    if (DestroyDriverInfoListOnCleanup)
        SetupDiDestroyDriverInfoList(DevInfo, DevInfoData, SPDIT_COMPATDRIVER);
cleanupDriverInstallationLock:
    NamespaceReleaseMutex(DriverInstallationLock);
    return Result;
}

static WINTUN_STATUS
CreateAdapter(
    _In_z_ const WCHAR *Pool,
    _In_z_ const WCHAR *Name,
    _In_opt_ const GUID *RequestedGUID,
    _Out_ WINTUN_ADAPTER **Adapter,
    _Inout_ BOOL *RebootRequired)
{
    LOG(WINTUN_LOG_INFO, L"Creating adapter");

    HDEVINFO DevInfo = SetupDiCreateDeviceInfoListExW(&GUID_DEVCLASS_NET, NULL, NULL, NULL);
    if (DevInfo == INVALID_HANDLE_VALUE)
        return LOG_LAST_ERROR(L"Creating empty device information set failed");
    DWORD Result;
    WCHAR ClassName[MAX_CLASS_NAME_LEN];
    if (!SetupDiClassNameFromGuidExW(&GUID_DEVCLASS_NET, ClassName, _countof(ClassName), NULL, NULL, NULL))
    {
        Result = LOG_LAST_ERROR(L"Retrieving class name associated with class GUID failed");
        goto cleanupDevInfo;
    }

    WCHAR PoolDeviceTypeName[MAX_POOL_DEVICE_TYPE];
    Result = GetPoolDeviceTypeName(Pool, PoolDeviceTypeName);
    if (Result != ERROR_SUCCESS)
        goto cleanupDevInfo;
    SP_DEVINFO_DATA DevInfoData = { .cbSize = sizeof(SP_DEVINFO_DATA) };
    if (!SetupDiCreateDeviceInfoW(
            DevInfo, ClassName, &GUID_DEVCLASS_NET, PoolDeviceTypeName, NULL, DICD_GENERATE_ID, &DevInfoData))
    {
        Result = LOG_LAST_ERROR(L"Creating new device information element failed");
        goto cleanupDevInfo;
    }
    SP_DEVINSTALL_PARAMS_W DevInstallParams = { .cbSize = sizeof(SP_DEVINSTALL_PARAMS_W) };
    if (!SetupDiGetDeviceInstallParamsW(DevInfo, &DevInfoData, &DevInstallParams))
    {
        Result = LOG_LAST_ERROR(L"Retrieving device installation parameters failed");
        goto cleanupDevInfo;
    }
    DevInstallParams.Flags |= DI_QUIETINSTALL;
    if (!SetupDiSetDeviceInstallParamsW(DevInfo, &DevInfoData, &DevInstallParams))
    {
        Result = LOG_LAST_ERROR(L"Setting device installation parameters failed");
        goto cleanupDevInfo;
    }
    if (!SetupDiSetSelectedDevice(DevInfo, &DevInfoData))
    {
        Result = LOG_LAST_ERROR(L"Failed selecting device");
        goto cleanupDevInfo;
    }
    static const WCHAR Hwids[_countof(WINTUN_HWID) + 1 /*Multi-string terminator*/] = WINTUN_HWID;
    if (!SetupDiSetDeviceRegistryPropertyW(DevInfo, &DevInfoData, SPDRP_HARDWAREID, (const BYTE *)Hwids, sizeof(Hwids)))
    {
        Result = LOG_LAST_ERROR(L"Failed setting hardware ID");
        goto cleanupDevInfo;
    }

    Result = SelectDriver(DevInfo, &DevInfoData, &DevInstallParams, RebootRequired);
    if (Result != ERROR_SUCCESS)
    {
        LOG(WINTUN_LOG_ERR, L"Failed to select driver");
        goto cleanupDevInfo;
    }

    HANDLE Mutex = NamespaceTakePoolMutex(Pool);
    if (!Mutex)
    {
        Result = LOG_LAST_ERROR(L"Failed to take pool mutex");
        goto cleanupDriverInfoList;
    }

    if (!SetupDiCallClassInstaller(DIF_REGISTERDEVICE, DevInfo, &DevInfoData))
    {
        Result = LOG_LAST_ERROR(L"Registering device failed");
        goto cleanupDevice;
    }
    if (!SetupDiCallClassInstaller(DIF_REGISTER_COINSTALLERS, DevInfo, &DevInfoData))
        LOG_LAST_ERROR(L"Registering coinstallers failed");

    HKEY NetDevRegKey = INVALID_HANDLE_VALUE;
    const int PollTimeout = 50 /* ms */;
    for (int i = 0; NetDevRegKey == INVALID_HANDLE_VALUE && i < WAIT_FOR_REGISTRY_TIMEOUT / PollTimeout; ++i)
    {
        if (i)
            Sleep(PollTimeout);
        NetDevRegKey = SetupDiOpenDevRegKey(
            DevInfo, &DevInfoData, DICS_FLAG_GLOBAL, 0, DIREG_DRV, KEY_SET_VALUE | KEY_QUERY_VALUE | KEY_NOTIFY);
    }
    if (NetDevRegKey == INVALID_HANDLE_VALUE)
    {
        Result = LOG_LAST_ERROR(L"Failed to open device-specific registry key");
        goto cleanupDevice;
    }
    if (RequestedGUID)
    {
        WCHAR RequestedGUIDStr[MAX_GUID_STRING_LEN];
        Result = RegSetValueExW(
            NetDevRegKey,
            L"NetSetupAnticipatedInstanceId",
            0,
            REG_SZ,
            (const BYTE *)RequestedGUIDStr,
            StringFromGUID2(RequestedGUID, RequestedGUIDStr, _countof(RequestedGUIDStr)) * sizeof(WCHAR));
        if (Result != ERROR_SUCCESS)
        {
            LOG_LAST_ERROR(L"Failed to set NetSetupAnticipatedInstanceId");
            goto cleanupNetDevRegKey;
        }
    }

    if (!SetupDiCallClassInstaller(DIF_INSTALLINTERFACES, DevInfo, &DevInfoData))
        LOG_LAST_ERROR(L"Installing interfaces failed");

    if (!SetupDiCallClassInstaller(DIF_INSTALLDEVICE, DevInfo, &DevInfoData))
    {
        Result = LOG_LAST_ERROR(L"Installing device failed");
        goto cleanupNetDevRegKey;
    }
    *RebootRequired = *RebootRequired || CheckReboot(DevInfo, &DevInfoData);

    if (!SetupDiSetDeviceRegistryPropertyW(
            DevInfo,
            &DevInfoData,
            SPDRP_DEVICEDESC,
            (const BYTE *)PoolDeviceTypeName,
            (DWORD)((wcslen(PoolDeviceTypeName) + 1) * sizeof(WCHAR))))
    {
        Result = LOG_LAST_ERROR(L"Failed to set adapter description");
        goto cleanupNetDevRegKey;
    }

    /* DIF_INSTALLDEVICE returns almost immediately, while the device installation continues in the background. It might
     * take a while, before all registry keys and values are populated. */
    WCHAR *DummyStr;
    Result = RegistryQueryStringWait(NetDevRegKey, L"NetCfgInstanceId", WAIT_FOR_REGISTRY_TIMEOUT, &DummyStr);
    if (Result != ERROR_SUCCESS)
    {
        LOG(WINTUN_LOG_ERR, L"Failed to get NetCfgInstanceId");
        goto cleanupNetDevRegKey;
    }
    HeapFree(ModuleHeap, 0, DummyStr);
    DWORD DummyDWORD;
    Result = RegistryQueryDWORDWait(NetDevRegKey, L"NetLuidIndex", WAIT_FOR_REGISTRY_TIMEOUT, &DummyDWORD);
    if (Result != ERROR_SUCCESS)
    {
        LOG(WINTUN_LOG_ERR, L"Failed to get NetLuidIndex");
        goto cleanupNetDevRegKey;
    }
    Result = RegistryQueryDWORDWait(NetDevRegKey, L"*IfType", WAIT_FOR_REGISTRY_TIMEOUT, &DummyDWORD);
    if (Result != ERROR_SUCCESS)
    {
        LOG(WINTUN_LOG_ERR, L"Failed to get *IfType");
        goto cleanupNetDevRegKey;
    }

    WINTUN_ADAPTER *a;
    Result = CreateAdapterData(Pool, DevInfo, &DevInfoData, &a);
    if (Result != ERROR_SUCCESS)
    {
        LOG(WINTUN_LOG_ERR, L"Failed to create adapter data");
        goto cleanupNetDevRegKey;
    }

    HKEY TcpipAdapterRegKey;
    WCHAR TcpipAdapterRegPath[MAX_REG_PATH];
    Result = GetTcpipAdapterRegPath(a, TcpipAdapterRegPath);
    if (Result != ERROR_SUCCESS)
        goto cleanupAdapter;
    Result = RegistryOpenKeyWait(
        HKEY_LOCAL_MACHINE,
        TcpipAdapterRegPath,
        KEY_QUERY_VALUE | KEY_NOTIFY,
        WAIT_FOR_REGISTRY_TIMEOUT,
        &TcpipAdapterRegKey);
    if (Result != ERROR_SUCCESS)
    {
        LOG(WINTUN_LOG_ERR, L"Failed to open adapter-specific TCP/IP interface registry key");
        goto cleanupAdapter;
    }
    Result = RegistryQueryStringWait(TcpipAdapterRegKey, L"IpConfig", WAIT_FOR_REGISTRY_TIMEOUT, &DummyStr);
    if (Result != ERROR_SUCCESS)
    {
        LOG(WINTUN_LOG_ERR, L"Failed to get IpConfig");
        goto cleanupTcpipAdapterRegKey;
    }
    HeapFree(ModuleHeap, 0, DummyStr);

    HKEY TcpipInterfaceRegKey;
    WCHAR TcpipInterfaceRegPath[MAX_REG_PATH];
    Result = GetTcpipInterfaceRegPath(a, TcpipInterfaceRegPath);
    if (Result != ERROR_SUCCESS)
    {
        LOG(WINTUN_LOG_ERR, L"Failed to determine interface-specific TCP/IP network registry key path");
        goto cleanupTcpipAdapterRegKey;
    }
    Result = RegistryOpenKeyWait(
        HKEY_LOCAL_MACHINE,
        TcpipInterfaceRegPath,
        KEY_QUERY_VALUE | KEY_SET_VALUE,
        WAIT_FOR_REGISTRY_TIMEOUT,
        &TcpipInterfaceRegKey);
    if (Result != ERROR_SUCCESS)
    {
        LOG(WINTUN_LOG_ERR, L"Failed to open interface-specific TCP/IP network registry key");
        goto cleanupTcpipAdapterRegKey;
    }

    static const DWORD EnableDeadGWDetect = 0;
    Result = RegSetKeyValueW(
        TcpipInterfaceRegKey, NULL, L"EnableDeadGWDetect", REG_DWORD, &EnableDeadGWDetect, sizeof(EnableDeadGWDetect));
    if (Result != ERROR_SUCCESS)
    {
        LOG_ERROR(L"Failed to set EnableDeadGWDetect", Result);
        goto cleanupTcpipInterfaceRegKey;
    }

    Result = WintunSetAdapterName(a, Name);
    if (Result != ERROR_SUCCESS)
    {
        LOG_ERROR(L"Failed to set adapter name", Result);
        goto cleanupTcpipInterfaceRegKey;
    }

    DEVPROPTYPE PropertyType;
    for (int Tries = 0; Tries < 1000; ++Tries)
    {
        NTSTATUS ProblemStatus;
        if (SetupDiGetDevicePropertyW(
                DevInfo,
                &DevInfoData,
                &DEVPKEY_Device_ProblemStatus,
                &PropertyType,
                (PBYTE)&ProblemStatus,
                sizeof(ProblemStatus),
                NULL,
                0) &&
            PropertyType == DEVPROP_TYPE_NTSTATUS)
        {
            Result = RtlNtStatusToDosError(ProblemStatus);
            _Analysis_assume_(Result != ERROR_SUCCESS);
            if (ProblemStatus != STATUS_PNP_DEVICE_CONFIGURATION_PENDING || Tries == 999)
            {
                LOG_ERROR(L"Failed to setup adapter", Result);
                goto cleanupTcpipInterfaceRegKey;
            }
            Sleep(10);
        }
        else
            break;
    }
    Result = ERROR_SUCCESS;

    *Adapter = a;

cleanupTcpipInterfaceRegKey:
    RegCloseKey(TcpipInterfaceRegKey);
cleanupTcpipAdapterRegKey:
    RegCloseKey(TcpipAdapterRegKey);
cleanupAdapter:
    if (Result != ERROR_SUCCESS)
        HeapFree(ModuleHeap, 0, a);
cleanupNetDevRegKey:
    RegCloseKey(NetDevRegKey);
cleanupDevice:
    if (Result != ERROR_SUCCESS)
    {
        /* The adapter failed to install, or the adapter ID was unobtainable. Clean-up. */
        SP_REMOVEDEVICE_PARAMS RemoveDeviceParams = { .ClassInstallHeader = { .cbSize = sizeof(SP_CLASSINSTALL_HEADER),
                                                                              .InstallFunction = DIF_REMOVE },
                                                      .Scope = DI_REMOVEDEVICE_GLOBAL };
        if (SetupDiSetClassInstallParamsW(
                DevInfo, &DevInfoData, &RemoveDeviceParams.ClassInstallHeader, sizeof(RemoveDeviceParams)) &&
            SetupDiCallClassInstaller(DIF_REMOVE, DevInfo, &DevInfoData))
            *RebootRequired = *RebootRequired || CheckReboot(DevInfo, &DevInfoData);
    }
    NamespaceReleaseMutex(Mutex);
cleanupDriverInfoList:
    SetupDiDestroyDriverInfoList(DevInfo, &DevInfoData, SPDIT_COMPATDRIVER);
cleanupDevInfo:
    SetupDiDestroyDeviceInfoList(DevInfo);
    return Result;
}

static WINTUN_STATUS
GetAdapter(_In_z_ const WCHAR *Pool, _In_ const GUID *CfgInstanceID, _Out_ WINTUN_ADAPTER **Adapter)
{
    HANDLE Mutex = NamespaceTakePoolMutex(Pool);
    if (!Mutex)
        return ERROR_INVALID_HANDLE;
    HDEVINFO DevInfo;
    SP_DEVINFO_DATA DevInfoData;
    DWORD Result = GetDevInfoData(CfgInstanceID, &DevInfo, &DevInfoData);
    if (Result != ERROR_SUCCESS)
    {
        LOG(WINTUN_LOG_ERR, L"Failed to locate adapter");
        goto cleanupMutex;
    }
    Result = CreateAdapterData(Pool, DevInfo, &DevInfoData, Adapter);
    if (Result != ERROR_SUCCESS)
        LOG(WINTUN_LOG_ERR, L"Failed to create adapter data");
    SetupDiDestroyDeviceInfoList(DevInfo);
cleanupMutex:
    NamespaceReleaseMutex(Mutex);
    return Result;
}

#include "rundll32.h"

WINTUN_STATUS WINAPI
WintunCreateAdapter(
    _In_z_ const WCHAR *Pool,
    _In_z_ const WCHAR *Name,
    _In_opt_ const GUID *RequestedGUID,
    _Out_ WINTUN_ADAPTER **Adapter,
    _Out_opt_ BOOL *RebootRequired)
{
    if (!ElevateToSystem())
        return LOG_LAST_ERROR(L"Failed to impersonate SYSTEM user");
    BOOL DummyRebootRequired;
    if (!RebootRequired)
        RebootRequired = &DummyRebootRequired;
    *RebootRequired = FALSE;
    DWORD Result;
    if (MAYBE_WOW64 && NativeMachine != IMAGE_FILE_PROCESS)
        Result = CreateAdapterViaRundll32(Pool, Name, RequestedGUID, Adapter, RebootRequired);
    else
        Result = CreateAdapter(Pool, Name, RequestedGUID, Adapter, RebootRequired);
    RevertToSelf();
    return Result;
}

WINTUN_STATUS WINAPI
WintunDeleteAdapter(_In_ const WINTUN_ADAPTER *Adapter, _In_ BOOL ForceCloseSessions, _Out_opt_ BOOL *RebootRequired)
{
    if (!ElevateToSystem())
        return LOG_LAST_ERROR(L"Failed to impersonate SYSTEM user");

    BOOL DummyRebootRequired;
    if (!RebootRequired)
        RebootRequired = &DummyRebootRequired;
    *RebootRequired = FALSE;
    DWORD Result;
    if (MAYBE_WOW64 && NativeMachine != IMAGE_FILE_PROCESS)
    {
        Result = DeleteAdapterViaRundll32(Adapter, ForceCloseSessions, RebootRequired);
        RevertToSelf();
        return Result;
    }

    HDEVINFO DevInfo;
    SP_DEVINFO_DATA DevInfoData;
    Result = GetDevInfoData(&Adapter->CfgInstanceID, &DevInfo, &DevInfoData);
    if (Result == ERROR_FILE_NOT_FOUND)
    {
        Result = ERROR_SUCCESS;
        goto cleanupToken;
    }
    else if (Result != ERROR_SUCCESS)
    {
        LOG(WINTUN_LOG_ERR, L"Failed to get adapter info data");
        goto cleanupToken;
    }

    if (ForceCloseSessions && ForceCloseWintunAdapterHandle(DevInfo, &DevInfoData) != ERROR_SUCCESS)
        LOG(WINTUN_LOG_WARN, L"Failed to force close adapter handles");

    SetQuietInstall(DevInfo, &DevInfoData);
    SP_REMOVEDEVICE_PARAMS RemoveDeviceParams = { .ClassInstallHeader = { .cbSize = sizeof(SP_CLASSINSTALL_HEADER),
                                                                          .InstallFunction = DIF_REMOVE },
                                                  .Scope = DI_REMOVEDEVICE_GLOBAL };
    if (SetupDiSetClassInstallParamsW(
            DevInfo, &DevInfoData, &RemoveDeviceParams.ClassInstallHeader, sizeof(RemoveDeviceParams)) &&
        SetupDiCallClassInstaller(DIF_REMOVE, DevInfo, &DevInfoData))
        *RebootRequired = *RebootRequired || CheckReboot(DevInfo, &DevInfoData);
    else
        Result = LOG_LAST_ERROR(L"Failed to remove existing adapter");
    SetupDiDestroyDeviceInfoList(DevInfo);
cleanupToken:
    RevertToSelf();
    return Result;
}

static WINTUN_STATUS
DeleteAllOurAdapters(_In_ WCHAR Pool[WINTUN_MAX_POOL], _Inout_ BOOL *RebootRequired)
{
    HANDLE Mutex = NamespaceTakePoolMutex(Pool);
    if (!Mutex)
        return ERROR_INVALID_HANDLE;
    DWORD Result = ERROR_SUCCESS;
    HDEVINFO DevInfo = SetupDiGetClassDevsExW(&GUID_DEVCLASS_NET, NULL, NULL, DIGCF_PRESENT, NULL, NULL, NULL);
    if (DevInfo == INVALID_HANDLE_VALUE)
    {
        NamespaceReleaseMutex(Mutex);
        return LOG_LAST_ERROR(L"Failed to get present adapters");
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

        BOOL IsOurs;
        if (IsOurAdapter(DevInfo, &DevInfoData, &IsOurs) != ERROR_SUCCESS || !IsOurs)
            continue;
        BOOL IsMember;
        Result = IsPoolMember(Pool, DevInfo, &DevInfoData, &IsMember);
        if (Result != ERROR_SUCCESS)
        {
            LOG(WINTUN_LOG_ERR, L"Failed to get pool membership");
            break;
        }
        if (!IsMember)
            continue;

        LOG(WINTUN_LOG_INFO, L"Force closing all open handles for existing adapter");
        if (ForceCloseWintunAdapterHandle(DevInfo, &DevInfoData) != ERROR_SUCCESS)
            LOG(WINTUN_LOG_WARN, L"Failed to force close adapter handles");

        LOG(WINTUN_LOG_INFO, L"Removing existing adapter");
        if (SetupDiSetClassInstallParamsW(DevInfo, &DevInfoData, &Params.ClassInstallHeader, sizeof(Params)) &&
            SetupDiCallClassInstaller(DIF_REMOVE, DevInfo, &DevInfoData))
            *RebootRequired = *RebootRequired || CheckReboot(DevInfo, &DevInfoData);
        else
        {
            LOG_LAST_ERROR(L"Failed to remove existing adapter");
            Result = Result != ERROR_SUCCESS ? Result : GetLastError();
        }
    }
    SetupDiDestroyDeviceInfoList(DevInfo);
    NamespaceReleaseMutex(Mutex);
    return Result;
}

WINTUN_STATUS WINAPI
WintunDeletePoolDriver(_In_z_ WCHAR Pool[WINTUN_MAX_POOL], _Out_opt_ BOOL *RebootRequired)
{
    if (!ElevateToSystem())
        return LOG_LAST_ERROR(L"Failed to impersonate SYSTEM user");

    BOOL DummyRebootRequired;
    if (!RebootRequired)
        RebootRequired = &DummyRebootRequired;
    *RebootRequired = FALSE;

    DWORD Result;
    if (MAYBE_WOW64 && NativeMachine != IMAGE_FILE_PROCESS)
    {
        Result = DeletePoolDriverViaRundll32(Pool, RebootRequired);
        RevertToSelf();
        return Result;
    }

    Result = DeleteAllOurAdapters(Pool, RebootRequired);
    if (Result != ERROR_SUCCESS)
        goto cleanupToken;

    HANDLE DriverInstallationLock = NamespaceTakeDriverInstallationMutex();
    if (!DriverInstallationLock)
    {
        Result = LOG_LAST_ERROR(L"Failed to take driver installation mutex");
        goto cleanupToken;
    }
    HDEVINFO DeviceInfoSet = SetupDiGetClassDevsW(&GUID_DEVCLASS_NET, NULL, NULL, 0);
    if (!DeviceInfoSet)
    {
        Result = LOG_LAST_ERROR(L"Failed to get adapter information");
        goto cleanupDriverInstallationLock;
    }
    if (!SetupDiBuildDriverInfoList(DeviceInfoSet, NULL, SPDIT_CLASSDRIVER))
    {
        Result = LOG_LAST_ERROR(L"Failed building driver info list");
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
        SP_DRVINFO_DETAIL_DATA_W *DriverDetail;
        if (GetAdapterDrvInfoDetail(DeviceInfoSet, NULL, &DriverInfo, &DriverDetail) != ERROR_SUCCESS)
            continue;
        if (!_wcsicmp(DriverDetail->HardwareID, WINTUN_HWID))
        {
            LOG(WINTUN_LOG_INFO, TEXT("Removing existing driver"));
            if (!SetupUninstallOEMInfW(PathFindFileNameW(DriverDetail->InfFileName), 0, NULL))
            {
                LOG_LAST_ERROR(TEXT("Unable to remove existing driver"));
                Result = Result != ERROR_SUCCESS ? Result : GetLastError();
            }
        }
        HeapFree(ModuleHeap, 0, DriverDetail);
    }
    SetupDiDestroyDriverInfoList(DeviceInfoSet, NULL, SPDIT_CLASSDRIVER);
cleanupDeviceInfoSet:
    SetupDiDestroyDeviceInfoList(DeviceInfoSet);
cleanupDriverInstallationLock:
    NamespaceReleaseMutex(DriverInstallationLock);
cleanupToken:
    RevertToSelf();
    return Result;
}

WINTUN_STATUS WINAPI
WintunEnumAdapters(_In_z_ const WCHAR *Pool, _In_ WINTUN_ENUM_CALLBACK_FUNC Func, _In_ LPARAM Param)
{
    HANDLE Mutex = NamespaceTakePoolMutex(Pool);
    if (!Mutex)
        return ERROR_INVALID_HANDLE;
    DWORD Result = ERROR_SUCCESS;
    HDEVINFO DevInfo = SetupDiGetClassDevsExW(&GUID_DEVCLASS_NET, NULL, NULL, DIGCF_PRESENT, NULL, NULL, NULL);
    if (DevInfo == INVALID_HANDLE_VALUE)
    {
        Result = LOG_LAST_ERROR(L"Failed to get present adapters");
        goto cleanupMutex;
    }
    BOOL Continue = TRUE;
    for (DWORD EnumIndex = 0; Continue; ++EnumIndex)
    {
        SP_DEVINFO_DATA DevInfoData = { .cbSize = sizeof(SP_DEVINFO_DATA) };
        if (!SetupDiEnumDeviceInfo(DevInfo, EnumIndex, &DevInfoData))
        {
            if (GetLastError() == ERROR_NO_MORE_ITEMS)
                break;
            continue;
        }

        BOOL IsOurs;
        if (IsOurAdapter(DevInfo, &DevInfoData, &IsOurs) != ERROR_SUCCESS || !IsOurs)
            continue;

        BOOL IsMember;
        Result = IsPoolMember(Pool, DevInfo, &DevInfoData, &IsMember);
        if (Result != ERROR_SUCCESS)
        {
            LOG(WINTUN_LOG_ERR, L"Failed to get pool membership");
            break;
        }
        if (!IsMember)
            continue;

        WINTUN_ADAPTER *Adapter;
        Result = CreateAdapterData(Pool, DevInfo, &DevInfoData, &Adapter);
        if (Result != ERROR_SUCCESS)
        {
            LOG(WINTUN_LOG_ERR, L"Failed to create adapter data");
            break;
        }
        Continue = Func(Adapter, Param);
        HeapFree(ModuleHeap, 0, Adapter);
    }
    SetupDiDestroyDeviceInfoList(DevInfo);
cleanupMutex:
    NamespaceReleaseMutex(Mutex);
    return Result;
}

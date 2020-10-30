/* SPDX-License-Identifier: GPL-2.0
 *
 * Copyright (C) 2018-2020 WireGuard LLC. All Rights Reserved.
 */

#include "pch.h"

#pragma warning(disable : 4221) /* nonstandard: address of automatic in initializer */

#define WAIT_FOR_REGISTRY_TIMEOUT 10000     /* ms */
#define MAX_POOL_DEVICE_TYPE (MAX_POOL + 8) /* Should accommodate a pool name with " Tunnel" appended */
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

static USHORT NativeMachine = IMAGE_FILE_PROCESS;

WINTUN_STATUS
AdapterGetDrvInfoDetail(
    _In_ HDEVINFO DevInfo,
    _In_opt_ SP_DEVINFO_DATA *DevInfoData,
    _In_ SP_DRVINFO_DATA_W *DrvInfoData,
    _Out_ SP_DRVINFO_DETAIL_DATA_W **DrvInfoDetailData)
{
    DWORD Size = sizeof(SP_DRVINFO_DETAIL_DATA_W) + 0x100;
    for (;;)
    {
        *DrvInfoDetailData = HeapAlloc(ModuleHeap, 0, Size);
        if (!*DrvInfoDetailData)
            return LOG(WINTUN_LOG_ERR, L"Out of memory"), ERROR_OUTOFMEMORY;
        (*DrvInfoDetailData)->cbSize = sizeof(SP_DRVINFO_DETAIL_DATA_W);
        if (SetupDiGetDriverInfoDetailW(DevInfo, DevInfoData, DrvInfoData, *DrvInfoDetailData, Size, &Size))
            return ERROR_SUCCESS;
        DWORD Result = GetLastError();
        HeapFree(ModuleHeap, 0, *DrvInfoDetailData);
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
        *Buf = HeapAlloc(ModuleHeap, 0, *BufLen);
        if (!*Buf)
            return LOG(WINTUN_LOG_ERR, L"Out of memory"), ERROR_OUTOFMEMORY;
        if (SetupDiGetDeviceRegistryPropertyW(DevInfo, DevInfoData, Property, ValueType, *Buf, *BufLen, BufLen))
            return ERROR_SUCCESS;
        DWORD Result = GetLastError();
        HeapFree(ModuleHeap, 0, *Buf);
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
        return LOG(WINTUN_LOG_ERR, L"Failed to query hardware ID"), Result;
    *IsOurs = IsOurHardwareID(Hwids);
    return ERROR_SUCCESS;
}

static WINTUN_STATUS
GetDeviceObject(_In_opt_z_ const WCHAR *InstanceId, _Out_ HANDLE *Handle)
{
    ULONG InterfacesLen;
    DWORD Result = CM_Get_Device_Interface_List_SizeW(
        &InterfacesLen, (GUID *)&GUID_DEVINTERFACE_NET, (DEVINSTID_W)InstanceId, CM_GET_DEVICE_INTERFACE_LIST_PRESENT);
    if (Result != CR_SUCCESS)
    {
        LOG(WINTUN_LOG_ERR, L"Failed to get device associated device instances size");
        return ERROR_GEN_FAILURE;
    }
    WCHAR *Interfaces = HeapAlloc(ModuleHeap, 0, InterfacesLen * sizeof(WCHAR));
    if (!Interfaces)
        return LOG(WINTUN_LOG_ERR, L"Out of memory"), ERROR_OUTOFMEMORY;
    Result = CM_Get_Device_Interface_ListW(
        (GUID *)&GUID_DEVINTERFACE_NET,
        (DEVINSTID_W)InstanceId,
        Interfaces,
        InterfacesLen,
        CM_GET_DEVICE_INTERFACE_LIST_PRESENT);
    if (Result != CR_SUCCESS)
    {
        LOG(WINTUN_LOG_ERR, L"Failed to get device associated device instances");
        Result = ERROR_GEN_FAILURE;
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
    Result = *Handle != INVALID_HANDLE_VALUE ? ERROR_SUCCESS : LOG_LAST_ERROR(L"Failed to connect to device");
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
        return LOG_ERROR(L"Failed to query device instance ID size", Result);
    WCHAR *InstanceId = HeapAlloc(ModuleHeap, HEAP_ZERO_MEMORY, sizeof(*InstanceId) * RequiredBytes);
    if (!InstanceId)
        return LOG(WINTUN_LOG_ERR, L"Out of memory"), ERROR_OUTOFMEMORY;
    if (!SetupDiGetDeviceInstanceIdW(DevInfo, DevInfoData, InstanceId, RequiredBytes, &RequiredBytes))
    {
        Result = LOG_LAST_ERROR(L"Failed to get device instance ID");
        goto out;
    }
    HANDLE NdisHandle;
    Result = GetDeviceObject(InstanceId, &NdisHandle);
    if (Result != ERROR_SUCCESS)
    {
        LOG(WINTUN_LOG_ERR, L"Failed to get adapter device object");
        goto out;
    }
    Result = DeviceIoControl(NdisHandle, TUN_IOCTL_FORCE_CLOSE_HANDLES, NULL, 0, NULL, 0, &RequiredBytes, NULL)
                 ? ERROR_SUCCESS
                 : LOG_LAST_ERROR(L"Failed to perform ioctl");
    CloseHandle(NdisHandle);
out:
    HeapFree(ModuleHeap, 0, InstanceId);
    return Result;
}

WINTUN_STATUS
AdapterDisableAllOurs(_In_ HDEVINFO DevInfo, _Inout_ SP_DEVINFO_DATA_LIST **DisabledAdapters)
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
            goto cleanupDeviceInfoData;
        }
        BOOL IsOurs;
        if (IsOurAdapter(DevInfo, &DeviceNode->Data, &IsOurs) != ERROR_SUCCESS || !IsOurs)
            goto cleanupDeviceInfoData;

        ULONG Status, ProblemCode;
        if (CM_Get_DevNode_Status(&Status, &ProblemCode, DeviceNode->Data.DevInst, 0) != CR_SUCCESS ||
            ((Status & DN_HAS_PROBLEM) && ProblemCode == CM_PROB_DISABLED))
            goto cleanupDeviceInfoData;

        LOG(WINTUN_LOG_INFO, L"Force closing all open handles for existing adapter");
        if (ForceCloseWintunAdapterHandle(DevInfo, &DeviceNode->Data) != ERROR_SUCCESS)
            LOG(WINTUN_LOG_WARN, L"Failed to force close adapter handles");
        Sleep(200);

        LOG(WINTUN_LOG_INFO, L"Disabling existing adapter");
        if (!SetupDiSetClassInstallParamsW(DevInfo, &DeviceNode->Data, &Params.ClassInstallHeader, sizeof(Params)) ||
            !SetupDiCallClassInstaller(DIF_PROPERTYCHANGE, DevInfo, &DeviceNode->Data))
        {
            LOG_LAST_ERROR(L"Unable to disable existing adapter");
            Result = Result != ERROR_SUCCESS ? Result : GetLastError();
            goto cleanupDeviceInfoData;
        }

        DeviceNode->Next = *DisabledAdapters;
        *DisabledAdapters = DeviceNode;
        continue;

    cleanupDeviceInfoData:
        HeapFree(ModuleHeap, 0, &DeviceNode->Data);
    }
    return Result;
}

WINTUN_STATUS
AdapterEnableAll(_In_ HDEVINFO DevInfo, _In_ SP_DEVINFO_DATA_LIST *AdaptersToEnable)
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
            LOG_LAST_ERROR(L"Unable to enable existing adapter");
            Result = Result != ERROR_SUCCESS ? Result : GetLastError();
        }
    }
    return Result;
}

WINTUN_STATUS
AdapterDeleteAllOurs(void)
{
    DWORD Result = ERROR_SUCCESS;
    HDEVINFO DevInfo = SetupDiGetClassDevsExW(&GUID_DEVCLASS_NET, NULL, NULL, DIGCF_PRESENT, NULL, NULL, NULL);
    if (DevInfo == INVALID_HANDLE_VALUE)
        return LOG_LAST_ERROR(L"Failed to get present class devices");
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

        LOG(WINTUN_LOG_INFO, L"Force closing all open handles for existing adapter");
        if (ForceCloseWintunAdapterHandle(DevInfo, &DevInfoData) != ERROR_SUCCESS)
            LOG(WINTUN_LOG_WARN, L"Failed to force close adapter handles");
        Sleep(200);

        LOG(WINTUN_LOG_INFO, L"Removing existing adapter");
        if (!SetupDiSetClassInstallParamsW(DevInfo, &DevInfoData, &Params.ClassInstallHeader, sizeof(Params)) ||
            !SetupDiCallClassInstaller(DIF_REMOVE, DevInfo, &DevInfoData))
        {
            LOG_LAST_ERROR(L"Unable to remove existing adapter");
            Result = Result != ERROR_SUCCESS ? Result : GetLastError();
        }
    }
    SetupDiDestroyDeviceInfoList(DevInfo);
    return Result;
}

void
AdapterInit(void)
{
#ifdef MAYBE_WOW64
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
#endif
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
        LOG(WINTUN_LOG_ERR, L"Failed to query NetCfgInstanceId value");
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
        return LOG_LAST_ERROR(L"Failed to get present class devices");
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
GetPoolDeviceTypeName(_In_z_count_c_(MAX_POOL) const WCHAR *Pool, _Out_cap_c_(MAX_POOL_DEVICE_TYPE) WCHAR *Name)
{
    if (_snwprintf_s(Name, MAX_POOL_DEVICE_TYPE, _TRUNCATE, L"%.*s Tunnel", MAX_POOL, Pool) == -1)
        return LOG(WINTUN_LOG_ERR, L"Pool name too long"), ERROR_INVALID_PARAMETER;
    return ERROR_SUCCESS;
}

static WINTUN_STATUS
IsPoolMember(
    _In_z_count_c_(MAX_POOL) const WCHAR *Pool,
    _In_ HDEVINFO DevInfo,
    _In_ SP_DEVINFO_DATA *DevInfoData,
    _Out_ BOOL *IsMember)
{
    WCHAR *DeviceDesc, *FriendlyName;
    DWORD Result = GetDeviceRegistryString(DevInfo, DevInfoData, SPDRP_DEVICEDESC, &DeviceDesc);
    if (Result != ERROR_SUCCESS)
    {
        LOG(WINTUN_LOG_ERR, L"Failed to query device description property");
        return Result;
    }
    Result = GetDeviceRegistryString(DevInfo, DevInfoData, SPDRP_FRIENDLYNAME, &FriendlyName);
    if (Result != ERROR_SUCCESS)
    {
        LOG(WINTUN_LOG_ERR, L"Failed to query friendly name property");
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
    _In_z_count_c_(MAX_POOL) const WCHAR *Pool,
    _In_ HDEVINFO DevInfo,
    _In_ SP_DEVINFO_DATA *DevInfoData,
    _Out_ WINTUN_ADAPTER **Adapter)
{
    DWORD Result;

    /* Open HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\<class>\<id> registry key. */
    HKEY Key = SetupDiOpenDevRegKey(DevInfo, DevInfoData, DICS_FLAG_GLOBAL, 0, DIREG_DRV, KEY_QUERY_VALUE);
    if (Key == INVALID_HANDLE_VALUE)
        return LOG_LAST_ERROR(L"Opening device registry key failed");

    *Adapter = HeapAlloc(ModuleHeap, 0, sizeof(WINTUN_ADAPTER));
    if (!*Adapter)
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
        LOG(WINTUN_LOG_ERR, L"Failed to query NetCfgInstanceId value");
        goto cleanupAdapter;
    }
    if (FAILED(CLSIDFromString(ValueStr, &(*Adapter)->CfgInstanceID)))
    {
        LOG(WINTUN_LOG_ERR, L"NetCfgInstanceId is not a GUID");
        HeapFree(ModuleHeap, 0, ValueStr);
        Result = ERROR_INVALID_DATA;
        goto cleanupAdapter;
    }
    HeapFree(ModuleHeap, 0, ValueStr);

    /* Read the NetLuidIndex value. */
    Result = RegistryQueryDWORD(Key, L"NetLuidIndex", &(*Adapter)->LuidIndex, TRUE);
    if (Result != ERROR_SUCCESS)
    {
        LOG(WINTUN_LOG_ERR, L"Failed to query NetLuidIndex value");
        goto cleanupAdapter;
    }

    /* Read the NetLuidIndex value. */
    Result = RegistryQueryDWORD(Key, L"*IfType", &(*Adapter)->IfType, TRUE);
    if (Result != ERROR_SUCCESS)
    {
        LOG(WINTUN_LOG_ERR, L"Failed to query *IfType value");
        goto cleanupAdapter;
    }

    DWORD Size;
    if (!SetupDiGetDeviceInstanceIdW(
            DevInfo, DevInfoData, (*Adapter)->DevInstanceID, _countof((*Adapter)->DevInstanceID), &Size))
    {
        Result = LOG_LAST_ERROR(L"Failed to get device instance ID");
        goto cleanupAdapter;
    }

    if (wcsncpy_s((*Adapter)->Pool, _countof((*Adapter)->Pool), Pool, _TRUNCATE) == STRUNCATE)
    {
        LOG(WINTUN_LOG_ERR, L"Pool name too long");
        Result = ERROR_INVALID_PARAMETER;
        goto cleanupAdapter;
    }
    Result = ERROR_SUCCESS;

cleanupAdapter:
    if (Result != ERROR_SUCCESS)
        HeapFree(ModuleHeap, 0, *Adapter);
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
WintunGetAdapter(
    _In_z_count_c_(MAX_POOL) const WCHAR *Pool,
    _In_z_count_c_(MAX_ADAPTER_NAME) const WCHAR *Name,
    _Out_ WINTUN_ADAPTER **Adapter)
{
    DWORD Result;
    HANDLE Mutex = NamespaceTakeMutex(Pool);
    if (!Mutex)
        return ERROR_INVALID_HANDLE;

    HDEVINFO DevInfo = SetupDiGetClassDevsExW(&GUID_DEVCLASS_NET, NULL, NULL, DIGCF_PRESENT, NULL, NULL, NULL);
    if (DevInfo == INVALID_HANDLE_VALUE)
    {
        Result = LOG_LAST_ERROR(L"Failed to get present class devices");
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
            LOG(WINTUN_LOG_ERR, L"Failed to determine hardware ID");
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
            LOG(WINTUN_LOG_ERR, L"Failed to determine pool membership");
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
WintunSetAdapterName(_In_ const WINTUN_ADAPTER *Adapter, _In_z_count_c_(MAX_ADAPTER_NAME) const WCHAR *Name)
{
    DWORD Result;
    const int MaxSuffix = 1000;
    WCHAR AvailableName[MAX_ADAPTER_NAME];
    if (wcsncpy_s(AvailableName, _countof(AvailableName), Name, _TRUNCATE) == STRUNCATE)
        return LOG(WINTUN_LOG_ERR, L"Pool name too long"), ERROR_INVALID_PARAMETER;
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
                    if (_snwprintf_s(
                            Proposal, _countof(Proposal), _TRUNCATE, L"%.*s %d", MAX_ADAPTER_NAME, Name, j + 1) == -1)
                        return LOG(WINTUN_LOG_ERR, L"Pool name too long"), ERROR_INVALID_PARAMETER;
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
        if (_snwprintf_s(
                AvailableName, _countof(AvailableName), _TRUNCATE, L"%.*s %d", MAX_ADAPTER_NAME, Name, i + 1) == -1)
            return LOG(WINTUN_LOG_ERR, L"Pool name too long"), ERROR_INVALID_PARAMETER;
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
WintunGetAdapterLUID(_In_ const WINTUN_ADAPTER *Adapter, _Out_ LUID *Luid)
{
    *(LONGLONG *)Luid = (((LONGLONG)Adapter->LuidIndex & ((1 << 24) - 1)) << 24) |
                        (((LONGLONG)Adapter->IfType & ((1 << 16) - 1)) << 48);
}

WINTUN_STATUS WINAPI
WintunGetAdapterDeviceObject(_In_ const WINTUN_ADAPTER *Adapter, _Out_ HANDLE *Handle)
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
#if defined(HAVE_EV) && defined(HAVE_WHQL)
    DWORD MajorVersion;
    RtlGetNtVersionNumbers(&MajorVersion, NULL, NULL);
    return MajorVersion >= 10;
#elif defined(HAVE_WHQL)
    return TRUE;
#else
    return FALSE;
#endif
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
    return DrvInfoDetailData->CompatIDsOffset > 1 && !_wcsicmp(DrvInfoDetailData->HardwareID, WINTUN_HWID) ||
           DrvInfoDetailData->CompatIDsLength &&
               IsOurHardwareID(DrvInfoDetailData->HardwareID + DrvInfoDetailData->CompatIDsOffset);
}

static BOOL
IsNewer(_In_ const SP_DRVINFO_DATA_W *DrvInfoData, _In_ const FILETIME *DriverDate, _In_ DWORDLONG DriverVersion)
{
    if (DrvInfoData->DriverDate.dwHighDateTime > DriverDate->dwHighDateTime)
        return TRUE;
    if (DrvInfoData->DriverDate.dwHighDateTime < DriverDate->dwHighDateTime)
        return FALSE;

    if (DrvInfoData->DriverDate.dwLowDateTime > DriverDate->dwLowDateTime)
        return TRUE;
    if (DrvInfoData->DriverDate.dwLowDateTime < DriverDate->dwLowDateTime)
        return FALSE;

    if (DrvInfoData->DriverVersion > DriverVersion)
        return TRUE;
    if (DrvInfoData->DriverVersion < DriverVersion)
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
        LOG(WINTUN_LOG_ERR, L"Failed to query IpConfig value");
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

static WINTUN_STATUS
CreateAdapter(
    _In_z_count_c_(MAX_PATH) const WCHAR *InfPath,
    _In_z_count_c_(MAX_POOL) const WCHAR *Pool,
    _In_z_count_c_(MAX_ADAPTER_NAME) const WCHAR *Name,
    _In_opt_ const GUID *RequestedGUID,
    _Out_ WINTUN_ADAPTER **Adapter,
    _Inout_ BOOL *RebootRequired)
{
    DWORD Result;
    HANDLE Mutex = NamespaceTakeMutex(Pool);
    if (!Mutex)
        return ERROR_INVALID_HANDLE;

    HDEVINFO DevInfo = SetupDiCreateDeviceInfoListExW(&GUID_DEVCLASS_NET, NULL, NULL, NULL);
    if (DevInfo == INVALID_HANDLE_VALUE)
    {
        Result = LOG_LAST_ERROR(L"Creating empty device information set failed");
        goto cleanupMutex;
    }

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
    DevInstallParams.Flags |= DI_QUIETINSTALL | DI_ENUMSINGLEINF;
    wcscpy_s(DevInstallParams.DriverPath, _countof(DevInstallParams.DriverPath), InfPath);
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
    if (!SetupDiBuildDriverInfoList(DevInfo, &DevInfoData, SPDIT_COMPATDRIVER)) /* TODO: This takes ~510ms */
    {
        Result = LOG_LAST_ERROR(L"Failed building driver info list");
        goto cleanupDevInfo;
    }

    FILETIME DriverDate = { 0, 0 };
    DWORDLONG DriverVersion = 0;
    for (DWORD EnumIndex = 0;; ++EnumIndex) /* TODO: This loop takes ~600ms */
    {
        SP_DRVINFO_DATA_W DrvInfoData = { .cbSize = sizeof(SP_DRVINFO_DATA_W) };
        if (!SetupDiEnumDriverInfoW(DevInfo, &DevInfoData, SPDIT_COMPATDRIVER, EnumIndex, &DrvInfoData))
        {
            if (GetLastError() == ERROR_NO_MORE_ITEMS)
                break;
            continue;
        }

        /* Check the driver version first, since the check is trivial and will save us iterating over hardware IDs for
         * any driver versioned prior our best match. */
        if (!IsNewer(&DrvInfoData, &DriverDate, DriverVersion))
            continue;

        SP_DRVINFO_DETAIL_DATA_W *DrvInfoDetailData;
        if (AdapterGetDrvInfoDetail(DevInfo, &DevInfoData, &DrvInfoData, &DrvInfoDetailData) != ERROR_SUCCESS)
        {
            LOG(WINTUN_LOG_WARN, L"Failed getting driver info detail");
            continue;
        }
        if (!IsOurDrvInfoDetail(DrvInfoDetailData))
        {
            HeapFree(ModuleHeap, 0, DrvInfoDetailData);
            continue;
        }
        HeapFree(ModuleHeap, 0, DrvInfoDetailData);

        if (!SetupDiSetSelectedDriverW(DevInfo, &DevInfoData, &DrvInfoData))
            continue;

        DriverDate = DrvInfoData.DriverDate;
        DriverVersion = DrvInfoData.DriverVersion;
    }

    if (!DriverVersion)
    {
        LOG(WINTUN_LOG_ERR, L"No appropriate drivers found");
        Result = ERROR_FILE_NOT_FOUND;
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
        Result = LOG_LAST_ERROR(L"Failed to set device description");
        goto cleanupNetDevRegKey;
    }

    /* DIF_INSTALLDEVICE returns almost immediately, while the device installation continues in the background. It might
     * take a while, before all registry keys and values are populated. */
    WCHAR *DummyStr;
    Result = RegistryQueryStringWait(NetDevRegKey, L"NetCfgInstanceId", WAIT_FOR_REGISTRY_TIMEOUT, &DummyStr);
    if (Result != ERROR_SUCCESS)
    {
        LOG(WINTUN_LOG_ERR, L"Failed to query NetCfgInstanceId value");
        goto cleanupNetDevRegKey;
    }
    HeapFree(ModuleHeap, 0, DummyStr);
    DWORD DummyDWORD;
    Result = RegistryQueryDWORDWait(NetDevRegKey, L"NetLuidIndex", WAIT_FOR_REGISTRY_TIMEOUT, &DummyDWORD);
    if (Result != ERROR_SUCCESS)
    {
        LOG(WINTUN_LOG_ERR, L"Failed to query NetLuidIndex value");
        goto cleanupNetDevRegKey;
    }
    Result = RegistryQueryDWORDWait(NetDevRegKey, L"*IfType", WAIT_FOR_REGISTRY_TIMEOUT, &DummyDWORD);
    if (Result != ERROR_SUCCESS)
    {
        LOG(WINTUN_LOG_ERR, L"Failed to query *IfType value");
        goto cleanupNetDevRegKey;
    }

    Result = CreateAdapterData(Pool, DevInfo, &DevInfoData, Adapter);
    if (Result != ERROR_SUCCESS)
    {
        LOG(WINTUN_LOG_ERR, L"Failed to create adapter data");
        goto cleanupNetDevRegKey;
    }

    HKEY TcpipAdapterRegKey;
    WCHAR TcpipAdapterRegPath[MAX_REG_PATH];
    Result = GetTcpipAdapterRegPath(*Adapter, TcpipAdapterRegPath);
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
        LOG(WINTUN_LOG_ERR, L"Failed to open adapter-specific TCP/IP adapter registry key");
        goto cleanupAdapter;
    }
    Result = RegistryQueryStringWait(TcpipAdapterRegKey, L"IpConfig", WAIT_FOR_REGISTRY_TIMEOUT, &DummyStr);
    if (Result != ERROR_SUCCESS)
    {
        LOG(WINTUN_LOG_ERR, L"Failed to query IpConfig value");
        goto cleanupTcpipAdapterRegKey;
    }
    HeapFree(ModuleHeap, 0, DummyStr);

    HKEY TcpipInterfaceRegKey;
    WCHAR TcpipInterfaceRegPath[MAX_REG_PATH];
    Result = GetTcpipInterfaceRegPath(*Adapter, TcpipInterfaceRegPath);
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
        LOG_ERROR(L"Failed to set EnableDeadGWDetect", Result);

    Result = WintunSetAdapterName(*Adapter, Name);
    if (Result != ERROR_SUCCESS)
        LOG_ERROR(L"Failed to set adapter name", Result);
    RegCloseKey(TcpipInterfaceRegKey);
cleanupTcpipAdapterRegKey:
    RegCloseKey(TcpipAdapterRegKey);
cleanupAdapter:
    if (Result != ERROR_SUCCESS)
        HeapFree(ModuleHeap, 0, *Adapter);
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
cleanupDriverInfoList:
    SetupDiDestroyDriverInfoList(DevInfo, &DevInfoData, SPDIT_COMPATDRIVER);
cleanupDevInfo:
    SetupDiDestroyDeviceInfoList(DevInfo);
cleanupMutex:
    NamespaceReleaseMutex(Mutex);
    return Result;
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
    if (!CreateDirectoryW(RandomTempSubDirectory, SecurityAttributes))
        return LOG_LAST_ERROR(L"Failed to create temporary folder");
    return ERROR_SUCCESS;
}

#ifdef MAYBE_WOW64

typedef struct _PROCESS_STDOUT_STATE
{
    HANDLE Stdout;
    WCHAR *Response;
    DWORD ResponseCapacity;
} PROCESS_STDOUT_STATE;

static DWORD WINAPI
ProcessStdout(_Inout_ PROCESS_STDOUT_STATE *State)
{
    for (DWORD Offset = 0, MaxLen = State->ResponseCapacity - 1; Offset < MaxLen;)
    {
        DWORD SizeRead;
        if (!ReadFile(State->Stdout, State->Response + Offset, sizeof(WCHAR) * (MaxLen - Offset), &SizeRead, NULL))
            return ERROR_SUCCESS;
        if (SizeRead % sizeof(WCHAR))
            return ERROR_INVALID_DATA;
        Offset += SizeRead / sizeof(WCHAR);
        State->Response[Offset] = 0;
    }
    return ERROR_BUFFER_OVERFLOW;
}

static DWORD WINAPI
ProcessStderr(_In_ HANDLE Stderr)
{
    enum
    {
        OnNone,
        OnLevelStart,
        OnLevel,
        OnLevelEnd,
        OnSpace,
        OnMsg
    } State = OnNone;
    WCHAR Msg[0x200];
    DWORD Count = 0;
    WINTUN_LOGGER_LEVEL Level = WINTUN_LOG_INFO;
    for (;;)
    {
        WCHAR Buf[0x200];
        DWORD SizeRead;
        if (!ReadFile(Stderr, Buf, sizeof(Buf), &SizeRead, NULL))
            return ERROR_SUCCESS;
        if (SizeRead % sizeof(WCHAR))
            return ERROR_INVALID_DATA;
        SizeRead /= sizeof(WCHAR);
        for (DWORD i = 0; i < SizeRead; ++i)
        {
            WCHAR c = Buf[i];
            if (State == OnNone && c == L'[')
                State = OnLevelStart;
            else if (
                State == OnLevelStart && ((Level = WINTUN_LOG_INFO, c == L'+') ||
                                          (Level = WINTUN_LOG_WARN, c == L'-') || (Level = WINTUN_LOG_ERR, c == L'!')))
                State = OnLevelEnd;
            else if (State == OnLevelEnd && c == L']')
                State = OnSpace;
            else if (State == OnSpace && !iswspace(c) || State == OnMsg && c != L'\r' && c != L'\n')
            {
                if (Count < _countof(Msg) - 1)
                    Msg[Count++] = c;
                State = OnMsg;
            }
            else if (State == OnMsg && c == L'\n')
            {
                Msg[Count] = 0;
                Logger(Level, Msg);
                State = OnNone;
                Count = 0;
            }
        }
    }
}

static WINTUN_STATUS
ExecuteRunDll32(
    _In_z_ const WCHAR *Arguments,
    _Out_z_cap_c_(ResponseCapacity) WCHAR *Response,
    _In_ DWORD ResponseCapacity)
{
    WCHAR WindowsDirectory[MAX_PATH];
    if (!GetWindowsDirectoryW(WindowsDirectory, _countof(WindowsDirectory)))
        return LOG_LAST_ERROR(L"Failed to get Windows folder");
    WCHAR RunDll32Path[MAX_PATH];
    if (!PathCombineW(RunDll32Path, WindowsDirectory, L"Sysnative\\rundll32.exe"))
        return ERROR_BUFFER_OVERFLOW;

    DWORD Result;
    WCHAR RandomTempSubDirectory[MAX_PATH];
    if ((Result = CreateTemporaryDirectory(RandomTempSubDirectory)) != ERROR_SUCCESS)
        return LOG(WINTUN_LOG_ERR, L"Failed to create temporary folder"), Result;
    WCHAR DllPath[MAX_PATH] = { 0 };
    if (!PathCombineW(DllPath, RandomTempSubDirectory, L"wintun.dll"))
    {
        Result = ERROR_BUFFER_OVERFLOW;
        goto cleanupDirectory;
    }
    const WCHAR *WintunDllResourceName;
    switch (NativeMachine)
    {
    case IMAGE_FILE_MACHINE_AMD64:
        WintunDllResourceName = L"wintun-amd64.dll";
        break;
    case IMAGE_FILE_MACHINE_ARM64:
        WintunDllResourceName = L"wintun-arm64.dll";
        break;
    default:
        LOG(WINTUN_LOG_ERR, L"Failed to copy resource");
        Result = ERROR_NOT_SUPPORTED;
        goto cleanupDirectory;
    }
    if ((Result = ResourceCopyToFile(DllPath, WintunDllResourceName)) != ERROR_SUCCESS)
    {
        LOG(WINTUN_LOG_ERR, L"Failed to copy resource");
        goto cleanupDelete;
    }
    size_t CommandLineLen = 10 + MAX_PATH + 2 + wcslen(Arguments) + 1;
    WCHAR *CommandLine = HeapAlloc(ModuleHeap, 0, CommandLineLen * sizeof(WCHAR));
    if (!CommandLine)
    {
        LOG(WINTUN_LOG_ERR, L"Out of memory");
        Result = ERROR_OUTOFMEMORY;
        goto cleanupDelete;
    }
    if (_snwprintf_s(CommandLine, CommandLineLen, _TRUNCATE, L"rundll32 \"%.*s\",%s", MAX_PATH, DllPath, Arguments) ==
        -1)
    {
        LOG(WINTUN_LOG_ERR, L"Command line too long");
        Result = ERROR_INVALID_PARAMETER;
        goto cleanupDelete;
    }
    HANDLE StreamRStdout = INVALID_HANDLE_VALUE, StreamRStderr = INVALID_HANDLE_VALUE,
           StreamWStdout = INVALID_HANDLE_VALUE, StreamWStderr = INVALID_HANDLE_VALUE;
    if (!CreatePipe(&StreamRStdout, &StreamWStdout, SecurityAttributes, 0) ||
        !CreatePipe(&StreamRStderr, &StreamWStderr, SecurityAttributes, 0))
    {
        Result = LOG_LAST_ERROR(L"Failed to create pipes");
        goto cleanupPipes;
    }
    if (!SetHandleInformation(StreamWStdout, HANDLE_FLAG_INHERIT, HANDLE_FLAG_INHERIT) ||
        !SetHandleInformation(StreamWStderr, HANDLE_FLAG_INHERIT, HANDLE_FLAG_INHERIT))
    {
        Result = LOG_LAST_ERROR(L"Failed to set handle info");
        goto cleanupPipes;
    }
    if (ResponseCapacity)
        Response[0] = 0;
    PROCESS_STDOUT_STATE ProcessStdoutState = { .Stdout = StreamRStdout,
                                                .Response = Response,
                                                .ResponseCapacity = ResponseCapacity };
    HANDLE ThreadStdout = NULL, ThreadStderr = NULL;
    if ((ThreadStdout = CreateThread(SecurityAttributes, 0, ProcessStdout, &ProcessStdoutState, 0, NULL)) == NULL ||
        (ThreadStderr = CreateThread(SecurityAttributes, 0, ProcessStderr, StreamRStderr, 0, NULL)) == NULL)
    {
        Result = LOG_LAST_ERROR(L"Failed to spawn reader threads");
        goto cleanupThreads;
    }
    STARTUPINFOW si = { .cb = sizeof(STARTUPINFO),
                        .dwFlags = STARTF_USESHOWWINDOW | STARTF_USESTDHANDLES,
                        .wShowWindow = SW_HIDE,
                        .hStdOutput = StreamWStdout,
                        .hStdError = StreamWStderr };
    PROCESS_INFORMATION pi;
    if (!CreateProcessW(RunDll32Path, CommandLine, NULL, NULL, TRUE, 0, NULL, NULL, &si, &pi))
    {
        Result = LOG_LAST_ERROR(L"Creating process failed");
        goto cleanupThreads;
    }
    WaitForSingleObject(pi.hProcess, INFINITE);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
cleanupThreads:
    if (ThreadStderr)
    {
        CloseHandle(StreamWStderr);
        StreamWStderr = INVALID_HANDLE_VALUE;
        WaitForSingleObject(ThreadStderr, INFINITE);
        CloseHandle(ThreadStderr);
    }
    if (ThreadStdout)
    {
        CloseHandle(StreamWStdout);
        StreamWStdout = INVALID_HANDLE_VALUE;
        WaitForSingleObject(ThreadStdout, INFINITE);
        if (!GetExitCodeThread(ThreadStdout, &Result))
            Result = LOG_LAST_ERROR(L"Failed to retrieve thread result");
        else if (Result != ERROR_SUCCESS)
            LOG_ERROR(L"Failed to read process output", Result);
        CloseHandle(ThreadStdout);
    }
cleanupPipes:
    CloseHandle(StreamRStderr);
    CloseHandle(StreamWStderr);
    CloseHandle(StreamRStdout);
    CloseHandle(StreamWStdout);
    HeapFree(ModuleHeap, 0, CommandLine);
cleanupDelete:
    DeleteFileW(DllPath);
cleanupDirectory:
    RemoveDirectoryW(RandomTempSubDirectory);
    return Result;
}

static WINTUN_STATUS
GetAdapter(_In_z_count_c_(MAX_POOL) const WCHAR *Pool, _In_ const GUID *CfgInstanceID, _Out_ WINTUN_ADAPTER **Adapter)
{
    HANDLE Mutex = NamespaceTakeMutex(Pool);
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

static WINTUN_STATUS
CreateAdapterNatively(
    _In_z_count_c_(MAX_POOL) const WCHAR *Pool,
    _In_z_count_c_(MAX_ADAPTER_NAME) const WCHAR *Name,
    _In_opt_ const GUID *RequestedGUID,
    _Out_ WINTUN_ADAPTER **Adapter,
    _Inout_ BOOL *RebootRequired)
{
    LOG(WINTUN_LOG_INFO, L"Spawning native process");
    WCHAR RequestedGUIDStr[MAX_GUID_STRING_LEN];
    WCHAR Arguments[15 + MAX_POOL + 3 + MAX_ADAPTER_NAME + 2 + MAX_GUID_STRING_LEN + 1];
    if (_snwprintf_s(
            Arguments,
            _countof(Arguments),
            _TRUNCATE,
            RequestedGUID ? L"CreateAdapter \"%.*s\" \"%.*s\" %.*s" : L"CreateAdapter \"%.*s\" \"%.*s\"",
            MAX_POOL,
            Pool,
            MAX_ADAPTER_NAME,
            Name,
            RequestedGUID ? StringFromGUID2(RequestedGUID, RequestedGUIDStr, _countof(RequestedGUIDStr)) : 0,
            RequestedGUIDStr) == -1)
        return LOG(WINTUN_LOG_ERR, L"Command line too long"), ERROR_INVALID_PARAMETER;
    WCHAR Response[8 + 1 + MAX_GUID_STRING_LEN + 1 + 8 + 1];
    DWORD Result = ExecuteRunDll32(Arguments, Response, _countof(Response));
    if (Result != ERROR_SUCCESS)
    {
        LOG(WINTUN_LOG_ERR, L"Error executing worker process");
        return Result;
    }
    int Argc;
    WCHAR **Argv = CommandLineToArgvW(Response, &Argc);
    GUID CfgInstanceID;
    if (Argc < 3 || FAILED(CLSIDFromString(Argv[1], &CfgInstanceID)))
    {
        LOG(WINTUN_LOG_ERR, L"Incomplete or invalid response");
        Result = ERROR_INVALID_PARAMETER;
        goto cleanupArgv;
    }
    Result = wcstoul(Argv[0], NULL, 16);
    if (Result == ERROR_SUCCESS && GetAdapter(Pool, &CfgInstanceID, Adapter) != ERROR_SUCCESS)
    {
        LOG(WINTUN_LOG_ERR, L"Failed to get adapter");
        Result = ERROR_FILE_NOT_FOUND;
    }
    if (wcstoul(Argv[2], NULL, 16))
        *RebootRequired = TRUE;
cleanupArgv:
    LocalFree(Argv);
    return Result;
}

#endif

WINTUN_STATUS WINAPI
WintunCreateAdapter(
    _In_z_count_c_(MAX_POOL) const WCHAR *Pool,
    _In_z_count_c_(MAX_ADAPTER_NAME) const WCHAR *Name,
    _In_opt_ const GUID *RequestedGUID,
    _Out_ WINTUN_ADAPTER **Adapter,
    _Inout_ BOOL *RebootRequired)
{
#ifdef MAYBE_WOW64
    if (NativeMachine != IMAGE_FILE_PROCESS)
        return CreateAdapterNatively(Pool, Name, RequestedGUID, Adapter, RebootRequired);
#endif

    DWORD Result = ERROR_SUCCESS;
    WCHAR RandomTempSubDirectory[MAX_PATH];
    if ((Result = CreateTemporaryDirectory(RandomTempSubDirectory)) != ERROR_SUCCESS)
        return LOG(WINTUN_LOG_ERR, L"Failed to create temporary folder"), Result;

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
        LOG(WINTUN_LOG_WARN, L"Unable to install code signing certificate");

    LOG(WINTUN_LOG_INFO, L"Copying resources to temporary path");
    if ((Result = ResourceCopyToFile(CatPath, UseWHQL ? L"wintun-whql.cat" : L"wintun.cat")) != ERROR_SUCCESS ||
        (Result = ResourceCopyToFile(SysPath, UseWHQL ? L"wintun-whql.sys" : L"wintun.sys")) != ERROR_SUCCESS ||
        (Result = ResourceCopyToFile(InfPath, UseWHQL ? L"wintun-whql.inf" : L"wintun.inf")) != ERROR_SUCCESS)
    {
        LOG(WINTUN_LOG_ERR, L"Failed to copy resources");
        goto cleanupDelete;
    }

    LOG(WINTUN_LOG_INFO, L"Installing driver");
    WCHAR InfStorePath[MAX_PATH];
    WCHAR *InfStoreFilename;
    if (!SetupCopyOEMInfW(InfPath, NULL, SPOST_PATH, 0, InfStorePath, _countof(InfStorePath), NULL, &InfStoreFilename))
    {
        Result = LOG_LAST_ERROR(L"Could not install driver to store");
        goto cleanupDelete;
    }

    Result = CreateAdapter(InfPath, Pool, Name, RequestedGUID, Adapter, RebootRequired);

    LOG(WINTUN_LOG_INFO, L"Removing driver");
    if (!SetupUninstallOEMInfW(InfStoreFilename, SUOI_FORCEDELETE, NULL))
    {
        LOG_LAST_ERROR(L"Unable to remove existing driver");
        Result = Result != ERROR_SUCCESS ? Result : GetLastError();
    }
cleanupDelete:
    DeleteFileW(CatPath);
    DeleteFileW(SysPath);
    DeleteFileW(InfPath);
cleanupDirectory:
    RemoveDirectoryW(RandomTempSubDirectory);
    return Result;
}

#ifdef MAYBE_WOW64

static WINTUN_STATUS
DeleteAdapterNatively(_In_ const WINTUN_ADAPTER *Adapter, _Inout_ BOOL *RebootRequired)
{
    LOG(WINTUN_LOG_INFO, L"Spawning native process");
    WCHAR GuidStr[MAX_GUID_STRING_LEN];
    WCHAR Arguments[14 + MAX_GUID_STRING_LEN + 1];
    if (_snwprintf_s(
            Arguments,
            _countof(Arguments),
            _TRUNCATE,
            L"DeleteAdapter %.*s",
            StringFromGUID2(&Adapter->CfgInstanceID, GuidStr, _countof(GuidStr)),
            GuidStr) == -1)
        return LOG(WINTUN_LOG_ERR, L"Command line too long"), ERROR_INVALID_PARAMETER;
    WCHAR Response[8 + 1 + 8 + 1];
    DWORD Result = ExecuteRunDll32(Arguments, Response, _countof(Response));
    if (Result != ERROR_SUCCESS)
        LOG(WINTUN_LOG_ERR, L"Error executing worker process");
    int Argc;
    WCHAR **Argv = CommandLineToArgvW(Response, &Argc);
    if (Argc < 2)
    {
        LOG(WINTUN_LOG_ERR, L"Incomplete or invalid response");
        Result = ERROR_INVALID_PARAMETER;
        goto cleanupArgv;
    }
    Result = wcstoul(Argv[0], NULL, 16);
    if (wcstoul(Argv[1], NULL, 16))
        *RebootRequired = TRUE;
cleanupArgv:
    LocalFree(Argv);
    return Result;
}

#endif

WINTUN_STATUS WINAPI
WintunDeleteAdapter(_In_ const WINTUN_ADAPTER *Adapter, _Inout_ BOOL *RebootRequired)
{
#ifdef MAYBE_WOW64
    if (NativeMachine != IMAGE_FILE_PROCESS)
        return DeleteAdapterNatively(Adapter, RebootRequired);
#endif

    HDEVINFO DevInfo;
    SP_DEVINFO_DATA DevInfoData;
    DWORD Result = GetDevInfoData(&Adapter->CfgInstanceID, &DevInfo, &DevInfoData);
    if (Result == ERROR_FILE_NOT_FOUND)
        return ERROR_SUCCESS;
    if (Result != ERROR_SUCCESS)
    {
        LOG(WINTUN_LOG_ERR, L"Failed to get device info data");
        return Result;
    }
    SetQuietInstall(DevInfo, &DevInfoData);
    SP_REMOVEDEVICE_PARAMS RemoveDeviceParams = { .ClassInstallHeader = { .cbSize = sizeof(SP_CLASSINSTALL_HEADER),
                                                                          .InstallFunction = DIF_REMOVE },
                                                  .Scope = DI_REMOVEDEVICE_GLOBAL };
    if (SetupDiSetClassInstallParamsW(
            DevInfo, &DevInfoData, &RemoveDeviceParams.ClassInstallHeader, sizeof(RemoveDeviceParams)) &&
        SetupDiCallClassInstaller(DIF_REMOVE, DevInfo, &DevInfoData))
        *RebootRequired = *RebootRequired || CheckReboot(DevInfo, &DevInfoData);
    else
        Result = LOG_LAST_ERROR(L"Unable to remove existing adapter");
    SetupDiDestroyDeviceInfoList(DevInfo);
    return Result;
}

WINTUN_STATUS WINAPI
WintunEnumAdapters(_In_z_count_c_(MAX_POOL) const WCHAR *Pool, _In_ WINTUN_ENUM_FUNC Func, _In_ LPARAM Param)
{
    HANDLE Mutex = NamespaceTakeMutex(Pool);
    if (!Mutex)
        return ERROR_INVALID_HANDLE;
    DWORD Result = ERROR_SUCCESS;
    HDEVINFO DevInfo = SetupDiGetClassDevsExW(&GUID_DEVCLASS_NET, NULL, NULL, DIGCF_PRESENT, NULL, NULL, NULL);
    if (DevInfo == INVALID_HANDLE_VALUE)
    {
        Result = LOG_LAST_ERROR(L"Failed to get present class devices");
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
            LOG(WINTUN_LOG_ERR, L"Failed to determine pool membership");
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

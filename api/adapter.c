/* SPDX-License-Identifier: GPL-2.0
 *
 * Copyright (C) 2018-2021 WireGuard LLC. All Rights Reserved.
 */

#include <Windows.h>
#include <winternl.h>
#include <cfgmgr32.h>
#include <devguid.h>
#include <iphlpapi.h>
#include <objbase.h>
#include <ndisguid.h>
#include <SetupAPI.h>
#include <Shlwapi.h>
#include <devioctl.h>
#include <wchar.h>
#include <initguid.h> /* Keep these two at bottom in this order, so that we only generate extra GUIDs for devpkey. The other keys we'll get from uuid.lib like usual. */
#include <devpkey.h>

/* We pretend we're Windows 8, and then hack around the limitation in Windows 7 below. */
#if NTDDI_VERSION == NTDDI_WIN7
#    undef NTDDI_VERSION
#    define NTDDI_VERSION NTDDI_WIN8
#    include <devquery.h>
#    include <swdevice.h>
#    undef NTDDI_VERSION
#    define NTDDI_VERSION NTDDI_WIN7
#else
#    include <devquery.h>
#    include <swdevice.h>
#endif

#include "adapter.h"
#include "driver.h"
#include "logger.h"
#include "main.h"
#include "namespace.h"
#include "nci.h"
#include "ntdll.h"
#include "rundll32.h"
#include "registry.h"
#include "adapter_win7.h"

#pragma warning(disable : 4221) /* nonstandard: address of automatic in initializer */

const DEVPROPKEY DEVPKEY_Wintun_Name = {
    { 0x3361c968, 0x2f2e, 0x4660, { 0xb4, 0x7e, 0x69, 0x9c, 0xdc, 0x4c, 0x32, 0xb9 } },
    DEVPROPID_FIRST_USABLE + 1
};

_Must_inspect_result_
static _Return_type_success_(return != FALSE)
BOOL
PopulateAdapterData(_Inout_ WINTUN_ADAPTER *Adapter)
{
    DWORD LastError = ERROR_SUCCESS;

    /* Open HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\<class>\<id> registry key. */
    HKEY Key =
        SetupDiOpenDevRegKey(Adapter->DevInfo, &Adapter->DevInfoData, DICS_FLAG_GLOBAL, 0, DIREG_DRV, KEY_QUERY_VALUE);
    if (Key == INVALID_HANDLE_VALUE)
    {
        LOG_LAST_ERROR(L"Failed to open adapter device registry key");
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

    Adapter->InterfaceFilename = AdapterGetDeviceObjectFileName(Adapter->DevInstanceID);
    if (!Adapter->InterfaceFilename)
    {
        LastError = LOG_LAST_ERROR(L"Unable to determine device object file name");
        goto cleanupKey;
    }

cleanupKey:
    RegCloseKey(Key);
    return RET_ERROR(TRUE, LastError);
}

static volatile LONG OrphanThreadIsWorking = FALSE;

static DWORD
DoOrphanedDeviceCleanup(_In_opt_ LPVOID Ctx)
{
    AdapterCleanupOrphanedDevices();
    OrphanThreadIsWorking = FALSE;
    return 0;
}

static VOID QueueUpOrphanedDeviceCleanupRoutine(VOID)
{
    if (InterlockedCompareExchange(&OrphanThreadIsWorking, TRUE, FALSE) == FALSE)
        QueueUserWorkItem(DoOrphanedDeviceCleanup, NULL, 0);
}

VOID AdapterCleanupOrphanedDevices(VOID)
{
    HANDLE DeviceInstallationMutex = NamespaceTakeDeviceInstallationMutex();
    if (!DeviceInstallationMutex)
    {
        LOG_LAST_ERROR(L"Failed to take device installation mutex");
        return;
    }

    if (IsWindows7)
    {
        AdapterCleanupOrphanedDevicesWin7();
        goto cleanupDeviceInstallationMutex;
    }

    HDEVINFO DevInfo = SetupDiGetClassDevsExW(&GUID_DEVCLASS_NET, WINTUN_ENUMERATOR, NULL, 0, NULL, NULL, NULL);
    if (DevInfo == INVALID_HANDLE_VALUE)
    {
        LOG_LAST_ERROR(L"Failed to get adapters");
        goto cleanupDeviceInstallationMutex;
    }

    SP_DEVINFO_DATA DevInfoData = { .cbSize = sizeof(DevInfoData) };
    for (DWORD EnumIndex = 0;; ++EnumIndex)
    {
        if (!SetupDiEnumDeviceInfo(DevInfo, EnumIndex, &DevInfoData))
        {
            if (GetLastError() == ERROR_NO_MORE_ITEMS)
                break;
            continue;
        }
        ULONG Status, Code;
        if (CM_Get_DevNode_Status(&Status, &Code, DevInfoData.DevInst, 0) == CR_SUCCESS && !(Status & DN_HAS_PROBLEM))
            continue;

        DEVPROPTYPE PropType;
        WCHAR Name[MAX_ADAPTER_NAME] = L"<unknown>";
        SetupDiGetDevicePropertyW(
            DevInfo,
            &DevInfoData,
            &DEVPKEY_Wintun_Name,
            &PropType,
            (PBYTE)Name,
            MAX_ADAPTER_NAME * sizeof(Name[0]),
            NULL,
            0);
        if (!AdapterRemoveInstance(DevInfo, &DevInfoData))
        {
            LOG_LAST_ERROR(L"Failed to remove orphaned adapter \"%s\"", Name);
            continue;
        }
        LOG(WINTUN_LOG_INFO, L"Removed orphaned adapter \"%s\"", Name);
    }
    SetupDiDestroyDeviceInfoList(DevInfo);
cleanupDeviceInstallationMutex:
    NamespaceReleaseMutex(DeviceInstallationMutex);
}

_Use_decl_annotations_
VOID WINAPI
WintunCloseAdapter(WINTUN_ADAPTER *Adapter)
{
    if (!Adapter)
        return;
    Free(Adapter->InterfaceFilename);
    if (Adapter->SwDevice)
        SwDeviceClose(Adapter->SwDevice);
    if (Adapter->DevInfo)
    {
        if (!AdapterRemoveInstance(Adapter->DevInfo, &Adapter->DevInfoData))
            LOG_LAST_ERROR(L"Failed to remove adapter when closing");
        SetupDiDestroyDeviceInfoList(Adapter->DevInfo);
    }
    Free(Adapter);
    QueueUpOrphanedDeviceCleanupRoutine();
}

static _Return_type_success_(return != FALSE)
BOOL
RenameByNetGUID(_In_ GUID *Guid, _In_reads_or_z_(MAX_ADAPTER_NAME) LPCWSTR Name)
{
    DWORD LastError = ERROR_NOT_FOUND;
    HDEVINFO DevInfo = SetupDiGetClassDevsExW(&GUID_DEVCLASS_NET, WINTUN_ENUMERATOR, NULL, 0, NULL, NULL, NULL);
    if (DevInfo == INVALID_HANDLE_VALUE)
    {
        LastError = GetLastError();
        goto cleanup;
    }

    SP_DEVINFO_DATA DevInfoData = { .cbSize = sizeof(DevInfoData) };
    for (DWORD EnumIndex = 0;; ++EnumIndex)
    {
        if (!SetupDiEnumDeviceInfo(DevInfo, EnumIndex, &DevInfoData))
        {
            if (GetLastError() == ERROR_NO_MORE_ITEMS)
                break;
            continue;
        }

        HKEY Key = SetupDiOpenDevRegKey(DevInfo, &DevInfoData, DICS_FLAG_GLOBAL, 0, DIREG_DRV, KEY_QUERY_VALUE);
        if (Key == INVALID_HANDLE_VALUE)
            continue;
        LPWSTR ValueStr = RegistryQueryString(Key, L"NetCfgInstanceId", TRUE);
        RegCloseKey(Key);
        if (!ValueStr)
            continue;
        GUID Guid2;
        HRESULT HRet = CLSIDFromString(ValueStr, &Guid2);
        Free(ValueStr);
        if (FAILED(HRet) || memcmp(Guid, &Guid2, sizeof(*Guid)))
            continue;
        LastError = SetupDiSetDevicePropertyW(
                        DevInfo,
                        &DevInfoData,
                        &DEVPKEY_Wintun_Name,
                        DEVPROP_TYPE_STRING,
                        (PBYTE)Name,
                        (DWORD)((wcslen(Name) + 1) * sizeof(Name[0])),
                        0)
                        ? ERROR_SUCCESS
                        : GetLastError();
        break;
    }
    SetupDiDestroyDeviceInfoList(DevInfo);
cleanup:
    return RET_ERROR(TRUE, LastError);
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

static _Return_type_success_(return != FALSE)
BOOL
NciSetAdapterName(_In_ GUID *Guid, _In_reads_or_z_(MAX_ADAPTER_NAME) LPCWSTR Name)
{
    const int MaxSuffix = 1000;
    WCHAR AvailableName[MAX_ADAPTER_NAME];
    if (wcsncpy_s(AvailableName, _countof(AvailableName), Name, _TRUNCATE) == STRUNCATE)
    {
        SetLastError(ERROR_BUFFER_OVERFLOW);
        return FALSE;
    }
    for (int i = 0;; ++i)
    {
        DWORD LastError = NciSetConnectionName(Guid, AvailableName);
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
                        SetLastError(ERROR_BUFFER_OVERFLOW);
                        return FALSE;
                    }
                    if (_wcsnicmp(Proposal, AvailableName, MAX_ADAPTER_NAME) == 0)
                        continue;
                    DWORD LastError2 = NciSetConnectionName(&Guid2, Proposal);
                    if (LastError2 == ERROR_DUP_NAME)
                        continue;
                    if (!RenameByNetGUID(&Guid2, Proposal))
                        LOG_LAST_ERROR(L"Failed to set foreign adapter name to \"%s\"", Proposal);
                    if (LastError2 == ERROR_SUCCESS)
                    {
                        LastError = NciSetConnectionName(Guid, AvailableName);
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
            SetLastError(LastError);
            return FALSE;
        }
        if (_snwprintf_s(AvailableName, _countof(AvailableName), _TRUNCATE, L"%s %d", Name, i + 1) == -1)
        {
            SetLastError(ERROR_BUFFER_OVERFLOW);
            return FALSE;
        }
    }
    return TRUE;
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
    HANDLE Handle = CreateFileW(
        Adapter->InterfaceFilename,
        GENERIC_READ | GENERIC_WRITE,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        NULL,
        OPEN_EXISTING,
        0,
        NULL);
    if (Handle == INVALID_HANDLE_VALUE)
        LOG_LAST_ERROR(L"Failed to connect to adapter interface %s", Adapter->InterfaceFilename);
    return Handle;
}

_Use_decl_annotations_
LPWSTR
AdapterGetDeviceObjectFileName(LPCWSTR InstanceId)
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

typedef struct _WAIT_FOR_INTERFACE_CTX
{
    HANDLE Event;
    DWORD LastError;
} WAIT_FOR_INTERFACE_CTX;

static VOID WINAPI
WaitForInterfaceCallback(
    _In_ HDEVQUERY DevQuery,
    _Inout_ PVOID Context,
    _In_ const DEV_QUERY_RESULT_ACTION_DATA *ActionData)
{
    WAIT_FOR_INTERFACE_CTX *Ctx = Context;
    DWORD Ret = ERROR_SUCCESS;
    switch (ActionData->Action)
    {
    case DevQueryResultStateChange:
        if (ActionData->Data.State != DevQueryStateAborted)
            return;
        Ret = ERROR_DEVICE_NOT_AVAILABLE;
    case DevQueryResultAdd:
    case DevQueryResultUpdate:
        break;
    default:
        return;
    }
    Ctx->LastError = Ret;
    SetEvent(Ctx->Event);
}

_Must_inspect_result_
static _Return_type_success_(return != FALSE)
BOOL
WaitForInterface(_In_ WCHAR *InstanceId)
{
    if (IsWindows7)
        return TRUE;

    DWORD LastError = ERROR_SUCCESS;
    static const DEVPROP_BOOLEAN DevPropTrue = DEVPROP_TRUE;
    const DEVPROP_FILTER_EXPRESSION Filters[] = { { .Operator = DEVPROP_OPERATOR_EQUALS_IGNORE_CASE,
                                                    .Property.CompKey.Key = DEVPKEY_Device_InstanceId,
                                                    .Property.CompKey.Store = DEVPROP_STORE_SYSTEM,
                                                    .Property.Type = DEVPROP_TYPE_STRING,
                                                    .Property.Buffer = InstanceId,
                                                    .Property.BufferSize =
                                                        (ULONG)((wcslen(InstanceId) + 1) * sizeof(InstanceId[0])) },
                                                  { .Operator = DEVPROP_OPERATOR_EQUALS,
                                                    .Property.CompKey.Key = DEVPKEY_DeviceInterface_Enabled,
                                                    .Property.CompKey.Store = DEVPROP_STORE_SYSTEM,
                                                    .Property.Type = DEVPROP_TYPE_BOOLEAN,
                                                    .Property.Buffer = (PVOID)&DevPropTrue,
                                                    .Property.BufferSize = sizeof(DevPropTrue) },
                                                  { .Operator = DEVPROP_OPERATOR_EQUALS,
                                                    .Property.CompKey.Key = DEVPKEY_DeviceInterface_ClassGuid,
                                                    .Property.CompKey.Store = DEVPROP_STORE_SYSTEM,
                                                    .Property.Type = DEVPROP_TYPE_GUID,
                                                    .Property.Buffer = (PVOID)&GUID_DEVINTERFACE_NET,
                                                    .Property.BufferSize = sizeof(GUID_DEVINTERFACE_NET) } };
    WAIT_FOR_INTERFACE_CTX Ctx = { .Event = CreateEventW(NULL, FALSE, FALSE, NULL) };
    if (!Ctx.Event)
    {
        LastError = LOG_LAST_ERROR(L"Failed to create event");
        goto cleanup;
    }
    HDEVQUERY Query;
    HRESULT HRet = DevCreateObjectQuery(
        DevObjectTypeDeviceInterface,
        DevQueryFlagUpdateResults,
        0,
        NULL,
        _countof(Filters),
        Filters,
        WaitForInterfaceCallback,
        &Ctx,
        &Query);
    if (FAILED(HRet))
    {
        LastError = LOG_ERROR(HRet, L"Failed to create device query");
        goto cleanupEvent;
    }
    LastError = WaitForSingleObject(Ctx.Event, 15000);
    if (LastError != WAIT_OBJECT_0)
    {
        if (LastError == WAIT_FAILED)
            LastError = LOG_LAST_ERROR(L"Failed to wait for device query");
        else
            LastError = LOG_ERROR(LastError, L"Timed out waiting for device query");
        goto cleanupQuery;
    }
    LastError = Ctx.LastError;
    if (LastError != ERROR_SUCCESS)
        LastError = LOG_ERROR(LastError, L"Failed to get enabled device");
cleanupQuery:
    DevCloseObjectQuery(Query);
cleanupEvent:
    CloseHandle(Ctx.Event);
cleanup:
    return RET_ERROR(TRUE, LastError);
}

typedef struct _SW_DEVICE_CREATE_CTX
{
    HRESULT CreateResult;
    WCHAR *DeviceInstanceId;
    HANDLE Triggered;
} SW_DEVICE_CREATE_CTX;

static VOID
DeviceCreateCallback(
    _In_ HSWDEVICE SwDevice,
    _In_ HRESULT CreateResult,
    _In_ VOID *Context,
    _In_opt_ PCWSTR DeviceInstanceId)
{
    SW_DEVICE_CREATE_CTX *Ctx = Context;
    Ctx->CreateResult = CreateResult;
    if (DeviceInstanceId)
        wcsncpy_s(Ctx->DeviceInstanceId, MAX_DEVICE_ID_LEN, DeviceInstanceId, _TRUNCATE);
    SetEvent(Ctx->Triggered);
}

_Use_decl_annotations_
WINTUN_ADAPTER_HANDLE WINAPI
WintunCreateAdapter(LPCWSTR Name, LPCWSTR TunnelType, const GUID *RequestedGUID)
{
    DWORD LastError = ERROR_SUCCESS;
    WINTUN_ADAPTER *Adapter = NULL;

    HANDLE DeviceInstallationMutex = NamespaceTakeDeviceInstallationMutex();
    if (!DeviceInstallationMutex)
    {
        LastError = LOG_LAST_ERROR(L"Failed to take device installation mutex");
        goto cleanup;
    }

    HDEVINFO DevInfoExistingAdapters;
    SP_DEVINFO_DATA_LIST *ExistingAdapters;
    if (!DriverInstall(&DevInfoExistingAdapters, &ExistingAdapters))
    {
        LastError = GetLastError();
        goto cleanupDeviceInstallationMutex;
    }

    LOG(WINTUN_LOG_INFO, L"Creating adapter");

    Adapter = Zalloc(sizeof(*Adapter));
    if (!Adapter)
        goto cleanupDriverInstall;

    WCHAR TunnelTypeName[MAX_ADAPTER_NAME + 8];
    if (_snwprintf_s(TunnelTypeName, _countof(TunnelTypeName), _TRUNCATE, L"%s Tunnel", TunnelType) == -1)
    {
        LastError = ERROR_BUFFER_OVERFLOW;
        goto cleanupAdapter;
    }

    DEVINST RootNode;
    WCHAR RootNodeName[200 /* rasmans.dll uses 200 hard coded instead of calling CM_Get_Device_ID_Size. */];
    CONFIGRET ConfigRet;
    if ((ConfigRet = CM_Locate_DevNodeW(&RootNode, NULL, CM_LOCATE_DEVNODE_NORMAL)) != CR_SUCCESS ||
        (ConfigRet = CM_Get_Device_IDW(RootNode, RootNodeName, _countof(RootNodeName), 0)) != CR_SUCCESS)
    {
        LastError = LOG_ERROR(CM_MapCrToWin32Err(ConfigRet, ERROR_GEN_FAILURE), L"Failed to get root node name");
        goto cleanupAdapter;
    }

    GUID InstanceId;
    HRESULT HRet = S_OK;
    if (RequestedGUID)
        memcpy(&InstanceId, RequestedGUID, sizeof(InstanceId));
    else
        HRet = CoCreateGuid(&InstanceId);
    WCHAR InstanceIdStr[MAX_GUID_STRING_LEN];
    if (FAILED(HRet) || !StringFromGUID2(&InstanceId, InstanceIdStr, _countof(InstanceIdStr)))
    {
        LastError = LOG_ERROR(HRet, L"Failed to convert GUID");
        goto cleanupAdapter;
    }
    SW_DEVICE_CREATE_CTX CreateContext = { .DeviceInstanceId = Adapter->DevInstanceID,
                                           .Triggered = CreateEventW(NULL, FALSE, FALSE, NULL) };
    if (!CreateContext.Triggered)
    {
        LastError = LOG_LAST_ERROR(L"Failed to create event trigger");
        goto cleanupAdapter;
    }

    if (IsWindows7)
    {
        if (!CreateAdapterWin7(Adapter, Name, TunnelTypeName))
        {
            LastError = GetLastError();
            goto cleanupCreateContext;
        }
        goto skipSwDevice;
    }
    if (!IsWindows10)
        goto skipStub;

    SW_DEVICE_CREATE_INFO StubCreateInfo = { .cbSize = sizeof(StubCreateInfo),
                                             .pszInstanceId = InstanceIdStr,
                                             .pszzHardwareIds = L"",
                                             .CapabilityFlags =
                                                 SWDeviceCapabilitiesSilentInstall | SWDeviceCapabilitiesDriverRequired,
                                             .pszDeviceDescription = TunnelTypeName };
    DEVPROPERTY StubDeviceProperties[] = { { .CompKey = { .Key = DEVPKEY_Device_ClassGuid,
                                                          .Store = DEVPROP_STORE_SYSTEM },
                                             .Type = DEVPROP_TYPE_GUID,
                                             .Buffer = (PVOID)&GUID_DEVCLASS_NET,
                                             .BufferSize = sizeof(GUID_DEVCLASS_NET) } };
    HRet = SwDeviceCreate(
        WINTUN_HWID,
        RootNodeName,
        &StubCreateInfo,
        _countof(StubDeviceProperties),
        StubDeviceProperties,
        DeviceCreateCallback,
        &CreateContext,
        &Adapter->SwDevice);
    if (FAILED(HRet))
    {
        LastError = LOG_ERROR(HRet, L"Failed to initiate stub device creation");
        goto cleanupCreateContext;
    }
    if (WaitForSingleObject(CreateContext.Triggered, INFINITE) != WAIT_OBJECT_0)
    {
        LastError = LOG_LAST_ERROR(L"Failed to wait for stub device creation trigger");
        goto cleanupCreateContext;
    }
    if (FAILED(CreateContext.CreateResult))
    {
        LastError = LOG_ERROR(CreateContext.CreateResult, L"Failed to create stub device");
        goto cleanupCreateContext;
    }
    DEVINST DevInst;
    CONFIGRET CRet = CM_Locate_DevNodeW(&DevInst, Adapter->DevInstanceID, CM_LOCATE_DEVNODE_PHANTOM);
    if (CRet != CR_SUCCESS)
    {
        LastError =
            LOG_ERROR(CM_MapCrToWin32Err(CRet, ERROR_DEVICE_ENUMERATION_ERROR), L"Failed to make stub device list");
        goto cleanupCreateContext;
    }
    HKEY DriverKey;
    CRet = CM_Open_DevNode_Key(DevInst, KEY_SET_VALUE, 0, RegDisposition_OpenAlways, &DriverKey, CM_REGISTRY_SOFTWARE);
    if (CRet != CR_SUCCESS)
    {
        LastError =
            LOG_ERROR(CM_MapCrToWin32Err(CRet, ERROR_PNP_REGISTRY_ERROR), L"Failed to create software registry key");
        goto cleanupCreateContext;
    }
    LastError =
        RegSetValueExW(DriverKey, L"SuggestedInstanceId", 0, REG_BINARY, (const BYTE *)&InstanceId, sizeof(InstanceId));
    RegCloseKey(DriverKey);
    if (LastError != ERROR_SUCCESS)
    {
        LastError = LOG_ERROR(LastError, L"Failed to set SuggestedInstanceId to %s", InstanceIdStr);
        goto cleanupCreateContext;
    }
    SwDeviceClose(Adapter->SwDevice);
    Adapter->SwDevice = NULL;

skipStub:;
    static const WCHAR Hwids[_countof(WINTUN_HWID) + 1 /*Multi-string terminator*/] = WINTUN_HWID;
    SW_DEVICE_CREATE_INFO CreateInfo = { .cbSize = sizeof(CreateInfo),
                                         .pszInstanceId = InstanceIdStr,
                                         .pszzHardwareIds = Hwids,
                                         .CapabilityFlags =
                                             SWDeviceCapabilitiesSilentInstall | SWDeviceCapabilitiesDriverRequired,
                                         .pszDeviceDescription = TunnelTypeName };
    DEVPROPERTY DeviceProperties[] = {
        { .CompKey = { .Key = DEVPKEY_Wintun_Name, .Store = DEVPROP_STORE_SYSTEM },
          .Type = DEVPROP_TYPE_STRING,
          .Buffer = (WCHAR *)Name,
          .BufferSize = (ULONG)((wcslen(Name) + 1) * sizeof(*Name)) },
        { .CompKey = { .Key = DEVPKEY_Device_FriendlyName, .Store = DEVPROP_STORE_SYSTEM },
          .Type = DEVPROP_TYPE_STRING,
          .Buffer = TunnelTypeName,
          .BufferSize = (ULONG)((wcslen(TunnelTypeName) + 1) * sizeof(*TunnelTypeName)) },
        { .CompKey = { .Key = DEVPKEY_Device_DeviceDesc, .Store = DEVPROP_STORE_SYSTEM },
          .Type = DEVPROP_TYPE_STRING,
          .Buffer = TunnelTypeName,
          .BufferSize = (ULONG)((wcslen(TunnelTypeName) + 1) * sizeof(*TunnelTypeName)) }
    };

    HRet = SwDeviceCreate(
        WINTUN_HWID,
        RootNodeName,
        &CreateInfo,
        _countof(DeviceProperties),
        DeviceProperties,
        DeviceCreateCallback,
        &CreateContext,
        &Adapter->SwDevice);
    if (FAILED(HRet))
    {
        LastError = LOG_ERROR(HRet, L"Failed to initiate device creation");
        goto cleanupCreateContext;
    }
    if (WaitForSingleObject(CreateContext.Triggered, INFINITE) != WAIT_OBJECT_0)
    {
        LastError = LOG_LAST_ERROR(L"Failed to wait for device creation trigger");
        goto cleanupCreateContext;
    }
    if (FAILED(CreateContext.CreateResult))
    {
        LastError = LOG_ERROR(CreateContext.CreateResult, L"Failed to create device");
        goto cleanupCreateContext;
    }

    if (!WaitForInterface(Adapter->DevInstanceID))
    {
        LastError = GetLastError();
        DEVPROPTYPE PropertyType = 0;
        NTSTATUS NtStatus = 0;
        INT32 ProblemCode = 0;
        Adapter->DevInfo = SetupDiCreateDeviceInfoListExW(NULL, NULL, NULL, NULL);
        if (Adapter->DevInfo == INVALID_HANDLE_VALUE)
        {
            Adapter->DevInfo = NULL;
            goto cleanupCreateContext;
        }
        Adapter->DevInfoData.cbSize = sizeof(Adapter->DevInfoData);
        if (!SetupDiOpenDeviceInfoW(
                Adapter->DevInfo, Adapter->DevInstanceID, NULL, DIOD_INHERIT_CLASSDRVS, &Adapter->DevInfoData))
        {
            SetupDiDestroyDeviceInfoList(Adapter->DevInfo);
            Adapter->DevInfo = NULL;
            goto cleanupCreateContext;
        }
        if (!SetupDiGetDevicePropertyW(
                Adapter->DevInfo,
                &Adapter->DevInfoData,
                &DEVPKEY_Device_ProblemStatus,
                &PropertyType,
                (PBYTE)&NtStatus,
                sizeof(NtStatus),
                NULL,
                0) ||
            PropertyType != DEVPROP_TYPE_NTSTATUS)
            NtStatus = 0;
        if (!SetupDiGetDevicePropertyW(
                Adapter->DevInfo,
                &Adapter->DevInfoData,
                &DEVPKEY_Device_ProblemCode,
                &PropertyType,
                (PBYTE)&ProblemCode,
                sizeof(ProblemCode),
                NULL,
                0) ||
            (PropertyType != DEVPROP_TYPE_INT32 && PropertyType != DEVPROP_TYPE_UINT32))
            ProblemCode = 0;
        LastError = RtlNtStatusToDosError(NtStatus);
        if (LastError == ERROR_SUCCESS)
            LastError = ERROR_DEVICE_NOT_AVAILABLE;
        LOG_ERROR(LastError, L"Failed to setup adapter (problem code: 0x%X, ntstatus: 0x%X)", ProblemCode, NtStatus);
        goto cleanupCreateContext;
    }

skipSwDevice:
    Adapter->DevInfo = SetupDiCreateDeviceInfoListExW(&GUID_DEVCLASS_NET, NULL, NULL, NULL);
    if (Adapter->DevInfo == INVALID_HANDLE_VALUE)
    {
        Adapter->DevInfo = NULL;
        LastError = LOG_LAST_ERROR(L"Failed to make device list");
        goto cleanupCreateContext;
    }
    Adapter->DevInfoData.cbSize = sizeof(Adapter->DevInfoData);
    if (!SetupDiOpenDeviceInfoW(
            Adapter->DevInfo, Adapter->DevInstanceID, NULL, DIOD_INHERIT_CLASSDRVS, &Adapter->DevInfoData))
    {
        LastError = LOG_LAST_ERROR(L"Failed to open device instance ID %s", Adapter->DevInstanceID);
        SetupDiDestroyDeviceInfoList(Adapter->DevInfo);
        Adapter->DevInfo = NULL;
        goto cleanupCreateContext;
    }

    if (!PopulateAdapterData(Adapter))
    {
        LastError = LOG(WINTUN_LOG_ERR, L"Failed to populate adapter data");
        goto cleanupCreateContext;
    }

    if (!NciSetAdapterName(&Adapter->CfgInstanceID, Name))
    {
        LastError = LOG(WINTUN_LOG_ERR, L"Failed to set adapter name \"%s\"", Name);
        goto cleanupCreateContext;
    }

    if (IsWindows7)
        CreateAdapterPostWin7(Adapter, TunnelTypeName);

cleanupCreateContext:
    CloseHandle(CreateContext.Triggered);
cleanupAdapter:
    if (LastError != ERROR_SUCCESS)
    {
        WintunCloseAdapter(Adapter);
        Adapter = NULL;
    }
cleanupDriverInstall:
    DriverInstallDeferredCleanup(DevInfoExistingAdapters, ExistingAdapters);
cleanupDeviceInstallationMutex:
    NamespaceReleaseMutex(DeviceInstallationMutex);
cleanup:
    QueueUpOrphanedDeviceCleanupRoutine();
    return RET_ERROR(Adapter, LastError);
}

_Use_decl_annotations_
WINTUN_ADAPTER_HANDLE WINAPI
WintunOpenAdapter(LPCWSTR Name)
{
    DWORD LastError = ERROR_SUCCESS;
    WINTUN_ADAPTER *Adapter = NULL;

    HANDLE DeviceInstallationMutex = NamespaceTakeDeviceInstallationMutex();
    if (!DeviceInstallationMutex)
    {
        LastError = LOG_LAST_ERROR(L"Failed to take device installation mutex");
        goto cleanup;
    }

    Adapter = Zalloc(sizeof(*Adapter));
    if (!Adapter)
        goto cleanupDeviceInstallationMutex;

    HDEVINFO DevInfo =
        SetupDiGetClassDevsExW(&GUID_DEVCLASS_NET, WINTUN_ENUMERATOR, NULL, DIGCF_PRESENT, NULL, NULL, NULL);
    if (DevInfo == INVALID_HANDLE_VALUE)
    {
        LastError = LOG_LAST_ERROR(L"Failed to get present adapters");
        goto cleanupAdapter;
    }

    SP_DEVINFO_DATA DevInfoData = { .cbSize = sizeof(DevInfoData) };
    BOOL Found = FALSE;
    for (DWORD EnumIndex = 0; !Found; ++EnumIndex)
    {
        if (!SetupDiEnumDeviceInfo(DevInfo, EnumIndex, &DevInfoData))
        {
            if (GetLastError() == ERROR_NO_MORE_ITEMS)
                break;
            continue;
        }

        DEVPROPTYPE PropType;
        WCHAR OtherName[MAX_ADAPTER_NAME];
        Found = SetupDiGetDevicePropertyW(
                    DevInfo,
                    &DevInfoData,
                    &DEVPKEY_Wintun_Name,
                    &PropType,
                    (PBYTE)OtherName,
                    MAX_ADAPTER_NAME * sizeof(OtherName[0]),
                    NULL,
                    0) &&
                PropType == DEVPROP_TYPE_STRING && !_wcsicmp(Name, OtherName);
    }
    if (!Found)
    {
        LastError = LOG_ERROR(ERROR_NOT_FOUND, L"Failed to find matching adapter name");
        goto cleanupDevInfo;
    }
    DWORD RequiredChars = _countof(Adapter->DevInstanceID);
    if (!SetupDiGetDeviceInstanceIdW(DevInfo, &DevInfoData, Adapter->DevInstanceID, RequiredChars, &RequiredChars))
    {
        LastError = LOG_LAST_ERROR(L"Failed to get adapter instance ID");
        goto cleanupDevInfo;
    }
    Adapter->DevInfo = DevInfo;
    Adapter->DevInfoData = DevInfoData;
    BOOL Ret = WaitForInterface(Adapter->DevInstanceID) && PopulateAdapterData(Adapter);
    Adapter->DevInfo = NULL;
    if (!Ret)
    {
        LastError = LOG_LAST_ERROR(L"Failed to populate adapter");
        goto cleanupDevInfo;
    }

cleanupDevInfo:
    SetupDiDestroyDeviceInfoList(DevInfo);
cleanupAdapter:
    if (LastError != ERROR_SUCCESS)
    {
        WintunCloseAdapter(Adapter);
        Adapter = NULL;
    }
cleanupDeviceInstallationMutex:
    NamespaceReleaseMutex(DeviceInstallationMutex);
cleanup:
    QueueUpOrphanedDeviceCleanupRoutine();
    return RET_ERROR(Adapter, LastError);
}

_Use_decl_annotations_
BOOL
AdapterRemoveInstance(HDEVINFO DevInfo, SP_DEVINFO_DATA *DevInfoData)
{
#ifdef MAYBE_WOW64
    if (NativeMachine != IMAGE_FILE_PROCESS)
        return RemoveInstanceViaRundll32(DevInfo, DevInfoData);
#endif

    SP_REMOVEDEVICE_PARAMS RemoveDeviceParams = { .ClassInstallHeader = { .cbSize = sizeof(SP_CLASSINSTALL_HEADER),
                                                                          .InstallFunction = DIF_REMOVE },
                                                  .Scope = DI_REMOVEDEVICE_GLOBAL };
    return SetupDiSetClassInstallParamsW(
               DevInfo, DevInfoData, &RemoveDeviceParams.ClassInstallHeader, sizeof(RemoveDeviceParams)) &&
           SetupDiCallClassInstaller(DIF_REMOVE, DevInfo, DevInfoData);
}

_Use_decl_annotations_
BOOL
AdapterEnableInstance(HDEVINFO DevInfo, SP_DEVINFO_DATA *DevInfoData)
{
#ifdef MAYBE_WOW64
    if (NativeMachine != IMAGE_FILE_PROCESS)
        return EnableInstanceViaRundll32(DevInfo, DevInfoData);
#endif

    SP_PROPCHANGE_PARAMS Params = { .ClassInstallHeader = { .cbSize = sizeof(SP_CLASSINSTALL_HEADER),
                                                            .InstallFunction = DIF_PROPERTYCHANGE },
                                    .StateChange = DICS_ENABLE,
                                    .Scope = DICS_FLAG_GLOBAL };
    return SetupDiSetClassInstallParamsW(DevInfo, DevInfoData, &Params.ClassInstallHeader, sizeof(Params)) &&
           SetupDiCallClassInstaller(DIF_PROPERTYCHANGE, DevInfo, DevInfoData);
}

_Use_decl_annotations_
BOOL
AdapterDisableInstance(HDEVINFO DevInfo, SP_DEVINFO_DATA *DevInfoData)
{
#ifdef MAYBE_WOW64
    if (NativeMachine != IMAGE_FILE_PROCESS)
        return DisableInstanceViaRundll32(DevInfo, DevInfoData);
#endif
    SP_PROPCHANGE_PARAMS Params = { .ClassInstallHeader = { .cbSize = sizeof(SP_CLASSINSTALL_HEADER),
                                                            .InstallFunction = DIF_PROPERTYCHANGE },
                                    .StateChange = DICS_DISABLE,
                                    .Scope = DICS_FLAG_GLOBAL };
    return SetupDiSetClassInstallParamsW(DevInfo, DevInfoData, &Params.ClassInstallHeader, sizeof(Params)) &&
           SetupDiCallClassInstaller(DIF_PROPERTYCHANGE, DevInfo, DevInfoData);
}

/* SPDX-License-Identifier: GPL-2.0
 *
 * Copyright (C) 2018-2020 WireGuard LLC. All Rights Reserved.
 */

#pragma once

#include <Windows.h>
#include <IPExport.h>

typedef _Return_type_success_(return == ERROR_SUCCESS) DWORD WINSTATUS;
extern HINSTANCE ResourceModule;

_Check_return_
HANDLE
TakeNameMutex(_In_z_ LPCWSTR Pool);

void
ReleaseNameMutex(_In_ HANDLE Mutex);

void
NamespaceInit();

void
NamespaceCleanup();

extern WINSTATUS(WINAPI *NciSetConnectionName)(_In_ LPCGUID Guid, _In_z_ LPCWSTR NewName);

extern WINSTATUS(WINAPI *NciGetConnectionName)(
    _In_ LPCGUID Guid,
    _Out_z_bytecap_(InDestNameBytes) LPWSTR Name,
    _In_ DWORD InDestNameBytes,
    _Out_opt_ DWORD *OutDestNameBytes);

void
NciInit();

void
NciCleanup();

WINSTATUS
RegistryOpenKeyWait(
    _In_ HKEY Key,
    _In_z_count_c_(MAX_PATH) LPCWSTR Path,
    _In_ DWORD Access,
    _In_ DWORD Timeout,
    _Out_ HKEY *KeyOut);

WINSTATUS
RegistryWaitForKey(_In_ HKEY Key, _In_z_count_c_(MAX_PATH) LPCWSTR Path, _In_ DWORD Timeout);

WINSTATUS
RegistryGetString(_Inout_ LPWSTR *Buf, _In_ DWORD Len, _In_ DWORD ValueType);

WINSTATUS
RegistryGetMultiString(_Inout_ LPWSTR *Buf, _In_ DWORD Len, _In_ DWORD ValueType);

WINSTATUS
RegistryQueryString(_In_ HKEY Key, _In_opt_z_ LPCWSTR Name, _Out_ LPWSTR *Value);

WINSTATUS
RegistryQueryStringWait(_In_ HKEY Key, _In_opt_z_ LPCWSTR Name, _In_ DWORD Timeout, _Out_ LPWSTR *Value);

WINSTATUS
RegistryQueryDWORD(_In_ HKEY Key, _In_opt_z_ LPCWSTR Name, _Out_ DWORD *Value);

WINSTATUS
RegistryQueryDWORDWait(_In_ HKEY Key, _In_opt_z_ LPCWSTR Name, _In_ DWORD Timeout, _Out_ DWORD *Value);

WINSTATUS WINAPI
WintunGetVersion(
    _Out_ DWORD *DriverVersionMaj,
    _Out_ DWORD *DriverVersionMin,
    _Out_ DWORD *NdisVersionMaj,
    _Out_ DWORD *NdisVersionMin);

#define MAX_POOL 256
#define MAX_INSTANCE_ID MAX_PATH /* TODO: Is MAX_PATH always enough? */

typedef struct _WINTUN_ADAPTER
{
    GUID CfgInstanceID;
    WCHAR DevInstanceID[MAX_INSTANCE_ID];
    DWORD LuidIndex;
    DWORD IfType;
    WCHAR Pool[MAX_POOL];
} WINTUN_ADAPTER;

VOID WINAPI
WintunFreeAdapter(_In_ WINTUN_ADAPTER *Adapter);

WINSTATUS WINAPI
WintunGetAdapter(_In_z_count_c_(MAX_POOL) LPCWSTR Pool, _In_z_ LPCWSTR Name, _Out_ WINTUN_ADAPTER **Adapter);

WINSTATUS WINAPI
WintunGetAdapterName(_In_ const WINTUN_ADAPTER *Adapter, _Out_cap_c_(MAX_ADAPTER_NAME) LPWSTR Name);

WINSTATUS WINAPI
WintunSetAdapterName(_In_ const WINTUN_ADAPTER *Adapter, _In_z_count_c_(MAX_ADAPTER_NAME) LPCWSTR Name);

void WINAPI
WintunGetAdapterGUID(_In_ const WINTUN_ADAPTER *Adapter, _Out_ GUID *Guid);

void WINAPI
WintunGetAdapterLUID(_In_ const WINTUN_ADAPTER *Adapter, _Out_ LUID *Luid);

WINSTATUS WINAPI
WintunGetAdapterDeviceObject(_In_ const WINTUN_ADAPTER *Adapter, _Out_ HANDLE *Handle);

WINSTATUS WINAPI
WintunCreateAdapter(
    _In_z_count_c_(MAX_POOL) LPCWSTR Pool,
    _In_z_ LPCWSTR Name,
    _In_opt_ const GUID *RequestedGUID,
    _Out_ WINTUN_ADAPTER **Adapter,
    _Inout_ BOOL *RebootRequired);

WINSTATUS WINAPI
WintunDeleteAdapter(_In_ const WINTUN_ADAPTER *Adapter, _Inout_ BOOL *RebootRequired);

typedef BOOL(CALLBACK *WINTUN_ENUMPROC)(_In_ const WINTUN_ADAPTER *Adapter, _In_ LPARAM Param);

WINSTATUS WINAPI
WintunEnumAdapters(_In_z_count_c_(MAX_POOL) LPCWSTR Pool, _In_ WINTUN_ENUMPROC Func, _In_ LPARAM Param);

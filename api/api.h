/* SPDX-License-Identifier: GPL-2.0
 *
 * Copyright (C) 2018-2020 WireGuard LLC. All Rights Reserved.
 */

#pragma once

#include <Windows.h>
#include <IPExport.h>

typedef _Return_type_success_(return == ERROR_SUCCESS) DWORD WINTUN_STATUS;
extern HINSTANCE ResourceModule;

_Check_return_
HANDLE
TakeNameMutex(_In_z_ const WCHAR *Pool);

void
ReleaseNameMutex(_In_ HANDLE Mutex);

void
NamespaceInit();

void
NamespaceCleanup();

extern DWORD(WINAPI *NciSetConnectionName)(_In_ const GUID *Guid, _In_z_ const WCHAR *NewName);

extern DWORD(WINAPI *NciGetConnectionName)(
    _In_ const GUID *Guid,
    _Out_z_bytecap_(InDestNameBytes) WCHAR *Name,
    _In_ DWORD InDestNameBytes,
    _Out_opt_ DWORD *OutDestNameBytes);

void
NciInit();

void
NciCleanup();

#define MAX_REG_PATH \
    256 /* Maximum registry path length \
           https://support.microsoft.com/en-us/help/256986/windows-registry-information-for-advanced-users */

WINTUN_STATUS
RegistryOpenKeyWait(
    _In_ HKEY Key,
    _In_z_count_c_(MAX_REG_PATH) const WCHAR *Path,
    _In_ DWORD Access,
    _In_ DWORD Timeout,
    _Out_ HKEY *KeyOut);

WINTUN_STATUS
RegistryWaitForKey(_In_ HKEY Key, _In_z_count_c_(MAX_REG_PATH) const WCHAR *Path, _In_ DWORD Timeout);

WINTUN_STATUS
RegistryGetString(_Inout_ WCHAR **Buf, _In_ DWORD Len, _In_ DWORD ValueType);

WINTUN_STATUS
RegistryGetMultiString(_Inout_ WCHAR **Buf, _In_ DWORD Len, _In_ DWORD ValueType);

WINTUN_STATUS
RegistryQueryString(_In_ HKEY Key, _In_opt_z_ const WCHAR *Name, _Out_ WCHAR **Value);

WINTUN_STATUS
RegistryQueryStringWait(_In_ HKEY Key, _In_opt_z_ const WCHAR *Name, _In_ DWORD Timeout, _Out_ WCHAR **Value);

WINTUN_STATUS
RegistryQueryDWORD(_In_ HKEY Key, _In_opt_z_ const WCHAR *Name, _Out_ DWORD *Value);

WINTUN_STATUS
RegistryQueryDWORDWait(_In_ HKEY Key, _In_opt_z_ const WCHAR *Name, _In_ DWORD Timeout, _Out_ DWORD *Value);

WINTUN_STATUS WINAPI
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

void WINAPI
WintunFreeAdapter(_In_ WINTUN_ADAPTER *Adapter);

WINTUN_STATUS WINAPI
WintunGetAdapter(_In_z_count_c_(MAX_POOL) const WCHAR *Pool, _In_z_count_c_(MAX_ADAPTER_NAME) const WCHAR *Name, _Out_ WINTUN_ADAPTER **Adapter);

WINTUN_STATUS WINAPI
WintunGetAdapterName(_In_ const WINTUN_ADAPTER *Adapter, _Out_cap_c_(MAX_ADAPTER_NAME) WCHAR *Name);

WINTUN_STATUS WINAPI
WintunSetAdapterName(_In_ const WINTUN_ADAPTER *Adapter, _In_z_count_c_(MAX_ADAPTER_NAME) const WCHAR *Name);

void WINAPI
WintunGetAdapterGUID(_In_ const WINTUN_ADAPTER *Adapter, _Out_ GUID *Guid);

void WINAPI
WintunGetAdapterLUID(_In_ const WINTUN_ADAPTER *Adapter, _Out_ LUID *Luid);

WINTUN_STATUS WINAPI
WintunGetAdapterDeviceObject(_In_ const WINTUN_ADAPTER *Adapter, _Out_ HANDLE *Handle);

WINTUN_STATUS WINAPI
WintunCreateAdapter(
    _In_z_count_c_(MAX_POOL) const WCHAR *Pool,
    _In_z_count_c_(MAX_ADAPTER_NAME) const WCHAR *Name,
    _In_opt_ const GUID *RequestedGUID,
    _Out_ WINTUN_ADAPTER **Adapter,
    _Inout_ BOOL *RebootRequired);

WINTUN_STATUS WINAPI
WintunDeleteAdapter(_In_ const WINTUN_ADAPTER *Adapter, _Inout_ BOOL *RebootRequired);

typedef BOOL(CALLBACK *WINTUN_ENUMPROC)(_In_ const WINTUN_ADAPTER *Adapter, _In_ LPARAM Param);

WINTUN_STATUS WINAPI
WintunEnumAdapters(_In_z_count_c_(MAX_POOL) const WCHAR *Pool, _In_ WINTUN_ENUMPROC Func, _In_ LPARAM Param);

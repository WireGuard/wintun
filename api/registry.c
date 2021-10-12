/* SPDX-License-Identifier: GPL-2.0
 *
 * Copyright (C) 2018-2021 WireGuard LLC. All Rights Reserved.
 */

#include "logger.h"
#include "registry.h"
#include <Windows.h>
#include <wchar.h>
#include <stdlib.h>
#include <strsafe.h>

_Use_decl_annotations_
BOOL
RegistryGetString(LPWSTR *Buf, DWORD Len, DWORD ValueType)
{
    if (wcsnlen(*Buf, Len) >= Len)
    {
        /* String is missing zero-terminator. */
        LPWSTR BufZ = ReZallocArray(*Buf, (SIZE_T)Len + 1, sizeof(*BufZ));
        if (!BufZ)
            return FALSE;
        _Analysis_assume_((wmemset(BufZ, L'A', (SIZE_T)Len + 1), TRUE));
        *Buf = BufZ;
    }

    if (ValueType != REG_EXPAND_SZ)
        return TRUE;

    /* ExpandEnvironmentStringsW() returns strlen on success or 0 on error. Bail out on empty input strings to
     * disambiguate. */
    if (!(*Buf)[0])
        return TRUE;

    for (;;)
    {
        LPWSTR Expanded = AllocArray(Len, sizeof(*Expanded));
        if (!Expanded)
            return FALSE;
        DWORD Result = ExpandEnvironmentStringsW(*Buf, Expanded, Len);
        if (!Result)
        {
            LOG_LAST_ERROR(L"Failed to expand environment variables: %s", *Buf);
            Free(Expanded);
            return FALSE;
        }
        if (Result > Len)
        {
            Free(Expanded);
            Len = Result;
            continue;
        }
        Free(*Buf);
        *Buf = Expanded;
        return TRUE;
    }
}

_Must_inspect_result_
static _Return_type_success_(return != NULL)
_Post_maybenull_
_Post_writable_byte_size_(*BufLen)
VOID *
RegistryQuery(_In_ HKEY Key, _In_opt_z_ LPCWSTR Name, _Out_opt_ DWORD *ValueType, _Inout_ DWORD *BufLen, _In_ BOOL Log)
{
    for (;;)
    {
        BYTE *p = Alloc(*BufLen);
        if (!p)
            return NULL;
        LSTATUS LastError = RegQueryValueExW(Key, Name, NULL, ValueType, p, BufLen);
        if (LastError == ERROR_SUCCESS)
            return p;
        Free(p);
        if (LastError != ERROR_MORE_DATA)
        {
            if (Log)
            {
                WCHAR RegPath[MAX_REG_PATH];
                LoggerGetRegistryKeyPath(Key, RegPath);
                LOG_ERROR(LastError, L"Failed to query registry value %.*s\\%s", MAX_REG_PATH, RegPath, Name);
            }
            SetLastError(LastError);
            return NULL;
        }
    }
}

_Use_decl_annotations_
LPWSTR
RegistryQueryString(HKEY Key, LPCWSTR Name, BOOL Log)
{
    DWORD LastError, ValueType, Size = 256 * sizeof(WCHAR);
    LPWSTR Value = RegistryQuery(Key, Name, &ValueType, &Size, Log);
    if (!Value)
        return NULL;
    switch (ValueType)
    {
    case REG_SZ:
    case REG_EXPAND_SZ:
    case REG_MULTI_SZ:
        if (RegistryGetString(&Value, Size / sizeof(*Value), ValueType))
            return Value;
        LastError = GetLastError();
        break;
    default: {
        WCHAR RegPath[MAX_REG_PATH];
        LoggerGetRegistryKeyPath(Key, RegPath);
        LOG(WINTUN_LOG_ERR,
            L"Registry value %.*s\\%s is not a string (type: %u)",
            MAX_REG_PATH,
            RegPath,
            Name,
            ValueType);
        LastError = ERROR_INVALID_DATATYPE;
    }
    }
    Free(Value);
    SetLastError(LastError);
    return NULL;
}

_Use_decl_annotations_
BOOL
RegistryQueryDWORD(HKEY Key, LPCWSTR Name, DWORD *Value, BOOL Log)
{
    DWORD ValueType, Size = sizeof(DWORD);
    DWORD LastError = RegQueryValueExW(Key, Name, NULL, &ValueType, (BYTE *)Value, &Size);
    if (LastError != ERROR_SUCCESS)
    {
        if (Log)
        {
            WCHAR RegPath[MAX_REG_PATH];
            LoggerGetRegistryKeyPath(Key, RegPath);
            LOG_ERROR(LastError, L"Failed to query registry value %.*s\\%s", MAX_REG_PATH, RegPath, Name);
        }
        SetLastError(LastError);
        return FALSE;
    }
    if (ValueType != REG_DWORD)
    {
        WCHAR RegPath[MAX_REG_PATH];
        LoggerGetRegistryKeyPath(Key, RegPath);
        LOG(WINTUN_LOG_ERR, L"Value %.*s\\%s is not a DWORD (type: %u)", MAX_REG_PATH, RegPath, Name, ValueType);
        SetLastError(ERROR_INVALID_DATATYPE);
        return FALSE;
    }
    if (Size != sizeof(DWORD))
    {
        WCHAR RegPath[MAX_REG_PATH];
        LoggerGetRegistryKeyPath(Key, RegPath);
        LOG(WINTUN_LOG_ERR, L"Value %.*s\\%s size is not 4 bytes (size: %u)", MAX_REG_PATH, RegPath, Name, Size);
        SetLastError(ERROR_INVALID_DATA);
        return FALSE;
    }
    return TRUE;
}

/* SPDX-License-Identifier: GPL-2.0
 *
 * Copyright (C) 2018-2020 WireGuard LLC. All Rights Reserved.
 */

#include "pch.h"

static WINTUN_STATUS
OpenKeyWait(_In_ HKEY Key, _Inout_z_ WCHAR *Path, _In_ DWORD Access, _In_ ULONGLONG Deadline, _Out_ HKEY *KeyOut)
{
    DWORD Result;
    WCHAR *PathNext = wcschr(Path, L'\\');
    if (PathNext)
        *PathNext = 0;

    HANDLE Event = CreateEventW(NULL, FALSE, FALSE, NULL);
    if (!Event)
        return LOG_LAST_ERROR(L"Failed to create event");
    for (;;)
    {
        Result = RegNotifyChangeKeyValue(Key, FALSE, REG_NOTIFY_CHANGE_NAME, Event, TRUE);
        if (Result != ERROR_SUCCESS)
        {
            LOG_ERROR(L"Failed to setup notification", Result);
            break;
        }

        HKEY Subkey;
        Result = RegOpenKeyExW(Key, Path, 0, PathNext ? KEY_NOTIFY : Access, &Subkey);
        if (Result == ERROR_SUCCESS)
        {
            if (PathNext)
            {
                Result = OpenKeyWait(Subkey, PathNext + 1, Access, Deadline, KeyOut);
                RegCloseKey(Subkey);
            }
            else
                *KeyOut = Subkey;
            break;
        }
        if (Result != ERROR_FILE_NOT_FOUND && Result != ERROR_PATH_NOT_FOUND)
        {
            LOG_ERROR(L"Failed to open", Result);
            break;
        }

        LONGLONG TimeLeft = Deadline - GetTickCount64();
        if (TimeLeft < 0)
            TimeLeft = 0;
        if (WaitForSingleObject(Event, (DWORD)TimeLeft) != WAIT_OBJECT_0)
        {
            LOG(WINTUN_LOG_ERR, L"Timeout waiting");
            break;
        }
    }
    CloseHandle(Event);
    return Result;
}

WINTUN_STATUS
RegistryOpenKeyWait(
    _In_ HKEY Key,
    _In_z_count_c_(MAX_REG_PATH) const WCHAR *Path,
    _In_ DWORD Access,
    _In_ DWORD Timeout,
    _Out_ HKEY *KeyOut)
{
    WCHAR Buf[MAX_REG_PATH];
    wcscpy_s(Buf, _countof(Buf), Path);
    return OpenKeyWait(Key, Buf, Access, GetTickCount64() + Timeout, KeyOut);
}

WINTUN_STATUS
RegistryGetString(_Inout_ WCHAR **Buf, _In_ DWORD Len, _In_ DWORD ValueType)
{
    HANDLE Heap = GetProcessHeap();

    if (wcsnlen(*Buf, Len) >= Len)
    {
        /* String is missing zero-terminator. */
        WCHAR *BufZ = HeapAlloc(Heap, 0, ((size_t)Len + 1) * sizeof(WCHAR));
        if (!BufZ)
            return LOG(WINTUN_LOG_ERR, L"Out of memory"), ERROR_OUTOFMEMORY;
        wmemcpy(BufZ, *Buf, Len);
        BufZ[Len] = 0;
        HeapFree(Heap, 0, *Buf);
        *Buf = BufZ;
    }

    if (ValueType != REG_EXPAND_SZ)
        return ERROR_SUCCESS;

    /* ExpandEnvironmentStringsW() returns strlen on success or 0 on error. Bail out on empty input strings to
     * disambiguate. */
    if (!(*Buf)[0])
        return ERROR_SUCCESS;

    Len = Len * 2 + 64;
    for (;;)
    {
        WCHAR *Expanded = HeapAlloc(Heap, 0, Len * sizeof(WCHAR));
        if (!Expanded)
            return LOG(WINTUN_LOG_ERR, L"Out of memory"), ERROR_OUTOFMEMORY;
        DWORD Result = ExpandEnvironmentStringsW(*Buf, Expanded, Len);
        if (!Result)
        {
            Result = LOG_LAST_ERROR(L"Failed to expand environment variables");
            HeapFree(Heap, 0, Expanded);
            return Result;
        }
        if (Result > Len)
        {
            HeapFree(Heap, 0, Expanded);
            Len = Result;
            continue;
        }
        HeapFree(Heap, 0, *Buf);
        *Buf = Expanded;
        return ERROR_SUCCESS;
    }
}

WINTUN_STATUS
RegistryGetMultiString(_Inout_ WCHAR **Buf, _In_ DWORD Len, _In_ DWORD ValueType)
{
    HANDLE Heap = GetProcessHeap();

    if (ValueType == REG_MULTI_SZ)
    {
        for (size_t i = 0;; i += wcsnlen(*Buf + i, Len - i) + 1)
        {
            if (i > Len)
            {
                /* Missing string and list terminators. */
                WCHAR *BufZ = HeapAlloc(Heap, 0, ((size_t)Len + 2) * sizeof(WCHAR));
                if (!BufZ)
                    return LOG(WINTUN_LOG_ERR, L"Out of memory"), ERROR_OUTOFMEMORY;
                wmemcpy(BufZ, *Buf, Len);
                BufZ[Len] = 0;
                BufZ[Len + 1] = 0;
                HeapFree(Heap, 0, *Buf);
                *Buf = BufZ;
                return ERROR_SUCCESS;
            }
            if (i == Len)
            {
                /* Missing list terminator. */
                WCHAR *BufZ = HeapAlloc(Heap, 0, ((size_t)Len + 1) * sizeof(WCHAR));
                if (!BufZ)
                    return LOG(WINTUN_LOG_ERR, L"Out of memory"), ERROR_OUTOFMEMORY;
                wmemcpy(BufZ, *Buf, Len);
                BufZ[Len] = 0;
                HeapFree(Heap, 0, *Buf);
                *Buf = BufZ;
                return ERROR_SUCCESS;
            }
            if (!(*Buf)[i])
                return ERROR_SUCCESS;
        }
    }

    /* Sanitize REG_SZ/REG_EXPAND_SZ and append a list terminator to make a multi-string. */
    DWORD Result = RegistryGetString(Buf, Len, ValueType);
    if (Result != ERROR_SUCCESS)
        return Result;
    Len = (DWORD)wcslen(*Buf) + 1;
    WCHAR *BufZ = HeapAlloc(Heap, 0, ((size_t)Len + 1) * sizeof(WCHAR));
    if (!BufZ)
        return LOG(WINTUN_LOG_ERR, L"Out of memory"), ERROR_OUTOFMEMORY;
    wmemcpy(BufZ, *Buf, Len);
    BufZ[Len] = 0;
    HeapFree(Heap, 0, *Buf);
    *Buf = BufZ;
    return ERROR_SUCCESS;
}

static WINTUN_STATUS
RegistryQuery(
    _In_ HKEY Key,
    _In_opt_z_ const WCHAR *Name,
    _Out_opt_ DWORD *ValueType,
    _Out_ void **Buf,
    _Inout_ DWORD *BufLen)
{
    HANDLE Heap = GetProcessHeap();
    for (;;)
    {
        *Buf = HeapAlloc(Heap, 0, *BufLen);
        if (!*Buf)
            return LOG(WINTUN_LOG_ERR, L"Out of memory"), ERROR_OUTOFMEMORY;
        LSTATUS Result = RegQueryValueExW(Key, Name, NULL, ValueType, (BYTE *)*Buf, BufLen);
        if (Result == ERROR_SUCCESS)
            return ERROR_SUCCESS;
        HeapFree(Heap, 0, *Buf);
        if (Result != ERROR_MORE_DATA)
            return LOG_ERROR(L"Querying value failed", Result);
    }
}

WINTUN_STATUS
RegistryQueryString(_In_ HKEY Key, _In_opt_z_ const WCHAR *Name, _Out_ WCHAR **Value)
{
    DWORD ValueType, Size = 256 * sizeof(WCHAR);
    DWORD Result = RegistryQuery(Key, Name, &ValueType, Value, &Size);
    if (Result != ERROR_SUCCESS)
        return Result;
    switch (ValueType)
    {
    case REG_SZ:
    case REG_EXPAND_SZ:
    case REG_MULTI_SZ:
        Result = RegistryGetString(Value, Size / sizeof(WCHAR), ValueType);
        if (Result != ERROR_SUCCESS)
            HeapFree(GetProcessHeap(), 0, *Value);
        return Result;
    default:
        LOG(WINTUN_LOG_ERR, L"Value is not a string");
        HeapFree(GetProcessHeap(), 0, *Value);
        return ERROR_INVALID_DATATYPE;
    }
}

WINTUN_STATUS
RegistryQueryStringWait(_In_ HKEY Key, _In_opt_z_ const WCHAR *Name, _In_ DWORD Timeout, _Out_ WCHAR **Value)
{
    DWORD Result;
    ULONGLONG Deadline = GetTickCount64() + Timeout;
    HANDLE Event = CreateEventW(NULL, FALSE, FALSE, NULL);
    if (!Event)
        return LOG_LAST_ERROR(L"Failed to create event");
    for (;;)
    {
        Result = RegNotifyChangeKeyValue(Key, FALSE, REG_NOTIFY_CHANGE_LAST_SET, Event, TRUE);
        if (Result != ERROR_SUCCESS)
        {
            LOG_ERROR(L"Failed to setup notification", Result);
            break;
        }
        Result = RegistryQueryString(Key, Name, Value);
        if (Result != ERROR_FILE_NOT_FOUND && Result != ERROR_PATH_NOT_FOUND)
            break;
        LONGLONG TimeLeft = Deadline - GetTickCount64();
        if (TimeLeft < 0)
            TimeLeft = 0;
        if (WaitForSingleObject(Event, (DWORD)TimeLeft) != WAIT_OBJECT_0)
        {
            LOG(WINTUN_LOG_ERR, L"Timeout waiting");
            break;
        }
    }
    CloseHandle(Event);
    return Result;
}

WINTUN_STATUS
RegistryQueryDWORD(_In_ HKEY Key, _In_opt_z_ const WCHAR *Name, _Out_ DWORD *Value)
{
    DWORD ValueType, Size = sizeof(DWORD);
    DWORD Result = RegQueryValueExW(Key, Name, NULL, &ValueType, (BYTE *)Value, &Size);
    if (Result != ERROR_SUCCESS)
        return LOG_ERROR(L"Querying failed", Result);
    if (ValueType != REG_DWORD)
    {
        LOG(WINTUN_LOG_ERR, L"Value is not a DWORD");
        return ERROR_INVALID_DATATYPE;
    }
    if (Size != sizeof(DWORD))
    {
        LOG(WINTUN_LOG_ERR, L"Value size is not 4 bytes");
        return ERROR_INVALID_DATA;
    }
    return ERROR_SUCCESS;
}

WINTUN_STATUS
RegistryQueryDWORDWait(_In_ HKEY Key, _In_opt_z_ const WCHAR *Name, _In_ DWORD Timeout, _Out_ DWORD *Value)
{
    DWORD Result;
    ULONGLONG Deadline = GetTickCount64() + Timeout;
    HANDLE Event = CreateEventW(NULL, FALSE, FALSE, NULL);
    if (!Event)
        return LOG_LAST_ERROR(L"Failed to create event");
    for (;;)
    {
        Result = RegNotifyChangeKeyValue(Key, FALSE, REG_NOTIFY_CHANGE_LAST_SET, Event, TRUE);
        if (Result != ERROR_SUCCESS)
        {
            LOG_ERROR(L"Failed to setup notification", Result);
            break;
        }
        Result = RegistryQueryDWORD(Key, Name, Value);
        if (Result != ERROR_FILE_NOT_FOUND && Result != ERROR_PATH_NOT_FOUND)
            break;
        LONGLONG TimeLeft = Deadline - GetTickCount64();
        if (TimeLeft < 0)
            TimeLeft = 0;
        if (WaitForSingleObject(Event, (DWORD)TimeLeft) != WAIT_OBJECT_0)
        {
            LOG(WINTUN_LOG_ERR, L"Timeout waiting");
            break;
        }
    }
    CloseHandle(Event);
    return Result;
}

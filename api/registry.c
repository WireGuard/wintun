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
        return GetLastError();
    for (;;)
    {
        Result = RegNotifyChangeKeyValue(Key, FALSE, REG_NOTIFY_CHANGE_NAME, Event, TRUE);
        if (Result != ERROR_SUCCESS)
            break;

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
            break;

        LONGLONG TimeLeft = Deadline - GetTickCount64();
        if (TimeLeft < 0)
            TimeLeft = 0;
        if (WaitForSingleObject(Event, (DWORD)TimeLeft) != WAIT_OBJECT_0)
            break;
    }
    CloseHandle(Event);
    return Result;
}

/**
 * Opens the specified registry key. It waits for the registry key to become available.
 *
 * @param Key           Handle of the parent registry key. Must be opened with notify access.
 *
 * @param Path          Subpath of the registry key to open
 *
 * @param Access        A mask that specifies the desired access rights to the key to be opened
 *
 * @param Timeout       Timeout to wait for the value in milliseconds
 *
 * @param KeyOut        Pointer to a variable to receive the key handle
 *
 * @return ERROR_SUCCESS on success; WAIT_TIMEOUT on timeout; error code otherwise
 */
WINTUN_STATUS
RegistryOpenKeyWait(
    _In_ HKEY Key,
    _In_z_count_c_(MAX_PATH) const WCHAR *Path,
    _In_ DWORD Access,
    _In_ DWORD Timeout,
    _Out_ HKEY *KeyOut)
{
    WCHAR Buf[MAX_PATH];
    wcscpy_s(Buf, _countof(Buf), Path);
    return OpenKeyWait(Key, Buf, Access, GetTickCount64() + Timeout, KeyOut);
}

WINTUN_STATUS
RegistryWaitForKey(_In_ HKEY Key, _In_z_count_c_(MAX_PATH) const WCHAR *Path, _In_ DWORD Timeout)
{
    HKEY k;
    DWORD Result = RegistryOpenKeyWait(Key, Path, KEY_NOTIFY, Timeout, &k);
    if (Result != ERROR_SUCCESS)
        return Result;
    RegCloseKey(k);
    return ERROR_SUCCESS;
}

/**
 * Validate and/or sanitize string value read from registry.
 *
 * @param Buf           On input, it contains pointer to pointer where the data is stored. The data must be
 *                      allocated using HeapAlloc(GetProcessHeap(), 0).
 *                      On output, it contains pointer to pointer where the sanitized data is stored. It must be
 *                      released with HeapFree(GetProcessHeap(), 0, *Buf) after use.
 *
 * @param Len           Length of data string in wide characters
 *
 * @param ValueType     Type of data. Must be either REG_SZ or REG_EXPAND_SZ. REG_MULTI_SZ is treated like REG_SZ; only
 *                      the first string of a multi-string is to be used.
 *
 * @return ERROR_SUCCESS on success; Win32 error code otherwise
 */
WINTUN_STATUS
RegistryGetString(_Inout_ WCHAR **Buf, _In_ DWORD Len, _In_ DWORD ValueType)
{
    HANDLE Heap = GetProcessHeap();

    if (wcsnlen(*Buf, Len) >= Len)
    {
        /* String is missing zero-terminator. */
        WCHAR *BufZ = HeapAlloc(Heap, 0, ((size_t)Len + 1) * sizeof(WCHAR));
        if (!BufZ)
            return ERROR_OUTOFMEMORY;
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
            return ERROR_OUTOFMEMORY;
        DWORD Result = ExpandEnvironmentStringsW(*Buf, Expanded, Len);
        if (!Result)
        {
            Result = GetLastError();
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

/**
 * Validate and/or sanitize multi-string value read from registry.
 *
 * @param Buf           On input, it contains pointer to pointer where the data is stored. The data must be
 *                      allocated using HeapAlloc(GetProcessHeap(), 0).
 *                      On output, it contains pointer to pointer where the sanitized data is stored. It must be
 *                      released with HeapFree(GetProcessHeap(), 0, *Buf) after use.
 *
 * @param Len           Length of data string in wide characters
 *
 * @param ValueType     Type of data. Must be one of REG_MULTI_SZ, REG_SZ or REG_EXPAND_SZ.
 *
 * @return ERROR_SUCCESS on success; Win32 error code otherwise
 */
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
                    return ERROR_OUTOFMEMORY;
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
                    return ERROR_OUTOFMEMORY;
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
        return ERROR_OUTOFMEMORY;
    wmemcpy(BufZ, *Buf, Len);
    BufZ[Len] = 0;
    HeapFree(Heap, 0, *Buf);
    *Buf = BufZ;
    return ERROR_SUCCESS;
}

/**
 * Retrieves the type and data for the specified value name associated with an open registry key.
 *
 * @param Key           Handle of the registry key to read from. Must be opened with read
 *                      access.
 *
 * @param Name          Name of the value to read
 *
 * @param ValueType     A pointer to a variable that receives a code indicating the type of data stored in the specified
 *                      value.
 *
 * @param Buf           Pointer to a pointer to retrieve registry value. The buffer must be released with
 *                      HeapFree(GetProcessHeap(), 0, *Buf) after use.
 *
 * @param BufLen        On input, a hint of expected registry value size in bytes; on output, actual registry value size
 *                      in bytes.
 *
 * @return ERROR_SUCCESS on success; Win32 error code otherwise
 */
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
            return ERROR_OUTOFMEMORY;
        LSTATUS Result = RegQueryValueExW(Key, Name, NULL, ValueType, (BYTE *)*Buf, BufLen);
        if (Result == ERROR_SUCCESS)
            return ERROR_SUCCESS;
        HeapFree(Heap, 0, *Buf);
        if (Result != ERROR_MORE_DATA)
            return Result;
    }
}

/**
 * Reads string value from registry key.
 *
 * @param Key           Handle of the registry key to read from. Must be opened with read
 *                      access.
 *
 * @param Name          Name of the value to read
 *
 * @param Value         Pointer to string to retrieve registry value. If the value type is
 *                      REG_EXPAND_SZ the value is expanded using ExpandEnvironmentStrings(). If the value type is
 *                      REG_MULTI_SZ, only the first string from the multi-string is returned.
 *                      The string must be released with HeapFree(GetProcessHeap(), 0, Value) after use.
 *
 * @return ERROR_SUCCESS on success; Win32 error code otherwise
 */
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
        HeapFree(GetProcessHeap(), 0, *Value);
        return ERROR_INVALID_DATATYPE;
    }
}

/**
 * Reads string value from registry key. It waits for the registry value to become available.
 *
 * @param Key           Handle of the registry key to read from. Must be opened with read and notify
 *                      access.
 *
 * @param Name          Name of the value to read
 *
 * @param Timeout       Timeout to wait for the value in milliseconds
 *
 * @param Value         Pointer to string to retrieve registry value. If the value type is
 *                      REG_EXPAND_SZ the value is expanded using ExpandEnvironmentStrings().
 *                      The string must be released with HeapFree(GetProcessHeap(), 0, Value)
 *                      after use.
 *
 * @return ERROR_SUCCESS on success; Win32 error code otherwise
 */
WINTUN_STATUS
RegistryQueryStringWait(_In_ HKEY Key, _In_opt_z_ const WCHAR *Name, _In_ DWORD Timeout, _Out_ WCHAR **Value)
{
    DWORD Result;
    ULONGLONG Deadline = GetTickCount64() + Timeout;
    HANDLE Event = CreateEventW(NULL, FALSE, FALSE, NULL);
    if (!Event)
        return GetLastError();
    for (;;)
    {
        Result = RegNotifyChangeKeyValue(Key, FALSE, REG_NOTIFY_CHANGE_LAST_SET, Event, TRUE);
        if (Result != ERROR_SUCCESS)
            break;
        Result = RegistryQueryString(Key, Name, Value);
        if (Result != ERROR_FILE_NOT_FOUND && Result != ERROR_PATH_NOT_FOUND)
            break;
        LONGLONG TimeLeft = Deadline - GetTickCount64();
        if (TimeLeft < 0)
            TimeLeft = 0;
        if (WaitForSingleObject(Event, (DWORD)TimeLeft) != WAIT_OBJECT_0)
            break;
    }
    CloseHandle(Event);
    return Result;
}

/**
 * Reads a 32-bit DWORD value from registry key.
 *
 * @param Key           Handle of the registry key to read from. Must be opened with read
 *                      access.
 *
 * @param Name          Name of the value to read
 *
 * @param Value         Pointer to DWORD to retrieve registry value
 *
 * @return ERROR_SUCCESS on success; Win32 error code otherwise
 */
WINTUN_STATUS
RegistryQueryDWORD(_In_ HKEY Key, _In_opt_z_ const WCHAR *Name, _Out_ DWORD *Value)
{
    DWORD ValueType, Size = sizeof(DWORD);
    DWORD Result = RegQueryValueExW(Key, Name, NULL, &ValueType, (BYTE *)Value, &Size);
    if (Result != ERROR_SUCCESS)
        return Result;
    if (ValueType != REG_DWORD)
        return ERROR_INVALID_DATATYPE;
    if (Size != sizeof(DWORD))
        return ERROR_INVALID_DATA;
    return ERROR_SUCCESS;
}

/**
 * Reads a 32-bit DWORD value from registry key. It waits for the registry value to become available.
 *
 * @param Key           Handle of the registry key to read from. Must be opened with read
 *                      access.
 *
 * @param Name          Name of the value to read
 *
 * @param Timeout       Timeout to wait for the value in milliseconds
 *
 * @param Value         Pointer to DWORD to retrieve registry value
 *
 * @return ERROR_SUCCESS on success; Win32 error code otherwise
 */
WINTUN_STATUS
RegistryQueryDWORDWait(_In_ HKEY Key, _In_opt_z_ const WCHAR *Name, _In_ DWORD Timeout, _Out_ DWORD *Value)
{
    DWORD Result;
    ULONGLONG Deadline = GetTickCount64() + Timeout;
    HANDLE Event = CreateEventW(NULL, FALSE, FALSE, NULL);
    if (!Event)
        return GetLastError();
    for (;;)
    {
        Result = RegNotifyChangeKeyValue(Key, FALSE, REG_NOTIFY_CHANGE_LAST_SET, Event, TRUE);
        if (Result != ERROR_SUCCESS)
            break;
        Result = RegistryQueryDWORD(Key, Name, Value);
        if (Result != ERROR_FILE_NOT_FOUND && Result != ERROR_PATH_NOT_FOUND)
            break;
        LONGLONG TimeLeft = Deadline - GetTickCount64();
        if (TimeLeft < 0)
            TimeLeft = 0;
        if (WaitForSingleObject(Event, (DWORD)TimeLeft) != WAIT_OBJECT_0)
            break;
    }
    CloseHandle(Event);
    return Result;
}

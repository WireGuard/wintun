/* SPDX-License-Identifier: GPL-2.0
 *
 * Copyright (C) 2018-2020 WireGuard LLC. All Rights Reserved.
 */

#include "pch.h"

WINTUN_STATUS
CopyResource(
    _In_z_ const WCHAR *DestinationPath,
    _In_opt_ SECURITY_ATTRIBUTES *SecurityAttributes,
    _In_z_ const WCHAR *ResourceName)
{
    HRSRC FoundResource = FindResourceW(ResourceModule, ResourceName, RT_RCDATA);
    if (!FoundResource)
        return WINTUN_LOGGER_LAST_ERROR(L"Failed to find resource");
    DWORD SizeResource = SizeofResource(ResourceModule, FoundResource);
    if (!SizeResource)
        return WINTUN_LOGGER_LAST_ERROR(L"Failed to size resource");
    HGLOBAL LoadedResource = LoadResource(ResourceModule, FoundResource);
    if (!LoadedResource)
        return WINTUN_LOGGER_LAST_ERROR(L"Failed to load resource");
    LPVOID LockedResource = LockResource(LoadedResource);
    if (!LockedResource)
    {
        WINTUN_LOGGER(WINTUN_LOG_ERR, L"Failed to lock resource");
        return ERROR_LOCK_FAILED;
    }
    HANDLE DestinationHandle = CreateFileW(
        DestinationPath,
        GENERIC_WRITE,
        0,
        SecurityAttributes,
        CREATE_NEW,
        FILE_ATTRIBUTE_NORMAL | FILE_ATTRIBUTE_TEMPORARY,
        NULL);
    if (DestinationHandle == INVALID_HANDLE_VALUE)
        return WINTUN_LOGGER_LAST_ERROR(L"Failed to create file");
    DWORD BytesWritten;
    DWORD Result = ERROR_SUCCESS;
    if (!WriteFile(DestinationHandle, LockedResource, SizeResource, &BytesWritten, NULL))
        Result = WINTUN_LOGGER_LAST_ERROR(L"Failed to write file");
    if (BytesWritten != SizeResource)
    {
        WINTUN_LOGGER(WINTUN_LOG_ERR, L"Incomplete write");
        Result = Result != ERROR_SUCCESS ? Result : ERROR_WRITE_FAULT;
    }
    CloseHandle(DestinationHandle);
    return Result;
}

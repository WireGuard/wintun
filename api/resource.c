/* SPDX-License-Identifier: GPL-2.0
 *
 * Copyright (C) 2018-2020 WireGuard LLC. All Rights Reserved.
 */

#include "pch.h"

WINTUN_STATUS
ResourceGetAddress(_In_z_ const WCHAR *ResourceName, _Out_ const void **Address, _Out_ DWORD *Size)
{
    HRSRC FoundResource = FindResourceW(ResourceModule, ResourceName, RT_RCDATA);
    if (!FoundResource)
        return LOG_LAST_ERROR(L"Failed to find resource");
    *Size = SizeofResource(ResourceModule, FoundResource);
    if (!*Size)
        return LOG_LAST_ERROR(L"Failed to size resource");
    HGLOBAL LoadedResource = LoadResource(ResourceModule, FoundResource);
    if (!LoadedResource)
        return LOG_LAST_ERROR(L"Failed to load resource");
    *Address = LockResource(LoadedResource);
    if (!*Address)
    {
        LOG(WINTUN_LOG_ERR, L"Failed to lock resource");
        return ERROR_LOCK_FAILED;
    }
    return ERROR_SUCCESS;
}

WINTUN_STATUS
ResourceCopyToFile(_In_z_ const WCHAR *DestinationPath, _In_z_ const WCHAR *ResourceName)
{
    const void *LockedResource;
    DWORD SizeResource;
    DWORD Result = ResourceGetAddress(ResourceName, &LockedResource, &SizeResource);
    if (Result != ERROR_SUCCESS)
        return LOG(WINTUN_LOG_ERR, L"Failed to locate resource"), Result;
    HANDLE DestinationHandle = CreateFileW(
        DestinationPath,
        GENERIC_WRITE,
        0,
        SecurityAttributes,
        CREATE_NEW,
        FILE_ATTRIBUTE_NORMAL | FILE_ATTRIBUTE_TEMPORARY,
        NULL);
    if (DestinationHandle == INVALID_HANDLE_VALUE)
        return LOG_LAST_ERROR(L"Failed to create file");
    DWORD BytesWritten;
    if (!WriteFile(DestinationHandle, LockedResource, SizeResource, &BytesWritten, NULL))
        Result = LOG_LAST_ERROR(L"Failed to write file");
    if (BytesWritten != SizeResource)
    {
        LOG(WINTUN_LOG_ERR, L"Incomplete write");
        Result = Result != ERROR_SUCCESS ? Result : ERROR_WRITE_FAULT;
    }
    CloseHandle(DestinationHandle);
    return Result;
}

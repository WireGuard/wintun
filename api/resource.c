/* SPDX-License-Identifier: GPL-2.0
 *
 * Copyright (C) 2018-2020 WireGuard LLC. All Rights Reserved.
 */

#include "pch.h"

/**
 * Locates RT_RCDATA resource memory address and size.
 *
 * ResourceName         Name of the RT_RCDATA resource. Use MAKEINTRESOURCEW to locate resource by ID.
 *
 * Address              Pointer to a pointer variable to receive resource address.
 *
 * Size                 Pointer to a variable to receive resource size.
 *
 * @return ERROR_SUCCESS on success; Win32 error code otherwise.
 */
WINTUN_STATUS
ResourceGetAddress(_In_z_ const WCHAR *ResourceName, _Out_ const VOID **Address, _Out_ DWORD *Size)
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

/**
 * Copies resource to a file.
 *
 * DestinationPath      File path
 *
 * SecurityAttributes   File security attributes. May be NULL for detault.
 *
 * ResourceName         Name of the RT_RCDATA resource. Use MAKEINTRESOURCEW to locate resource by ID.
 *
 * @return ERROR_SUCCESS on success; Win32 error code otherwise.
 */
WINTUN_STATUS
ResourceCopyToFile(
    _In_z_ const WCHAR *DestinationPath,
    _In_opt_ SECURITY_ATTRIBUTES *SecurityAttributes,
    _In_z_ const WCHAR *ResourceName)
{
    const VOID *LockedResource;
    DWORD SizeResource;
    DWORD Result = ResourceGetAddress(ResourceName, &LockedResource, &SizeResource);
    if (Result != ERROR_SUCCESS)
        return LOG_ERROR("Failed to locate resource", Result);
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

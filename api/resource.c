/* SPDX-License-Identifier: GPL-2.0
 *
 * Copyright (C) 2018-2021 WireGuard LLC. All Rights Reserved.
 */

#include "logger.h"
#include "main.h"
#include "resource.h"
#include <Windows.h>
#include <Shlwapi.h>
#include <NTSecAPI.h>

_Use_decl_annotations_
const VOID *
ResourceGetAddress(LPCWSTR ResourceName, DWORD *Size)
{
    HRSRC FoundResource = FindResourceW(ResourceModule, ResourceName, RT_RCDATA);
    if (!FoundResource)
    {
        LOG_LAST_ERROR(L"Failed to find resource %s", ResourceName);
        return NULL;
    }
    *Size = SizeofResource(ResourceModule, FoundResource);
    if (!*Size)
    {
        LOG_LAST_ERROR(L"Failed to query resource %s size", ResourceName);
        return NULL;
    }
    HGLOBAL LoadedResource = LoadResource(ResourceModule, FoundResource);
    if (!LoadedResource)
    {
        LOG_LAST_ERROR(L"Failed to load resource %s", ResourceName);
        return NULL;
    }
    BYTE *Address = LockResource(LoadedResource);
    if (!Address)
    {
        LOG(WINTUN_LOG_ERR, L"Failed to lock resource %s", ResourceName);
        SetLastError(ERROR_LOCK_FAILED);
        return NULL;
    }
    return Address;
}

_Use_decl_annotations_
BOOL
ResourceCopyToFile(LPCWSTR DestinationPath, LPCWSTR ResourceName)
{
    DWORD SizeResource;
    const VOID *LockedResource = ResourceGetAddress(ResourceName, &SizeResource);
    if (!LockedResource)
    {
        LOG(WINTUN_LOG_ERR, L"Failed to locate resource %s", ResourceName);
        return FALSE;
    }
    HANDLE DestinationHandle = CreateFileW(
        DestinationPath,
        GENERIC_WRITE,
        0,
        &SecurityAttributes,
        CREATE_NEW,
        FILE_ATTRIBUTE_NORMAL | FILE_ATTRIBUTE_TEMPORARY,
        NULL);
    if (DestinationHandle == INVALID_HANDLE_VALUE)
    {
        LOG_LAST_ERROR(L"Failed to create file %s", DestinationPath);
        return FALSE;
    }
    DWORD BytesWritten;
    DWORD LastError;
    if (!WriteFile(DestinationHandle, LockedResource, SizeResource, &BytesWritten, NULL))
    {
        LastError = LOG_LAST_ERROR(L"Failed to write file %s", DestinationPath);
        goto cleanupDestinationHandle;
    }
    if (BytesWritten != SizeResource)
    {
        LOG(WINTUN_LOG_ERR,
            L"Incomplete write to %s (written: %u, expected: %u)",
            DestinationPath,
            BytesWritten,
            SizeResource);
        LastError = ERROR_WRITE_FAULT;
        goto cleanupDestinationHandle;
    }
    LastError = ERROR_SUCCESS;
cleanupDestinationHandle:
    CloseHandle(DestinationHandle);
    return RET_ERROR(TRUE, LastError);
}

_Return_type_success_(return != FALSE)
BOOL
ResourceCreateTemporaryDirectory(_Out_writes_z_(MAX_PATH) LPWSTR RandomTempSubDirectory)
{
    WCHAR WindowsDirectory[MAX_PATH];
    if (!GetWindowsDirectoryW(WindowsDirectory, _countof(WindowsDirectory)))
    {
        LOG_LAST_ERROR(L"Failed to get Windows folder");
        return FALSE;
    }
    WCHAR WindowsTempDirectory[MAX_PATH];
    if (!PathCombineW(WindowsTempDirectory, WindowsDirectory, L"Temp"))
    {
        SetLastError(ERROR_BUFFER_OVERFLOW);
        return FALSE;
    }
    UCHAR RandomBytes[32] = { 0 };
    if (!RtlGenRandom(RandomBytes, sizeof(RandomBytes)))
    {
        LOG(WINTUN_LOG_ERR, L"Failed to generate random");
        SetLastError(ERROR_GEN_FAILURE);
        return FALSE;
    }
    WCHAR RandomSubDirectory[sizeof(RandomBytes) * 2 + 1];
    for (int i = 0; i < sizeof(RandomBytes); ++i)
        swprintf_s(&RandomSubDirectory[i * 2], 3, L"%02x", RandomBytes[i]);
    if (!PathCombineW(RandomTempSubDirectory, WindowsTempDirectory, RandomSubDirectory))
    {
        SetLastError(ERROR_BUFFER_OVERFLOW);
        return FALSE;
    }
    if (!CreateDirectoryW(RandomTempSubDirectory, &SecurityAttributes))
    {
        LOG_LAST_ERROR(L"Failed to create temporary folder %s", RandomTempSubDirectory);
        return FALSE;
    }
    return TRUE;
}

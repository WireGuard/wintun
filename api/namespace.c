/* SPDX-License-Identifier: GPL-2.0
 *
 * Copyright (C) 2018-2021 WireGuard LLC. All Rights Reserved.
 */

#include "logger.h"
#include "main.h"
#include "namespace.h"

#include <Windows.h>
#include <winternl.h>
#include <winefs.h>
#include <wchar.h>
#include <stdlib.h>

static HANDLE PrivateNamespace = NULL;
static HANDLE BoundaryDescriptor = NULL;
static CRITICAL_SECTION Initializing;

static _Return_type_success_(return != FALSE)
BOOL NamespaceRuntimeInit(VOID)
{
    DWORD LastError;

    EnterCriticalSection(&Initializing);
    if (PrivateNamespace)
    {
        LeaveCriticalSection(&Initializing);
        return TRUE;
    }

    BYTE Sid[MAX_SID_SIZE];
    DWORD SidSize = sizeof(Sid);
    if (!CreateWellKnownSid(IsLocalSystem ? WinLocalSystemSid : WinBuiltinAdministratorsSid, NULL, Sid, &SidSize))
    {
        LastError = LOG_LAST_ERROR(L"Failed to create SID");
        goto cleanupLeaveCriticalSection;
    }

    BoundaryDescriptor = CreateBoundaryDescriptorW(L"Wintun", 0);
    if (!BoundaryDescriptor)
    {
        LastError = LOG_LAST_ERROR(L"Failed to create boundary descriptor");
        goto cleanupLeaveCriticalSection;
    }
    if (!AddSIDToBoundaryDescriptor(&BoundaryDescriptor, Sid))
    {
        LastError = LOG_LAST_ERROR(L"Failed to add SID to boundary descriptor");
        goto cleanupBoundaryDescriptor;
    }

    for (;;)
    {
        if ((PrivateNamespace = CreatePrivateNamespaceW(&SecurityAttributes, BoundaryDescriptor, L"Wintun")) != NULL)
            break;
        if ((LastError = GetLastError()) == ERROR_ALREADY_EXISTS)
        {
            if ((PrivateNamespace = OpenPrivateNamespaceW(BoundaryDescriptor, L"Wintun")) != NULL)
                break;
            if ((LastError = GetLastError()) == ERROR_PATH_NOT_FOUND)
                continue;
            LOG_ERROR(LastError, L"Failed to open private namespace");
        }
        else
            LOG_ERROR(LastError, L"Failed to create private namespace");
        goto cleanupBoundaryDescriptor;
    }

    LeaveCriticalSection(&Initializing);
    return TRUE;

cleanupBoundaryDescriptor:
    DeleteBoundaryDescriptor(BoundaryDescriptor);
cleanupLeaveCriticalSection:
    LeaveCriticalSection(&Initializing);
    SetLastError(LastError);
    return FALSE;
}

_Use_decl_annotations_
HANDLE
NamespaceTakeDriverInstallationMutex(VOID)
{
    if (!NamespaceRuntimeInit())
        return NULL;
    HANDLE Mutex = CreateMutexW(&SecurityAttributes, FALSE, L"Wintun\\Wintun-Driver-Installation-Mutex");
    if (!Mutex)
    {
        LOG_LAST_ERROR(L"Failed to create mutex");
        return NULL;
    }
    DWORD Result = WaitForSingleObject(Mutex, INFINITE);
    switch (Result)
    {
    case WAIT_OBJECT_0:
    case WAIT_ABANDONED:
        return Mutex;
    }
    LOG(WINTUN_LOG_ERR, L"Failed to get mutex (status: 0x%x)", Result);
    CloseHandle(Mutex);
    SetLastError(ERROR_GEN_FAILURE);
    return NULL;
}

_Use_decl_annotations_
HANDLE
NamespaceTakeDeviceInstallationMutex(VOID)
{
    if (!NamespaceRuntimeInit())
        return NULL;
    HANDLE Mutex = CreateMutexW(&SecurityAttributes, FALSE, L"Wintun\\Wintun-Device-Installation-Mutex");
    if (!Mutex)
    {
        LOG_LAST_ERROR(L"Failed to create mutex");
        return NULL;
    }
    DWORD Result = WaitForSingleObject(Mutex, INFINITE);
    switch (Result)
    {
    case WAIT_OBJECT_0:
    case WAIT_ABANDONED:
        return Mutex;
    }
    LOG(WINTUN_LOG_ERR, L"Failed to get mutex (status: 0x%x)", Result);
    CloseHandle(Mutex);
    SetLastError(ERROR_GEN_FAILURE);
    return NULL;
}

_Use_decl_annotations_
VOID
NamespaceReleaseMutex(HANDLE Mutex)
{
    ReleaseMutex(Mutex);
    CloseHandle(Mutex);
}

VOID NamespaceInit(VOID)
{
    InitializeCriticalSection(&Initializing);
}

VOID NamespaceDone(VOID)
{
    EnterCriticalSection(&Initializing);
    if (PrivateNamespace)
    {
        ClosePrivateNamespace(PrivateNamespace, 0);
        DeleteBoundaryDescriptor(BoundaryDescriptor);
        PrivateNamespace = NULL;
    }
    LeaveCriticalSection(&Initializing);
    DeleteCriticalSection(&Initializing);
}

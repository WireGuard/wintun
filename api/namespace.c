/* SPDX-License-Identifier: GPL-2.0
 *
 * Copyright (C) 2018-2020 WireGuard LLC. All Rights Reserved.
 */

#include "pch.h"

static SECURITY_ATTRIBUTES SecurityAttributes = { .nLength = sizeof(SECURITY_ATTRIBUTES) };
static BOOL HasInitialized = FALSE;
static CRITICAL_SECTION Initializing;
static BCRYPT_ALG_HANDLE AlgProvider;

static WCHAR *
NormalizeStringAlloc(_In_ NORM_FORM NormForm, _In_z_ const WCHAR *Source)
{
    WCHAR *Result = NULL;
    HANDLE Heap = GetProcessHeap();
    int Len = NormalizeString(NormForm, Source, -1, NULL, 0);
    for (int i = 0; i < 10; ++i)
    {
        if (Result)
            HeapFree(Heap, 0, Result);
        Result = HeapAlloc(Heap, 0, sizeof(WCHAR) * Len);
        Len = NormalizeString(NormForm, Source, -1, Result, Len);
        if (Len > 0)
            return Result;
        if (GetLastError() != ERROR_INSUFFICIENT_BUFFER)
            break;
        Len = -Len;
    }
    if (Result)
        HeapFree(Heap, 0, Result);
    return NULL;
}

static void
Bin2Hex(_In_bytecount_(Size) const void *Source, size_t Size, _Out_capcount_(Size * 2) WCHAR *Destination)
{
    for (size_t i = 0; i < Size; ++i)
    {
        static const WCHAR nibble[] = L"0123456789ABCDEF";
        *(Destination++) = nibble[(((unsigned char *)Source)[i] & 0xf0) >> 4];
        *(Destination++) = nibble[(((unsigned char *)Source)[i] & 0x0f)];
    }
}

static WINTUN_STATUS
NamespaceRuntimeInit()
{
    DWORD Result;

    EnterCriticalSection(&Initializing);
    if (HasInitialized)
    {
        LeaveCriticalSection(&Initializing);
        return ERROR_SUCCESS;
    }

    /* TODO: wireguard-go uses Blake2s hashing in tun\wintun\namespace_windows.go, unfortunately not available in
     * Windows API. SHA-256 is used instead. */
    if (!BCRYPT_SUCCESS(BCryptOpenAlgorithmProvider(&AlgProvider, BCRYPT_SHA256_ALGORITHM, NULL, 0)))
    {
        Result = ERROR_GEN_FAILURE;
        goto cleanupLeaveCriticalSection;
    }

    ULONG SecDescrSize;
    if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(
            L"O:SYD:P(A;;GA;;;SY)", 1, &SecurityAttributes.lpSecurityDescriptor, &SecDescrSize))
    {
        Result = GetLastError();
        goto cleanupBCryptCloseAlgorithmProvider;
    }
    BYTE Sid[MAX_SID_SIZE];
    DWORD SidSize = MAX_SID_SIZE;
    if (!CreateWellKnownSid(WinLocalSystemSid, NULL, Sid, &SidSize))
    {
        Result = GetLastError();
        goto cleanupSecurityDescriptor;
    }

    HANDLE Boundary = CreateBoundaryDescriptorW(L"Wintun", 0);
    if (!Boundary)
    {
        Result = GetLastError();
        goto cleanupSecurityDescriptor;
    }
    if (!AddSIDToBoundaryDescriptor(&Boundary, Sid))
    {
        Result = GetLastError();
        goto cleanupSecurityDescriptor;
    }

    for (;;)
    {
        if (CreatePrivateNamespaceW(&SecurityAttributes, Boundary, L"Wintun"))
            break;
        Result = GetLastError();
        if (Result == ERROR_ALREADY_EXISTS)
        {
            if (OpenPrivateNamespaceW(Boundary, L"Wintun"))
                break;
            Result = GetLastError();
            if (Result == ERROR_PATH_NOT_FOUND)
                continue;
        }
        goto cleanupSecurityDescriptor;
    }

    HasInitialized = TRUE;
    Result = ERROR_SUCCESS;
    goto cleanupLeaveCriticalSection;

cleanupSecurityDescriptor:
    LocalFree(SecurityAttributes.lpSecurityDescriptor);
cleanupBCryptCloseAlgorithmProvider:
    BCryptCloseAlgorithmProvider(AlgProvider, 0);
cleanupLeaveCriticalSection:
    LeaveCriticalSection(&Initializing);
    return Result;
}

_Check_return_
HANDLE
NamespaceTakeMutex(_In_z_ const WCHAR *Pool)
{
    HANDLE Mutex = NULL;

    if (NamespaceRuntimeInit() != ERROR_SUCCESS)
        return NULL;

    /* TODO: wireguard-go uses Blake2s hashing in tun\wintun\namespace_windows.go, unfortunately not available in
     * Windows API. SHA-256 is used instead. */
    BCRYPT_HASH_HANDLE Sha256 = NULL;
    if (!BCRYPT_SUCCESS(BCryptCreateHash(AlgProvider, &Sha256, NULL, 0, NULL, 0, 0)))
        return NULL;
    static const char mutex_label[] = "WireGuard Adapter Name Mutex Stable Suffix v1 jason@zx2c4.com";
    if (!BCRYPT_SUCCESS(BCryptHashData(Sha256, (PUCHAR)mutex_label, sizeof(mutex_label) - sizeof(char), 0)))
        goto cleanupSha256;
    WCHAR *PoolNorm = NormalizeStringAlloc(NormalizationC, Pool);
    if (!PoolNorm)
        goto cleanupSha256;
    /* TODO: wireguard-go hashes UTF-8 normalized pool name. We hash UTF-16 here. */
    if (!BCRYPT_SUCCESS(BCryptHashData(Sha256, (PUCHAR)PoolNorm, (int)wcslen(PoolNorm), 0)))
        goto cleanupPoolNorm;
    BYTE Hash[32];
    if (!BCRYPT_SUCCESS(BCryptFinishHash(Sha256, Hash, sizeof(Hash), 0)))
        goto cleanupPoolNorm;
    static const WCHAR MutexNamePrefix[] = L"Wintun\\Wintun-Name-Mutex-";
    WCHAR MutexName[_countof(MutexNamePrefix) /*<= incl. terminator*/ + sizeof(Hash) * 2];
    memcpy(MutexName, MutexNamePrefix, sizeof(MutexNamePrefix) - sizeof(WCHAR));
    Bin2Hex(Hash, sizeof(Hash), MutexName + _countof(MutexNamePrefix) - 1);
    MutexName[_countof(MutexName) - 1] = 0;
    Mutex = CreateMutexW(&SecurityAttributes, FALSE, MutexName);
    if (!Mutex)
        goto cleanupPoolNorm;
    switch (WaitForSingleObject(Mutex, INFINITE))
    {
    case WAIT_OBJECT_0:
    case WAIT_ABANDONED:
        goto cleanupPoolNorm;
    }

    CloseHandle(Mutex);
    Mutex = NULL;
cleanupPoolNorm:
    HeapFree(GetProcessHeap(), 0, PoolNorm);
cleanupSha256:
    BCryptDestroyHash(Sha256);
    return Mutex;
}

void
NamespaceReleaseMutex(_In_ HANDLE Mutex)
{
    ReleaseMutex(Mutex);
    CloseHandle(Mutex);
}

void
NamespaceInit()
{
    InitializeCriticalSection(&Initializing);
}

void
NamespaceCleanup()
{
    EnterCriticalSection(&Initializing);
    if (HasInitialized)
    {
        LocalFree(SecurityAttributes.lpSecurityDescriptor);
        BCryptCloseAlgorithmProvider(AlgProvider, 0);
        HasInitialized = FALSE;
    }
    LeaveCriticalSection(&Initializing);
    DeleteCriticalSection(&Initializing);
}

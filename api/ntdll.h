/* SPDX-License-Identifier: GPL-2.0
 *
 * Copyright (C) 2018-2021 WireGuard LLC. All Rights Reserved.
 */

#pragma once

#include <Windows.h>

enum
{
    SystemModuleInformation = 11
};

typedef struct _RTL_PROCESS_MODULE_INFORMATION
{
    HANDLE Section;
    PVOID MappedBase;
    PVOID ImageBase;
    ULONG ImageSize;
    ULONG Flags;
    USHORT LoadOrderIndex;
    USHORT InitOrderIndex;
    USHORT LoadCount;
    USHORT OffsetToFileName;
    UCHAR FullPathName[256];
} RTL_PROCESS_MODULE_INFORMATION, *PRTL_PROCESS_MODULE_INFORMATION;

typedef struct _RTL_PROCESS_MODULES
{
    ULONG NumberOfModules;
    RTL_PROCESS_MODULE_INFORMATION Modules[1];
} RTL_PROCESS_MODULES, *PRTL_PROCESS_MODULES;

typedef struct _KEY_NAME_INFORMATION
{
    ULONG NameLength;
    WCHAR Name[1];
} KEY_NAME_INFORMATION, *PKEY_NAME_INFORMATION;

#define STATUS_INFO_LENGTH_MISMATCH ((NTSTATUS)0xC0000004L) // TODO: #include <ntstatus.h> instead of this
#define STATUS_PNP_DEVICE_CONFIGURATION_PENDING ((NTSTATUS)0xC0000495L)

/* We can't use RtlGetVersion, because appcompat's aclayers.dll shims it to report Vista
 * when run from legacy contexts. So, we instead use the undocumented RtlGetNtVersionNumbers.
 *
 * Another way would be reading from the PEB directly:
 *   ((DWORD *)NtCurrentTeb()->ProcessEnvironmentBlock)[sizeof(void *) == 8 ? 70 : 41]
 * Or just read from KUSER_SHARED_DATA the same way on 32-bit and 64-bit:
 *    *(DWORD *)0x7FFE026C
 */
EXTERN_C
DECLSPEC_IMPORT VOID NTAPI
RtlGetNtVersionNumbers(_Out_opt_ DWORD *MajorVersion, _Out_opt_ DWORD *MinorVersion, _Out_opt_ DWORD *BuildNumber);

EXTERN_C
DECLSPEC_IMPORT DWORD NTAPI
NtQueryKey(
    _In_ HANDLE KeyHandle,
    _In_ int KeyInformationClass,
    _Out_bytecap_post_bytecount_(Length, *ResultLength) PVOID KeyInformation,
    _In_ ULONG Length,
    _Out_ PULONG ResultLength);

/* This is documented in NTSecAPI.h, which we can't include, due to header conflicts. It actually lives in advapi32.dll. */
#define RtlGenRandom SystemFunction036
BOOLEAN
NTAPI
RtlGenRandom(_Out_writes_bytes_all_(RandomBufferLength) PVOID RandomBuffer, _In_ ULONG RandomBufferLength);
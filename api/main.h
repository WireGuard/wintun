/* SPDX-License-Identifier: GPL-2.0
 *
 * Copyright (C) 2018-2021 WireGuard LLC. All Rights Reserved.
 */

#pragma once

#include <Windows.h>

#if defined(_M_IX86)
#    define IMAGE_FILE_PROCESS IMAGE_FILE_MACHINE_I386
#elif defined(_M_AMD64)
#    define IMAGE_FILE_PROCESS IMAGE_FILE_MACHINE_AMD64
#elif defined(_M_ARM)
#    define IMAGE_FILE_PROCESS IMAGE_FILE_MACHINE_ARMNT
#elif defined(_M_ARM64)
#    define IMAGE_FILE_PROCESS IMAGE_FILE_MACHINE_ARM64
#else
#    error Unsupported architecture
#endif

extern HINSTANCE ResourceModule;
extern HANDLE ModuleHeap;
extern SECURITY_ATTRIBUTES SecurityAttributes;
extern BOOL IsLocalSystem;
extern USHORT NativeMachine;

#if NTDDI_VERSION > NTDDI_WIN7
#    define IsWindows7 FALSE
#else
extern BOOL IsWindows7;
#endif

#if NTDDI_VERSION >= NTDDI_WIN10
#    define IsWindows10 TRUE
#else
extern BOOL IsWindows10;
#endif
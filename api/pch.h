/* SPDX-License-Identifier: GPL-2.0
 *
 * Copyright (C) 2018-2020 WireGuard LLC. All Rights Reserved.
 */

#pragma once

#include "adapter.h"
#include "api.h"
#include "elevate.h"
#include "logger.h"
#include "namespace.h"
#include "nci.h"
#include "ntldr.h"
#include "registry.h"
#include "resource.h"
#include "wintun.h"

#pragma warning(push)
#pragma warning(disable: 4201) /* nonstandard extension used: nameless struct/union */
#include <bcrypt.h>
#include <cfgmgr32.h>
#include <delayimp.h>
#include <devguid.h>
#include <IPExport.h>
#include <iphlpapi.h>
#include <locale.h>
#include <ndisguid.h>
#include <newdev.h>
#include <objbase.h>
#include <Psapi.h>
#include <sddl.h>
#include <SetupAPI.h>
#include <Shlwapi.h>
#include <string.h>
#include <TlHelp32.h>
#include <wchar.h>
#include <Windows.h>
#include <winternl.h>
#define _NTDEF_ //TODO: find a better way to include both ntsecapi.h and winternl.h or include ntdef.h for real somehow
#include <NTSecAPI.h>
#define STATUS_INFO_LENGTH_MISMATCH ((NTSTATUS)0xC0000004L) //TODO: #include <ntstatus.h> instead of this
#pragma warning(pop)
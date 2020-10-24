/* SPDX-License-Identifier: GPL-2.0
 *
 * Copyright (C) 2018-2020 WireGuard LLC. All Rights Reserved.
 */

#pragma once

#include "adapter.h"
#include "atomic.h"
#include "api.h"
#include "driver.h"
#include "logger.h"
#include "namespace.h"
#include "nci.h"
#include "registry.h"
#include "resource.h"
#include "wintun.h"

#include <bcrypt.h>
#include <cfgmgr32.h>
#include <devguid.h>
#include <iphlpapi.h>
#include <locale.h>
#include <ndisguid.h>
#include <newdev.h>
#include <NTSecAPI.h>
#include <objbase.h>
#include <Psapi.h>
#include <sddl.h>
#include <SetupAPI.h>
#include <Shlwapi.h>
#include <string.h>
#include <TlHelp32.h>
#include <wchar.h>
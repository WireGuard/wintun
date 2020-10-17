/* SPDX-License-Identifier: GPL-2.0
 *
 * Copyright (C) 2018-2020 WireGuard LLC. All Rights Reserved.
 */

#pragma once

#include <Windows.h>

#ifndef __L
#    define __L(x) L##x
#endif
#ifndef _L
#    define _L(x) __L(x)
#endif

extern HINSTANCE ResourceModule;
extern SECURITY_ATTRIBUTES *SecurityAttributes;

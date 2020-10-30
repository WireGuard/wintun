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

#if defined(_M_IX86) || defined(_M_ARM)
#define MAYBE_WOW64
#endif
#if defined(_M_AMD64) || defined(_M_ARM64) || defined(_DEBUG)
#define ACCEPT_WOW64
#endif

extern HINSTANCE ResourceModule;
extern HANDLE ModuleHeap;
extern SECURITY_ATTRIBUTES *SecurityAttributes;

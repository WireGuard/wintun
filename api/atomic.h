/* SPDX-License-Identifier: GPL-2.0
 *
 * Copyright (C) 2018-2020 WireGuard LLC. All Rights Reserved.
 */

#pragma once

#include <Windows.h>

static __forceinline VOID
InterlockedSetU(_Inout_ _Interlocked_operand_ ULONG volatile *Target, _In_ ULONG Value)
{
    *Target = Value;
}

static __forceinline LONG
InterlockedGet(_In_ _Interlocked_operand_ LONG volatile *Value)
{
    return *Value;
}

static __forceinline ULONG
InterlockedGetU(_In_ _Interlocked_operand_ ULONG volatile *Value)
{
    return *Value;
}

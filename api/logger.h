/* SPDX-License-Identifier: GPL-2.0
 *
 * Copyright (C) 2018-2020 WireGuard LLC. All Rights Reserved.
 */

#pragma once

#include <Windows.h>

typedef enum _WINTUN_LOGGER_LEVEL
{
    WINTUN_LOG_INFO = 0,
    WINTUN_LOG_WARN,
    WINTUN_LOG_ERR
} WINTUN_LOGGER_LEVEL;

typedef BOOL(CALLBACK *WINTUN_LOGGER_FUNC)(_In_ WINTUN_LOGGER_LEVEL Level, _In_z_ const WCHAR *Message);

extern WINTUN_LOGGER_FUNC Logger;

VOID WINAPI
WintunSetLogger(_In_ WINTUN_LOGGER_FUNC NewLogger);

_Post_equals_last_error_ DWORD
LoggerError(_In_z_ const WCHAR *Prefix, _In_ DWORD Error);

inline _Post_equals_last_error_ DWORD
LoggerLastError(_In_z_ const WCHAR *Prefix)
{
    DWORD Error = GetLastError();
    LoggerError(Prefix, Error);
    SetLastError(Error);
    return Error;
}

#define LOG(lvl, msg) (Logger((lvl), _L(__FUNCTION__) L": " msg))
#define LOG_ERROR(msg, err) (LoggerError(_L(__FUNCTION__) L": " msg, (err)))
#define LOG_LAST_ERROR(msg) (LoggerLastError(_L(__FUNCTION__) L": " msg))

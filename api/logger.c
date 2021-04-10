/* SPDX-License-Identifier: GPL-2.0
 *
 * Copyright (C) 2018-2021 WireGuard LLC. All Rights Reserved.
 */

#include "logger.h"
#include "ntdll.h"
#include <Windows.h>
#include <winternl.h>
#include <wchar.h>

static BOOL CALLBACK
NopLogger(_In_ WINTUN_LOGGER_LEVEL Level, _In_z_ const WCHAR *LogLine)
{
    UNREFERENCED_PARAMETER(Level);
    UNREFERENCED_PARAMETER(LogLine);
    return TRUE;
}

WINTUN_LOGGER_CALLBACK Logger = NopLogger;

void CALLBACK
WintunSetLogger(_In_ WINTUN_LOGGER_CALLBACK NewLogger)
{
    if (!NewLogger)
        NewLogger = NopLogger;
    Logger = NewLogger;
}

static VOID
StrTruncate(_Inout_count_(StrChars) WCHAR *Str, _In_ SIZE_T StrChars)
{
    Str[StrChars - 2] = L'\u2026'; /* Horizontal Ellipsis */
    Str[StrChars - 1] = 0;
}

_Post_equals_last_error_ DWORD
LoggerLog(_In_ WINTUN_LOGGER_LEVEL Level, _In_z_ const WCHAR *Function, _In_z_ const WCHAR *LogLine)
{
    DWORD LastError = GetLastError();
    if (Function)
    {
        WCHAR Combined[0x400];
        if (_snwprintf_s(Combined, _countof(Combined), _TRUNCATE, L"%s: %s", Function, LogLine) == -1)
            StrTruncate(Combined, _countof(Combined));
        Logger(Level, Combined);
    }
    else
        Logger(Level, LogLine);
    SetLastError(LastError);
    return LastError;
}

_Post_equals_last_error_ DWORD
LoggerLogV(
    _In_ WINTUN_LOGGER_LEVEL Level,
    _In_z_ const WCHAR *Function,
    _In_z_ _Printf_format_string_ const WCHAR *Format,
    _In_ va_list Args)
{
    DWORD LastError = GetLastError();
    WCHAR LogLine[0x400];
    if (_vsnwprintf_s(LogLine, _countof(LogLine), _TRUNCATE, Format, Args) == -1)
        StrTruncate(LogLine, _countof(LogLine));
    if (Function)
        LoggerLog(Level, Function, LogLine);
    else
        Logger(Level, LogLine);
    SetLastError(LastError);
    return LastError;
}

_Post_equals_last_error_ DWORD
LoggerError(_In_ DWORD Error, _In_z_ const WCHAR *Function, _In_z_ const WCHAR *Prefix)
{
    WCHAR *SystemMessage = NULL, *FormattedMessage = NULL;
    FormatMessageW(
        FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_MAX_WIDTH_MASK,
        NULL,
        HRESULT_FROM_SETUPAPI(Error),
        MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
        (void *)&SystemMessage,
        0,
        NULL);
    FormatMessageW(
        FORMAT_MESSAGE_FROM_STRING | FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_ARGUMENT_ARRAY |
            FORMAT_MESSAGE_MAX_WIDTH_MASK,
        SystemMessage ? L"%4: %1: %3(Code 0x%2!08X!)" : L"%4: %1: Code 0x%2!08X!",
        0,
        0,
        (void *)&FormattedMessage,
        0,
        (va_list *)(DWORD_PTR[]){ (DWORD_PTR)Prefix, (DWORD_PTR)Error, (DWORD_PTR)SystemMessage, (DWORD_PTR)Function });
    if (FormattedMessage)
        Logger(WINTUN_LOG_ERR, FormattedMessage);
    LocalFree(FormattedMessage);
    LocalFree(SystemMessage);
    return Error;
}

_Post_equals_last_error_ DWORD
LoggerErrorV(
    _In_ DWORD Error,
    _In_z_ const WCHAR *Function,
    _In_z_ _Printf_format_string_ const WCHAR *Format,
    _In_ va_list Args)
{
    WCHAR Prefix[0x400];
    if (_vsnwprintf_s(Prefix, _countof(Prefix), _TRUNCATE, Format, Args) == -1)
        StrTruncate(Prefix, _countof(Prefix));
    return LoggerError(Error, Function, Prefix);
}

VOID
LoggerGetRegistryKeyPath(_In_ HKEY Key, _Out_cap_c_(MAX_REG_PATH) WCHAR *Path)
{
    DWORD LastError = GetLastError();
    if (Key == NULL)
    {
        wcscpy_s(Path, MAX_REG_PATH, L"<null>");
        goto out;
    }
    if (_snwprintf_s(Path, MAX_REG_PATH, _TRUNCATE, L"0x%p", Key) == -1)
        StrTruncate(Path, MAX_REG_PATH);
    union
    {
        KEY_NAME_INFORMATION KeyNameInfo;
        WCHAR Data[offsetof(KEY_NAME_INFORMATION, Name) + MAX_REG_PATH];
    } Buffer;
    DWORD Size;
    if (!NT_SUCCESS(NtQueryKey(Key, 3, &Buffer, sizeof(Buffer), &Size)) ||
        Size < offsetof(KEY_NAME_INFORMATION, Name) || Buffer.KeyNameInfo.NameLength >= MAX_REG_PATH * sizeof(WCHAR))
        goto out;
    Buffer.KeyNameInfo.NameLength /= sizeof(WCHAR);
    wmemcpy_s(Path, MAX_REG_PATH, Buffer.KeyNameInfo.Name, Buffer.KeyNameInfo.NameLength);
    Path[Buffer.KeyNameInfo.NameLength] = L'\0';
out:
    SetLastError(LastError);
}

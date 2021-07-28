/* SPDX-License-Identifier: GPL-2.0
 *
 * Copyright (C) 2018-2021 WireGuard LLC. All Rights Reserved.
 */

#include "logger.h"
#include "adapter.h"
#include "ntdll.h"
#include <Windows.h>
#include <winternl.h>
#include <wchar.h>
#include <stdlib.h>

static BOOL CALLBACK
NopLogger(_In_ WINTUN_LOGGER_LEVEL Level, _In_z_ LPCWSTR LogLine)
{
    return TRUE;
}

WINTUN_LOGGER_CALLBACK Logger = NopLogger;

_Use_decl_annotations_
VOID WINAPI
WintunSetLogger(WINTUN_LOGGER_CALLBACK NewLogger)
{
    if (!NewLogger)
        NewLogger = NopLogger;
    Logger = NewLogger;
}

static VOID
StrTruncate(_Inout_count_(StrChars) LPWSTR Str, _In_ SIZE_T StrChars)
{
    Str[StrChars - 2] = L'\u2026'; /* Horizontal Ellipsis */
    Str[StrChars - 1] = 0;
}

_Use_decl_annotations_
DWORD
LoggerLog(WINTUN_LOGGER_LEVEL Level, LPCWSTR Function, LPCWSTR LogLine)
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

_Use_decl_annotations_
DWORD
LoggerLogV(WINTUN_LOGGER_LEVEL Level, LPCWSTR Function, LPCWSTR Format, va_list Args)
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

_Use_decl_annotations_
DWORD
LoggerError(DWORD Error, LPCWSTR Function, LPCWSTR Prefix)
{
    LPWSTR SystemMessage = NULL, FormattedMessage = NULL;
    FormatMessageW(
        FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_MAX_WIDTH_MASK,
        NULL,
        HRESULT_FROM_SETUPAPI(Error),
        MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
        (VOID *)&SystemMessage,
        0,
        NULL);
    FormatMessageW(
        FORMAT_MESSAGE_FROM_STRING | FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_ARGUMENT_ARRAY |
            FORMAT_MESSAGE_MAX_WIDTH_MASK,
        SystemMessage ? L"%4: %1: %3(Code 0x%2!08X!)" : L"%4: %1: Code 0x%2!08X!",
        0,
        0,
        (VOID *)&FormattedMessage,
        0,
        (va_list *)(DWORD_PTR[]){ (DWORD_PTR)Prefix, (DWORD_PTR)Error, (DWORD_PTR)SystemMessage, (DWORD_PTR)Function });
    if (FormattedMessage)
        Logger(WINTUN_LOG_ERR, FormattedMessage);
    LocalFree(FormattedMessage);
    LocalFree(SystemMessage);
    return Error;
}

_Use_decl_annotations_
DWORD
LoggerErrorV(DWORD Error, LPCWSTR Function, LPCWSTR Format, va_list Args)
{
    WCHAR Prefix[0x400];
    if (_vsnwprintf_s(Prefix, _countof(Prefix), _TRUNCATE, Format, Args) == -1)
        StrTruncate(Prefix, _countof(Prefix));
    return LoggerError(Error, Function, Prefix);
}

_Use_decl_annotations_
VOID
LoggerGetRegistryKeyPath(HKEY Key, LPWSTR Path)
{
    DWORD LastError = GetLastError();
    if (Key == NULL)
    {
        wcsncpy_s(Path, MAX_REG_PATH, L"<null>", _TRUNCATE);
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

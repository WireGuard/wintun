/* SPDX-License-Identifier: GPL-2.0
 *
 * Copyright (C) 2018-2021 WireGuard LLC. All Rights Reserved.
 */

#include "logger.h"
#include "adapter.h"
#include "ntdll.h"
#include <Windows.h>
#include <iphlpapi.h>
#include <winternl.h>
#include <wchar.h>
#include <stdlib.h>

static BOOL CALLBACK
NopLogger(_In_ WINTUN_LOGGER_LEVEL Level, _In_ DWORD64 Timestamp, _In_z_ LPCWSTR LogLine)
{
    return TRUE;
}

WINTUN_LOGGER_CALLBACK Logger = NopLogger;

static DWORD64 Now(VOID)
{
    LARGE_INTEGER Timestamp;
    NtQuerySystemTime(&Timestamp);
    return Timestamp.QuadPart;
}

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
LoggerLog(WINTUN_LOGGER_LEVEL Level, LPCWSTR LogLine)
{
    DWORD LastError = GetLastError();
    Logger(Level, Now(), LogLine);
    SetLastError(LastError);
    return LastError;
}

_Use_decl_annotations_
DWORD
LoggerLogV(WINTUN_LOGGER_LEVEL Level, LPCWSTR Format, va_list Args)
{
    DWORD LastError = GetLastError();
    WCHAR LogLine[0x400];
    if (_vsnwprintf_s(LogLine, _countof(LogLine), _TRUNCATE, Format, Args) == -1)
        StrTruncate(LogLine, _countof(LogLine));
    Logger(Level, Now(), LogLine);
    SetLastError(LastError);
    return LastError;
}

_Use_decl_annotations_
DWORD
LoggerError(DWORD Error, LPCWSTR Prefix)
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
        SystemMessage ? L"%1: %3(Code 0x%2!08X!)" : L"%1: Code 0x%2!08X!",
        0,
        0,
        (VOID *)&FormattedMessage,
        0,
        (va_list *)(DWORD_PTR[]){ (DWORD_PTR)Prefix, (DWORD_PTR)Error, (DWORD_PTR)SystemMessage });
    if (FormattedMessage)
        Logger(WINTUN_LOG_ERR, Now(), FormattedMessage);
    LocalFree(FormattedMessage);
    LocalFree(SystemMessage);
    return Error;
}

_Use_decl_annotations_
DWORD
LoggerErrorV(DWORD Error, LPCWSTR Format, va_list Args)
{
    WCHAR LogLine[0x400];
    if (_vsnwprintf_s(LogLine, _countof(LogLine), _TRUNCATE, Format, Args) == -1)
        StrTruncate(LogLine, _countof(LogLine));
    return LoggerError(Error, LogLine);
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

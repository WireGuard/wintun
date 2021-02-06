/* SPDX-License-Identifier: GPL-2.0
 *
 * Copyright (C) 2018-2021 WireGuard LLC. All Rights Reserved.
 */

#include "logger.h"
#include "ntdll.h"
#include <Windows.h>
#include <winternl.h>
#include <wchar.h>

#define _PRECISION_MAX ((size_t)-1)
#define _PRECISION_RUNTIME ((size_t)-2)

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

_Success_(return >= 0)
_Check_return_opt_ static ptrdiff_t
PushTerminator(
    _Out_writes_(BufferCount) _Always_(_Post_z_) wchar_t *Buffer,
    _In_ size_t BufferCount,
    _In_ size_t MaxCount,
    _In_ size_t Count)
{
    if (Count < BufferCount)
    {
        Buffer[Count] = L'\0';
        return Count;
    }
    if (MaxCount == _TRUNCATE)
    {
        Buffer[BufferCount - 1] = L'\0';
        return -1;
    }
    _invalid_parameter_noinfo();
    _set_errno(ERANGE);
    Buffer[0] = L'\0';
    return -1;
}

static ptrdiff_t
PushChar(
    _Out_writes_(BufferCount) wchar_t *Buffer,
    _In_ size_t BufferCount,
    _In_ size_t MaxCount,
    _In_ size_t Count,
    _In_ wchar_t Char)
{
    if (Count < BufferCount)
    {
        if (Count < MaxCount)
        {
            Buffer[Count] = Char;
            return 1;
        }
        Buffer[MaxCount] = L'\0';
        return -1;
    }
    if (MaxCount == _TRUNCATE)
    {
        Buffer[BufferCount - 1] = L'\0';
        return -1;
    }
    _invalid_parameter_noinfo();
    _set_errno(ERANGE);
    Buffer[0] = L'\0';
    return -1;
}

_Success_(return >= 0)
_Check_return_opt_ static ptrdiff_t
LoggerSPrintF(
    _Out_writes_opt_(BufferCount) _Always_(_Post_z_) wchar_t *Buffer,
    _In_ size_t BufferCount,
    _In_ size_t MaxCount,
    _In_z_ wchar_t const *Format,
    va_list Args)
{
    if (!Buffer || !BufferCount || !Format)
    {
        _set_errno(EINVAL);
        return -1;
    }
    for (size_t Count = 0;;)
    {
        ptrdiff_t Result;
        if (*Format == L'\0')
            return PushTerminator(Buffer, BufferCount, MaxCount, Count);
        if (*Format != L'%')
        {
            Result = PushChar(Buffer, BufferCount, MaxCount, Count, *(Format++));
            if (Result < 0)
                return Result;
            Count += Result;
            continue;
        }
        const wchar_t *Flag = Format + 1, *FlagEnd = Flag + (wcschr(L"-+0 #", *Flag) ? 1 : 0);
        const wchar_t *Width = FlagEnd, *WidthEnd = Width;
#pragma warning(suppress : 6031)
        wcstoul(Width, (wchar_t **)&WidthEnd, 10);
        const wchar_t *Precision = WidthEnd, *PrecisionEnd = Precision;
        size_t PrecisionVal = _PRECISION_MAX;
        if (Precision[0] == L'.')
        {
            if (Precision[1] == L'*')
            {
                PrecisionVal = _PRECISION_RUNTIME;
                PrecisionEnd = Precision + 2;
            }
            else
                PrecisionVal = wcstoul(Precision + 1, (wchar_t **)&PrecisionEnd, 10);
        }
        size_t FieldPrecision;
        const wchar_t *Size = PrecisionEnd, *SizeEnd = Size;
        if (Size[0] == L'I' && (Size[1] == L'3' && Size[2] == L'2' || Size[1] == L'6' && Size[2] == L'4'))
            SizeEnd = Size + 3;
        else if (Size[0] == L'h' && Size[1] == L'h' || Size[0] == L'l' && Size[1] == L'l')
            SizeEnd = Size + 2;
        else if (
            Size[0] == L'h' || Size[0] == L'I' || Size[0] == L'j' || Size[0] == L'l' || Size[0] == L'L' ||
            Size[0] == L't' || Size[0] == L'w' || Size[0] == L'z')
            SizeEnd = Size + 1;
        const wchar_t *Type = SizeEnd, *TypeEnd = Type + 1;
        if (*Type == L'r')
        {
            FieldPrecision = PrecisionVal == _PRECISION_RUNTIME ? va_arg(Args, unsigned long) : MAX_REG_PATH;
            WCHAR RegPath[MAX_REG_PATH];
            LoggerGetRegistryKeyPath(va_arg(Args, HKEY), RegPath);
            for (size_t i = 0; i < FieldPrecision && RegPath[i];)
            {
                Result = PushChar(Buffer, BufferCount, MaxCount, Count, RegPath[i++]);
                if (Result < 0)
                    return Result;
                Count += Result;
            }
            Format = TypeEnd;
            continue;
        }
        wchar_t FormatSub[100];
        const size_t FormatSubCount = TypeEnd - Format;
        if (FormatSubCount >= _countof(FormatSub))
        {
            _invalid_parameter(Format, _L(__FUNCTION__), _L(__FILE__), __LINE__, 0);
            _set_errno(EINVAL);
            Buffer[0] = L'\0';
            return -1;
        }
        wmemcpy(FormatSub, Format, FormatSubCount);
        FormatSub[FormatSubCount] = 0;
        Result = _vsnwprintf_s(
            Buffer + Count, BufferCount - Count, MaxCount != _TRUNCATE ? MaxCount - Count : _TRUNCATE, FormatSub, Args);
        if (Result < 0)
            return Result;
        Count += Result;
        Format = TypeEnd;
#pragma warning(push)
#pragma warning(disable : 6269)
        if (PrecisionVal == _PRECISION_RUNTIME)
            va_arg(Args, unsigned long);
        va_arg(Args, int);
#pragma warning(pop)
    }
}

_Post_equals_last_error_ DWORD
LoggerLogV(_In_ WINTUN_LOGGER_LEVEL Level, _In_z_ const WCHAR *Function, _In_z_ const WCHAR *Format, _In_ va_list Args)
{
    DWORD LastError = GetLastError();
    WCHAR LogLine[0x400];
    if (LoggerSPrintF(LogLine, _countof(LogLine), _TRUNCATE, Format, Args) == -1)
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
        SystemMessage ? L"%4: %1: %3(Code 0x%2!08X!)" : L"%1: Code 0x%2!08X!",
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
LoggerErrorV(_In_ DWORD Error, _In_z_ const WCHAR *Function, _In_z_ const WCHAR *Format, _In_ va_list Args)
{
    WCHAR Prefix[0x400];
    if (LoggerSPrintF(Prefix, _countof(Prefix), _TRUNCATE, Format, Args) == -1)
        StrTruncate(Prefix, _countof(Prefix));
    return LoggerError(Error, Function, Prefix);
}

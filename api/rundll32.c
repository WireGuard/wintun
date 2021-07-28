/* SPDX-License-Identifier: GPL-2.0
 *
 * Copyright (C) 2018-2021 WireGuard LLC. All Rights Reserved.
 */

#include "rundll32.h"
#include "adapter.h"
#include "main.h"
#include "logger.h"
#include "resource.h"
#include <Windows.h>
#include <shellapi.h>
#include <Shlwapi.h>
#include <cfgmgr32.h>
#include <objbase.h>
#include <assert.h>

#ifdef ACCEPT_WOW64

#    define EXPORT comment(linker, "/EXPORT:" __FUNCTION__ "=" __FUNCDNAME__)

static DWORD
WriteFormatted(_In_ DWORD StdHandle, _In_z_ LPCWSTR Template, ...)
{
    LPWSTR FormattedMessage = NULL;
    DWORD Size;
    va_list Arguments;
    va_start(Arguments, Template);
    DWORD Len = FormatMessageW(
        FORMAT_MESSAGE_FROM_STRING | FORMAT_MESSAGE_ALLOCATE_BUFFER,
        Template,
        0,
        0,
        (VOID *)&FormattedMessage,
        0,
        &Arguments);
    if (SUCCEEDED(DWordMult(Len, sizeof(*FormattedMessage), &Size)))
        WriteFile(GetStdHandle(StdHandle), FormattedMessage, Size, &Size, NULL);
    else
        Size = 0;
    LocalFree(FormattedMessage);
    va_end(Arguments);
    return Size / sizeof(*FormattedMessage);
}

static VOID CALLBACK
ConsoleLogger(_In_ WINTUN_LOGGER_LEVEL Level, _In_z_ LPCWSTR LogLine)
{
    LPCWSTR Template;
    switch (Level)
    {
    case WINTUN_LOG_INFO:
        Template = L"[+] %1\n";
        break;
    case WINTUN_LOG_WARN:
        Template = L"[-] %1\n";
        break;
    case WINTUN_LOG_ERR:
        Template = L"[!] %1\n";
        break;
    default:
        return;
    }
    WriteFormatted(STD_ERROR_HANDLE, Template, LogLine);
}

VOID __stdcall CreateAdapter(HWND hwnd, HINSTANCE hinst, LPSTR lpszCmdLine, int nCmdShow)
{
#    pragma EXPORT

    int Argc;
    LPWSTR *Argv = CommandLineToArgvW(GetCommandLineW(), &Argc);
    WintunSetLogger(ConsoleLogger);

    if (Argc < 4)
        goto cleanup;
    if (wcslen(Argv[2]) >= WINTUN_MAX_POOL)
        goto cleanup;
    if (wcslen(Argv[3]) >= MAX_ADAPTER_NAME)
        goto cleanup;
    GUID RequestedGUID;
    if (Argc > 4 && FAILED(CLSIDFromString(Argv[4], &RequestedGUID)))
        goto cleanup;

    BOOL RebootRequired;
    WINTUN_ADAPTER *Adapter = WintunCreateAdapter(Argv[2], Argv[3], Argc > 4 ? &RequestedGUID : NULL, &RebootRequired);
    DWORD LastError = Adapter ? ERROR_SUCCESS : GetLastError();
    WriteFormatted(
        STD_OUTPUT_HANDLE, L"%1!X! %2!s! %3!X!", LastError, Adapter ? Adapter->DevInstanceID : L"", RebootRequired);
    if (Adapter)
        WintunFreeAdapter(Adapter);

cleanup:
    LocalFree(Argv);
}

VOID __stdcall DeleteAdapter(HWND hwnd, HINSTANCE hinst, LPSTR lpszCmdLine, int nCmdShow)
{
#    pragma EXPORT

    int Argc;
    LPWSTR *Argv = CommandLineToArgvW(GetCommandLineW(), &Argc);
    WintunSetLogger(ConsoleLogger);

    if (Argc < 4)
        goto cleanup;

    DWORD LastError;
    BOOL RebootRequired = FALSE;
    WINTUN_ADAPTER *Adapter = AdapterOpenFromDevInstanceId(Argv[2], Argv[3]);
    if (!Adapter)
    {
        LastError = GetLastError();
        goto write;
    }
    BOOL ForceCloseSessions = wcstoul(Argv[4], NULL, 10);
    LastError = WintunDeleteAdapter(Adapter, ForceCloseSessions, &RebootRequired) ? ERROR_SUCCESS : GetLastError();
    WintunFreeAdapter(Adapter);
write:
    WriteFormatted(STD_OUTPUT_HANDLE, L"%1!X! %2!X!", LastError, RebootRequired);

cleanup:
    LocalFree(Argv);
}

VOID __stdcall DeletePoolDriver(HWND hwnd, HINSTANCE hinst, LPSTR lpszCmdLine, int nCmdShow)
{
#    pragma EXPORT

    int Argc;
    LPWSTR *Argv = CommandLineToArgvW(GetCommandLineW(), &Argc);
    WintunSetLogger(ConsoleLogger);

    if (Argc < 2)
        goto cleanup;

    BOOL RebootRequired;
    DWORD LastError = WintunDeletePoolDriver(Argv[2], &RebootRequired) ? ERROR_SUCCESS : GetLastError();
    WriteFormatted(STD_OUTPUT_HANDLE, L"%1!X! %2!X!", LastError, RebootRequired);

cleanup:
    LocalFree(Argv);
}
#endif

#ifdef MAYBE_WOW64

_Return_type_success_(return != FALSE)
static BOOL
AppendToBuffer(_Inout_ LPWSTR *Buffer, _In_ CONST WCHAR Addition, _Inout_ SIZE_T *BufferPos, _Inout_ SIZE_T *BufferLen)
{
    SIZE_T NewPos;
    if (FAILED(SIZETAdd(*BufferPos, sizeof(Addition), &NewPos)))
        return FALSE;
    if (NewPos >= *BufferLen)
    {
        SIZE_T NewLen;
        if (FAILED(SIZETMult(NewPos, 3, &NewLen)))
            return FALSE;
        LPWSTR NewBuffer = ReZalloc(*Buffer, NewLen);
        if (!NewBuffer)
            return FALSE;
        *Buffer = NewBuffer;
        *BufferLen = NewLen;
    }
    SIZE_T NewIndex = *BufferPos / sizeof(**Buffer);
    if (*Buffer + NewIndex < *Buffer)
        return FALSE;
    (*Buffer)[NewIndex] = Addition;
    *BufferPos = NewPos;
    return TRUE;
}

_Must_inspect_result_
static _Return_type_success_(return != NULL)
_Post_maybenull_
LPWSTR
ArgvToCommandLineW(_In_ SIZE_T ArgCount, ...)
{
    LPWSTR Output = NULL;
    SIZE_T BufferPos = 0, BufferLen = 0;
#    define Append(Char) \
        do \
        { \
            if (!AppendToBuffer(&Output, Char, &BufferPos, &BufferLen)) \
                goto cleanupBuffer; \
        } while (0)

    va_list Args;
    va_start(Args, ArgCount);
    for (SIZE_T i = 0; i < ArgCount; ++i)
    {
        LPCWSTR Arg = va_arg(Args, LPCWSTR);
        SIZE_T ArgLen = wcslen(Arg);
        if (ArgLen >= DWORD_MAX >> 3)
            goto cleanupBuffer;
        if (i)
            Append(L' ');
        Append(L'"');
        for (SIZE_T j = 0;; ++j)
        {
            SIZE_T NumberBackslashes = 0;

            while (j < ArgLen && Arg[j] == L'\\')
            {
                ++j;
                ++NumberBackslashes;
            }
            if (j >= ArgLen)
            {
                for (SIZE_T k = 0; k < NumberBackslashes * 2; ++k)
                    Append(L'\\');
                break;
            }
            else if (Arg[j] == L'"')
            {
                for (SIZE_T k = 0; k < NumberBackslashes * 2 + 1; ++k)
                    Append(L'\\');
                Append(Arg[j]);
            }
            else
            {
                for (SIZE_T k = 0; k < NumberBackslashes; ++k)
                    Append(L'\\');
                Append(Arg[j]);
            }
        }
        Append(L'"');
    }
    va_end(Args);
    return Output;

cleanupBuffer:
    Free(Output);
    return NULL;
#    undef Append
}

typedef struct _PROCESS_STDOUT_STATE
{
    HANDLE Stdout;
    LPWSTR Response;
    DWORD ResponseCapacity;
} PROCESS_STDOUT_STATE;

_Return_type_success_(return != ERROR_SUCCESS)
static DWORD WINAPI
ProcessStdout(_Inout_ PROCESS_STDOUT_STATE *State)
{
    for (DWORD Offset = 0, MaxLen = State->ResponseCapacity - 1; Offset < MaxLen;)
    {
        DWORD Size;
        if (FAILED(DWordMult(MaxLen - Offset, sizeof(WCHAR), &Size)))
            return ERROR_BUFFER_OVERFLOW;
        if (!ReadFile(State->Stdout, State->Response + Offset, Size, &Size, NULL))
            return ERROR_SUCCESS;
        if (Size % sizeof(WCHAR))
            return ERROR_INVALID_DATA;
        Offset += Size / sizeof(WCHAR);
        State->Response[Offset] = 0;
    }
    return ERROR_BUFFER_OVERFLOW;
}

static DWORD WINAPI
ProcessStderr(_In_ HANDLE Stderr)
{
    enum
    {
        OnNone,
        OnLevelStart,
        OnLevel,
        OnLevelEnd,
        OnSpace,
        OnMsg
    } State = OnNone;
    WCHAR Msg[0x200];
    DWORD Count = 0;
    WINTUN_LOGGER_LEVEL Level = WINTUN_LOG_INFO;
    for (;;)
    {
        WCHAR Buf[0x200];
        DWORD SizeRead;
        if (!ReadFile(Stderr, Buf, sizeof(Buf), &SizeRead, NULL))
            return ERROR_SUCCESS;
        if (SizeRead % sizeof(*Buf))
            return ERROR_INVALID_DATA;
        SizeRead /= sizeof(*Buf);
        for (DWORD i = 0; i < SizeRead; ++i)
        {
            WCHAR c = Buf[i];
            if (State == OnNone && c == L'[')
                State = OnLevelStart;
            else if (
                State == OnLevelStart && ((Level = WINTUN_LOG_INFO, c == L'+') ||
                                          (Level = WINTUN_LOG_WARN, c == L'-') || (Level = WINTUN_LOG_ERR, c == L'!')))
                State = OnLevelEnd;
            else if (State == OnLevelEnd && c == L']')
                State = OnSpace;
            else if (State == OnSpace && !iswspace(c) || State == OnMsg && c != L'\r' && c != L'\n')
            {
                if (Count < _countof(Msg) - 1)
                    Msg[Count++] = c;
                State = OnMsg;
            }
            else if (State == OnMsg && c == L'\n')
            {
                Msg[Count] = 0;
                LoggerLog(Level, NULL, Msg);
                State = OnNone;
                Count = 0;
            }
        }
    }
}

static _Return_type_success_(return != FALSE)
BOOL
ExecuteRunDll32(
    _In_z_ LPCWSTR Function,
    _In_z_ LPCWSTR Arguments,
    _Out_z_cap_c_(ResponseCapacity) LPWSTR Response,
    _In_ DWORD ResponseCapacity)
{
    WCHAR WindowsDirectory[MAX_PATH];
    if (!GetWindowsDirectoryW(WindowsDirectory, _countof(WindowsDirectory)))
    {
        LOG_LAST_ERROR(L"Failed to get Windows folder");
        return FALSE;
    }
    WCHAR RunDll32Path[MAX_PATH];
    if (!PathCombineW(RunDll32Path, WindowsDirectory, L"Sysnative\\rundll32.exe"))
    {
        SetLastError(ERROR_BUFFER_OVERFLOW);
        return FALSE;
    }

    DWORD LastError;
    WCHAR RandomTempSubDirectory[MAX_PATH];
    if (!ResourceCreateTemporaryDirectory(RandomTempSubDirectory))
    {
        LOG(WINTUN_LOG_ERR, L"Failed to create temporary folder");
        return FALSE;
    }
    WCHAR DllPath[MAX_PATH] = { 0 };
    if (!PathCombineW(DllPath, RandomTempSubDirectory, L"wintun.dll"))
    {
        LastError = ERROR_BUFFER_OVERFLOW;
        goto cleanupDirectory;
    }
    LPCWSTR WintunDllResourceName;
    switch (NativeMachine)
    {
    case IMAGE_FILE_MACHINE_AMD64:
        WintunDllResourceName = L"wintun-amd64.dll";
        break;
    case IMAGE_FILE_MACHINE_ARM64:
        WintunDllResourceName = L"wintun-arm64.dll";
        break;
    default:
        LOG(WINTUN_LOG_ERR, L"Unsupported platform 0x%x", NativeMachine);
        LastError = ERROR_NOT_SUPPORTED;
        goto cleanupDirectory;
    }
    if (!ResourceCopyToFile(DllPath, WintunDllResourceName))
    {
        LastError = LOG(WINTUN_LOG_ERR, L"Failed to copy resource %s to %s", WintunDllResourceName, DllPath);
        goto cleanupDelete;
    }
    size_t CommandLineLen = 10 + MAX_PATH + 2 + wcslen(Arguments) + 1 + wcslen(Function) + 1;
    LPWSTR CommandLine = AllocArray(CommandLineLen, sizeof(*CommandLine));
    if (!CommandLine)
    {
        LastError = GetLastError();
        goto cleanupDelete;
    }
    if (_snwprintf_s(
            CommandLine,
            CommandLineLen,
            _TRUNCATE,
            L"rundll32 \"%.*s\",%s %s",
            MAX_PATH,
            DllPath,
            Function,
            Arguments) == -1)
    {
        LOG(WINTUN_LOG_ERR, L"Command line too long");
        LastError = ERROR_INVALID_PARAMETER;
        goto cleanupDelete;
    }
    HANDLE StreamRStdout = INVALID_HANDLE_VALUE, StreamRStderr = INVALID_HANDLE_VALUE,
           StreamWStdout = INVALID_HANDLE_VALUE, StreamWStderr = INVALID_HANDLE_VALUE;
    if (!CreatePipe(&StreamRStdout, &StreamWStdout, &SecurityAttributes, 0) ||
        !CreatePipe(&StreamRStderr, &StreamWStderr, &SecurityAttributes, 0))
    {
        LastError = LOG_LAST_ERROR(L"Failed to create pipes");
        goto cleanupPipes;
    }
    if (!SetHandleInformation(StreamWStdout, HANDLE_FLAG_INHERIT, HANDLE_FLAG_INHERIT) ||
        !SetHandleInformation(StreamWStderr, HANDLE_FLAG_INHERIT, HANDLE_FLAG_INHERIT))
    {
        LastError = LOG_LAST_ERROR(L"Failed to set handle info");
        goto cleanupPipes;
    }
    if (ResponseCapacity)
        Response[0] = 0;
    PROCESS_STDOUT_STATE ProcessStdoutState = { .Stdout = StreamRStdout,
                                                .Response = Response,
                                                .ResponseCapacity = ResponseCapacity };
    HANDLE ThreadStdout = NULL, ThreadStderr = NULL;
    if ((ThreadStdout = CreateThread(NULL, 0, ProcessStdout, &ProcessStdoutState, 0, NULL)) == NULL ||
        (ThreadStderr = CreateThread(NULL, 0, ProcessStderr, StreamRStderr, 0, NULL)) == NULL)
    {
        LastError = LOG_LAST_ERROR(L"Failed to spawn readers");
        goto cleanupThreads;
    }
    STARTUPINFOW si = { .cb = sizeof(STARTUPINFO),
                        .dwFlags = STARTF_USESHOWWINDOW | STARTF_USESTDHANDLES,
                        .wShowWindow = SW_HIDE,
                        .hStdOutput = StreamWStdout,
                        .hStdError = StreamWStderr };
    PROCESS_INFORMATION pi;
    if (!CreateProcessW(RunDll32Path, CommandLine, NULL, NULL, TRUE, 0, NULL, NULL, &si, &pi))
    {
        LastError = LOG_LAST_ERROR(L"Failed to create process: %s", CommandLine);
        goto cleanupThreads;
    }
    LastError = ERROR_SUCCESS;
    WaitForSingleObject(pi.hProcess, INFINITE);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
cleanupThreads:
    if (ThreadStderr)
    {
        CloseHandle(StreamWStderr);
        StreamWStderr = INVALID_HANDLE_VALUE;
        WaitForSingleObject(ThreadStderr, INFINITE);
        CloseHandle(ThreadStderr);
    }
    if (ThreadStdout)
    {
        CloseHandle(StreamWStdout);
        StreamWStdout = INVALID_HANDLE_VALUE;
        WaitForSingleObject(ThreadStdout, INFINITE);
        DWORD ThreadResult;
        if (!GetExitCodeThread(ThreadStdout, &ThreadResult))
            LOG_LAST_ERROR(L"Failed to retrieve stdout reader result");
        else if (ThreadResult != ERROR_SUCCESS)
            LOG_ERROR(LastError, L"Failed to read process output");
        CloseHandle(ThreadStdout);
    }
cleanupPipes:
    CloseHandle(StreamRStderr);
    CloseHandle(StreamWStderr);
    CloseHandle(StreamRStdout);
    CloseHandle(StreamWStdout);
    Free(CommandLine);
cleanupDelete:
    DeleteFileW(DllPath);
cleanupDirectory:
    RemoveDirectoryW(RandomTempSubDirectory);
    return RET_ERROR(TRUE, LastError);
}

_Use_decl_annotations_
WINTUN_ADAPTER *
CreateAdapterViaRundll32(LPCWSTR Pool, LPCWSTR Name, const GUID *RequestedGUID, BOOL *RebootRequired)
{
    LOG(WINTUN_LOG_INFO, L"Spawning native process");
    LPWSTR Arguments = NULL;
    if (RequestedGUID)
    {
        WCHAR RequestedGUIDStr[MAX_GUID_STRING_LEN];
        if (StringFromGUID2(RequestedGUID, RequestedGUIDStr, _countof(RequestedGUIDStr)))
            Arguments = ArgvToCommandLineW(3, Pool, Name, RequestedGUIDStr);
    }
    else
        Arguments = ArgvToCommandLineW(2, Pool, Name);
    if (!Arguments)
    {
        LOG(WINTUN_LOG_ERR, L"Command line too long");
        SetLastError(ERROR_INVALID_PARAMETER);
        return NULL;
    }
    WINTUN_ADAPTER *Adapter = NULL;
    DWORD LastError;
    WCHAR Response[8 + 1 + MAX_GUID_STRING_LEN + 1 + 8 + 1];
    if (!ExecuteRunDll32(L"CreateAdapter", Arguments, Response, _countof(Response)))
    {
        LastError = GetLastError();
        LOG(WINTUN_LOG_ERR, L"Error executing worker process: %s", Arguments);
        goto cleanupArguments;
    }
    int Argc;
    LPWSTR *Argv = CommandLineToArgvW(Response, &Argc);
    if (Argc < 3)
    {
        LOG(WINTUN_LOG_ERR, L"Incomplete response: %s", Response);
        LastError = ERROR_INVALID_PARAMETER;
        goto cleanupArgv;
    }
    LastError = wcstoul(Argv[0], NULL, 16);
    if (LastError == ERROR_SUCCESS && (Adapter = AdapterOpenFromDevInstanceId(Pool, Argv[1])) == NULL)
    {
        LOG(WINTUN_LOG_ERR, L"Failed to get adapter %s", Argv[1]);
        LastError = ERROR_FILE_NOT_FOUND;
    }
    if (wcstoul(Argv[2], NULL, 16))
        *RebootRequired = TRUE;
cleanupArgv:
    LocalFree(Argv);
cleanupArguments:
    Free(Arguments);
    SetLastError(LastError);
    return Adapter;
}

_Use_decl_annotations_
BOOL
DeleteAdapterViaRundll32(const WINTUN_ADAPTER *Adapter, BOOL ForceCloseSessions, BOOL *RebootRequired)
{
    LOG(WINTUN_LOG_INFO, L"Spawning native process");
    LPWSTR Arguments = ArgvToCommandLineW(3, Adapter->Pool, Adapter->DevInstanceID, ForceCloseSessions ? L"1" : L"0");
    if (!Arguments)
    {
        LOG(WINTUN_LOG_ERR, L"Command line too long");
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }
    WCHAR Response[8 + 1 + 8 + 1];
    DWORD LastError;
    if (!ExecuteRunDll32(L"DeleteAdapter", Arguments, Response, _countof(Response)))
    {
        LastError = GetLastError();
        LOG(WINTUN_LOG_ERR, L"Error executing worker process: %s", Arguments);
        goto cleanupArguments;
    }
    int Argc;
    LPWSTR *Argv = CommandLineToArgvW(Response, &Argc);
    if (Argc < 2)
    {
        LOG(WINTUN_LOG_ERR, L"Incomplete response: %s", Response);
        LastError = ERROR_INVALID_PARAMETER;
        goto cleanupArgv;
    }
    LastError = wcstoul(Argv[0], NULL, 16);
    if (wcstoul(Argv[1], NULL, 16))
        *RebootRequired = TRUE;
cleanupArgv:
    LocalFree(Argv);
cleanupArguments:
    Free(Arguments);
    return RET_ERROR(TRUE, LastError);
}

_Use_decl_annotations_
BOOL
DeletePoolDriverViaRundll32(LPCWSTR Pool, BOOL *RebootRequired)
{
    LOG(WINTUN_LOG_INFO, L"Spawning native process");
    LPWSTR Arguments = ArgvToCommandLineW(1, Pool);
    if (!Arguments)
    {
        LOG(WINTUN_LOG_ERR, L"Command line too long");
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }
    WCHAR Response[8 + 1 + 8 + 1];
    DWORD LastError;
    if (!ExecuteRunDll32(L"DeletePoolDriver", Arguments, Response, _countof(Response)))
    {
        LastError = GetLastError();
        LOG(WINTUN_LOG_ERR, L"Error executing worker process: %s", Arguments);
        goto cleanupArguments;
    }
    int Argc;
    LPWSTR *Argv = CommandLineToArgvW(Response, &Argc);
    if (Argc < 2)
    {
        LOG(WINTUN_LOG_ERR, L"Incomplete response: %s", Response);
        LastError = ERROR_INVALID_PARAMETER;
        goto cleanupArgv;
    }
    LastError = wcstoul(Argv[0], NULL, 16);
    if (wcstoul(Argv[1], NULL, 16))
        *RebootRequired = TRUE;
cleanupArgv:
    LocalFree(Argv);
cleanupArguments:
    Free(Arguments);
    return RET_ERROR(TRUE, LastError);
}
#endif

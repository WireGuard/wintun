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
    WCHAR Msg[0x200], Buf[0x220], LevelRune;
    DWORD64 Timestamp;
    DWORD SizeRead;
    WINTUN_LOGGER_LEVEL Level;
    for (;;)
    {
        if (!ReadFile(Stderr, Buf, sizeof(Buf), &SizeRead, NULL) || !SizeRead)
            return ERROR_SUCCESS;
        if (SizeRead % sizeof(*Buf))
            return ERROR_INVALID_DATA;
        Msg[0] = Buf[SizeRead / sizeof(*Buf) - 1] = L'\0';
        if (swscanf_s(Buf, L"[%c %I64u] %[^\n]", &LevelRune, 1, &Timestamp, Msg, (DWORD)_countof(Msg)) != 3 || !Msg[0])
            return ERROR_INVALID_DATA;
        if (!((Level = WINTUN_LOG_INFO, LevelRune == L'+') || (Level = WINTUN_LOG_WARN, LevelRune == L'-') ||
              (Level = WINTUN_LOG_ERR, LevelRune == L'!')))
            return ERROR_INVALID_DATA;
        Logger(Level, Timestamp, Msg);
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
    if (!PathCombineW(DllPath, RandomTempSubDirectory, L"setupapihost.dll"))
    {
        LastError = ERROR_BUFFER_OVERFLOW;
        goto cleanupDirectory;
    }
    LPCWSTR WintunDllResourceName;
    switch (NativeMachine)
    {
    case IMAGE_FILE_MACHINE_AMD64:
        WintunDllResourceName = L"setupapihost-amd64.dll";
        break;
    case IMAGE_FILE_MACHINE_ARM64:
        WintunDllResourceName = L"setupapihost-arm64.dll";
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
            LastError = LOG_LAST_ERROR(L"Failed to retrieve stdout reader result");
        else if (ThreadResult != ERROR_SUCCESS)
            LastError = LOG_ERROR(ThreadResult, L"Failed to read process output");
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

static _Return_type_success_(return != FALSE)
BOOL
InvokeClassInstaller(_In_ LPCWSTR Action, _In_ LPCWSTR Function, _In_ HDEVINFO DevInfo, _In_ SP_DEVINFO_DATA *DevInfoData)
{
    LOG(WINTUN_LOG_INFO, L"Spawning native process to %s instance", Action);

    WCHAR InstanceId[MAX_DEVICE_ID_LEN];
    DWORD RequiredChars = _countof(InstanceId);
    if (!SetupDiGetDeviceInstanceIdW(DevInfo, DevInfoData, InstanceId, RequiredChars, &RequiredChars))
    {
        LOG_LAST_ERROR(L"Failed to get adapter instance ID");
        return FALSE;
    }
    LPWSTR Arguments = ArgvToCommandLineW(1, InstanceId);
    if (!Arguments)
    {
        SetLastError(LOG_ERROR(ERROR_INVALID_PARAMETER, L"Command line too long"));
        return FALSE;
    }
    DWORD LastError;
    WCHAR Response[8 + 1];
    if (!ExecuteRunDll32(Function, Arguments, Response, _countof(Response)))
    {
        LastError = LOG_LAST_ERROR(L"Error executing worker process: %s", Arguments);
        goto cleanupArguments;
    }
    int Argc;
    LPWSTR *Argv = CommandLineToArgvW(Response, &Argc);
    if (Argc < 1)
    {
        LastError = LOG_ERROR(ERROR_INVALID_PARAMETER, L"Incomplete response: %s", Response);
        goto cleanupArgv;
    }
    LastError = wcstoul(Argv[0], NULL, 16);
cleanupArgv:
    LocalFree(Argv);
cleanupArguments:
    Free(Arguments);
    return RET_ERROR(TRUE, LastError);
}

_Use_decl_annotations_
BOOL
RemoveInstanceViaRundll32(HDEVINFO DevInfo, SP_DEVINFO_DATA *DevInfoData)
{
    return InvokeClassInstaller(L"remove", L"RemoveInstance", DevInfo, DevInfoData);
}

_Use_decl_annotations_
BOOL
EnableInstanceViaRundll32(HDEVINFO DevInfo, SP_DEVINFO_DATA *DevInfoData)
{
    return InvokeClassInstaller(L"enable", L"EnableInstance", DevInfo, DevInfoData);
}

_Use_decl_annotations_
BOOL
DisableInstanceViaRundll32(HDEVINFO DevInfo, SP_DEVINFO_DATA *DevInfoData)
{
    return InvokeClassInstaller(L"disable", L"DisableInstance", DevInfo, DevInfoData);
}

_Use_decl_annotations_
BOOL
CreateInstanceWin7ViaRundll32(LPWSTR InstanceId)
{
    LOG(WINTUN_LOG_INFO, L"Spawning native process to create instance");

    DWORD LastError;
    WCHAR Response[MAX_DEVICE_ID_LEN + 1];
    if (!ExecuteRunDll32(L"CreateInstanceWin7", L"", Response, _countof(Response)))
    {
        LastError = LOG_LAST_ERROR(L"Error executing worker process");
        goto cleanup;
    }
    int Argc;
    LPWSTR *Argv = CommandLineToArgvW(Response, &Argc);
    if (Argc < 2)
    {
        LastError = LOG_ERROR(ERROR_INVALID_PARAMETER, L"Incomplete response: %s", Response);
        goto cleanupArgv;
    }
    LastError = wcstoul(Argv[0], NULL, 16);
    if (LastError == ERROR_SUCCESS)
        wcsncpy_s(InstanceId, MAX_DEVICE_ID_LEN, Argv[1], _TRUNCATE);
cleanupArgv:
    LocalFree(Argv);
cleanup:
    return RET_ERROR(TRUE, LastError);
}
#endif

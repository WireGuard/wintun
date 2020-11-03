/* SPDX-License-Identifier: GPL-2.0
 *
 * Copyright (C) 2018-2020 WireGuard LLC. All Rights Reserved.
 */

/* TODO: This is currently #include'd in adapter.c. Move into rundll32.c properly. */

typedef struct _PROCESS_STDOUT_STATE
{
    HANDLE Stdout;
    WCHAR *Response;
    DWORD ResponseCapacity;
} PROCESS_STDOUT_STATE;

static DWORD WINAPI
ProcessStdout(_Inout_ PROCESS_STDOUT_STATE *State)
{
    for (DWORD Offset = 0, MaxLen = State->ResponseCapacity - 1; Offset < MaxLen;)
    {
        DWORD SizeRead;
        if (!ReadFile(State->Stdout, State->Response + Offset, sizeof(WCHAR) * (MaxLen - Offset), &SizeRead, NULL))
            return ERROR_SUCCESS;
        if (SizeRead % sizeof(WCHAR))
            return ERROR_INVALID_DATA;
        Offset += SizeRead / sizeof(WCHAR);
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
        if (SizeRead % sizeof(WCHAR))
            return ERROR_INVALID_DATA;
        SizeRead /= sizeof(WCHAR);
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
                Logger(Level, Msg);
                State = OnNone;
                Count = 0;
            }
        }
    }
}

static WINTUN_STATUS
ExecuteRunDll32(
    _In_z_ const WCHAR *Arguments,
    _Out_z_cap_c_(ResponseCapacity) WCHAR *Response,
    _In_ DWORD ResponseCapacity)
{
    WCHAR WindowsDirectory[MAX_PATH];
    if (!GetWindowsDirectoryW(WindowsDirectory, _countof(WindowsDirectory)))
        return LOG_LAST_ERROR(L"Failed to get Windows folder");
    WCHAR RunDll32Path[MAX_PATH];
    if (!PathCombineW(RunDll32Path, WindowsDirectory, L"Sysnative\\rundll32.exe"))
        return ERROR_BUFFER_OVERFLOW;

    DWORD Result;
    WCHAR RandomTempSubDirectory[MAX_PATH];
    if ((Result = CreateTemporaryDirectory(RandomTempSubDirectory)) != ERROR_SUCCESS)
        return LOG(WINTUN_LOG_ERR, L"Failed to create temporary folder"), Result;
    WCHAR DllPath[MAX_PATH] = { 0 };
    if (!PathCombineW(DllPath, RandomTempSubDirectory, L"wintun.dll"))
    {
        Result = ERROR_BUFFER_OVERFLOW;
        goto cleanupDirectory;
    }
    const WCHAR *WintunDllResourceName;
    switch (NativeMachine)
    {
    case IMAGE_FILE_MACHINE_AMD64:
        WintunDllResourceName = L"wintun-amd64.dll";
        break;
    case IMAGE_FILE_MACHINE_ARM64:
        WintunDllResourceName = L"wintun-arm64.dll";
        break;
    default:
        LOG(WINTUN_LOG_ERR, L"Unsupported platform");
        Result = ERROR_NOT_SUPPORTED;
        goto cleanupDirectory;
    }
    if ((Result = ResourceCopyToFile(DllPath, WintunDllResourceName)) != ERROR_SUCCESS)
    {
        LOG(WINTUN_LOG_ERR, L"Failed to copy resource");
        goto cleanupDelete;
    }
    size_t CommandLineLen = 10 + MAX_PATH + 2 + wcslen(Arguments) + 1;
    WCHAR *CommandLine = HeapAlloc(ModuleHeap, 0, CommandLineLen * sizeof(WCHAR));
    if (!CommandLine)
    {
        LOG(WINTUN_LOG_ERR, L"Out of memory");
        Result = ERROR_OUTOFMEMORY;
        goto cleanupDelete;
    }
    if (_snwprintf_s(CommandLine, CommandLineLen, _TRUNCATE, L"rundll32 \"%.*s\",%s", MAX_PATH, DllPath, Arguments) ==
        -1)
    {
        LOG(WINTUN_LOG_ERR, L"Command line too long");
        Result = ERROR_INVALID_PARAMETER;
        goto cleanupDelete;
    }
    HANDLE StreamRStdout = INVALID_HANDLE_VALUE, StreamRStderr = INVALID_HANDLE_VALUE,
           StreamWStdout = INVALID_HANDLE_VALUE, StreamWStderr = INVALID_HANDLE_VALUE;
    if (!CreatePipe(&StreamRStdout, &StreamWStdout, &SecurityAttributes, 0) ||
        !CreatePipe(&StreamRStderr, &StreamWStderr, &SecurityAttributes, 0))
    {
        Result = LOG_LAST_ERROR(L"Failed to create pipes");
        goto cleanupPipes;
    }
    if (!SetHandleInformation(StreamWStdout, HANDLE_FLAG_INHERIT, HANDLE_FLAG_INHERIT) ||
        !SetHandleInformation(StreamWStderr, HANDLE_FLAG_INHERIT, HANDLE_FLAG_INHERIT))
    {
        Result = LOG_LAST_ERROR(L"Failed to set handle info");
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
        Result = LOG_LAST_ERROR(L"Failed to spawn readers");
        goto cleanupThreads;
    }
    STARTUPINFOW si = { .cb = sizeof(STARTUPINFO),
                        .dwFlags = STARTF_USESHOWWINDOW | STARTF_USESTDHANDLES,
                        .wShowWindow = SW_HIDE,
                        .hStdOutput = StreamWStdout,
                        .hStdError = StreamWStderr };
    PROCESS_INFORMATION pi;
    HANDLE ProcessToken = GetPrimarySystemTokenFromThread();
    if (!ProcessToken)
    {
        Result = LOG_LAST_ERROR(L"Failed to get primary system token from thread");
        goto cleanupThreads;
    }
    if (!CreateProcessAsUserW(ProcessToken, RunDll32Path, CommandLine, NULL, NULL, TRUE, 0, NULL, NULL, &si, &pi))
    {
        Result = LOG_LAST_ERROR(L"Failed to create process");
        goto cleanupToken;
    }
    WaitForSingleObject(pi.hProcess, INFINITE);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
cleanupToken:
    CloseHandle(ProcessToken);
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
        if (!GetExitCodeThread(ThreadStdout, &Result))
            Result = LOG_LAST_ERROR(L"Failed to retrieve stdout reader result");
        else if (Result != ERROR_SUCCESS)
            LOG_ERROR(L"Failed to read process output", Result);
        CloseHandle(ThreadStdout);
    }
cleanupPipes:
    CloseHandle(StreamRStderr);
    CloseHandle(StreamWStderr);
    CloseHandle(StreamRStdout);
    CloseHandle(StreamWStdout);
    HeapFree(ModuleHeap, 0, CommandLine);
cleanupDelete:
    DeleteFileW(DllPath);
cleanupDirectory:
    RemoveDirectoryW(RandomTempSubDirectory);
    return Result;
}

static WINTUN_STATUS
CreateAdapterViaRundll32(
    _In_z_ const WCHAR *Pool,
    _In_z_ const WCHAR *Name,
    _In_opt_ const GUID *RequestedGUID,
    _Out_ WINTUN_ADAPTER **Adapter,
    _Inout_ BOOL *RebootRequired)
{
    LOG(WINTUN_LOG_INFO, L"Spawning native process");
    WCHAR RequestedGUIDStr[MAX_GUID_STRING_LEN];
    WCHAR Arguments[15 + WINTUN_MAX_POOL + 3 + MAX_ADAPTER_NAME + 2 + MAX_GUID_STRING_LEN + 1];
    if (_snwprintf_s(
            Arguments,
            _countof(Arguments),
            _TRUNCATE,
            RequestedGUID ? L"CreateAdapter \"%s\" \"%s\" %.*s" : L"CreateAdapter \"%s\" \"%s\"",
            Pool,
            Name,
            RequestedGUID ? StringFromGUID2(RequestedGUID, RequestedGUIDStr, _countof(RequestedGUIDStr)) : 0,
            RequestedGUIDStr) == -1)
        return LOG(WINTUN_LOG_ERR, L"Command line too long"), ERROR_INVALID_PARAMETER;
    WCHAR Response[8 + 1 + MAX_GUID_STRING_LEN + 1 + 8 + 1];
    DWORD Result = ExecuteRunDll32(Arguments, Response, _countof(Response));
    if (Result != ERROR_SUCCESS)
    {
        LOG(WINTUN_LOG_ERR, L"Error executing worker process");
        return Result;
    }
    int Argc;
    WCHAR **Argv = CommandLineToArgvW(Response, &Argc);
    GUID CfgInstanceID;
    if (Argc < 3 || FAILED(CLSIDFromString(Argv[1], &CfgInstanceID)))
    {
        LOG(WINTUN_LOG_ERR, L"Incomplete or invalid response");
        Result = ERROR_INVALID_PARAMETER;
        goto cleanupArgv;
    }
    Result = wcstoul(Argv[0], NULL, 16);
    if (Result == ERROR_SUCCESS && GetAdapter(Pool, &CfgInstanceID, Adapter) != ERROR_SUCCESS)
    {
        LOG(WINTUN_LOG_ERR, L"Failed to get adapter");
        Result = ERROR_FILE_NOT_FOUND;
    }
    if (wcstoul(Argv[2], NULL, 16))
        *RebootRequired = TRUE;
cleanupArgv:
    LocalFree(Argv);
    return Result;
}

static WINTUN_STATUS
DeleteAdapterViaRundll32(_In_ const WINTUN_ADAPTER *Adapter, _In_ BOOL ForceCloseSessions, _Inout_ BOOL *RebootRequired)
{
    LOG(WINTUN_LOG_INFO, L"Spawning native process");
    WCHAR GuidStr[MAX_GUID_STRING_LEN];
    WCHAR Arguments[16 + MAX_GUID_STRING_LEN + 1];
    if (_snwprintf_s(
            Arguments,
            _countof(Arguments),
            _TRUNCATE,
            L"DeleteAdapter %d %.*s",
            ForceCloseSessions ? 1 : 0,
            StringFromGUID2(&Adapter->CfgInstanceID, GuidStr, _countof(GuidStr)),
            GuidStr) == -1)
        return LOG(WINTUN_LOG_ERR, L"Command line too long"), ERROR_INVALID_PARAMETER;
    WCHAR Response[8 + 1 + 8 + 1];
    DWORD Result = ExecuteRunDll32(Arguments, Response, _countof(Response));
    if (Result != ERROR_SUCCESS)
    {
        LOG(WINTUN_LOG_ERR, L"Error executing worker process");
        return Result;
    }
    int Argc;
    WCHAR **Argv = CommandLineToArgvW(Response, &Argc);
    if (Argc < 2)
    {
        LOG(WINTUN_LOG_ERR, L"Incomplete or invalid response");
        Result = ERROR_INVALID_PARAMETER;
        goto cleanupArgv;
    }
    Result = wcstoul(Argv[0], NULL, 16);
    if (wcstoul(Argv[1], NULL, 16))
        *RebootRequired = TRUE;
cleanupArgv:
    LocalFree(Argv);
    return Result;
}

static WINTUN_STATUS
DeleteDriverViaRundll32()
{
    LOG(WINTUN_LOG_INFO, L"Spawning native process");
    WCHAR Response[8 + 1];
    DWORD Result = ExecuteRunDll32(L"DeleteDriver", Response, _countof(Response));
    if (Result != ERROR_SUCCESS)
    {
        LOG(WINTUN_LOG_ERR, L"Error executing worker process");
        return Result;
    }
    int Argc;
    WCHAR **Argv = CommandLineToArgvW(Response, &Argc);
    if (Argc < 1)
    {
        LOG(WINTUN_LOG_ERR, L"Incomplete or invalid response");
        Result = ERROR_INVALID_PARAMETER;
        goto cleanupArgv;
    }
    Result = wcstoul(Argv[0], NULL, 16);
cleanupArgv:
    LocalFree(Argv);
    return Result;
}
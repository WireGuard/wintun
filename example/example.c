/* SPDX-License-Identifier: GPL-2.0
 *
 * Copyright (C) 2018-2020 WireGuard LLC. All Rights Reserved.
 */

#include "../api/wintun.h"
#include <stdarg.h>
#include <stdio.h>

static WINTUN_GET_VERSION_FUNC WintunGetVersion;
static WINTUN_SET_LOGGER_FUNC WintunSetLogger;
static WINTUN_CREATE_ADAPTER_FUNC WintunCreateAdapter;
static WINTUN_DELETE_ADAPTER_FUNC WintunDeleteAdapter;
static WINTUN_START_SESSION_FUNC WintunStartSession;
static WINTUN_END_SESSION_FUNC WintunEndSession;
static WINTUN_RECEIVE_PACKET_FUNC WintunReceivePacket;
static WINTUN_RECEIVE_RELEASE_FUNC WintunReceiveRelease;
static WINTUN_ALLOCATE_SEND_PACKET_FUNC WintunAllocateSendPacket;
static WINTUN_SEND_PACKET_FUNC WintunSendPacket;

static HANDLE QuitEvent;
static volatile BOOL HaveQuit;

static BOOL CALLBACK
ConsoleLogger(_In_ WINTUN_LOGGER_LEVEL Level, _In_z_ const WCHAR *LogLine)
{
    FILETIME Timestamp;
    GetSystemTimePreciseAsFileTime(&Timestamp);
    SYSTEMTIME SystemTime;
    FileTimeToSystemTime(&Timestamp, &SystemTime);
    WCHAR LevelMarker;
    switch (Level)
    {
    case WINTUN_LOG_INFO:
        LevelMarker = L'+';
        break;
    case WINTUN_LOG_WARN:
        LevelMarker = L'-';
        break;
    case WINTUN_LOG_ERR:
        LevelMarker = L'!';
        break;
    default:
        return FALSE;
    }
    fwprintf(
        stderr,
        L"%04d-%02d-%02d %02d:%02d:%02d.%04d [%c] %s\n",
        SystemTime.wYear,
        SystemTime.wMonth,
        SystemTime.wDay,
        SystemTime.wHour,
        SystemTime.wMinute,
        SystemTime.wSecond,
        SystemTime.wMilliseconds,
        LevelMarker,
        LogLine);
    return TRUE;
}

static DWORD
LogLastError(_In_z_ const WCHAR *Prefix)
{
    DWORD Error = GetLastError();
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
        SystemMessage ? L"%1: %3(Code 0x%2!08X!)" : L"%1: Code 0x%2!08X!",
        0,
        0,
        (void *)&FormattedMessage,
        0,
        (va_list *)(DWORD_PTR[]){ (DWORD_PTR)Prefix, (DWORD_PTR)Error, (DWORD_PTR)SystemMessage });
    if (FormattedMessage)
        ConsoleLogger(WINTUN_LOG_ERR, FormattedMessage);
    LocalFree(FormattedMessage);
    LocalFree(SystemMessage);
    SetLastError(Error);
    return Error;
}

static void
Log(_In_ WINTUN_LOGGER_LEVEL Level, _In_z_ const WCHAR *Format, ...)
{
    WCHAR LogLine[0x200];
    va_list args;
    va_start(args, Format);
    _vsnwprintf_s(LogLine, _countof(LogLine), _TRUNCATE, Format, args);
    va_end(args);
    ConsoleLogger(Level, LogLine);
}

static BOOL WINAPI
CtrlHandler(DWORD CtrlType)
{
    switch (CtrlType)
    {
    case CTRL_C_EVENT:
    case CTRL_BREAK_EVENT:
    case CTRL_CLOSE_EVENT:
    case CTRL_LOGOFF_EVENT:
    case CTRL_SHUTDOWN_EVENT:
        HaveQuit = TRUE;
        SetEvent(QuitEvent);
        return TRUE;
    }
    return FALSE;
}

static DWORD WINAPI
TestAdapter(_Inout_ DWORD_PTR Index)
{
    /* Create adapter. */
    WCHAR AdapterName[MAX_ADAPTER_NAME];
    _snwprintf_s(
        AdapterName,
        _countof(AdapterName),
        _TRUNCATE,
        L"test-%d.%d-%zu",
        WINTUN_VERSION_MAJ,
        WINTUN_VERSION_MIN,
        Index);
    const GUID AdapterGuid = { 0xeef7ebf,
                               WINTUN_VERSION_MAJ,
                               WINTUN_VERSION_MIN,
                               { (BYTE)Index & 0xff, 0xa, 0x33, 0xbf, 0x5c, 0x8, 0x4a, 0xc6 } };
    while (!HaveQuit)
    {
        WINTUN_ADAPTER_HANDLE Adapter;
        BOOL RebootRequired = FALSE;
        DWORD Result = WintunCreateAdapter(L"Example", AdapterName, &AdapterGuid, &Adapter, &RebootRequired);
        if (Result != ERROR_SUCCESS)
        {
            Log(WINTUN_LOG_ERR, L"%s adapter creation failed.\n", AdapterName);
            return Result;
        }

        DWORDLONG WintunVersion = WintunGetVersion();
        Log(WINTUN_LOG_INFO,
            L"%s adapter created (Wintun %d.%d.%d.%d, reboot: %d).\n",
            AdapterName,
            (WintunVersion >> 48) & 0xffff,
            (WintunVersion >> 32) & 0xffff,
            (WintunVersion >> 16) & 0xffff,
            (WintunVersion >> 0) & 0xffff,
            RebootRequired ? 1 : 0);

        WINTUN_SESSION_HANDLE Session;
        HANDLE WaitHandles[2] = { NULL, QuitEvent };
        Result = WintunStartSession(Adapter, 0x100000, &Session, &WaitHandles[0]);
        if (Result != ERROR_SUCCESS)
        {
            Log(WINTUN_LOG_ERR, L"%s session creation failed.\n", AdapterName);
            goto cleanupAdapter;
        }
        while (!HaveQuit)
        {
            BYTE *Packet;
            DWORD PacketSize;
            Result = WintunReceivePacket(Session, &Packet, &PacketSize);
            switch (Result)
            {
            case ERROR_SUCCESS:
                // TODO: Process packet.
                WintunReceiveRelease(Session, Packet);
                continue;
            case ERROR_NO_MORE_ITEMS:
                if (WaitForMultipleObjects(_countof(WaitHandles), WaitHandles, FALSE, INFINITE) == WAIT_OBJECT_0)
                    continue;
                goto cleanupSession;
            }
            Log(WINTUN_LOG_ERR, L"%s packet read failed (Code 0x%08X).\n", AdapterName, Result);
            goto cleanupSession;
        }
    cleanupSession:
        WintunEndSession(Session);
    cleanupAdapter:
        WintunDeleteAdapter(Adapter, TRUE, &RebootRequired);
    }
    return ERROR_SUCCESS;
}

int
main(void)
{
    Log(WINTUN_LOG_INFO, L"Wintun Test v%d.%d\n", WINTUN_VERSION_MAJ, WINTUN_VERSION_MIN);

    HMODULE Wintun =
        LoadLibraryExW(L"wintun.dll", NULL, LOAD_LIBRARY_SEARCH_APPLICATION_DIR | LOAD_LIBRARY_SEARCH_SYSTEM32);
    if (!Wintun)
        return LogLastError(L"Failed to load wintun.dll");
    DWORD Result;
    if ((WintunGetVersion = (WINTUN_GET_VERSION_FUNC)GetProcAddress(Wintun, "WintunGetVersion")) == NULL ||
        (WintunSetLogger = (WINTUN_SET_LOGGER_FUNC)GetProcAddress(Wintun, "WintunSetLogger")) == NULL ||
        (WintunCreateAdapter = (WINTUN_CREATE_ADAPTER_FUNC)GetProcAddress(Wintun, "WintunCreateAdapter")) == NULL ||
        (WintunDeleteAdapter = (WINTUN_DELETE_ADAPTER_FUNC)GetProcAddress(Wintun, "WintunDeleteAdapter")) == NULL ||
        (WintunStartSession = (WINTUN_START_SESSION_FUNC)GetProcAddress(Wintun, "WintunStartSession")) == NULL ||
        (WintunEndSession = (WINTUN_END_SESSION_FUNC)GetProcAddress(Wintun, "WintunEndSession")) == NULL ||
        (WintunReceivePacket = (WINTUN_RECEIVE_PACKET_FUNC)GetProcAddress(Wintun, "WintunReceivePacket")) == NULL ||
        (WintunReceiveRelease = (WINTUN_RECEIVE_RELEASE_FUNC)GetProcAddress(Wintun, "WintunReceiveRelease")) == NULL ||
        (WintunAllocateSendPacket =
             (WINTUN_ALLOCATE_SEND_PACKET_FUNC)GetProcAddress(Wintun, "WintunAllocateSendPacket")) == NULL ||
        (WintunSendPacket = (WINTUN_SEND_PACKET_FUNC)GetProcAddress(Wintun, "WintunSendPacket")) == NULL)
    {
        Result = LogLastError(L"Failed to get wintun.dll entries");
        goto cleanupWintun;
    }

    HaveQuit = FALSE;
    QuitEvent = CreateEventW(NULL, TRUE, FALSE, NULL);
    if (!QuitEvent)
    {
        Result = LogLastError(L"Failed to create event");
        goto cleanupWintun;
    }
    WintunSetLogger(ConsoleLogger);
    if (!SetConsoleCtrlHandler(CtrlHandler, TRUE))
    {
        Result = LogLastError(L"Failed to set console handler");
        goto cleanupQuit;
    }

    HANDLE Workers[MAXIMUM_WAIT_OBJECTS] = { 0 };
    for (size_t i = 0; i < _countof(Workers); ++i)
        if (!Workers[i])
        {
            Workers[i] = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)TestAdapter, (LPVOID)i, 0, NULL);
            if (!Workers[i])
            {
                Result = LogLastError(L"Failed to create thread");
                goto cleanupWorkers;
            }
        }
    WaitForMultipleObjectsEx(_countof(Workers), Workers, TRUE, INFINITE, TRUE);
    Result = ERROR_SUCCESS;
cleanupWorkers:
    HaveQuit = TRUE;
    SetEvent(QuitEvent);
    for (size_t i = 0; i < _countof(Workers); ++i)
        if (Workers[i])
        {
            WaitForSingleObject(Workers[i], INFINITE);
            CloseHandle(Workers[i]);
        }
    SetConsoleCtrlHandler(CtrlHandler, FALSE);
cleanupQuit:
    CloseHandle(QuitEvent);
cleanupWintun:
    FreeLibrary(Wintun);
    return Result;
}

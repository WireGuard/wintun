# [Wintun Network Adapter](https://www.wintun.net/)
### TUN Device Driver for Windows

This is a layer 3 TUN driver for Windows 7, 8, 8.1, and 10. Originally created for [WireGuard](https://www.wireguard.com/), it is intended to be useful to a wide variety of projects that require layer 3 tunneling devices with implementations primarily in userspace.

## Installation

Wintun is deployed as a platform-specific `wintun.dll` file. Install the `wintun.dll` file side-by-side with your application.

## Usage

Include `wintun.h` file in your project and dynamically load the `wintun.dll` using [`LoadLibraryEx()`](https://docs.microsoft.com/en-us/windows/win32/api/libloaderapi/nf-libloaderapi-loadlibraryexa) and [`GetProcAddress()`](https://docs.microsoft.com/en-us/windows/win32/api/libloaderapi/nf-libloaderapi-getprocaddress).

Each function has its function typedef in `wintun.h` with additional usage documentation.

```C
#include "wintun.h"
⋮
HMODULE Wintun = LoadLibraryExW(L"wintun.dll", NULL, LOAD_LIBRARY_SEARCH_APPLICATION_DIR);
if (!Wintun)
    return GetLastError();
WINTUN_CREATE_ADAPTER_FUNC WintunCreateAdapter = (WINTUN_CREATE_ADAPTER_FUNC)GetProcAddress(Wintun, "WintunCreateAdapter");
WINTUN_DELETE_ADAPTER_FUNC WintunDeleteAdapter = (WINTUN_DELETE_ADAPTER_FUNC)GetProcAddress(Wintun, "WintunDeleteAdapter");
```

### Adapter management

Adapters are grouped together in pools to allow various clients on the same machine. Each client vendor should pick own unique pool name.

Manage the network adapters using following functions:

- `WintunCreateAdapter()` creates a new adapter.
- `WintunDeleteAdapter()` deletes the adapter.
- `WintunEnumAdapters()` enumerates all existing adapters.
- `WintunGetAdapter()` gets existing adapter handle.
- `WintunFreeAdapter()` frees adapter handle.
- `WintunGetAdapterDeviceObject()` opens adapter device object.
- `WintunGetAdapterGUID()` gets adapter GUID.
- `WintunGetAdapterLUID()` gets adapter LUID.
- `WintunGetAdapterName()` gets adapter name.
- `WintunSetAdapterName()` sets adapter name.

Example:

```C
DWORD Result;
WINTUN_ADAPTER_HANDLE Adapter;
BOOL RebootRequired;
Result = WintunCreateAdapter(L"com.contoso.myapp", "My VPN adapter", NULL, &Adapter, &RebootRequired);
if (Result != ERROR_SUCCESS)
    return Result;
```

### Session management

Once adapter is created, use the following functions to start a session and transfer packets:

- `WintunStartSession()` starts a session. One adapter may have only one session.
- `WintunEndSession()` ends and frees the session.
- `WintunIsPacketAvailable()` checks if there is a receive packet available.
- `WintunReceivePacket()` receives one packet.
- `WintunReceiveRelease()` releases internal buffer after client processed the receive packet.
- `WintunAllocateSendPacket()` allocates memory for send packet.
- `WintunSendPacket()` sends the packet.

#### Writing to and from rings

Reading packets from the adapter may be done as:

```C
for (;;) {
    BYTE *Packet;
    DWORD PacketSize;
    DWORD Result = WintunReceivePacket(Session, &Packet, &PacketSize);
    switch (Result) {
    case ERROR_SUCCESS:
        // TODO: Process packet.
        WintunReceiveRelease(Session, Packet);
        break;
    case ERROR_NO_MORE_ITEMS:
        WintunWaitForPacket(Session, INFINITE);
        continue;
    }
    return Result;
}
```

It may be desirable to spin on `WintunReceivePacket()` while it returns `ERROR_NO_MORE_ITEMS` for some time under heavy use before waiting with `WintunWaitForPacket()`, in order to reduce latency.

Writing packets to the adapter may be done as:

```C
// TODO: Calculate packet size.
BYTE *Packet;
DWORD Result = WintunAllocateSendPacket(Session, PacketSize, &Packet);
if (Result != ERROR_SUCCESS)
    return Result;
// TODO: Fill the packet.
WintunSendPacket(Session, Packet);
```

### Misc functions

Other `wintun.dll` functions are:

- `WintunGetVersion()` returns driver and NDIS major and minor versions.
- `WintunSetLogger()` sets global logging callback function.

Example:

```C
static BOOL CALLBACK
ConsoleLogger(_In_ WINTUN_LOGGER_LEVEL Level, _In_z_ const WCHAR *LogLine)
{
    const WCHAR *Template;
    switch (Level)
    {
    case WINTUN_LOG_INFO: Template = L"[+] %s\n"; break;
    case WINTUN_LOG_WARN: Template = L"[-] %s\n"; break;
    case WINTUN_LOG_ERR:  Template = L"[!] %s\n"; break;
    default: return FALSE;
    }
    fwprintf(stderr, Template, LogLine);
    return TRUE;
}
⋮
WintunSetLogger(ConsoleLogger);
```

## Building

**Do not distribute drivers named "Wintun", as they will most certainly clash with official deployments. Instead distribute `wintun.dll`.**

General requirements:

- [Visual Studio 2019](https://visualstudio.microsoft.com/downloads/)
- [Windows Driver Kit for Windows 10, version 1903](https://docs.microsoft.com/en-us/windows-hardware/drivers/download-the-wdk)

`wintun.sln` may be opened in Visual Studio for development and building. Be sure to run `bcdedit /set testsigning on` before to enable unsigned driver loading. The default run sequence (F5) in Visual Studio will build and insert Wintun.

## License

The entire contents of this repository, including all documentation code, is "Copyright © 2018-2020 WireGuard LLC. All Rights Reserved." and is licensed under the [GPLv2](COPYING).

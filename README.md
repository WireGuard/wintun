# [Wintun Network Adapter](https://www.wintun.net/)
### TUN Device Driver for Windows

This is a layer 3 TUN driver for Windows 7, 8, 8.1, and 10. Originally created for [WireGuard](https://www.wireguard.com/), it is intended to be useful to a wide variety of projects that require layer 3 tunneling devices with implementations primarily in userspace.

## Build Requirements

- [Visual Studio 2019](https://visualstudio.microsoft.com/downloads/)
- [Windows Driver Kit for Windows 10, version 1903](https://docs.microsoft.com/en-us/windows-hardware/drivers/download-the-wdk)
- [WiX Toolset 3.11.1](http://wixtoolset.org/releases/)


## Digital Signing

Digital signing is an integral part of the build process. By default, the driver will be test-signed using a certificate that the WDK should automatically generate. To subsequently load the driver, you will need to put your computer into test mode by executing as Administrator `bcdedit /set testsigning on`.

If you possess an EV certificate for kernel mode code signing you should switch TUN driver digital signing from test-signing to production-signing by authoring your `wintun.vcxproj.user` file to look something like this:

```xml
<?xml version="1.0" encoding="utf-8"?>
<Project ToolsVersion="15.0" xmlns="http://schemas.microsoft.com/developer/msbuild/2003">
  <PropertyGroup>
    <SignMode>ProductionSign</SignMode>
    <CrossCertificateFile>$(WDKContentRoot)CrossCertificates\DigiCert_High_Assurance_EV_Root_CA.crt</CrossCertificateFile>
    <ProductionCertificate>DF98E075A012ED8C86FBCF14854B8F9555CB3D45</ProductionCertificate>
    <TimestampServer>http://timestamp.digicert.com</TimestampServer>
  </PropertyGroup>
</Project>
```

Modify the `<CrossCertificateFile>` to contain the full path to the cross-signing certificate of CA that issued your certificate. You should be able to find its `.crt` file in `C:\Program Files (x86)\Windows Kits\10\CrossCertificates`. Note that the `$(WDKContentRoot)` expands to `C:\Program Files (x86)\Windows Kits\10\`.

If you already have `wintun.vcxproj.user` file, just add the `<PropertyGroup>` section.


## Building from Command Line

Open _Developer Command Prompt for VS 2019_ and use the `msbuild` command:

```
msbuild wintun.proj [/t:<target>]
```

### Targets

  - `Build`: Builds the driver release configurations of all supported platforms. This is the default target.

  - `Clean`: Deletes all intermediate and output files.

  - `Rebuild`: Alias for `Clean` followed by `Build`.

  - `SDV`: Runs Static Driver Verifier, which includes a clean driver build, only for AMD64 release configuration.

  - `DVL`: Runs the `SDV`, and creates a Driver Verification Log, only for AMD64 release configurations.

  - `MSM`: Builds Microsoft Installer Merge Modules in `<output folder>\wintun-<platform>-<version>.msm`. Requires WHQL signed driver.

The driver output folders are:

Platform and Configuration | Folder
-------------------------- | --------------------
x86 Debug                  | `x86\Debug\wintun`
x86 Release                | `x86\Release\wintun`
AMD64 Debug                | `amd64\Debug\wintun`
AMD64 Release              | `amd64\Release\wintun`
ARM64 Debug                | `arm64\Debug\wintun`
ARM64 Release              | `arm64\Release\wintun`

Do note that since the `Build` target builds for all supported platforms, you will need to have the toolchains installed for those platforms.

#### Building Microsoft Installer Merge Modules

1. `msbuild wintun.proj /t:DVL;Build`.
2. Perform Windows Hardware Lab Kit tests.
3. Submit submission package to Microsoft.
4. Copy WHQL-signed driver to `x86\Release\whql\` and `amd64\Release\whql\` subfolders.
5. `msbuild wintun.proj /t:MSM`
6. MSM files are placed in `dist` subfolder.

Note: due to the use of SHA256 signatures throughout, Windows 7 users who would like a prompt-less installation generally need to have the [KB2921916 hotfix](https://support.microsoft.com/en-us/help/2921916/the-untrusted-publisher-dialog-box-appears-when-you-install-a-driver-i) installed, which can be obtained from these mirrors: [amd64](https://download.wireguard.com/windows-toolchain/distfiles/Windows6.1-KB2921916-x64.msu) and [x86](https://download.wireguard.com/windows-toolchain/distfiles/Windows6.1-KB2921916-x86.msu).

## Usage

After loading the driver and creating a network interface the typical way using [SetupAPI](https://docs.microsoft.com/en-us/windows-hardware/drivers/install/setupapi), open the NDIS device object associated with the PnPInstanceId.

### Ring layout

You must allocate two ring structs, one for receiving and one for sending:

```C
typedef struct _TUN_RING {
    volatile ULONG Head;
    volatile ULONG Tail;
    volatile LONG Alertable;
    UCHAR Data[];
} TUN_RING;
```

- `Head`: Byte offset of the first packet in the ring. Its value must be a multiple of 4 and less than ring capacity.

- `Tail`: Byte offset of the start of free space in the ring. Its value must be multiple of 4 and less than ring capacity.

- `Alertable`: Zero when the consumer is processing packets, non-zero when the consumer has processed all packets and is waiting for `TailMoved` event.

- `Data`: The ring data.

In order to determine the size of the `Data` array:

1. Pick a ring capacity ranging from 128kiB to 64MiB bytes. This capacity must be a power of two (e.g. 1MiB). The ring can hold up to this much data.
2. Add 0x10000 trailing bytes to the capacity, in order to allow for always-contigious packet segments.

The total ring size memory is then `sizeof(TUN_RING) + capacity + 0x10000`.

Each packet is stored in the ring aligned to `sizeof(ULONG)` as:

```C
typedef struct _TUN_PACKET {
    ULONG Size;
    UCHAR Data[];
} TUN_PACKET;
```

- `Size`: Size of packet (max 0xFFFF).

- `Data`: Layer 3 IPv4 or IPv6 packet.

### Registering rings

In order to register the two `TUN_RING`s, prepare a registration struct as:

```C
typedef struct _TUN_REGISTER_RINGS
{
    struct
    {
        ULONG RingSize;
        TUN_RING *Ring;
        HANDLE TailMoved;
    } Send, Receive;
} TUN_REGISTER_RINGS;
```

- `Send.RingSize`, `Receive.RingSize`: Sizes of the rings (`sizeof(TUN_RING) + capacity + 0x10000`, as above).

- `Send.Ring`, `Receive.Ring`: Pointers to the rings.

- `Send.TailMoved`: A handle to an [`auto-reset event`](https://docs.microsoft.com/en-us/windows/win32/api/synchapi/nf-synchapi-createeventa) created by the client that Wintun signals after it moves the `Tail` member of the send ring.

- `Receive.TailMoved`: A handle to an [`auto-reset event`](https://docs.microsoft.com/en-us/windows/win32/api/synchapi/nf-synchapi-createeventa) created by the client that the client will signal when it changes `Receive.Ring->Tail` and `Receive.Ring->Alertable` is non-zero.

With events created, send and receive rings allocated, and registration struct populated, [`DeviceIoControl`](https://docs.microsoft.com/en-us/windows/win32/api/ioapiset/nf-ioapiset-deviceiocontrol)(`TUN_IOCTL_REGISTER_RINGS`: 0xca6ce5c0) with pointer and size of descriptor struct specified as `lpInBuffer` and `nInBufferSize` parameters. You may call `TUN_IOCTL_REGISTER_RINGS` on one handle only.


### Writing to and from rings

Reading packets from the send ring may be done as:

```C
for (;;) {
    TUN_PACKET *next = PopFromRing(r->Send.Ring);
    if (!next) {
        r->Send.Ring->Alertable = TRUE;
        next = PopFromRing(r->Send.Ring);
        if (!next) {
            WaitForSingleObject(r->Send.TailMoved, INFINITE);
            r->Send.Ring->Alertable = FALSE;
            continue;
        }
        r->Send.Ring->Alertable = FALSE;
        ResetEvent(r->Send.TailMoved);
    }
    SendToClientProgram(next);
}
```

It may be desirable to spin for ~50ms before waiting on the `TailMoved` event, in order to reduce latency.

When closing the handle, Wintun will set the `Tail` to 0xFFFFFFFF and set the `TailMoved` event to unblock the waiting user process.

Writing packets to the receive ring may be done as:

```C
for (;;) {
    TUN_PACKET *next = ReceiveFromClientProgram();
    WriteToRing(r->Receive.Ring, next);
    if (r->Receive.Ring->Alertable)
        SetEvent(r->Recieve.TailMoved);
}
```

Wintun will abort reading the receive ring on invalid `Head` or `Tail` or on a bogus packet. In this case, Wintun will set the `Head` to 0xFFFFFFFF. In order to restart it, reopen the handle and call `TUN_IOCTL_REGISTER_RINGS` again. However, it should be entirely possible to avoid feeding Wintun bogus packets and invalid offsets.

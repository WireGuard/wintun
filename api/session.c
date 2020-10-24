/* SPDX-License-Identifier: GPL-2.0
 *
 * Copyright (C) 2018-2020 WireGuard LLC. All Rights Reserved.
 */

#include "pch.h"

#pragma warning(disable : 4200) /* nonstandard: zero-sized array in struct/union */

#define TUN_ALIGNMENT sizeof(ULONG)
#define TUN_ALIGN(Size) (((ULONG)(Size) + ((ULONG)TUN_ALIGNMENT - 1)) & ~((ULONG)TUN_ALIGNMENT - 1))
#define TUN_IS_ALIGNED(Size) (!((ULONG)(Size) & ((ULONG)TUN_ALIGNMENT - 1)))
#define TUN_MAX_PACKET_SIZE TUN_ALIGN(sizeof(TUN_PACKET) + WINTUN_MAX_IP_PACKET_SIZE)
#define TUN_RING_CAPACITY(Size) ((Size) - sizeof(TUN_RING) - (TUN_MAX_PACKET_SIZE - TUN_ALIGNMENT))
#define TUN_RING_SIZE(Capacity) (sizeof(TUN_RING) + (Capacity) + (TUN_MAX_PACKET_SIZE - TUN_ALIGNMENT))
#define TUN_RING_WRAP(Value, Capacity) ((Value) & (Capacity - 1))

typedef struct _TUN_PACKET
{
    ULONG Size;
    UCHAR _Field_size_bytes_(Size)
    Data[];
} TUN_PACKET;

typedef struct _TUN_RING
{
    volatile ULONG Head;
    volatile ULONG Tail;
    volatile LONG Alertable;
    UCHAR Data[];
} TUN_RING;

#define TUN_IOCTL_REGISTER_RINGS CTL_CODE(51820U, 0x970U, METHOD_BUFFERED, FILE_READ_DATA | FILE_WRITE_DATA)

typedef struct _TUN_REGISTER_RINGS
{
    struct
    {
        ULONG RingSize;
        TUN_RING *Ring;
        HANDLE TailMoved;
    } Send, Receive;
} TUN_REGISTER_RINGS;

typedef struct _TUN_SESSION
{
    ULONG Capacity;
    TUN_REGISTER_RINGS Descriptor;
    HANDLE Handle;
} TUN_SESSION;

WINTUN_STATUS WINAPI
WintunStartSession(_In_ const WINTUN_ADAPTER *Adapter, _In_ DWORD Capacity, _Out_ TUN_SESSION **Session)
{
    HANDLE Heap = GetProcessHeap();
    *Session = HeapAlloc(Heap, 0, sizeof(TUN_SESSION));
    if (!*Session)
        return LOG(WINTUN_LOG_ERR, L"Out of memory"), ERROR_OUTOFMEMORY;
    const ULONG RingSize = TUN_RING_SIZE(Capacity);
    DWORD Result;
    BYTE *AllocatedRegion = VirtualAlloc(0, (size_t)RingSize * 2, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!AllocatedRegion)
    {
        Result = LOG_LAST_ERROR(L"Failed to allocate ring memory");
        goto cleanupRings;
    }
    (*Session)->Descriptor.Send.RingSize = RingSize;
    (*Session)->Descriptor.Send.Ring = (TUN_RING *)AllocatedRegion;
    (*Session)->Descriptor.Send.TailMoved = CreateEventW(SecurityAttributes, FALSE, FALSE, NULL);
    if (!(*Session)->Descriptor.Send.TailMoved)
    {
        Result = LOG_LAST_ERROR(L"Failed to create send event");
        goto cleanupAllocatedRegion;
    }

    (*Session)->Descriptor.Receive.RingSize = RingSize;
    (*Session)->Descriptor.Receive.Ring = (TUN_RING *)(AllocatedRegion + RingSize);
    (*Session)->Descriptor.Receive.TailMoved = CreateEvent(SecurityAttributes, FALSE, FALSE, NULL);
    if (!(*Session)->Descriptor.Receive.TailMoved)
    {
        Result = LOG_LAST_ERROR(L"Failed to create receive event");
        goto cleanupSendTailMoved;
    }

    Result = WintunGetAdapterDeviceObject(Adapter, &(*Session)->Handle);
    if (Result != ERROR_SUCCESS)
    {
        LOG(WINTUN_LOG_ERR, L"Failed to open adapter device object");
        goto cleanupReceiveTailMoved;
    }
    DWORD BytesReturned;
    if (!DeviceIoControl(
            (*Session)->Handle,
            TUN_IOCTL_REGISTER_RINGS,
            &(*Session)->Descriptor,
            sizeof(TUN_REGISTER_RINGS),
            NULL,
            0,
            &BytesReturned,
            NULL))
    {
        Result = LOG_LAST_ERROR(L"Failed to perform ioctl");
        goto cleanupHandle;
    }
    (*Session)->Capacity = Capacity;
    return ERROR_SUCCESS;
cleanupHandle:
    CloseHandle((*Session)->Handle);
cleanupReceiveTailMoved:
    CloseHandle((*Session)->Descriptor.Receive.TailMoved);
cleanupSendTailMoved:
    CloseHandle((*Session)->Descriptor.Send.TailMoved);
cleanupAllocatedRegion:
    VirtualFree(AllocatedRegion, 0, MEM_RELEASE);
cleanupRings:
    HeapFree(Heap, 0, *Session);
    *Session = NULL;
    return Result;
}

void WINAPI
WintunEndSession(_In_ TUN_SESSION *Session)
{
    SetEvent(Session->Descriptor.Send.TailMoved); // wake the reader if it's sleeping
    CloseHandle(Session->Handle);
    CloseHandle(Session->Descriptor.Send.TailMoved);
    CloseHandle(Session->Descriptor.Receive.TailMoved);
    VirtualFree(Session->Descriptor.Send.Ring, 0, MEM_RELEASE);
    HeapFree(GetProcessHeap(), 0, Session);
}

BOOL WINAPI
WintunIsPacketAvailable(_In_ TUN_SESSION *Session)
{
    return InterlockedGetU(&Session->Descriptor.Send.Ring->Head) !=
           InterlockedGetU(&Session->Descriptor.Send.Ring->Tail);
}

WINTUN_STATUS WINAPI
WintunWaitForPacket(_In_ TUN_SESSION *Session, _In_ DWORD Milliseconds)
{
    return WaitForSingleObject(Session->Descriptor.Send.TailMoved, Milliseconds);
}

WINTUN_STATUS WINAPI
WintunReceivePackets(_In_ TUN_SESSION *Session, _Inout_ WINTUN_PACKET *Queue)
{
    ULONG BuffHead = InterlockedGetU(&Session->Descriptor.Send.Ring->Head);
    if (BuffHead >= Session->Capacity)
        return ERROR_HANDLE_EOF;

    for (; Queue; Queue = Queue->Next)
    {
        const ULONG BuffTail = InterlockedGetU(&Session->Descriptor.Send.Ring->Tail);
        if (BuffTail >= Session->Capacity)
            return ERROR_HANDLE_EOF;

        if (BuffHead == BuffTail)
            return ERROR_NO_MORE_ITEMS;

        const ULONG BuffContent = TUN_RING_WRAP(BuffTail - BuffHead, Session->Capacity);
        if (BuffContent < sizeof(TUN_PACKET))
            return ERROR_INVALID_DATA;

        const TUN_PACKET *Packet = (TUN_PACKET *)&Session->Descriptor.Send.Ring->Data[BuffHead];
        if (Packet->Size > WINTUN_MAX_IP_PACKET_SIZE)
            return ERROR_INVALID_DATA;

        const ULONG AlignedPacketSize = TUN_ALIGN(sizeof(TUN_PACKET) + Packet->Size);
        if (AlignedPacketSize > BuffContent)
            return ERROR_INVALID_DATA;

        Queue->Size = Packet->Size;
        memcpy(Queue->Data, Packet->Data, Packet->Size);
        BuffHead = TUN_RING_WRAP(BuffHead + AlignedPacketSize, Session->Capacity);
        InterlockedSetU(&Session->Descriptor.Send.Ring->Head, BuffHead);
    }

    return ERROR_SUCCESS;
}

WINTUN_STATUS WINAPI
WintunSendPackets(_In_ TUN_SESSION *Session, _In_ const WINTUN_PACKET *Queue)
{
    ULONG BuffTail = InterlockedGetU(&Session->Descriptor.Receive.Ring->Tail);
    if (BuffTail >= Session->Capacity)
        return ERROR_HANDLE_EOF;

    for (; Queue; Queue = Queue->Next)
    {
        const ULONG PacketSize = Queue->Size;
        const ULONG AlignedPacketSize = TUN_ALIGN(sizeof(TUN_PACKET) + PacketSize);

        const ULONG BuffHead = InterlockedGetU(&Session->Descriptor.Receive.Ring->Head);
        if (BuffHead >= Session->Capacity)
            return ERROR_HANDLE_EOF;

        const ULONG BuffSpace = TUN_RING_WRAP(BuffHead - BuffTail - TUN_ALIGNMENT, Session->Capacity);
        if (AlignedPacketSize > BuffSpace)
            return ERROR_BUFFER_OVERFLOW; /* Dropping when ring is full. */

        TUN_PACKET *Packet = (TUN_PACKET *)&Session->Descriptor.Receive.Ring->Data[BuffTail];
        Packet->Size = PacketSize;
        memcpy(Packet->Data, Queue->Data, PacketSize);
        BuffTail = TUN_RING_WRAP(BuffTail + AlignedPacketSize, Session->Capacity);
        InterlockedSetU(&Session->Descriptor.Receive.Ring->Tail, BuffTail);

        if (InterlockedGet(&Session->Descriptor.Receive.Ring->Alertable))
            SetEvent(Session->Descriptor.Receive.TailMoved);
    }

    return ERROR_SUCCESS;
}

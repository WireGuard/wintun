/* SPDX-License-Identifier: GPL-2.0
 *
 * Copyright (C) 2018-2019 WireGuard LLC. All Rights Reserved.
 */

#include <ntifs.h>
#include <wdm.h>
#include <wdmsec.h>
#include <ndis.h>
#include <ntstrsafe.h>

#pragma warning(disable : 4100) /* unreferenced formal parameter */
#pragma warning(disable : 4200) /* nonstandard: zero-sized array in struct/union */
#pragma warning(disable : 4204) /* nonstandard: non-constant aggregate initializer */
#pragma warning(disable : 4221) /* nonstandard: cannot be initialized using address of automatic variable */
#pragma warning(disable : 6320) /* exception-filter expression is the constant EXCEPTION_EXECUTE_HANDLER */

#define NDIS_MINIPORT_VERSION_MIN ((NDIS_MINIPORT_MINIMUM_MAJOR_VERSION << 16) | NDIS_MINIPORT_MINIMUM_MINOR_VERSION)
#define NDIS_MINIPORT_VERSION_MAX ((NDIS_MINIPORT_MAJOR_VERSION << 16) | NDIS_MINIPORT_MINOR_VERSION)

#define TUN_VENDOR_NAME "Wintun Tunnel"
#define TUN_VENDOR_ID 0xFFFFFF00
#define TUN_LINK_SPEED 100000000000ULL /* 100gbps */

/* Memory alignment of packets and rings */
#define TUN_ALIGNMENT sizeof(ULONG)
#define TUN_ALIGN(Size) (((ULONG)(Size) + ((ULONG)TUN_ALIGNMENT - 1)) & ~((ULONG)TUN_ALIGNMENT - 1))
#define TUN_IS_ALIGNED(Size) (!((ULONG)(Size) & ((ULONG)TUN_ALIGNMENT - 1)))
/* Maximum IP packet size */
#define TUN_MAX_IP_PACKET_SIZE 0xFFFF
/* Maximum packet size */
#define TUN_MAX_PACKET_SIZE TUN_ALIGN(sizeof(TUN_PACKET) + TUN_MAX_IP_PACKET_SIZE)
/* Minimum ring capacity. */
#define TUN_MIN_RING_CAPACITY 0x20000 /* 128kiB */
/* Maximum ring capacity. */
#define TUN_MAX_RING_CAPACITY 0x4000000 /* 64MiB */
/* Calculates ring capacity */
#define TUN_RING_CAPACITY(Size) ((Size) - sizeof(TUN_RING) - (TUN_MAX_PACKET_SIZE - TUN_ALIGNMENT))
/* Calculates ring offset modulo capacity */
#define TUN_RING_WRAP(Value, Capacity) ((Value) & (Capacity - 1))

#if REG_DWORD == REG_DWORD_BIG_ENDIAN
#    define TUN_HTONS(x) ((USHORT)(x))
#    define TUN_HTONL(x) ((ULONG)(x))
#elif REG_DWORD == REG_DWORD_LITTLE_ENDIAN
#    define TUN_HTONS(x) ((((USHORT)(x)&0x00ff) << 8) | (((USHORT)(x)&0xff00) >> 8))
#    define TUN_HTONL(x) \
        ((((ULONG)(x)&0x000000ff) << 24) | (((ULONG)(x)&0x0000ff00) << 8) | (((ULONG)(x)&0x00ff0000) >> 8) | \
         (((ULONG)(x)&0xff000000) >> 24))
#else
#    error "Unable to determine endianess"
#endif

#define TUN_MEMORY_TAG TUN_HTONL('wtun')

typedef struct _TUN_PACKET
{
    /* Size of packet data (TUN_MAX_IP_PACKET_SIZE max) */
    ULONG Size;

    /* Packet data */
    UCHAR _Field_size_bytes_(Size)
    Data[];
} TUN_PACKET;

typedef struct _TUN_RING
{
    /* Byte offset of the first packet in the ring. Its value must be a multiple of TUN_ALIGNMENT and less than ring
     * capacity. */
    volatile ULONG Head;

    /* Byte offset of the first free space in the ring. Its value must be multiple of TUN_ALIGNMENT and less than ring
     * capacity. */
    volatile ULONG Tail;

    /* Non-zero when consumer is in alertable state. */
    volatile LONG Alertable;

    /* Ring data. Its capacity must be a power of 2 + extra TUN_MAX_PACKET_SIZE-TUN_ALIGNMENT space to
     * eliminate need for wrapping. */
    UCHAR Data[];
} TUN_RING;

typedef struct _TUN_REGISTER_RINGS
{
    struct
    {
        /* Size of the ring */
        ULONG RingSize;

        /* Pointer to client allocated ring */
        TUN_RING *Ring;

        /* On send: An event created by the client the Wintun signals after it moves the Tail member of the send ring.
         * On receive: An event created by the client the client will signal when it moves the Tail member of
         * the receive ring if receive ring is alertable. */
        HANDLE TailMoved;
    } Send, Receive;
} TUN_REGISTER_RINGS;

/* Register rings hosted by the client
 * The lpInBuffer and nInBufferSize parameters of DeviceIoControl() must point to an TUN_REGISTER_RINGS struct.
 * Client must wait for this IOCTL to finish before adding packets to the ring. */
#define TUN_IOCTL_REGISTER_RINGS CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800, METHOD_BUFFERED, FILE_READ_DATA | FILE_WRITE_DATA)
/* TODO: Select and specify OEM-specific device type instead of FILE_DEVICE_UNKNOWN. */

typedef enum _TUN_FLAGS
{
    TUN_FLAGS_RUNNING = 1 << 0, /* Toggles between paused and running state */
    TUN_FLAGS_PRESENT = 1 << 1, /* Toggles between removal pending and being present */
} TUN_FLAGS;

typedef struct _TUN_CTX
{
    volatile LONG Flags;

    /* Used like RCU. When we're making use of rings, we take a shared lock. When we want to register or release the
     * rings and toggle the state, we take an exclusive lock before toggling the atomic and then releasing. It's similar
     * to setting the atomic and then calling rcu_barrier(). */
    EX_SPIN_LOCK TransitionLock;

    NDIS_HANDLE MiniportAdapterHandle; /* This is actually a pointer to NDIS_MINIPORT_BLOCK struct. */
    DEVICE_OBJECT *FunctionalDeviceObject;
    NDIS_STATISTICS_INFO Statistics;

    struct
    {
        FILE_OBJECT *volatile Owner;
        KEVENT Disconnected;

        struct
        {
            MDL *Mdl;
            TUN_RING *Ring;
            ULONG Capacity;
            KEVENT *TailMoved;
            KSPIN_LOCK Lock;
            ULONG RingTail;
            struct
            {
                NET_BUFFER_LIST *Head, *Tail;
            } ActiveNbls;
        } Send;

        struct
        {
            MDL *Mdl;
            TUN_RING *Ring;
            ULONG Capacity;
            KEVENT *TailMoved;
            HANDLE Thread;
            KSPIN_LOCK Lock;
            struct
            {
                NET_BUFFER_LIST *Head, *Tail;
                IO_REMOVE_LOCK RemoveLock;
            } ActiveNbls;
        } Receive;
    } Device;

    NDIS_HANDLE NblPool;
} TUN_CTX;

static UINT NdisVersion;
static NDIS_HANDLE NdisMiniportDriverHandle;
static DRIVER_DISPATCH *NdisDispatchDeviceControl, *NdisDispatchClose;
static ERESOURCE TunDispatchCtxGuard;
static SECURITY_DESCRIPTOR *TunDispatchSecurityDescriptor;

static __forceinline ULONG
InterlockedExchangeU(_Inout_ _Interlocked_operand_ ULONG volatile *Target, _In_ ULONG Value)
{
    return (ULONG)InterlockedExchange((LONG volatile *)Target, Value);
}

static __forceinline LONG
InterlockedGet(_In_ _Interlocked_operand_ LONG volatile *Value)
{
    return *Value;
}

static __forceinline ULONG
InterlockedGetU(_In_ _Interlocked_operand_ ULONG volatile *Value)
{
    return *Value;
}

static __forceinline PVOID
InterlockedGetPointer(_In_ _Interlocked_operand_ PVOID volatile *Value)
{
    return *Value;
}

static __forceinline LONG64
InterlockedGet64(_In_ _Interlocked_operand_ LONG64 volatile *Value)
{
#ifdef _WIN64
    return *Value;
#else
    return InterlockedCompareExchange64(Value, 0, 0);
#endif
}

#define TunInitUnicodeString(str, buf) \
    { \
        (str)->Length = 0; \
        (str)->MaximumLength = sizeof(buf); \
        (str)->Buffer = buf; \
    }

_IRQL_requires_max_(DISPATCH_LEVEL)
static VOID
TunIndicateStatus(_In_ NDIS_HANDLE MiniportAdapterHandle, _In_ NDIS_MEDIA_CONNECT_STATE MediaConnectState)
{
    NDIS_LINK_STATE State = { .Header = { .Type = NDIS_OBJECT_TYPE_DEFAULT,
                                          .Revision = NDIS_LINK_STATE_REVISION_1,
                                          .Size = NDIS_SIZEOF_LINK_STATE_REVISION_1 },
                              .MediaConnectState = MediaConnectState,
                              .MediaDuplexState = MediaDuplexStateFull,
                              .XmitLinkSpeed = TUN_LINK_SPEED,
                              .RcvLinkSpeed = TUN_LINK_SPEED,
                              .PauseFunctions = NdisPauseFunctionsUnsupported };

    NDIS_STATUS_INDICATION Indication = { .Header = { .Type = NDIS_OBJECT_TYPE_STATUS_INDICATION,
                                                      .Revision = NDIS_STATUS_INDICATION_REVISION_1,
                                                      .Size = NDIS_SIZEOF_STATUS_INDICATION_REVISION_1 },
                                          .SourceHandle = MiniportAdapterHandle,
                                          .StatusCode = NDIS_STATUS_LINK_STATE,
                                          .StatusBuffer = &State,
                                          .StatusBufferSize = sizeof(State) };

    NdisMIndicateStatusEx(MiniportAdapterHandle, &Indication);
}

static VOID
TunNblSetOffsetAndMarkActive(_Inout_ NET_BUFFER_LIST *Nbl, _In_ ULONG Offset)
{
    ASSERT(TUN_IS_ALIGNED(Offset)); /* Alignment ensures bit 0 will be 0 (0=active, 1=completed). */
    NET_BUFFER_LIST_MINIPORT_RESERVED(Nbl)[0] = (VOID *)Offset;
}

static ULONG
TunNblGetOffset(_In_ NET_BUFFER_LIST *Nbl)
{
    return (ULONG)((ULONG_PTR)(NET_BUFFER_LIST_MINIPORT_RESERVED(Nbl)[0]) & ~((ULONG_PTR)TUN_ALIGNMENT - 1));
}

static VOID
TunNblMarkCompleted(_Inout_ NET_BUFFER_LIST *Nbl)
{
    *(ULONG_PTR *)&NET_BUFFER_LIST_MINIPORT_RESERVED(Nbl)[0] |= 1;
}

static BOOLEAN
TunNblIsCompleted(_In_ NET_BUFFER_LIST *Nbl)
{
    return (ULONG_PTR)(NET_BUFFER_LIST_MINIPORT_RESERVED(Nbl)[0]) & 1;
}

static MINIPORT_SEND_NET_BUFFER_LISTS TunSendNetBufferLists;
_Use_decl_annotations_
static VOID
TunSendNetBufferLists(
    NDIS_HANDLE MiniportAdapterContext,
    NET_BUFFER_LIST *NetBufferLists,
    NDIS_PORT_NUMBER PortNumber,
    ULONG SendFlags)
{
    TUN_CTX *Ctx = (TUN_CTX *)MiniportAdapterContext;
    LONG64 SentPacketsCount = 0, SentPacketsSize = 0, ErrorPacketsCount = 0, DiscardedPacketsCount = 0;

    for (NET_BUFFER_LIST *Nbl = NetBufferLists, *NextNbl; Nbl; Nbl = NextNbl)
    {
        NextNbl = NET_BUFFER_LIST_NEXT_NBL(Nbl);

        /* Measure NBL. */
        ULONG PacketsCount = 0, RequiredRingSpace = 0;
        for (NET_BUFFER *Nb = NET_BUFFER_LIST_FIRST_NB(Nbl); Nb; Nb = NET_BUFFER_NEXT_NB(Nb))
        {
            PacketsCount++;
            UINT PacketSize = NET_BUFFER_DATA_LENGTH(Nb);
            if (PacketSize <= TUN_MAX_IP_PACKET_SIZE)
                RequiredRingSpace += TUN_ALIGN(sizeof(TUN_PACKET) + PacketSize);
        }

        KIRQL Irql = ExAcquireSpinLockShared(&Ctx->TransitionLock);
        LONG Flags = InterlockedGet(&Ctx->Flags);
        NDIS_STATUS Status;
        if ((Status = NDIS_STATUS_ADAPTER_REMOVED, !(Flags & TUN_FLAGS_PRESENT)) ||
            (Status = NDIS_STATUS_PAUSED, !(Flags & TUN_FLAGS_RUNNING)) ||
            (Status = NDIS_STATUS_MEDIA_DISCONNECTED, KeReadStateEvent(&Ctx->Device.Disconnected)))
            goto skipNbl;

        TUN_RING *Ring = Ctx->Device.Send.Ring;
        ULONG RingCapacity = Ctx->Device.Send.Capacity;

        /* Allocate space for packet(s) in the ring. */
        ULONG RingHead = InterlockedGetU(&Ring->Head);
        if (Status = NDIS_STATUS_ADAPTER_NOT_READY, RingHead >= RingCapacity)
            goto skipNbl;

        KLOCK_QUEUE_HANDLE LockHandle;
        KeAcquireInStackQueuedSpinLock(&Ctx->Device.Send.Lock, &LockHandle);

        ULONG RingTail = Ctx->Device.Send.RingTail;
        ASSERT(RingTail < RingCapacity);

        ULONG RingSpace = TUN_RING_WRAP(RingHead - RingTail - TUN_ALIGNMENT, RingCapacity);
        if (Status = NDIS_STATUS_BUFFER_OVERFLOW, RingSpace < RequiredRingSpace)
            goto cleanupKeReleaseInStackQueuedSpinLock;

        Ctx->Device.Send.RingTail = TUN_RING_WRAP(RingTail + RequiredRingSpace, RingCapacity);
        TunNblSetOffsetAndMarkActive(Nbl, Ctx->Device.Send.RingTail);
        *(Ctx->Device.Send.ActiveNbls.Head ? &NET_BUFFER_LIST_NEXT_NBL(Ctx->Device.Send.ActiveNbls.Tail)
                                           : &Ctx->Device.Send.ActiveNbls.Head) = Nbl;
        Ctx->Device.Send.ActiveNbls.Tail = Nbl;

        KeReleaseInStackQueuedSpinLock(&LockHandle);

        /* Copy packet(s). */
        for (NET_BUFFER *Nb = NET_BUFFER_LIST_FIRST_NB(Nbl); Nb; Nb = NET_BUFFER_NEXT_NB(Nb))
        {
            UINT PacketSize = NET_BUFFER_DATA_LENGTH(Nb);
            if (Status = NDIS_STATUS_INVALID_LENGTH, PacketSize > TUN_MAX_IP_PACKET_SIZE)
                goto skipPacket;

            TUN_PACKET *Packet = (TUN_PACKET *)(Ring->Data + RingTail);
            Packet->Size = PacketSize;
            void *NbData = NdisGetDataBuffer(Nb, PacketSize, Packet->Data, 1, 0);
            if (!NbData)
            {
                /* The space for the packet has already been allocated in the ring. Write a zero-packet rather than
                 * fixing the gap in the ring. */
                NdisZeroMemory(Packet->Data, PacketSize);
                DiscardedPacketsCount++;
            }
            else
            {
                if (NbData != Packet->Data)
                    NdisMoveMemory(Packet->Data, NbData, PacketSize);
                SentPacketsCount++;
                SentPacketsSize += PacketSize;
            }

            RingTail = TUN_RING_WRAP(RingTail + TUN_ALIGN(sizeof(TUN_PACKET) + PacketSize), RingCapacity);
            continue;

        skipPacket:
            ErrorPacketsCount++;
            NET_BUFFER_LIST_STATUS(Nbl) = Status;
        }
        ASSERT(RingTail == TunNblGetOffset(Nbl));

        /* Adjust the ring tail. */
        TunNblMarkCompleted(Nbl);
        KeAcquireInStackQueuedSpinLock(&Ctx->Device.Send.Lock, &LockHandle);
        while (Ctx->Device.Send.ActiveNbls.Head && TunNblIsCompleted(Ctx->Device.Send.ActiveNbls.Head))
        {
            NET_BUFFER_LIST *CompletedNbl = Ctx->Device.Send.ActiveNbls.Head;
            Ctx->Device.Send.ActiveNbls.Head = NET_BUFFER_LIST_NEXT_NBL(CompletedNbl);
            InterlockedExchangeU(&Ring->Tail, TunNblGetOffset(CompletedNbl));
            KeSetEvent(Ctx->Device.Send.TailMoved, IO_NETWORK_INCREMENT, FALSE);
            NET_BUFFER_LIST_NEXT_NBL(CompletedNbl) = NULL;
            NdisMSendNetBufferListsComplete(
                Ctx->MiniportAdapterHandle, CompletedNbl, NDIS_SEND_COMPLETE_FLAGS_DISPATCH_LEVEL);
        }
        KeReleaseInStackQueuedSpinLock(&LockHandle);
        ExReleaseSpinLockShared(&Ctx->TransitionLock, Irql);
        continue;

    cleanupKeReleaseInStackQueuedSpinLock:
        KeReleaseInStackQueuedSpinLock(&LockHandle);
    skipNbl:
        NET_BUFFER_LIST_STATUS(Nbl) = Status;
        NET_BUFFER_LIST_NEXT_NBL(Nbl) = NULL;
        NdisMSendNetBufferListsComplete(Ctx->MiniportAdapterHandle, Nbl, NDIS_SEND_COMPLETE_FLAGS_DISPATCH_LEVEL);
        ExReleaseSpinLockShared(&Ctx->TransitionLock, Irql);
        DiscardedPacketsCount += PacketsCount;
    }

    InterlockedAdd64((LONG64 *)&Ctx->Statistics.ifHCOutOctets, SentPacketsSize);
    InterlockedAdd64((LONG64 *)&Ctx->Statistics.ifHCOutUcastOctets, SentPacketsSize);
    InterlockedAdd64((LONG64 *)&Ctx->Statistics.ifHCOutUcastPkts, SentPacketsCount);
    InterlockedAdd64((LONG64 *)&Ctx->Statistics.ifOutErrors, ErrorPacketsCount);
    InterlockedAdd64((LONG64 *)&Ctx->Statistics.ifOutDiscards, DiscardedPacketsCount);
}

static MINIPORT_CANCEL_SEND TunCancelSend;
_Use_decl_annotations_
static VOID
TunCancelSend(NDIS_HANDLE MiniportAdapterContext, PVOID CancelId)
{
}

/* NDIS may change NET_BUFFER_LIST_NEXT_NBL(Nbl) at will between the NdisMIndicateReceiveNetBufferLists() and
 * MINIPORT_RETURN_NET_BUFFER_LISTS calls. Therefore, we use our own ->Next pointer for book-keeping. */
#define NET_BUFFER_LIST_NEXT_NBL_EX(Nbl) (NET_BUFFER_LIST_MINIPORT_RESERVED(Nbl)[1])

/* Wintun-specific MINIPORT_RETURN_NET_BUFFER_LISTS return flag to indicate the NBL was not really sent to NDIS and
 * the receiver thread is calling the MINIPORT_RETURN_NET_BUFFER_LISTS handler manualy to perform regular NBL's
 * post-processing. Must not overlap any of the standard NDIS_RETURN_FLAGS_* values. */
#define TUN_RETURN_FLAGS_DISCARD 0x00010000

static MINIPORT_RETURN_NET_BUFFER_LISTS TunReturnNetBufferLists;
_Use_decl_annotations_
static VOID
TunReturnNetBufferLists(NDIS_HANDLE MiniportAdapterContext, PNET_BUFFER_LIST NetBufferLists, ULONG ReturnFlags)
{
    TUN_CTX *Ctx = (TUN_CTX *)MiniportAdapterContext;
    TUN_RING *Ring = Ctx->Device.Receive.Ring;
    BOOLEAN WasNdisIndicated = !(ReturnFlags & TUN_RETURN_FLAGS_DISCARD);

    LONG64 ReceivedPacketsCount = 0, ReceivedPacketsSize = 0, ErrorPacketsCount = 0, DiscardedPacketsCount = 0;
    for (NET_BUFFER_LIST *Nbl = NetBufferLists, *NextNbl; Nbl; Nbl = NextNbl)
    {
        NextNbl = NET_BUFFER_LIST_NEXT_NBL(Nbl);

        if (WasNdisIndicated)
        {
            if (NT_SUCCESS(NET_BUFFER_LIST_STATUS(Nbl)))
            {
                ReceivedPacketsCount++;
                ReceivedPacketsSize += NET_BUFFER_LIST_FIRST_NB(Nbl)->DataLength;
            }
            else
                ErrorPacketsCount++;
        }
        else
            DiscardedPacketsCount++;

        TunNblMarkCompleted(Nbl);
        for (;;)
        {
            KLOCK_QUEUE_HANDLE LockHandle;
            KeAcquireInStackQueuedSpinLock(&Ctx->Device.Receive.Lock, &LockHandle);
            NET_BUFFER_LIST *CompletedNbl = Ctx->Device.Receive.ActiveNbls.Head;
            if (!CompletedNbl || !TunNblIsCompleted(CompletedNbl))
            {
                KeReleaseInStackQueuedSpinLock(&LockHandle);
                break;
            }
            Ctx->Device.Receive.ActiveNbls.Head = NET_BUFFER_LIST_NEXT_NBL_EX(CompletedNbl);
            KeReleaseInStackQueuedSpinLock(&LockHandle);
            InterlockedExchangeU(&Ring->Head, TunNblGetOffset(CompletedNbl));
            NdisFreeNetBufferList(CompletedNbl);
        }

        if (WasNdisIndicated)
            IoReleaseRemoveLock(&Ctx->Device.Receive.ActiveNbls.RemoveLock, Nbl);
    }

    InterlockedAdd64((LONG64 *)&Ctx->Statistics.ifHCInOctets, ReceivedPacketsSize);
    InterlockedAdd64((LONG64 *)&Ctx->Statistics.ifHCInUcastOctets, ReceivedPacketsSize);
    InterlockedAdd64((LONG64 *)&Ctx->Statistics.ifHCInUcastPkts, ReceivedPacketsCount);
    InterlockedAdd64((LONG64 *)&Ctx->Statistics.ifInErrors, ErrorPacketsCount);
    InterlockedAdd64((LONG64 *)&Ctx->Statistics.ifInDiscards, DiscardedPacketsCount);
}

_IRQL_requires_max_(PASSIVE_LEVEL)
_Function_class_(KSTART_ROUTINE)
static VOID
TunProcessReceiveData(_Inout_ TUN_CTX *Ctx)
{
    TUN_RING *Ring = Ctx->Device.Receive.Ring;
    ULONG RingCapacity = Ctx->Device.Receive.Capacity;
    const ULONG SpinMax = 10000 * 50 / KeQueryTimeIncrement(); /* 50ms */
    VOID *Events[] = { &Ctx->Device.Disconnected, Ctx->Device.Receive.TailMoved };
    ASSERT(RTL_NUMBER_OF(Events) <= THREAD_WAIT_OBJECTS);

    ULONG RingHead = InterlockedGetU(&Ring->Head);
    if (RingHead >= RingCapacity)
        goto cleanup;

    while (!KeReadStateEvent(&Ctx->Device.Disconnected))
    {
        /* Get next packet from the ring. */
        ULONG RingTail = InterlockedGetU(&Ring->Tail);
        if (RingHead == RingTail)
        {
            ULONG64 SpinStart;
            KeQueryTickCount(&SpinStart);
            for (;;)
            {
                RingTail = InterlockedGetU(&Ring->Tail);
                if (RingTail != RingHead)
                    break;
                if (KeReadStateEvent(&Ctx->Device.Disconnected))
                    break;
                ULONG64 SpinNow;
                KeQueryTickCount(&SpinNow);
                if (SpinNow - SpinStart >= SpinMax)
                    break;

                /* This should really call KeYieldProcessorEx(&zero), so it does the Hyper-V paravirtualization call,
                 * but it's not exported. */
                YieldProcessor();
            }
            if (RingHead == RingTail)
            {
                InterlockedExchange(&Ring->Alertable, TRUE);
                RingTail = InterlockedGetU(&Ring->Tail);
                if (RingHead == RingTail)
                {
                    KeWaitForMultipleObjects(
                        RTL_NUMBER_OF(Events), Events, WaitAny, Executive, KernelMode, FALSE, NULL, NULL);
                    InterlockedExchange(&Ring->Alertable, FALSE);
                    continue;
                }
                InterlockedExchange(&Ring->Alertable, FALSE);
                KeClearEvent(Ctx->Device.Receive.TailMoved);
            }
        }
        if (RingTail >= RingCapacity)
            break;

        ULONG RingContent = TUN_RING_WRAP(RingTail - RingHead, RingCapacity);
        if (RingContent < sizeof(TUN_PACKET))
            break;

        TUN_PACKET *Packet = (TUN_PACKET *)(Ring->Data + RingHead);
        ULONG PacketSize = Packet->Size;
        if (PacketSize > TUN_MAX_IP_PACKET_SIZE)
            break;

        ULONG AlignedPacketSize = TUN_ALIGN(sizeof(TUN_PACKET) + PacketSize);
        if (AlignedPacketSize > RingContent)
            break;

        ULONG NblFlags;
        USHORT NblProto;
        if (PacketSize >= 20 && Packet->Data[0] >> 4 == 4)
        {
            NblFlags = NDIS_NBL_FLAGS_IS_IPV4;
            NblProto = TUN_HTONS(NDIS_ETH_TYPE_IPV4);
        }
        else if (PacketSize >= 40 && Packet->Data[0] >> 4 == 6)
        {
            NblFlags = NDIS_NBL_FLAGS_IS_IPV6;
            NblProto = TUN_HTONS(NDIS_ETH_TYPE_IPV6);
        }
        else
            break;

        RingHead = TUN_RING_WRAP(RingHead + AlignedPacketSize, RingCapacity);

        NET_BUFFER_LIST *Nbl = NdisAllocateNetBufferAndNetBufferList(
            Ctx->NblPool, 0, 0, Ctx->Device.Receive.Mdl, (ULONG)(Packet->Data - (UCHAR *)Ring), PacketSize);
        if (!Nbl)
        {
            InterlockedIncrement64((LONG64 *)&Ctx->Statistics.ifInDiscards);
            continue;
        }

        Nbl->SourceHandle = Ctx->MiniportAdapterHandle;
        NdisSetNblFlag(Nbl, NblFlags);
        NET_BUFFER_LIST_INFO(Nbl, NetBufferListFrameType) = (PVOID)NblProto;
        NET_BUFFER_LIST_STATUS(Nbl) = NDIS_STATUS_SUCCESS;
        TunNblSetOffsetAndMarkActive(Nbl, RingHead);
        KLOCK_QUEUE_HANDLE LockHandle;
        KeAcquireInStackQueuedSpinLock(&Ctx->Device.Receive.Lock, &LockHandle);
        *(Ctx->Device.Receive.ActiveNbls.Head ? &NET_BUFFER_LIST_NEXT_NBL_EX(Ctx->Device.Receive.ActiveNbls.Tail)
                                              : &Ctx->Device.Receive.ActiveNbls.Head) = Nbl;
        Ctx->Device.Receive.ActiveNbls.Tail = Nbl;
        KeReleaseInStackQueuedSpinLock(&LockHandle);

        KIRQL Irql = ExAcquireSpinLockShared(&Ctx->TransitionLock);
        if ((InterlockedGet(&Ctx->Flags) & (TUN_FLAGS_PRESENT | TUN_FLAGS_RUNNING)) !=
            (TUN_FLAGS_PRESENT | TUN_FLAGS_RUNNING))
            goto skipNbl;

        if (!NT_SUCCESS(IoAcquireRemoveLock(&Ctx->Device.Receive.ActiveNbls.RemoveLock, Nbl)))
            goto skipNbl;

        NdisMIndicateReceiveNetBufferLists(
            Ctx->MiniportAdapterHandle,
            Nbl,
            NDIS_DEFAULT_PORT_NUMBER,
            1,
            NDIS_RECEIVE_FLAGS_DISPATCH_LEVEL | NDIS_RECEIVE_FLAGS_SINGLE_ETHER_TYPE);

        ExReleaseSpinLockShared(&Ctx->TransitionLock, Irql);
        continue;

    skipNbl:
        NET_BUFFER_LIST_NEXT_NBL(Nbl) = NULL;
        TunReturnNetBufferLists(Ctx, Nbl, TUN_RETURN_FLAGS_DISCARD);
        ExReleaseSpinLockShared(&Ctx->TransitionLock, Irql);
    }

    /* Wait for all NBLs to return: 1. To prevent race between proceeding and invalidating ring head. 2. To have
     * TunDispatchUnregisterBuffers() implicitly wait before releasing ring MDL used by NBL(s). */
    if (NT_SUCCESS(IoAcquireRemoveLock(&Ctx->Device.Receive.ActiveNbls.RemoveLock, NULL)))
        IoReleaseRemoveLockAndWait(&Ctx->Device.Receive.ActiveNbls.RemoveLock, NULL);
cleanup:
    InterlockedExchangeU(&Ring->Head, MAXULONG);
}

_IRQL_requires_max_(PASSIVE_LEVEL)
_Must_inspect_result_
static NTSTATUS
TunRegisterBuffers(_Inout_ TUN_CTX *Ctx, _Inout_ IRP *Irp)
{
    NTSTATUS Status;
    IO_STACK_LOCATION *Stack = IoGetCurrentIrpStackLocation(Irp);

    if (InterlockedCompareExchangePointer(&Ctx->Device.Owner, Stack->FileObject, NULL) != NULL)
        return STATUS_ALREADY_INITIALIZED;

    TUN_REGISTER_RINGS *Rrb = Irp->AssociatedIrp.SystemBuffer;
    if (Status = STATUS_INVALID_PARAMETER, Stack->Parameters.DeviceIoControl.InputBufferLength != sizeof(*Rrb))
        goto cleanupResetOwner;

    Ctx->Device.Send.Capacity = TUN_RING_CAPACITY(Rrb->Send.RingSize);
    if (Status = STATUS_INVALID_PARAMETER,
        (Ctx->Device.Send.Capacity < TUN_MIN_RING_CAPACITY || Ctx->Device.Send.Capacity > TUN_MAX_RING_CAPACITY ||
         PopulationCount64(Ctx->Device.Send.Capacity) != 1 || !Rrb->Send.TailMoved || !Rrb->Send.Ring))
        goto cleanupResetOwner;

    if (!NT_SUCCESS(
            Status = ObReferenceObjectByHandle(
                Rrb->Send.TailMoved,
                /* We will not wait on send ring tail moved event. */
                EVENT_MODIFY_STATE,
                *ExEventObjectType,
                UserMode,
                &Ctx->Device.Send.TailMoved,
                NULL)))
        goto cleanupResetOwner;

    Ctx->Device.Send.Mdl = IoAllocateMdl(Rrb->Send.Ring, Rrb->Send.RingSize, FALSE, FALSE, NULL);
    if (Status = STATUS_INSUFFICIENT_RESOURCES, !Ctx->Device.Send.Mdl)
        goto cleanupSendTailMoved;
    try
    {
        Status = STATUS_INVALID_USER_BUFFER;
        MmProbeAndLockPages(Ctx->Device.Send.Mdl, UserMode, IoWriteAccess);
    }
    except(EXCEPTION_EXECUTE_HANDLER) { goto cleanupSendMdl; }

    Ctx->Device.Send.Ring =
        MmGetSystemAddressForMdlSafe(Ctx->Device.Send.Mdl, NormalPagePriority | MdlMappingNoExecute);
    if (Status = STATUS_INSUFFICIENT_RESOURCES, !Ctx->Device.Send.Ring)
        goto cleanupSendUnlockPages;

    Ctx->Device.Send.RingTail = InterlockedGetU(&Ctx->Device.Send.Ring->Tail);
    if (Status = STATUS_INVALID_PARAMETER, Ctx->Device.Send.RingTail >= Ctx->Device.Send.Capacity)
        goto cleanupSendUnlockPages;

    Ctx->Device.Receive.Capacity = TUN_RING_CAPACITY(Rrb->Receive.RingSize);
    if (Status = STATUS_INVALID_PARAMETER,
        (Ctx->Device.Receive.Capacity < TUN_MIN_RING_CAPACITY || Ctx->Device.Receive.Capacity > TUN_MAX_RING_CAPACITY ||
         PopulationCount64(Ctx->Device.Receive.Capacity) != 1 || !Rrb->Receive.TailMoved || !Rrb->Receive.Ring))
        goto cleanupSendUnlockPages;

    if (!NT_SUCCESS(
            Status = ObReferenceObjectByHandle(
                Rrb->Receive.TailMoved,
                /* We need to clear receive ring TailMoved event on transition to non-alertable state. */
                SYNCHRONIZE | EVENT_MODIFY_STATE,
                *ExEventObjectType,
                UserMode,
                &Ctx->Device.Receive.TailMoved,
                NULL)))
        goto cleanupSendUnlockPages;

    Ctx->Device.Receive.Mdl = IoAllocateMdl(Rrb->Receive.Ring, Rrb->Receive.RingSize, FALSE, FALSE, NULL);
    if (Status = STATUS_INSUFFICIENT_RESOURCES, !Ctx->Device.Receive.Mdl)
        goto cleanupReceiveTailMoved;
    try
    {
        Status = STATUS_INVALID_USER_BUFFER;
        MmProbeAndLockPages(Ctx->Device.Receive.Mdl, UserMode, IoWriteAccess);
    }
    except(EXCEPTION_EXECUTE_HANDLER) { goto cleanupReceiveMdl; }

    Ctx->Device.Receive.Ring =
        MmGetSystemAddressForMdlSafe(Ctx->Device.Receive.Mdl, NormalPagePriority | MdlMappingNoExecute);
    if (Status = STATUS_INSUFFICIENT_RESOURCES, !Ctx->Device.Receive.Ring)
        goto cleanupReceiveUnlockPages;

    KeClearEvent(&Ctx->Device.Disconnected);

    OBJECT_ATTRIBUTES ObjectAttributes;
    InitializeObjectAttributes(&ObjectAttributes, NULL, OBJ_KERNEL_HANDLE, NULL, NULL);
    if (Status = NDIS_STATUS_FAILURE,
        !NT_SUCCESS(PsCreateSystemThread(
            &Ctx->Device.Receive.Thread, THREAD_ALL_ACCESS, &ObjectAttributes, NULL, NULL, TunProcessReceiveData, Ctx)))
        goto cleanupFlagsConnected;

    TunIndicateStatus(Ctx->MiniportAdapterHandle, MediaConnectStateConnected);
    return STATUS_SUCCESS;

cleanupFlagsConnected:
    KeSetEvent(&Ctx->Device.Disconnected, IO_NO_INCREMENT, FALSE);
    ExReleaseSpinLockExclusive(
        &Ctx->TransitionLock,
        ExAcquireSpinLockExclusive(&Ctx->TransitionLock)); /* Ensure above change is visible to all readers. */
cleanupReceiveUnlockPages:
    MmUnlockPages(Ctx->Device.Receive.Mdl);
cleanupReceiveMdl:
    IoFreeMdl(Ctx->Device.Receive.Mdl);
cleanupReceiveTailMoved:
    ObDereferenceObject(Ctx->Device.Receive.TailMoved);
cleanupSendUnlockPages:
    MmUnlockPages(Ctx->Device.Send.Mdl);
cleanupSendMdl:
    IoFreeMdl(Ctx->Device.Send.Mdl);
cleanupSendTailMoved:
    ObDereferenceObject(Ctx->Device.Send.TailMoved);
cleanupResetOwner:
    InterlockedExchangePointer(&Ctx->Device.Owner, NULL);
    return Status;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
static VOID
TunUnregisterBuffers(_Inout_ TUN_CTX *Ctx, _In_ FILE_OBJECT *Owner)
{
    if (InterlockedCompareExchangePointer(&Ctx->Device.Owner, NULL, Owner) != Owner)
        return;

    TunIndicateStatus(Ctx->MiniportAdapterHandle, MediaConnectStateDisconnected);

    KeSetEvent(&Ctx->Device.Disconnected, IO_NO_INCREMENT, FALSE);
    ExReleaseSpinLockExclusive(
        &Ctx->TransitionLock,
        ExAcquireSpinLockExclusive(&Ctx->TransitionLock)); /* Ensure above change is visible to all readers. */

    PKTHREAD ThreadObject;
    if (NT_SUCCESS(
            ObReferenceObjectByHandle(Ctx->Device.Receive.Thread, SYNCHRONIZE, NULL, KernelMode, &ThreadObject, NULL)))
    {
        KeWaitForSingleObject(ThreadObject, Executive, KernelMode, FALSE, NULL);
        ObDereferenceObject(ThreadObject);
    }
    ZwClose(Ctx->Device.Receive.Thread);

    InterlockedExchangeU(&Ctx->Device.Send.Ring->Tail, MAXULONG);
    KeSetEvent(Ctx->Device.Send.TailMoved, IO_NO_INCREMENT, FALSE);

    MmUnlockPages(Ctx->Device.Receive.Mdl);
    IoFreeMdl(Ctx->Device.Receive.Mdl);
    ObDereferenceObject(Ctx->Device.Receive.TailMoved);
    MmUnlockPages(Ctx->Device.Send.Mdl);
    IoFreeMdl(Ctx->Device.Send.Mdl);
    ObDereferenceObject(Ctx->Device.Send.TailMoved);
}

static NTSTATUS TunInitializeDispatchSecurityDescriptor(VOID)
{
    NTSTATUS Status;
    SID_IDENTIFIER_AUTHORITY NtAuthority = SECURITY_NT_AUTHORITY;
    SID LocalSystem = { 0 };
    if (!NT_SUCCESS(Status = RtlInitializeSid(&LocalSystem, &NtAuthority, 1)))
        return Status;
    LocalSystem.SubAuthority[0] = 18;
    struct
    {
        ACL Dacl;
        ACCESS_ALLOWED_ACE AceFiller;
        SID SidFiller;
    } DaclStorage = { 0 };
    if (!NT_SUCCESS(Status = RtlCreateAcl(&DaclStorage.Dacl, sizeof(DaclStorage), ACL_REVISION)))
        return Status;
    ACCESS_MASK AccessMask = GENERIC_ALL;
    RtlMapGenericMask(&AccessMask, IoGetFileObjectGenericMapping());
    if (!NT_SUCCESS(Status = RtlAddAccessAllowedAce(&DaclStorage.Dacl, ACL_REVISION, AccessMask, &LocalSystem)))
        return Status;
    SECURITY_DESCRIPTOR SecurityDescriptor = { 0 };
    if (!NT_SUCCESS(Status = RtlCreateSecurityDescriptor(&SecurityDescriptor, SECURITY_DESCRIPTOR_REVISION)))
        return Status;
    if (!NT_SUCCESS(Status = RtlSetDaclSecurityDescriptor(&SecurityDescriptor, TRUE, &DaclStorage.Dacl, FALSE)))
        return Status;
    SecurityDescriptor.Control |= SE_DACL_PROTECTED;
    ULONG RequiredBytes = 0;
    Status = RtlAbsoluteToSelfRelativeSD(&SecurityDescriptor, NULL, &RequiredBytes);
    if (Status != STATUS_BUFFER_TOO_SMALL)
		return NT_SUCCESS(Status) ? STATUS_INSUFFICIENT_RESOURCES : Status;
    TunDispatchSecurityDescriptor = ExAllocatePoolWithTag(NonPagedPoolNx, RequiredBytes, TUN_MEMORY_TAG);
    if (!TunDispatchSecurityDescriptor)
        return STATUS_INSUFFICIENT_RESOURCES;
    Status = RtlAbsoluteToSelfRelativeSD(&SecurityDescriptor, TunDispatchSecurityDescriptor, &RequiredBytes);
    if (!NT_SUCCESS(Status))
        return Status;
    return STATUS_SUCCESS;
}

_Dispatch_type_(IRP_MJ_DEVICE_CONTROL)
static DRIVER_DISPATCH_PAGED TunDispatchDeviceControl;
_Use_decl_annotations_
static NTSTATUS
TunDispatchDeviceControl(DEVICE_OBJECT *DeviceObject, IRP *Irp)
{
    IO_STACK_LOCATION *Stack = IoGetCurrentIrpStackLocation(Irp);
    if (Stack->Parameters.DeviceIoControl.IoControlCode != TUN_IOCTL_REGISTER_RINGS)
        return NdisDispatchDeviceControl(DeviceObject, Irp);

    SECURITY_SUBJECT_CONTEXT SubjectContext;
    SeCaptureSubjectContext(&SubjectContext);
    NTSTATUS Status;
    ACCESS_MASK GrantedAccess;
    BOOLEAN HasAccess = SeAccessCheck(
        TunDispatchSecurityDescriptor,
        &SubjectContext,
        FALSE,
        FILE_WRITE_DATA,
        0,
        NULL,
        IoGetFileObjectGenericMapping(),
        Irp->RequestorMode,
        &GrantedAccess,
        &Status);
    SeReleaseSubjectContext(&SubjectContext);
    if (!HasAccess)
        goto cleanup;
    ExAcquireResourceSharedLite(&TunDispatchCtxGuard, TRUE);
#pragma warning(suppress : 28175)
    TUN_CTX *Ctx = DeviceObject->Reserved;
    Status = NDIS_STATUS_ADAPTER_NOT_READY;
    if (Ctx)
        Status = TunRegisterBuffers(Ctx, Irp);
    ExReleaseResourceLite(&TunDispatchCtxGuard);
cleanup:
    Irp->IoStatus.Status = Status;
    Irp->IoStatus.Information = 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return Status;
}

_Dispatch_type_(IRP_MJ_CLOSE)
static DRIVER_DISPATCH_PAGED TunDispatchClose;
_Use_decl_annotations_
static NTSTATUS
TunDispatchClose(DEVICE_OBJECT *DeviceObject, IRP *Irp)
{
    ExAcquireResourceSharedLite(&TunDispatchCtxGuard, TRUE);
#pragma warning(suppress : 28175)
    TUN_CTX *Ctx = DeviceObject->Reserved;
    if (Ctx)
        TunUnregisterBuffers(Ctx, IoGetCurrentIrpStackLocation(Irp)->FileObject);
    ExReleaseResourceLite(&TunDispatchCtxGuard);
    return NdisDispatchClose(DeviceObject, Irp);
}

static MINIPORT_RESTART TunRestart;
_Use_decl_annotations_
static NDIS_STATUS
TunRestart(NDIS_HANDLE MiniportAdapterContext, PNDIS_MINIPORT_RESTART_PARAMETERS MiniportRestartParameters)
{
    TUN_CTX *Ctx = (TUN_CTX *)MiniportAdapterContext;
    InterlockedOr(&Ctx->Flags, TUN_FLAGS_RUNNING);
    return NDIS_STATUS_SUCCESS;
}

static MINIPORT_PAUSE TunPause;
_Use_decl_annotations_
static NDIS_STATUS
TunPause(NDIS_HANDLE MiniportAdapterContext, PNDIS_MINIPORT_PAUSE_PARAMETERS MiniportPauseParameters)
{
    TUN_CTX *Ctx = (TUN_CTX *)MiniportAdapterContext;

    InterlockedAnd(&Ctx->Flags, ~TUN_FLAGS_RUNNING);
    ExReleaseSpinLockExclusive(
        &Ctx->TransitionLock,
        ExAcquireSpinLockExclusive(&Ctx->TransitionLock)); /* Ensure above change is visible to all readers. */

    if (NT_SUCCESS(IoAcquireRemoveLock(&Ctx->Device.Receive.ActiveNbls.RemoveLock, NULL)))
        IoReleaseRemoveLockAndWait(&Ctx->Device.Receive.ActiveNbls.RemoveLock, NULL);

    return NDIS_STATUS_SUCCESS;
}

static MINIPORT_DEVICE_PNP_EVENT_NOTIFY TunDevicePnPEventNotify;
_Use_decl_annotations_
static VOID
TunDevicePnPEventNotify(NDIS_HANDLE MiniportAdapterContext, PNET_DEVICE_PNP_EVENT NetDevicePnPEvent)
{
}

static MINIPORT_INITIALIZE TunInitializeEx;
_Use_decl_annotations_
static NDIS_STATUS
TunInitializeEx(
    NDIS_HANDLE MiniportAdapterHandle,
    NDIS_HANDLE MiniportDriverContext,
    PNDIS_MINIPORT_INIT_PARAMETERS MiniportInitParameters)
{
    NDIS_STATUS Status;

    if (!MiniportAdapterHandle)
        return NDIS_STATUS_FAILURE;

/* Leaking memory 'Ctx'. Note: 'Ctx' is freed in TunHaltEx or on failure. */
#pragma warning(suppress : 6014)
    TUN_CTX *Ctx = ExAllocatePoolWithTag(NonPagedPoolNx, sizeof(*Ctx), TUN_MEMORY_TAG);
    if (!Ctx)
        return NDIS_STATUS_FAILURE;
    NdisZeroMemory(Ctx, sizeof(*Ctx));

    Ctx->MiniportAdapterHandle = MiniportAdapterHandle;

    NdisMGetDeviceProperty(MiniportAdapterHandle, NULL, &Ctx->FunctionalDeviceObject, NULL, NULL, NULL);
    /* Reverse engineering indicates that we'd be better off calling
     * NdisWdfGetAdapterContextFromAdapterHandle(functional_device),
     * which points to our TUN_CTX object directly, but this isn't
     * available before Windows 10, so for now we just stick it into
     * this reserved field. Revisit this when we drop support for old
     * Windows versions. */
#pragma warning(suppress : 28175)
    ASSERT(!Ctx->FunctionalDeviceObject->Reserved);
#pragma warning(suppress : 28175)
    Ctx->FunctionalDeviceObject->Reserved = Ctx;

    Ctx->Statistics.Header.Type = NDIS_OBJECT_TYPE_DEFAULT;
    Ctx->Statistics.Header.Revision = NDIS_STATISTICS_INFO_REVISION_1;
    Ctx->Statistics.Header.Size = NDIS_SIZEOF_STATISTICS_INFO_REVISION_1;
    Ctx->Statistics.SupportedStatistics =
        NDIS_STATISTICS_FLAGS_VALID_DIRECTED_FRAMES_RCV | NDIS_STATISTICS_FLAGS_VALID_MULTICAST_FRAMES_RCV |
        NDIS_STATISTICS_FLAGS_VALID_BROADCAST_FRAMES_RCV | NDIS_STATISTICS_FLAGS_VALID_BYTES_RCV |
        NDIS_STATISTICS_FLAGS_VALID_RCV_DISCARDS | NDIS_STATISTICS_FLAGS_VALID_RCV_ERROR |
        NDIS_STATISTICS_FLAGS_VALID_DIRECTED_FRAMES_XMIT | NDIS_STATISTICS_FLAGS_VALID_MULTICAST_FRAMES_XMIT |
        NDIS_STATISTICS_FLAGS_VALID_BROADCAST_FRAMES_XMIT | NDIS_STATISTICS_FLAGS_VALID_BYTES_XMIT |
        NDIS_STATISTICS_FLAGS_VALID_XMIT_ERROR | NDIS_STATISTICS_FLAGS_VALID_XMIT_DISCARDS |
        NDIS_STATISTICS_FLAGS_VALID_DIRECTED_BYTES_RCV | NDIS_STATISTICS_FLAGS_VALID_MULTICAST_BYTES_RCV |
        NDIS_STATISTICS_FLAGS_VALID_BROADCAST_BYTES_RCV | NDIS_STATISTICS_FLAGS_VALID_DIRECTED_BYTES_XMIT |
        NDIS_STATISTICS_FLAGS_VALID_MULTICAST_BYTES_XMIT | NDIS_STATISTICS_FLAGS_VALID_BROADCAST_BYTES_XMIT;
    KeInitializeEvent(&Ctx->Device.Disconnected, NotificationEvent, TRUE);
    KeInitializeSpinLock(&Ctx->Device.Send.Lock);
    KeInitializeSpinLock(&Ctx->Device.Receive.Lock);
    IoInitializeRemoveLock(&Ctx->Device.Receive.ActiveNbls.RemoveLock, TUN_MEMORY_TAG, 0, 0);

    NET_BUFFER_LIST_POOL_PARAMETERS NblPoolParameters = {
        .Header = { .Type = NDIS_OBJECT_TYPE_DEFAULT,
                    .Revision = NET_BUFFER_LIST_POOL_PARAMETERS_REVISION_1,
                    .Size = NDIS_SIZEOF_NET_BUFFER_LIST_POOL_PARAMETERS_REVISION_1 },
        .ProtocolId = NDIS_PROTOCOL_ID_DEFAULT,
        .fAllocateNetBuffer = TRUE,
        .PoolTag = TUN_MEMORY_TAG
    };
/* Leaking memory 'Ctx->NblPool'. Note: 'Ctx->NblPool' is freed in TunHaltEx or on failure. */
#pragma warning(suppress : 6014)
    Ctx->NblPool = NdisAllocateNetBufferListPool(MiniportAdapterHandle, &NblPoolParameters);
    if (Status = NDIS_STATUS_FAILURE, !Ctx->NblPool)
        goto cleanupFreeCtx;

    NDIS_MINIPORT_ADAPTER_REGISTRATION_ATTRIBUTES AdapterRegistrationAttributes = {
        .Header = { .Type = NDIS_OBJECT_TYPE_MINIPORT_ADAPTER_REGISTRATION_ATTRIBUTES,
                    .Revision = NdisVersion < NDIS_RUNTIME_VERSION_630
                                    ? NDIS_MINIPORT_ADAPTER_REGISTRATION_ATTRIBUTES_REVISION_1
                                    : NDIS_MINIPORT_ADAPTER_REGISTRATION_ATTRIBUTES_REVISION_2,
                    .Size = NdisVersion < NDIS_RUNTIME_VERSION_630
                                ? NDIS_SIZEOF_MINIPORT_ADAPTER_REGISTRATION_ATTRIBUTES_REVISION_1
                                : NDIS_SIZEOF_MINIPORT_ADAPTER_REGISTRATION_ATTRIBUTES_REVISION_2 },
        .AttributeFlags = NDIS_MINIPORT_ATTRIBUTES_NO_HALT_ON_SUSPEND | NDIS_MINIPORT_ATTRIBUTES_SURPRISE_REMOVE_OK,
        .InterfaceType = NdisInterfaceInternal,
        .MiniportAdapterContext = Ctx
    };
    if (Status = NDIS_STATUS_FAILURE,
        !NT_SUCCESS(NdisMSetMiniportAttributes(
            MiniportAdapterHandle, (PNDIS_MINIPORT_ADAPTER_ATTRIBUTES)&AdapterRegistrationAttributes)))
        goto cleanupFreeNblPool;

    NDIS_PM_CAPABILITIES PmCapabilities = {
        .Header = { .Type = NDIS_OBJECT_TYPE_DEFAULT,
                    .Revision = NdisVersion < NDIS_RUNTIME_VERSION_630 ? NDIS_PM_CAPABILITIES_REVISION_1
                                                                       : NDIS_PM_CAPABILITIES_REVISION_2,
                    .Size = NdisVersion < NDIS_RUNTIME_VERSION_630 ? NDIS_SIZEOF_NDIS_PM_CAPABILITIES_REVISION_1
                                                                   : NDIS_SIZEOF_NDIS_PM_CAPABILITIES_REVISION_2 },
        .MinMagicPacketWakeUp = NdisDeviceStateUnspecified,
        .MinPatternWakeUp = NdisDeviceStateUnspecified,
        .MinLinkChangeWakeUp = NdisDeviceStateUnspecified
    };
    static NDIS_OID SupportedOids[] = { OID_GEN_MAXIMUM_TOTAL_SIZE,
                                        OID_GEN_CURRENT_LOOKAHEAD,
                                        OID_GEN_TRANSMIT_BUFFER_SPACE,
                                        OID_GEN_RECEIVE_BUFFER_SPACE,
                                        OID_GEN_TRANSMIT_BLOCK_SIZE,
                                        OID_GEN_RECEIVE_BLOCK_SIZE,
                                        OID_GEN_VENDOR_DESCRIPTION,
                                        OID_GEN_VENDOR_ID,
                                        OID_GEN_VENDOR_DRIVER_VERSION,
                                        OID_GEN_XMIT_OK,
                                        OID_GEN_RCV_OK,
                                        OID_GEN_CURRENT_PACKET_FILTER,
                                        OID_GEN_STATISTICS,
                                        OID_GEN_INTERRUPT_MODERATION,
                                        OID_GEN_LINK_PARAMETERS,
                                        OID_PNP_SET_POWER,
                                        OID_PNP_QUERY_POWER };
    NDIS_MINIPORT_ADAPTER_GENERAL_ATTRIBUTES AdapterGeneralAttributes = {
        .Header = { .Type = NDIS_OBJECT_TYPE_MINIPORT_ADAPTER_GENERAL_ATTRIBUTES,
                    .Revision = NDIS_MINIPORT_ADAPTER_GENERAL_ATTRIBUTES_REVISION_2,
                    .Size = NDIS_SIZEOF_MINIPORT_ADAPTER_GENERAL_ATTRIBUTES_REVISION_2 },
        .MediaType = NdisMediumIP,
        .PhysicalMediumType = NdisPhysicalMediumUnspecified,
        .MtuSize = TUN_MAX_IP_PACKET_SIZE,
        .MaxXmitLinkSpeed = TUN_LINK_SPEED,
        .MaxRcvLinkSpeed = TUN_LINK_SPEED,
        .RcvLinkSpeed = TUN_LINK_SPEED,
        .XmitLinkSpeed = TUN_LINK_SPEED,
        .MediaConnectState = MediaConnectStateDisconnected,
        .LookaheadSize = TUN_MAX_IP_PACKET_SIZE,
        .MacOptions =
            NDIS_MAC_OPTION_TRANSFERS_NOT_PEND | NDIS_MAC_OPTION_COPY_LOOKAHEAD_DATA | NDIS_MAC_OPTION_NO_LOOPBACK,
        .SupportedPacketFilters = NDIS_PACKET_TYPE_DIRECTED | NDIS_PACKET_TYPE_ALL_MULTICAST |
                                  NDIS_PACKET_TYPE_BROADCAST | NDIS_PACKET_TYPE_ALL_LOCAL |
                                  NDIS_PACKET_TYPE_ALL_FUNCTIONAL,
        .AccessType = NET_IF_ACCESS_BROADCAST,
        .DirectionType = NET_IF_DIRECTION_SENDRECEIVE,
        .ConnectionType = NET_IF_CONNECTION_DEDICATED,
        .IfType = IF_TYPE_PROP_VIRTUAL,
        .IfConnectorPresent = FALSE,
        .SupportedStatistics = Ctx->Statistics.SupportedStatistics,
        .SupportedPauseFunctions = NdisPauseFunctionsUnsupported,
        .AutoNegotiationFlags =
            NDIS_LINK_STATE_XMIT_LINK_SPEED_AUTO_NEGOTIATED | NDIS_LINK_STATE_RCV_LINK_SPEED_AUTO_NEGOTIATED |
            NDIS_LINK_STATE_DUPLEX_AUTO_NEGOTIATED | NDIS_LINK_STATE_PAUSE_FUNCTIONS_AUTO_NEGOTIATED,
        .SupportedOidList = SupportedOids,
        .SupportedOidListLength = sizeof(SupportedOids),
        .PowerManagementCapabilitiesEx = &PmCapabilities
    };
    if (Status = NDIS_STATUS_FAILURE,
        !NT_SUCCESS(NdisMSetMiniportAttributes(
            MiniportAdapterHandle, (PNDIS_MINIPORT_ADAPTER_ATTRIBUTES)&AdapterGeneralAttributes)))
        goto cleanupFreeNblPool;

    /* A miniport driver can call NdisMIndicateStatusEx after setting its
     * registration attributes even if the driver is still in the context
     * of the MiniportInitializeEx function. */
    TunIndicateStatus(Ctx->MiniportAdapterHandle, MediaConnectStateDisconnected);
    InterlockedOr(&Ctx->Flags, TUN_FLAGS_PRESENT);
    return NDIS_STATUS_SUCCESS;

cleanupFreeNblPool:
    NdisFreeNetBufferListPool(Ctx->NblPool);
cleanupFreeCtx:
    ExFreePoolWithTag(Ctx, TUN_MEMORY_TAG);
    return Status;
}

static MINIPORT_HALT TunHaltEx;
_Use_decl_annotations_
static VOID
TunHaltEx(NDIS_HANDLE MiniportAdapterContext, NDIS_HALT_ACTION HaltAction)
{
    TUN_CTX *Ctx = (TUN_CTX *)MiniportAdapterContext;

    InterlockedAnd(&Ctx->Flags, ~TUN_FLAGS_PRESENT);
    ExReleaseSpinLockExclusive(
        &Ctx->TransitionLock,
        ExAcquireSpinLockExclusive(&Ctx->TransitionLock)); /* Ensure above change is visible to all readers. */
    NdisFreeNetBufferListPool(Ctx->NblPool);

    InterlockedExchangePointer(&Ctx->MiniportAdapterHandle, NULL);
#pragma warning(suppress : 28175)
    InterlockedExchangePointer(&Ctx->FunctionalDeviceObject->Reserved, NULL);
    ExAcquireResourceExclusiveLite(&TunDispatchCtxGuard, TRUE); /* Ensure above change is visible to all readers. */
    ExReleaseResourceLite(&TunDispatchCtxGuard);
    ExFreePoolWithTag(Ctx, TUN_MEMORY_TAG);
}

static MINIPORT_SHUTDOWN TunShutdownEx;
_Use_decl_annotations_
static VOID
TunShutdownEx(NDIS_HANDLE MiniportAdapterContext, NDIS_SHUTDOWN_ACTION ShutdownAction)
{
}

_IRQL_requires_max_(APC_LEVEL)
_Must_inspect_result_
static NDIS_STATUS
TunOidQueryWrite(_Inout_ NDIS_OID_REQUEST *OidRequest, _In_ ULONG Value)
{
    if (OidRequest->DATA.QUERY_INFORMATION.InformationBufferLength < sizeof(ULONG))
    {
        OidRequest->DATA.QUERY_INFORMATION.BytesNeeded = sizeof(ULONG);
        OidRequest->DATA.QUERY_INFORMATION.BytesWritten = 0;
        return NDIS_STATUS_BUFFER_TOO_SHORT;
    }

    OidRequest->DATA.QUERY_INFORMATION.BytesNeeded = OidRequest->DATA.QUERY_INFORMATION.BytesWritten = sizeof(ULONG);
    *(ULONG *)OidRequest->DATA.QUERY_INFORMATION.InformationBuffer = Value;
    return NDIS_STATUS_SUCCESS;
}

_IRQL_requires_max_(APC_LEVEL)
_Must_inspect_result_
static NDIS_STATUS
TunOidQueryWrite32or64(_Inout_ NDIS_OID_REQUEST *OidRequest, _In_ ULONG64 Value)
{
    if (OidRequest->DATA.QUERY_INFORMATION.InformationBufferLength < sizeof(ULONG))
    {
        OidRequest->DATA.QUERY_INFORMATION.BytesNeeded = sizeof(ULONG64);
        OidRequest->DATA.QUERY_INFORMATION.BytesWritten = 0;
        return NDIS_STATUS_BUFFER_TOO_SHORT;
    }

    if (OidRequest->DATA.QUERY_INFORMATION.InformationBufferLength < sizeof(ULONG64))
    {
        OidRequest->DATA.QUERY_INFORMATION.BytesNeeded = sizeof(ULONG64);
        OidRequest->DATA.QUERY_INFORMATION.BytesWritten = sizeof(ULONG);
        *(ULONG *)OidRequest->DATA.QUERY_INFORMATION.InformationBuffer = (ULONG)(Value & 0xffffffff);
        return NDIS_STATUS_SUCCESS;
    }

    OidRequest->DATA.QUERY_INFORMATION.BytesNeeded = OidRequest->DATA.QUERY_INFORMATION.BytesWritten = sizeof(ULONG64);
    *(ULONG64 *)OidRequest->DATA.QUERY_INFORMATION.InformationBuffer = Value;
    return NDIS_STATUS_SUCCESS;
}

_IRQL_requires_max_(APC_LEVEL)
_Must_inspect_result_
static NDIS_STATUS
TunOidQueryWriteBuf(_Inout_ NDIS_OID_REQUEST *OidRequest, _In_bytecount_(Size) const void *Buf, _In_ ULONG Size)
{
    if (OidRequest->DATA.QUERY_INFORMATION.InformationBufferLength < Size)
    {
        OidRequest->DATA.QUERY_INFORMATION.BytesNeeded = Size;
        OidRequest->DATA.QUERY_INFORMATION.BytesWritten = 0;
        return NDIS_STATUS_BUFFER_TOO_SHORT;
    }

    OidRequest->DATA.QUERY_INFORMATION.BytesNeeded = OidRequest->DATA.QUERY_INFORMATION.BytesWritten = Size;
    NdisMoveMemory(OidRequest->DATA.QUERY_INFORMATION.InformationBuffer, Buf, Size);
    return NDIS_STATUS_SUCCESS;
}

_IRQL_requires_max_(APC_LEVEL)
_Must_inspect_result_
static NDIS_STATUS
TunOidQuery(_Inout_ TUN_CTX *Ctx, _Inout_ NDIS_OID_REQUEST *OidRequest)
{
    ASSERT(
        OidRequest->RequestType == NdisRequestQueryInformation ||
        OidRequest->RequestType == NdisRequestQueryStatistics);

    switch (OidRequest->DATA.QUERY_INFORMATION.Oid)
    {
    case OID_GEN_MAXIMUM_TOTAL_SIZE:
    case OID_GEN_TRANSMIT_BLOCK_SIZE:
    case OID_GEN_RECEIVE_BLOCK_SIZE:
        return TunOidQueryWrite(OidRequest, TUN_MAX_IP_PACKET_SIZE);

    case OID_GEN_TRANSMIT_BUFFER_SPACE:
        return TunOidQueryWrite(OidRequest, TUN_MAX_RING_CAPACITY);

    case OID_GEN_RECEIVE_BUFFER_SPACE:
        return TunOidQueryWrite(OidRequest, TUN_MAX_RING_CAPACITY);

    case OID_GEN_VENDOR_ID:
        return TunOidQueryWrite(OidRequest, TUN_HTONL(TUN_VENDOR_ID));

    case OID_GEN_VENDOR_DESCRIPTION:
        return TunOidQueryWriteBuf(OidRequest, TUN_VENDOR_NAME, (ULONG)sizeof(TUN_VENDOR_NAME));

    case OID_GEN_VENDOR_DRIVER_VERSION:
        return TunOidQueryWrite(OidRequest, (WINTUN_VERSION_MAJ << 16) | WINTUN_VERSION_MIN);

    case OID_GEN_XMIT_OK:
        return TunOidQueryWrite32or64(
            OidRequest,
            InterlockedGet64((LONG64 *)&Ctx->Statistics.ifHCOutUcastPkts) +
                InterlockedGet64((LONG64 *)&Ctx->Statistics.ifHCOutMulticastPkts) +
                InterlockedGet64((LONG64 *)&Ctx->Statistics.ifHCOutBroadcastPkts));

    case OID_GEN_RCV_OK:
        return TunOidQueryWrite32or64(
            OidRequest,
            InterlockedGet64((LONG64 *)&Ctx->Statistics.ifHCInUcastPkts) +
                InterlockedGet64((LONG64 *)&Ctx->Statistics.ifHCInMulticastPkts) +
                InterlockedGet64((LONG64 *)&Ctx->Statistics.ifHCInBroadcastPkts));

    case OID_GEN_STATISTICS:
        return TunOidQueryWriteBuf(OidRequest, &Ctx->Statistics, (ULONG)sizeof(Ctx->Statistics));

    case OID_GEN_INTERRUPT_MODERATION: {
        static const NDIS_INTERRUPT_MODERATION_PARAMETERS InterruptParameters = {
            .Header = { .Type = NDIS_OBJECT_TYPE_DEFAULT,
                        .Revision = NDIS_INTERRUPT_MODERATION_PARAMETERS_REVISION_1,
                        .Size = NDIS_SIZEOF_INTERRUPT_MODERATION_PARAMETERS_REVISION_1 },
            .InterruptModeration = NdisInterruptModerationNotSupported
        };
        return TunOidQueryWriteBuf(OidRequest, &InterruptParameters, (ULONG)sizeof(InterruptParameters));
    }

    case OID_PNP_QUERY_POWER:
        OidRequest->DATA.QUERY_INFORMATION.BytesNeeded = OidRequest->DATA.QUERY_INFORMATION.BytesWritten = 0;
        return NDIS_STATUS_SUCCESS;
    }

    OidRequest->DATA.QUERY_INFORMATION.BytesWritten = 0;
    return NDIS_STATUS_NOT_SUPPORTED;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
static NDIS_STATUS
TunOidSet(_Inout_ TUN_CTX *Ctx, _Inout_ NDIS_OID_REQUEST *OidRequest)
{
    ASSERT(OidRequest->RequestType == NdisRequestSetInformation);

    OidRequest->DATA.SET_INFORMATION.BytesNeeded = OidRequest->DATA.SET_INFORMATION.BytesRead = 0;

    switch (OidRequest->DATA.SET_INFORMATION.Oid)
    {
    case OID_GEN_CURRENT_PACKET_FILTER:
    case OID_GEN_CURRENT_LOOKAHEAD:
        if (OidRequest->DATA.SET_INFORMATION.InformationBufferLength != 4)
        {
            OidRequest->DATA.SET_INFORMATION.BytesNeeded = 4;
            return NDIS_STATUS_INVALID_LENGTH;
        }
        OidRequest->DATA.SET_INFORMATION.BytesRead = 4;
        return NDIS_STATUS_SUCCESS;

    case OID_GEN_LINK_PARAMETERS:
        OidRequest->DATA.SET_INFORMATION.BytesRead = OidRequest->DATA.SET_INFORMATION.InformationBufferLength;
        return NDIS_STATUS_SUCCESS;

    case OID_GEN_INTERRUPT_MODERATION:
        return NDIS_STATUS_INVALID_DATA;

    case OID_PNP_SET_POWER:
        if (OidRequest->DATA.SET_INFORMATION.InformationBufferLength != sizeof(NDIS_DEVICE_POWER_STATE))
        {
            OidRequest->DATA.SET_INFORMATION.BytesNeeded = sizeof(NDIS_DEVICE_POWER_STATE);
            return NDIS_STATUS_INVALID_LENGTH;
        }
        OidRequest->DATA.SET_INFORMATION.BytesRead = sizeof(NDIS_DEVICE_POWER_STATE);
        return NDIS_STATUS_SUCCESS;
    }

    return NDIS_STATUS_NOT_SUPPORTED;
}

static MINIPORT_OID_REQUEST TunOidRequest;
_Use_decl_annotations_
static NDIS_STATUS
TunOidRequest(NDIS_HANDLE MiniportAdapterContext, PNDIS_OID_REQUEST OidRequest)
{
    switch (OidRequest->RequestType)
    {
    case NdisRequestQueryInformation:
    case NdisRequestQueryStatistics:
        return TunOidQuery(MiniportAdapterContext, OidRequest);

    case NdisRequestSetInformation:
        return TunOidSet(MiniportAdapterContext, OidRequest);

    default:
        return NDIS_STATUS_INVALID_OID;
    }
}

static MINIPORT_CANCEL_OID_REQUEST TunCancelOidRequest;
_Use_decl_annotations_
static VOID
TunCancelOidRequest(NDIS_HANDLE MiniportAdapterContext, PVOID RequestId)
{
}

static MINIPORT_DIRECT_OID_REQUEST TunDirectOidRequest;
_Use_decl_annotations_
static NDIS_STATUS
TunDirectOidRequest(NDIS_HANDLE MiniportAdapterContext, PNDIS_OID_REQUEST OidRequest)
{
    switch (OidRequest->RequestType)
    {
    case NdisRequestQueryInformation:
    case NdisRequestQueryStatistics:
    case NdisRequestSetInformation:
        return NDIS_STATUS_NOT_SUPPORTED;

    default:
        return NDIS_STATUS_INVALID_OID;
    }
}

static MINIPORT_CANCEL_DIRECT_OID_REQUEST TunCancelDirectOidRequest;
_Use_decl_annotations_
static VOID
TunCancelDirectOidRequest(NDIS_HANDLE MiniportAdapterContext, PVOID RequestId)
{
}

static MINIPORT_SYNCHRONOUS_OID_REQUEST TunSynchronousOidRequest;
_Use_decl_annotations_
static NDIS_STATUS
TunSynchronousOidRequest(NDIS_HANDLE MiniportAdapterContext, PNDIS_OID_REQUEST OidRequest)
{
    switch (OidRequest->RequestType)
    {
    case NdisRequestQueryInformation:
    case NdisRequestQueryStatistics:
    case NdisRequestSetInformation:
        return NDIS_STATUS_NOT_SUPPORTED;

    default:
        return NDIS_STATUS_INVALID_OID;
    }
}

static MINIPORT_UNLOAD TunUnload;
_Use_decl_annotations_
static VOID
TunUnload(PDRIVER_OBJECT DriverObject)
{
    NdisMDeregisterMiniportDriver(NdisMiniportDriverHandle);
    ExDeleteResourceLite(&TunDispatchCtxGuard);
    ExFreePoolWithTag(TunDispatchSecurityDescriptor, TUN_MEMORY_TAG);
}

DRIVER_INITIALIZE DriverEntry;
_Use_decl_annotations_
NTSTATUS
DriverEntry(DRIVER_OBJECT *DriverObject, UNICODE_STRING *RegistryPath)
{
    NTSTATUS Status;

    if (!NT_SUCCESS(Status = TunInitializeDispatchSecurityDescriptor()))
        return Status;

    NdisVersion = NdisGetVersion();
    if (NdisVersion < NDIS_MINIPORT_VERSION_MIN)
        return NDIS_STATUS_UNSUPPORTED_REVISION;
    if (NdisVersion > NDIS_MINIPORT_VERSION_MAX)
        NdisVersion = NDIS_MINIPORT_VERSION_MAX;

    ExInitializeResourceLite(&TunDispatchCtxGuard);

    NDIS_MINIPORT_DRIVER_CHARACTERISTICS miniport = {
        .Header = { .Type = NDIS_OBJECT_TYPE_MINIPORT_DRIVER_CHARACTERISTICS,
                    .Revision = NdisVersion < NDIS_RUNTIME_VERSION_680
                                    ? NDIS_MINIPORT_DRIVER_CHARACTERISTICS_REVISION_2
                                    : NDIS_MINIPORT_DRIVER_CHARACTERISTICS_REVISION_3,
                    .Size = NdisVersion < NDIS_RUNTIME_VERSION_680
                                ? NDIS_SIZEOF_MINIPORT_DRIVER_CHARACTERISTICS_REVISION_2
                                : NDIS_SIZEOF_MINIPORT_DRIVER_CHARACTERISTICS_REVISION_3 },

        .MajorNdisVersion = (UCHAR)((NdisVersion & 0x00ff0000) >> 16),
        .MinorNdisVersion = (UCHAR)(NdisVersion & 0x000000ff),

        .MajorDriverVersion = WINTUN_VERSION_MAJ,
        .MinorDriverVersion = WINTUN_VERSION_MIN,

        .InitializeHandlerEx = TunInitializeEx,
        .HaltHandlerEx = TunHaltEx,
        .UnloadHandler = TunUnload,
        .PauseHandler = TunPause,
        .RestartHandler = TunRestart,
        .OidRequestHandler = TunOidRequest,
        .SendNetBufferListsHandler = TunSendNetBufferLists,
        .ReturnNetBufferListsHandler = TunReturnNetBufferLists,
        .CancelSendHandler = TunCancelSend,
        .DevicePnPEventNotifyHandler = TunDevicePnPEventNotify,
        .ShutdownHandlerEx = TunShutdownEx,
        .CancelOidRequestHandler = TunCancelOidRequest,
        .DirectOidRequestHandler = TunDirectOidRequest,
        .CancelDirectOidRequestHandler = TunCancelDirectOidRequest,
        .SynchronousOidRequestHandler = TunSynchronousOidRequest
    };
    Status = NdisMRegisterMiniportDriver(DriverObject, RegistryPath, NULL, &miniport, &NdisMiniportDriverHandle);
    if (!NT_SUCCESS(Status))
    {
        ExDeleteResourceLite(&TunDispatchCtxGuard);
        ExFreePoolWithTag(TunDispatchSecurityDescriptor, TUN_MEMORY_TAG);
        return Status;
    }

    NdisDispatchDeviceControl = DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL];
    NdisDispatchClose = DriverObject->MajorFunction[IRP_MJ_CLOSE];
    DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = TunDispatchDeviceControl;
    DriverObject->MajorFunction[IRP_MJ_CLOSE] = TunDispatchClose;

    return STATUS_SUCCESS;
}

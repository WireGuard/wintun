/* SPDX-License-Identifier: GPL-2.0
 *
 * Copyright (C) 2018-2019 WireGuard LLC. All Rights Reserved.
 */

#include <stdio.h>
#include <string.h>
#include <ntifs.h>
#include <wdm.h>
#include <wdmsec.h>
#include <ndis.h>
#include <bcrypt.h>
#include <ntstrsafe.h>
#include "undocumented.h"

#pragma warning(disable : 4100) /* unreferenced formal parameter */
#pragma warning(disable : 4200) /* nonstandard: zero-sized array in struct/union */
#pragma warning(disable : 4204) /* nonstandard: non-constant aggregate initializer */
#pragma warning(disable : 4221) /* nonstandard: cannot be initialized using address of automatic variable */
#pragma warning(disable : 6320) /* exception-filter expression is the constant EXCEPTION_EXECUTE_HANDLER */

#define NDIS_MINIPORT_VERSION_MIN ((NDIS_MINIPORT_MINIMUM_MAJOR_VERSION << 16) | NDIS_MINIPORT_MINIMUM_MINOR_VERSION)
#define NDIS_MINIPORT_VERSION_MAX ((NDIS_MINIPORT_MAJOR_VERSION << 16) | NDIS_MINIPORT_MINOR_VERSION)

#define TUN_DEVICE_NAME L"WINTUN%u"

#define TUN_VENDOR_NAME "Wintun Tunnel"
#define TUN_VENDOR_ID 0xFFFFFF00
#define TUN_LINK_SPEED 100000000000ULL /* 100gbps */

/* Maximum number of full-sized exchange packets that can be exchanged in a single read/write. */
#define TUN_EXCH_MAX_PACKETS 256
/* Maximum exchange packet size - empirically determined by net buffer list (pool) limitations */
#define TUN_EXCH_MAX_PACKET_SIZE 0xF000
#define TUN_EXCH_ALIGNMENT sizeof(ULONG) /* Memory alignment in exchange buffers */
/* Maximum IP packet size (headers + payload) */
#define TUN_EXCH_MAX_IP_PACKET_SIZE (TUN_EXCH_MAX_PACKET_SIZE - sizeof(TUN_PACKET))
/* Maximum size of read/write exchange buffer */
#define TUN_EXCH_MAX_BUFFER_SIZE (TUN_EXCH_MAX_PACKETS * TUN_EXCH_MAX_PACKET_SIZE)
#define TUN_EXCH_MIN_BUFFER_SIZE_READ TUN_EXCH_MAX_PACKET_SIZE /* Minimum size of read exchange buffer */
#define TUN_EXCH_MIN_BUFFER_SIZE_WRITE (sizeof(TUN_PACKET))    /* Minimum size of write exchange buffer */
#define TUN_QUEUE_MAX_NBLS 1000
#define TUN_CSQ_INSERT_HEAD ((PVOID)TRUE)
#define TUN_CSQ_INSERT_TAIL ((PVOID)FALSE)

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
    ULONG Size; /* Size of packet data (TUN_EXCH_MAX_IP_PACKET_SIZE max) */
    _Field_size_bytes_(Size)
    UCHAR Data[]; /* Packet data */
} TUN_PACKET;

typedef enum _TUN_FLAGS
{
    TUN_FLAGS_RUNNING = 1 << 0, /* Toggles between paused and running state */
    TUN_FLAGS_PRESENT = 1 << 1, /* Toggles between removal pending and being present */
} TUN_FLAGS;

typedef struct _TUN_CTX
{
    volatile LONG Flags;

    /* Used like RCU. When we're making use of queues, we take a shared lock. When we want to
     * drain the queues and toggle the state, we take an exclusive lock before toggling the
     * atomic and then releasing. It's similar to setting the atomic and then calling rcu_barrier(). */
    EX_SPIN_LOCK TransitionLock;

    NDIS_HANDLE MiniportAdapterHandle; /* This is actually a pointer to NDIS_MINIPORT_BLOCK struct. */
    NDIS_STATISTICS_INFO Statistics;

    volatile LONG64 ActiveNBLCount;

    struct
    {
        NDIS_HANDLE Handle;
        volatile LONG64 RefCount;
        IO_REMOVE_LOCK RemoveLock;

        struct
        {
            KSPIN_LOCK Lock;
            IO_CSQ Csq;
            LIST_ENTRY List;
        } ReadQueue;

        DEVICE_OBJECT *Object;
    } Device;

    struct
    {
        KSPIN_LOCK Lock;
        NET_BUFFER_LIST *FirstNbl, *LastNbl;
        NET_BUFFER *NextNb;
        volatile LONG NumNbl;
    } PacketQueue;

    NDIS_HANDLE NBLPool;
} TUN_CTX;

typedef struct _TUN_MAPPED_UBUFFER
{
    VOID *volatile UserAddress;
    VOID *KernelAddress;
    MDL *Mdl;
    ULONG Size;
    FAST_MUTEX InitializationComplete;
    /* TODO: ThreadID for checking */
} TUN_MAPPED_UBUFFER;

typedef struct _TUN_FILE_CTX
{
    TUN_MAPPED_UBUFFER ReadBuffer;
} TUN_FILE_CTX;

static UINT NdisVersion;
static NDIS_HANDLE NdisMiniportDriverHandle;
static DRIVER_DISPATCH *NdisDispatchPnP;
static volatile LONG64 TunAdapterCount;

static __forceinline LONG
InterlockedGet(_In_ _Interlocked_operand_ LONG volatile *Value)
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

#define TunPacketAlign(size) (((ULONG)(size) + (ULONG)(TUN_EXCH_ALIGNMENT - 1)) & ~(ULONG)(TUN_EXCH_ALIGNMENT - 1))
#define TunInitUnicodeString(str, buf) \
    { \
        (str)->Length = 0; \
        (str)->MaximumLength = sizeof(buf); \
        (str)->Buffer = buf; \
    }

_IRQL_requires_max_(DISPATCH_LEVEL)
_IRQL_requires_same_
static void
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

_IRQL_requires_max_(DISPATCH_LEVEL)
static void
TunCompleteRequest(_Inout_ TUN_CTX *Ctx, _Inout_ IRP *Irp, _In_ NTSTATUS Status, _In_ CCHAR PriorityBoost)
{
    Irp->IoStatus.Status = Status;
    IoCompleteRequest(Irp, PriorityBoost);
    IoReleaseRemoveLock(&Ctx->Device.RemoveLock, Irp);
}

_IRQL_requires_max_(DISPATCH_LEVEL)
static NDIS_STATUS
TunCompletePause(_Inout_ TUN_CTX *Ctx, _In_ BOOLEAN AsyncCompletion)
{
    ASSERT(InterlockedGet64(&Ctx->ActiveNBLCount) > 0);
    if (InterlockedDecrement64(&Ctx->ActiveNBLCount) <= 0)
    {
        if (AsyncCompletion)
            NdisMPauseComplete(Ctx->MiniportAdapterHandle);
        return NDIS_STATUS_SUCCESS;
    }

    return NDIS_STATUS_PENDING;
}

static IO_CSQ_INSERT_IRP_EX TunCsqInsertIrpEx;
_Use_decl_annotations_
static NTSTATUS
TunCsqInsertIrpEx(IO_CSQ *Csq, IRP *Irp, PVOID InsertContext)
{
    TUN_CTX *Ctx = CONTAINING_RECORD(Csq, TUN_CTX, Device.ReadQueue.Csq);
    if (InsertContext == TUN_CSQ_INSERT_HEAD)
        InsertHeadList(&Ctx->Device.ReadQueue.List, &Irp->Tail.Overlay.ListEntry);
    else
        InsertTailList(&Ctx->Device.ReadQueue.List, &Irp->Tail.Overlay.ListEntry);
    return STATUS_SUCCESS;
}

static IO_CSQ_REMOVE_IRP TunCsqRemoveIrp;
_Use_decl_annotations_
static VOID
TunCsqRemoveIrp(IO_CSQ *Csq, IRP *Irp)
{
    RemoveEntryList(&Irp->Tail.Overlay.ListEntry);
}

static IO_CSQ_PEEK_NEXT_IRP TunCsqPeekNextIrp;
_Use_decl_annotations_
static IRP *
TunCsqPeekNextIrp(IO_CSQ *Csq, IRP *Irp, _In_ PVOID PeekContext)
{
    TUN_CTX *Ctx = CONTAINING_RECORD(Csq, TUN_CTX, Device.ReadQueue.Csq);

    /* If the IRP is non-NULL, we will start peeking from that IRP onwards, else
     * we will start from the listhead. This is done under the assumption that
     * new IRPs are always inserted at the tail. */
    for (LIST_ENTRY *Head = &Ctx->Device.ReadQueue.List, *Next = Irp ? Irp->Tail.Overlay.ListEntry.Flink : Head->Flink;
         Next != Head;
         Next = Next->Flink)
    {
        IRP *NextIrp = CONTAINING_RECORD(Next, IRP, Tail.Overlay.ListEntry);
        if (!PeekContext)
            return NextIrp;

        IO_STACK_LOCATION *Stack = IoGetCurrentIrpStackLocation(NextIrp);
        if (Stack->FileObject == (FILE_OBJECT *)PeekContext)
            return NextIrp;
    }

    return NULL;
}

_IRQL_raises_(DISPATCH_LEVEL)
_IRQL_requires_max_(DISPATCH_LEVEL)
_Requires_lock_not_held_(CONTAINING_RECORD(Csq, TUN_CTX, Device.ReadQueue.Csq)->Device.ReadQueue.Lock)
_Acquires_lock_(CONTAINING_RECORD(Csq, TUN_CTX, Device.ReadQueue.Csq)->Device.ReadQueue.Lock)
static VOID
TunCsqAcquireLock(_In_ IO_CSQ *Csq, _Out_ _At_(*Irql, _Post_ _IRQL_saves_) KIRQL *Irql)
{
    KeAcquireSpinLock(&CONTAINING_RECORD(Csq, TUN_CTX, Device.ReadQueue.Csq)->Device.ReadQueue.Lock, Irql);
}

_IRQL_requires_(DISPATCH_LEVEL)
_Requires_lock_held_(CONTAINING_RECORD(Csq, TUN_CTX, Device.ReadQueue.Csq)->Device.ReadQueue.Lock)
_Releases_lock_(CONTAINING_RECORD(Csq, TUN_CTX, Device.ReadQueue.Csq)->Device.ReadQueue.Lock)
static VOID
TunCsqReleaseLock(_In_ IO_CSQ *Csq, _In_ _IRQL_restores_ KIRQL Irql)
{
    KeReleaseSpinLock(&CONTAINING_RECORD(Csq, TUN_CTX, Device.ReadQueue.Csq)->Device.ReadQueue.Lock, Irql);
}

static IO_CSQ_COMPLETE_CANCELED_IRP TunCsqCompleteCanceledIrp;
_Use_decl_annotations_
static VOID
TunCsqCompleteCanceledIrp(IO_CSQ *Csq, IRP *Irp)
{
    TUN_CTX *Ctx = CONTAINING_RECORD(Csq, TUN_CTX, Device.ReadQueue.Csq);
    TunCompleteRequest(Ctx, Irp, STATUS_CANCELLED, IO_NO_INCREMENT);
}

_IRQL_requires_max_(APC_LEVEL)
_Must_inspect_result_
static NTSTATUS
TunMapUbuffer(_Inout_ TUN_MAPPED_UBUFFER *MappedBuffer, _In_ VOID *UserAddress, _In_ ULONG Size)
{
    VOID *CurrentUserAddress = InterlockedGetPointer(&MappedBuffer->UserAddress);
    if (CurrentUserAddress)
    {
        if (UserAddress != CurrentUserAddress || Size > MappedBuffer->Size) /* TODO: Check ThreadID */
            return STATUS_ALREADY_INITIALIZED;
        return STATUS_SUCCESS;
    }

    NTSTATUS Status = STATUS_SUCCESS;
    ExAcquireFastMutex(&MappedBuffer->InitializationComplete);

    /* Recheck the same thing as above, but locked this time. */
    CurrentUserAddress = InterlockedGetPointer(&MappedBuffer->UserAddress);
    if (CurrentUserAddress)
    {
        if (UserAddress != CurrentUserAddress || Size > MappedBuffer->Size) /* TODO: Check ThreadID */
            Status = STATUS_ALREADY_INITIALIZED;
        goto err_releasemutex;
    }

    MappedBuffer->Mdl = IoAllocateMdl(UserAddress, Size, FALSE, FALSE, NULL);
    Status = STATUS_INSUFFICIENT_RESOURCES;
    if (!MappedBuffer->Mdl)
        goto err_releasemutex;

    Status = STATUS_INVALID_USER_BUFFER;
    try
    {
        MmProbeAndLockPages(MappedBuffer->Mdl, UserMode, IoWriteAccess);
    }
    except(EXCEPTION_EXECUTE_HANDLER) { goto err_freemdl; }

    MappedBuffer->KernelAddress =
        MmGetSystemAddressForMdlSafe(MappedBuffer->Mdl, NormalPagePriority | MdlMappingNoExecute);
    Status = STATUS_INSUFFICIENT_RESOURCES;
    if (!MappedBuffer->KernelAddress)
        goto err_unlockmdl;
    MappedBuffer->Size = Size;
    InterlockedExchangePointer(&MappedBuffer->UserAddress, UserAddress);
    ExReleaseFastMutex(&MappedBuffer->InitializationComplete);
    return STATUS_SUCCESS;

err_unlockmdl:
    MmUnlockPages(MappedBuffer->Mdl);
err_freemdl:
    IoFreeMdl(MappedBuffer->Mdl);
    MappedBuffer->Mdl = NULL;
err_releasemutex:
    ExReleaseFastMutex(&MappedBuffer->InitializationComplete);
    return Status;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
static void
TunUnmapUbuffer(_Inout_ TUN_MAPPED_UBUFFER *MappedBuffer)
{
    if (MappedBuffer->Mdl)
    {
        MmUnlockPages(MappedBuffer->Mdl);
        IoFreeMdl(MappedBuffer->Mdl);
        MappedBuffer->UserAddress = MappedBuffer->KernelAddress = MappedBuffer->Mdl = NULL;
    }
}

_IRQL_requires_max_(APC_LEVEL)
_Must_inspect_result_
static NTSTATUS
TunMapIrp(_In_ IRP *Irp)
{
    ULONG Size;
    TUN_MAPPED_UBUFFER *UserBuffer;
    IO_STACK_LOCATION *Stack = IoGetCurrentIrpStackLocation(Irp);
    TUN_FILE_CTX *FileCtx = (TUN_FILE_CTX *)Stack->FileObject->FsContext;

    switch (Stack->MajorFunction)
    {
    case IRP_MJ_READ:
        Size = Stack->Parameters.Read.Length;
        if (Size < TUN_EXCH_MIN_BUFFER_SIZE_READ)
            return STATUS_INVALID_USER_BUFFER;
        UserBuffer = &FileCtx->ReadBuffer;
        break;
    default:
        return STATUS_INVALID_PARAMETER;
    }
    if (Size > TUN_EXCH_MAX_BUFFER_SIZE)
        return STATUS_INVALID_USER_BUFFER;
    return TunMapUbuffer(UserBuffer, Irp->UserBuffer, Size);
}

_IRQL_requires_max_(DISPATCH_LEVEL)
_Must_inspect_result_
static _Return_type_success_(
    return != NULL) IRP *TunRemoveNextIrp(_Inout_ TUN_CTX *Ctx, _Out_ UCHAR **Buffer, _Out_ ULONG *Size)
{
    IRP *Irp = IoCsqRemoveNextIrp(&Ctx->Device.ReadQueue.Csq, NULL);
    if (!Irp)
        return NULL;
    IO_STACK_LOCATION *Stack = IoGetCurrentIrpStackLocation(Irp);
    *Size = Stack->Parameters.Read.Length;
    ASSERT(Irp->IoStatus.Information <= (ULONG_PTR)*Size);
    *Buffer = ((TUN_FILE_CTX *)Stack->FileObject->FsContext)->ReadBuffer.KernelAddress;
    return Irp;
}

_IRQL_requires_same_
static BOOLEAN
TunWontFitIntoIrp(_In_ IRP *Irp, _In_ ULONG Size, _In_ NET_BUFFER *Nb)
{
    return (ULONG_PTR)Size <
           Irp->IoStatus.Information + TunPacketAlign(sizeof(TUN_PACKET) + NET_BUFFER_DATA_LENGTH(Nb));
}

_IRQL_requires_max_(DISPATCH_LEVEL)
_Must_inspect_result_
static NTSTATUS
TunWriteIntoIrp(_Inout_ IRP *Irp, _Inout_ UCHAR *Buffer, _In_ NET_BUFFER *Nb, _Inout_ NDIS_STATISTICS_INFO *Statistics)
{
    ULONG PacketSize = NET_BUFFER_DATA_LENGTH(Nb);
    TUN_PACKET *Packet = (TUN_PACKET *)(Buffer + Irp->IoStatus.Information);

    Packet->Size = PacketSize; /* We shouldn't trust Packet->Size directly for reading, because the user controls it. */
    void *NbData = NdisGetDataBuffer(Nb, PacketSize, Packet->Data, 1, 0);
    if (!NbData)
    {
        if (Statistics)
            InterlockedIncrement64((LONG64 *)&Statistics->ifOutErrors);
        return NDIS_STATUS_RESOURCES;
    }
    if (NbData != Packet->Data)
        NdisMoveMemory(Packet->Data, NbData, PacketSize);

    Irp->IoStatus.Information += TunPacketAlign(sizeof(TUN_PACKET) + PacketSize);

    InterlockedAdd64((LONG64 *)&Statistics->ifHCOutOctets, PacketSize);
    InterlockedAdd64((LONG64 *)&Statistics->ifHCOutUcastOctets, PacketSize);
    InterlockedIncrement64((LONG64 *)&Statistics->ifHCOutUcastPkts);
    return STATUS_SUCCESS;
}

#define NET_BUFFER_LIST_REFCOUNT(nbl) ((volatile LONG64 *)NET_BUFFER_LIST_MINIPORT_RESERVED(nbl))

_IRQL_requires_same_
static void
TunNBLRefInit(_Inout_ TUN_CTX *Ctx, _Inout_ NET_BUFFER_LIST *Nbl)
{
    InterlockedIncrement64(&Ctx->ActiveNBLCount);
    InterlockedIncrement(&Ctx->PacketQueue.NumNbl);
    InterlockedExchange64(NET_BUFFER_LIST_REFCOUNT(Nbl), 1);
}

_IRQL_requires_same_
static void
TunNBLRefInc(_Inout_ NET_BUFFER_LIST *Nbl)
{
    ASSERT(InterlockedGet64(NET_BUFFER_LIST_REFCOUNT(Nbl)));
    InterlockedIncrement64(NET_BUFFER_LIST_REFCOUNT(Nbl));
}

_When_((SendCompleteFlags & NDIS_SEND_COMPLETE_FLAGS_DISPATCH_LEVEL), _IRQL_requires_(DISPATCH_LEVEL))
_When_(!(SendCompleteFlags & NDIS_SEND_COMPLETE_FLAGS_DISPATCH_LEVEL), _IRQL_requires_max_(DISPATCH_LEVEL))
static BOOLEAN
TunNBLRefDec(_Inout_ TUN_CTX *Ctx, _Inout_ NET_BUFFER_LIST *Nbl, _In_ ULONG SendCompleteFlags)
{
    ASSERT(InterlockedGet64(NET_BUFFER_LIST_REFCOUNT(Nbl)) > 0);
    if (InterlockedDecrement64(NET_BUFFER_LIST_REFCOUNT(Nbl)) <= 0)
    {
        NET_BUFFER_LIST_NEXT_NBL(Nbl) = NULL;
        NdisMSendNetBufferListsComplete(Ctx->MiniportAdapterHandle, Nbl, SendCompleteFlags);
        ASSERT(InterlockedGet(&Ctx->PacketQueue.NumNbl) > 0);
        InterlockedDecrement(&Ctx->PacketQueue.NumNbl);
        TunCompletePause(Ctx, TRUE);
        return TRUE;
    }
    return FALSE;
}

_IRQL_requires_same_
static void
TunAppendNBL(_Inout_ NET_BUFFER_LIST **Head, _Inout_ NET_BUFFER_LIST **Tail, __drv_aliasesMem _In_ NET_BUFFER_LIST *Nbl)
{
    *(*Tail ? &NET_BUFFER_LIST_NEXT_NBL(*Tail) : Head) = Nbl;
    *Tail = Nbl;
    NET_BUFFER_LIST_NEXT_NBL(Nbl) = NULL;
}

_Requires_lock_not_held_(Ctx->PacketQueue.Lock)
_IRQL_requires_max_(DISPATCH_LEVEL)
static void
TunQueueAppend(_Inout_ TUN_CTX *Ctx, _In_ NET_BUFFER_LIST *Nbl, _In_ ULONG MaxNbls)
{
    for (NET_BUFFER_LIST *NextNbl; Nbl; Nbl = NextNbl)
    {
        NextNbl = NET_BUFFER_LIST_NEXT_NBL(Nbl);
        if (!NET_BUFFER_LIST_FIRST_NB(Nbl))
        {
            NET_BUFFER_LIST_NEXT_NBL(Nbl) = NULL;
            NdisMSendNetBufferListsComplete(Ctx->MiniportAdapterHandle, Nbl, 0);
            continue;
        }

        KLOCK_QUEUE_HANDLE LockHandle;
        KeAcquireInStackQueuedSpinLock(&Ctx->PacketQueue.Lock, &LockHandle);
        TunNBLRefInit(Ctx, Nbl);
        TunAppendNBL(&Ctx->PacketQueue.FirstNbl, &Ctx->PacketQueue.LastNbl, Nbl);

        while ((ULONG)InterlockedGet(&Ctx->PacketQueue.NumNbl) > MaxNbls && Ctx->PacketQueue.FirstNbl)
        {
            NET_BUFFER_LIST *SecondNbl = NET_BUFFER_LIST_NEXT_NBL(Ctx->PacketQueue.FirstNbl);

            NET_BUFFER_LIST_STATUS(Ctx->PacketQueue.FirstNbl) = NDIS_STATUS_SEND_ABORTED;
            TunNBLRefDec(Ctx, Ctx->PacketQueue.FirstNbl, NDIS_SEND_COMPLETE_FLAGS_DISPATCH_LEVEL);

            Ctx->PacketQueue.NextNb = NULL;
            Ctx->PacketQueue.FirstNbl = SecondNbl;
            if (!Ctx->PacketQueue.FirstNbl)
                Ctx->PacketQueue.LastNbl = NULL;
        }

        KeReleaseInStackQueuedSpinLock(&LockHandle);
    }
}

_Requires_lock_held_(Ctx->PacketQueue.Lock)
_IRQL_requires_(DISPATCH_LEVEL)
_Must_inspect_result_
static _Return_type_success_(return !=
                                    NULL) NET_BUFFER *TunQueueRemove(_Inout_ TUN_CTX *Ctx, _Out_ NET_BUFFER_LIST **Nbl)
{
    NET_BUFFER_LIST *TopNbl;
    NET_BUFFER *RetNbl;

retry:
    TopNbl = Ctx->PacketQueue.FirstNbl;
    *Nbl = TopNbl;
    if (!TopNbl)
        return NULL;
    if (!Ctx->PacketQueue.NextNb)
        Ctx->PacketQueue.NextNb = NET_BUFFER_LIST_FIRST_NB(TopNbl);
    RetNbl = Ctx->PacketQueue.NextNb;
    Ctx->PacketQueue.NextNb = NET_BUFFER_NEXT_NB(RetNbl);
    if (!Ctx->PacketQueue.NextNb)
    {
        Ctx->PacketQueue.FirstNbl = NET_BUFFER_LIST_NEXT_NBL(TopNbl);
        if (!Ctx->PacketQueue.FirstNbl)
            Ctx->PacketQueue.LastNbl = NULL;
        NET_BUFFER_LIST_NEXT_NBL(TopNbl) = NULL;
    }
    else
        TunNBLRefInc(TopNbl);

    if (RetNbl && NET_BUFFER_DATA_LENGTH(RetNbl) > TUN_EXCH_MAX_IP_PACKET_SIZE)
    {
        NET_BUFFER_LIST_STATUS(TopNbl) = NDIS_STATUS_INVALID_LENGTH;
        TunNBLRefDec(Ctx, TopNbl, NDIS_SEND_COMPLETE_FLAGS_DISPATCH_LEVEL);
        InterlockedIncrement64((LONG64 *)&Ctx->Statistics.ifOutDiscards);
        goto retry;
    }

    return RetNbl;
}

/* Note: Must be called immediately after TunQueueRemove without dropping ctx->PacketQueue.Lock. */
_Requires_lock_held_(Ctx->PacketQueue.Lock)
_IRQL_requires_(DISPATCH_LEVEL)
static void
TunQueuePrepend(_Inout_ TUN_CTX *Ctx, _In_ NET_BUFFER *Nb, _In_ NET_BUFFER_LIST *Nbl)
{
    Ctx->PacketQueue.NextNb = Nb;

    if (!Nbl || Nbl == Ctx->PacketQueue.FirstNbl)
        return;

    TunNBLRefInc(Nbl);
    if (!Ctx->PacketQueue.FirstNbl)
        Ctx->PacketQueue.FirstNbl = Ctx->PacketQueue.LastNbl = Nbl;
    else
    {
        NET_BUFFER_LIST_NEXT_NBL(Nbl) = Ctx->PacketQueue.FirstNbl;
        Ctx->PacketQueue.FirstNbl = Nbl;
    }
}

_Requires_lock_not_held_(Ctx->PacketQueue.Lock)
_IRQL_requires_max_(DISPATCH_LEVEL)
static void
TunQueueClear(_Inout_ TUN_CTX *Ctx, _In_ NDIS_STATUS Status)
{
    KLOCK_QUEUE_HANDLE LockHandle;
    KeAcquireInStackQueuedSpinLock(&Ctx->PacketQueue.Lock, &LockHandle);
    for (NET_BUFFER_LIST *Nbl = Ctx->PacketQueue.FirstNbl, *NextNbl; Nbl; Nbl = NextNbl)
    {
        NextNbl = NET_BUFFER_LIST_NEXT_NBL(Nbl);
        NET_BUFFER_LIST_STATUS(Nbl) = Status;
        TunNBLRefDec(Ctx, Nbl, NDIS_SEND_COMPLETE_FLAGS_DISPATCH_LEVEL);
    }
    Ctx->PacketQueue.FirstNbl = NULL;
    Ctx->PacketQueue.LastNbl = NULL;
    Ctx->PacketQueue.NextNb = NULL;
    InterlockedExchange(&Ctx->PacketQueue.NumNbl, 0);
    KeReleaseInStackQueuedSpinLock(&LockHandle);
}

_Requires_lock_not_held_(Ctx->PacketQueue.Lock)
_IRQL_requires_max_(DISPATCH_LEVEL)
static void
TunQueueProcess(_Inout_ TUN_CTX *Ctx)
{
    IRP *Irp = NULL;
    UCHAR *Buffer = NULL;
    ULONG Size = 0;
    NET_BUFFER *Nb;
    KLOCK_QUEUE_HANDLE LockHandle;

    for (;;)
    {
        NET_BUFFER_LIST *Nbl;

        KeAcquireInStackQueuedSpinLock(&Ctx->PacketQueue.Lock, &LockHandle);

        /* Get head NB (and IRP). */
        if (!Irp)
        {
            Nb = TunQueueRemove(Ctx, &Nbl);
            if (!Nb)
            {
                KeReleaseInStackQueuedSpinLock(&LockHandle);
                return;
            }
            Irp = TunRemoveNextIrp(Ctx, &Buffer, &Size);
            if (!Irp)
            {
                TunQueuePrepend(Ctx, Nb, Nbl);
                KeReleaseInStackQueuedSpinLock(&LockHandle);
                if (Nbl)
                    TunNBLRefDec(Ctx, Nbl, 0);
                return;
            }

            _Analysis_assume_(Buffer);
            _Analysis_assume_(Irp->IoStatus.Information <= Size);
        }
        else
            Nb = TunQueueRemove(Ctx, &Nbl);

        /* If the NB won't fit in the IRP, return it. */
        if (Nb && TunWontFitIntoIrp(Irp, Size, Nb))
        {
            TunQueuePrepend(Ctx, Nb, Nbl);
            if (Nbl)
                TunNBLRefDec(Ctx, Nbl, NDIS_SEND_COMPLETE_FLAGS_DISPATCH_LEVEL);
            Nbl = NULL;
            Nb = NULL;
        }

        KeReleaseInStackQueuedSpinLock(&LockHandle);

        /* Process NB and IRP. */
        if (Nb)
        {
            NTSTATUS status = TunWriteIntoIrp(Irp, Buffer, Nb, &Ctx->Statistics);
            if (!NT_SUCCESS(status))
            {
                if (Nbl)
                    NET_BUFFER_LIST_STATUS(Nbl) = status;
                IoCsqInsertIrpEx(&Ctx->Device.ReadQueue.Csq, Irp, NULL, TUN_CSQ_INSERT_HEAD);
                Irp = NULL;
            }
        }
        else
        {
            TunCompleteRequest(Ctx, Irp, STATUS_SUCCESS, IO_NETWORK_INCREMENT);
            Irp = NULL;
        }

        if (Nbl)
            TunNBLRefDec(Ctx, Nbl, 0);
    }
}

_IRQL_requires_same_
static void
TunSetNBLStatus(_Inout_opt_ NET_BUFFER_LIST *Nbl, _In_ NDIS_STATUS Status)
{
    for (; Nbl; Nbl = NET_BUFFER_LIST_NEXT_NBL(Nbl))
        NET_BUFFER_LIST_STATUS(Nbl) = Status;
}

static MINIPORT_SEND_NET_BUFFER_LISTS TunSendNetBufferLists;
_Use_decl_annotations_
static void
TunSendNetBufferLists(
    NDIS_HANDLE MiniportAdapterContext,
    NET_BUFFER_LIST *NetBufferLists,
    NDIS_PORT_NUMBER PortNumber,
    ULONG SendFlags)
{
    TUN_CTX *Ctx = (TUN_CTX *)MiniportAdapterContext;

    KIRQL Irql = ExAcquireSpinLockShared(&Ctx->TransitionLock);
    LONG Flags = InterlockedGet(&Ctx->Flags);
    NDIS_STATUS Status;
    if ((Status = NDIS_STATUS_ADAPTER_REMOVED, !(Flags & TUN_FLAGS_PRESENT)) ||
        (Status = NDIS_STATUS_PAUSED, !(Flags & TUN_FLAGS_RUNNING)) ||
        (Status = NDIS_STATUS_MEDIA_DISCONNECTED, InterlockedGet64(&Ctx->Device.RefCount) <= 0))
    {
        TunSetNBLStatus(NetBufferLists, Status);
        NdisMSendNetBufferListsComplete(
            Ctx->MiniportAdapterHandle, NetBufferLists, NDIS_SEND_COMPLETE_FLAGS_DISPATCH_LEVEL);
        goto cleanup_ExReleaseSpinLockShared;
    }

    TunQueueAppend(Ctx, NetBufferLists, TUN_QUEUE_MAX_NBLS);

    TunQueueProcess(Ctx);

cleanup_ExReleaseSpinLockShared:
    ExReleaseSpinLockShared(&Ctx->TransitionLock, Irql);
}

static MINIPORT_CANCEL_SEND TunCancelSend;
_Use_decl_annotations_
static void
TunCancelSend(NDIS_HANDLE MiniportAdapterContext, PVOID CancelId)
{
    TUN_CTX *Ctx = (TUN_CTX *)MiniportAdapterContext;
    KLOCK_QUEUE_HANDLE LockHandle;

    KeAcquireInStackQueuedSpinLock(&Ctx->PacketQueue.Lock, &LockHandle);

    NET_BUFFER_LIST *LastNbl = NULL, **LastNblLink = &Ctx->PacketQueue.FirstNbl;
    for (NET_BUFFER_LIST *Nbl = Ctx->PacketQueue.FirstNbl, *NextNbl; Nbl; Nbl = NextNbl)
    {
        NextNbl = NET_BUFFER_LIST_NEXT_NBL(Nbl);
        if (NDIS_GET_NET_BUFFER_LIST_CANCEL_ID(Nbl) == CancelId)
        {
            NET_BUFFER_LIST_STATUS(Nbl) = NDIS_STATUS_SEND_ABORTED;
            *LastNblLink = NextNbl;
            TunNBLRefDec(Ctx, Nbl, NDIS_SEND_COMPLETE_FLAGS_DISPATCH_LEVEL);
        }
        else
        {
            LastNbl = Nbl;
            LastNblLink = &NET_BUFFER_LIST_NEXT_NBL(Nbl);
        }
    }
    Ctx->PacketQueue.LastNbl = LastNbl;

    KeReleaseInStackQueuedSpinLock(&LockHandle);
}

_IRQL_requires_max_(APC_LEVEL)
_Must_inspect_result_
static NTSTATUS
TunDispatchRead(_Inout_ TUN_CTX *Ctx, _Inout_ IRP *Irp)
{
    NTSTATUS Status = TunMapIrp(Irp);
    if (!NT_SUCCESS(Status))
        goto cleanup_CompleteRequest;

    KIRQL Irql = ExAcquireSpinLockShared(&Ctx->TransitionLock);
    LONG Flags = InterlockedGet(&Ctx->Flags);
    if ((Status = STATUS_FILE_FORCED_CLOSED, !(Flags & TUN_FLAGS_PRESENT)) ||
        !NT_SUCCESS(Status = IoCsqInsertIrpEx(&Ctx->Device.ReadQueue.Csq, Irp, NULL, TUN_CSQ_INSERT_TAIL)))
        goto cleanup_ExReleaseSpinLockShared;

    TunQueueProcess(Ctx);
    ExReleaseSpinLockShared(&Ctx->TransitionLock, Irql);
    return STATUS_PENDING;

cleanup_ExReleaseSpinLockShared:
    ExReleaseSpinLockShared(&Ctx->TransitionLock, Irql);
cleanup_CompleteRequest:
    TunCompleteRequest(Ctx, Irp, Status, IO_NO_INCREMENT);
    return Status;
}

#define NET_BUFFER_LIST_MDL_REFCOUNT(Nbl) (NET_BUFFER_LIST_MINIPORT_RESERVED(Nbl)[0])

static MINIPORT_RETURN_NET_BUFFER_LISTS TunReturnNetBufferLists;
_Use_decl_annotations_
static void
TunReturnNetBufferLists(NDIS_HANDLE MiniportAdapterContext, PNET_BUFFER_LIST NetBufferLists, ULONG ReturnFlags)
{
    TUN_CTX *Ctx = (TUN_CTX *)MiniportAdapterContext;

    LONG64 StatSize = 0, StatPacketsOk = 0, StatPacketsError = 0;
    for (NET_BUFFER_LIST *Nbl = NetBufferLists, *NextNbl; Nbl; Nbl = NextNbl)
    {
        NextNbl = NET_BUFFER_LIST_NEXT_NBL(Nbl);
        NET_BUFFER_LIST_NEXT_NBL(Nbl) = NULL;

        if (NT_SUCCESS(NET_BUFFER_LIST_STATUS(Nbl)))
        {
            StatSize += NET_BUFFER_LIST_FIRST_NB(Nbl)->DataLength;
            StatPacketsOk++;
        }
        else
            StatPacketsError++;

        TunCompletePause(Ctx, TRUE);

        LONG volatile *MdlRefCount = NET_BUFFER_LIST_MDL_REFCOUNT(Nbl);
        ASSERT(InterlockedGet(MdlRefCount) > 0);
        if (InterlockedDecrement(MdlRefCount) <= 0)
        {
            /* MdlRefCount is also the first pointer in the allocation. */
            ExFreePoolWithTag((PVOID)MdlRefCount, TUN_MEMORY_TAG);
            NdisFreeMdl(NET_BUFFER_LIST_FIRST_NB(Nbl)->MdlChain);
        }
        NdisFreeNetBufferList(Nbl);
    }

    InterlockedAdd64((LONG64 *)&Ctx->Statistics.ifHCInOctets, StatSize);
    InterlockedAdd64((LONG64 *)&Ctx->Statistics.ifHCInUcastOctets, StatSize);
    InterlockedAdd64((LONG64 *)&Ctx->Statistics.ifHCInUcastPkts, StatPacketsOk);
    InterlockedAdd64((LONG64 *)&Ctx->Statistics.ifInErrors, StatPacketsError);
}

_IRQL_requires_max_(APC_LEVEL)
_Must_inspect_result_
static NTSTATUS
TunDispatchWrite(_Inout_ TUN_CTX *Ctx, _Inout_ IRP *Irp)
{
    NTSTATUS Status;
    IO_STACK_LOCATION *Stack = IoGetCurrentIrpStackLocation(Irp);
    ULONG Size = Stack->Parameters.Write.Length;
    if (Status = STATUS_INVALID_USER_BUFFER, (Size < TUN_EXCH_MIN_BUFFER_SIZE_WRITE || Size > TUN_EXCH_MAX_BUFFER_SIZE))
        goto cleanup_CompleteRequest;
    UCHAR *BufferStart = ExAllocatePoolWithTag(NonPagedPoolNx, Size, TUN_MEMORY_TAG);
    if (Status = STATUS_INSUFFICIENT_RESOURCES, !BufferStart)
        goto cleanup_CompleteRequest;
    /* We don't write to this until we're totally finished using Packet->Size. */
    LONG *MdlRefCount = (LONG *)BufferStart;
    try
    {
        Status = STATUS_INVALID_USER_BUFFER;
        ProbeForRead(Irp->UserBuffer, Size, 1);
        NdisMoveMemory(BufferStart, Irp->UserBuffer, Size);
    }
    except(EXCEPTION_EXECUTE_HANDLER) { goto cleanup_ExFreePoolWithTag; }

    MDL *Mdl = NdisAllocateMdl(Ctx->MiniportAdapterHandle, BufferStart, Size);
    if (Status = STATUS_INSUFFICIENT_RESOURCES, !Mdl)
        goto cleanup_ExFreePoolWithTag;

    const UCHAR *BufferPos = BufferStart, *BufferEnd = BufferStart + Size;
    typedef enum
    {
        EtherTypeIndexIPv4 = 0,
        EtherTypeIndexStart = 0,
        EtherTypeIndexIPv6,
        EtherTypeIndexEnd
    } EtherTypeIndex;
    static const struct
    {
        ULONG NblFlags;
        USHORT NblProto;
    } EtherTypeConstants[EtherTypeIndexEnd] = {
        { NDIS_NBL_FLAGS_IS_IPV4, TUN_HTONS(NDIS_ETH_TYPE_IPV4) },
        { NDIS_NBL_FLAGS_IS_IPV6, TUN_HTONS(NDIS_ETH_TYPE_IPV6) },
    };
    struct
    {
        NET_BUFFER_LIST *Head, *Tail;
        LONG Count;
    } NblQueue[EtherTypeIndexEnd] = { { NULL, NULL, 0 }, { NULL, NULL, 0 } };
    LONG NblCount = 0;
    while (BufferEnd - BufferPos >= sizeof(TUN_PACKET))
    {
        if (Status = STATUS_INVALID_USER_BUFFER, NblCount >= MAXLONG)
            goto cleanup_nbl_queues;
        TUN_PACKET *Packet = (TUN_PACKET *)BufferPos;
        if (Status = STATUS_INVALID_USER_BUFFER, Packet->Size > TUN_EXCH_MAX_IP_PACKET_SIZE)
            goto cleanup_nbl_queues;
        ULONG AlignedPacketSize = TunPacketAlign(sizeof(TUN_PACKET) + Packet->Size);
        if (Status = STATUS_INVALID_USER_BUFFER, (BufferEnd - BufferPos < (ptrdiff_t)AlignedPacketSize))
            goto cleanup_nbl_queues;

        EtherTypeIndex Index;
        if (Packet->Size >= 20 && Packet->Data[0] >> 4 == 4)
            Index = EtherTypeIndexIPv4;
        else if (Packet->Size >= 40 && Packet->Data[0] >> 4 == 6)
            Index = EtherTypeIndexIPv6;
        else
        {
            Status = STATUS_INVALID_USER_BUFFER;
            goto cleanup_nbl_queues;
        }

        NET_BUFFER_LIST *Nbl = NdisAllocateNetBufferAndNetBufferList(
            Ctx->NBLPool, 0, 0, Mdl, (ULONG)(Packet->Data - BufferStart), Packet->Size);
        if (Status = STATUS_INSUFFICIENT_RESOURCES, !Nbl)
            goto cleanup_nbl_queues;

        Nbl->SourceHandle = Ctx->MiniportAdapterHandle;
        NdisSetNblFlag(Nbl, EtherTypeConstants[Index].NblFlags);
        NET_BUFFER_LIST_INFO(Nbl, NetBufferListFrameType) = (PVOID)EtherTypeConstants[Index].NblProto;
        NET_BUFFER_LIST_STATUS(Nbl) = NDIS_STATUS_SUCCESS;
        NET_BUFFER_LIST_MDL_REFCOUNT(Nbl) = MdlRefCount;
        TunAppendNBL(&NblQueue[Index].Head, &NblQueue[Index].Tail, Nbl);
        NblQueue[Index].Count++;
        NblCount++;
        BufferPos += AlignedPacketSize;
    }

    if (Status = STATUS_INVALID_USER_BUFFER, (ULONG)(BufferPos - BufferStart) != Size)
        goto cleanup_nbl_queues;
    Irp->IoStatus.Information = Size;

    if (Status = STATUS_SUCCESS, !NblCount)
        goto cleanup_nbl_queues;

    KIRQL Irql = ExAcquireSpinLockShared(&Ctx->TransitionLock);
    LONG Flags = InterlockedGet(&Ctx->Flags);
    if ((Status = STATUS_FILE_FORCED_CLOSED, !(Flags & TUN_FLAGS_PRESENT)) ||
        (Status = STATUS_SUCCESS, !(Flags & TUN_FLAGS_RUNNING)))
    {
        InterlockedAdd64((LONG64 *)&Ctx->Statistics.ifInDiscards, NblCount);
        InterlockedAdd64((LONG64 *)&Ctx->Statistics.ifInErrors, NblCount);
        goto cleanup_ExReleaseSpinLockShared;
    }

    InterlockedAdd64(&Ctx->ActiveNBLCount, NblCount);
    *MdlRefCount = NblCount;
    for (EtherTypeIndex Index = EtherTypeIndexStart; Index < EtherTypeIndexEnd; Index++)
    {
        if (!NblQueue[Index].Head)
            continue;
        NdisMIndicateReceiveNetBufferLists(
            Ctx->MiniportAdapterHandle,
            NblQueue[Index].Head,
            NDIS_DEFAULT_PORT_NUMBER,
            NblQueue[Index].Count,
            NDIS_RECEIVE_FLAGS_SINGLE_ETHER_TYPE | NDIS_RECEIVE_FLAGS_DISPATCH_LEVEL);
    }

    ExReleaseSpinLockShared(&Ctx->TransitionLock, Irql);
    TunCompleteRequest(Ctx, Irp, STATUS_SUCCESS, IO_NETWORK_INCREMENT);
    return STATUS_SUCCESS;

cleanup_ExReleaseSpinLockShared:
    ExReleaseSpinLockShared(&Ctx->TransitionLock, Irql);
cleanup_nbl_queues:
    for (EtherTypeIndex Index = EtherTypeIndexStart; Index < EtherTypeIndexEnd; Index++)
    {
        for (NET_BUFFER_LIST *Nbl = NblQueue[Index].Head, *NextNbl; Nbl; Nbl = NextNbl)
        {
            NextNbl = NET_BUFFER_LIST_NEXT_NBL(Nbl);
            NET_BUFFER_LIST_NEXT_NBL(Nbl) = NULL;
            NdisFreeNetBufferList(Nbl);
        }
    }
    NdisFreeMdl(Mdl);
cleanup_ExFreePoolWithTag:
    ExFreePoolWithTag(BufferStart, TUN_MEMORY_TAG);
cleanup_CompleteRequest:
    TunCompleteRequest(Ctx, Irp, Status, IO_NO_INCREMENT);
    return Status;
}

_IRQL_requires_max_(APC_LEVEL)
_Must_inspect_result_
static NTSTATUS
TunDispatchCreate(_Inout_ TUN_CTX *Ctx, _Inout_ IRP *Irp)
{
    NTSTATUS Status;
    TUN_FILE_CTX *FileCtx = ExAllocatePoolWithTag(NonPagedPoolNx, sizeof(*FileCtx), TUN_MEMORY_TAG);
    if (!FileCtx)
        return STATUS_INSUFFICIENT_RESOURCES;
    RtlZeroMemory(FileCtx, sizeof(*FileCtx));
    ExInitializeFastMutex(&FileCtx->ReadBuffer.InitializationComplete);

    KIRQL Irql = ExAcquireSpinLockShared(&Ctx->TransitionLock);
    LONG Flags = InterlockedGet(&Ctx->Flags);
    if ((Status = STATUS_DELETE_PENDING, !(Flags & TUN_FLAGS_PRESENT)))
        goto cleanup_ExReleaseSpinLockShared;

    IO_STACK_LOCATION *Stack = IoGetCurrentIrpStackLocation(Irp);
    if (!NT_SUCCESS(Status = IoAcquireRemoveLock(&Ctx->Device.RemoveLock, Stack->FileObject)))
        goto cleanup_ExReleaseSpinLockShared;
    Stack->FileObject->FsContext = FileCtx;

    if (InterlockedIncrement64(&Ctx->Device.RefCount) == 1)
        TunIndicateStatus(Ctx->MiniportAdapterHandle, MediaConnectStateConnected);

    Status = STATUS_SUCCESS;

cleanup_ExReleaseSpinLockShared:
    ExReleaseSpinLockShared(&Ctx->TransitionLock, Irql);
    TunCompleteRequest(Ctx, Irp, Status, IO_NO_INCREMENT);
    if (!NT_SUCCESS(Status))
        ExFreePoolWithTag(FileCtx, TUN_MEMORY_TAG);
    return Status;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
static void
TunDispatchClose(_Inout_ TUN_CTX *Ctx, _Inout_ IRP *Irp)
{
    IO_STACK_LOCATION *Stack = IoGetCurrentIrpStackLocation(Irp);
    ASSERT(InterlockedGet64(&Ctx->Device.RefCount) > 0);
    BOOLEAN IsLastFileHandle = InterlockedDecrement64(&Ctx->Device.RefCount) <= 0;
    ExReleaseSpinLockExclusive(
        &Ctx->TransitionLock,
        ExAcquireSpinLockExclusive(&Ctx->TransitionLock)); /* Ensure above change is visible to all readers. */
    if (IsLastFileHandle)
    {
        NDIS_HANDLE AdapterHandle = InterlockedGetPointer(&Ctx->MiniportAdapterHandle);
        if (AdapterHandle)
            TunIndicateStatus(AdapterHandle, MediaConnectStateDisconnected);
        TunQueueClear(Ctx, NDIS_STATUS_MEDIA_DISCONNECTED);
    }
    TUN_FILE_CTX *FileCtx = (TUN_FILE_CTX *)Stack->FileObject->FsContext;
    TunUnmapUbuffer(&FileCtx->ReadBuffer);
    ExFreePoolWithTag(FileCtx, TUN_MEMORY_TAG);
    IoReleaseRemoveLock(&Ctx->Device.RemoveLock, Stack->FileObject);
}

static DRIVER_DISPATCH TunDispatch;
_Use_decl_annotations_
static NTSTATUS
TunDispatch(DEVICE_OBJECT *DeviceObject, IRP *Irp)
{
    NTSTATUS Status = STATUS_SUCCESS;

    Irp->IoStatus.Information = 0;
    TUN_CTX *Ctx = NdisGetDeviceReservedExtension(DeviceObject);
    if (!Ctx)
    {
        Status = STATUS_INVALID_HANDLE;
        goto cleanup_complete_req;
    }

    IO_STACK_LOCATION *Stack = IoGetCurrentIrpStackLocation(Irp);
    switch (Stack->MajorFunction)
    {
    case IRP_MJ_READ:
        if (!NT_SUCCESS(Status = IoAcquireRemoveLock(&Ctx->Device.RemoveLock, Irp)))
            goto cleanup_complete_req;
        return TunDispatchRead(Ctx, Irp);

    case IRP_MJ_WRITE:
        if (!NT_SUCCESS(Status = IoAcquireRemoveLock(&Ctx->Device.RemoveLock, Irp)))
            goto cleanup_complete_req;
        return TunDispatchWrite(Ctx, Irp);

    case IRP_MJ_CREATE:
        if (!NT_SUCCESS(Status = IoAcquireRemoveLock(&Ctx->Device.RemoveLock, Irp)))
            goto cleanup_complete_req;
        return TunDispatchCreate(Ctx, Irp);

    case IRP_MJ_CLOSE:
        TunDispatchClose(Ctx, Irp);
        break;

    case IRP_MJ_CLEANUP:
        for (IRP *PendingIrp; (PendingIrp = IoCsqRemoveNextIrp(&Ctx->Device.ReadQueue.Csq, Stack->FileObject)) != NULL;)
            TunCompleteRequest(Ctx, PendingIrp, STATUS_CANCELLED, IO_NO_INCREMENT);
        break;

    default:
        Status = STATUS_INVALID_PARAMETER;
        break;
    }

cleanup_complete_req:
    Irp->IoStatus.Status = Status;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return Status;
}

_Dispatch_type_(IRP_MJ_PNP) static DRIVER_DISPATCH TunDispatchPnP;
_Use_decl_annotations_
static NTSTATUS
TunDispatchPnP(DEVICE_OBJECT *DeviceObject, IRP *Irp)
{
    IO_STACK_LOCATION *Stack = IoGetCurrentIrpStackLocation(Irp);
    if (Stack->MajorFunction == IRP_MJ_PNP)
    {
#pragma warning(suppress : 28175)
        TUN_CTX *Ctx = DeviceObject->Reserved;
        if (!Ctx)
            return NdisDispatchPnP(DeviceObject, Irp);

        switch (Stack->MinorFunction)
        {
        case IRP_MN_QUERY_REMOVE_DEVICE:
        case IRP_MN_SURPRISE_REMOVAL:
            InterlockedAnd(&Ctx->Flags, ~TUN_FLAGS_PRESENT);
            ExReleaseSpinLockExclusive(
                &Ctx->TransitionLock,
                ExAcquireSpinLockExclusive(&Ctx->TransitionLock)); /* Ensure above change is visible to all readers. */
            TunQueueClear(Ctx, NDIS_STATUS_ADAPTER_REMOVED);
            break;

        case IRP_MN_CANCEL_REMOVE_DEVICE:
            InterlockedOr(&Ctx->Flags, TUN_FLAGS_PRESENT);
            break;
        }
    }

    return NdisDispatchPnP(DeviceObject, Irp);
}

static MINIPORT_RESTART TunRestart;
_Use_decl_annotations_
static NDIS_STATUS
TunRestart(NDIS_HANDLE MiniportAdapterContext, PNDIS_MINIPORT_RESTART_PARAMETERS MiniportRestartParameters)
{
    TUN_CTX *Ctx = (TUN_CTX *)MiniportAdapterContext;

    InterlockedExchange64(&Ctx->ActiveNBLCount, 1);
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
    TunQueueClear(Ctx, NDIS_STATUS_PAUSED);

    return TunCompletePause(Ctx, FALSE);
}

static MINIPORT_DEVICE_PNP_EVENT_NOTIFY TunDevicePnPEventNotify;
_Use_decl_annotations_
static void
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

    /* Register device first. Having only one device per adapter allows us to store
     * adapter context inside device extension. */
    WCHAR DeviceName[sizeof(L"\\Device\\" TUN_DEVICE_NAME L"4294967295") / sizeof(WCHAR) + 1] = { 0 };
    UNICODE_STRING UnicodeDeviceName;
    TunInitUnicodeString(&UnicodeDeviceName, DeviceName);
    RtlUnicodeStringPrintf(
        &UnicodeDeviceName, L"\\Device\\" TUN_DEVICE_NAME, (ULONG)MiniportInitParameters->NetLuid.Info.NetLuidIndex);

    WCHAR SymbolicName[sizeof(L"\\DosDevices\\" TUN_DEVICE_NAME L"4294967295") / sizeof(WCHAR) + 1] = { 0 };
    UNICODE_STRING UnicodeSymbolicName;
    TunInitUnicodeString(&UnicodeSymbolicName, SymbolicName);
    RtlUnicodeStringPrintf(
        &UnicodeSymbolicName,
        L"\\DosDevices\\" TUN_DEVICE_NAME,
        (ULONG)MiniportInitParameters->NetLuid.Info.NetLuidIndex);

    static PDRIVER_DISPATCH DispatchTable[IRP_MJ_MAXIMUM_FUNCTION + 1] = {
        TunDispatch, /* IRP_MJ_CREATE                   */
        NULL,        /* IRP_MJ_CREATE_NAMED_PIPE        */
        TunDispatch, /* IRP_MJ_CLOSE                    */
        TunDispatch, /* IRP_MJ_READ                     */
        TunDispatch, /* IRP_MJ_WRITE                    */
        NULL,        /* IRP_MJ_QUERY_INFORMATION        */
        NULL,        /* IRP_MJ_SET_INFORMATION          */
        NULL,        /* IRP_MJ_QUERY_EA                 */
        NULL,        /* IRP_MJ_SET_EA                   */
        NULL,        /* IRP_MJ_FLUSH_BUFFERS            */
        NULL,        /* IRP_MJ_QUERY_VOLUME_INFORMATION */
        NULL,        /* IRP_MJ_SET_VOLUME_INFORMATION   */
        NULL,        /* IRP_MJ_DIRECTORY_CONTROL        */
        NULL,        /* IRP_MJ_FILE_SYSTEM_CONTROL      */
        NULL,        /* IRP_MJ_DEVICE_CONTROL           */
        NULL,        /* IRP_MJ_INTERNAL_DEVICE_CONTROL  */
        NULL,        /* IRP_MJ_SHUTDOWN                 */
        NULL,        /* IRP_MJ_LOCK_CONTROL             */
        TunDispatch, /* IRP_MJ_CLEANUP                  */
    };
    NDIS_DEVICE_OBJECT_ATTRIBUTES DeviceObjectAttributes = {
        .Header = { .Type = NDIS_OBJECT_TYPE_DEVICE_OBJECT_ATTRIBUTES,
                    .Revision = NDIS_DEVICE_OBJECT_ATTRIBUTES_REVISION_1,
                    .Size = NDIS_SIZEOF_DEVICE_OBJECT_ATTRIBUTES_REVISION_1 },
        .DeviceName = &UnicodeDeviceName,
        .SymbolicName = &UnicodeSymbolicName,
        .MajorFunctions = DispatchTable,
        .ExtensionSize = sizeof(TUN_CTX),
        .DefaultSDDLString = &SDDL_DEVOBJ_SYS_ALL /* Kernel, and SYSTEM: full control. Others: none */
    };
    NDIS_HANDLE DeviceObjectHandle;
    DEVICE_OBJECT *DeviceObject;
    if (!NT_SUCCESS(
            Status = NdisRegisterDeviceEx(
                NdisMiniportDriverHandle, &DeviceObjectAttributes, &DeviceObject, &DeviceObjectHandle)))
        return NDIS_STATUS_FAILURE;

    DeviceObject->Flags &= ~(DO_BUFFERED_IO | DO_DIRECT_IO);

    TUN_CTX *Ctx = NdisGetDeviceReservedExtension(DeviceObject);
    if (!Ctx)
    {
        Status = NDIS_STATUS_FAILURE;
        goto cleanup_NdisDeregisterDeviceEx;
    }
    DEVICE_OBJECT *FunctionalDeviceObject;
    NdisMGetDeviceProperty(MiniportAdapterHandle, NULL, &FunctionalDeviceObject, NULL, NULL, NULL);

    /* Reverse engineering indicates that we'd be better off calling
     * NdisWdfGetAdapterContextFromAdapterHandle(functional_device),
     * which points to our TUN_CTX object directly, but this isn't
     * available before Windows 10, so for now we just stick it into
     * this reserved field. Revisit this when we drop support for old
     * Windows versions. */
#pragma warning(suppress : 28175)
    ASSERT(!FunctionalDeviceObject->Reserved);
#pragma warning(suppress : 28175)
    FunctionalDeviceObject->Reserved = Ctx;

    NdisZeroMemory(Ctx, sizeof(*Ctx));
    Ctx->MiniportAdapterHandle = MiniportAdapterHandle;

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

    Ctx->Device.Handle = DeviceObjectHandle;
    Ctx->Device.Object = DeviceObject;
    IoInitializeRemoveLock(&Ctx->Device.RemoveLock, TUN_MEMORY_TAG, 0, 0);
    KeInitializeSpinLock(&Ctx->Device.ReadQueue.Lock);
    IoCsqInitializeEx(
        &Ctx->Device.ReadQueue.Csq,
        TunCsqInsertIrpEx,
        TunCsqRemoveIrp,
        TunCsqPeekNextIrp,
        TunCsqAcquireLock,
        TunCsqReleaseLock,
        TunCsqCompleteCanceledIrp);
    InitializeListHead(&Ctx->Device.ReadQueue.List);

    KeInitializeSpinLock(&Ctx->PacketQueue.Lock);

    NET_BUFFER_LIST_POOL_PARAMETERS NblPoolParameters = {
        .Header = { .Type = NDIS_OBJECT_TYPE_DEFAULT,
                    .Revision = NET_BUFFER_LIST_POOL_PARAMETERS_REVISION_1,
                    .Size = NDIS_SIZEOF_NET_BUFFER_LIST_POOL_PARAMETERS_REVISION_1 },
        .ProtocolId = NDIS_PROTOCOL_ID_DEFAULT,
        .fAllocateNetBuffer = TRUE,
        .PoolTag = TUN_MEMORY_TAG
    };
#pragma warning( \
    suppress : 6014) /* Leaking memory 'ctx->NBLPool'. Note: 'ctx->NBLPool' is freed in TunHaltEx; or on failure. */
    Ctx->NBLPool = NdisAllocateNetBufferListPool(MiniportAdapterHandle, &NblPoolParameters);
    if (!Ctx->NBLPool)
    {
        Status = NDIS_STATUS_FAILURE;
        goto cleanup_NdisDeregisterDeviceEx;
    }

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
    if (!NT_SUCCESS(
            Status = NdisMSetMiniportAttributes(
                MiniportAdapterHandle, (PNDIS_MINIPORT_ADAPTER_ATTRIBUTES)&AdapterRegistrationAttributes)))
    {
        Status = NDIS_STATUS_FAILURE;
        goto cleanup_NdisFreeNetBufferListPool;
    }

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
        .MtuSize = TUN_EXCH_MAX_IP_PACKET_SIZE,
        .MaxXmitLinkSpeed = TUN_LINK_SPEED,
        .MaxRcvLinkSpeed = TUN_LINK_SPEED,
        .RcvLinkSpeed = TUN_LINK_SPEED,
        .XmitLinkSpeed = TUN_LINK_SPEED,
        .MediaConnectState = MediaConnectStateDisconnected,
        .LookaheadSize = TUN_EXCH_MAX_IP_PACKET_SIZE,
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
    if (!NT_SUCCESS(
            Status = NdisMSetMiniportAttributes(
                MiniportAdapterHandle, (PNDIS_MINIPORT_ADAPTER_ATTRIBUTES)&AdapterGeneralAttributes)))
    {
        Status = NDIS_STATUS_FAILURE;
        goto cleanup_NdisFreeNetBufferListPool;
    }

    /* A miniport driver can call NdisMIndicateStatusEx after setting its
     * registration attributes even if the driver is still in the context
     * of the MiniportInitializeEx function. */
    TunIndicateStatus(MiniportAdapterHandle, MediaConnectStateDisconnected);
    InterlockedIncrement64(&TunAdapterCount);
    InterlockedOr(&Ctx->Flags, TUN_FLAGS_PRESENT);
    return NDIS_STATUS_SUCCESS;

cleanup_NdisFreeNetBufferListPool:
    NdisFreeNetBufferListPool(Ctx->NBLPool);
cleanup_NdisDeregisterDeviceEx:
    NdisDeregisterDeviceEx(DeviceObjectHandle);
    return Status;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
static NTSTATUS
TunDeviceSetDenyAllDacl(_In_ DEVICE_OBJECT *DeviceObject)
{
    NTSTATUS Status;
    SECURITY_DESCRIPTOR Sd;
    ACL Acl;
    HANDLE DeviceObjectHandle;

    if (!NT_SUCCESS(Status = RtlCreateSecurityDescriptor(&Sd, SECURITY_DESCRIPTOR_REVISION)))
        return Status;
    if (!NT_SUCCESS(Status = RtlCreateAcl(&Acl, sizeof(ACL), ACL_REVISION)))
        return Status;
    if (!NT_SUCCESS(Status = RtlSetDaclSecurityDescriptor(&Sd, TRUE, &Acl, FALSE)))
        return Status;
    Status = ObOpenObjectByPointer(
        DeviceObject, OBJ_KERNEL_HANDLE, NULL, WRITE_DAC, *IoDeviceObjectType, KernelMode, &DeviceObjectHandle);
    if (!NT_SUCCESS(Status))
        return Status;

    Status = ZwSetSecurityObject(DeviceObjectHandle, DACL_SECURITY_INFORMATION, &Sd);

    ZwClose(DeviceObjectHandle);
    return Status;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
static void
TunForceHandlesClosed(_Inout_ TUN_CTX *Ctx)
{
    NTSTATUS Status;
    PEPROCESS Process;
    KAPC_STATE ApcState;
    PVOID Object = NULL;
    ULONG VerifierFlags = 0;
    OBJECT_HANDLE_INFORMATION HandleInfo;
    SYSTEM_HANDLE_INFORMATION_EX *HandleTable = NULL;

    MmIsVerifierEnabled(&VerifierFlags);

    for (ULONG Size = 0, RequestedSize;
         (Status = ZwQuerySystemInformation(SystemExtendedHandleInformation, HandleTable, Size, &RequestedSize)) ==
         STATUS_INFO_LENGTH_MISMATCH;
         Size = RequestedSize)
    {
        if (HandleTable)
            ExFreePoolWithTag(HandleTable, TUN_MEMORY_TAG);
        HandleTable = ExAllocatePoolWithTag(PagedPool, RequestedSize, TUN_MEMORY_TAG);
        if (!HandleTable)
            return;
    }
    if (!NT_SUCCESS(Status) || !HandleTable)
        goto out;

    for (ULONG_PTR Index = 0; Index < HandleTable->NumberOfHandles; ++Index)
    {
        /* XXX: We should perhaps first look at table->Handles[i].ObjectTypeIndex, but
         * the value changes lots between NT versions, and it should be implicit anyway. */
        FILE_OBJECT *FileObject = HandleTable->Handles[Index].Object;
        if (!FileObject || FileObject->Type != 5 || FileObject->DeviceObject != Ctx->Device.Object)
            continue;
        Status = PsLookupProcessByProcessId(HandleTable->Handles[Index].UniqueProcessId, &Process);
        if (!NT_SUCCESS(Status))
            continue;
        KeStackAttachProcess(Process, &ApcState);
        if (!VerifierFlags)
            Status = ObReferenceObjectByHandle(
                HandleTable->Handles[Index].HandleValue, 0, NULL, UserMode, &Object, &HandleInfo);
        if (NT_SUCCESS(Status))
        {
            if (VerifierFlags || Object == FileObject)
                ObCloseHandle(HandleTable->Handles[Index].HandleValue, UserMode);
            if (!VerifierFlags)
                ObfDereferenceObject(Object);
        }
        KeUnstackDetachProcess(&ApcState);
        ObfDereferenceObject(Process);
    }
out:
    if (HandleTable)
        ExFreePoolWithTag(HandleTable, TUN_MEMORY_TAG);
}

_IRQL_requires_max_(APC_LEVEL)
static void
TunWaitForReferencesToDropToZero(_In_ DEVICE_OBJECT *DeviceObject)
{
    /* The sleep loop isn't pretty, but we don't have a choice. This is an NDIS bug we're working around. */
    enum
    {
        SleepTime = 50,
        TotalTime = 2 * 60 * 1000,
        MaxTries = TotalTime / SleepTime
    };
#pragma warning(suppress : 28175)
    for (int Try = 0; Try < MaxTries && DeviceObject->ReferenceCount; ++Try)
        NdisMSleep(SleepTime);
}

static MINIPORT_HALT TunHaltEx;
_Use_decl_annotations_
static void
TunHaltEx(NDIS_HANDLE MiniportAdapterContext, NDIS_HALT_ACTION HaltAction)
{
    TUN_CTX *Ctx = (TUN_CTX *)MiniportAdapterContext;

    ASSERT(!InterlockedGet64(&Ctx->ActiveNBLCount)); /* Adapter should not be halted if there are (potential)
                                                      * active NBLs present. */

    InterlockedAnd(&Ctx->Flags, ~TUN_FLAGS_PRESENT);
    ExReleaseSpinLockExclusive(
        &Ctx->TransitionLock,
        ExAcquireSpinLockExclusive(&Ctx->TransitionLock)); /* Ensure above change is visible to all readers. */

    for (IRP *PendingIrp; (PendingIrp = IoCsqRemoveNextIrp(&Ctx->Device.ReadQueue.Csq, NULL)) != NULL;)
        TunCompleteRequest(Ctx, PendingIrp, STATUS_FILE_FORCED_CLOSED, IO_NO_INCREMENT);

    /* Setting a deny-all DACL we prevent userspace to open the device by symlink after TunForceHandlesClosed(). */
    TunDeviceSetDenyAllDacl(Ctx->Device.Object);

    if (InterlockedGet64(&Ctx->Device.RefCount))
        TunForceHandlesClosed(Ctx);

    /* Wait for processing IRP(s) to complete. */
    IoAcquireRemoveLock(&Ctx->Device.RemoveLock, NULL);
    IoReleaseRemoveLockAndWait(&Ctx->Device.RemoveLock, NULL);
    NdisFreeNetBufferListPool(Ctx->NBLPool);

    /* MiniportAdapterHandle must not be used in TunDispatch(). After TunHaltEx() returns it is invalidated. */
    InterlockedExchangePointer(&Ctx->MiniportAdapterHandle, NULL);

    ASSERT(InterlockedGet64(&TunAdapterCount) > 0);
    if (InterlockedDecrement64(&TunAdapterCount) <= 0)
        TunWaitForReferencesToDropToZero(Ctx->Device.Object);

    /* Deregister device _after_ we are done using ctx not to risk an UaF. The ctx is hosted by device extension. */
    NdisDeregisterDeviceEx(Ctx->Device.Handle);
}

static MINIPORT_SHUTDOWN TunShutdownEx;
_Use_decl_annotations_
static void
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
TunOidQuery(_Inout_ TUN_CTX *ctx, _Inout_ NDIS_OID_REQUEST *OidRequest)
{
    ASSERT(
        OidRequest->RequestType == NdisRequestQueryInformation ||
        OidRequest->RequestType == NdisRequestQueryStatistics);

    switch (OidRequest->DATA.QUERY_INFORMATION.Oid)
    {
    case OID_GEN_MAXIMUM_TOTAL_SIZE:
    case OID_GEN_TRANSMIT_BLOCK_SIZE:
    case OID_GEN_RECEIVE_BLOCK_SIZE:
        return TunOidQueryWrite(OidRequest, TUN_EXCH_MAX_IP_PACKET_SIZE);

    case OID_GEN_TRANSMIT_BUFFER_SPACE:
        return TunOidQueryWrite(OidRequest, TUN_EXCH_MAX_IP_PACKET_SIZE * TUN_QUEUE_MAX_NBLS);

    case OID_GEN_RECEIVE_BUFFER_SPACE:
        return TunOidQueryWrite(OidRequest, TUN_EXCH_MAX_IP_PACKET_SIZE * TUN_EXCH_MAX_PACKETS);

    case OID_GEN_VENDOR_ID:
        return TunOidQueryWrite(OidRequest, TUN_HTONL(TUN_VENDOR_ID));

    case OID_GEN_VENDOR_DESCRIPTION:
        return TunOidQueryWriteBuf(OidRequest, TUN_VENDOR_NAME, (ULONG)sizeof(TUN_VENDOR_NAME));

    case OID_GEN_VENDOR_DRIVER_VERSION:
        return TunOidQueryWrite(OidRequest, (WINTUN_VERSION_MAJ << 16) | WINTUN_VERSION_MIN);

    case OID_GEN_XMIT_OK:
        return TunOidQueryWrite32or64(
            OidRequest,
            InterlockedGet64((LONG64 *)&ctx->Statistics.ifHCOutUcastPkts) +
                InterlockedGet64((LONG64 *)&ctx->Statistics.ifHCOutMulticastPkts) +
                InterlockedGet64((LONG64 *)&ctx->Statistics.ifHCOutBroadcastPkts));

    case OID_GEN_RCV_OK:
        return TunOidQueryWrite32or64(
            OidRequest,
            InterlockedGet64((LONG64 *)&ctx->Statistics.ifHCInUcastPkts) +
                InterlockedGet64((LONG64 *)&ctx->Statistics.ifHCInMulticastPkts) +
                InterlockedGet64((LONG64 *)&ctx->Statistics.ifHCInBroadcastPkts));

    case OID_GEN_STATISTICS:
        return TunOidQueryWriteBuf(OidRequest, &ctx->Statistics, (ULONG)sizeof(ctx->Statistics));

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
TunOidSet(_Inout_ TUN_CTX *ctx, _Inout_ NDIS_OID_REQUEST *OidRequest)
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
static void
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
static void
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
}

DRIVER_INITIALIZE DriverEntry;
_Use_decl_annotations_
NTSTATUS
DriverEntry(DRIVER_OBJECT *DriverObject, UNICODE_STRING *RegistryPath)
{
    NTSTATUS status;

    NdisVersion = NdisGetVersion();
    if (NdisVersion < NDIS_MINIPORT_VERSION_MIN)
        return NDIS_STATUS_UNSUPPORTED_REVISION;
    if (NdisVersion > NDIS_MINIPORT_VERSION_MAX)
        NdisVersion = NDIS_MINIPORT_VERSION_MAX;

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
    status = NdisMRegisterMiniportDriver(DriverObject, RegistryPath, NULL, &miniport, &NdisMiniportDriverHandle);
    if (!NT_SUCCESS(status))
        return status;

    NdisDispatchPnP = DriverObject->MajorFunction[IRP_MJ_PNP];
    DriverObject->MajorFunction[IRP_MJ_PNP] = TunDispatchPnP;

    return STATUS_SUCCESS;
}

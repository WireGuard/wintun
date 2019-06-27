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

#pragma warning(disable : 4100) // unreferenced formal parameter
#pragma warning(disable : 4200) // nonstandard extension used: zero-sized array in struct/union
#pragma warning(disable : 4204) // nonstandard extension used: non-constant aggregate initializer
#pragma warning(disable : 4221) // nonstandard extension used: <member>: cannot be initialized using address of
                                // automatic variable <variable>
#pragma warning(disable : 6320) // exception-filter expression is the constant EXCEPTION_EXECUTE_HANDLER

#define NDIS_MINIPORT_VERSION_MIN ((NDIS_MINIPORT_MINIMUM_MAJOR_VERSION << 16) | NDIS_MINIPORT_MINIMUM_MINOR_VERSION)
#define NDIS_MINIPORT_VERSION_MAX ((NDIS_MINIPORT_MAJOR_VERSION << 16) | NDIS_MINIPORT_MINOR_VERSION)

#define TUN_DEVICE_NAME L"WINTUN%u"

#define TUN_VENDOR_NAME "Wintun Tunnel"
#define TUN_VENDOR_ID 0xFFFFFF00
#define TUN_LINK_SPEED 100000000000ULL // 100gbps

// Maximum number of full-sized exchange packets that can be exchanged in a single read/write.
#define TUN_EXCH_MAX_PACKETS 256
// Maximum exchange packet size - empirically determined by net buffer list (pool) limitations
#define TUN_EXCH_MAX_PACKET_SIZE 0xF000
#define TUN_EXCH_ALIGNMENT 16 // Memory alignment in exchange buffers
// Maximum IP packet size (headers + payload)
#define TUN_EXCH_MAX_IP_PACKET_SIZE (TUN_EXCH_MAX_PACKET_SIZE - sizeof(TUN_PACKET))
// Maximum size of read/write exchange buffer
#define TUN_EXCH_MAX_BUFFER_SIZE (TUN_EXCH_MAX_PACKETS * TUN_EXCH_MAX_PACKET_SIZE)
#define TUN_EXCH_MIN_BUFFER_SIZE_READ TUN_EXCH_MAX_PACKET_SIZE // Minimum size of read exchange buffer
#define TUN_EXCH_MIN_BUFFER_SIZE_WRITE (sizeof(TUN_PACKET))    // Minimum size of write exchange buffer
#define TUN_QUEUE_MAX_NBLS 1000
#define TUN_MEMORY_TAG 'wtun'
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

typedef struct _TUN_PACKET
{
    ULONG Size; // Size of packet data (TUN_EXCH_MAX_IP_PACKET_SIZE max)
    _Field_size_bytes_(Size) __declspec(align(TUN_EXCH_ALIGNMENT)) UCHAR Data[]; // Packet data
} TUN_PACKET;

typedef enum _TUN_FLAGS
{
    TUN_FLAGS_RUNNING = 1 << 0, // Toggles between paused and running state
    TUN_FLAGS_PRESENT = 1 << 1, // Toggles between removal pending and being present
} TUN_FLAGS;

typedef struct _TUN_CTX
{
    volatile LONG Flags;

    /* Used like RCU. When we're making use of queues, we take a shared lock. When we want to
     * drain the queues and toggle the state, we take an exclusive lock before toggling the
     * atomic and then releasing. It's similar to setting the atomic and then calling rcu_barrier(). */
    EX_SPIN_LOCK TransitionLock;

    NDIS_HANDLE MiniportAdapterHandle; // This is actually a pointer to NDIS_MINIPORT_BLOCK struct.
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
        LONG NumNbl;
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
    // TODO: ThreadID for checking
} TUN_MAPPED_UBUFFER;

typedef struct _TUN_FILE_CTX
{
    TUN_MAPPED_UBUFFER ReadBuffer;
    TUN_MAPPED_UBUFFER WriteBuffer;
} TUN_FILE_CTX;

static UINT NdisVersion;
static NDIS_HANDLE NdisMiniportDriverHandle;
static DRIVER_DISPATCH *NdisDispatchPnP;
static volatile LONG64 TunAdapterCount;

#define InterlockedGet(val) (InterlockedAdd((val), 0))
#define InterlockedGet64(val) (InterlockedAdd64((val), 0))
#define InterlockedGetPointer(val) (InterlockedCompareExchangePointer((val), NULL, NULL))
#define TunPacketAlign(size) (((UINT)(size) + (UINT)(TUN_EXCH_ALIGNMENT - 1)) & ~(UINT)(TUN_EXCH_ALIGNMENT - 1))
#define TunInitUnicodeString(str, buf) \
    { \
        (str)->Length = 0; \
        (str)->MaximumLength = sizeof(buf); \
        (str)->Buffer = buf; \
    }

_IRQL_requires_max_(DISPATCH_LEVEL)
_IRQL_requires_same_ static void
TunIndicateStatus(_In_ NDIS_HANDLE MiniportAdapterHandle, _In_ NDIS_MEDIA_CONNECT_STATE MediaConnectState)
{
    NDIS_LINK_STATE state = { .Header = { .Type = NDIS_OBJECT_TYPE_DEFAULT,
                                          .Revision = NDIS_LINK_STATE_REVISION_1,
                                          .Size = NDIS_SIZEOF_LINK_STATE_REVISION_1 },
                              .MediaConnectState = MediaConnectState,
                              .MediaDuplexState = MediaDuplexStateFull,
                              .XmitLinkSpeed = TUN_LINK_SPEED,
                              .RcvLinkSpeed = TUN_LINK_SPEED,
                              .PauseFunctions = NdisPauseFunctionsUnsupported };

    NDIS_STATUS_INDICATION t = { .Header = { .Type = NDIS_OBJECT_TYPE_STATUS_INDICATION,
                                             .Revision = NDIS_STATUS_INDICATION_REVISION_1,
                                             .Size = NDIS_SIZEOF_STATUS_INDICATION_REVISION_1 },
                                 .SourceHandle = MiniportAdapterHandle,
                                 .StatusCode = NDIS_STATUS_LINK_STATE,
                                 .StatusBuffer = &state,
                                 .StatusBufferSize = sizeof(state) };

    NdisMIndicateStatusEx(MiniportAdapterHandle, &t);
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
    TUN_CTX *ctx = CONTAINING_RECORD(Csq, TUN_CTX, Device.ReadQueue.Csq);
    (InsertContext == TUN_CSQ_INSERT_HEAD ? InsertHeadList
                                          : InsertTailList)(&ctx->Device.ReadQueue.List, &Irp->Tail.Overlay.ListEntry);
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
    TUN_CTX *ctx = CONTAINING_RECORD(Csq, TUN_CTX, Device.ReadQueue.Csq);

    /* If the IRP is non-NULL, we will start peeking from that IRP onwards, else
     * we will start from the listhead. This is done under the assumption that
     * new IRPs are always inserted at the tail. */
    for (LIST_ENTRY *head = &ctx->Device.ReadQueue.List, *next = Irp ? Irp->Tail.Overlay.ListEntry.Flink : head->Flink;
         next != head;
         next = next->Flink)
    {
        IRP *irp_next = CONTAINING_RECORD(next, IRP, Tail.Overlay.ListEntry);
        if (!PeekContext)
            return irp_next;

        IO_STACK_LOCATION *stack = IoGetCurrentIrpStackLocation(irp_next);
        if (stack->FileObject == (FILE_OBJECT *)PeekContext)
            return irp_next;
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
    TUN_CTX *ctx = CONTAINING_RECORD(Csq, TUN_CTX, Device.ReadQueue.Csq);
    TunCompleteRequest(ctx, Irp, STATUS_CANCELLED, IO_NO_INCREMENT);
}

_IRQL_requires_max_(APC_LEVEL)
_Must_inspect_result_
static NTSTATUS
TunMapUbuffer(_Inout_ TUN_MAPPED_UBUFFER *MappedBuffer, _In_ VOID *UserAddress, _In_ ULONG Size)
{
    VOID *current_uaddr = InterlockedGetPointer(&MappedBuffer->UserAddress);
    if (current_uaddr)
    {
        if (UserAddress != current_uaddr || Size > MappedBuffer->Size) // TODO: Check ThreadID
            return STATUS_ALREADY_INITIALIZED;
        return STATUS_SUCCESS;
    }

    NTSTATUS status = STATUS_SUCCESS;
    ExAcquireFastMutex(&MappedBuffer->InitializationComplete);

    // Recheck the same thing as above, but locked this time.
    current_uaddr = InterlockedGetPointer(&MappedBuffer->UserAddress);
    if (current_uaddr)
    {
        if (UserAddress != current_uaddr || Size > MappedBuffer->Size) // TODO: Check ThreadID
            status = STATUS_ALREADY_INITIALIZED;
        goto err_releasemutex;
    }

    MappedBuffer->Mdl = IoAllocateMdl(UserAddress, Size, FALSE, FALSE, NULL);
    status = STATUS_INSUFFICIENT_RESOURCES;
    if (!MappedBuffer->Mdl)
        goto err_releasemutex;

    status = STATUS_INVALID_USER_BUFFER;
    try
    {
        MmProbeAndLockPages(MappedBuffer->Mdl, UserMode, IoWriteAccess);
    }
    except(EXCEPTION_EXECUTE_HANDLER) { goto err_freemdl; }

    MappedBuffer->KernelAddress =
        MmGetSystemAddressForMdlSafe(MappedBuffer->Mdl, NormalPagePriority | MdlMappingNoExecute);
    status = STATUS_INSUFFICIENT_RESOURCES;
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
    return status;
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
    ULONG size;
    TUN_MAPPED_UBUFFER *ubuffer;
    IO_STACK_LOCATION *stack = IoGetCurrentIrpStackLocation(Irp);
    TUN_FILE_CTX *file_ctx = (TUN_FILE_CTX *)stack->FileObject->FsContext;

    switch (stack->MajorFunction)
    {
    case IRP_MJ_READ:
        size = stack->Parameters.Read.Length;
        if (size < TUN_EXCH_MIN_BUFFER_SIZE_READ)
            return STATUS_INVALID_USER_BUFFER;
        ubuffer = &file_ctx->ReadBuffer;
        break;
    case IRP_MJ_WRITE:
        size = stack->Parameters.Write.Length;
        if (size < TUN_EXCH_MIN_BUFFER_SIZE_WRITE)
            return STATUS_INVALID_USER_BUFFER;
        ubuffer = &file_ctx->WriteBuffer;
        break;
    default:
        return STATUS_INVALID_PARAMETER;
    }
    if (size > TUN_EXCH_MAX_BUFFER_SIZE)
        return STATUS_INVALID_USER_BUFFER;
    return TunMapUbuffer(ubuffer, Irp->UserBuffer, size);
}

_IRQL_requires_max_(DISPATCH_LEVEL)
_Must_inspect_result_
static _Return_type_success_(
    return != NULL) IRP *TunRemoveNextIrp(_Inout_ TUN_CTX *Ctx, _Out_ UCHAR **Buffer, _Out_ ULONG *Size)
{
    IRP *irp = IoCsqRemoveNextIrp(&Ctx->Device.ReadQueue.Csq, NULL);
    if (!irp)
        return NULL;
    IO_STACK_LOCATION *stack = IoGetCurrentIrpStackLocation(irp);
    *Size = stack->Parameters.Read.Length;
    ASSERT(irp->IoStatus.Information <= (ULONG_PTR)*Size);
    *Buffer = ((TUN_FILE_CTX *)stack->FileObject->FsContext)->ReadBuffer.KernelAddress;
    return irp;
}

_IRQL_requires_same_ static BOOLEAN
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
    ULONG p_size = NET_BUFFER_DATA_LENGTH(Nb);
    TUN_PACKET *p = (TUN_PACKET *)(Buffer + Irp->IoStatus.Information);

    p->Size = p_size;
    void *ptr = NdisGetDataBuffer(Nb, p_size, p->Data, 1, 0);
    if (!ptr)
    {
        if (Statistics)
            InterlockedIncrement64((LONG64 *)&Statistics->ifOutErrors);
        return NDIS_STATUS_RESOURCES;
    }
    if (ptr != p->Data)
        NdisMoveMemory(p->Data, ptr, p_size);

    Irp->IoStatus.Information += TunPacketAlign(sizeof(TUN_PACKET) + p_size);

    InterlockedAdd64((LONG64 *)&Statistics->ifHCOutOctets, p_size);
    InterlockedAdd64((LONG64 *)&Statistics->ifHCOutUcastOctets, p_size);
    InterlockedIncrement64((LONG64 *)&Statistics->ifHCOutUcastPkts);
    return STATUS_SUCCESS;
}

#define NET_BUFFER_LIST_REFCOUNT(nbl) ((volatile LONG64 *)NET_BUFFER_LIST_MINIPORT_RESERVED(nbl))

_IRQL_requires_same_ static void
TunNBLRefInit(_Inout_ TUN_CTX *Ctx, _Inout_ NET_BUFFER_LIST *Nbl)
{
    InterlockedIncrement64(&Ctx->ActiveNBLCount);
    InterlockedIncrement(&Ctx->PacketQueue.NumNbl);
    InterlockedExchange64(NET_BUFFER_LIST_REFCOUNT(Nbl), 1);
}

_IRQL_requires_same_ static void
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

_IRQL_requires_same_ static void
TunAppendNBL(_Inout_ NET_BUFFER_LIST **Head, _Inout_ NET_BUFFER_LIST **Tail, __drv_aliasesMem _In_ NET_BUFFER_LIST *Nbl)
{
    *(*Tail ? &NET_BUFFER_LIST_NEXT_NBL(*Tail) : Head) = Nbl;
    *Tail = Nbl;
    NET_BUFFER_LIST_NEXT_NBL(Nbl) = NULL;
}

_Requires_lock_not_held_(Ctx->PacketQueue.Lock)
_IRQL_requires_max_(DISPATCH_LEVEL)
static void
TunQueueAppend(_Inout_ TUN_CTX *Ctx, _In_ NET_BUFFER_LIST *Nbl, _In_ UINT MaxNbls)
{
    for (NET_BUFFER_LIST *nbl_next; Nbl; Nbl = nbl_next)
    {
        nbl_next = NET_BUFFER_LIST_NEXT_NBL(Nbl);
        if (!NET_BUFFER_LIST_FIRST_NB(Nbl))
        {
            NET_BUFFER_LIST_NEXT_NBL(Nbl) = NULL;
            NdisMSendNetBufferListsComplete(Ctx->MiniportAdapterHandle, Nbl, 0);
            continue;
        }

        KLOCK_QUEUE_HANDLE lqh;
        KeAcquireInStackQueuedSpinLock(&Ctx->PacketQueue.Lock, &lqh);
        TunNBLRefInit(Ctx, Nbl);
        TunAppendNBL(&Ctx->PacketQueue.FirstNbl, &Ctx->PacketQueue.LastNbl, Nbl);

        while ((UINT)InterlockedGet(&Ctx->PacketQueue.NumNbl) > MaxNbls && Ctx->PacketQueue.FirstNbl)
        {
            NET_BUFFER_LIST *nbl_second = NET_BUFFER_LIST_NEXT_NBL(Ctx->PacketQueue.FirstNbl);

            NET_BUFFER_LIST_STATUS(Ctx->PacketQueue.FirstNbl) = NDIS_STATUS_SEND_ABORTED;
            TunNBLRefDec(Ctx, Ctx->PacketQueue.FirstNbl, NDIS_SEND_COMPLETE_FLAGS_DISPATCH_LEVEL);

            Ctx->PacketQueue.NextNb = NULL;
            Ctx->PacketQueue.FirstNbl = nbl_second;
            if (!Ctx->PacketQueue.FirstNbl)
                Ctx->PacketQueue.LastNbl = NULL;
        }

        KeReleaseInStackQueuedSpinLock(&lqh);
    }
}

_Requires_lock_held_(Ctx->PacketQueue.Lock)
_IRQL_requires_(DISPATCH_LEVEL)
_Must_inspect_result_
static _Return_type_success_(return !=
                                    NULL) NET_BUFFER *TunQueueRemove(_Inout_ TUN_CTX *Ctx, _Out_ NET_BUFFER_LIST **Nbl)
{
    NET_BUFFER_LIST *nbl_top;
    NET_BUFFER *ret;

retry:
    nbl_top = Ctx->PacketQueue.FirstNbl;
    *Nbl = nbl_top;
    if (!nbl_top)
        return NULL;
    if (!Ctx->PacketQueue.NextNb)
        Ctx->PacketQueue.NextNb = NET_BUFFER_LIST_FIRST_NB(nbl_top);
    ret = Ctx->PacketQueue.NextNb;
    Ctx->PacketQueue.NextNb = NET_BUFFER_NEXT_NB(ret);
    if (!Ctx->PacketQueue.NextNb)
    {
        Ctx->PacketQueue.FirstNbl = NET_BUFFER_LIST_NEXT_NBL(nbl_top);
        if (!Ctx->PacketQueue.FirstNbl)
            Ctx->PacketQueue.LastNbl = NULL;
        NET_BUFFER_LIST_NEXT_NBL(nbl_top) = NULL;
    }
    else
        TunNBLRefInc(nbl_top);

    if (ret && NET_BUFFER_DATA_LENGTH(ret) > TUN_EXCH_MAX_IP_PACKET_SIZE)
    {
        NET_BUFFER_LIST_STATUS(nbl_top) = NDIS_STATUS_INVALID_LENGTH;
        TunNBLRefDec(Ctx, nbl_top, NDIS_SEND_COMPLETE_FLAGS_DISPATCH_LEVEL);
        InterlockedIncrement64((LONG64 *)&Ctx->Statistics.ifOutDiscards);
        goto retry;
    }

    return ret;
}

// Note: Must be called immediately after TunQueueRemove without dropping ctx->PacketQueue.Lock.
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
    KLOCK_QUEUE_HANDLE lqh;
    KeAcquireInStackQueuedSpinLock(&Ctx->PacketQueue.Lock, &lqh);
    for (NET_BUFFER_LIST *nbl = Ctx->PacketQueue.FirstNbl, *nbl_next; nbl; nbl = nbl_next)
    {
        nbl_next = NET_BUFFER_LIST_NEXT_NBL(nbl);
        NET_BUFFER_LIST_STATUS(nbl) = Status;
        TunNBLRefDec(Ctx, nbl, NDIS_SEND_COMPLETE_FLAGS_DISPATCH_LEVEL);
    }
    Ctx->PacketQueue.FirstNbl = NULL;
    Ctx->PacketQueue.LastNbl = NULL;
    Ctx->PacketQueue.NextNb = NULL;
    InterlockedExchange(&Ctx->PacketQueue.NumNbl, 0);
    KeReleaseInStackQueuedSpinLock(&lqh);
}

_Requires_lock_not_held_(Ctx->PacketQueue.Lock)
_IRQL_requires_max_(DISPATCH_LEVEL)
static void
TunQueueProcess(_Inout_ TUN_CTX *Ctx)
{
    IRP *irp = NULL;
    UCHAR *buffer = NULL;
    ULONG size = 0;
    NET_BUFFER *nb;
    KLOCK_QUEUE_HANDLE lqh;

    for (;;)
    {
        NET_BUFFER_LIST *nbl;

        KeAcquireInStackQueuedSpinLock(&Ctx->PacketQueue.Lock, &lqh);

        /* Get head NB (and IRP). */
        if (!irp)
        {
            nb = TunQueueRemove(Ctx, &nbl);
            if (!nb)
            {
                KeReleaseInStackQueuedSpinLock(&lqh);
                return;
            }
            irp = TunRemoveNextIrp(Ctx, &buffer, &size);
            if (!irp)
            {
                TunQueuePrepend(Ctx, nb, nbl);
                KeReleaseInStackQueuedSpinLock(&lqh);
                if (nbl)
                    TunNBLRefDec(Ctx, nbl, 0);
                return;
            }

            _Analysis_assume_(buffer);
            _Analysis_assume_(irp->IoStatus.Information <= size);
        }
        else
            nb = TunQueueRemove(Ctx, &nbl);

        /* If the NB won't fit in the IRP, return it. */
        if (nb && TunWontFitIntoIrp(irp, size, nb))
        {
            TunQueuePrepend(Ctx, nb, nbl);
            if (nbl)
                TunNBLRefDec(Ctx, nbl, NDIS_SEND_COMPLETE_FLAGS_DISPATCH_LEVEL);
            nbl = NULL;
            nb = NULL;
        }

        KeReleaseInStackQueuedSpinLock(&lqh);

        /* Process NB and IRP. */
        if (nb)
        {
            NTSTATUS status = TunWriteIntoIrp(irp, buffer, nb, &Ctx->Statistics);
            if (!NT_SUCCESS(status))
            {
                if (nbl)
                    NET_BUFFER_LIST_STATUS(nbl) = status;
                IoCsqInsertIrpEx(&Ctx->Device.ReadQueue.Csq, irp, NULL, TUN_CSQ_INSERT_HEAD);
                irp = NULL;
            }
        }
        else
        {
            TunCompleteRequest(Ctx, irp, STATUS_SUCCESS, IO_NETWORK_INCREMENT);
            irp = NULL;
        }

        if (nbl)
            TunNBLRefDec(Ctx, nbl, 0);
    }
}

_IRQL_requires_same_ static void
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
    TUN_CTX *ctx = (TUN_CTX *)MiniportAdapterContext;

    InterlockedIncrement64(&ctx->ActiveNBLCount);

    KIRQL irql = ExAcquireSpinLockShared(&ctx->TransitionLock);
    LONG flags = InterlockedGet(&ctx->Flags);
    NDIS_STATUS status;
    if ((status = NDIS_STATUS_ADAPTER_REMOVED, !(flags & TUN_FLAGS_PRESENT)) ||
        (status = NDIS_STATUS_PAUSED, !(flags & TUN_FLAGS_RUNNING)) ||
        (status = NDIS_STATUS_MEDIA_DISCONNECTED, InterlockedGet64(&ctx->Device.RefCount) <= 0))
    {
        TunSetNBLStatus(NetBufferLists, status);
        NdisMSendNetBufferListsComplete(
            ctx->MiniportAdapterHandle, NetBufferLists, NDIS_SEND_COMPLETE_FLAGS_DISPATCH_LEVEL);
        goto cleanup_ExReleaseSpinLockShared;
    }

    TunQueueAppend(ctx, NetBufferLists, TUN_QUEUE_MAX_NBLS);

    TunQueueProcess(ctx);

cleanup_ExReleaseSpinLockShared:
    ExReleaseSpinLockShared(&ctx->TransitionLock, irql);
    TunCompletePause(ctx, TRUE);
}

static MINIPORT_CANCEL_SEND TunCancelSend;
_Use_decl_annotations_
static void
TunCancelSend(NDIS_HANDLE MiniportAdapterContext, PVOID CancelId)
{
    TUN_CTX *ctx = (TUN_CTX *)MiniportAdapterContext;
    KLOCK_QUEUE_HANDLE lqh;

    KeAcquireInStackQueuedSpinLock(&ctx->PacketQueue.Lock, &lqh);

    NET_BUFFER_LIST *nbl_last = NULL, **nbl_last_link = &ctx->PacketQueue.FirstNbl;
    for (NET_BUFFER_LIST *nbl = ctx->PacketQueue.FirstNbl, *nbl_next; nbl; nbl = nbl_next)
    {
        nbl_next = NET_BUFFER_LIST_NEXT_NBL(nbl);
        if (NDIS_GET_NET_BUFFER_LIST_CANCEL_ID(nbl) == CancelId)
        {
            NET_BUFFER_LIST_STATUS(nbl) = NDIS_STATUS_SEND_ABORTED;
            *nbl_last_link = nbl_next;
            TunNBLRefDec(ctx, nbl, NDIS_SEND_COMPLETE_FLAGS_DISPATCH_LEVEL);
        }
        else
        {
            nbl_last = nbl;
            nbl_last_link = &NET_BUFFER_LIST_NEXT_NBL(nbl);
        }
    }
    ctx->PacketQueue.LastNbl = nbl_last;

    KeReleaseInStackQueuedSpinLock(&lqh);
}

_IRQL_requires_max_(APC_LEVEL)
_Must_inspect_result_
static NTSTATUS
TunDispatchRead(_Inout_ TUN_CTX *Ctx, _Inout_ IRP *Irp)
{
    NTSTATUS status = TunMapIrp(Irp);
    if (!NT_SUCCESS(status))
        goto cleanup_CompleteRequest;

    KIRQL irql = ExAcquireSpinLockShared(&Ctx->TransitionLock);
    LONG flags = InterlockedGet(&Ctx->Flags);
    if ((status = STATUS_FILE_FORCED_CLOSED, !(flags & TUN_FLAGS_PRESENT)) ||
        !NT_SUCCESS(status = IoCsqInsertIrpEx(&Ctx->Device.ReadQueue.Csq, Irp, NULL, TUN_CSQ_INSERT_TAIL)))
        goto cleanup_ExReleaseSpinLockShared;

    TunQueueProcess(Ctx);
    ExReleaseSpinLockShared(&Ctx->TransitionLock, irql);
    return STATUS_PENDING;

cleanup_ExReleaseSpinLockShared:
    ExReleaseSpinLockShared(&Ctx->TransitionLock, irql);
cleanup_CompleteRequest:
    TunCompleteRequest(Ctx, Irp, status, IO_NO_INCREMENT);
    return status;
}

#define IRP_REFCOUNT(irp) ((volatile LONG *)&(irp)->Tail.Overlay.DriverContext[0])
#define NET_BUFFER_LIST_IRP(nbl) (NET_BUFFER_LIST_MINIPORT_RESERVED(nbl)[0])

_IRQL_requires_max_(APC_LEVEL)
_Must_inspect_result_
static NTSTATUS
TunDispatchWrite(_Inout_ TUN_CTX *Ctx, _Inout_ IRP *Irp)
{
    NTSTATUS status;

    InterlockedIncrement64(&Ctx->ActiveNBLCount);

    if (!NT_SUCCESS(status = TunMapIrp(Irp)))
        goto cleanup_CompleteRequest;

    KIRQL irql = ExAcquireSpinLockShared(&Ctx->TransitionLock);
    LONG flags = InterlockedGet(&Ctx->Flags);
    if (status = STATUS_FILE_FORCED_CLOSED, !(flags & TUN_FLAGS_PRESENT))
        goto cleanup_ExReleaseSpinLockShared;

    IO_STACK_LOCATION *stack = IoGetCurrentIrpStackLocation(Irp);
    TUN_MAPPED_UBUFFER *ubuffer = &((TUN_FILE_CTX *)stack->FileObject->FsContext)->WriteBuffer;
    UCHAR *buffer = ubuffer->KernelAddress;
    ULONG size = stack->Parameters.Write.Length;

    const UCHAR *b = buffer, *b_end = buffer + size;
    typedef enum _ethtypeidx_t
    {
        ethtypeidx_ipv4 = 0,
        ethtypeidx_start = 0,
        ethtypeidx_ipv6,
        ethtypeidx_end
    } ethtypeidx_t;
    static const struct
    {
        ULONG nbl_flags;
        USHORT nbl_proto;
    } ether_const[ethtypeidx_end] = {
        { NDIS_NBL_FLAGS_IS_IPV4, TUN_HTONS(NDIS_ETH_TYPE_IPV4) },
        { NDIS_NBL_FLAGS_IS_IPV6, TUN_HTONS(NDIS_ETH_TYPE_IPV6) },
    };
    struct
    {
        NET_BUFFER_LIST *head, *tail;
        LONG count;
    } nbl_queue[ethtypeidx_end] = { { NULL, NULL, 0 }, { NULL, NULL, 0 } };
    LONG nbl_count = 0;
    while (b_end - b >= sizeof(TUN_PACKET))
    {
        if (nbl_count >= MAXLONG)
        {
            status = STATUS_INVALID_USER_BUFFER;
            goto cleanup_nbl_queues;
        }

        TUN_PACKET *p = (TUN_PACKET *)b;
        if (p->Size > TUN_EXCH_MAX_IP_PACKET_SIZE)
        {
            status = STATUS_INVALID_USER_BUFFER;
            goto cleanup_nbl_queues;
        }
        ULONG p_size = TunPacketAlign(sizeof(TUN_PACKET) + p->Size);
        if (b_end - b < (ptrdiff_t)p_size)
        {
            status = STATUS_INVALID_USER_BUFFER;
            goto cleanup_nbl_queues;
        }

        ethtypeidx_t idx;
        if (p->Size >= 20 && p->Data[0] >> 4 == 4)
            idx = ethtypeidx_ipv4;
        else if (p->Size >= 40 && p->Data[0] >> 4 == 6)
            idx = ethtypeidx_ipv6;
        else
        {
            status = STATUS_INVALID_USER_BUFFER;
            goto cleanup_nbl_queues;
        }

        NET_BUFFER_LIST *nbl =
            NdisAllocateNetBufferAndNetBufferList(Ctx->NBLPool, 0, 0, ubuffer->Mdl, (ULONG)(p->Data - buffer), p->Size);
        if (!nbl)
        {
            status = STATUS_INSUFFICIENT_RESOURCES;
            goto cleanup_nbl_queues;
        }

        nbl->SourceHandle = Ctx->MiniportAdapterHandle;
        NdisSetNblFlag(nbl, ether_const[idx].nbl_flags);
        NET_BUFFER_LIST_INFO(nbl, NetBufferListFrameType) = (PVOID)ether_const[idx].nbl_proto;
        NET_BUFFER_LIST_STATUS(nbl) = NDIS_STATUS_SUCCESS;
        NET_BUFFER_LIST_IRP(nbl) = Irp;
        TunAppendNBL(&nbl_queue[idx].head, &nbl_queue[idx].tail, nbl);
        nbl_queue[idx].count++;
        nbl_count++;
        b += p_size;
    }

    if ((ULONG)(b - buffer) != size)
    {
        status = STATUS_INVALID_USER_BUFFER;
        goto cleanup_nbl_queues;
    }
    Irp->IoStatus.Information = size;

    if (!nbl_count)
    {
        status = STATUS_SUCCESS;
        goto cleanup_ExReleaseSpinLockShared;
    }
    if (!(flags & TUN_FLAGS_RUNNING))
    {
        InterlockedAdd64((LONG64 *)&Ctx->Statistics.ifInDiscards, nbl_count);
        InterlockedAdd64((LONG64 *)&Ctx->Statistics.ifInErrors, nbl_count);
        status = STATUS_SUCCESS;
        goto cleanup_nbl_queues;
    }

    InterlockedAdd64(&Ctx->ActiveNBLCount, nbl_count);
    InterlockedExchange(IRP_REFCOUNT(Irp), nbl_count);
    IoMarkIrpPending(Irp);

    if (nbl_queue[ethtypeidx_ipv4].head)
        NdisMIndicateReceiveNetBufferLists(
            Ctx->MiniportAdapterHandle,
            nbl_queue[ethtypeidx_ipv4].head,
            NDIS_DEFAULT_PORT_NUMBER,
            nbl_queue[ethtypeidx_ipv4].count,
            NDIS_RECEIVE_FLAGS_SINGLE_ETHER_TYPE);
    if (nbl_queue[ethtypeidx_ipv6].head)
        NdisMIndicateReceiveNetBufferLists(
            Ctx->MiniportAdapterHandle,
            nbl_queue[ethtypeidx_ipv6].head,
            NDIS_DEFAULT_PORT_NUMBER,
            nbl_queue[ethtypeidx_ipv6].count,
            NDIS_RECEIVE_FLAGS_SINGLE_ETHER_TYPE);

    ExReleaseSpinLockShared(&Ctx->TransitionLock, irql);
    TunCompletePause(Ctx, TRUE);
    return STATUS_PENDING;

cleanup_nbl_queues:
    for (ethtypeidx_t idx = ethtypeidx_start; idx < ethtypeidx_end; idx++)
    {
        for (NET_BUFFER_LIST *nbl = nbl_queue[idx].head, *nbl_next; nbl; nbl = nbl_next)
        {
            nbl_next = NET_BUFFER_LIST_NEXT_NBL(nbl);
            NET_BUFFER_LIST_NEXT_NBL(nbl) = NULL;
            NdisFreeNetBufferList(nbl);
        }
    }
cleanup_ExReleaseSpinLockShared:
    ExReleaseSpinLockShared(&Ctx->TransitionLock, irql);
cleanup_CompleteRequest:
    TunCompleteRequest(Ctx, Irp, status, IO_NO_INCREMENT);
    TunCompletePause(Ctx, TRUE);
    return status;
}

static MINIPORT_RETURN_NET_BUFFER_LISTS TunReturnNetBufferLists;
_Use_decl_annotations_
static void
TunReturnNetBufferLists(NDIS_HANDLE MiniportAdapterContext, PNET_BUFFER_LIST NetBufferLists, ULONG ReturnFlags)
{
    TUN_CTX *ctx = (TUN_CTX *)MiniportAdapterContext;

    LONG64 stat_size = 0, stat_p_ok = 0, stat_p_err = 0;
    for (NET_BUFFER_LIST *nbl = NetBufferLists, *nbl_next; nbl; nbl = nbl_next)
    {
        nbl_next = NET_BUFFER_LIST_NEXT_NBL(nbl);
        NET_BUFFER_LIST_NEXT_NBL(nbl) = NULL;

        IRP *irp = NET_BUFFER_LIST_IRP(nbl);
        if (NT_SUCCESS(NET_BUFFER_LIST_STATUS(nbl)))
        {
            ULONG p_size = NET_BUFFER_LIST_FIRST_NB(nbl)->DataLength;
            stat_size += p_size;
            stat_p_ok++;
        }
        else
            stat_p_err++;

        NdisFreeNetBufferList(nbl);
        TunCompletePause(ctx, TRUE);

        ASSERT(InterlockedGet(IRP_REFCOUNT(irp)) > 0);
        if (InterlockedDecrement(IRP_REFCOUNT(irp)) <= 0)
            TunCompleteRequest(ctx, irp, STATUS_SUCCESS, IO_NETWORK_INCREMENT);
    }

    InterlockedAdd64((LONG64 *)&ctx->Statistics.ifHCInOctets, stat_size);
    InterlockedAdd64((LONG64 *)&ctx->Statistics.ifHCInUcastOctets, stat_size);
    InterlockedAdd64((LONG64 *)&ctx->Statistics.ifHCInUcastPkts, stat_p_ok);
    InterlockedAdd64((LONG64 *)&ctx->Statistics.ifInErrors, stat_p_err);
}

_IRQL_requires_max_(APC_LEVEL)
_Must_inspect_result_
static NTSTATUS
TunDispatchCreate(_Inout_ TUN_CTX *Ctx, _Inout_ IRP *Irp)
{
    NTSTATUS status;
    TUN_FILE_CTX *file_ctx = ExAllocatePoolWithTag(NonPagedPoolNx, sizeof(*file_ctx), TUN_HTONL(TUN_MEMORY_TAG));
    if (!file_ctx)
        return STATUS_INSUFFICIENT_RESOURCES;
    RtlZeroMemory(file_ctx, sizeof(*file_ctx));
    ExInitializeFastMutex(&file_ctx->ReadBuffer.InitializationComplete);
    ExInitializeFastMutex(&file_ctx->WriteBuffer.InitializationComplete);

    KIRQL irql = ExAcquireSpinLockShared(&Ctx->TransitionLock);
    LONG flags = InterlockedGet(&Ctx->Flags);
    if ((status = STATUS_DELETE_PENDING, !(flags & TUN_FLAGS_PRESENT)))
        goto cleanup_ExReleaseSpinLockShared;

    IO_STACK_LOCATION *stack = IoGetCurrentIrpStackLocation(Irp);
    if (!NT_SUCCESS(status = IoAcquireRemoveLock(&Ctx->Device.RemoveLock, stack->FileObject)))
        goto cleanup_ExReleaseSpinLockShared;
    stack->FileObject->FsContext = file_ctx;

    if (InterlockedIncrement64(&Ctx->Device.RefCount) == 1)
        TunIndicateStatus(Ctx->MiniportAdapterHandle, MediaConnectStateConnected);

    status = STATUS_SUCCESS;

cleanup_ExReleaseSpinLockShared:
    ExReleaseSpinLockShared(&Ctx->TransitionLock, irql);
    TunCompleteRequest(Ctx, Irp, status, IO_NO_INCREMENT);
    if (!NT_SUCCESS(status))
        ExFreePoolWithTag(file_ctx, TUN_HTONL(TUN_MEMORY_TAG));
    return status;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
static void
TunDispatchClose(_Inout_ TUN_CTX *Ctx, _Inout_ IRP *Irp)
{
    IO_STACK_LOCATION *stack = IoGetCurrentIrpStackLocation(Irp);
    KIRQL irql = ExAcquireSpinLockExclusive(&Ctx->TransitionLock);
    ASSERT(InterlockedGet64(&Ctx->Device.RefCount) > 0);
    BOOLEAN last_handle = InterlockedDecrement64(&Ctx->Device.RefCount) <= 0;
    ExReleaseSpinLockExclusive(&Ctx->TransitionLock, irql);
    if (last_handle)
    {
        NDIS_HANDLE handle = InterlockedGetPointer(&Ctx->MiniportAdapterHandle);
        if (handle)
            TunIndicateStatus(handle, MediaConnectStateDisconnected);
        TunQueueClear(Ctx, NDIS_STATUS_MEDIA_DISCONNECTED);
    }
    TUN_FILE_CTX *file_ctx = (TUN_FILE_CTX *)stack->FileObject->FsContext;
    TunUnmapUbuffer(&file_ctx->ReadBuffer);
    TunUnmapUbuffer(&file_ctx->WriteBuffer);
    ExFreePoolWithTag(file_ctx, TUN_HTONL(TUN_MEMORY_TAG));
    IoReleaseRemoveLock(&Ctx->Device.RemoveLock, stack->FileObject);
}

static DRIVER_DISPATCH TunDispatch;
_Use_decl_annotations_
static NTSTATUS
TunDispatch(DEVICE_OBJECT *DeviceObject, IRP *Irp)
{
    NTSTATUS status = STATUS_SUCCESS;

    Irp->IoStatus.Information = 0;
    TUN_CTX *ctx = NdisGetDeviceReservedExtension(DeviceObject);
    if (!ctx)
    {
        status = STATUS_INVALID_HANDLE;
        goto cleanup_complete_req;
    }

    IO_STACK_LOCATION *stack = IoGetCurrentIrpStackLocation(Irp);
    switch (stack->MajorFunction)
    {
    case IRP_MJ_READ:
        if (!NT_SUCCESS(status = IoAcquireRemoveLock(&ctx->Device.RemoveLock, Irp)))
            goto cleanup_complete_req;
        return TunDispatchRead(ctx, Irp);

    case IRP_MJ_WRITE:
        if (!NT_SUCCESS(status = IoAcquireRemoveLock(&ctx->Device.RemoveLock, Irp)))
            goto cleanup_complete_req;
        return TunDispatchWrite(ctx, Irp);

    case IRP_MJ_CREATE:
        if (!NT_SUCCESS(status = IoAcquireRemoveLock(&ctx->Device.RemoveLock, Irp)))
            goto cleanup_complete_req;
        return TunDispatchCreate(ctx, Irp);

    case IRP_MJ_CLOSE:
        TunDispatchClose(ctx, Irp);
        break;

    case IRP_MJ_CLEANUP:
        for (IRP *pending_irp;
             (pending_irp = IoCsqRemoveNextIrp(&ctx->Device.ReadQueue.Csq, stack->FileObject)) != NULL;)
            TunCompleteRequest(ctx, pending_irp, STATUS_CANCELLED, IO_NO_INCREMENT);
        break;

    default:
        status = STATUS_INVALID_PARAMETER;
        break;
    }

cleanup_complete_req:
    Irp->IoStatus.Status = status;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return status;
}

_Dispatch_type_(IRP_MJ_PNP) static DRIVER_DISPATCH TunDispatchPnP;
_Use_decl_annotations_
static NTSTATUS
TunDispatchPnP(DEVICE_OBJECT *DeviceObject, IRP *Irp)
{
    IO_STACK_LOCATION *stack = IoGetCurrentIrpStackLocation(Irp);
    if (stack->MajorFunction == IRP_MJ_PNP)
    {
#pragma warning(suppress : 28175)
        TUN_CTX *ctx = DeviceObject->Reserved;

        switch (stack->MinorFunction)
        {
        case IRP_MN_QUERY_REMOVE_DEVICE:
        case IRP_MN_SURPRISE_REMOVAL: {
            KIRQL irql = ExAcquireSpinLockExclusive(&ctx->TransitionLock);
            InterlockedAnd(&ctx->Flags, ~TUN_FLAGS_PRESENT);
            ExReleaseSpinLockExclusive(&ctx->TransitionLock, irql);
            TunQueueClear(ctx, NDIS_STATUS_ADAPTER_REMOVED);
            break;
        }

        case IRP_MN_CANCEL_REMOVE_DEVICE:
            InterlockedOr(&ctx->Flags, TUN_FLAGS_PRESENT);
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
    TUN_CTX *ctx = (TUN_CTX *)MiniportAdapterContext;

    InterlockedExchange64(&ctx->ActiveNBLCount, 1);
    InterlockedOr(&ctx->Flags, TUN_FLAGS_RUNNING);

    return NDIS_STATUS_SUCCESS;
}

static MINIPORT_PAUSE TunPause;
_Use_decl_annotations_
static NDIS_STATUS
TunPause(NDIS_HANDLE MiniportAdapterContext, PNDIS_MINIPORT_PAUSE_PARAMETERS MiniportPauseParameters)
{
    TUN_CTX *ctx = (TUN_CTX *)MiniportAdapterContext;

    KIRQL irql = ExAcquireSpinLockExclusive(&ctx->TransitionLock);
    InterlockedAnd(&ctx->Flags, ~TUN_FLAGS_RUNNING);
    ExReleaseSpinLockExclusive(&ctx->TransitionLock, irql);
    TunQueueClear(ctx, NDIS_STATUS_PAUSED);

    return TunCompletePause(ctx, FALSE);
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
    NDIS_STATUS status;

    if (!MiniportAdapterHandle)
        return NDIS_STATUS_FAILURE;

    /* Register device first.
     * Having only one device per adapter allows us to store adapter context inside device extension. */
    WCHAR device_name[sizeof(L"\\Device\\" TUN_DEVICE_NAME) / sizeof(WCHAR) + 10 /*MAXULONG as string*/] = { 0 };
    UNICODE_STRING unicode_device_name;
    TunInitUnicodeString(&unicode_device_name, device_name);
    RtlUnicodeStringPrintf(
        &unicode_device_name, L"\\Device\\" TUN_DEVICE_NAME, (ULONG)MiniportInitParameters->NetLuid.Info.NetLuidIndex);

    WCHAR symbolic_name[sizeof(L"\\DosDevices\\" TUN_DEVICE_NAME) / sizeof(WCHAR) + 10 /*MAXULONG as string*/] = { 0 };
    UNICODE_STRING unicode_symbolic_name;
    TunInitUnicodeString(&unicode_symbolic_name, symbolic_name);
    RtlUnicodeStringPrintf(
        &unicode_symbolic_name,
        L"\\DosDevices\\" TUN_DEVICE_NAME,
        (ULONG)MiniportInitParameters->NetLuid.Info.NetLuidIndex);

    static PDRIVER_DISPATCH dispatch_table[IRP_MJ_MAXIMUM_FUNCTION + 1] = {
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
    NDIS_DEVICE_OBJECT_ATTRIBUTES t = {
        .Header = { .Type = NDIS_OBJECT_TYPE_DEVICE_OBJECT_ATTRIBUTES,
                    .Revision = NDIS_DEVICE_OBJECT_ATTRIBUTES_REVISION_1,
                    .Size = NDIS_SIZEOF_DEVICE_OBJECT_ATTRIBUTES_REVISION_1 },
        .DeviceName = &unicode_device_name,
        .SymbolicName = &unicode_symbolic_name,
        .MajorFunctions = dispatch_table,
        .ExtensionSize = sizeof(TUN_CTX),
        .DefaultSDDLString = &SDDL_DEVOBJ_SYS_ALL /* Kernel, and SYSTEM: full control. Others: none */
    };
    NDIS_HANDLE handle;
    DEVICE_OBJECT *object;
    if (!NT_SUCCESS(status = NdisRegisterDeviceEx(NdisMiniportDriverHandle, &t, &object, &handle)))
        return NDIS_STATUS_FAILURE;

    object->Flags &= ~(DO_BUFFERED_IO | DO_DIRECT_IO);

    TUN_CTX *ctx = NdisGetDeviceReservedExtension(object);
    if (!ctx)
    {
        status = NDIS_STATUS_FAILURE;
        goto cleanup_NdisDeregisterDeviceEx;
    }
    DEVICE_OBJECT *functional_device;
    NdisMGetDeviceProperty(MiniportAdapterHandle, NULL, &functional_device, NULL, NULL, NULL);

    /* Reverse engineering indicates that we'd be better off calling
     * NdisWdfGetAdapterContextFromAdapterHandle(functional_device),
     * which points to our TUN_CTX object directly, but this isn't
     * available before Windows 10, so for now we just stick it into
     * this reserved field. Revisit this when we drop support for old
     * Windows versions. */
#pragma warning(suppress : 28175)
    ASSERT(!functional_device->Reserved);
#pragma warning(suppress : 28175)
    functional_device->Reserved = ctx;

    NdisZeroMemory(ctx, sizeof(*ctx));
    ctx->MiniportAdapterHandle = MiniportAdapterHandle;

    ctx->Statistics.Header.Type = NDIS_OBJECT_TYPE_DEFAULT;
    ctx->Statistics.Header.Revision = NDIS_STATISTICS_INFO_REVISION_1;
    ctx->Statistics.Header.Size = NDIS_SIZEOF_STATISTICS_INFO_REVISION_1;
    ctx->Statistics.SupportedStatistics =
        NDIS_STATISTICS_FLAGS_VALID_DIRECTED_FRAMES_RCV | NDIS_STATISTICS_FLAGS_VALID_MULTICAST_FRAMES_RCV |
        NDIS_STATISTICS_FLAGS_VALID_BROADCAST_FRAMES_RCV | NDIS_STATISTICS_FLAGS_VALID_BYTES_RCV |
        NDIS_STATISTICS_FLAGS_VALID_RCV_DISCARDS | NDIS_STATISTICS_FLAGS_VALID_RCV_ERROR |
        NDIS_STATISTICS_FLAGS_VALID_DIRECTED_FRAMES_XMIT | NDIS_STATISTICS_FLAGS_VALID_MULTICAST_FRAMES_XMIT |
        NDIS_STATISTICS_FLAGS_VALID_BROADCAST_FRAMES_XMIT | NDIS_STATISTICS_FLAGS_VALID_BYTES_XMIT |
        NDIS_STATISTICS_FLAGS_VALID_XMIT_ERROR | NDIS_STATISTICS_FLAGS_VALID_XMIT_DISCARDS |
        NDIS_STATISTICS_FLAGS_VALID_DIRECTED_BYTES_RCV | NDIS_STATISTICS_FLAGS_VALID_MULTICAST_BYTES_RCV |
        NDIS_STATISTICS_FLAGS_VALID_BROADCAST_BYTES_RCV | NDIS_STATISTICS_FLAGS_VALID_DIRECTED_BYTES_XMIT |
        NDIS_STATISTICS_FLAGS_VALID_MULTICAST_BYTES_XMIT | NDIS_STATISTICS_FLAGS_VALID_BROADCAST_BYTES_XMIT;

    ctx->Device.Handle = handle;
    ctx->Device.Object = object;
    IoInitializeRemoveLock(&ctx->Device.RemoveLock, TUN_HTONL(TUN_MEMORY_TAG), 0, 0);
    KeInitializeSpinLock(&ctx->Device.ReadQueue.Lock);
    IoCsqInitializeEx(
        &ctx->Device.ReadQueue.Csq,
        TunCsqInsertIrpEx,
        TunCsqRemoveIrp,
        TunCsqPeekNextIrp,
        TunCsqAcquireLock,
        TunCsqReleaseLock,
        TunCsqCompleteCanceledIrp);
    InitializeListHead(&ctx->Device.ReadQueue.List);

    KeInitializeSpinLock(&ctx->PacketQueue.Lock);

    NET_BUFFER_LIST_POOL_PARAMETERS nbl_pool_param = {
        .Header = { .Type = NDIS_OBJECT_TYPE_DEFAULT,
                    .Revision = NET_BUFFER_LIST_POOL_PARAMETERS_REVISION_1,
                    .Size = NDIS_SIZEOF_NET_BUFFER_LIST_POOL_PARAMETERS_REVISION_1 },
        .ProtocolId = NDIS_PROTOCOL_ID_DEFAULT,
        .fAllocateNetBuffer = TRUE,
        .PoolTag = TUN_HTONL(TUN_MEMORY_TAG)
    };
#pragma warning( \
    suppress : 6014) /* Leaking memory 'ctx->NBLPool'. Note: 'ctx->NBLPool' is freed in TunHaltEx; or on failure. */
    ctx->NBLPool = NdisAllocateNetBufferListPool(MiniportAdapterHandle, &nbl_pool_param);
    if (!ctx->NBLPool)
    {
        status = NDIS_STATUS_FAILURE;
        goto cleanup_NdisDeregisterDeviceEx;
    }

    NDIS_MINIPORT_ADAPTER_REGISTRATION_ATTRIBUTES attr = {
        .Header = { .Type = NDIS_OBJECT_TYPE_MINIPORT_ADAPTER_REGISTRATION_ATTRIBUTES,
                    .Revision = NdisVersion < NDIS_RUNTIME_VERSION_630
                                    ? NDIS_MINIPORT_ADAPTER_REGISTRATION_ATTRIBUTES_REVISION_1
                                    : NDIS_MINIPORT_ADAPTER_REGISTRATION_ATTRIBUTES_REVISION_2,
                    .Size = NdisVersion < NDIS_RUNTIME_VERSION_630
                                ? NDIS_SIZEOF_MINIPORT_ADAPTER_REGISTRATION_ATTRIBUTES_REVISION_1
                                : NDIS_SIZEOF_MINIPORT_ADAPTER_REGISTRATION_ATTRIBUTES_REVISION_2 },
        .AttributeFlags = NDIS_MINIPORT_ATTRIBUTES_NO_HALT_ON_SUSPEND | NDIS_MINIPORT_ATTRIBUTES_SURPRISE_REMOVE_OK,
        .InterfaceType = NdisInterfaceInternal,
        .MiniportAdapterContext = ctx
    };
    if (!NT_SUCCESS(
            status = NdisMSetMiniportAttributes(MiniportAdapterHandle, (PNDIS_MINIPORT_ADAPTER_ATTRIBUTES)&attr)))
    {
        status = NDIS_STATUS_FAILURE;
        goto cleanup_NdisFreeNetBufferListPool;
    }

    NDIS_PM_CAPABILITIES pmcap = {
        .Header = { .Type = NDIS_OBJECT_TYPE_DEFAULT,
                    .Revision = NdisVersion < NDIS_RUNTIME_VERSION_630 ? NDIS_PM_CAPABILITIES_REVISION_1
                                                                       : NDIS_PM_CAPABILITIES_REVISION_2,
                    .Size = NdisVersion < NDIS_RUNTIME_VERSION_630 ? NDIS_SIZEOF_NDIS_PM_CAPABILITIES_REVISION_1
                                                                   : NDIS_SIZEOF_NDIS_PM_CAPABILITIES_REVISION_2 },
        .MinMagicPacketWakeUp = NdisDeviceStateUnspecified,
        .MinPatternWakeUp = NdisDeviceStateUnspecified,
        .MinLinkChangeWakeUp = NdisDeviceStateUnspecified
    };
    static NDIS_OID suported_oids[] = { OID_GEN_MAXIMUM_TOTAL_SIZE,
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
    NDIS_MINIPORT_ADAPTER_GENERAL_ATTRIBUTES gen = {
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
        .SupportedStatistics = ctx->Statistics.SupportedStatistics,
        .SupportedPauseFunctions = NdisPauseFunctionsUnsupported,
        .AutoNegotiationFlags =
            NDIS_LINK_STATE_XMIT_LINK_SPEED_AUTO_NEGOTIATED | NDIS_LINK_STATE_RCV_LINK_SPEED_AUTO_NEGOTIATED |
            NDIS_LINK_STATE_DUPLEX_AUTO_NEGOTIATED | NDIS_LINK_STATE_PAUSE_FUNCTIONS_AUTO_NEGOTIATED,
        .SupportedOidList = suported_oids,
        .SupportedOidListLength = sizeof(suported_oids),
        .PowerManagementCapabilitiesEx = &pmcap
    };
    if (!NT_SUCCESS(
            status = NdisMSetMiniportAttributes(MiniportAdapterHandle, (PNDIS_MINIPORT_ADAPTER_ATTRIBUTES)&gen)))
    {
        status = NDIS_STATUS_FAILURE;
        goto cleanup_NdisFreeNetBufferListPool;
    }

    /* A miniport driver can call NdisMIndicateStatusEx after setting its
     * registration attributes even if the driver is still in the context
     * of the MiniportInitializeEx function. */
    TunIndicateStatus(MiniportAdapterHandle, MediaConnectStateDisconnected);
    InterlockedIncrement64(&TunAdapterCount);
    InterlockedOr(&ctx->Flags, TUN_FLAGS_PRESENT);
    return NDIS_STATUS_SUCCESS;

cleanup_NdisFreeNetBufferListPool:
    NdisFreeNetBufferListPool(ctx->NBLPool);
cleanup_NdisDeregisterDeviceEx:
    NdisDeregisterDeviceEx(handle);
    return status;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
static NTSTATUS
TunDeviceSetDenyAllDacl(_In_ DEVICE_OBJECT *DeviceObject)
{
    NTSTATUS status;
    SECURITY_DESCRIPTOR sd;
    ACL acl;
    HANDLE handle;

    if (!NT_SUCCESS(status = RtlCreateSecurityDescriptor(&sd, SECURITY_DESCRIPTOR_REVISION)))
        return status;
    if (!NT_SUCCESS(status = RtlCreateAcl(&acl, sizeof(ACL), ACL_REVISION)))
        return status;
    if (!NT_SUCCESS(status = RtlSetDaclSecurityDescriptor(&sd, TRUE, &acl, FALSE)))
        return status;
    status = ObOpenObjectByPointer(
        DeviceObject, OBJ_KERNEL_HANDLE, NULL, WRITE_DAC, *IoDeviceObjectType, KernelMode, &handle);
    if (!NT_SUCCESS(status))
        return status;

    status = ZwSetSecurityObject(handle, DACL_SECURITY_INFORMATION, &sd);

    ZwClose(handle);
    return status;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
static void
TunForceHandlesClosed(_Inout_ TUN_CTX *Ctx)
{
    NTSTATUS status;
    PEPROCESS process;
    KAPC_STATE apc_state;
    PVOID object = NULL;
    ULONG verifier_flags = 0;
    OBJECT_HANDLE_INFORMATION handle_info;
    SYSTEM_HANDLE_INFORMATION_EX *table = NULL;

    MmIsVerifierEnabled(&verifier_flags);

    for (ULONG size = 0, req; (status = ZwQuerySystemInformation(SystemExtendedHandleInformation, table, size, &req)) ==
                              STATUS_INFO_LENGTH_MISMATCH;
         size = req)
    {
        if (table)
            ExFreePoolWithTag(table, TUN_HTONL(TUN_MEMORY_TAG));
        table = ExAllocatePoolWithTag(PagedPool, req, TUN_HTONL(TUN_MEMORY_TAG));
        if (!table)
            return;
    }
    if (!NT_SUCCESS(status) || !table)
        goto out;

    for (ULONG_PTR i = 0; i < table->NumberOfHandles; ++i)
    {
        FILE_OBJECT *file =
            table->Handles[i].Object; // XXX: We should perhaps first look at table->Handles[i].ObjectTypeIndex, but
                                      // the value changes lots between NT versions, and it should be implicit anyway.
        if (!file || file->Type != 5 || file->DeviceObject != Ctx->Device.Object)
            continue;
        status = PsLookupProcessByProcessId(table->Handles[i].UniqueProcessId, &process);
        if (!NT_SUCCESS(status))
            continue;
        KeStackAttachProcess(process, &apc_state);
        if (!verifier_flags)
            status = ObReferenceObjectByHandle(table->Handles[i].HandleValue, 0, NULL, UserMode, &object, &handle_info);
        if (NT_SUCCESS(status))
        {
            if (verifier_flags || object == file)
                ObCloseHandle(table->Handles[i].HandleValue, UserMode);
            if (!verifier_flags)
                ObfDereferenceObject(object);
        }
        KeUnstackDetachProcess(&apc_state);
        ObfDereferenceObject(process);
    }
out:
    if (table)
        ExFreePoolWithTag(table, TUN_HTONL(TUN_MEMORY_TAG));
}

_IRQL_requires_max_(APC_LEVEL)
static void
TunWaitForReferencesToDropToZero(_In_ DEVICE_OBJECT *device_object)
{
    /* The sleep loop isn't pretty, but we don't have a choice. This is an NDIS bug we're working around. */
    enum
    {
        SleepTime = 50,
        TotalTime = 2 * 60 * 1000,
        MaxTries = TotalTime / SleepTime
    };
#pragma warning(suppress : 28175)
    for (int i = 0; i < MaxTries && device_object->ReferenceCount; ++i)
        NdisMSleep(SleepTime);
}

static MINIPORT_HALT TunHaltEx;
_Use_decl_annotations_
static void
TunHaltEx(NDIS_HANDLE MiniportAdapterContext, NDIS_HALT_ACTION HaltAction)
{
    TUN_CTX *ctx = (TUN_CTX *)MiniportAdapterContext;

    ASSERT(!InterlockedGet64(&ctx->ActiveNBLCount)); // Adapter should not be halted if there are (potential)
                                                     // active NBLs present.

    KIRQL irql = ExAcquireSpinLockExclusive(&ctx->TransitionLock);
    InterlockedAnd(&ctx->Flags, ~TUN_FLAGS_PRESENT);
    ExReleaseSpinLockExclusive(&ctx->TransitionLock, irql);

    for (IRP *pending_irp; (pending_irp = IoCsqRemoveNextIrp(&ctx->Device.ReadQueue.Csq, NULL)) != NULL;)
        TunCompleteRequest(ctx, pending_irp, STATUS_FILE_FORCED_CLOSED, IO_NO_INCREMENT);

    /* Setting a deny-all DACL we prevent userspace to open the device by symlink after TunForceHandlesClosed(). */
    TunDeviceSetDenyAllDacl(ctx->Device.Object);

    if (InterlockedGet64(&ctx->Device.RefCount))
        TunForceHandlesClosed(ctx);

    /* Wait for processing IRP(s) to complete. */
    IoAcquireRemoveLock(&ctx->Device.RemoveLock, NULL);
    IoReleaseRemoveLockAndWait(&ctx->Device.RemoveLock, NULL);
    NdisFreeNetBufferListPool(ctx->NBLPool);

    /* MiniportAdapterHandle must not be used in TunDispatch(). After TunHaltEx() returns it is invalidated. */
    InterlockedExchangePointer(&ctx->MiniportAdapterHandle, NULL);

    ASSERT(InterlockedGet64(&TunAdapterCount) > 0);
    if (InterlockedDecrement64(&TunAdapterCount) <= 0)
        TunWaitForReferencesToDropToZero(ctx->Device.Object);

    /* Deregister device _after_ we are done using ctx not to risk an UaF. The ctx is hosted by device extension. */
    NdisDeregisterDeviceEx(ctx->Device.Handle);
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
TunOidQueryWriteBuf(_Inout_ NDIS_OID_REQUEST *OidRequest, _In_bytecount_(Size) const void *Buf, _In_ UINT Size)
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
        return TunOidQueryWriteBuf(OidRequest, TUN_VENDOR_NAME, (UINT)sizeof(TUN_VENDOR_NAME));

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
        return TunOidQueryWriteBuf(OidRequest, &ctx->Statistics, (UINT)sizeof(ctx->Statistics));

    case OID_GEN_INTERRUPT_MODERATION: {
        static const NDIS_INTERRUPT_MODERATION_PARAMETERS intp = {
            .Header = { .Type = NDIS_OBJECT_TYPE_DEFAULT,
                        .Revision = NDIS_INTERRUPT_MODERATION_PARAMETERS_REVISION_1,
                        .Size = NDIS_SIZEOF_INTERRUPT_MODERATION_PARAMETERS_REVISION_1 },
            .InterruptModeration = NdisInterruptModerationNotSupported
        };
        return TunOidQueryWriteBuf(OidRequest, &intp, (UINT)sizeof(intp));
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

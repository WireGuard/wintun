/* SPDX-License-Identifier: GPL-2.0
 *
 * Copyright (C) 2018-2019 WireGuard LLC. All Rights Reserved.
 */

#define NDIS_MINIPORT_DRIVER
#define NDIS620_MINIPORT
#define NDIS_SUPPORT_NDIS620    1
#define NDIS_WDM                1

#include <stdio.h>
#include <string.h>
#include <wdm.h>
#include <wdmsec.h>
#include <ndis.h>
#include <bcrypt.h>
#include <ntstrsafe.h>

#pragma warning(disable : 4100) // unreferenced formal parameter
#pragma warning(disable : 4200) // nonstandard extension used: zero-sized array in struct/union
#pragma warning(disable : 4204) // nonstandard extension used: non-constant aggregate initializer
#pragma warning(disable : 4221) // nonstandard extension used: <member>: cannot be initialized using address of automatic variable <variable>

#define TUN_DEVICE_NAME         L"WINTUN%u"

#define TUN_VENDOR_NAME         "Wintun Tunnel"
#define TUN_VENDOR_ID           0xFFFFFF00
#define TUN_LINK_SPEED          100000000000ULL // 100gbps

#define TUN_EXCH_MAX_PACKETS            256                                                 // Maximum number of exchange packets that can be exchanged in a single read/write
#define TUN_EXCH_MAX_PACKET_SIZE        0xF000                                              // Maximum exchange packet size - empirically determined by net buffer list (pool) limitations
#define TUN_EXCH_ALIGNMENT              16                                                  // Memory alignment in exchange buffers
#define TUN_EXCH_MAX_IP_PACKET_SIZE     (TUN_EXCH_MAX_PACKET_SIZE - sizeof(TUN_PACKET))     // Maximum IP packet size (headers + payload)
#define TUN_EXCH_MAX_BUFFER_SIZE        (TUN_EXCH_MAX_PACKETS * TUN_EXCH_MAX_PACKET_SIZE)   // Maximum size of read/write exchange buffer
#define TUN_EXCH_MIN_BUFFER_SIZE_READ   TUN_EXCH_MAX_PACKET_SIZE                            // Minimum size of read exchange buffer
#define TUN_EXCH_MIN_BUFFER_SIZE_WRITE  (sizeof(TUN_PACKET))                                // Minimum size of write exchange buffer
#define TUN_QUEUE_MAX_NBLS              1000

typedef struct _TUN_PACKET {
	ULONG Size;                     // Size of packet data (TUN_EXCH_MAX_IP_PACKET_SIZE max)
	_Field_size_bytes_(Size)
	__declspec(align(TUN_EXCH_ALIGNMENT))
	UCHAR Data[];                   // Packet data
} TUN_PACKET;

typedef enum _TUN_STATE {
	TUN_STATE_HALTED = 0,           // The Halted state is the initial state of all adapters. When an adapter is in the Halted state, NDIS can call the driver's MiniportInitializeEx function to initialize the adapter.
	TUN_STATE_SHUTDOWN,             // In the Shutdown state, a system shutdown and restart must occur before the system can use the adapter again
	TUN_STATE_INITIALIZING,         // In the Initializing state, a miniport driver completes any operations that are required to initialize an adapter.
	TUN_STATE_PAUSED,               // In the Paused state, the adapter does not indicate received network data or accept send requests.
	TUN_STATE_RESTARTING,           // In the Restarting state, a miniport driver completes any operations that are required to restart send and receive operations for an adapter.
	TUN_STATE_RUNNING,              // In the Running state, a miniport driver performs send and receive processing for an adapter.
	TUN_STATE_PAUSING,              // In the Pausing state, a miniport driver completes any operations that are required to stop send and receive operations for an adapter.
} TUN_STATE;

typedef struct _TUN_CTX {
	volatile TUN_STATE State;

	volatile NDIS_DEVICE_POWER_STATE PowerState;

	NDIS_HANDLE MiniportAdapterHandle;
	NDIS_STATISTICS_INFO Statistics;

	volatile LONG64 ActiveTransactionCount;

	struct {
		NDIS_HANDLE Handle;
		DEVICE_OBJECT *Object;
		volatile LONG64 RefCount;

		struct {
			KSPIN_LOCK Lock;
			IO_CSQ Csq;
			LIST_ENTRY List;
		} ReadQueue;
	} Device;

	struct {
		KSPIN_LOCK Lock;
		NET_BUFFER_LIST *FirstNbl, *LastNbl;
		NET_BUFFER *NextNb;
		LONG NumNbl;
	} PacketQueue;

	NDIS_HANDLE NBLPool;
} TUN_CTX;

static NDIS_HANDLE NdisMiniportDriverHandle = NULL;

#if REG_DWORD == REG_DWORD_BIG_ENDIAN
#define TUN_MEMORY_TAG  'wtun'
#define TunHtons(x)     ((USHORT)(x))
#define TunHtonl(x)     ((ULONG)(x))
#elif REG_DWORD == REG_DWORD_LITTLE_ENDIAN
#define TUN_MEMORY_TAG  'nutw'
#define TunHtons(x)     RtlUshortByteSwap(x)
#define TunHtonl(x)     RtlUlongByteSwap(x)
#else
#error "Unable to determine endianess"
#endif

#define TUN_CSQ_INSERT_HEAD             ((PVOID)TRUE)
#define TUN_CSQ_INSERT_TAIL             ((PVOID)FALSE)

#define InterlockedGet(val)             (InterlockedAdd((val), 0))
#define InterlockedGet64(val)           (InterlockedAdd64((val), 0))
#define InterlockedGetPointer(val)      (InterlockedCompareExchangePointer((val), NULL, NULL))
#define InterlockedSubtract(val, n)     (InterlockedAdd((val), -(LONG)(n)))
#define InterlockedSubtract64(val, n)   (InterlockedAdd64((val), -(LONG64)(n)))
#define TunPacketAlign(size)            (((UINT)(size) + (UINT)(TUN_EXCH_ALIGNMENT - 1)) & ~(UINT)(TUN_EXCH_ALIGNMENT - 1))
#define TunInitUnicodeString(str, buf)  { (str)->Length = 0; (str)->MaximumLength = sizeof(buf); (str)->Buffer = buf; }

_IRQL_requires_max_(DISPATCH_LEVEL)
_IRQL_requires_same_
static void TunIndicateStatus(_In_ TUN_CTX *ctx)
{
	NDIS_LINK_STATE state = {
		.Header = {
			.Type      = NDIS_OBJECT_TYPE_DEFAULT,
			.Revision  = NDIS_LINK_STATE_REVISION_1,
			.Size      = NDIS_SIZEOF_LINK_STATE_REVISION_1
		},
		.MediaConnectState = ctx->Device.RefCount > 0 ? MediaConnectStateConnected : MediaConnectStateDisconnected,
		.MediaDuplexState  = MediaDuplexStateFull,
		.XmitLinkSpeed     = TUN_LINK_SPEED,
		.RcvLinkSpeed      = TUN_LINK_SPEED,
		.PauseFunctions    = NdisPauseFunctionsUnsupported
	};

	NDIS_STATUS_INDICATION t = {
		.Header = {
			.Type     = NDIS_OBJECT_TYPE_STATUS_INDICATION,
			.Revision = NDIS_STATUS_INDICATION_REVISION_1,
			.Size     = NDIS_SIZEOF_STATUS_INDICATION_REVISION_1
		},
		.SourceHandle     = ctx->MiniportAdapterHandle,
		.StatusCode       = NDIS_STATUS_LINK_STATE,
		.StatusBuffer     = &state,
		.StatusBufferSize = sizeof(state)
	};

	NdisMIndicateStatusEx(ctx->MiniportAdapterHandle, &t);
}


_IRQL_requires_max_(HIGH_LEVEL)
_Must_inspect_result_
static _Return_type_success_(return != NULL) TUN_CTX * volatile *TunGetContextPointer(_In_ DEVICE_OBJECT *DeviceObject)
{
	return (TUN_CTX * volatile *)NdisGetDeviceReservedExtension(DeviceObject);
}

_IRQL_requires_max_(HIGH_LEVEL)
_Must_inspect_result_
static _Return_type_success_(return != NULL) TUN_CTX *TunGetContext(_In_ DEVICE_OBJECT *DeviceObject)
{
	TUN_CTX * volatile * ctx = TunGetContextPointer(DeviceObject);
	return ctx ? InterlockedGetPointer(ctx) : NULL;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
static void TunCompleteRequest(_Inout_ IRP *Irp, _In_ ULONG_PTR Information, _In_ NTSTATUS Status)
{
	Irp->IoStatus.Information = Information;
	Irp->IoStatus.Status      = Status;
	IoCompleteRequest(Irp, IO_NO_INCREMENT);
}

_IRQL_requires_same_
_Must_inspect_result_
static NTSTATUS TunCheckForPause(_Inout_ TUN_CTX *ctx, _In_ LONG64 increment)
{
	ASSERT(InterlockedGet64(&ctx->ActiveTransactionCount) <= MAXLONG64 - increment);
	InterlockedAdd64(&ctx->ActiveTransactionCount, increment);
	return
		InterlockedGet((LONG *)&ctx->State) != TUN_STATE_RUNNING ? STATUS_NDIS_PAUSED :
		ctx->PowerState >= NdisDeviceStateD1                     ? STATUS_NDIS_LOW_POWER_STATE :
		STATUS_SUCCESS;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
static NDIS_STATUS TunCompletePause(_Inout_ TUN_CTX *ctx, _In_ LONG64 decrement, _In_ BOOLEAN async_completion)
{
	ASSERT(decrement <= InterlockedGet64(&ctx->ActiveTransactionCount));
	if (!InterlockedSubtract64(&ctx->ActiveTransactionCount, decrement) &&
		InterlockedCompareExchange((LONG *)&ctx->State, TUN_STATE_PAUSED, TUN_STATE_PAUSING) == TUN_STATE_PAUSING) {
		InterlockedExchange64(&ctx->Device.RefCount, 0);
		TunIndicateStatus(ctx);
		if (async_completion)
			NdisMPauseComplete(ctx->MiniportAdapterHandle);
		return NDIS_STATUS_SUCCESS;
	}

	return NDIS_STATUS_PENDING;
}

static IO_CSQ_INSERT_IRP_EX TunCsqInsertIrpEx;
_Use_decl_annotations_
static NTSTATUS TunCsqInsertIrpEx(IO_CSQ *Csq, IRP *Irp, PVOID InsertContext)
{
	TUN_CTX *ctx = CONTAINING_RECORD(Csq, TUN_CTX, Device.ReadQueue.Csq);
	(InsertContext == TUN_CSQ_INSERT_HEAD ? InsertHeadList : InsertTailList)(&ctx->Device.ReadQueue.List, &Irp->Tail.Overlay.ListEntry);
	return STATUS_SUCCESS;
}

static IO_CSQ_REMOVE_IRP TunCsqRemoveIrp;
_Use_decl_annotations_
static VOID TunCsqRemoveIrp(IO_CSQ *Csq, IRP *Irp)
{
	RemoveEntryList(&Irp->Tail.Overlay.ListEntry);
}

static IO_CSQ_PEEK_NEXT_IRP TunCsqPeekNextIrp;
_Use_decl_annotations_
static IRP *TunCsqPeekNextIrp(IO_CSQ *Csq, IRP *Irp, _In_ PVOID PeekContext)
{
	TUN_CTX *ctx = CONTAINING_RECORD(Csq, TUN_CTX, Device.ReadQueue.Csq);

	/* If the IRP is non-NULL, we will start peeking from that IRP onwards, else
	 * we will start from the listhead. This is done under the assumption that
	 * new IRPs are always inserted at the tail. */
	for (LIST_ENTRY
			*head = &ctx->Device.ReadQueue.List,
			*next = Irp ? Irp->Tail.Overlay.ListEntry.Flink : head->Flink;
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
_Acquires_lock_(CONTAINING_RECORD(Csq, TUN_CTX, Device.ReadQueue.Csq)->Device.ReadQueue.Lock)
static VOID TunCsqAcquireLock(_In_ IO_CSQ *Csq, _Out_ _At_(*Irql, _Post_ _IRQL_saves_) KIRQL *Irql)
{
	TUN_CTX *ctx = CONTAINING_RECORD(Csq, TUN_CTX, Device.ReadQueue.Csq);
	KeAcquireSpinLock(&ctx->Device.ReadQueue.Lock, Irql);
}

_IRQL_requires_(DISPATCH_LEVEL)
_Releases_lock_(CONTAINING_RECORD(Csq, TUN_CTX, Device.ReadQueue.Csq)->Device.ReadQueue.Lock)
static VOID TunCsqReleaseLock(_In_ IO_CSQ *Csq, _In_ _IRQL_restores_ KIRQL Irql)
{
	TUN_CTX *ctx = CONTAINING_RECORD(Csq, TUN_CTX, Device.ReadQueue.Csq);
	KeReleaseSpinLock(&ctx->Device.ReadQueue.Lock, Irql);
}

static IO_CSQ_COMPLETE_CANCELED_IRP TunCsqCompleteCanceledIrp;
_Use_decl_annotations_
static VOID TunCsqCompleteCanceledIrp(IO_CSQ *Csq, IRP *Irp)
{
	TUN_CTX *ctx = CONTAINING_RECORD(Csq, TUN_CTX, Device.ReadQueue.Csq);
	TunCompleteRequest(Irp, 0, STATUS_CANCELLED);
	TunCompletePause(ctx, 1, TRUE);
}

_IRQL_requires_same_
static void TunSetNBLStatus(_Inout_opt_ NET_BUFFER_LIST *nbl, _In_ NDIS_STATUS status)
{
	for (; nbl; nbl = NET_BUFFER_LIST_NEXT_NBL(nbl))
		NET_BUFFER_LIST_STATUS(nbl) = status;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
_Must_inspect_result_
static NTSTATUS TunGetIrpBuffer(_In_ IRP *Irp, _Out_ UCHAR **buffer, _Out_ ULONG *size)
{
	/* Get and validate request parameters. */
	ULONG priority;
	IO_STACK_LOCATION *stack = IoGetCurrentIrpStackLocation(Irp);
	switch (stack->MajorFunction) {
	case IRP_MJ_READ:
		*size = stack->Parameters.Read.Length;
		priority = NormalPagePriority;
		break;

	case IRP_MJ_WRITE:
		*size = stack->Parameters.Write.Length;
		priority = NormalPagePriority | MdlMappingNoWrite;
		break;

	default:
		return STATUS_INVALID_PARAMETER;
	}

	/* Get buffer size and address. */
	if (!Irp->MdlAddress)
		return STATUS_INVALID_PARAMETER;
	ULONG size_mdl;
	NdisQueryMdl(Irp->MdlAddress, buffer, &size_mdl, priority);
	if (!buffer)
		return STATUS_INSUFFICIENT_RESOURCES;
	if (size_mdl < *size)
		*size = size_mdl;

	if (*size > TUN_EXCH_MAX_BUFFER_SIZE)
		return STATUS_INVALID_USER_BUFFER;

	switch (stack->MajorFunction) {
	case IRP_MJ_READ:
		if (*size < TUN_EXCH_MIN_BUFFER_SIZE_READ)
			return STATUS_INVALID_USER_BUFFER;
		break;

	case IRP_MJ_WRITE:
		if (*size < TUN_EXCH_MIN_BUFFER_SIZE_WRITE)
			return STATUS_INVALID_USER_BUFFER;
		break;
	}

	return STATUS_SUCCESS;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
_Must_inspect_result_
static _Return_type_success_(return != NULL) IRP *TunRemoveNextIrp(_Inout_ TUN_CTX *ctx, _Out_ UCHAR ** buffer, _Out_ ULONG *size)
{
	IRP *irp;

retry:
	irp = IoCsqRemoveNextIrp(&ctx->Device.ReadQueue.Csq, NULL);
	if (!irp)
		return NULL;

	NTSTATUS status = TunGetIrpBuffer(irp, buffer, size);
	if (!NT_SUCCESS(status)) {
		irp->IoStatus.Status = status;
		IoCompleteRequest(irp, IO_NETWORK_INCREMENT);
		TunCompletePause(ctx, 1, TRUE);
		goto retry;
	}

	ASSERT(irp->IoStatus.Information <= (ULONG_PTR)*size);

	return irp;
}

_IRQL_requires_same_
static BOOLEAN TunCanFitIntoIrp(_In_ IRP *Irp, _In_ ULONG size, _In_ NET_BUFFER *nb)
{
	return (ULONG_PTR)size < Irp->IoStatus.Information + TunPacketAlign(sizeof(TUN_PACKET) + NET_BUFFER_DATA_LENGTH(nb));
}

_IRQL_requires_max_(DISPATCH_LEVEL)
_Must_inspect_result_
static NTSTATUS TunWriteIntoIrp(_Inout_ TUN_CTX *ctx, _Inout_ IRP *Irp, _Inout_ UCHAR *buffer, _In_ NET_BUFFER *nb)
{
	ULONG p_size = NET_BUFFER_DATA_LENGTH(nb);
	TUN_PACKET *p = (TUN_PACKET *)(buffer + Irp->IoStatus.Information);

	p->Size = p_size;
	void *ptr = NdisGetDataBuffer(nb, p_size, p->Data, 1, 0);
	if (!ptr) {
		InterlockedIncrement64((LONG64 *)&ctx->Statistics.ifOutErrors);
		return NDIS_STATUS_RESOURCES;
	}
	if (ptr != p->Data)
		NdisMoveMemory(p->Data, ptr, p_size);

	Irp->IoStatus.Information += TunPacketAlign(sizeof(TUN_PACKET) + p_size);

	InterlockedAdd64((LONG64 *)&ctx->Statistics.ifHCOutOctets,      p_size);
	InterlockedAdd64((LONG64 *)&ctx->Statistics.ifHCOutUcastOctets, p_size);
	InterlockedIncrement64((LONG64 *)&ctx->Statistics.ifHCOutUcastPkts);
	return STATUS_SUCCESS;
}

#define NET_BUFFER_LIST_MINIPORT_RESERVED_REFCOUNT(nbl) ((volatile LONG64 *)NET_BUFFER_LIST_MINIPORT_RESERVED(nbl))

_IRQL_requires_same_
static void TunNBLRefInit(_Inout_ TUN_CTX *ctx, _Inout_ NET_BUFFER_LIST *nbl)
{
	InterlockedAdd64(&ctx->ActiveTransactionCount, 1);
	InterlockedAdd(&ctx->PacketQueue.NumNbl, 1);
	InterlockedExchange64(NET_BUFFER_LIST_MINIPORT_RESERVED_REFCOUNT(nbl), 1);
}

_IRQL_requires_same_
static void TunNBLRefInc(_Inout_ NET_BUFFER_LIST *nbl)
{
	ASSERT(InterlockedGet64(NET_BUFFER_LIST_MINIPORT_RESERVED_REFCOUNT(nbl)));
	InterlockedAdd64(NET_BUFFER_LIST_MINIPORT_RESERVED_REFCOUNT(nbl), 1);
}

_When_( (SendCompleteFlags & NDIS_SEND_COMPLETE_FLAGS_DISPATCH_LEVEL), _IRQL_requires_    (DISPATCH_LEVEL))
_When_(!(SendCompleteFlags & NDIS_SEND_COMPLETE_FLAGS_DISPATCH_LEVEL), _IRQL_requires_max_(DISPATCH_LEVEL))
static BOOLEAN TunNBLRefDec(_Inout_ TUN_CTX *ctx, _Inout_ NET_BUFFER_LIST *nbl, _In_ ULONG SendCompleteFlags)
{
	ASSERT(InterlockedGet64(NET_BUFFER_LIST_MINIPORT_RESERVED_REFCOUNT(nbl)));
	if (!InterlockedSubtract64(NET_BUFFER_LIST_MINIPORT_RESERVED_REFCOUNT(nbl), 1)) {
		NET_BUFFER_LIST_NEXT_NBL(nbl) = NULL;
		NdisMSendNetBufferListsComplete(ctx->MiniportAdapterHandle, nbl, SendCompleteFlags);
		InterlockedSubtract(&ctx->PacketQueue.NumNbl, 1);
		TunCompletePause(ctx, 1, TRUE);
		return TRUE;
	}
	return FALSE;
}

_IRQL_requires_same_
static void TunAppendNBL(_Inout_ NET_BUFFER_LIST **head, _Inout_ NET_BUFFER_LIST **tail, __drv_aliasesMem _In_ NET_BUFFER_LIST *nbl)
{
	*(*tail ? &NET_BUFFER_LIST_NEXT_NBL(*tail) : head) = nbl;
	*tail = nbl;
	NET_BUFFER_LIST_NEXT_NBL(nbl) = NULL;
}

_Requires_lock_not_held_(ctx->PacketQueue.Lock)
_IRQL_requires_max_(DISPATCH_LEVEL)
static void TunQueueAppend(_Inout_ TUN_CTX *ctx, _In_ NET_BUFFER_LIST *nbl, _In_ UINT max_nbls)
{
	for (NET_BUFFER_LIST *nbl_next; nbl; nbl = nbl_next) {
		nbl_next = NET_BUFFER_LIST_NEXT_NBL(nbl);
		if (!NET_BUFFER_LIST_FIRST_NB(nbl)) {
			NET_BUFFER_LIST_NEXT_NBL(nbl) = NULL;
			NdisMSendNetBufferListsComplete(ctx->MiniportAdapterHandle, nbl, 0);
			continue;
		}

		KLOCK_QUEUE_HANDLE lqh;
		KeAcquireInStackQueuedSpinLock(&ctx->PacketQueue.Lock, &lqh);
		TunNBLRefInit(ctx, nbl);
		TunAppendNBL(&ctx->PacketQueue.FirstNbl, &ctx->PacketQueue.LastNbl, nbl);

		while ((UINT)InterlockedGet(&ctx->PacketQueue.NumNbl) > max_nbls && ctx->PacketQueue.FirstNbl) {
			NET_BUFFER_LIST *nbl_second = NET_BUFFER_LIST_NEXT_NBL(ctx->PacketQueue.FirstNbl);

			NET_BUFFER_LIST_STATUS(ctx->PacketQueue.FirstNbl) = NDIS_STATUS_SEND_ABORTED;
			TunNBLRefDec(ctx, ctx->PacketQueue.FirstNbl, NDIS_SEND_COMPLETE_FLAGS_DISPATCH_LEVEL);

			ctx->PacketQueue.NextNb = NULL;
			ctx->PacketQueue.FirstNbl = nbl_second;
			if (!ctx->PacketQueue.FirstNbl)
				ctx->PacketQueue.LastNbl = NULL;
		}

		KeReleaseInStackQueuedSpinLock(&lqh);
	}
}

_Requires_lock_held_(ctx->PacketQueue.Lock)
_IRQL_requires_(DISPATCH_LEVEL)
_Must_inspect_result_
static _Return_type_success_(return != NULL) NET_BUFFER *TunQueueRemove(_Inout_ TUN_CTX *ctx, _Out_ NET_BUFFER_LIST **nbl)
{
	NET_BUFFER_LIST *nbl_top;
	NET_BUFFER *ret;

retry:
	nbl_top = ctx->PacketQueue.FirstNbl;
	*nbl = nbl_top;
	if (!nbl_top)
		return NULL;
	if (!ctx->PacketQueue.NextNb)
		ctx->PacketQueue.NextNb = NET_BUFFER_LIST_FIRST_NB(nbl_top);
	ret = ctx->PacketQueue.NextNb;
	ctx->PacketQueue.NextNb = NET_BUFFER_NEXT_NB(ret);
	if (!ctx->PacketQueue.NextNb) {
		ctx->PacketQueue.FirstNbl = NET_BUFFER_LIST_NEXT_NBL(nbl_top);
		if (!ctx->PacketQueue.FirstNbl)
			ctx->PacketQueue.LastNbl = NULL;
		NET_BUFFER_LIST_NEXT_NBL(nbl_top) = NULL;
	} else
		TunNBLRefInc(nbl_top);

	if (ret && NET_BUFFER_DATA_LENGTH(ret) > TUN_EXCH_MAX_IP_PACKET_SIZE) {
		NET_BUFFER_LIST_STATUS(nbl_top) = NDIS_STATUS_INVALID_LENGTH;
		TunNBLRefDec(ctx, nbl_top, NDIS_SEND_COMPLETE_FLAGS_DISPATCH_LEVEL);
		InterlockedIncrement64((LONG64 *)&ctx->Statistics.ifOutDiscards);
		goto retry; /* A for (;;) and a break would be fine, but this is clearer actually. */
	}

	return ret;
}

/* Note: Must be called immediately after TunQueueRemove without dropping ctx->PacketQueue.Lock. */
_Requires_lock_held_(ctx->PacketQueue.Lock)
_IRQL_requires_(DISPATCH_LEVEL)
static void TunQueuePrepend(_Inout_ TUN_CTX *ctx, _In_ NET_BUFFER *nb, _In_ NET_BUFFER_LIST *nbl)
{
	ctx->PacketQueue.NextNb = nb;

	if (!nbl || nbl == ctx->PacketQueue.FirstNbl)
		return;

	TunNBLRefInc(nbl);
	if (!ctx->PacketQueue.FirstNbl)
		ctx->PacketQueue.FirstNbl = ctx->PacketQueue.LastNbl = nbl;
	else {
		NET_BUFFER_LIST_NEXT_NBL(nbl) = ctx->PacketQueue.FirstNbl;
		ctx->PacketQueue.FirstNbl = nbl;
	}
}

_Requires_lock_not_held_(ctx->PacketQueue.Lock)
_IRQL_requires_max_(DISPATCH_LEVEL)
static void TunQueueClear(_Inout_ TUN_CTX *ctx)
{
	KLOCK_QUEUE_HANDLE lqh;
	KeAcquireInStackQueuedSpinLock(&ctx->PacketQueue.Lock, &lqh);
	for (NET_BUFFER_LIST *nbl = ctx->PacketQueue.FirstNbl, *nbl_next; nbl; nbl = nbl_next) {
		nbl_next = NET_BUFFER_LIST_NEXT_NBL(nbl);
		NET_BUFFER_LIST_STATUS(nbl) = STATUS_NDIS_PAUSED;
		TunNBLRefDec(ctx, nbl, NDIS_SEND_COMPLETE_FLAGS_DISPATCH_LEVEL);
	}
	ctx->PacketQueue.FirstNbl = NULL;
	ctx->PacketQueue.LastNbl  = NULL;
	ctx->PacketQueue.NextNb   = NULL;
	InterlockedExchange(&ctx->PacketQueue.NumNbl, 0);
	KeReleaseInStackQueuedSpinLock(&lqh);
}

_Requires_lock_not_held_(ctx->PacketQueue.Lock)
_IRQL_requires_max_(DISPATCH_LEVEL)
static void TunQueueProcess(_Inout_ TUN_CTX *ctx)
{
	IRP *irp = NULL;
	UCHAR *buffer = NULL;
	ULONG size = 0;
	NET_BUFFER *nb;
	KLOCK_QUEUE_HANDLE lqh;

	for (;;) {
		NET_BUFFER_LIST *nbl;

		KeAcquireInStackQueuedSpinLock(&ctx->PacketQueue.Lock, &lqh);

		/* Get head NB (and IRP). */
		if (!irp) {
			nb = TunQueueRemove(ctx, &nbl);
			if (!nb) {
				KeReleaseInStackQueuedSpinLock(&lqh);
				return;
			}
			irp = TunRemoveNextIrp(ctx, &buffer, &size);
			if (!irp) {
				TunQueuePrepend(ctx, nb, nbl);
				KeReleaseInStackQueuedSpinLock(&lqh);
				if (nbl)
					TunNBLRefDec(ctx, nbl, 0);
				return;
			}
		} else
			nb = TunQueueRemove(ctx, &nbl);

		/* If the NB won't fit in the IRP, return it. */
		if (nb && TunCanFitIntoIrp(irp, size, nb)) {
			TunQueuePrepend(ctx, nb, nbl);
			if (nbl)
				TunNBLRefDec(ctx, nbl, NDIS_SEND_COMPLETE_FLAGS_DISPATCH_LEVEL);
			nbl = NULL;
			nb = NULL;
		}

		KeReleaseInStackQueuedSpinLock(&lqh);

		/* Process NB and IRP. */
		if (nb) {
			NTSTATUS status = TunWriteIntoIrp(ctx, irp, buffer, nb);
			if (!NT_SUCCESS(status)) {
				if (nbl)
					NET_BUFFER_LIST_STATUS(nbl) = status;
				IoCsqInsertIrpEx(&ctx->Device.ReadQueue.Csq, irp, NULL, TUN_CSQ_INSERT_HEAD);
				irp = NULL;
			}
		} else {
			irp->IoStatus.Status = STATUS_SUCCESS;
			IoCompleteRequest(irp, IO_NETWORK_INCREMENT);
			TunCompletePause(ctx, 1, TRUE);
			irp = NULL;
		}

		if (nbl)
			TunNBLRefDec(ctx, nbl, 0);
	}
}

static DRIVER_DISPATCH TunDispatchCreate;
_Use_decl_annotations_
static NTSTATUS TunDispatchCreate(DEVICE_OBJECT *DeviceObject, IRP *Irp)
{
	NTSTATUS status = STATUS_UNSUCCESSFUL;

	TUN_CTX *ctx = TunGetContext(DeviceObject);
	if (!ctx) {
		status = STATUS_INVALID_HANDLE;
		goto cleanup_complete_req;
	}

	if (!NT_SUCCESS(status = TunCheckForPause(ctx, 1)))
		goto cleanup_TunCompletePause;

	ASSERT(InterlockedGet64(&ctx->Device.RefCount) < MAXLONG64);
	InterlockedIncrement64(&ctx->Device.RefCount);
	TunIndicateStatus(ctx);

cleanup_TunCompletePause:
	TunCompletePause(ctx, 1, TRUE);
cleanup_complete_req:
	TunCompleteRequest(Irp, 0, status);
	return status;
}

static DRIVER_DISPATCH TunDispatchClose;
_Use_decl_annotations_
static NTSTATUS TunDispatchClose(DEVICE_OBJECT *DeviceObject, IRP *Irp)
{
	NTSTATUS status = STATUS_UNSUCCESSFUL;

	TUN_CTX *ctx = TunGetContext(DeviceObject);
	if (!ctx) {
		status = STATUS_INVALID_HANDLE;
		goto cleanup_complete_req;
	}

	if (!NT_SUCCESS(status = TunCheckForPause(ctx, 1)))
		goto cleanup_TunCompletePause;

	ASSERT(InterlockedGet64(&ctx->Device.RefCount) > 0);
	InterlockedDecrement64(&ctx->Device.RefCount);
	TunIndicateStatus(ctx);

cleanup_TunCompletePause:
	TunCompletePause(ctx, 1, TRUE);
cleanup_complete_req:
	TunCompleteRequest(Irp, 0, status);
	return status;
}

static DRIVER_DISPATCH TunDispatchRead;
_Use_decl_annotations_
static NTSTATUS TunDispatchRead(DEVICE_OBJECT *DeviceObject, IRP *Irp)
{
	NTSTATUS status = STATUS_UNSUCCESSFUL;

	TUN_CTX *ctx = TunGetContext(DeviceObject);
	if (!ctx) {
		status = STATUS_INVALID_HANDLE;
		goto cleanup_complete_req;
	}

	if (!NT_SUCCESS(status = TunCheckForPause(ctx, 1)))
		goto cleanup_TunCompletePause;

	Irp->IoStatus.Information = 0;
	InterlockedIncrement64(&ctx->ActiveTransactionCount);
	status = IoCsqInsertIrpEx(&ctx->Device.ReadQueue.Csq, Irp, NULL, TUN_CSQ_INSERT_TAIL);
	if (!NT_SUCCESS(status)) {
		InterlockedDecrement64(&ctx->ActiveTransactionCount);
		goto cleanup_TunCompletePause;
	}

	TunQueueProcess(ctx);

	TunCompletePause(ctx, 1, TRUE);
	return STATUS_PENDING;

cleanup_TunCompletePause:
	TunCompletePause(ctx, 1, TRUE);
cleanup_complete_req:
	TunCompleteRequest(Irp, 0, status);
	return status;
}

static DRIVER_DISPATCH TunDispatchWrite;
_Use_decl_annotations_
static NTSTATUS TunDispatchWrite(DEVICE_OBJECT *DeviceObject, IRP *Irp)
{
	NTSTATUS status = STATUS_UNSUCCESSFUL;
	ULONG_PTR information = 0;

	TUN_CTX *ctx = TunGetContext(DeviceObject);
	if (!ctx) {
		status = STATUS_INVALID_HANDLE;
		goto cleanup_complete_req;
	}

	if (!NT_SUCCESS(status = TunCheckForPause(ctx, 1)))
		goto cleanup_TunCompletePause;

	UCHAR *buffer;
	ULONG size;
	status = TunGetIrpBuffer(Irp, &buffer, &size);
	if (!NT_SUCCESS(status))
		goto cleanup_TunCompletePause;

	const UCHAR *b = buffer, *b_end = buffer + size;
	ULONG nbl_count = 0;
	NET_BUFFER_LIST *nbl_head = NULL, *nbl_tail = NULL;
	LONG64 stat_size = 0, stat_p_ok = 0, stat_p_err = 0;
	while (b < b_end) {
		TUN_PACKET *p = (TUN_PACKET *)b;
		if (p->Size > TUN_EXCH_MAX_IP_PACKET_SIZE)
			break;
		UINT p_size = TunPacketAlign(sizeof(TUN_PACKET) + p->Size);
		if (b + p_size > b_end)
			break;

		ULONG nbl_flags;
		USHORT nbl_proto;
		if (p->Size >= 20 && p->Data[0] >> 4 == 4) {
			nbl_flags = NDIS_NBL_FLAGS_IS_IPV4;
			nbl_proto = NDIS_ETH_TYPE_IPV4;
		} else if (p->Size >= 40 && p->Data[0] >> 4 == 6) {
			nbl_flags = NDIS_NBL_FLAGS_IS_IPV6;
			nbl_proto = NDIS_ETH_TYPE_IPV6;
		} else {
			goto skip_packet;
		}

		MDL *mdl = NdisAllocateMdl(ctx->MiniportAdapterHandle, p->Data, p->Size);
		if (!mdl)
			goto skip_packet;

		NET_BUFFER_LIST *nbl = NdisAllocateNetBufferAndNetBufferList(ctx->NBLPool, 0, 0, mdl, 0, p->Size);
		if (!nbl)
			goto cleanup_NdisFreeMdl;

		nbl->SourceHandle = ctx->MiniportAdapterHandle;
		NdisSetNblFlag(nbl, nbl_flags);
		NET_BUFFER_LIST_INFO(nbl, NetBufferListFrameType) = (PVOID)TunHtons(nbl_proto);
		NET_BUFFER_LIST_STATUS(nbl) = NDIS_STATUS_SUCCESS;
		TunAppendNBL(&nbl_head, &nbl_tail, nbl);
		nbl_count++;
		goto next_packet;

	cleanup_NdisFreeMdl:
		NdisFreeMdl(mdl);
	skip_packet:
		stat_p_err++;
	next_packet:
		b += p_size;
	}

	/* Commentary from Jason:
	 *
	 * Problem statement:
	 *     We call IoCompleteRequest(Irp) immediately after NdisMIndicateReceiveNetBufferLists, which frees Irp->MdlAddress.
	 *     Since we've just given the same memory to NdisMIndicateReceiveNetBufferLists (in a different MDL), we wind up
	 *     freeing the memory before NDIS finishes processing them.
	 *
	 * Fix possibility 1:
	 *     Move IoCompleteRequest(Irp) to TunReturnNetBufferLists. This reqiures reference counting how many NBLs are currently
	 *     in flight that are using an IRP. When that drops to zero, we can call IoCompleteRequest(Irp).
	 * Problem:
	 *     This means we have to block future wireguard-go Writes until *all* NBLs have completed processing in the networking
	 *     stack. Is that safe to do? Will that introduce latency? Can userspace processes sabotage it by refusing to read from
	 *     a TCP socket buffer? We don't know enough about how NdisMIndicateReceiveNetBufferLists works to assess its
	 *     characteristics here.
	 *
	 * Fix possibility 2:
	 *     Use NDIS_RECEIVE_FLAGS_RESOURCES, so that NdisMIndicateReceiveNetBufferLists makes a copy, and then we'll simply
	 *     free everything immediately after. This is slow, and it could potentially lead to wireguard-go making the kernel
	 *     allocate lots of memory in the case that NdisAllocateNetBufferAndNetBufferList doesn't ratelimit its creation in the
	 *     same way Linux's skb_alloc does. However, it does make the lifetime of Irps shorter, which is easier to analyze, and
	 *     it might lead to better latency, since we don't need to wait until userspace sends its next packets, so long as
	 *     Ndis' ingestion queue doesn't become too large.
	 *
	 * Choice:
	 *     Both (1) and (2) have pros and cons. Making (1) work is clearly the better long term goal. But we lack the knowledge
	 *     to make it work correctly. (2) seems like an acceptable stopgap solution until we're smart enough to reason about
	 *     (1). So, let's implement (2) now, and we'll let more knowledgeable people advise us on (1) later.
	 */
	if (nbl_head)
		NdisMIndicateReceiveNetBufferLists(ctx->MiniportAdapterHandle, nbl_head, NDIS_DEFAULT_PORT_NUMBER, nbl_count, NDIS_RECEIVE_FLAGS_RESOURCES);

	for (NET_BUFFER_LIST *nbl = nbl_head, *nbl_next; nbl; nbl = nbl_next) {
		nbl_next = NET_BUFFER_LIST_NEXT_NBL(nbl);
		NET_BUFFER_LIST_NEXT_NBL(nbl) = NULL;

		MDL *mdl = NET_BUFFER_FIRST_MDL(NET_BUFFER_LIST_FIRST_NB(nbl));
		if (NT_SUCCESS(NET_BUFFER_LIST_STATUS(nbl))) {
			ULONG p_size = MmGetMdlByteCount(mdl);
			stat_size += p_size;
			stat_p_ok++;
		} else
			stat_p_err++;
		NdisFreeMdl(mdl);
		NdisFreeNetBufferList(nbl);
	}

	InterlockedAdd64((LONG64 *)&ctx->Statistics.ifHCInOctets,      stat_size);
	InterlockedAdd64((LONG64 *)&ctx->Statistics.ifHCInUcastOctets, stat_size);
	InterlockedAdd64((LONG64 *)&ctx->Statistics.ifHCInUcastPkts,   stat_p_ok);
	InterlockedAdd64((LONG64 *)&ctx->Statistics.ifInErrors,        stat_p_err);

	information = b - buffer;

cleanup_TunCompletePause:
	TunCompletePause(ctx, 1, TRUE);
cleanup_complete_req:
	TunCompleteRequest(Irp, information, status);
	return status;
}

static DRIVER_DISPATCH TunDispatchCleanup;
_Use_decl_annotations_
static NTSTATUS TunDispatchCleanup(DEVICE_OBJECT *DeviceObject, IRP *Irp)
{
	NTSTATUS status = STATUS_UNSUCCESSFUL;

	TUN_CTX *ctx = TunGetContext(DeviceObject);
	if (!ctx) {
		status = STATUS_INVALID_HANDLE;
		goto cleanup_complete_req;
	}

	LONG64 count = 1;
	if (!NT_SUCCESS(status = TunCheckForPause(ctx, count)))
		goto cleanup_TunCompletePause;

	IO_STACK_LOCATION *stack = IoGetCurrentIrpStackLocation(Irp);
	IRP *pending_irp;
	while ((pending_irp = IoCsqRemoveNextIrp(&ctx->Device.ReadQueue.Csq, stack->FileObject)) != NULL) {
		count++;
		TunCompleteRequest(pending_irp, 0, STATUS_CANCELLED);
	}

cleanup_TunCompletePause:
	TunCompletePause(ctx, count, TRUE);
cleanup_complete_req:
	TunCompleteRequest(Irp, 0, status);
	return status;
}

static MINIPORT_SET_OPTIONS TunSetOptions;
_Use_decl_annotations_
static NDIS_STATUS TunSetOptions(NDIS_HANDLE NdisDriverHandle, NDIS_HANDLE DriverContext)
{
	/* TODO: This handler is optional. See if it can be removed. */
	return NDIS_STATUS_SUCCESS;
}

static MINIPORT_PAUSE TunPause;
_Use_decl_annotations_
static NDIS_STATUS TunPause(NDIS_HANDLE MiniportAdapterContext, PNDIS_MINIPORT_PAUSE_PARAMETERS MiniportPauseParameters)
{
	TUN_CTX *ctx = (TUN_CTX *)MiniportAdapterContext;

	LONG64 count = 1;
	InterlockedAdd64(&ctx->ActiveTransactionCount, count);

	if (InterlockedCompareExchange((LONG *)&ctx->State, TUN_STATE_PAUSING, TUN_STATE_RUNNING) != TUN_STATE_RUNNING) {
		InterlockedDecrement64(&ctx->ActiveTransactionCount);
		return NDIS_STATUS_FAILURE;
	}

	TunQueueClear(ctx);

	/* Cancel pending IRPs to unblock waiting clients. */
	IRP *pending_irp;
	while ((pending_irp = IoCsqRemoveNextIrp(&ctx->Device.ReadQueue.Csq, NULL)) != NULL) {
		count++;
		TunCompleteRequest(pending_irp, 0, STATUS_CANCELLED);
	}

	return TunCompletePause(ctx, count, FALSE);
}

static MINIPORT_RESTART TunRestart;
_Use_decl_annotations_
static NDIS_STATUS TunRestart(NDIS_HANDLE MiniportAdapterContext, PNDIS_MINIPORT_RESTART_PARAMETERS MiniportRestartParameters)
{
	TUN_CTX *ctx = (TUN_CTX *)MiniportAdapterContext;
	if (InterlockedCompareExchange((LONG *)&ctx->State, TUN_STATE_RESTARTING, TUN_STATE_PAUSED) != TUN_STATE_PAUSED)
		return NDIS_STATUS_FAILURE;

	ASSERT(!InterlockedGet64(&ctx->Device.RefCount));
	TunIndicateStatus(ctx);

	InterlockedExchange((LONG *)&ctx->State, TUN_STATE_RUNNING);
	return NDIS_STATUS_SUCCESS;
}

static MINIPORT_RETURN_NET_BUFFER_LISTS TunReturnNetBufferLists;
_Use_decl_annotations_
static void TunReturnNetBufferLists(NDIS_HANDLE MiniportAdapterContext, PNET_BUFFER_LIST NetBufferLists, ULONG ReturnFlags)
{
	ASSERTMSG("TunReturnNetBufferLists() should not be called as NBLs are delivered using NDIS_RECEIVE_FLAGS_RESOURCES flag in NdisMIndicateReceiveNetBufferLists().", 0);
}

static MINIPORT_CANCEL_SEND TunCancelSend;
_Use_decl_annotations_
static void TunCancelSend(NDIS_HANDLE MiniportAdapterContext, PVOID CancelId)
{
	TUN_CTX *ctx = (TUN_CTX *)MiniportAdapterContext;
	KLOCK_QUEUE_HANDLE lqh;

	KeAcquireInStackQueuedSpinLock(&ctx->PacketQueue.Lock, &lqh);

	NET_BUFFER_LIST *nbl_last = NULL, **nbl_last_link = &ctx->PacketQueue.FirstNbl;
	for (NET_BUFFER_LIST *nbl = ctx->PacketQueue.FirstNbl, *nbl_next; nbl; nbl = nbl_next) {
		nbl_next = NET_BUFFER_LIST_NEXT_NBL(nbl);
		if (NDIS_GET_NET_BUFFER_LIST_CANCEL_ID(nbl) == CancelId) {
			*nbl_last_link = nbl_next;
			TunNBLRefDec(ctx, nbl, NDIS_SEND_COMPLETE_FLAGS_DISPATCH_LEVEL);
		} else {
			nbl_last = nbl;
			nbl_last_link = &NET_BUFFER_LIST_NEXT_NBL(nbl);
		}
	}
	ctx->PacketQueue.LastNbl = nbl_last;

	KeReleaseInStackQueuedSpinLock(&lqh);
}

static MINIPORT_DEVICE_PNP_EVENT_NOTIFY TunDevicePnPEventNotify;
_Use_decl_annotations_
static void TunDevicePnPEventNotify(NDIS_HANDLE MiniportAdapterContext, PNET_DEVICE_PNP_EVENT NetDevicePnPEvent)
{
}

static MINIPORT_SHUTDOWN TunShutdownEx;
_Use_decl_annotations_
static void TunShutdownEx(NDIS_HANDLE MiniportAdapterContext, NDIS_SHUTDOWN_ACTION ShutdownAction)
{
	TUN_CTX *ctx = (TUN_CTX *)MiniportAdapterContext;

	if (ShutdownAction == NdisShutdownBugCheck)
		return;

	InterlockedExchange((LONG *)&ctx->State, TUN_STATE_SHUTDOWN);
}

static MINIPORT_CANCEL_DIRECT_OID_REQUEST TunCancelDirectOidRequest;
_Use_decl_annotations_
static void TunCancelDirectOidRequest(NDIS_HANDLE MiniportAdapterContext, PVOID RequestId)
{
}

static MINIPORT_CANCEL_OID_REQUEST TunCancelOidRequest;
_Use_decl_annotations_
static void TunCancelOidRequest(NDIS_HANDLE MiniportAdapterContext, PVOID RequestId)
{
}

static MINIPORT_INITIALIZE TunInitializeEx;
_Use_decl_annotations_
static NDIS_STATUS TunInitializeEx(NDIS_HANDLE MiniportAdapterHandle, NDIS_HANDLE MiniportDriverContext, PNDIS_MINIPORT_INIT_PARAMETERS MiniportInitParameters)
{
	NDIS_STATUS status;

	if (!MiniportAdapterHandle)
		return NDIS_STATUS_FAILURE;

	TUN_CTX *ctx;
	#pragma warning(suppress: 6014) /* Leaking memory 'ctx'. Note: 'ctx' is aliased in attr.MiniportAdapterContext; or freed on failure. */
	if (!NT_SUCCESS(NdisAllocateMemoryWithTag(&ctx, sizeof(TUN_CTX), TUN_MEMORY_TAG)))
		return NDIS_STATUS_FAILURE;

	NdisZeroMemory(ctx, sizeof(*ctx));
	ctx->State                 = TUN_STATE_INITIALIZING;
	ctx->PowerState            = NdisDeviceStateD0;
	ctx->MiniportAdapterHandle = MiniportAdapterHandle;

	ctx->Statistics.Header.Type         = NDIS_OBJECT_TYPE_DEFAULT;
	ctx->Statistics.Header.Revision     = NDIS_STATISTICS_INFO_REVISION_1;
	ctx->Statistics.Header.Size         = NDIS_SIZEOF_STATISTICS_INFO_REVISION_1;
	ctx->Statistics.SupportedStatistics =
		NDIS_STATISTICS_FLAGS_VALID_DIRECTED_FRAMES_RCV |
		NDIS_STATISTICS_FLAGS_VALID_MULTICAST_FRAMES_RCV |
		NDIS_STATISTICS_FLAGS_VALID_BROADCAST_FRAMES_RCV |
		NDIS_STATISTICS_FLAGS_VALID_BYTES_RCV |
		NDIS_STATISTICS_FLAGS_VALID_RCV_DISCARDS |
		NDIS_STATISTICS_FLAGS_VALID_RCV_ERROR |
		NDIS_STATISTICS_FLAGS_VALID_DIRECTED_FRAMES_XMIT |
		NDIS_STATISTICS_FLAGS_VALID_MULTICAST_FRAMES_XMIT |
		NDIS_STATISTICS_FLAGS_VALID_BROADCAST_FRAMES_XMIT |
		NDIS_STATISTICS_FLAGS_VALID_BYTES_XMIT |
		NDIS_STATISTICS_FLAGS_VALID_XMIT_ERROR |
		NDIS_STATISTICS_FLAGS_VALID_XMIT_DISCARDS |
		NDIS_STATISTICS_FLAGS_VALID_DIRECTED_BYTES_RCV |
		NDIS_STATISTICS_FLAGS_VALID_MULTICAST_BYTES_RCV |
		NDIS_STATISTICS_FLAGS_VALID_BROADCAST_BYTES_RCV |
		NDIS_STATISTICS_FLAGS_VALID_DIRECTED_BYTES_XMIT |
		NDIS_STATISTICS_FLAGS_VALID_MULTICAST_BYTES_XMIT |
		NDIS_STATISTICS_FLAGS_VALID_BROADCAST_BYTES_XMIT;

	NDIS_MINIPORT_ADAPTER_REGISTRATION_ATTRIBUTES attr = {
		.Header = {
			.Type           = NDIS_OBJECT_TYPE_MINIPORT_ADAPTER_REGISTRATION_ATTRIBUTES,
			.Revision       = NDIS_MINIPORT_ADAPTER_REGISTRATION_ATTRIBUTES_REVISION_1,
			.Size           = NDIS_SIZEOF_MINIPORT_ADAPTER_REGISTRATION_ATTRIBUTES_REVISION_1
		},
		.AttributeFlags         = NDIS_MINIPORT_ATTRIBUTES_NO_HALT_ON_SUSPEND,
		.InterfaceType          = NdisInterfaceInternal,
		.MiniportAdapterContext = ctx
	};
	if (!NT_SUCCESS(NdisMSetMiniportAttributes(MiniportAdapterHandle, (PNDIS_MINIPORT_ADAPTER_ATTRIBUTES)&attr))) {
		status = NDIS_STATUS_FAILURE;
		goto cleanup_ctx;
	}

	NDIS_PM_CAPABILITIES pmcap = {
		.Header = {
			.Type         = NDIS_OBJECT_TYPE_DEFAULT,
			.Revision     = NDIS_PM_CAPABILITIES_REVISION_1,
			.Size         = NDIS_SIZEOF_NDIS_PM_CAPABILITIES_REVISION_1
		},
		.MinMagicPacketWakeUp = NdisDeviceStateUnspecified,
		.MinPatternWakeUp     = NdisDeviceStateUnspecified,
		.MinLinkChangeWakeUp  = NdisDeviceStateUnspecified
	};
	static NDIS_OID suported_oids[] = {
		OID_GEN_MAXIMUM_TOTAL_SIZE,
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
		OID_PNP_QUERY_POWER
	};
	NDIS_MINIPORT_ADAPTER_GENERAL_ATTRIBUTES gen = {
		.Header = {
			.Type                  = NDIS_OBJECT_TYPE_MINIPORT_ADAPTER_GENERAL_ATTRIBUTES,
			.Revision              = NDIS_MINIPORT_ADAPTER_GENERAL_ATTRIBUTES_REVISION_2,
			.Size                  = NDIS_SIZEOF_MINIPORT_ADAPTER_GENERAL_ATTRIBUTES_REVISION_2
		},
		.MediaType                     = NdisMediumIP,
		.PhysicalMediumType            = NdisPhysicalMediumUnspecified,
		.MtuSize                       = TUN_EXCH_MAX_IP_PACKET_SIZE,
		.MaxXmitLinkSpeed              = TUN_LINK_SPEED,
		.MaxRcvLinkSpeed               = TUN_LINK_SPEED,
		.RcvLinkSpeed                  = TUN_LINK_SPEED,
		.XmitLinkSpeed                 = TUN_LINK_SPEED,
		.MediaConnectState             = MediaConnectStateDisconnected,
		.LookaheadSize                 = TUN_EXCH_MAX_IP_PACKET_SIZE,
		.MacOptions =
			NDIS_MAC_OPTION_TRANSFERS_NOT_PEND |
			NDIS_MAC_OPTION_COPY_LOOKAHEAD_DATA |
			NDIS_MAC_OPTION_NO_LOOPBACK,
		.SupportedPacketFilters =
			NDIS_PACKET_TYPE_DIRECTED |
			NDIS_PACKET_TYPE_ALL_MULTICAST |
			NDIS_PACKET_TYPE_BROADCAST |
			NDIS_PACKET_TYPE_ALL_LOCAL |
			NDIS_PACKET_TYPE_ALL_FUNCTIONAL,
		.AccessType                    = NET_IF_ACCESS_BROADCAST,
		.DirectionType                 = NET_IF_DIRECTION_SENDRECEIVE,
		.ConnectionType                = NET_IF_CONNECTION_DEDICATED,
		.IfType                        = IF_TYPE_PROP_VIRTUAL,
		.IfConnectorPresent            = FALSE,
		.SupportedStatistics           = ctx->Statistics.SupportedStatistics,
		.SupportedPauseFunctions       = NdisPauseFunctionsUnsupported,
		.AutoNegotiationFlags =
			NDIS_LINK_STATE_XMIT_LINK_SPEED_AUTO_NEGOTIATED |
			NDIS_LINK_STATE_RCV_LINK_SPEED_AUTO_NEGOTIATED |
			NDIS_LINK_STATE_DUPLEX_AUTO_NEGOTIATED |
			NDIS_LINK_STATE_PAUSE_FUNCTIONS_AUTO_NEGOTIATED,
		.SupportedOidList              = suported_oids,
		.SupportedOidListLength        = sizeof(suported_oids),
		.PowerManagementCapabilitiesEx = &pmcap
	};
	if (!NT_SUCCESS(NdisMSetMiniportAttributes(MiniportAdapterHandle, (PNDIS_MINIPORT_ADAPTER_ATTRIBUTES)&gen))) {
		status = NDIS_STATUS_FAILURE;
		goto cleanup_ctx;
	}

	KeInitializeSpinLock(&ctx->PacketQueue.Lock);

	KeInitializeSpinLock(&ctx->Device.ReadQueue.Lock);
	InitializeListHead(&ctx->Device.ReadQueue.List);
	IoCsqInitializeEx(&ctx->Device.ReadQueue.Csq,
		TunCsqInsertIrpEx,
		TunCsqRemoveIrp,
		TunCsqPeekNextIrp,
		TunCsqAcquireLock,
		TunCsqReleaseLock,
		TunCsqCompleteCanceledIrp);

	/* A miniport driver can call NdisMIndicateStatusEx after setting its
	 * registration attributes even if the driver is still in the context
	 * of the MiniportInitializeEx function.
	 */
	TunIndicateStatus(ctx);

	NET_BUFFER_LIST_POOL_PARAMETERS nbl_pool_param = {
			.Header = {
			.Type       = NDIS_OBJECT_TYPE_DEFAULT,
			.Revision   = NET_BUFFER_LIST_POOL_PARAMETERS_REVISION_1,
			.Size       = NDIS_SIZEOF_NET_BUFFER_LIST_POOL_PARAMETERS_REVISION_1
		},
		.ProtocolId         = NDIS_PROTOCOL_ID_DEFAULT,
		.fAllocateNetBuffer = TRUE,
		.PoolTag            = TUN_MEMORY_TAG
	};
	#pragma warning(suppress: 6014) /* Leaking memory 'ctx->NBLPool'. Note: 'ctx->NBLPool' is freed in TunHaltEx; or freed on failure. */
	ctx->NBLPool = NdisAllocateNetBufferListPool(MiniportAdapterHandle, &nbl_pool_param); 
	if (!ctx->NBLPool) {
		status = NDIS_STATUS_FAILURE;
		goto cleanup_ctx;
	}

	WCHAR device_name[(sizeof(L"\\Device\\" TUN_DEVICE_NAME) + 10/*MAXULONG as string*/) / sizeof(WCHAR)];
	UNICODE_STRING unicode_device_name;
	TunInitUnicodeString(&unicode_device_name, device_name);
	RtlUnicodeStringPrintf(&unicode_device_name, L"\\Device\\" TUN_DEVICE_NAME, (ULONG)MiniportInitParameters->NetLuid.Info.NetLuidIndex);

	WCHAR symbolic_name[(sizeof(L"\\DosDevices\\" TUN_DEVICE_NAME) + 10/*MAXULONG as string*/) / sizeof(WCHAR)];
	UNICODE_STRING unicode_symbolic_name;
	TunInitUnicodeString(&unicode_symbolic_name, symbolic_name);
	RtlUnicodeStringPrintf(&unicode_symbolic_name, L"\\DosDevices\\" TUN_DEVICE_NAME, (ULONG)MiniportInitParameters->NetLuid.Info.NetLuidIndex);

	static PDRIVER_DISPATCH dispatch_table[IRP_MJ_MAXIMUM_FUNCTION + 1] = {
		TunDispatchCreate,  /* IRP_MJ_CREATE                   */
		NULL,               /* IRP_MJ_CREATE_NAMED_PIPE        */
		TunDispatchClose,   /* IRP_MJ_CLOSE                    */
		TunDispatchRead,    /* IRP_MJ_READ                     */
		TunDispatchWrite,   /* IRP_MJ_WRITE                    */
		NULL,               /* IRP_MJ_QUERY_INFORMATION        */
		NULL,               /* IRP_MJ_SET_INFORMATION          */
		NULL,               /* IRP_MJ_QUERY_EA                 */
		NULL,               /* IRP_MJ_SET_EA                   */
		NULL,               /* IRP_MJ_FLUSH_BUFFERS            */
		NULL,               /* IRP_MJ_QUERY_VOLUME_INFORMATION */
		NULL,               /* IRP_MJ_SET_VOLUME_INFORMATION   */
		NULL,               /* IRP_MJ_DIRECTORY_CONTROL        */
		NULL,               /* IRP_MJ_FILE_SYSTEM_CONTROL      */
		NULL,               /* IRP_MJ_DEVICE_CONTROL           */
		NULL,               /* IRP_MJ_INTERNAL_DEVICE_CONTROL  */
		NULL,               /* IRP_MJ_SHUTDOWN                 */
		NULL,               /* IRP_MJ_LOCK_CONTROL             */
		TunDispatchCleanup, /* IRP_MJ_CLEANUP                  */
	};
	NDIS_DEVICE_OBJECT_ATTRIBUTES t = {
		.Header = {
			.Type      = NDIS_OBJECT_TYPE_DEVICE_OBJECT_ATTRIBUTES,
			.Revision  = NDIS_DEVICE_OBJECT_ATTRIBUTES_REVISION_1,
			.Size      = NDIS_SIZEOF_DEVICE_OBJECT_ATTRIBUTES_REVISION_1
		},
		.DeviceName        = &unicode_device_name,
		.SymbolicName      = &unicode_symbolic_name,
		.MajorFunctions    = dispatch_table,
		.ExtensionSize     = sizeof(TUN_CTX *),
		.DefaultSDDLString = &SDDL_DEVOBJ_SYS_ALL /* Kernel, and SYSTEM: full control. Others: none */
	};
	if (!NT_SUCCESS(NdisRegisterDeviceEx(NdisMiniportDriverHandle, &t, &ctx->Device.Object, &ctx->Device.Handle))) {
		status = NDIS_STATUS_FAILURE;
		goto cleanup_NdisFreeNetBufferListPool;
	}

	ctx->Device.Object->Flags &= ~DO_BUFFERED_IO;
	ctx->Device.Object->Flags |=  DO_DIRECT_IO;

	TUN_CTX * volatile * control_device_extension = TunGetContextPointer(ctx->Device.Object);
	if (!control_device_extension) {
		status = NDIS_STATUS_FAILURE;
		goto cleanup_NdisDeregisterDeviceEx;
	}
	InterlockedExchangePointer(control_device_extension, ctx);

	ctx->State = TUN_STATE_PAUSED;
	return NDIS_STATUS_SUCCESS;

cleanup_NdisDeregisterDeviceEx:
	NdisDeregisterDeviceEx(ctx->Device.Handle);
cleanup_NdisFreeNetBufferListPool:
	NdisFreeNetBufferListPool(ctx->NBLPool);
cleanup_ctx:
	NdisFreeMemory(ctx, 0, 0);
	return status;
}

static MINIPORT_UNLOAD TunDriverUnload;
_Use_decl_annotations_
static VOID TunDriverUnload(PDRIVER_OBJECT DriverObject)
{
	NdisMDeregisterMiniportDriver(NdisMiniportDriverHandle);
}

static MINIPORT_HALT TunHaltEx;
_Use_decl_annotations_
static void TunHaltEx(NDIS_HANDLE MiniportAdapterContext, NDIS_HALT_ACTION HaltAction)
{
	TUN_CTX *ctx = (TUN_CTX *)MiniportAdapterContext;
	if (InterlockedGet((LONG *)&ctx->State) != TUN_STATE_PAUSED)
		return;

	ASSERT(!InterlockedGet64(&ctx->ActiveTransactionCount));
	ASSERT(!InterlockedGet64(&ctx->Device.RefCount));

	/* Reset adapter context in device object, as Windows keeps calling dispatch handlers even after NdisDeregisterDeviceEx(). */
	TUN_CTX * volatile * control_device_extension = TunGetContextPointer(ctx->Device.Object);
	if (control_device_extension)
		InterlockedExchangePointer(control_device_extension, NULL);

	/* Release resources. */
	NdisDeregisterDeviceEx(ctx->Device.Handle);
	NdisFreeNetBufferListPool(ctx->NBLPool);
	NdisFreeMemory(ctx, 0, 0);
}

_IRQL_requires_max_(PASSIVE_LEVEL)
static NDIS_STATUS TunOidSet(_Inout_ TUN_CTX *ctx, _Inout_ NDIS_OID_REQUEST *OidRequest)
{
	ASSERT(OidRequest->RequestType == NdisRequestSetInformation);

	OidRequest->DATA.SET_INFORMATION.BytesRead   = 0;
	OidRequest->DATA.SET_INFORMATION.BytesNeeded = 0;

	switch (OidRequest->DATA.SET_INFORMATION.Oid) {
	case OID_GEN_CURRENT_PACKET_FILTER:
	case OID_GEN_CURRENT_LOOKAHEAD:
		if (OidRequest->DATA.SET_INFORMATION.InformationBufferLength != 4) {
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
		if (OidRequest->DATA.SET_INFORMATION.InformationBufferLength != sizeof(NDIS_DEVICE_POWER_STATE)) {
			OidRequest->DATA.SET_INFORMATION.BytesNeeded = sizeof(NDIS_DEVICE_POWER_STATE);
			return NDIS_STATUS_INVALID_LENGTH;
		}
		OidRequest->DATA.SET_INFORMATION.BytesRead = sizeof(NDIS_DEVICE_POWER_STATE);
		ctx->PowerState = *((NDIS_DEVICE_POWER_STATE *)OidRequest->DATA.SET_INFORMATION.InformationBuffer);
		return NDIS_STATUS_SUCCESS;
	}

	return NDIS_STATUS_INVALID_OID;
}

_IRQL_requires_max_(APC_LEVEL)
_Must_inspect_result_
static NDIS_STATUS TunOidQuery(_Inout_ TUN_CTX *ctx, _Inout_ NDIS_OID_REQUEST *OidRequest)
{
	ASSERT(OidRequest->RequestType == NdisRequestQueryInformation || OidRequest->RequestType == NdisRequestQueryStatistics);

	UINT value32;
	UINT size = sizeof(value32);
	const void *buf = &value32;

	switch (OidRequest->DATA.QUERY_INFORMATION.Oid) {
	case OID_GEN_MAXIMUM_TOTAL_SIZE:
	case OID_GEN_TRANSMIT_BLOCK_SIZE:
	case OID_GEN_RECEIVE_BLOCK_SIZE:
		value32 = TUN_EXCH_MAX_IP_PACKET_SIZE;
		break;

	case OID_GEN_TRANSMIT_BUFFER_SPACE:
	case OID_GEN_RECEIVE_BUFFER_SPACE:
		value32 = TUN_EXCH_MAX_IP_PACKET_SIZE * TUN_EXCH_MAX_PACKETS;
		break;

	case OID_GEN_VENDOR_ID:
		value32 = TunHtonl(TUN_VENDOR_ID);
		break;

	case OID_GEN_VENDOR_DESCRIPTION:
		size = (UINT)sizeof(TUN_VENDOR_NAME);
		buf = TUN_VENDOR_NAME;
		break;

	case OID_GEN_VENDOR_DRIVER_VERSION:
		value32 = (WINTUN_VERSION_MAJ << 16) | WINTUN_VERSION_MIN;
		break;

	case OID_GEN_XMIT_OK:
		value32 = (UINT)(
			InterlockedGet64((LONG64 *)&ctx->Statistics.ifHCOutUcastPkts    ) +
			InterlockedGet64((LONG64 *)&ctx->Statistics.ifHCOutMulticastPkts) +
			InterlockedGet64((LONG64 *)&ctx->Statistics.ifHCOutBroadcastPkts));
		break;

	case OID_GEN_RCV_OK:
		value32 = (UINT)(
			InterlockedGet64((LONG64 *)&ctx->Statistics.ifHCInUcastPkts    ) +
			InterlockedGet64((LONG64 *)&ctx->Statistics.ifHCInMulticastPkts) +
			InterlockedGet64((LONG64 *)&ctx->Statistics.ifHCInBroadcastPkts));
		break;

	case OID_GEN_STATISTICS:
		size = (UINT)sizeof(ctx->Statistics);
		buf = &ctx->Statistics;
		break;

	case OID_GEN_INTERRUPT_MODERATION: {
		static const NDIS_INTERRUPT_MODERATION_PARAMETERS intp = {
			.Header = {
				.Type         = NDIS_OBJECT_TYPE_DEFAULT,
				.Revision     = NDIS_INTERRUPT_MODERATION_PARAMETERS_REVISION_1,
				.Size         = NDIS_SIZEOF_INTERRUPT_MODERATION_PARAMETERS_REVISION_1
			},
			.InterruptModeration = NdisInterruptModerationNotSupported
		};
		size = (UINT)sizeof(intp);
		buf = &intp;
		break;
	}

	case OID_PNP_QUERY_POWER:
		size = 0;
		break;

	default:
		OidRequest->DATA.QUERY_INFORMATION.BytesWritten = 0;
		return NDIS_STATUS_INVALID_OID;
	}

	if (size > OidRequest->DATA.QUERY_INFORMATION.InformationBufferLength) {
		OidRequest->DATA.QUERY_INFORMATION.BytesNeeded  = size;
		OidRequest->DATA.QUERY_INFORMATION.BytesWritten = 0;
		return NDIS_STATUS_INVALID_LENGTH;
	}

	NdisMoveMemory(OidRequest->DATA.QUERY_INFORMATION.InformationBuffer, buf, size);
	OidRequest->DATA.QUERY_INFORMATION.BytesNeeded = OidRequest->DATA.QUERY_INFORMATION.BytesWritten = size;

	return NDIS_STATUS_SUCCESS;
}

static MINIPORT_OID_REQUEST TunOidRequest;
_Use_decl_annotations_
static NDIS_STATUS TunOidRequest(NDIS_HANDLE MiniportAdapterContext, PNDIS_OID_REQUEST OidRequest)
{
	switch (OidRequest->RequestType) {
	case NdisRequestQueryInformation:
	case NdisRequestQueryStatistics:
		return TunOidQuery(MiniportAdapterContext, OidRequest);

	case NdisRequestSetInformation:
		return TunOidSet(MiniportAdapterContext, OidRequest);

	default:
		return NDIS_STATUS_NOT_SUPPORTED;
	}
}

static MINIPORT_DIRECT_OID_REQUEST TunDirectOidRequest;
_Use_decl_annotations_
static NDIS_STATUS TunDirectOidRequest(NDIS_HANDLE MiniportAdapterContext, PNDIS_OID_REQUEST OidRequest)
{
	switch (OidRequest->RequestType) {
	case NdisRequestQueryInformation:
	case NdisRequestQueryStatistics:
	case NdisRequestSetInformation:
		return NDIS_STATUS_INVALID_OID;

	default:
		return NDIS_STATUS_NOT_SUPPORTED;
	}
}

static MINIPORT_SEND_NET_BUFFER_LISTS TunSendNetBufferLists;
_Use_decl_annotations_
static void TunSendNetBufferLists(NDIS_HANDLE MiniportAdapterContext, NET_BUFFER_LIST *NetBufferLists, NDIS_PORT_NUMBER PortNumber, ULONG SendFlags)
{
	TUN_CTX *ctx = (TUN_CTX *)MiniportAdapterContext;

	NDIS_STATUS status;
	if (!NT_SUCCESS(status = TunCheckForPause(ctx, 1))) {
		TunSetNBLStatus(NetBufferLists, status);
		NdisMSendNetBufferListsComplete(ctx->MiniportAdapterHandle, NetBufferLists, SendFlags & NDIS_SEND_FLAGS_DISPATCH_LEVEL ? NDIS_SEND_COMPLETE_FLAGS_DISPATCH_LEVEL : 0);
		goto cleanup_TunCompletePause;
	}

	TunQueueAppend(ctx, NetBufferLists, TUN_QUEUE_MAX_NBLS);
	TunQueueProcess(ctx);

cleanup_TunCompletePause:
	TunCompletePause(ctx, 1, TRUE);
}

DRIVER_INITIALIZE DriverEntry;
_Use_decl_annotations_
NTSTATUS DriverEntry(DRIVER_OBJECT *DriverObject, UNICODE_STRING *RegistryPath)
{
	NDIS_MINIPORT_DRIVER_CHARACTERISTICS miniport = {
		.Header = {
			.Type                  = NDIS_OBJECT_TYPE_MINIPORT_DRIVER_CHARACTERISTICS,
			.Revision              = NDIS_MINIPORT_DRIVER_CHARACTERISTICS_REVISION_2,
			.Size                  = NDIS_SIZEOF_MINIPORT_DRIVER_CHARACTERISTICS_REVISION_2
		},

		.MajorNdisVersion              = NDIS_MINIPORT_MAJOR_VERSION,
		.MinorNdisVersion              = NDIS_MINIPORT_MINOR_VERSION,

		.MajorDriverVersion            = WINTUN_VERSION_MAJ,
		.MinorDriverVersion            = WINTUN_VERSION_MIN,

		.SetOptionsHandler             = TunSetOptions,
		.InitializeHandlerEx           = TunInitializeEx,
		.HaltHandlerEx                 = TunHaltEx,
		.UnloadHandler                 = TunDriverUnload,
		.PauseHandler                  = TunPause,
		.RestartHandler                = TunRestart,
		.OidRequestHandler             = TunOidRequest,
		.SendNetBufferListsHandler     = TunSendNetBufferLists,
		.ReturnNetBufferListsHandler   = TunReturnNetBufferLists,
		.CancelSendHandler             = TunCancelSend,
		.DevicePnPEventNotifyHandler   = TunDevicePnPEventNotify,
		.ShutdownHandlerEx             = TunShutdownEx,
		.CancelOidRequestHandler       = TunCancelOidRequest,
		.DirectOidRequestHandler       = TunDirectOidRequest,
		.CancelDirectOidRequestHandler = TunCancelDirectOidRequest
	};
	return NdisMRegisterMiniportDriver(DriverObject, RegistryPath, NULL, &miniport, &NdisMiniportDriverHandle);
}

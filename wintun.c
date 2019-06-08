/* SPDX-License-Identifier: GPL-2.0
 *
 * Copyright (C) 2018-2019 WireGuard LLC. All Rights Reserved.
 */

#include <stdio.h>
#include <string.h>
#include <ntifs.h>
#include <wdm.h>
#include <wdmguid.h>
#include <wdmsec.h>
#include <ndis.h>
#include <ndisguid.h>
#include <bcrypt.h>
#include <ntstrsafe.h>
#include "undocumented.h"

#pragma warning(disable : 4100) // unreferenced formal parameter
#pragma warning(disable : 4200) // nonstandard extension used: zero-sized array in struct/union
#pragma warning(disable : 4204) // nonstandard extension used: non-constant aggregate initializer
#pragma warning(disable : 4221) // nonstandard extension used: <member>: cannot be initialized using address of automatic variable <variable>

#define TUN_DEVICE_NAME         L"WINTUN%u"

#define TUN_VENDOR_NAME         "Wintun Tunnel"
#define TUN_VENDOR_ID           0xFFFFFF00
#define TUN_LINK_SPEED          100000000000ULL // 100gbps

#define TUN_EXCH_MAX_PACKETS            256                                                 // Maximum number of full-sized exchange packets that can be exchanged in a single read/write
#define TUN_EXCH_MAX_PACKET_SIZE        0xF000                                              // Maximum exchange packet size - empirically determined by net buffer list (pool) limitations
#define TUN_EXCH_ALIGNMENT              16                                                  // Memory alignment in exchange buffers
#define TUN_EXCH_MAX_IP_PACKET_SIZE     (TUN_EXCH_MAX_PACKET_SIZE - sizeof(TUN_PACKET))     // Maximum IP packet size (headers + payload)
#define TUN_EXCH_MAX_BUFFER_SIZE        (TUN_EXCH_MAX_PACKETS * TUN_EXCH_MAX_PACKET_SIZE)   // Maximum size of read/write exchange buffer
#define TUN_EXCH_MIN_BUFFER_SIZE_READ   TUN_EXCH_MAX_PACKET_SIZE                            // Minimum size of read exchange buffer
#define TUN_EXCH_MIN_BUFFER_SIZE_WRITE  (sizeof(TUN_PACKET))                                // Minimum size of write exchange buffer
#define TUN_QUEUE_MAX_NBLS              1000
#define TUN_MEMORY_TAG                  'wtun'
#define TUN_CSQ_INSERT_HEAD             ((PVOID)TRUE)
#define TUN_CSQ_INSERT_TAIL             ((PVOID)FALSE)

#if REG_DWORD == REG_DWORD_BIG_ENDIAN
#define TUN_HTONS(x)    ((USHORT)(x))
#define TUN_HTONL(x)    ((ULONG)(x))
#elif REG_DWORD == REG_DWORD_LITTLE_ENDIAN
#define TUN_HTONS(x)    (((USHORT)(x) & 0x00ff) << 8 | ((USHORT)(x) & 0xff00) >> 8)
#define TUN_HTONL(x)    (((ULONG)(x) & 0x000000ff) << 24 | ((ULONG)(x) & 0x0000ff00) << 8 | ((ULONG)(x) & 0x00ff0000) >> 8 | ((ULONG)(x) & 0xff000000) >> 24)
#else
#error "Unable to determine endianess"
#endif

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
	TUN_STATE_HALTING,              // In the Halting state, a miniport driver completes any operations that are required to halt an adapter.
	TUN_STATE_PAUSED,               // In the Paused state, the adapter does not indicate received network data or accept send requests.
	TUN_STATE_RESTARTING,           // In the Restarting state, a miniport driver completes any operations that are required to restart send and receive operations for an adapter.
	TUN_STATE_RUNNING,              // In the Running state, a miniport driver performs send and receive processing for an adapter.
	TUN_STATE_PAUSING,              // In the Pausing state, a miniport driver completes any operations that are required to stop send and receive operations for an adapter.
} TUN_STATE;

typedef struct _TUN_CTX {
	volatile TUN_STATE State;
	volatile NDIS_DEVICE_POWER_STATE PowerState;

	/* Used like RCU. When we're making use of queues, we take a shared lock. When we want to
	 * drain the queues and toggle the state, we take an exclusive lock before toggling the
	 * atomic and then releasing. It's similar to setting the atomic and then calling rcu_barrier(). */
	EX_SPIN_LOCK TransitionLock;

	NDIS_HANDLE MiniportAdapterHandle;
	NDIS_STATISTICS_INFO Statistics;

	volatile LONG64 ActiveTransactionCount;

	volatile struct {
		FILE_OBJECT *FileObject;
		PVOID Handle;
	} PnPNotifications;

	struct {
		NDIS_HANDLE Handle;
		volatile LONG64 RefCount;
		IO_REMOVE_LOCK RemoveLock;

		struct {
			KSPIN_LOCK Lock;
			IO_CSQ Csq;
			LIST_ENTRY List;
		} ReadQueue;

		DEVICE_OBJECT *Object;
	} Device;

	struct {
		KSPIN_LOCK Lock;
		NET_BUFFER_LIST *FirstNbl, *LastNbl;
		NET_BUFFER *NextNb;
		LONG NumNbl;
	} PacketQueue;

	NDIS_HANDLE NBLPool;

	ULONG NetLuidIndex;
} TUN_CTX;

static UINT NdisVersion;
static PVOID TunNotifyInterfaceChangeHandle;
static NDIS_HANDLE NdisMiniportDriverHandle;
static volatile LONG64 AdapterCount;

#define InterlockedGet(val)             (InterlockedAdd((val), 0))
#define InterlockedGet64(val)           (InterlockedAdd64((val), 0))
#define InterlockedGetPointer(val)      (InterlockedCompareExchangePointer((val), NULL, NULL))
#define TunPacketAlign(size)            (((UINT)(size) + (UINT)(TUN_EXCH_ALIGNMENT - 1)) & ~(UINT)(TUN_EXCH_ALIGNMENT - 1))
#define TunInitUnicodeString(str, buf)  { (str)->Length = 0; (str)->MaximumLength = sizeof(buf); (str)->Buffer = buf; }

_IRQL_requires_max_(DISPATCH_LEVEL)
_IRQL_requires_same_
static void TunIndicateStatus(_In_ NDIS_HANDLE MiniportAdapterHandle, _In_ NDIS_MEDIA_CONNECT_STATE MediaConnectState)
{
	NDIS_LINK_STATE state = {
		.Header = {
			.Type      = NDIS_OBJECT_TYPE_DEFAULT,
			.Revision  = NDIS_LINK_STATE_REVISION_1,
			.Size      = NDIS_SIZEOF_LINK_STATE_REVISION_1
		},
		.MediaConnectState = MediaConnectState,
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
		.SourceHandle     = MiniportAdapterHandle,
		.StatusCode       = NDIS_STATUS_LINK_STATE,
		.StatusBuffer     = &state,
		.StatusBufferSize = sizeof(state)
	};

	NdisMIndicateStatusEx(MiniportAdapterHandle, &t);
}

_IRQL_requires_max_(DISPATCH_LEVEL)
static void TunCompleteRequest(_Inout_ TUN_CTX *ctx, _Inout_ IRP *irp, _In_ NTSTATUS status, _In_ CCHAR priority_boost)
{
	irp->IoStatus.Status = status;
	IoCompleteRequest(irp, priority_boost);
	IoReleaseRemoveLock(&ctx->Device.RemoveLock, irp);
}

_IRQL_requires_same_
_Must_inspect_result_
_Requires_lock_held_(ctx->TransitionLock)
static NTSTATUS TunCheckForPause(_Inout_ TUN_CTX *ctx)
{
	ASSERT(InterlockedGet64(&ctx->ActiveTransactionCount) < MAXLONG64);
	InterlockedIncrement64(&ctx->ActiveTransactionCount);
	return
		InterlockedGet64(&ctx->Device.RefCount)    <= 0                 ? NDIS_STATUS_SEND_ABORTED :
		InterlockedGet  ((LONG *)&ctx->State)      != TUN_STATE_RUNNING ? STATUS_NDIS_PAUSED :
		InterlockedGet  ((LONG *)&ctx->PowerState) >= NdisDeviceStateD1 ? STATUS_NDIS_LOW_POWER_STATE :
		STATUS_SUCCESS;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
static NDIS_STATUS TunCompletePause(_Inout_ TUN_CTX *ctx, _In_ BOOLEAN async_completion)
{
	ASSERT(InterlockedGet64(&ctx->ActiveTransactionCount) > 0);
	if (InterlockedDecrement64(&ctx->ActiveTransactionCount) <= 0 &&
		InterlockedCompareExchange((LONG *)&ctx->State, TUN_STATE_PAUSED, TUN_STATE_PAUSING) == TUN_STATE_PAUSING) {
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
_Requires_lock_not_held_(CONTAINING_RECORD(Csq, TUN_CTX, Device.ReadQueue.Csq)->Device.ReadQueue.Lock)
_Acquires_lock_(CONTAINING_RECORD(Csq, TUN_CTX, Device.ReadQueue.Csq)->Device.ReadQueue.Lock)
static VOID TunCsqAcquireLock(_In_ IO_CSQ *Csq, _Out_ _At_(*Irql, _Post_ _IRQL_saves_) KIRQL *Irql)
{
	KeAcquireSpinLock(&CONTAINING_RECORD(Csq, TUN_CTX, Device.ReadQueue.Csq)->Device.ReadQueue.Lock, Irql);
}

_IRQL_requires_(DISPATCH_LEVEL)
_Requires_lock_held_(CONTAINING_RECORD(Csq, TUN_CTX, Device.ReadQueue.Csq)->Device.ReadQueue.Lock)
_Releases_lock_(CONTAINING_RECORD(Csq, TUN_CTX, Device.ReadQueue.Csq)->Device.ReadQueue.Lock)
static VOID TunCsqReleaseLock(_In_ IO_CSQ *Csq, _In_ _IRQL_restores_ KIRQL Irql)
{
	KeReleaseSpinLock(&CONTAINING_RECORD(Csq, TUN_CTX, Device.ReadQueue.Csq)->Device.ReadQueue.Lock, Irql);
}

static IO_CSQ_COMPLETE_CANCELED_IRP TunCsqCompleteCanceledIrp;
_Use_decl_annotations_
static VOID TunCsqCompleteCanceledIrp(IO_CSQ *Csq, IRP *Irp)
{
	TUN_CTX *ctx = CONTAINING_RECORD(Csq, TUN_CTX, Device.ReadQueue.Csq);
	TunCompleteRequest(ctx, Irp, STATUS_CANCELLED, IO_NO_INCREMENT);
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

		/* If we use MdlMappingNoWrite flag and call NdisMIndicateReceiveNetBufferLists without
		 * NDIS_RECEIVE_FLAGS_RESOURCES flag we've got a ATTEMPTED_WRITE_TO_READONLY_MEMORY page
		 * fault. */
		priority = NormalPagePriority /*| MdlMappingNoWrite*/;
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
static _Return_type_success_(return != NULL) IRP *TunRemoveNextIrp(_Inout_ TUN_CTX *ctx, _Out_ UCHAR **buffer, _Out_ ULONG *size)
{
	IRP *irp;

retry:
	irp = IoCsqRemoveNextIrp(&ctx->Device.ReadQueue.Csq, NULL);
	if (!irp)
		return NULL;

	NTSTATUS status = TunGetIrpBuffer(irp, buffer, size);
	if (!NT_SUCCESS(status)) {
		TunCompleteRequest(ctx, irp, status, IO_NO_INCREMENT);
		goto retry;
	}

	ASSERT(irp->IoStatus.Information <= (ULONG_PTR)*size);

	return irp;
}

_IRQL_requires_same_
static BOOLEAN TunWontFitIntoIrp(_In_ IRP *Irp, _In_ ULONG size, _In_ NET_BUFFER *nb)
{
	return (ULONG_PTR)size < Irp->IoStatus.Information + TunPacketAlign(sizeof(TUN_PACKET) + NET_BUFFER_DATA_LENGTH(nb));
}

_IRQL_requires_max_(DISPATCH_LEVEL)
_Must_inspect_result_
static NTSTATUS TunWriteIntoIrp(_Inout_ IRP *Irp, _Inout_ UCHAR *buffer, _In_ NET_BUFFER *nb, _Inout_ NDIS_STATISTICS_INFO *statistics)
{
	ULONG p_size = NET_BUFFER_DATA_LENGTH(nb);
	TUN_PACKET *p = (TUN_PACKET *)(buffer + Irp->IoStatus.Information);

	p->Size = p_size;
	void *ptr = NdisGetDataBuffer(nb, p_size, p->Data, 1, 0);
	if (!ptr) {
		if (statistics)
			InterlockedIncrement64((LONG64 *)&statistics->ifOutErrors);
		return NDIS_STATUS_RESOURCES;
	}
	if (ptr != p->Data)
		NdisMoveMemory(p->Data, ptr, p_size);

	Irp->IoStatus.Information += TunPacketAlign(sizeof(TUN_PACKET) + p_size);

	InterlockedAdd64((LONG64 *)&statistics->ifHCOutOctets,      p_size);
	InterlockedAdd64((LONG64 *)&statistics->ifHCOutUcastOctets, p_size);
	InterlockedIncrement64((LONG64 *)&statistics->ifHCOutUcastPkts);
	return STATUS_SUCCESS;
}

#define NET_BUFFER_LIST_REFCOUNT(nbl) ((volatile LONG64 *)NET_BUFFER_LIST_MINIPORT_RESERVED(nbl))

_IRQL_requires_same_
static void TunNBLRefInit(_Inout_ TUN_CTX *ctx, _Inout_ NET_BUFFER_LIST *nbl)
{
	ASSERT(InterlockedGet64(&ctx->ActiveTransactionCount) < MAXLONG64);
	InterlockedIncrement64(&ctx->ActiveTransactionCount);
	ASSERT(InterlockedGet(&ctx->PacketQueue.NumNbl) < MAXLONG);
	InterlockedIncrement(&ctx->PacketQueue.NumNbl);
	InterlockedExchange64(NET_BUFFER_LIST_REFCOUNT(nbl), 1);
}

_IRQL_requires_same_
static void TunNBLRefInc(_Inout_ NET_BUFFER_LIST *nbl)
{
	ASSERT(InterlockedGet64(NET_BUFFER_LIST_REFCOUNT(nbl)));
	ASSERT(InterlockedGet64(NET_BUFFER_LIST_REFCOUNT(nbl)) < MAXLONG64);
	InterlockedIncrement64(NET_BUFFER_LIST_REFCOUNT(nbl));
}

_When_( (SendCompleteFlags & NDIS_SEND_COMPLETE_FLAGS_DISPATCH_LEVEL), _IRQL_requires_    (DISPATCH_LEVEL))
_When_(!(SendCompleteFlags & NDIS_SEND_COMPLETE_FLAGS_DISPATCH_LEVEL), _IRQL_requires_max_(DISPATCH_LEVEL))
static BOOLEAN TunNBLRefDec(_Inout_ TUN_CTX *ctx, _Inout_ NET_BUFFER_LIST *nbl, _In_ ULONG SendCompleteFlags)
{
	ASSERT(InterlockedGet64(NET_BUFFER_LIST_REFCOUNT(nbl)) > 0);
	if (InterlockedDecrement64(NET_BUFFER_LIST_REFCOUNT(nbl)) <= 0) {
		NET_BUFFER_LIST_NEXT_NBL(nbl) = NULL;
		NdisMSendNetBufferListsComplete(ctx->MiniportAdapterHandle, nbl, SendCompleteFlags);
		ASSERT(InterlockedGet(&ctx->PacketQueue.NumNbl) > 0);
		InterlockedDecrement(&ctx->PacketQueue.NumNbl);
		TunCompletePause(ctx, TRUE);
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
static void TunQueueClear(_Inout_ TUN_CTX *ctx, _In_ NDIS_STATUS status)
{
	KLOCK_QUEUE_HANDLE lqh;
	KeAcquireInStackQueuedSpinLock(&ctx->PacketQueue.Lock, &lqh);
	for (NET_BUFFER_LIST *nbl = ctx->PacketQueue.FirstNbl, *nbl_next; nbl; nbl = nbl_next) {
		nbl_next = NET_BUFFER_LIST_NEXT_NBL(nbl);
		NET_BUFFER_LIST_STATUS(nbl) = status;
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

			_Analysis_assume_(buffer);
			_Analysis_assume_(irp->IoStatus.Information <= size);
		} else
			nb = TunQueueRemove(ctx, &nbl);

		/* If the NB won't fit in the IRP, return it. */
		if (nb && TunWontFitIntoIrp(irp, size, nb)) {
			TunQueuePrepend(ctx, nb, nbl);
			if (nbl)
				TunNBLRefDec(ctx, nbl, NDIS_SEND_COMPLETE_FLAGS_DISPATCH_LEVEL);
			nbl = NULL;
			nb = NULL;
		}

		KeReleaseInStackQueuedSpinLock(&lqh);

		/* Process NB and IRP. */
		if (nb) {
			NTSTATUS status = TunWriteIntoIrp(irp, buffer, nb, &ctx->Statistics);
			if (!NT_SUCCESS(status)) {
				if (nbl)
					NET_BUFFER_LIST_STATUS(nbl) = status;
				IoCsqInsertIrpEx(&ctx->Device.ReadQueue.Csq, irp, NULL, TUN_CSQ_INSERT_HEAD);
				irp = NULL;
			}
		} else {
			TunCompleteRequest(ctx, irp, STATUS_SUCCESS, IO_NETWORK_INCREMENT);
			irp = NULL;
		}

		if (nbl)
			TunNBLRefDec(ctx, nbl, 0);
	}
}

_IRQL_requires_same_
static void TunSetNBLStatus(_Inout_opt_ NET_BUFFER_LIST *nbl, _In_ NDIS_STATUS status)
{
	for (; nbl; nbl = NET_BUFFER_LIST_NEXT_NBL(nbl))
		NET_BUFFER_LIST_STATUS(nbl) = status;
}

static MINIPORT_SEND_NET_BUFFER_LISTS TunSendNetBufferLists;
_Use_decl_annotations_
static void TunSendNetBufferLists(NDIS_HANDLE MiniportAdapterContext, NET_BUFFER_LIST *NetBufferLists, NDIS_PORT_NUMBER PortNumber, ULONG SendFlags)
{
	TUN_CTX *ctx = (TUN_CTX *)MiniportAdapterContext;

	KIRQL irql = ExAcquireSpinLockShared(&ctx->TransitionLock);

	NDIS_STATUS status;
	if (!NT_SUCCESS(status = TunCheckForPause(ctx))) {
		TunSetNBLStatus(NetBufferLists, status);
		NdisMSendNetBufferListsComplete(ctx->MiniportAdapterHandle, NetBufferLists, NDIS_SEND_COMPLETE_FLAGS_DISPATCH_LEVEL);
		goto cleanup_TunCompletePause;
	}

	TunQueueAppend(ctx, NetBufferLists, TUN_QUEUE_MAX_NBLS);

	TunQueueProcess(ctx);

cleanup_TunCompletePause:
	TunCompletePause(ctx, TRUE);
	ExReleaseSpinLockShared(&ctx->TransitionLock, irql);
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
			NET_BUFFER_LIST_STATUS(nbl) = NDIS_STATUS_SEND_ABORTED;
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

#define IRP_REFCOUNT(irp)        ((volatile LONG *)&(irp)->Tail.Overlay.DriverContext[0])
#define NET_BUFFER_LIST_IRP(nbl) (NET_BUFFER_LIST_MINIPORT_RESERVED(nbl)[0])

_IRQL_requires_max_(DISPATCH_LEVEL)
_Must_inspect_result_
static NTSTATUS TunWriteFromIrp(_Inout_ TUN_CTX *ctx, _Inout_ IRP *Irp)
{
	NTSTATUS status;

	KIRQL irql = ExAcquireSpinLockShared(&ctx->TransitionLock);

	if (!NT_SUCCESS(TunCheckForPause(ctx))) {
		status = STATUS_CANCELLED;
		goto cleanup_TunCompletePause;
	}

	UCHAR *buffer;
	ULONG size;
	if (!NT_SUCCESS(status = TunGetIrpBuffer(Irp, &buffer, &size)))
		goto cleanup_TunCompletePause;

	const UCHAR *b = buffer, *b_end = buffer + size;
	typedef enum _ethtypeidx_t {
		ethtypeidx_ipv4 = 0, ethtypeidx_start = 0,
		ethtypeidx_ipv6,
		ethtypeidx_end
	} ethtypeidx_t;
	static const struct {
		ULONG nbl_flags;
		USHORT nbl_proto;
	} ether_const[ethtypeidx_end] = {
		{ NDIS_NBL_FLAGS_IS_IPV4, TUN_HTONS(NDIS_ETH_TYPE_IPV4) },
		{ NDIS_NBL_FLAGS_IS_IPV6, TUN_HTONS(NDIS_ETH_TYPE_IPV6) },
	};
	struct {
		NET_BUFFER_LIST *head, *tail;
		LONG count;
	} nbl_queue[ethtypeidx_end] = {
		{ NULL, NULL, 0 },
		{ NULL, NULL, 0 }
	};
	while (b + sizeof(TUN_PACKET) <= b_end) {
		if (nbl_queue[ethtypeidx_ipv4].count + nbl_queue[ethtypeidx_ipv6].count >= MAXLONG) {
			status = STATUS_INVALID_USER_BUFFER;
			goto cleanup_nbl_queues;
		}

		TUN_PACKET *p = (TUN_PACKET *)b;
		if (p->Size > TUN_EXCH_MAX_IP_PACKET_SIZE) {
			status = STATUS_INVALID_USER_BUFFER;
			goto cleanup_nbl_queues;
		}
		UINT p_size = TunPacketAlign(sizeof(TUN_PACKET) + p->Size);
		if (b + p_size > b_end) {
			status = STATUS_INVALID_USER_BUFFER;
			goto cleanup_nbl_queues;
		}

		ethtypeidx_t idx;
		if (p->Size >= 20 && p->Data[0] >> 4 == 4)
			idx = ethtypeidx_ipv4;
		else if (p->Size >= 40 && p->Data[0] >> 4 == 6)
			idx = ethtypeidx_ipv6;
		else {
			status = STATUS_INVALID_USER_BUFFER;
			goto cleanup_nbl_queues;
		}

		MDL *mdl = NdisAllocateMdl(ctx->MiniportAdapterHandle, p->Data, p->Size);
		if (!mdl) {
			status = STATUS_INSUFFICIENT_RESOURCES;
			goto cleanup_nbl_queues;
		}

		NET_BUFFER_LIST *nbl = NdisAllocateNetBufferAndNetBufferList(ctx->NBLPool, 0, 0, mdl, 0, p->Size);
		if (!nbl) {
			NdisFreeMdl(mdl);
			status = STATUS_INSUFFICIENT_RESOURCES;
			goto cleanup_nbl_queues;
		}

		nbl->SourceHandle = ctx->MiniportAdapterHandle;
		NdisSetNblFlag(nbl, ether_const[idx].nbl_flags);
		NET_BUFFER_LIST_INFO(nbl, NetBufferListFrameType) = (PVOID)ether_const[idx].nbl_proto;
		NET_BUFFER_LIST_STATUS(nbl) = NDIS_STATUS_SUCCESS;
		NET_BUFFER_LIST_IRP(nbl) = Irp;
		TunAppendNBL(&nbl_queue[idx].head, &nbl_queue[idx].tail, nbl);
		nbl_queue[idx].count++;
		b += p_size;
	}

	if ((ULONG)(b - buffer) != size) {
		status = STATUS_INVALID_USER_BUFFER;
		goto cleanup_nbl_queues;
	}
	Irp->IoStatus.Information = size;

	if (!nbl_queue[ethtypeidx_ipv4].head && !nbl_queue[ethtypeidx_ipv6].head) {
		status = STATUS_SUCCESS;
		goto cleanup_TunCompletePause;
	}

	InterlockedExchange(IRP_REFCOUNT(Irp), nbl_queue[ethtypeidx_ipv4].count + nbl_queue[ethtypeidx_ipv6].count);
	IoMarkIrpPending(Irp);

	if (nbl_queue[ethtypeidx_ipv4].head)
		NdisMIndicateReceiveNetBufferLists(ctx->MiniportAdapterHandle, nbl_queue[ethtypeidx_ipv4].head, NDIS_DEFAULT_PORT_NUMBER, nbl_queue[ethtypeidx_ipv4].count, NDIS_RECEIVE_FLAGS_SINGLE_ETHER_TYPE);
	if (nbl_queue[ethtypeidx_ipv6].head)
		NdisMIndicateReceiveNetBufferLists(ctx->MiniportAdapterHandle, nbl_queue[ethtypeidx_ipv6].head, NDIS_DEFAULT_PORT_NUMBER, nbl_queue[ethtypeidx_ipv6].count, NDIS_RECEIVE_FLAGS_SINGLE_ETHER_TYPE);
	ExReleaseSpinLockShared(&ctx->TransitionLock, irql);
	return STATUS_PENDING;

cleanup_nbl_queues:
	for (ethtypeidx_t idx = ethtypeidx_start; idx < ethtypeidx_end; idx++) {
		for (NET_BUFFER_LIST *nbl = nbl_queue[idx].head, *nbl_next; nbl; nbl = nbl_next) {
			nbl_next = NET_BUFFER_LIST_NEXT_NBL(nbl);
			NET_BUFFER_LIST_NEXT_NBL(nbl) = NULL;
			NdisFreeMdl(NET_BUFFER_FIRST_MDL(NET_BUFFER_LIST_FIRST_NB(nbl)));
			NdisFreeNetBufferList(nbl);
		}
	}
cleanup_TunCompletePause:
	TunCompletePause(ctx, TRUE);
	ExReleaseSpinLockShared(&ctx->TransitionLock, irql);
	TunCompleteRequest(ctx, Irp, status, IO_NO_INCREMENT);
	return status;
}

static MINIPORT_RETURN_NET_BUFFER_LISTS TunReturnNetBufferLists;
_Use_decl_annotations_
static void TunReturnNetBufferLists(NDIS_HANDLE MiniportAdapterContext, PNET_BUFFER_LIST NetBufferLists, ULONG ReturnFlags)
{
	TUN_CTX *ctx = (TUN_CTX *)MiniportAdapterContext;

	LONG64 stat_size = 0, stat_p_ok = 0, stat_p_err = 0;
	for (NET_BUFFER_LIST *nbl = NetBufferLists, *nbl_next; nbl; nbl = nbl_next) {
		nbl_next = NET_BUFFER_LIST_NEXT_NBL(nbl);
		NET_BUFFER_LIST_NEXT_NBL(nbl) = NULL;

		IRP *irp = NET_BUFFER_LIST_IRP(nbl);
		MDL *mdl = NET_BUFFER_FIRST_MDL(NET_BUFFER_LIST_FIRST_NB(nbl));
		if (NT_SUCCESS(NET_BUFFER_LIST_STATUS(nbl))) {
			ULONG p_size = MmGetMdlByteCount(mdl);
			stat_size += p_size;
			stat_p_ok++;
		} else
			stat_p_err++;

		NdisFreeMdl(mdl);
		NdisFreeNetBufferList(nbl);

		ASSERT(InterlockedGet(IRP_REFCOUNT(irp)) > 0);
		if (InterlockedDecrement(IRP_REFCOUNT(irp)) <= 0) {
			TunCompleteRequest(ctx, irp, STATUS_SUCCESS, IO_NETWORK_INCREMENT);
			TunCompletePause(ctx, TRUE);
		}
	}

	InterlockedAdd64((LONG64 *)&ctx->Statistics.ifHCInOctets, stat_size);
	InterlockedAdd64((LONG64 *)&ctx->Statistics.ifHCInUcastOctets, stat_size);
	InterlockedAdd64((LONG64 *)&ctx->Statistics.ifHCInUcastPkts, stat_p_ok);
	InterlockedAdd64((LONG64 *)&ctx->Statistics.ifInErrors, stat_p_err);
}

static DRIVER_DISPATCH TunDispatch;
_Use_decl_annotations_
static NTSTATUS TunDispatch(DEVICE_OBJECT *DeviceObject, IRP *Irp)
{
	NTSTATUS status;
	KIRQL irql;

	Irp->IoStatus.Information = 0;

	TUN_CTX *ctx = NdisGetDeviceReservedExtension(DeviceObject);
	if (!ctx) {
		status = STATUS_INVALID_HANDLE;
		goto cleanup_complete_req;
	}

	IO_STACK_LOCATION *stack = IoGetCurrentIrpStackLocation(Irp);
	switch (stack->MajorFunction) {
	case IRP_MJ_READ:
		if ((status = STATUS_FILE_FORCED_CLOSED, InterlockedGet((LONG *)&ctx->State) < TUN_STATE_PAUSED) ||
			!NT_SUCCESS(status = IoAcquireRemoveLock(&ctx->Device.RemoveLock, Irp)))
			goto cleanup_complete_req;

		if (!NT_SUCCESS(status = IoCsqInsertIrpEx(&ctx->Device.ReadQueue.Csq, Irp, NULL, TUN_CSQ_INSERT_TAIL)))
			goto cleanup_complete_req_and_release_remove_lock;

		TunQueueProcess(ctx);
		return STATUS_PENDING;

	case IRP_MJ_WRITE:
		if ((status = STATUS_FILE_FORCED_CLOSED, InterlockedGet((LONG *)&ctx->State) < TUN_STATE_PAUSED) ||
			!NT_SUCCESS(status = IoAcquireRemoveLock(&ctx->Device.RemoveLock, Irp)))
			goto cleanup_complete_req;

		return TunWriteFromIrp(ctx, Irp);

	case IRP_MJ_CREATE:
		if ((status = STATUS_DELETE_PENDING, InterlockedGet((LONG *)&ctx->State) < TUN_STATE_PAUSED) ||
			!NT_SUCCESS(status = IoAcquireRemoveLock(&ctx->Device.RemoveLock, Irp)))
			goto cleanup_complete_req;

		if (!NT_SUCCESS(status = IoAcquireRemoveLock(&ctx->Device.RemoveLock, stack->FileObject)))
			goto cleanup_complete_req_and_release_remove_lock;

		ASSERT(InterlockedGet64(&ctx->Device.RefCount) < MAXLONG64);
		if (InterlockedIncrement64(&ctx->Device.RefCount) > 0)
			TunIndicateStatus(ctx->MiniportAdapterHandle, MediaConnectStateConnected);

		status = STATUS_SUCCESS;
		goto cleanup_complete_req_and_release_remove_lock;

	case IRP_MJ_CLOSE:
		irql = ExAcquireSpinLockExclusive(&ctx->TransitionLock);
		ASSERT(InterlockedGet64(&ctx->Device.RefCount) > 0);
		BOOLEAN last_handle = InterlockedDecrement64(&ctx->Device.RefCount) <= 0;
		ExReleaseSpinLockExclusive(&ctx->TransitionLock, irql);
		if (last_handle) {
			if (ctx->MiniportAdapterHandle)
				TunIndicateStatus(ctx->MiniportAdapterHandle, MediaConnectStateDisconnected);
			TunQueueClear(ctx, NDIS_STATUS_SEND_ABORTED);
		}
		IoReleaseRemoveLock(&ctx->Device.RemoveLock, stack->FileObject);

		status = STATUS_SUCCESS;
		goto cleanup_complete_req;

	case IRP_MJ_CLEANUP:
		for (IRP *pending_irp; (pending_irp = IoCsqRemoveNextIrp(&ctx->Device.ReadQueue.Csq, stack->FileObject)) != NULL; )
			TunCompleteRequest(ctx, pending_irp, STATUS_CANCELLED, IO_NO_INCREMENT);

		status = STATUS_SUCCESS;
		goto cleanup_complete_req;

	default:
		status = STATUS_INVALID_PARAMETER;
		goto cleanup_complete_req;
	}

cleanup_complete_req_and_release_remove_lock:
	TunCompleteRequest(ctx, Irp, status, IO_NO_INCREMENT);
	return status;

cleanup_complete_req:
	Irp->IoStatus.Status = status;
	IoCompleteRequest(Irp, IO_NO_INCREMENT);
	return status;
}

static MINIPORT_RESTART TunRestart;
_Use_decl_annotations_
static NDIS_STATUS TunRestart(NDIS_HANDLE MiniportAdapterContext, PNDIS_MINIPORT_RESTART_PARAMETERS MiniportRestartParameters)
{
	TUN_CTX *ctx = (TUN_CTX *)MiniportAdapterContext;

	InterlockedExchange((LONG *)&ctx->State, TUN_STATE_RESTARTING);
	InterlockedExchange64(&ctx->ActiveTransactionCount, 1);
	InterlockedExchange((LONG *)&ctx->State, TUN_STATE_RUNNING);

	return NDIS_STATUS_SUCCESS;
}

static MINIPORT_PAUSE TunPause;
_Use_decl_annotations_
static NDIS_STATUS TunPause(NDIS_HANDLE MiniportAdapterContext, PNDIS_MINIPORT_PAUSE_PARAMETERS MiniportPauseParameters)
{
	TUN_CTX *ctx = (TUN_CTX *)MiniportAdapterContext;

	KIRQL irql = ExAcquireSpinLockExclusive(&ctx->TransitionLock);
	InterlockedExchange((LONG *)&ctx->State, TUN_STATE_PAUSING);
	ExReleaseSpinLockExclusive(&ctx->TransitionLock, irql);
	TunQueueClear(ctx, STATUS_NDIS_PAUSED);

	return TunCompletePause(ctx, FALSE);
}

static MINIPORT_DEVICE_PNP_EVENT_NOTIFY TunDevicePnPEventNotify;
_Use_decl_annotations_
static void TunDevicePnPEventNotify(NDIS_HANDLE MiniportAdapterContext, PNET_DEVICE_PNP_EVENT NetDevicePnPEvent)
{
}

static DRIVER_NOTIFICATION_CALLBACK_ROUTINE TunPnPNotifyDeviceChange;
_Use_decl_annotations_
static NTSTATUS TunPnPNotifyDeviceChange(PVOID NotificationStruct, PVOID Context)
{
	TARGET_DEVICE_REMOVAL_NOTIFICATION *notification = NotificationStruct;
	TUN_CTX *ctx = Context;

	if (!ctx)
		return STATUS_SUCCESS;

	if (IsEqualGUID(&notification->Event, &GUID_TARGET_DEVICE_QUERY_REMOVE)) {
		KIRQL irql = ExAcquireSpinLockExclusive(&ctx->TransitionLock);
		InterlockedExchange((LONG *)&ctx->State, TUN_STATE_PAUSING);
		ExReleaseSpinLockExclusive(&ctx->TransitionLock, irql);
		/* The entire purpose of this PnP notification infrastructure is so that we can get here.
		 * The idea is that if there are un-returned NBLs, TunPause&TunHalt will never be called.
		 * So we clear them here after setting the paused state, which then frees up NDIS to do
		 * the right thing later on in the shutdown procedure. */
		TunQueueClear(ctx, STATUS_NDIS_REQUEST_ABORTED);
		FILE_OBJECT *file = ctx->PnPNotifications.FileObject;
		ctx->PnPNotifications.FileObject = NULL;
		if (file)
			ObDereferenceObject(file);
	} else if (IsEqualGUID(&notification->Event, &GUID_TARGET_DEVICE_REMOVE_COMPLETE) ||
		IsEqualGUID(&notification->Event, &GUID_TARGET_DEVICE_REMOVE_CANCELLED)) {
		PVOID handle = ctx->PnPNotifications.Handle;
		/* We unregister in the cancelled case too, because the initial remove request puts us
		 * in pausing state, so we won't pile up any further NBLs. */
		ctx->PnPNotifications.Handle = NULL;
		if (handle)
			IoUnregisterPlugPlayNotificationEx(handle);
	}

	return STATUS_SUCCESS;
}

static DRIVER_NOTIFICATION_CALLBACK_ROUTINE TunPnPNotifyInterfaceChange;
_Use_decl_annotations_
static NTSTATUS TunPnPNotifyInterfaceChange(PVOID NotificationStruct, PVOID Context)
{
	DEVICE_INTERFACE_CHANGE_NOTIFICATION *notification = NotificationStruct;
	DRIVER_OBJECT *driver_object = (DRIVER_OBJECT *)Context;
	DEVICE_OBJECT *device_object;
	FILE_OBJECT *file_object;
	TUN_CTX *ctx;

	_Analysis_assume_(driver_object);

	if (!IsEqualGUID(&notification->InterfaceClassGuid, &GUID_DEVINTERFACE_NET) ||
		!IsEqualGUID(&notification->Event, &GUID_DEVICE_INTERFACE_ARRIVAL))
		return STATUS_SUCCESS;

	if (!NT_SUCCESS(IoGetDeviceObjectPointer(notification->SymbolicLinkName,
		STANDARD_RIGHTS_ALL, &file_object, &device_object)))
		return STATUS_SUCCESS;
	if (device_object->DriverObject != driver_object) {
		ObDereferenceObject(file_object);
		return STATUS_SUCCESS;
	}
	#pragma warning(suppress: 28175)
	ctx = device_object->Reserved;

	ASSERT(!ctx->PnPNotifications.FileObject);
	ctx->PnPNotifications.FileObject = file_object;
	ASSERT(!ctx->PnPNotifications.Handle);
	#pragma warning(suppress: 6014) /* Leaking memory 'ctx->PnPNotifications.Handle'. Note: 'ctx->PnPNotifications.Handle' is unregistered in TunPnPNotifyDeviceChange(GUID_TARGET_DEVICE_REMOVE_COMPLETE/GUID_TARGET_DEVICE_REMOVE_CANCELLED); or on failure. */
	if (!NT_SUCCESS(IoRegisterPlugPlayNotification(EventCategoryTargetDeviceChange, 0,
		ctx->PnPNotifications.FileObject, driver_object, TunPnPNotifyDeviceChange,
		ctx, (PVOID *)&ctx->PnPNotifications.Handle))) {
		ctx->PnPNotifications.FileObject = NULL;
		ObDereferenceObject(file_object);
	}
	return STATUS_SUCCESS;
}

static MINIPORT_INITIALIZE TunInitializeEx;
_Use_decl_annotations_
static NDIS_STATUS TunInitializeEx(NDIS_HANDLE MiniportAdapterHandle, NDIS_HANDLE MiniportDriverContext, PNDIS_MINIPORT_INIT_PARAMETERS MiniportInitParameters)
{
	NDIS_STATUS status;

	if (!MiniportAdapterHandle)
		return NDIS_STATUS_FAILURE;

	/* Register device first.
	 * Having only one device per adapter allows us to store adapter context inside device extension. */
	WCHAR device_name[sizeof(L"\\Device\\" TUN_DEVICE_NAME) / sizeof(WCHAR) + 10/*MAXULONG as string*/] = { 0 };
	UNICODE_STRING unicode_device_name;
	TunInitUnicodeString(&unicode_device_name, device_name);
	RtlUnicodeStringPrintf(&unicode_device_name, L"\\Device\\" TUN_DEVICE_NAME, (ULONG)MiniportInitParameters->NetLuid.Info.NetLuidIndex);

	WCHAR symbolic_name[sizeof(L"\\DosDevices\\" TUN_DEVICE_NAME) / sizeof(WCHAR) + 10/*MAXULONG as string*/] = { 0 };
	UNICODE_STRING unicode_symbolic_name;
	TunInitUnicodeString(&unicode_symbolic_name, symbolic_name);
	RtlUnicodeStringPrintf(&unicode_symbolic_name, L"\\DosDevices\\" TUN_DEVICE_NAME, (ULONG)MiniportInitParameters->NetLuid.Info.NetLuidIndex);

	static PDRIVER_DISPATCH dispatch_table[IRP_MJ_MAXIMUM_FUNCTION + 1] = {
		TunDispatch,    /* IRP_MJ_CREATE                   */
		NULL,           /* IRP_MJ_CREATE_NAMED_PIPE        */
		TunDispatch,    /* IRP_MJ_CLOSE                    */
		TunDispatch,    /* IRP_MJ_READ                     */
		TunDispatch,    /* IRP_MJ_WRITE                    */
		NULL,           /* IRP_MJ_QUERY_INFORMATION        */
		NULL,           /* IRP_MJ_SET_INFORMATION          */
		NULL,           /* IRP_MJ_QUERY_EA                 */
		NULL,           /* IRP_MJ_SET_EA                   */
		NULL,           /* IRP_MJ_FLUSH_BUFFERS            */
		NULL,           /* IRP_MJ_QUERY_VOLUME_INFORMATION */
		NULL,           /* IRP_MJ_SET_VOLUME_INFORMATION   */
		NULL,           /* IRP_MJ_DIRECTORY_CONTROL        */
		NULL,           /* IRP_MJ_FILE_SYSTEM_CONTROL      */
		NULL,           /* IRP_MJ_DEVICE_CONTROL           */
		NULL,           /* IRP_MJ_INTERNAL_DEVICE_CONTROL  */
		NULL,           /* IRP_MJ_SHUTDOWN                 */
		NULL,           /* IRP_MJ_LOCK_CONTROL             */
		TunDispatch,    /* IRP_MJ_CLEANUP                  */
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
		.ExtensionSize     = sizeof(TUN_CTX),
		.DefaultSDDLString = &SDDL_DEVOBJ_SYS_ALL /* Kernel, and SYSTEM: full control. Others: none */
	};
	NDIS_HANDLE handle;
	DEVICE_OBJECT *object;
	if (!NT_SUCCESS(status = NdisRegisterDeviceEx(NdisMiniportDriverHandle, &t, &object, &handle)))
		return NDIS_STATUS_FAILURE;

	object->Flags &= ~DO_BUFFERED_IO;
	object->Flags |=  DO_DIRECT_IO;

	TUN_CTX *ctx = NdisGetDeviceReservedExtension(object);
	if (!ctx) {
		status = NDIS_STATUS_FAILURE;
		goto cleanup_NdisDeregisterDeviceEx;
	}

	DEVICE_OBJECT *functional_device;
	NdisMGetDeviceProperty(MiniportAdapterHandle, NULL, &functional_device, NULL, NULL, NULL);

	#pragma warning(suppress: 28175)
	ASSERT(!functional_device->Reserved);
	#pragma warning(suppress: 28175)
	functional_device->Reserved = ctx;

	NdisZeroMemory(ctx, sizeof(*ctx));
	InterlockedExchange((LONG *)&ctx->State,      TUN_STATE_INITIALIZING);
	InterlockedExchange((LONG *)&ctx->PowerState, NdisDeviceStateD0);
	ctx->MiniportAdapterHandle = MiniportAdapterHandle;
	ctx->NetLuidIndex = (ULONG)MiniportInitParameters->NetLuid.Info.NetLuidIndex;

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

	ctx->Device.Handle = handle;
	ctx->Device.Object = object;
	IoInitializeRemoveLock(&ctx->Device.RemoveLock, TUN_HTONL(TUN_MEMORY_TAG), 0, 0);
	KeInitializeSpinLock(&ctx->Device.ReadQueue.Lock);
	IoCsqInitializeEx(&ctx->Device.ReadQueue.Csq,
		TunCsqInsertIrpEx,
		TunCsqRemoveIrp,
		TunCsqPeekNextIrp,
		TunCsqAcquireLock,
		TunCsqReleaseLock,
		TunCsqCompleteCanceledIrp);
	InitializeListHead(&ctx->Device.ReadQueue.List);

	KeInitializeSpinLock(&ctx->PacketQueue.Lock);

	NET_BUFFER_LIST_POOL_PARAMETERS nbl_pool_param = {
		.Header = {
			.Type       = NDIS_OBJECT_TYPE_DEFAULT,
			.Revision   = NET_BUFFER_LIST_POOL_PARAMETERS_REVISION_1,
			.Size       = NDIS_SIZEOF_NET_BUFFER_LIST_POOL_PARAMETERS_REVISION_1
		},
		.ProtocolId         = NDIS_PROTOCOL_ID_DEFAULT,
		.fAllocateNetBuffer = TRUE,
		.PoolTag            = TUN_HTONL(TUN_MEMORY_TAG)
	};
	#pragma warning(suppress: 6014) /* Leaking memory 'ctx->NBLPool'. Note: 'ctx->NBLPool' is freed in TunHaltEx; or on failure. */
	ctx->NBLPool = NdisAllocateNetBufferListPool(MiniportAdapterHandle, &nbl_pool_param);
	if (!ctx->NBLPool) {
		status = NDIS_STATUS_FAILURE;
		goto cleanup_NdisDeregisterDeviceEx;
	}

	NDIS_MINIPORT_ADAPTER_REGISTRATION_ATTRIBUTES attr = {
		.Header = {
			.Type           = NDIS_OBJECT_TYPE_MINIPORT_ADAPTER_REGISTRATION_ATTRIBUTES,
			.Revision       = NdisVersion < NDIS_RUNTIME_VERSION_630 ? NDIS_MINIPORT_ADAPTER_REGISTRATION_ATTRIBUTES_REVISION_1        : NDIS_MINIPORT_ADAPTER_REGISTRATION_ATTRIBUTES_REVISION_2,
			.Size           = NdisVersion < NDIS_RUNTIME_VERSION_630 ? NDIS_SIZEOF_MINIPORT_ADAPTER_REGISTRATION_ATTRIBUTES_REVISION_1 : NDIS_SIZEOF_MINIPORT_ADAPTER_REGISTRATION_ATTRIBUTES_REVISION_2
		},
		.AttributeFlags         = NDIS_MINIPORT_ATTRIBUTES_NO_HALT_ON_SUSPEND,
		.InterfaceType          = NdisInterfaceInternal,
		.MiniportAdapterContext = ctx
	};
	if (!NT_SUCCESS(status = NdisMSetMiniportAttributes(MiniportAdapterHandle, (PNDIS_MINIPORT_ADAPTER_ATTRIBUTES)&attr))) {
		status = NDIS_STATUS_FAILURE;
		goto cleanup_NdisFreeNetBufferListPool;
	}

	NDIS_PM_CAPABILITIES pmcap = {
		.Header = {
			.Type         = NDIS_OBJECT_TYPE_DEFAULT,
			.Revision     = NdisVersion < NDIS_RUNTIME_VERSION_630 ? NDIS_PM_CAPABILITIES_REVISION_1             : NDIS_PM_CAPABILITIES_REVISION_2,
			.Size         = NdisVersion < NDIS_RUNTIME_VERSION_630 ? NDIS_SIZEOF_NDIS_PM_CAPABILITIES_REVISION_1 : NDIS_SIZEOF_NDIS_PM_CAPABILITIES_REVISION_2
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
	if (!NT_SUCCESS(status = NdisMSetMiniportAttributes(MiniportAdapterHandle, (PNDIS_MINIPORT_ADAPTER_ATTRIBUTES)&gen))) {
		status = NDIS_STATUS_FAILURE;
		goto cleanup_NdisFreeNetBufferListPool;
	}

	/* A miniport driver can call NdisMIndicateStatusEx after setting its
	 * registration attributes even if the driver is still in the context
	 * of the MiniportInitializeEx function.
	 */
	TunIndicateStatus(MiniportAdapterHandle, MediaConnectStateDisconnected);
	ASSERT(InterlockedGet64(&AdapterCount) < MAXLONG64);
	InterlockedIncrement64(&AdapterCount);
	InterlockedExchange((LONG *)&ctx->State, TUN_STATE_PAUSED);
	return NDIS_STATUS_SUCCESS;

cleanup_NdisFreeNetBufferListPool:
	NdisFreeNetBufferListPool(ctx->NBLPool);
cleanup_NdisDeregisterDeviceEx:
	NdisDeregisterDeviceEx(handle);
	return status;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
static void TunForceHandlesClosed(_Inout_ TUN_CTX *ctx)
{
	NTSTATUS status;
	PEPROCESS process;
	KAPC_STATE apc_state;
	PVOID object;
	OBJECT_HANDLE_INFORMATION handle_info;
	SYSTEM_HANDLE_INFORMATION_EX *table = NULL;

	for (ULONG size = 0, req; (status = ZwQuerySystemInformation(SystemExtendedHandleInformation, table, size, &req)) == STATUS_INFO_LENGTH_MISMATCH; size = req) {
		if (table)
			ExFreePoolWithTag(table, TUN_HTONL(TUN_MEMORY_TAG));
		table = ExAllocatePoolWithTag(PagedPool, req, TUN_HTONL(TUN_MEMORY_TAG));
		if (!table)
			return;
	}
	if (!NT_SUCCESS(status) || !table)
		goto out;

	for (ULONG_PTR i = 0; i < table->NumberOfHandles; ++i) {
		FILE_OBJECT *file = table->Handles[i].Object; //XXX: We should probably first look at table->Handles[i].ObjectTypeIndex, but the value changes lots between NT versions.
		if (!file || file->Type != 5 || file->DeviceObject != ctx->Device.Object)
			continue;
		status = PsLookupProcessByProcessId(table->Handles[i].UniqueProcessId, &process);
		if (!NT_SUCCESS(status))
			continue;
		KeStackAttachProcess(process, &apc_state);
		status = ObReferenceObjectByHandle(table->Handles[i].HandleValue, 0, NULL, UserMode, &object, &handle_info);
		if (NT_SUCCESS(status)) {
			if (object == file)
				ObCloseHandle(table->Handles[i].HandleValue, UserMode);
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
static void TunWaitForReferencesToDropToZero(_In_ DEVICE_OBJECT *device_object)
{
	/* The sleep loop isn't pretty, but we don't have a choice. This is an NDIS bug we're working around. */
	enum { SleepTime = 50, TotalTime = 2 * 60 * 1000, MaxTries = TotalTime / SleepTime };
	#pragma warning(suppress: 28175)
	for (int i = 0; i < MaxTries && device_object->ReferenceCount; ++i)
		NdisMSleep(SleepTime);
}

static MINIPORT_HALT TunHaltEx;
_Use_decl_annotations_
static void TunHaltEx(NDIS_HANDLE MiniportAdapterContext, NDIS_HALT_ACTION HaltAction)
{
	TUN_CTX *ctx = (TUN_CTX *)MiniportAdapterContext;

	ASSERT(!InterlockedGet64(&ctx->ActiveTransactionCount)); /* Adapter should not be halted if it wasn't fully paused first. */

	InterlockedExchange((LONG *)&ctx->State, TUN_STATE_HALTING);

	if (ctx->PnPNotifications.Handle) {
		PVOID h = ctx->PnPNotifications.Handle;
		ctx->PnPNotifications.Handle = NULL;
		IoUnregisterPlugPlayNotificationEx(h);
	}
	if (ctx->PnPNotifications.FileObject) {
		FILE_OBJECT *fo = ctx->PnPNotifications.FileObject;
		ctx->PnPNotifications.FileObject = NULL;
		ObDereferenceObject(fo);
	}

	for (IRP *pending_irp; (pending_irp = IoCsqRemoveNextIrp(&ctx->Device.ReadQueue.Csq, NULL)) != NULL;)
		TunCompleteRequest(ctx, pending_irp, STATUS_FILE_FORCED_CLOSED, IO_NO_INCREMENT);

	/* It's a bit annoying to reconstruct this here, but it's better than storing it, and
	 * although we could just get it from ndishandle+288, that's probably a bit dirty. */
	WCHAR symbolic_name[sizeof(L"\\DosDevices\\" TUN_DEVICE_NAME) / sizeof(WCHAR) + 10/*MAXULONG as string*/] = { 0 };
	UNICODE_STRING unicode_symbolic_name;
	TunInitUnicodeString(&unicode_symbolic_name, symbolic_name);
	RtlUnicodeStringPrintf(&unicode_symbolic_name, L"\\DosDevices\\" TUN_DEVICE_NAME, ctx->NetLuidIndex);
	/* We first get rid of the symbolic link, to prevent userspace from accidently reopening
	 * this while we're waiting for the refcount to drop to zero. It might still be possible to
	 * open it from the real path, in which case, maybe we should consider setting a deny-all DACL. */
	IoDeleteSymbolicLink(&unicode_symbolic_name);

	if (InterlockedGet64(&ctx->Device.RefCount))
		TunForceHandlesClosed(ctx);

	/* Wait for processing IRP(s) to complete. */
	IoAcquireRemoveLock(&ctx->Device.RemoveLock, NULL);
	IoReleaseRemoveLockAndWait(&ctx->Device.RemoveLock, NULL);
	NdisFreeNetBufferListPool(ctx->NBLPool);

	/* MiniportAdapterHandle must not be used in TunDispatch(). After TunHaltEx() returns it is invalidated. */
	ctx->MiniportAdapterHandle = NULL;

	InterlockedExchange((LONG *)&ctx->PowerState, NdisDeviceStateUnspecified);
	InterlockedExchange((LONG *)&ctx->State, TUN_STATE_HALTED);

	ASSERT(InterlockedGet64(&AdapterCount) > 0);
	if (InterlockedDecrement64(&AdapterCount) <= 0)
		TunWaitForReferencesToDropToZero(ctx->Device.Object);

	/* Deregister device _after_ we are done using ctx not to risk an UaF. The ctx is hosted by device extension. */
	NdisDeregisterDeviceEx(ctx->Device.Handle);
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

_IRQL_requires_max_(APC_LEVEL)
_Must_inspect_result_
static NDIS_STATUS TunOidQueryWrite(_Inout_ NDIS_OID_REQUEST *OidRequest, _In_ ULONG value)
{
	if (OidRequest->DATA.QUERY_INFORMATION.InformationBufferLength < sizeof(ULONG)) {
		OidRequest->DATA.QUERY_INFORMATION.BytesNeeded  = sizeof(ULONG);
		OidRequest->DATA.QUERY_INFORMATION.BytesWritten = 0;
		return NDIS_STATUS_BUFFER_TOO_SHORT;
	}

	OidRequest->DATA.QUERY_INFORMATION.BytesNeeded  =
	OidRequest->DATA.QUERY_INFORMATION.BytesWritten = sizeof(ULONG);
	*(ULONG *)OidRequest->DATA.QUERY_INFORMATION.InformationBuffer = value;
	return NDIS_STATUS_SUCCESS;
}

_IRQL_requires_max_(APC_LEVEL)
_Must_inspect_result_
static NDIS_STATUS TunOidQueryWrite32or64(_Inout_ NDIS_OID_REQUEST *OidRequest, _In_ ULONG64 value)
{
	if (OidRequest->DATA.QUERY_INFORMATION.InformationBufferLength < sizeof(ULONG)) {
		OidRequest->DATA.QUERY_INFORMATION.BytesNeeded  = sizeof(ULONG64);
		OidRequest->DATA.QUERY_INFORMATION.BytesWritten = 0;
		return NDIS_STATUS_BUFFER_TOO_SHORT;
	}

	if (OidRequest->DATA.QUERY_INFORMATION.InformationBufferLength < sizeof(ULONG64)) {
		OidRequest->DATA.QUERY_INFORMATION.BytesNeeded  = sizeof(ULONG64);
		OidRequest->DATA.QUERY_INFORMATION.BytesWritten = sizeof(ULONG);
		*(ULONG *)OidRequest->DATA.QUERY_INFORMATION.InformationBuffer = (ULONG)(value & 0xffffffff);
		return NDIS_STATUS_SUCCESS;
	}

	OidRequest->DATA.QUERY_INFORMATION.BytesNeeded  =
	OidRequest->DATA.QUERY_INFORMATION.BytesWritten = sizeof(ULONG64);
	*(ULONG64 *)OidRequest->DATA.QUERY_INFORMATION.InformationBuffer = value;
	return NDIS_STATUS_SUCCESS;
}

_IRQL_requires_max_(APC_LEVEL)
_Must_inspect_result_
static NDIS_STATUS TunOidQueryWriteBuf(_Inout_ NDIS_OID_REQUEST *OidRequest, _In_bytecount_(size) const void *buf, _In_ UINT size)
{
	if (OidRequest->DATA.QUERY_INFORMATION.InformationBufferLength < size) {
		OidRequest->DATA.QUERY_INFORMATION.BytesNeeded  = size;
		OidRequest->DATA.QUERY_INFORMATION.BytesWritten = 0;
		return NDIS_STATUS_BUFFER_TOO_SHORT;
	}

	OidRequest->DATA.QUERY_INFORMATION.BytesNeeded  =
	OidRequest->DATA.QUERY_INFORMATION.BytesWritten = size;
	NdisMoveMemory(OidRequest->DATA.QUERY_INFORMATION.InformationBuffer, buf, size);
	return NDIS_STATUS_SUCCESS;
}

_IRQL_requires_max_(APC_LEVEL)
_Must_inspect_result_
static NDIS_STATUS TunOidQuery(_Inout_ TUN_CTX *ctx, _Inout_ NDIS_OID_REQUEST *OidRequest)
{
	ASSERT(OidRequest->RequestType == NdisRequestQueryInformation || OidRequest->RequestType == NdisRequestQueryStatistics);

	switch (OidRequest->DATA.QUERY_INFORMATION.Oid) {
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
		return TunOidQueryWrite32or64(OidRequest,
			InterlockedGet64((LONG64 *)&ctx->Statistics.ifHCOutUcastPkts    ) +
			InterlockedGet64((LONG64 *)&ctx->Statistics.ifHCOutMulticastPkts) +
			InterlockedGet64((LONG64 *)&ctx->Statistics.ifHCOutBroadcastPkts));

	case OID_GEN_RCV_OK:
		return TunOidQueryWrite32or64(OidRequest,
			InterlockedGet64((LONG64 *)&ctx->Statistics.ifHCInUcastPkts    ) +
			InterlockedGet64((LONG64 *)&ctx->Statistics.ifHCInMulticastPkts) +
			InterlockedGet64((LONG64 *)&ctx->Statistics.ifHCInBroadcastPkts));

	case OID_GEN_STATISTICS:
		return TunOidQueryWriteBuf(OidRequest, &ctx->Statistics, (UINT)sizeof(ctx->Statistics));

	case OID_GEN_INTERRUPT_MODERATION: {
		static const NDIS_INTERRUPT_MODERATION_PARAMETERS intp = {
			.Header = {
				.Type         = NDIS_OBJECT_TYPE_DEFAULT,
				.Revision     = NDIS_INTERRUPT_MODERATION_PARAMETERS_REVISION_1,
				.Size         = NDIS_SIZEOF_INTERRUPT_MODERATION_PARAMETERS_REVISION_1
			},
			.InterruptModeration = NdisInterruptModerationNotSupported
		};
		return TunOidQueryWriteBuf(OidRequest, &intp, (UINT)sizeof(intp));
	}

	case OID_PNP_QUERY_POWER:
		OidRequest->DATA.QUERY_INFORMATION.BytesNeeded  =
		OidRequest->DATA.QUERY_INFORMATION.BytesWritten = 0;
		return NDIS_STATUS_SUCCESS;
	}

	OidRequest->DATA.QUERY_INFORMATION.BytesWritten = 0;
	return NDIS_STATUS_NOT_SUPPORTED;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
static NDIS_STATUS TunOidSet(_Inout_ TUN_CTX *ctx, _Inout_ NDIS_OID_REQUEST *OidRequest)
{
	ASSERT(OidRequest->RequestType == NdisRequestSetInformation);

	OidRequest->DATA.SET_INFORMATION.BytesNeeded = OidRequest->DATA.SET_INFORMATION.BytesRead = 0;

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

		NDIS_DEVICE_POWER_STATE state = *(NDIS_DEVICE_POWER_STATE *)OidRequest->DATA.SET_INFORMATION.InformationBuffer;
		KIRQL irql = ExAcquireSpinLockExclusive(&ctx->TransitionLock);
		InterlockedExchange((LONG *)&ctx->PowerState, state);
		ExReleaseSpinLockExclusive(&ctx->TransitionLock, irql);
		if (state >= NdisDeviceStateD1)
			TunQueueClear(ctx, STATUS_NDIS_LOW_POWER_STATE);

		return NDIS_STATUS_SUCCESS;
	}

	return NDIS_STATUS_NOT_SUPPORTED;
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
		return NDIS_STATUS_INVALID_OID;
	}
}

static MINIPORT_CANCEL_OID_REQUEST TunCancelOidRequest;
_Use_decl_annotations_
static void TunCancelOidRequest(NDIS_HANDLE MiniportAdapterContext, PVOID RequestId)
{
}

static MINIPORT_DIRECT_OID_REQUEST TunDirectOidRequest;
_Use_decl_annotations_
static NDIS_STATUS TunDirectOidRequest(NDIS_HANDLE MiniportAdapterContext, PNDIS_OID_REQUEST OidRequest)
{
	switch (OidRequest->RequestType) {
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
static void TunCancelDirectOidRequest(NDIS_HANDLE MiniportAdapterContext, PVOID RequestId)
{
}

static MINIPORT_UNLOAD TunUnload;
_Use_decl_annotations_
static VOID TunUnload(PDRIVER_OBJECT DriverObject)
{
	IoUnregisterPlugPlayNotificationEx(TunNotifyInterfaceChangeHandle);
	NdisMDeregisterMiniportDriver(NdisMiniportDriverHandle);
}

DRIVER_INITIALIZE DriverEntry;
_Use_decl_annotations_
NTSTATUS DriverEntry(DRIVER_OBJECT *DriverObject, UNICODE_STRING *RegistryPath)
{
	NTSTATUS status;

	NdisVersion = NdisGetVersion();
	if (NdisVersion < NDIS_RUNTIME_VERSION_620)
		return NDIS_STATUS_UNSUPPORTED_REVISION;
	if (NdisVersion > NDIS_RUNTIME_VERSION_630)
		NdisVersion = NDIS_RUNTIME_VERSION_630;

	if (!NT_SUCCESS(status = IoRegisterPlugPlayNotification(EventCategoryDeviceInterfaceChange, 0,
		(PVOID)&GUID_DEVINTERFACE_NET, DriverObject, TunPnPNotifyInterfaceChange, DriverObject,
		&TunNotifyInterfaceChangeHandle)))
		return status;

	NDIS_MINIPORT_DRIVER_CHARACTERISTICS miniport = {
		.Header = {
			.Type                  = NDIS_OBJECT_TYPE_MINIPORT_DRIVER_CHARACTERISTICS,
			.Revision              = NDIS_MINIPORT_DRIVER_CHARACTERISTICS_REVISION_2,
			.Size                  = NDIS_SIZEOF_MINIPORT_DRIVER_CHARACTERISTICS_REVISION_2
		},

		.MajorNdisVersion              = (UCHAR)((NdisVersion & 0x00ff0000) >> 16),
		.MinorNdisVersion              = (UCHAR) (NdisVersion & 0x000000ff),

		.MajorDriverVersion            = WINTUN_VERSION_MAJ,
		.MinorDriverVersion            = WINTUN_VERSION_MIN,

		.InitializeHandlerEx           = TunInitializeEx,
		.HaltHandlerEx                 = TunHaltEx,
		.UnloadHandler                 = TunUnload,
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
	if (!NT_SUCCESS(status = NdisMRegisterMiniportDriver(DriverObject, RegistryPath, NULL, &miniport, &NdisMiniportDriverHandle))) {
		IoUnregisterPlugPlayNotificationEx(TunNotifyInterfaceChangeHandle);
		return status;
	}
	return STATUS_SUCCESS;
}

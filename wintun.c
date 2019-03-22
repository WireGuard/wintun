/* SPDX-License-Identifier: GPL-2.0
 *
 * Copyright (C) 2018-2019 WireGuard LLC. All Rights Reserved.
 */

#define NDIS_MINIPORT_DRIVER
#define NDIS620_MINIPORT
#define NDIS_SUPPORT_NDIS620	1
#define NDIS_WDM		1

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

#define TUN_DEVICE_NAME		L"WINTUN%u"

#define TUN_VENDOR_NAME		"Wintun Tunnel"
#define TUN_VENDOR_ID		0xFFFFFF00
#define TUN_LINK_SPEED 		100000000000ULL // 100gbps

#define TUN_EXCH_MAX_PACKETS		256	// Maximum number of exchange packets that can be exchanged in a single read/write
#define TUN_EXCH_MAX_PACKET_SIZE	0xF000	// Maximum exchange packet size - empirically determined by net buffer list (pool) limitations
#define TUN_EXCH_ALIGNMENT		16	// Memory alignment in exchange buffers
#define TUN_EXCH_MAX_IP_PACKET_SIZE	(TUN_EXCH_MAX_PACKET_SIZE - sizeof(TUN_PACKET))		// Maximum IP packet size (headers + payload)
#define TUN_EXCH_MAX_BUFFER_SIZE	(TUN_EXCH_MAX_PACKETS * TUN_EXCH_MAX_PACKET_SIZE)	// Maximum size of read/write exchange buffer
#define TUN_QUEUE_MAX_NBLS		4096

typedef struct _TUN_PACKET {
	ULONG	Size;			// Size of packet data (TUN_EXCH_MAX_IP_PACKET_SIZE max)
	_Field_size_bytes_(Size)
	__declspec(align(TUN_EXCH_ALIGNMENT))
	UCHAR	Data[];			// Packet data
} TUN_PACKET;

typedef struct _TUN_EVENT {
	KEVENT	*Event;
	HANDLE	Handle;
} TUN_EVENT;

typedef struct _TUN_NBL_POOL {
	NDIS_HANDLE	Handle;
	NET_BUFFER_LIST	*List;
} TUN_NBL_POOL;

typedef enum _TUN_STATE {
	TUN_STATE_HALTED = 0,		// The Halted state is the initial state of all adapters. When an adapter is in the Halted state, NDIS can call the driver's MiniportInitializeEx function to initialize the adapter.
	TUN_STATE_SHUTDOWN,		// In the Shutdown state, a system shutdown and restart must occur before the system can use the adapter again
	TUN_STATE_INITIALIZING,		// In the Initializing state, a miniport driver completes any operations that are required to initialize an adapter.
	TUN_STATE_PAUSED,		// In the Paused state, the adapter does not indicate received network data or accept send requests.
	TUN_STATE_RESTARTING,		// In the Restarting state, a miniport driver completes any operations that are required to restart send and receive operations for an adapter.
	TUN_STATE_RUNNING,		// In the Running state, a miniport driver performs send and receive processing for an adapter.
	TUN_STATE_PAUSING,		// In the Pausing state, a miniport driver completes any operations that are required to stop send and receive operations for an adapter.
} TUN_STATE;

typedef struct _TUN_CTX {
	volatile TUN_STATE	State;

	volatile NDIS_DEVICE_POWER_STATE PowerState;

	NDIS_HANDLE		MiniportAdapterHandle;
	NDIS_STATISTICS_INFO	Statistics;

	volatile LONG64		ActiveNBLCount;

	struct {
		NDIS_HANDLE	Handle;
		DEVICE_OBJECT	*Object;
		volatile LONG64	RefCount;
		IRP volatile	*ActiveIrp;
	} Device;

	struct {
		NDIS_SPIN_LOCK	Lock;
		NET_BUFFER_LIST	*Head, *Tail;
		NET_BUFFER	*Buffer;
		UINT		Count;
	} PacketQueue;

	NDIS_HANDLE NBLPool;
} TUN_CTX;

static NDIS_HANDLE NdisMiniportDriverHandle = NULL;

#if REG_DWORD == REG_DWORD_BIG_ENDIAN
#define TUN_MEMORY_TAG	'wtun'
#define TunHtons(x)	((USHORT)(x))
#define TunHtonl(x)	((ULONG)(x))
#elif REG_DWORD == REG_DWORD_LITTLE_ENDIAN
#define TUN_MEMORY_TAG	'nutw'
#define TunHtons(x)	RtlUshortByteSwap(x)
#define TunHtonl(x)	RtlUlongByteSwap(x)
#else
#error "Unable to determine endianess"
#endif

#define InterlockedGet(val)		(InterlockedAdd((val), 0))
#define InterlockedGet64(val)		(InterlockedAdd64((val), 0))
#define InterlockedSubtract64(val, n)	(InterlockedAdd64((val), -(LONG64)(n)))
#define TunPacketAlign(size)		(((UINT)(size) + (UINT)(TUN_EXCH_ALIGNMENT - 1)) & ~(UINT)(TUN_EXCH_ALIGNMENT - 1))
#define TunInitUnicodeString(str, buf)	{ (str)->Length = 0; (str)->MaximumLength = sizeof(buf); (str)->Buffer = buf; }

_IRQL_requires_same_
static void TunAppendNBL(_Inout_ NET_BUFFER_LIST **head, _Inout_ NET_BUFFER_LIST **tail, __drv_aliasesMem _In_ NET_BUFFER_LIST *nbl)
{
	*(*tail ? &NET_BUFFER_LIST_NEXT_NBL(*tail) : head) = nbl;
	*tail = nbl;
	NET_BUFFER_LIST_NEXT_NBL(nbl) = NULL;
}

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
static TUN_CTX *TunGetContext(_In_ DEVICE_OBJECT *DeviceObject)
{
	TUN_CTX **control_device_extension = (TUN_CTX **)NdisGetDeviceReservedExtension(DeviceObject);
	return control_device_extension ? *control_device_extension : NULL;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
static void TunCompleteRequest(_Inout_ IRP *Irp, _In_ ULONG_PTR Information, _In_ NTSTATUS Status)
{
	Irp->IoStatus.Information = Information;
	Irp->IoStatus.Status      = Status;
	IoCompleteRequest(Irp, IO_NO_INCREMENT);
}

_IRQL_requires_max_(DISPATCH_LEVEL)
static void TunCompletePausing(_Inout_ TUN_CTX *ctx, _In_ LONG64 decrement)
{
	if (!InterlockedSubtract64(&ctx->ActiveNBLCount, decrement) &&
	    InterlockedCompareExchange((LONG *)&ctx->State, TUN_STATE_PAUSED, TUN_STATE_PAUSING) == TUN_STATE_PAUSING)
		NdisMPauseComplete(ctx->MiniportAdapterHandle);
}

_IRQL_requires_same_
static ULONG TunSetNBLStatus(_Inout_opt_ NET_BUFFER_LIST *nbl, _In_ NDIS_STATUS status)
{
	ULONG nbl_count = 0;
	for (; nbl; nbl = NET_BUFFER_LIST_NEXT_NBL(nbl), nbl_count++)
		NET_BUFFER_LIST_STATUS(nbl) = status;
	return nbl_count;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
static NTSTATUS TunGetIRPBuffer(_Inout_ IRP *Irp, _Out_ UCHAR **buffer, _Out_ ULONG *size)
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
	if (*size > TUN_EXCH_MAX_BUFFER_SIZE)
		return STATUS_INVALID_USER_BUFFER;

	/* Get buffer size and address. */
	if (!Irp->MdlAddress)
		return STATUS_INVALID_PARAMETER;
	ULONG sizeMdl;
	NdisQueryMdl(Irp->MdlAddress, buffer, &sizeMdl, priority);
	if (!buffer)
		return STATUS_INSUFFICIENT_RESOURCES;
	if (sizeMdl < *size)
		*size = sizeMdl;

	return STATUS_SUCCESS;
}

_Requires_lock_not_held_(ctx->PacketQueue.Lock.SpinLock)
_IRQL_requires_max_(DISPATCH_LEVEL)
static void TunProcessPacketQueue(_Inout_ TUN_CTX *ctx, _Inout_ IRP *Irp)
{
	/* Prepare IRP for read. */
	CCHAR PriorityBoost = IO_NO_INCREMENT;
	ULONG SendCompleteFlags = 0;
	ULONG nbl_count = 0;
	NET_BUFFER_LIST *nbl_head = NULL, *nbl_tail = NULL;
	UCHAR *buffer = NULL;
	ULONG size = 0;
	Irp->IoStatus.Information = 0;
	Irp->IoStatus.Status      = TunGetIRPBuffer(Irp, &buffer, &size);
	if (Irp->IoStatus.Status != STATUS_SUCCESS)
		goto cleanup_complete_req;

	UCHAR *b = buffer, *b_end = buffer + size;
	LONG64 stat_size = 0, stat_p_ok = 0, stat_p_err = 0;

	/* Transfer packets from NBL queue to IRP. */
	NdisAcquireSpinLock(&ctx->PacketQueue.Lock);
	if (ctx->PacketQueue.Lock.OldIrql >= DISPATCH_LEVEL)
		SendCompleteFlags |= NDIS_SEND_COMPLETE_FLAGS_DISPATCH_LEVEL;
	while (ctx->PacketQueue.Head) {
		for (; ctx->PacketQueue.Buffer; ctx->PacketQueue.Buffer = NET_BUFFER_NEXT_NB(ctx->PacketQueue.Buffer)) {
			ULONG p_size = NET_BUFFER_DATA_LENGTH(ctx->PacketQueue.Buffer);
			if (p_size > TUN_EXCH_MAX_IP_PACKET_SIZE) {
				NET_BUFFER_LIST_STATUS(ctx->PacketQueue.Head) = NDIS_STATUS_INVALID_LENGTH;
				goto error;
			}

			UCHAR *b_next = b + TunPacketAlign(sizeof(TUN_PACKET) + p_size);
			if (b_next > b_end)
				goto cleanup_NdisReleaseSpinLock;

			TUN_PACKET *p = (TUN_PACKET *)b;
			p->Size = p_size;
			void *ptr = NdisGetDataBuffer(ctx->PacketQueue.Buffer, p_size, p->Data, 1, 0);
			if (!ptr) {
				NET_BUFFER_LIST_STATUS(ctx->PacketQueue.Head) = NDIS_STATUS_RESOURCES;
				goto error;
			}
			if (ptr != p->Data)
				NdisMoveMemory(p->Data, ptr, p_size);

			stat_size += p_size;
			stat_p_ok++;
			b = b_next;
			continue;

		error:
			stat_p_err++;
		}

		/* NBL depleted: Relocate it to the "completed" queue. */
		NET_BUFFER_LIST *nbl_next = NET_BUFFER_LIST_NEXT_NBL(ctx->PacketQueue.Head);
		TunAppendNBL(&nbl_head, &nbl_tail, ctx->PacketQueue.Head);
		nbl_count++;
		ctx->PacketQueue.Head = nbl_next;
		if (ctx->PacketQueue.Head)
			ctx->PacketQueue.Buffer = NET_BUFFER_LIST_FIRST_NB(ctx->PacketQueue.Head);
		else
			ctx->PacketQueue.Tail  = NULL;
	}
cleanup_NdisReleaseSpinLock:
	ctx->PacketQueue.Count -= nbl_count;
	NdisReleaseSpinLock(&ctx->PacketQueue.Lock);

	Irp->IoStatus.Information = b - buffer;
	PriorityBoost = IO_NETWORK_INCREMENT;

	InterlockedAdd64((LONG64 *)&ctx->Statistics.ifHCOutOctets,      stat_size);
	InterlockedAdd64((LONG64 *)&ctx->Statistics.ifHCOutUcastOctets, stat_size);
	InterlockedAdd64((LONG64 *)&ctx->Statistics.ifHCOutUcastPkts,   stat_p_ok);
	InterlockedAdd64((LONG64 *)&ctx->Statistics.ifOutErrors,        stat_p_err);

cleanup_complete_req:
	IoCompleteRequest(Irp, PriorityBoost);
	IoStartNextPacket(ctx->Device.Object, FALSE);

	if (nbl_head) {
		NdisMSendNetBufferListsComplete(ctx->MiniportAdapterHandle, nbl_head, SendCompleteFlags);
		TunCompletePausing(ctx, nbl_count);
	}
}

static DRIVER_STARTIO TunStartIo;
_Use_decl_annotations_
VOID TunStartIo(_Inout_ DEVICE_OBJECT *DeviceObject, _Inout_ IRP *Irp)
{
	TUN_CTX *ctx = TunGetContext(DeviceObject);
	if (!ctx) {
		TunCompleteRequest(Irp, 0, STATUS_CANCELLED);
		IoStartNextPacket(DeviceObject, FALSE);
		return;
	}

	NdisAcquireSpinLock(&ctx->PacketQueue.Lock);
	if (!ctx->PacketQueue.Head) {
		/* Set active IRP before releasing the spin lock. If this thread would be interrupted after ctx->PacketQueue.Lock
		 * release and before ctx->Device.ActiveIrp is set, and TunSendNetBufferLists() is called meanwhile, the later
		 * will not notice pending IRP and not call TunProcessPacketQueue() causing read to stall until next
		 * TunSendNetBufferLists() call. */
		InterlockedExchangePointer((PVOID volatile *)&ctx->Device.ActiveIrp, Irp);
		NdisReleaseSpinLock(&ctx->PacketQueue.Lock);
		return;
	}
	NdisReleaseSpinLock(&ctx->PacketQueue.Lock);

	TunProcessPacketQueue(ctx, Irp);
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

	InterlockedIncrement64(&ctx->Device.RefCount);
	TunIndicateStatus(ctx);
	status = STATUS_SUCCESS;

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

	InterlockedDecrement64(&ctx->Device.RefCount);
	TunIndicateStatus(ctx);
	status = STATUS_SUCCESS;

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

	IoMarkIrpPending(Irp);
	IoStartPacket(DeviceObject, Irp, NULL, NULL);
	return STATUS_PENDING;

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

	UCHAR *buffer = NULL;
	ULONG size = 0;
	status = TunGetIRPBuffer(Irp, &buffer, &size);
	if (status != STATUS_SUCCESS)
		goto cleanup_complete_req;

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

		#pragma warning(suppress: 6014) /* Leaking memory 'nbl'. Note: 'nbl' is aliased in nbl_head/tail list and freed in TunReturnNetBufferLists. */
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

	InterlockedAdd64(&ctx->ActiveNBLCount, nbl_count);

	BOOLEAN update_statistics = TRUE;
	if ((status = STATUS_NDIS_PAUSED,          InterlockedGet((LONG *)&ctx->State) != TUN_STATE_RUNNING) ||
	    (status = STATUS_NDIS_LOW_POWER_STATE, ctx->PowerState >= NdisDeviceStateD1)) {
		update_statistics = FALSE;
		goto cleanup_nbl_head;
	}

	information = b - buffer;
	status      = STATUS_SUCCESS;

	if (!nbl_head)
		goto cleanup_statistics;

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
	NdisMIndicateReceiveNetBufferLists(ctx->MiniportAdapterHandle, nbl_head, NDIS_DEFAULT_PORT_NUMBER, nbl_count, NDIS_RECEIVE_FLAGS_RESOURCES);

cleanup_nbl_head:
	for (NET_BUFFER_LIST *nbl = nbl_head, *nbl_next; nbl; nbl = nbl_next) {
		nbl_next = NET_BUFFER_LIST_NEXT_NBL(nbl);
		NET_BUFFER_LIST_NEXT_NBL(nbl) = NULL;

		MDL *mdl = NET_BUFFER_FIRST_MDL(NET_BUFFER_LIST_FIRST_NB(nbl));
		if (update_statistics) {
			if (NET_BUFFER_LIST_STATUS(nbl) == NDIS_STATUS_SUCCESS) {
				ULONG p_size = MmGetMdlByteCount(mdl);
				stat_size += p_size;
				stat_p_ok++;
			} else
				stat_p_err++;
		}
		NdisFreeMdl(mdl);
		NdisFreeNetBufferList(nbl);
	}

cleanup_statistics:
	TunCompletePausing(ctx, nbl_count);

	InterlockedAdd64((LONG64 *)&ctx->Statistics.ifHCInOctets,      stat_size);
	InterlockedAdd64((LONG64 *)&ctx->Statistics.ifHCInUcastOctets, stat_size);
	InterlockedAdd64((LONG64 *)&ctx->Statistics.ifHCInUcastPkts,   stat_p_ok);
	InterlockedAdd64((LONG64 *)&ctx->Statistics.ifInErrors,        stat_p_err);

cleanup_complete_req:
	TunCompleteRequest(Irp, information, status);
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
	if (InterlockedCompareExchange((LONG *)&ctx->State, TUN_STATE_PAUSING, TUN_STATE_RUNNING) != TUN_STATE_RUNNING)
		return NDIS_STATUS_FAILURE;

	ULONG nbl_count = 0;
	NdisAcquireSpinLock(&ctx->PacketQueue.Lock);
	if (ctx->PacketQueue.Head) {
		NET_BUFFER_LIST *nbl = ctx->PacketQueue.Head;
		ctx->PacketQueue.Head   = NULL;
		ctx->PacketQueue.Buffer = NULL;
		ctx->PacketQueue.Tail   = NULL;
		ctx->PacketQueue.Count  = 0;
		NdisReleaseSpinLock(&ctx->PacketQueue.Lock);

		nbl_count += TunSetNBLStatus(nbl, NDIS_STATUS_PAUSED);
		NdisMSendNetBufferListsComplete(ctx->MiniportAdapterHandle, nbl, 0);
	} else
		NdisReleaseSpinLock(&ctx->PacketQueue.Lock);

	TunIndicateStatus(ctx);

	if (InterlockedSubtract64(&ctx->ActiveNBLCount, nbl_count))
		return NDIS_STATUS_PENDING;

	InterlockedExchange((LONG *)&ctx->State, TUN_STATE_PAUSED);
	return NDIS_STATUS_SUCCESS;
}

static MINIPORT_RESTART TunRestart;
_Use_decl_annotations_
static NDIS_STATUS TunRestart(NDIS_HANDLE MiniportAdapterContext, PNDIS_MINIPORT_RESTART_PARAMETERS MiniportRestartParameters)
{
	TUN_CTX *ctx = (TUN_CTX *)MiniportAdapterContext;
	if (InterlockedCompareExchange((LONG *)&ctx->State, TUN_STATE_RESTARTING, TUN_STATE_PAUSED) != TUN_STATE_PAUSED)
		return NDIS_STATUS_FAILURE;

	TunIndicateStatus(ctx);

	InterlockedExchange((LONG *)&ctx->State, TUN_STATE_RUNNING);
	return NDIS_STATUS_SUCCESS;
}

static MINIPORT_RETURN_NET_BUFFER_LISTS TunReturnNetBufferLists;
_Use_decl_annotations_
static void TunReturnNetBufferLists(NDIS_HANDLE MiniportAdapterContext, PNET_BUFFER_LIST NetBufferLists, ULONG ReturnFlags)
{
}

static MINIPORT_CANCEL_SEND TunCancelSend;
_Use_decl_annotations_
static void TunCancelSend(NDIS_HANDLE MiniportAdapterContext, PVOID CancelId)
{
	TUN_CTX *ctx = (TUN_CTX *)MiniportAdapterContext;
	ULONG nbl_drop_count = 0;
	NET_BUFFER_LIST *nbl_keep_head = NULL, *nbl_keep_tail = NULL, *nbl_drop_head = NULL, *nbl_drop_tail = NULL;

	NdisAcquireSpinLock(&ctx->PacketQueue.Lock);
	ULONG SendCompleteFlags = ctx->PacketQueue.Lock.OldIrql >= DISPATCH_LEVEL ? NDIS_SEND_COMPLETE_FLAGS_DISPATCH_LEVEL : 0;

	/* Split NBL queue into two queues: one with NBLs to keep, one with NBLs to drop. */
	for (NET_BUFFER_LIST *nbl = ctx->PacketQueue.Head, *nbl_next; nbl; nbl = nbl_next) {
		nbl_next = NET_BUFFER_LIST_NEXT_NBL(nbl);
		if (NDIS_GET_NET_BUFFER_LIST_CANCEL_ID(nbl) == CancelId) {
			NET_BUFFER_LIST_STATUS(nbl) = NDIS_STATUS_SEND_ABORTED;
			TunAppendNBL(&nbl_drop_head, &nbl_drop_tail, nbl);
			nbl_drop_count++;
		} else
			TunAppendNBL(&nbl_keep_head, &nbl_keep_tail, nbl);
	}

	if (ctx->PacketQueue.Head != nbl_keep_head) {
		ctx->PacketQueue.Buffer = nbl_keep_head ? NET_BUFFER_LIST_FIRST_NB(nbl_keep_head) : NULL;
		ctx->PacketQueue.Head   = nbl_keep_head;
	}

	ctx->PacketQueue.Count -= nbl_drop_count;
	NdisReleaseSpinLock(&ctx->PacketQueue.Lock);

	if (nbl_drop_head) {
		NdisMSendNetBufferListsComplete(ctx->MiniportAdapterHandle, nbl_drop_head, SendCompleteFlags);
		TunCompletePausing(ctx, nbl_drop_count);
	}
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
	if (NdisAllocateMemoryWithTag(&ctx, sizeof(TUN_CTX), TUN_MEMORY_TAG) != NDIS_STATUS_SUCCESS)
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
	if (NdisMSetMiniportAttributes(MiniportAdapterHandle, (PNDIS_MINIPORT_ADAPTER_ATTRIBUTES)&attr) != NDIS_STATUS_SUCCESS) {
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
	if (NdisMSetMiniportAttributes(MiniportAdapterHandle, (PNDIS_MINIPORT_ADAPTER_ATTRIBUTES)&gen) != NDIS_STATUS_SUCCESS) {
		status = NDIS_STATUS_FAILURE;
		goto cleanup_ctx;
	}

	NdisAllocateSpinLock(&ctx->PacketQueue.Lock);

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
		goto cleanup_NdisFreeSpinLock;
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
		TunDispatchCreate, /* IRP_MJ_CREATE            */
		NULL,              /* IRP_MJ_CREATE_NAMED_PIPE */
		TunDispatchClose,  /* IRP_MJ_CLOSE             */
		TunDispatchRead,   /* IRP_MJ_READ              */
		TunDispatchWrite,  /* IRP_MJ_WRITE             */
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
	if (NdisRegisterDeviceEx(NdisMiniportDriverHandle, &t, &ctx->Device.Object, &ctx->Device.Handle) != NDIS_STATUS_SUCCESS) {
		status = NDIS_STATUS_FAILURE;
		goto cleanup_NdisFreeNetBufferListPool;
	}

	ctx->Device.Object->Flags &= ~DO_BUFFERED_IO;
	ctx->Device.Object->Flags |=  DO_DIRECT_IO;

	IoSetStartIoAttributes(ctx->Device.Object, TRUE, TRUE);

	TUN_CTX **control_device_extension = (TUN_CTX **)NdisGetDeviceReservedExtension(ctx->Device.Object);
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
cleanup_NdisFreeSpinLock:
	NdisFreeSpinLock(&ctx->PacketQueue.Lock);
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

	/* Reset adapter context in device object, as Windows keep calling dispatch handlers even after NdisDeregisterDeviceEx(). */
	TUN_CTX **control_device_extension = (TUN_CTX **)NdisGetDeviceReservedExtension(ctx->Device.Object);
	if (control_device_extension)
		InterlockedExchangePointer(control_device_extension, NULL);

	/* Cancel pending IRP to unblock waiting clients. */
	IRP *Irp = InterlockedExchangePointer((PVOID volatile *)&ctx->Device.ActiveIrp, NULL);
	if (Irp)
		TunCompleteRequest(Irp, 0, STATUS_CANCELLED);

	/* Release resources. */
	NdisDeregisterDeviceEx(ctx->Device.Handle);
	NdisFreeNetBufferListPool(ctx->NBLPool);
	NdisFreeSpinLock(&ctx->PacketQueue.Lock);
	NdisFreeMemory(ctx, 0, 0);
}

_IRQL_requires_max_(PASSIVE_LEVEL)
_IRQL_requires_same_
static NDIS_STATUS TunOidSet(_Inout_ TUN_CTX *ctx, _In_ NDIS_OID Oid, _In_bytecount_(InformationBufferLength) const void *InformationBuffer, _In_ UINT InformationBufferLength, _Out_ UINT *BytesRead, _Out_ UINT *BytesNeeded)
{
	*BytesRead = 0;
	*BytesNeeded = 0;

	switch (Oid) {
	case OID_GEN_CURRENT_PACKET_FILTER:
	case OID_GEN_CURRENT_LOOKAHEAD:
		if (InformationBufferLength != 4) {
			*BytesNeeded = 4;
			return NDIS_STATUS_INVALID_LENGTH;
		}
		*BytesRead = 4;
		return NDIS_STATUS_SUCCESS;

	case OID_GEN_LINK_PARAMETERS:
		*BytesRead = InformationBufferLength;
		return NDIS_STATUS_SUCCESS;

	case OID_GEN_INTERRUPT_MODERATION:
		return NDIS_STATUS_INVALID_DATA;

	case OID_PNP_SET_POWER:
		if (InformationBufferLength != sizeof(NDIS_DEVICE_POWER_STATE)) {
			*BytesNeeded = sizeof(NDIS_DEVICE_POWER_STATE);
			return NDIS_STATUS_INVALID_LENGTH;
		}
		*BytesRead = sizeof(NDIS_DEVICE_POWER_STATE);
		ctx->PowerState = *((NDIS_DEVICE_POWER_STATE *)InformationBuffer);
		return NDIS_STATUS_SUCCESS;
	}

	return NDIS_STATUS_INVALID_OID;
}

_IRQL_requires_max_(APC_LEVEL)
_IRQL_requires_same_
static NDIS_STATUS TunOidQuery(_Inout_ TUN_CTX *ctx, _In_ NDIS_OID Oid, _Out_bytecap_post_bytecount_(InformationBufferLength, *BytesWritten) void *InformationBuffer, _In_ UINT InformationBufferLength, _Out_ UINT *BytesWritten, _Out_ UINT *BytesNeeded)
{
	UINT value32;
	UINT size = sizeof(value32);
	const void *buf = &value32;

	switch (Oid) {
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
		*BytesWritten = 0;
		return NDIS_STATUS_INVALID_OID;
	}

	if (size > InformationBufferLength) {
		*BytesNeeded = size;
		*BytesWritten = 0;
		return NDIS_STATUS_INVALID_LENGTH;
	}

	NdisMoveMemory(InformationBuffer, buf, size);
	*BytesNeeded = *BytesWritten = size;

	return NDIS_STATUS_SUCCESS;
}

static MINIPORT_OID_REQUEST TunOidRequest;
_Use_decl_annotations_
static NDIS_STATUS TunOidRequest(NDIS_HANDLE MiniportAdapterContext, PNDIS_OID_REQUEST OidRequest)
{
	switch (OidRequest->RequestType) {
	case NdisRequestQueryInformation:
	case NdisRequestQueryStatistics:
		return TunOidQuery(MiniportAdapterContext, OidRequest->DATA.QUERY_INFORMATION.Oid, OidRequest->DATA.QUERY_INFORMATION.InformationBuffer, OidRequest->DATA.QUERY_INFORMATION.InformationBufferLength, &OidRequest->DATA.QUERY_INFORMATION.BytesWritten, &OidRequest->DATA.QUERY_INFORMATION.BytesNeeded);

	case NdisRequestSetInformation:
		return TunOidSet(MiniportAdapterContext, OidRequest->DATA.SET_INFORMATION.Oid, OidRequest->DATA.SET_INFORMATION.InformationBuffer, OidRequest->DATA.SET_INFORMATION.InformationBufferLength, &OidRequest->DATA.SET_INFORMATION.BytesRead, &OidRequest->DATA.SET_INFORMATION.BytesNeeded);

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
	ULONG nbl_count = 0;

	InterlockedIncrement64(&ctx->ActiveNBLCount);

	NDIS_STATUS status;
	if ((status = NDIS_STATUS_PAUSED,          InterlockedGet((LONG *)&ctx->State) != TUN_STATE_RUNNING) ||
	    (status = NDIS_STATUS_LOW_POWER_STATE, ctx->PowerState >= NdisDeviceStateD1)) {
		TunSetNBLStatus(NetBufferLists, status);
		goto cleanup_NdisMSendNetBufferListsComplete;
	}

	/* Append NBL(s) to the queue. */
	NdisAcquireSpinLock(&ctx->PacketQueue.Lock);
	if (ctx->PacketQueue.Tail)
		NET_BUFFER_LIST_NEXT_NBL(ctx->PacketQueue.Tail) = NetBufferLists;
	else {
		ctx->PacketQueue.Head  = NetBufferLists;
		ctx->PacketQueue.Buffer = NET_BUFFER_LIST_FIRST_NB(NetBufferLists);
	}
	for (; NetBufferLists; NetBufferLists = NET_BUFFER_LIST_NEXT_NBL(NetBufferLists), nbl_count++)
		ctx->PacketQueue.Tail = NetBufferLists;
	ctx->PacketQueue.Count += nbl_count;
	NdisReleaseSpinLock(&ctx->PacketQueue.Lock);
	InterlockedAdd64(&ctx->ActiveNBLCount, nbl_count);

	IRP *Irp = InterlockedExchangePointer((PVOID volatile *)&ctx->Device.ActiveIrp, NULL);
	if (Irp)
		TunProcessPacketQueue(ctx, Irp);

	/* Prevent accumulation of NBLs by keeping only TUN_QUEUE_MAX_NBLS most recent ones. */
	NdisAcquireSpinLock(&ctx->PacketQueue.Lock);
	for (nbl_count = 0; ctx->PacketQueue.Count > TUN_QUEUE_MAX_NBLS; ctx->PacketQueue.Count--, nbl_count++) {
		_Analysis_assume_(ctx->PacketQueue.Head); /* ctx->PacketQueue.Count > 0 => ctx->PacketQueue.Head != NULL. */
		NET_BUFFER_LIST *nbl = ctx->PacketQueue.Head;
		ctx->PacketQueue.Head = NET_BUFFER_LIST_NEXT_NBL(ctx->PacketQueue.Head);
		NET_BUFFER_LIST_NEXT_NBL(nbl) = NetBufferLists;
		NetBufferLists = nbl;
	}
	NdisReleaseSpinLock(&ctx->PacketQueue.Lock);

cleanup_NdisMSendNetBufferListsComplete:
	if (NetBufferLists)
		NdisMSendNetBufferListsComplete(ctx->MiniportAdapterHandle, NetBufferLists, SendFlags & NDIS_SEND_FLAGS_DISPATCH_LEVEL ? NDIS_SEND_COMPLETE_FLAGS_DISPATCH_LEVEL : 0);

	TunCompletePausing(ctx, 1i64 + nbl_count);
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
	NTSTATUS status = NdisMRegisterMiniportDriver(DriverObject, RegistryPath, NULL, &miniport, &NdisMiniportDriverHandle);
	if (status != STATUS_SUCCESS)
		return status;

	DriverObject->DriverStartIo = TunStartIo;
	return STATUS_SUCCESS;
}

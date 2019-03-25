typedef struct _PACKET_QUEUE {
	KSPIN_LOCK Lock;
	NET_BUFFER_LIST *FirstNbl, *LastNbl;
	volatile NET_BUFFER_LIST *FirstToFree;
	NET_BUFFER *NextNb;
	UINT NumNbl;
} PACKET_QUEUE, *PPACKET_QUEUE;

// Annotation: requires Queue->Lock
void AddToFreeList(PACKET_QUEUE *Queue, NET_BUFFER_LIST *Nbl)
{
	if (!Queue->FirstToFree)
		Queue->FirstToFree = Nbl;
	else {
		NET_BUFFER_LIST_NEXT_NBL(Nbl) = Queue->FirstToFree;
		Queue->FirstToFree = Nbl;
	}
	--Queue->NumNbl;
}

// Annotation: requires Queue->Lock
void FreeFreeList(PACKET_QUEUE *Queue)
{
	NET_BUFFER_LIST *Next;

	while (Queue->FirstToFree) {
		Next = NET_BUFFER_LIST_NEXT_NBL(Queue->FirstToFree);
		FreeNbl(Queue->FirstToFree);
		Queue->FirstToFree = Next;
	}
}

// Annotation: requires Queue->Lock
NET_BUFFER *RemoveFromQueue(PACKET_QUEUE *Queue, NET_BUFFER_LIST **DetachedNbl)
{
	NET_BUFFER_LIST *Top;
	NET_BUFFER *Ret;

	Top = Queue->FirstNbl;
	if (!Top)
		return NULL;
	if (!Queue->NextNb)
		Queue->NextNb = NET_BUFFER_LIST_FIRST_NB(Top);
	Ret = Queue->NextNb;
	Queue->NextNb = NET_BUFFER_NEXT_NB(Ret);
	if (!Queue->NextNb) {
		Queue->FirstNbl = NET_BUFFER_LIST_NEXT_NBL(Top);
		if (!Queue->FirstNbl)
			Queue->LastNbl = NULL;
		NET_BUFFER_LIST_NEXT_NBL(Top) = NULL;
		AddToFreeList(Queue, Top);
		if (DetachedNbl)
			*DetachedNbl = Top;
	}
	return Ret;
}

// Annotation: requires Queue->Lock
void AppendToQueue(PACKET_QUEUE *Queue, NET_BUFFER_LIST *Nbl)
{
	NET_BUFFER_LIST *Next;

	for (; Nbl; Nbl = Next) {
		Next = NET_BUFFER_LIST_NEXT_NBL(Nbl);
		if (!NET_BUFFER_LIST_FIRST_NB(Nbl->FirstNb)) {
			FreeNbl(Nbl);
			continue;
		}
		if (!Queue->FirstNbl)
			Queue->FirstNbl = Queue->LastNbl = Nbl;
		else {
			NET_BUFFER_LIST_NEXT_NBL(Queue->LastNbl) = Nbl;
			Queue->LastNbl = Nbl;
		}
		++Queue->NumNbl;
	}
}

// Annotation: requires Queue->Lock
// Note: Must be called immediately after RemoveFromQueue without dropping Queue->Lock.
void PrependToQueue(PACKET_QUEUE *Queue, NET_BUFFER *Nb, NET_BUFFER_LIST *DetachedNbl)
{
	Queue->NextNb = Nb;

	if (!DetachedNbl)
		return;

	if (DetachedNbl == Queue->FirstToFree)
		Queue->FirstToFree = NET_BUFFER_LIST_NEXT_NBL(DetachedNbl);

	if (!Queue->FirstNbl)
		Queue->FirstNbl = Queue->LastNbl = DetachedNbl;
	else {
		NET_BUFFER_LIST_NEXT_NBL(DetachedNbl) = Queue->FirstNbl;
		Queue->FirstNbl = DetachedNbl;
	}
	++Queue->NumNbl;
}

// Annotation: requires Queue->Lock
void TrimQueueToNItems(PACKET_QUEUE *Queue, UINT MaxNbls)
{
	NET_BUFFER_LIST *Next;

	while (Queue->NumNbl > MaxNbls) {
		if (!Queue->FirstNbl)
			return;
		Next = NET_BUFFER_LIST_NEXT_NBL(Queue->FirstNbl);
		AddToFreeList(Queue->FirstNbl);
		Queue->NextNb = NULL;
		Queue->FirstNbl = Next;
		if (!Queue->FirstNbl)
			Queue->LastNbl = NULL;
	}
	FreeFreeList(Queue);
}

void TunDispatchRead(IRP *Irp)
{
	IoCsqInsertIrpEx(IoCsq, Irp, NULL, NULL);
	ProcessQueuedPackets();
}

void ProcessQueuedPackets(void)
{
	IRP *Irp;
	NET_BUFFER *Nb;
	KLOCK_QUEUE_HANDLE LockHandle;

	for (;;) {
		if (!Irp) {
			NET_BUFFER_LIST *DetachedNbl = NULL;

			KeAcquireInStackQueuedSpinLock(Queue->Lock, &LockHandle);
			Nb = RemoveFromQueue(Queue, &DetachedNbl);
			if (!Nb) {
				KeReleaseInStackQueuedSpinLock(Queue->Lock, &LockHandle);
				return;
			}
			Irp = IoCsqRemoveNextIrp(IoCsq, NULL);
			if (!Irp) {
				PrependToQueue(Queue, Nb, DetachedNbl);
				KeReleaseInStackQueuedSpinLock(Queue, &LockHandle);
				return;
			}
			KeReleaseInStackQueuedSpinLock(Queue->Lock, &LockHandle);
		} else {
			KeAcquireInStackQueuedSpinLock(Queue->Lock, &LockHandle);
			Nb = RemoveFromQueue(Queue, NULL);
			KeReleaseInStackQueuedSpinLock(Queue->Lock, &LockHandle);
		}
		if (!Nb || WriteIntoIrp(Irp, Nb) == IRP_HAD_NO_ROOM_FOR_IT) {
			TunCompleteRequest(Irp, 0, STATUS_SUCCESS);
			Irp = NULL;
		}
		if (Queue->FirstToFree) {
			KeAcquireInStackQueuedSpinLock(Queue->Lock, &LockHandle);
			FreeFreeList(Queue);
			KeReleaseInStackQueuedSpinLock(Queue->Lock, &LockHandle);
		}
	}
}

void TunSendNetBufferLists(NET_BUFFER_LIST *Nbl)
{
	KLOCK_QUEUE_HANDLE LockHandle;

	KeAcquireInStackQueuedSpinLock(Queue->Lock, &LockHandle);
	AppendToQueue(Queue, Nbl);
	TrimQueueToNItems(Queue, 1000);
	KeReleaseInStackQueuedSpinLock(Queue->Lock, &LockHandle);
	ProcessQueuedPackets();
}

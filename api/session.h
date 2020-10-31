/* SPDX-License-Identifier: GPL-2.0
 *
 * Copyright (C) 2018-2020 WireGuard LLC. All Rights Reserved.
 */

#pragma once

#include "wintun.h"
#include <Windows.h>

typedef struct _TUN_SESSION TUN_SESSION;

/**
 * @copydoc WINTUN_START_SESSION_FUNC
 */
WINTUN_STATUS WINAPI
WintunStartSession(
    _In_ const WINTUN_ADAPTER *Adapter,
    _In_ DWORD Capacity,
    _Out_ TUN_SESSION **Session,
    _Out_ HANDLE *ReadWait);

/**
 * @copydoc WINTUN_END_SESSION_FUNC
 */
void WINAPI
WintunEndSession(_In_ TUN_SESSION *Session);

/**
 * @copydoc WINTUN_RECEIVE_PACKET_FUNC
 */
WINTUN_STATUS WINAPI
WintunReceivePacket(_In_ TUN_SESSION *Session, _Out_bytecapcount_(*PacketSize) BYTE **Packet, _Out_ DWORD *PacketSize);

/**
 * @copydoc WINTUN_RECEIVE_RELEASE_FUNC
 */
void WINAPI
WintunReceiveRelease(_In_ TUN_SESSION *Session, _In_ const BYTE *Packet);

/**
 * @copydoc WINTUN_ALLOCATE_SEND_PACKET
 */
WINTUN_STATUS WINAPI
WintunAllocateSendPacket(
    _In_ TUN_SESSION *Session,
    _In_ DWORD PacketSize,
    _Out_bytecapcount_(PacketSize) BYTE **Packet);

/**
 * @copydoc WINTUN_SEND_PACKET
 */
void WINAPI
WintunSendPacket(_In_ TUN_SESSION *Session, _In_ const BYTE *Packet);

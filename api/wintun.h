/* SPDX-License-Identifier: GPL-2.0
 *
 * Copyright (C) 2018-2020 WireGuard LLC. All Rights Reserved.
 */

#pragma once

#include <Windows.h>
#include <IPExport.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef _Return_type_success_(return == ERROR_SUCCESS) DWORD WINTUN_STATUS;

/**
 * A handle representing Wintun adapter
 */
typedef void *WINTUN_ADAPTER_HANDLE;

/**
 * Maximum pool name length including zero terminator
 */
#define WINTUN_MAX_POOL 256

/**
 * Creates a Wintun adapter.
 *
 * @param Pool          Name of the adapter pool.
 *
 * @param Name          The requested name of the adapter.
 *
 * @param RequestedGUID  The GUID of the created network adapter, which then influences NLA generation
 *                      deterministically. If it is set to NULL, the GUID is chosen by the system at random, and hence
 *                      a new NLA entry is created for each new adapter. It is called "requested" GUID because the API
 *                      it uses is completely undocumented, and so there could be minor interesting complications with
 *                      its usage.
 *
 * @param Adapter       Pointer to a handle to receive the adapter handle. Must be released with
 *                      WintunFreeAdapter.
 *
 * @param RebootRequired  Pointer to a boolean flag to be set to TRUE in case SetupAPI suggests a reboot. Must be
 *                      initialised to FALSE manually before this function is called.
 *
 * @return ERROR_SUCCESS on success; Win32 error code otherwise.
 */
typedef WINTUN_STATUS(WINAPI *WINTUN_CREATE_ADAPTER_FUNC)(
    _In_z_count_c_(WINTUN_MAX_POOL) const WCHAR *Pool,
    _In_z_count_c_(MAX_ADAPTER_NAME) const WCHAR *Name,
    _In_opt_ const GUID *RequestedGUID,
    _Out_ WINTUN_ADAPTER_HANDLE *Adapter,
    _Inout_ BOOL *RebootRequired);

/**
 * Deletes a Wintun adapter.
 *
 * @param Adapter            Adapter handle obtained with WintunGetAdapter or WintunCreateAdapter.
 *
 * @param ForceCloseSessions Force close adapter handles that may be in use by other processes. Only set this to TRUE
 *                           with extreme care, as this is resource intensive and may put processes into an undefined
 *                           or unpredictable state. Most users should set this to FALSE.
 *
 * @param RebootRequired     Pointer to a boolean flag to be set to TRUE in case SetupAPI suggests a reboot. Must be
 *                           initialised to FALSE manually before this function is called.
 *
 * @return ERROR_SUCCESS on success or the adapter was not found; Win32 error code otherwise.
 */
typedef WINTUN_STATUS(WINAPI *WINTUN_DELETE_ADAPTER_FUNC)(
    _In_ WINTUN_ADAPTER_HANDLE Adapter,
    _In_ BOOL ForceCloseSessions,
    _Inout_ BOOL *RebootRequired);

/**
 * Called by WintunEnumAdapters for each adapter in the pool.
 *
 * @param Adapter       Adapter handle.
 *
 * @param Param         An application-defined value passed to the WintunEnumAdapters.
 *
 * @return Non-zero to continue iterating adapters; zero to stop.
 */
typedef BOOL(CALLBACK *WINTUN_ENUM_FUNC)(_In_ WINTUN_ADAPTER_HANDLE Adapter, _In_ LPARAM Param);

/**
 * Enumerates all Wintun adapters.
 *
 * @param Pool          Name of the adapter pool.
 *
 * @param Func          Callback function. To continue enumeration, the callback function must return TRUE; to stop
 *                      enumeration, it must return FALSE.
 *
 * @param Param         An application-defined value to be passed to the callback function.
 *
 * @return ERROR_SUCCESS on success; Win32 error code otherwise.
 */
typedef WINTUN_STATUS(WINAPI *WINTUN_ENUM_ADAPTERS_FUNC)(
    _In_z_count_c_(WINTUN_MAX_POOL) const WCHAR *Pool,
    _In_ WINTUN_ENUM_FUNC Func,
    _In_ LPARAM Param);

/**
 * Releases Wintun adapter resources.
 *
 * @param Adapter       Adapter handle obtained with WintunGetAdapter or WintunCreateAdapter.
 */
typedef void(WINAPI *WINTUN_FREE_ADAPTER_FUNC)(_In_ WINTUN_ADAPTER_HANDLE Adapter);

/**
 * Finds a Wintun adapter by its name.
 *
 * @param Pool          Name of the adapter pool.
 *
 * @param Name          Adapter name.
 *
 * @param Adapter       Pointer to a handle to receive the adapter handle. Must be released with WintunFreeAdapter.
 *
 * @return ERROR_SUCCESS on success; ERROR_FILE_NOT_FOUND if adapter with given name is not found; ERROR_ALREADY_EXISTS
 * if adapter is found but not a Wintun-class or not a member of the pool; Win32 error code otherwise
 */
typedef WINTUN_STATUS(WINAPI *WINTUN_GET_ADAPTER_FUNC)(
    _In_z_count_c_(WINTUN_MAX_POOL) const WCHAR *Pool,
    _In_z_count_c_(MAX_ADAPTER_NAME) const WCHAR *Name,
    _Out_ WINTUN_ADAPTER_HANDLE *Adapter);

/**
 * Returns a handle to the adapter device object.
 *
 * @param Adapter       Adapter handle obtained with WintunGetAdapter or WintunCreateAdapter.
 *
 * @param Handle        Pointer to receive the adapter device object handle. Must be released with CloseHandle.
 *
 * @return ERROR_SUCCESS on success; Win32 error code otherwise.
 */
typedef WINTUN_STATUS(
    WINAPI *WINTUN_GET_ADAPTER_DEVICE_OBJECT_FUNC)(_In_ WINTUN_ADAPTER_HANDLE Adapter, _Out_ HANDLE *Handle);

/**
 * Returns the GUID of the adapter.
 *
 * @param Adapter       Adapter handle obtained with WintunGetAdapter or WintunCreateAdapter
 *
 * @param Guid          Pointer to GUID to receive adapter ID.
 */
typedef void(WINAPI *WINTUN_GET_ADAPTER_GUID_FUNC)(_In_ WINTUN_ADAPTER_HANDLE Adapter, _Out_ GUID *Guid);

/**
 * Returns the LUID of the adapter.
 *
 * @param Adapter       Adapter handle obtained with WintunGetAdapter or WintunCreateAdapter
 *
 * @param Luid          Pointer to LUID to receive adapter LUID.
 */
typedef void(WINAPI *WINTUN_GET_ADAPTER_LUID_FUNC)(_In_ WINTUN_ADAPTER_HANDLE Adapter, _Out_ LUID *Luid);

/**
 * Returns the name of the Wintun adapter.
 *
 * @param Adapter       Adapter handle obtained with WintunGetAdapter or WintunCreateAdapter
 *
 * @param Name          Pointer to a string to receive adapter name
 *
 * @return ERROR_SUCCESS on success; Win32 error code otherwise.
 */
typedef WINTUN_STATUS(WINAPI *WINTUN_GET_ADAPTER_NAME_FUNC)(
    _In_ WINTUN_ADAPTER_HANDLE Adapter,
    _Out_cap_c_(MAX_ADAPTER_NAME) WCHAR *Name);

/**
 * Returns the version of the Wintun driver and NDIS system currently loaded.
 *
 * @param DriverVersionMaj  Pointer to a DWORD to receive the Wintun driver major version number.
 *
 * @param DriverVersionMin  Pointer to a DWORD to receive the Wintun driver minor version number.
 *
 * @param NdisVersionMaj  Pointer to a DWORD to receive the NDIS major version number.
 *
 * @param NdisVersionMin  Pointer to a DWORD to receive the NDIS minor version number.
 *
 * @return ERROR_SUCCESS on success; Win32 error code otherwise.
 */
typedef WINTUN_STATUS(WINAPI *WINTUN_GET_VERSION_FUNC)(
    _Out_ DWORD *DriverVersionMaj,
    _Out_ DWORD *DriverVersionMin,
    _Out_ DWORD *NdisVersionMaj,
    _Out_ DWORD *NdisVersionMin);

/**
 * Sets name of the Wintun adapter.
 *
 * @param Adapter       Adapter handle obtained with WintunGetAdapter or WintunCreateAdapter
 *
 * @param Name          Adapter name
 *
 * @return ERROR_SUCCESS on success; Win32 error code otherwise.
 */
typedef WINTUN_STATUS(WINAPI *WINTUN_SET_ADAPTER_NAME_FUNC)(
    _In_ WINTUN_ADAPTER_HANDLE Adapter,
    _In_z_count_c_(MAX_ADAPTER_NAME) const WCHAR *Name);

typedef enum _WINTUN_LOGGER_LEVEL
{
    WINTUN_LOG_INFO = 0,
    WINTUN_LOG_WARN,
    WINTUN_LOG_ERR
} WINTUN_LOGGER_LEVEL;

/**
 * Called by internal logger to report diagnostic messages
 *
 * @param Level         Message level.
 *
 * @param Message       Message text.
 *
 * @return Anything - return value is ignored.
 */
typedef BOOL(CALLBACK *WINTUN_LOGGER_FUNC)(_In_ WINTUN_LOGGER_LEVEL Level, _In_z_ const WCHAR *Message);

/**
 * Sets logger callback function.
 *
 * @param NewLogger     Pointer to callback function to use as a new global logger. NewLogger may be called from various
 *                      threads concurrently. Should the logging require serialization, you must handle serialization in
 *                      NewLogger.
 */
typedef void(WINAPI *WINTUN_SET_LOGGER_FUNC)(_In_ WINTUN_LOGGER_FUNC NewLogger);

/**
 * Minimum ring capacity.
 */
#define WINTUN_MIN_RING_CAPACITY 0x20000 /* 128kiB */

/**
 * Maximum ring capacity.
 */
#define WINTUN_MAX_RING_CAPACITY 0x4000000 /* 64MiB */

/**
 * A handle representing Wintun session
 */
typedef void *WINTUN_SESSION_HANDLE;

/**
 * Starts Wintun session.
 *
 * @param Adapter       Adapter handle obtained with WintunGetAdapter or WintunCreateAdapter
 *
 * @param Capacity      Rings capacity. Must be between WINTUN_MIN_RING_CAPACITY and WINTUN_MAX_RING_CAPACITY (incl.)
 *                      Must be a power of two.
 *
 * @param Session       Pointer to a variable to receive Wintun session handle
 *
 * @param ReadWait      Pointer to receive event handle to wait for available data when reading. Should
 *                      WintunReceivePackets return ERROR_NO_MORE_ITEMS (after spinning on it for a while under heavy
 *                      load), wait for this event to become signaled before retrying WintunReceivePackets. Do not call
 *                      CloseHandle on this event - it is managed by the session.
 *
 * @return ERROR_SUCCESS on success; Win32 error code otherwise.
 */
typedef WINTUN_STATUS(WINAPI *WINTUN_START_SESSION_FUNC)(
    _In_ WINTUN_ADAPTER_HANDLE Adapter,
    _In_ DWORD Capacity,
    _Out_ WINTUN_SESSION_HANDLE *Session,
    _Out_ HANDLE *ReadWait);

/**
 * Ends Wintun session.
 *
 * @param Session       Wintun session handle obtained with WintunStartSession
 */
typedef void(WINAPI *WINTUN_END_SESSION_FUNC)(_In_ WINTUN_SESSION_HANDLE Session);

/**
 * Maximum IP packet size
 */
#define WINTUN_MAX_IP_PACKET_SIZE 0xFFFF

/**
 * Retrieves one or packet. After the packet content is consumed, call WintunReceiveRelease with Packet returned
 * from this function to release internal buffer. This function is thread-safe.
 *
 * @param Session       Wintun session handle obtained with WintunStartSession
 *
 * @param Packet        Pointer to receive pointer to layer 3 IPv4 or IPv6 packet. Client may modify its content at
 *                      will.
 *
 * @param PacketSize    Pointer to receive Packet size.
 *
 * @return Returns one of the following values:
 * ERROR_HANDLE_EOF     Wintun adapter is terminating;
 * ERROR_NO_MORE_ITEMS  Wintun buffer is exhausted;
 * ERROR_INVALID_DATA   Wintun buffer is corrupt;
 * ERROR_SUCCESS        on success.
 * Regardless, if the error was returned, some packets might have been read nevertheless.
 */
typedef WINTUN_STATUS(WINAPI *WINTUN_RECEIVE_PACKETS_FUNC)(
    _In_ WINTUN_SESSION_HANDLE *Session,
    _Out_bytecapcount_(*PacketSize) BYTE **Packet,
    _Out_ DWORD *PacketSize);

/**
 * Releases internal buffer after the received packet has been processed by the client. This function is thread-safe.
 *
 * @param Session       Wintun session handle obtained with WintunStartSession
 *
 * @param Packet        Packet obtained with WintunReceivePacket
 */
typedef void(WINAPI *WINTUN_RECEIVE_RELEASE_FUNC)(_In_ WINTUN_SESSION_HANDLE *Session, _In_ const BYTE *Packet);

/**
 * Allocates memory for a packet to send. After the memory is filled with packet data, call WintunSendPacket to send
 * and release internal buffer. WintunAllocateSendPacket is thread-safe and the WintunAllocateSendPacket order of
 * calls define the packet sending order.
 *
 * @param Session       Wintun session handle obtained with WintunStartSession
 *
 * @param PacketSize    Exact packet size. Must be less or equal to WINTUN_MAX_IP_PACKET_SIZE.
 *
 * @param Packet        Pointer to receive pointer to memory where to prepare layer 3 IPv4 or IPv6 packet for sending.
 *
 * @return Returns one of the following values:
 * ERROR_HANDLE_EOF     Wintun adapter is terminating;
 * ERROR_BUFFER_OVERFLOW  Wintun buffer is full;
 * ERROR_SUCCESS        on success.
 */
typedef WINTUN_STATUS(WINAPI *WINTUN_ALLOCATE_SEND_PACKET_FUNC)(
    _In_ WINTUN_SESSION_HANDLE *Session,
    _In_ DWORD PacketSize,
    _Out_bytecapcount_(PacketSize) BYTE **Packet);

/**
 * Sends the packet and releases internal buffer. WintunSendPacket is thread-safe, but the WintunAllocateSendPacket
 * order of calls define the packet sending order. This means the packet is not guaranteed to be sent in the
 * WintunSendPacket yet.
 *
 * @param Session       Wintun session handle obtained with WintunStartSession
 *
 * @param Packet        Packet obtained with WintunAllocateSendPacket
 */
typedef void(WINAPI *WINTUN_SEND_PACKET_FUNC)(_In_ WINTUN_SESSION_HANDLE *Session, _In_ const BYTE *Packet);

#ifdef __cplusplus
}
#endif

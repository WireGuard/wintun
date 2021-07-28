/* SPDX-License-Identifier: GPL-2.0 OR MIT
 *
 * Copyright (C) 2018-2021 WireGuard LLC. All Rights Reserved.
 */

#pragma once

#include <windows.h>
#include <ipexport.h>
#include <ifdef.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * A handle representing Wintun adapter
 */
typedef struct _WINTUN_ADAPTER *WINTUN_ADAPTER_HANDLE;

/**
 * Maximum pool name length including zero terminator
 */
#define WINTUN_MAX_POOL 256

/**
 * Creates a new Wintun adapter.
 *
 * @param Pool          Name of the adapter pool. Zero-terminated string of up to WINTUN_MAX_POOL-1 characters.
 *
 * @param Name          The requested name of the adapter. Zero-terminated string of up to MAX_ADAPTER_NAME-1
 *                      characters.
 *
 * @param RequestedGUID The GUID of the created network adapter, which then influences NLA generation deterministically.
 *                      If it is set to NULL, the GUID is chosen by the system at random, and hence a new NLA entry is
 *                      created for each new adapter. It is called "requested" GUID because the API it uses is
 *                      completely undocumented, and so there could be minor interesting complications with its usage.
 *
 * @param RebootRequired  Optional pointer to a boolean flag to be set to TRUE in case SetupAPI suggests a reboot.
 *
 * @return If the function succeeds, the return value is the adapter handle. Must be released with WintunFreeAdapter. If
 * the function fails, the return value is NULL. To get extended error information, call GetLastError.
 */
typedef _Must_inspect_result_
_Return_type_success_(return != NULL)
_Post_maybenull_
WINTUN_ADAPTER_HANDLE(WINAPI WINTUN_CREATE_ADAPTER_FUNC_IMPL)
(_In_z_ LPCWSTR Pool, _In_z_ LPCWSTR Name, _In_opt_ const GUID *RequestedGUID, _Out_opt_ BOOL *RebootRequired);
typedef WINTUN_CREATE_ADAPTER_FUNC_IMPL *WINTUN_CREATE_ADAPTER_FUNC;

/**
 * Opens an existing Wintun adapter.
 *
 * @param Pool          Name of the adapter pool. Zero-terminated string of up to WINTUN_MAX_POOL-1 characters.
 *
 * @param Name          Adapter name. Zero-terminated string of up to MAX_ADAPTER_NAME-1 characters.
 *
 * @return If the function succeeds, the return value is adapter handle. Must be released with WintunFreeAdapter. If the
 * function fails, the return value is NULL. To get extended error information, call GetLastError. Possible errors
 * include the following: ERROR_FILE_NOT_FOUND if adapter with given name is not found; ERROR_ALREADY_EXISTS if adapter
 * is found but not a Wintun-class or not a member of the pool
 */
typedef _Must_inspect_result_
_Return_type_success_(return != NULL)
_Post_maybenull_
WINTUN_ADAPTER_HANDLE(WINAPI WINTUN_OPEN_ADAPTER_FUNC_IMPL)(_In_z_ LPCWSTR Pool, _In_z_ LPCWSTR Name);
typedef WINTUN_OPEN_ADAPTER_FUNC_IMPL *WINTUN_OPEN_ADAPTER_FUNC;

/**
 * Deletes a Wintun adapter.
 *
 * @param Adapter            Adapter handle obtained with WintunOpenAdapter or WintunCreateAdapter.
 *
 * @param ForceCloseSessions Force close adapter handles that may be in use by other processes. Only set this to TRUE
 *                           with extreme care, as this is resource intensive and may put processes into an undefined
 *                           or unpredictable state. Most users should set this to FALSE.
 *
 * @param RebootRequired     Optional pointer to a boolean flag to be set to TRUE in case SetupAPI suggests a reboot.
 *
 * @return If the function succeeds, the return value is nonzero. If the function fails, the return value is zero. To
 *         get extended error information, call GetLastError.
 */
typedef _Return_type_success_(return != FALSE)
BOOL(WINAPI WINTUN_DELETE_ADAPTER_FUNC_IMPL)
(_In_ WINTUN_ADAPTER_HANDLE Adapter, _In_ BOOL ForceCloseSessions, _Out_opt_ BOOL *RebootRequired);
typedef WINTUN_DELETE_ADAPTER_FUNC_IMPL *WINTUN_DELETE_ADAPTER_FUNC;

/**
 * Called by WintunEnumAdapters for each adapter in the pool.
 *
 * @param Adapter       Adapter handle, which will be freed when this function returns.
 *
 * @param Param         An application-defined value passed to the WintunEnumAdapters.
 *
 * @return Non-zero to continue iterating adapters; zero to stop.
 */
typedef BOOL(CALLBACK *WINTUN_ENUM_CALLBACK)(_In_ WINTUN_ADAPTER_HANDLE Adapter, _In_ LPARAM Param);

/**
 * Enumerates all Wintun adapters.
 *
 * @param Pool          Name of the adapter pool. Zero-terminated string of up to WINTUN_MAX_POOL-1 characters.
 *
 * @param Callback      Callback function. To continue enumeration, the callback function must return TRUE; to stop
 *                      enumeration, it must return FALSE.
 *
 * @param Param         An application-defined value to be passed to the callback function.
 *
 * @return If the function succeeds, the return value is nonzero. If the function fails, the return value is zero. To
 *         get extended error information, call GetLastError.
 */
typedef _Return_type_success_(return != FALSE)
BOOL(WINAPI WINTUN_ENUM_ADAPTERS_FUNC_IMPL)(_In_z_ LPCWSTR Pool, _In_ WINTUN_ENUM_CALLBACK Callback, _In_ LPARAM Param);
typedef WINTUN_ENUM_ADAPTERS_FUNC_IMPL *WINTUN_ENUM_ADAPTERS_FUNC;

/**
 * Releases Wintun adapter resources.
 *
 * @param Adapter       Adapter handle obtained with WintunOpenAdapter or WintunCreateAdapter.
 */
typedef VOID(WINAPI WINTUN_FREE_ADAPTER_FUNC_IMPL)(_In_ WINTUN_ADAPTER_HANDLE Adapter);
typedef WINTUN_FREE_ADAPTER_FUNC_IMPL *WINTUN_FREE_ADAPTER_FUNC;

/**
 * Deletes all Wintun adapters in a pool and if there are no more adapters in any other pools, also removes Wintun
 * from the driver store, usually called by uninstallers.
 *
 * @param Pool             Name of the adapter pool. Zero-terminated string of up to WINTUN_MAX_POOL-1 characters.
 *
 * @param RebootRequired   Optional pointer to a boolean flag to be set to TRUE in case SetupAPI suggests a reboot.
 *
 * @return If the function succeeds, the return value is nonzero. If the function fails, the return value is zero. To
 *         get extended error information, call GetLastError.
 */
typedef _Return_type_success_(return != FALSE)
BOOL(WINAPI WINTUN_DELETE_POOL_DRIVER_FUNC_IMPL)(_In_z_ LPCWSTR Pool, _Out_opt_ BOOL *RebootRequired);
typedef WINTUN_DELETE_POOL_DRIVER_FUNC_IMPL *WINTUN_DELETE_POOL_DRIVER_FUNC;

/**
 * Returns the LUID of the adapter.
 *
 * @param Adapter       Adapter handle obtained with WintunOpenAdapter or WintunCreateAdapter
 *
 * @param Luid          Pointer to LUID to receive adapter LUID.
 */
typedef VOID(WINAPI WINTUN_GET_ADAPTER_LUID_FUNC_IMPL)(_In_ WINTUN_ADAPTER_HANDLE Adapter, _Out_ NET_LUID *Luid);
typedef WINTUN_GET_ADAPTER_LUID_FUNC_IMPL *WINTUN_GET_ADAPTER_LUID_FUNC;

/**
 * Returns the name of the Wintun adapter.
 *
 * @param Adapter       Adapter handle obtained with WintunOpenAdapter or WintunCreateAdapter
 *
 * @param Name          Pointer to a string to receive adapter name
 *
 * @return If the function succeeds, the return value is nonzero. If the function fails, the return value is zero. To
 *         get extended error information, call GetLastError.
 */
typedef _Must_inspect_result_
_Return_type_success_(return != FALSE)
BOOL(WINAPI WINTUN_GET_ADAPTER_NAME_FUNC_IMPL)
(_In_ WINTUN_ADAPTER_HANDLE Adapter, _Out_writes_z_(MAX_ADAPTER_NAME) LPWSTR Name);
typedef WINTUN_GET_ADAPTER_NAME_FUNC_IMPL *WINTUN_GET_ADAPTER_NAME_FUNC;

/**
 * Sets name of the Wintun adapter.
 *
 * @param Adapter       Adapter handle obtained with WintunOpenAdapter or WintunCreateAdapter
 *
 * @param Name          Adapter name. Zero-terminated string of up to MAX_ADAPTER_NAME-1 characters.
 *
 * @return If the function succeeds, the return value is nonzero. If the function fails, the return value is zero. To
 *         get extended error information, call GetLastError.
 */
typedef _Return_type_success_(return != FALSE)
BOOL(WINAPI WINTUN_SET_ADAPTER_NAME_FUNC_IMPL)(_In_ WINTUN_ADAPTER_HANDLE Adapter, _In_z_ LPCWSTR Name);
typedef WINTUN_SET_ADAPTER_NAME_FUNC_IMPL *WINTUN_SET_ADAPTER_NAME_FUNC;

/**
 * Determines the version of the Wintun driver currently loaded.
 *
 * @return If the function succeeds, the return value is the version number. If the function fails, the return value is
 *         zero. To get extended error information, call GetLastError. Possible errors include the following:
 *         ERROR_FILE_NOT_FOUND  Wintun not loaded
 */
typedef _Return_type_success_(return != 0)
DWORD(WINAPI WINTUN_GET_RUNNING_DRIVER_VERSION_FUNC_IMPL)(VOID);
typedef WINTUN_GET_RUNNING_DRIVER_VERSION_FUNC_IMPL *WINTUN_GET_RUNNING_DRIVER_VERSION_FUNC;

/**
 * Determines the level of logging, passed to WINTUN_LOGGER_CALLBACK.
 */
typedef enum
{
    WINTUN_LOG_INFO, /**< Informational */
    WINTUN_LOG_WARN, /**< Warning */
    WINTUN_LOG_ERR   /**< Error */
} WINTUN_LOGGER_LEVEL;

/**
 * Called by internal logger to report diagnostic messages
 *
 * @param Level         Message level.
 *
 * @param Message       Message text.
 */
typedef VOID(CALLBACK *WINTUN_LOGGER_CALLBACK)(_In_ WINTUN_LOGGER_LEVEL Level, _In_z_ LPCWSTR Message);

/**
 * Sets logger callback function.
 *
 * @param NewLogger     Pointer to callback function to use as a new global logger. NewLogger may be called from various
 *                      threads concurrently. Should the logging require serialization, you must handle serialization in
 *                      NewLogger. Set to NULL to disable.
 */
typedef VOID(WINAPI WINTUN_SET_LOGGER_FUNC_IMPL)(_In_ WINTUN_LOGGER_CALLBACK NewLogger);
typedef WINTUN_SET_LOGGER_FUNC_IMPL *WINTUN_SET_LOGGER_FUNC;

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
typedef struct _TUN_SESSION *WINTUN_SESSION_HANDLE;

/**
 * Starts Wintun session.
 *
 * @param Adapter       Adapter handle obtained with WintunOpenAdapter or WintunCreateAdapter
 *
 * @param Capacity      Rings capacity. Must be between WINTUN_MIN_RING_CAPACITY and WINTUN_MAX_RING_CAPACITY (incl.)
 *                      Must be a power of two.
 *
 * @return Wintun session handle. Must be released with WintunEndSession. If the function fails, the return value is
 *         NULL. To get extended error information, call GetLastError.
 */
typedef _Must_inspect_result_
_Return_type_success_(return != NULL)
_Post_maybenull_
WINTUN_SESSION_HANDLE(WINAPI WINTUN_START_SESSION_FUNC_IMPL)(_In_ WINTUN_ADAPTER_HANDLE Adapter, _In_ DWORD Capacity);
typedef WINTUN_START_SESSION_FUNC_IMPL *WINTUN_START_SESSION_FUNC;

/**
 * Ends Wintun session.
 *
 * @param Session       Wintun session handle obtained with WintunStartSession
 */
typedef VOID(WINAPI WINTUN_END_SESSION_FUNC_IMPL)(_In_ WINTUN_SESSION_HANDLE Session);
typedef WINTUN_END_SESSION_FUNC_IMPL *WINTUN_END_SESSION_FUNC;

/**
 * Gets Wintun session's read-wait event handle.
 *
 * @param Session       Wintun session handle obtained with WintunStartSession
 *
 * @return Pointer to receive event handle to wait for available data when reading. Should
 *         WintunReceivePackets return ERROR_NO_MORE_ITEMS (after spinning on it for a while under heavy
 *         load), wait for this event to become signaled before retrying WintunReceivePackets. Do not call
 *         CloseHandle on this event - it is managed by the session.
 */
typedef HANDLE(WINAPI WINTUN_GET_READ_WAIT_EVENT_FUNC_IMPL)(_In_ WINTUN_SESSION_HANDLE Session);
typedef WINTUN_GET_READ_WAIT_EVENT_FUNC_IMPL *WINTUN_GET_READ_WAIT_EVENT_FUNC;

/**
 * Maximum IP packet size
 */
#define WINTUN_MAX_IP_PACKET_SIZE 0xFFFF

/**
 * Retrieves one or packet. After the packet content is consumed, call WintunReleaseReceivePacket with Packet returned
 * from this function to release internal buffer. This function is thread-safe.
 *
 * @param Session       Wintun session handle obtained with WintunStartSession
 *
 * @param PacketSize    Pointer to receive packet size.
 *
 * @return Pointer to layer 3 IPv4 or IPv6 packet. Client may modify its content at will. If the function fails, the
 *         return value is NULL. To get extended error information, call GetLastError. Possible errors include the
 *         following:
 *         ERROR_HANDLE_EOF     Wintun adapter is terminating;
 *         ERROR_NO_MORE_ITEMS  Wintun buffer is exhausted;
 *         ERROR_INVALID_DATA   Wintun buffer is corrupt
 */
typedef _Must_inspect_result_
_Return_type_success_(return != NULL)
_Post_maybenull_
_Post_writable_byte_size_(*PacketSize)
BYTE *(WINAPI WINTUN_RECEIVE_PACKET_FUNC_IMPL)(_In_ WINTUN_SESSION_HANDLE Session, _Out_ DWORD *PacketSize);
typedef WINTUN_RECEIVE_PACKET_FUNC_IMPL *WINTUN_RECEIVE_PACKET_FUNC;

/**
 * Releases internal buffer after the received packet has been processed by the client. This function is thread-safe.
 *
 * @param Session       Wintun session handle obtained with WintunStartSession
 *
 * @param Packet        Packet obtained with WintunReceivePacket
 */
typedef VOID(
    WINAPI WINTUN_RELEASE_RECEIVE_PACKET_FUNC_IMPL)(_In_ WINTUN_SESSION_HANDLE Session, _In_ const BYTE *Packet);
typedef WINTUN_RELEASE_RECEIVE_PACKET_FUNC_IMPL *WINTUN_RELEASE_RECEIVE_PACKET_FUNC;

/**
 * Allocates memory for a packet to send. After the memory is filled with packet data, call WintunSendPacket to send
 * and release internal buffer. WintunAllocateSendPacket is thread-safe and the WintunAllocateSendPacket order of
 * calls define the packet sending order.
 *
 * @param Session       Wintun session handle obtained with WintunStartSession
 *
 * @param PacketSize    Exact packet size. Must be less or equal to WINTUN_MAX_IP_PACKET_SIZE.
 *
 * @return Returns pointer to memory where to prepare layer 3 IPv4 or IPv6 packet for sending. If the function fails,
 *         the return value is NULL. To get extended error information, call GetLastError. Possible errors include the
 *         following:
 *         ERROR_HANDLE_EOF       Wintun adapter is terminating;
 *         ERROR_BUFFER_OVERFLOW  Wintun buffer is full;
 */
typedef _Must_inspect_result_
_Return_type_success_(return != NULL)
_Post_maybenull_
_Post_writable_byte_size_(PacketSize)
BYTE *(WINAPI WINTUN_ALLOCATE_SEND_PACKET_FUNC_IMPL)(_In_ WINTUN_SESSION_HANDLE Session, _In_ DWORD PacketSize);
typedef WINTUN_ALLOCATE_SEND_PACKET_FUNC_IMPL *WINTUN_ALLOCATE_SEND_PACKET_FUNC;

/**
 * Sends the packet and releases internal buffer. WintunSendPacket is thread-safe, but the WintunAllocateSendPacket
 * order of calls define the packet sending order. This means the packet is not guaranteed to be sent in the
 * WintunSendPacket yet.
 *
 * @param Session       Wintun session handle obtained with WintunStartSession
 *
 * @param Packet        Packet obtained with WintunAllocateSendPacket
 */
typedef VOID(WINAPI WINTUN_SEND_PACKET_FUNC_IMPL)(_In_ WINTUN_SESSION_HANDLE Session, _In_ const BYTE *Packet);
typedef WINTUN_SEND_PACKET_FUNC_IMPL *WINTUN_SEND_PACKET_FUNC;

#ifdef __cplusplus
}
#endif

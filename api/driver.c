/* SPDX-License-Identifier: GPL-2.0
 *
 * Copyright (C) 2018-2020 WireGuard LLC. All Rights Reserved.
 */

#include "pch.h"

#pragma warning(disable : 4221) /* nonstandard: address of automatic in initializer */

typedef struct _SP_DEVINFO_DATA_LIST
{
    SP_DEVINFO_DATA Data;
    struct _SP_DEVINFO_DATA_LIST *Next;
} SP_DEVINFO_DATA_LIST;

/**
 * Retrieves driver information detail for a device information set or a particular device information element in the
 * device information set.
 *
 * @param DevInfo       A handle to the device information set that contains a device information element that
 *                      represents the device for which to retrieve driver information.
 *
 * @param DevInfoData   A pointer to a structure that specifies the device information element in DevInfo.
 *
 * @param DrvInfoData   A pointer to a structure that specifies the driver information element that represents the
 *                      driver for which to retrieve details.
 *
 * @param DrvInfoDetailData  A pointer to a structure that receives detailed information about the specified driver.
 *                      Must be released with HeapFree(GetProcessHeap(), 0, *DrvInfoDetailData) after use.
 *
 * @return non-zero on success; zero otherwise - use GetLastError().
 */
_Return_type_success_(return != NULL) SP_DRVINFO_DETAIL_DATA_W *DriverGetDrvInfoDetail(
    _In_ HDEVINFO DevInfo,
    _In_opt_ SP_DEVINFO_DATA *DevInfoData,
    _In_ SP_DRVINFO_DATA_W *DrvInfoData)
{
    HANDLE Heap = GetProcessHeap();
    DWORD Size = sizeof(SP_DRVINFO_DETAIL_DATA_W) + 0x100;
    DWORD Result;
    for (;;)
    {
        SP_DRVINFO_DETAIL_DATA_W *DrvInfoDetailData = HeapAlloc(Heap, 0, Size);
        if (!DrvInfoDetailData)
        {
            Result = ERROR_OUTOFMEMORY;
            goto out;
        }
        DrvInfoDetailData->cbSize = sizeof(SP_DRVINFO_DETAIL_DATA_W);
        if (SetupDiGetDriverInfoDetailW(DevInfo, DevInfoData, DrvInfoData, DrvInfoDetailData, Size, &Size))
            return DrvInfoDetailData;
        Result = GetLastError();
        HeapFree(Heap, 0, DrvInfoDetailData);
        if (Result != ERROR_INSUFFICIENT_BUFFER)
        {
            WINTUN_LOGGER_ERROR(L"Failed", Result);
            goto out;
        }
    }
out:
    SetLastError(Result);
    return NULL;
}

/**
 * Checks if the device (i.e. network adapter) is using Wintun driver.
 *
 * @param DevInfo       A handle to the device information set that contains a device information element that
 *                      represents the device.
 *
 * @param DevInfoData   A pointer to a structure that specifies the device information element in DevInfo.
 *
 * @return non-zero when using Wintun driver; zero when not or error - use GetLastError().
 */
BOOL
DriverIsWintunAdapter(_In_ HDEVINFO DevInfo, _In_opt_ SP_DEVINFO_DATA *DevInfoData)
{
    BOOL Found = FALSE;
    if (!SetupDiBuildDriverInfoList(DevInfo, DevInfoData, SPDIT_COMPATDRIVER))
    {
        WINTUN_LOGGER_LAST_ERROR(L"Failed to build list of drivers");
        return FALSE;
    }
    HANDLE Heap = GetProcessHeap();
    for (DWORD EnumIndex = 0; !Found; ++EnumIndex)
    {
        SP_DRVINFO_DATA_W DrvInfoData = { .cbSize = sizeof(SP_DRVINFO_DATA_W) };
        if (!SetupDiEnumDriverInfoW(DevInfo, DevInfoData, SPDIT_COMPATDRIVER, EnumIndex, &DrvInfoData))
        {
            if (GetLastError() == ERROR_NO_MORE_ITEMS)
                break;
            continue;
        }
        SP_DRVINFO_DETAIL_DATA_W *DrvInfoDetailData = DriverGetDrvInfoDetail(DevInfo, DevInfoData, &DrvInfoData);
        if (!DrvInfoDetailData)
            continue;
        Found = !_wcsicmp(DrvInfoDetailData->HardwareID, WINTUN_HWID);
        HeapFree(Heap, 0, DrvInfoDetailData);
    }
    SetupDiDestroyDriverInfoList(DevInfo, DevInfoData, SPDIT_COMPATDRIVER);
    SetLastError(ERROR_SUCCESS);
    return Found;
}

/**
 * Returns a handle to the adapter device object.
 *
 * @param InstanceId    Adapter device instance ID.
 *
 * @return device handle on success; INVALID_HANDLE_VALUE otherwise - use GetLastError().
 */
_Return_type_success_(return != INVALID_HANDLE_VALUE) HANDLE
    DriverGetAdapterDeviceObject(_In_opt_z_ const WCHAR *InstanceId)
{
    HANDLE Heap = GetProcessHeap();
    ULONG InterfacesLen;
    HANDLE Handle = INVALID_HANDLE_VALUE;
    DWORD Result = CM_Get_Device_Interface_List_SizeW(
        &InterfacesLen, (GUID *)&GUID_DEVINTERFACE_NET, (DEVINSTID_W)InstanceId, CM_GET_DEVICE_INTERFACE_LIST_PRESENT);
    if (Result != CR_SUCCESS)
    {
        WINTUN_LOGGER(WINTUN_LOG_ERR, L"Failed to get device associated device instances size");
        SetLastError(ERROR_GEN_FAILURE);
        return INVALID_HANDLE_VALUE;
    }
    WCHAR *Interfaces = HeapAlloc(Heap, 0, InterfacesLen * sizeof(WCHAR));
    if (!Interfaces)
    {
        SetLastError(ERROR_OUTOFMEMORY);
        return INVALID_HANDLE_VALUE;
    }
    Result = CM_Get_Device_Interface_ListW(
        (GUID *)&GUID_DEVINTERFACE_NET,
        (DEVINSTID_W)InstanceId,
        Interfaces,
        InterfacesLen,
        CM_GET_DEVICE_INTERFACE_LIST_PRESENT);
    if (Result != CR_SUCCESS)
    {
        WINTUN_LOGGER(WINTUN_LOG_ERR, L"Failed to get device associated device instances");
        Result = ERROR_GEN_FAILURE;
        goto cleanupBuf;
    }
    Handle = CreateFileW(
        Interfaces,
        GENERIC_READ | GENERIC_WRITE,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        NULL,
        OPEN_EXISTING,
        0,
        NULL);
    Result = Handle != INVALID_HANDLE_VALUE ? ERROR_SUCCESS : WINTUN_LOGGER_LAST_ERROR(L"Failed to connect to device");
cleanupBuf:
    HeapFree(Heap, 0, Interfaces);
    SetLastError(Result);
    return Handle;
}

#if defined(HAVE_EV) || defined(HAVE_WHQL)

/* We can't use RtlGetVersion, because appcompat's aclayers.dll shims it to report Vista
 * when run from legacy contexts. So, we instead use the undocumented RtlGetNtVersionNumbers.
 *
 * Another way would be reading from the PEB directly:
 *   ((DWORD *)NtCurrentTeb()->ProcessEnvironmentBlock)[sizeof(void *) == 8 ? 70 : 41]
 * Or just read from KUSER_SHARED_DATA the same way on 32-bit and 64-bit:
 *    *(DWORD *)0x7FFE026C
 */
extern VOID NTAPI
RtlGetNtVersionNumbers(_Out_opt_ DWORD *MajorVersion, _Out_opt_ DWORD *MinorVersion, _Out_opt_ DWORD *BuildNumber);

/**
 * Queries driver availability and Windows requirement about driver signing model.
 *
 * @return non-zero when WHQL/Attestation-signed drivers are available and required; zero otherwise.
 */
static BOOL
HaveWHQL()
{
#    if defined(HAVE_EV) && defined(HAVE_WHQL)
    DWORD MajorVersion;
    RtlGetNtVersionNumbers(&MajorVersion, NULL, NULL);
    return MajorVersion >= 10;
#    elif defined(HAVE_EV)
    return FALSE;
#    elif defined(HAVE_WHQL)
    return TRUE;
#    endif
}

/**
 * Locates the white-space string span.
 *
 * \param Beg           String start
 *
 * \param End           String end (non-inclusive)
 *
 * \return First non-white-space character or string end.
 */
static const CHAR *
SkipWSpace(_In_ const CHAR *Beg, _In_ const CHAR *End)
{
    for (; Beg < End && iswspace(*Beg); ++Beg)
        ;
    return Beg;
}

/**
 * Locates the non-LF string span.
 *
 * \param Beg           String start
 *
 * \param End           String end (non-inclusive)
 *
 * \return First LF character or string end.
 */
static const CHAR *
SkipNonLF(_In_ const CHAR *Beg, _In_ const CHAR *End)
{
    for (; Beg < End && *Beg != '\n'; ++Beg)
        ;
    return Beg;
}

/**
 * Queries the version of the driver this wintun.dll is packing.
 *
 * DriverDate           Pointer to a variable to receive the driver date.
 *
 * DriverVersion        Pointer to a variable to receive the driver version.
 *
 * @return ERROR_SUCCESS on success; Win32 error code otherwise.
 */
WINTUN_STATUS
DriverGetVersion(_Out_ FILETIME *DriverDate, _Out_ DWORDLONG *DriverVersion)
{
    const VOID *LockedResource;
    DWORD SizeResource;
    DWORD Result = ResourceGetAddress(HaveWHQL() ? L"wintun-whql.inf" : L"wintun.inf", &LockedResource, &SizeResource);
    if (Result != ERROR_SUCCESS)
        return WINTUN_LOGGER_ERROR(L"Failed to locate resource", Result);
    enum
    {
        SectNone,
        SectUnknown,
        SectVersion
    } Section = SectNone;
    for (const CHAR *Inf = (const CHAR *)LockedResource, *InfEnd = Inf + SizeResource; Inf < InfEnd; ++Inf)
    {
        if (*Inf == ';')
        {
            Inf = SkipNonLF(Inf + 1, InfEnd);
            continue;
        }
        Inf = SkipWSpace(Inf, InfEnd);
        if (*Inf == '[')
        {
            Section = Inf + 9 <= InfEnd && !_strnicmp(Inf, "[Version]", 9) ? SectVersion : SectUnknown;
        }
        else if (Section == SectVersion)
        {
            if (Inf + 9 <= InfEnd && !_strnicmp(Inf, "DriverVer", 9))
            {
                Inf = SkipWSpace(Inf + 9, InfEnd);
                if (Inf < InfEnd && *Inf == '=')
                {
                    Inf = SkipWSpace(Inf + 1, InfEnd);
                    /* Duplicate buffer, as RT_RCDATA resource is not guaranteed to be zero-terminated. */
                    CHAR buf[0x100];
                    size_t n = InfEnd - Inf;
                    if (n >= _countof(buf))
                        n = _countof(buf) - 1;
                    strncpy_s(buf, _countof(buf), Inf, n);
                    buf[n] = 0;
                    const CHAR *p = buf;
                    CHAR *p_next;
                    unsigned long date[3] = { 0, 0, 0 };
                    for (size_t i = 0;; ++i, ++p)
                    {
                        date[i] = strtoul(p, &p_next, 10);
                        p = p_next;
                        if (i >= _countof(date) - 1)
                            break;
                        if (*p != '/' && *p != '-')
                        {
                            WINTUN_LOGGER(WINTUN_LOG_ERR, L"Unexpected date delimiter");
                            return ERROR_INVALID_DATA;
                        }
                    }
                    if (date[0] < 1 || date[0] > 12 || date[1] < 1 || date[1] > 31 || date[2] < 1601 || date[2] > 30827)
                    {
                        WINTUN_LOGGER(WINTUN_LOG_ERR, L"Invalid date");
                        return ERROR_INVALID_DATA;
                    }
                    const SYSTEMTIME st = { .wYear = (WORD)date[2], .wMonth = (WORD)date[0], .wDay = (WORD)date[1] };
                    SystemTimeToFileTime(&st, DriverDate);
                    p = SkipWSpace(p, buf + n);
                    ULONGLONG version[4] = { 0, 0, 0, 0 };
                    if (*p == ',')
                    {
                        p = SkipWSpace(p + 1, buf + n);
                        for (size_t i = 0;; ++i, ++p)
                        {
                            version[i] = strtoul(p, &p_next, 10);
                            if (version[i] > 0xffff)
                            {
                                WINTUN_LOGGER(WINTUN_LOG_ERR, L"Version field may not exceed 65535");
                                return ERROR_INVALID_DATA;
                            }
                            p = p_next;
                            if (i >= _countof(version) - 1 || !*p || *p == ';' || iswspace(*p))
                                break;
                            if (*p != '.')
                            {
                                WINTUN_LOGGER(WINTUN_LOG_ERR, L"Unexpected version delimiter");
                                return ERROR_INVALID_DATA;
                            }
                        }
                    }
                    *DriverVersion = (version[0] << 48) | (version[1] << 32) | (version[2] << 16) | version[3];
                    return ERROR_SUCCESS;
                }
            }
        }
        Inf = SkipNonLF(Inf, InfEnd);
    }
    WINTUN_LOGGER(WINTUN_LOG_ERR, L"DriverVer not found in INF resource");
    return ERROR_FILE_NOT_FOUND;
}

/**
 * Checks if the Wintun driver is loaded.
 *
 * Note: This function does not log any errors, not to flood the log when called from the EnsureDriverUnloaded() loop.
 *
 * @return non-zero when loaded; zero when not loaded or error - use GetLastError().
 */
static BOOL IsDriverLoaded(VOID)
{
    VOID *StackBuffer[0x80];
    VOID **Drivers = StackBuffer;
    DWORD Size = 0;
    if (!EnumDeviceDrivers(Drivers, sizeof(StackBuffer), &Size))
        return FALSE;
    if (Size > sizeof(StackBuffer))
    {
        HANDLE Heap = GetProcessHeap();
        Drivers = HeapAlloc(Heap, 0, Size);
        if (!Drivers)
        {
            SetLastError(ERROR_OUTOFMEMORY);
            return FALSE;
        }
        if (!EnumDeviceDrivers(Drivers, Size, &Size))
        {
            DWORD Result = GetLastError();
            HeapFree(Heap, 0, Drivers);
            SetLastError(Result);
            return FALSE;
        }
    }
    BOOL Found = FALSE;
    for (DWORD i = Size / sizeof(Drivers[0]); i-- > 0;)
    {
        WCHAR MaybeWintun[11];
        if (GetDeviceDriverBaseNameW(Drivers[i], MaybeWintun, _countof(MaybeWintun)) == 10 &&
            !_wcsicmp(MaybeWintun, L"wintun.sys"))
        {
            Found = TRUE;
            break;
        }
    }
    if (Drivers != StackBuffer)
        HeapFree(GetProcessHeap(), 0, Drivers);
    SetLastError(ERROR_SUCCESS);
    return Found;
}

/**
 * Polls for 15 sec until the Wintun driver is unloaded.
 *
 * @return non-zero if the driver unloaded; zero on error or timeout - use GetLastError().
 */
static BOOL EnsureDriverUnloaded(VOID)
{
    BOOL Loaded;
    for (int i = 0; (Loaded = IsDriverLoaded()) != 0 && i < 300; ++i)
        Sleep(50);
    return !Loaded;
}

/**
 * Installs code-signing certificate to the computer's Trusted Publishers certificate store.
 *
 * @param SignedResource  ID of the RT_RCDATA resource containing the signed binary to extract the code-signing
 *                      certificate from.
 *
 * @return ERROR_SUCCESS on success; Win32 error code otherwise.
 */
static WINTUN_STATUS
InstallCertificate(_In_z_ const WCHAR *SignedResource)
{
    WINTUN_LOGGER(WINTUN_LOG_INFO, L"Trusting code signing certificate");
    const VOID *LockedResource;
    DWORD SizeResource;
    DWORD Result = ResourceGetAddress(SignedResource, &LockedResource, &SizeResource);
    if (Result != ERROR_SUCCESS)
        return WINTUN_LOGGER_ERROR("Failed to locate resource", Result);
    const CERT_BLOB CertBlob = { .cbData = SizeResource, .pbData = (BYTE *)LockedResource };
    HCERTSTORE QueriedStore;
    if (!CryptQueryObject(
            CERT_QUERY_OBJECT_BLOB,
            &CertBlob,
            CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED_EMBED,
            CERT_QUERY_FORMAT_FLAG_ALL,
            0,
            0,
            0,
            0,
            &QueriedStore,
            0,
            NULL))
        return WINTUN_LOGGER_LAST_ERROR("Failed to find certificate");
    HCERTSTORE TrustedStore =
        CertOpenStore(CERT_STORE_PROV_SYSTEM, 0, 0, CERT_SYSTEM_STORE_LOCAL_MACHINE, L"TrustedPublisher");
    if (!TrustedStore)
    {
        Result = WINTUN_LOGGER_LAST_ERROR(L"Failed to open store");
        goto cleanupQueriedStore;
    }
    LPSTR CodeSigningOid[] = { szOID_PKIX_KP_CODE_SIGNING };
    CERT_ENHKEY_USAGE EnhancedUsage = { .cUsageIdentifier = 1, .rgpszUsageIdentifier = CodeSigningOid };
    for (const CERT_CONTEXT *CertContext = NULL; (CertContext = CertFindCertificateInStore(
                                                      QueriedStore,
                                                      X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
                                                      CERT_FIND_EXT_ONLY_ENHKEY_USAGE_FLAG,
                                                      CERT_FIND_ENHKEY_USAGE,
                                                      &EnhancedUsage,
                                                      CertContext)) != NULL;)
    {
        CERT_EXTENSION *Ext = CertFindExtension(
            szOID_BASIC_CONSTRAINTS2, CertContext->pCertInfo->cExtension, CertContext->pCertInfo->rgExtension);
        CERT_BASIC_CONSTRAINTS2_INFO Constraints;
        DWORD Size = sizeof(Constraints);
        if (Ext &&
            CryptDecodeObjectEx(
                X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
                szOID_BASIC_CONSTRAINTS2,
                Ext->Value.pbData,
                Ext->Value.cbData,
                0,
                NULL,
                &Constraints,
                &Size) &&
            !Constraints.fCA)
            if (!CertAddCertificateContextToStore(TrustedStore, CertContext, CERT_STORE_ADD_REPLACE_EXISTING, NULL))
            {
                WINTUN_LOGGER_LAST_ERROR(L"Failed to add certificate to store");
                Result = Result != ERROR_SUCCESS ? Result : GetLastError();
            }
    }
    CertCloseStore(TrustedStore, 0);
cleanupQueriedStore:
    CertCloseStore(QueriedStore, 0);
    return Result;
}

/**
 * Installs Wintun driver to the Windows driver store and updates existing adapters to use it.
 *
 * @param UpdateExisting  Set to non-zero when existing adapters should be upgraded to the newest driver.
 *
 * @return ERROR_SUCCESS on success; Win32 error code otherwise.
 */
static WINTUN_STATUS
InstallDriver(_In_ BOOL UpdateExisting)
{
    WCHAR WindowsDirectory[MAX_PATH];
    if (!GetWindowsDirectoryW(WindowsDirectory, _countof(WindowsDirectory)))
        return WINTUN_LOGGER_LAST_ERROR(L"Failed to get Windows folder");
    WCHAR WindowsTempDirectory[MAX_PATH];
    if (!PathCombineW(WindowsTempDirectory, WindowsDirectory, L"Temp"))
        return ERROR_BUFFER_OVERFLOW;
    UCHAR RandomBytes[32] = { 0 };
#    pragma warning(suppress : 6387)
    if (!RtlGenRandom(RandomBytes, sizeof(RandomBytes)))
        return WINTUN_LOGGER_LAST_ERROR(L"Failed to generate random");
    WCHAR RandomSubDirectory[sizeof(RandomBytes) * 2 + 1];
    for (int i = 0; i < sizeof(RandomBytes); ++i)
        swprintf_s(&RandomSubDirectory[i * 2], 3, L"%02x", RandomBytes[i]);
    WCHAR RandomTempSubDirectory[MAX_PATH];
    if (!PathCombineW(RandomTempSubDirectory, WindowsTempDirectory, RandomSubDirectory))
        return ERROR_BUFFER_OVERFLOW;
    SECURITY_ATTRIBUTES SecurityAttributes = { .nLength = sizeof(SecurityAttributes) };
    if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(
            L"O:SYD:P(A;;GA;;;SY)", SDDL_REVISION_1, &SecurityAttributes.lpSecurityDescriptor, NULL))
        return WINTUN_LOGGER_LAST_ERROR(L"Failed to convert security descriptor");
    DWORD Result = ERROR_SUCCESS;
    if (!CreateDirectoryW(RandomTempSubDirectory, &SecurityAttributes))
    {
        Result = WINTUN_LOGGER_LAST_ERROR(L"Failed to create temporary folder");
        goto cleanupFree;
    }

    WCHAR CatPath[MAX_PATH] = { 0 };
    WCHAR SysPath[MAX_PATH] = { 0 };
    WCHAR InfPath[MAX_PATH] = { 0 };
    if (!PathCombineW(CatPath, RandomTempSubDirectory, L"wintun.cat") ||
        !PathCombineW(SysPath, RandomTempSubDirectory, L"wintun.sys") ||
        !PathCombineW(InfPath, RandomTempSubDirectory, L"wintun.inf"))
    {
        Result = ERROR_BUFFER_OVERFLOW;
        goto cleanupFree;
    }

    BOOL UseWHQL = HaveWHQL();
    if (!UseWHQL && (Result = InstallCertificate(L"wintun.sys")) != ERROR_SUCCESS)
        WINTUN_LOGGER_ERROR(L"Unable to install code signing certificate", Result);

    WINTUN_LOGGER(WINTUN_LOG_INFO, L"Copying resources to temporary path");
    if ((Result = ResourceCopyToFile(CatPath, &SecurityAttributes, UseWHQL ? L"wintun-whql.cat" : L"wintun.cat")) !=
            ERROR_SUCCESS ||
        (Result = ResourceCopyToFile(SysPath, &SecurityAttributes, UseWHQL ? L"wintun-whql.sys" : L"wintun.sys")) !=
            ERROR_SUCCESS ||
        (Result = ResourceCopyToFile(InfPath, &SecurityAttributes, UseWHQL ? L"wintun-whql.inf" : L"wintun.inf")) !=
            ERROR_SUCCESS)
    {
        Result = WINTUN_LOGGER_LAST_ERROR(L"Failed to copy resources");
        goto cleanupDelete;
    }

    WINTUN_LOGGER(WINTUN_LOG_INFO, L"Installing driver");
    if (!SetupCopyOEMInfW(InfPath, NULL, SPOST_PATH, 0, NULL, 0, NULL, NULL))
        Result = WINTUN_LOGGER_LAST_ERROR(L"Could not install driver to store");
    BOOL RebootRequired = FALSE;
    if (UpdateExisting &&
        !UpdateDriverForPlugAndPlayDevicesW(
            NULL, WINTUN_HWID, InfPath, INSTALLFLAG_FORCE | INSTALLFLAG_NONINTERACTIVE, &RebootRequired))
        WINTUN_LOGGER_LAST_ERROR(L"Could not update existing adapters");
    if (RebootRequired)
        WINTUN_LOGGER(WINTUN_LOG_WARN, L"A reboot might be required, which really should not be the case");

cleanupDelete:
    DeleteFileW(CatPath);
    DeleteFileW(SysPath);
    DeleteFileW(InfPath);
    RemoveDirectoryW(RandomTempSubDirectory);
cleanupFree:
    LocalFree(SecurityAttributes.lpSecurityDescriptor);
    return Result;
}

/**
 * Removes Wintun driver from the Windows driver store.
 *
 * @return ERROR_SUCCESS on success; Win32 error code otherwise.
 */
static WINTUN_STATUS RemoveDriver(VOID)
{
    HDEVINFO DevInfo = SetupDiGetClassDevsW(&GUID_DEVCLASS_NET, NULL, NULL, 0);
    if (!DevInfo)
        return WINTUN_LOGGER_LAST_ERROR(L"Failed to request device information");
    DWORD Result = ERROR_SUCCESS;
    if (!SetupDiBuildDriverInfoList(DevInfo, NULL, SPDIT_CLASSDRIVER))
    {
        Result = WINTUN_LOGGER_LAST_ERROR(L"Failed to build list of drivers");
        goto cleanupDeviceInfoSet;
    }
    HANDLE Heap = GetProcessHeap();
    for (DWORD EnumIndex = 0;; ++EnumIndex)
    {
        SP_DRVINFO_DATA_W DrvInfoData = { .cbSize = sizeof(DrvInfoData) };
        if (!SetupDiEnumDriverInfoW(DevInfo, NULL, SPDIT_CLASSDRIVER, EnumIndex, &DrvInfoData))
        {
            if (GetLastError() == ERROR_NO_MORE_ITEMS)
                break;
            continue;
        }
        SP_DRVINFO_DETAIL_DATA_W *DrvInfoDetailData = DriverGetDrvInfoDetail(DevInfo, NULL, &DrvInfoData);
        if (!DrvInfoDetailData)
            continue;
        if (!_wcsicmp(DrvInfoDetailData->HardwareID, WINTUN_HWID))
        {
            PathStripPathW(DrvInfoDetailData->InfFileName);
            WINTUN_LOGGER(WINTUN_LOG_INFO, L"Removing existing driver");
            if (!SetupUninstallOEMInfW(DrvInfoDetailData->InfFileName, SUOI_FORCEDELETE, NULL))
            {
                WINTUN_LOGGER_LAST_ERROR(L"Unable to remove existing driver");
                Result = Result != ERROR_SUCCESS ? Result : GetLastError();
            }
        }
        HeapFree(Heap, 0, DrvInfoDetailData);
    }
    SetupDiDestroyDriverInfoList(DevInfo, NULL, SPDIT_CLASSDRIVER);
cleanupDeviceInfoSet:
    SetupDiDestroyDeviceInfoList(DevInfo);
    return Result;
}

#    define TUN_IOCTL_FORCE_CLOSE_HANDLES CTL_CODE(51820U, 0x971U, METHOD_NEITHER, FILE_READ_DATA | FILE_WRITE_DATA)

/**
 * Closes all client handles to the Wintun adapter.
 *
 * @param DevInfo       A handle to the device information set that contains a device information element that
 *                      represents the device.
 *
 * @param DevInfoData   A pointer to a structure that specifies the device information element in DevInfo.
 *
 * @return ERROR_SUCCESS on success; Win32 error code otherwise.
 */
static WINTUN_STATUS
ForceCloseWintunAdapterHandle(_In_ HDEVINFO DevInfo, _In_ SP_DEVINFO_DATA *DevInfoData)
{
    DWORD Result = ERROR_SUCCESS;
    DWORD RequiredBytes;
    if (SetupDiGetDeviceInstanceIdW(DevInfo, DevInfoData, NULL, 0, &RequiredBytes) ||
        (Result = GetLastError()) != ERROR_INSUFFICIENT_BUFFER)
        return WINTUN_LOGGER_ERROR(L"Failed to query device instance ID size", Result);
    HANDLE Heap = GetProcessHeap();
    WCHAR *InstanceId = HeapAlloc(Heap, HEAP_ZERO_MEMORY, sizeof(*InstanceId) * RequiredBytes);
    if (!InstanceId)
        return ERROR_OUTOFMEMORY;
    if (!SetupDiGetDeviceInstanceIdW(DevInfo, DevInfoData, InstanceId, RequiredBytes, &RequiredBytes))
    {
        Result = WINTUN_LOGGER_LAST_ERROR(L"Failed to get device instance ID");
        goto out;
    }
    HANDLE NdisHandle = DriverGetAdapterDeviceObject(InstanceId);
    if (NdisHandle == INVALID_HANDLE_VALUE)
    {
        Result = GetLastError();
        goto out;
    }
    Result = DeviceIoControl(NdisHandle, TUN_IOCTL_FORCE_CLOSE_HANDLES, NULL, 0, NULL, 0, &RequiredBytes, NULL)
                 ? ERROR_SUCCESS
                 : WINTUN_LOGGER_LAST_ERROR(L"Failed to perform ioctl");
    CloseHandle(NdisHandle);
out:
    HeapFree(Heap, 0, InstanceId);
    return Result;
}

/**
 * Disables Wintun adapters.
 *
 * @param DevInfo       A handle to the device information set.
 *
 * @param DisabledAdapters  Output list of disabled adapters. The adapters disabled are inserted in the list head.
 *
 * @return ERROR_SUCCESS on success; Win32 error code otherwise.
 */
static WINTUN_STATUS
DisableWintunAdapters(_In_ HDEVINFO DevInfo, _Inout_ SP_DEVINFO_DATA_LIST **DisabledAdapters)
{
    SP_PROPCHANGE_PARAMS Params = { .ClassInstallHeader = { .cbSize = sizeof(SP_CLASSINSTALL_HEADER),
                                                            .InstallFunction = DIF_PROPERTYCHANGE },
                                    .StateChange = DICS_DISABLE,
                                    .Scope = DICS_FLAG_GLOBAL };
    DWORD Result = ERROR_SUCCESS;
    HANDLE Heap = GetProcessHeap();
    for (DWORD EnumIndex = 0;; ++EnumIndex)
    {
        SP_DEVINFO_DATA_LIST *DeviceNode = HeapAlloc(Heap, 0, sizeof(SP_DEVINFO_DATA_LIST));
        if (!DeviceNode)
            return ERROR_OUTOFMEMORY;
        DeviceNode->Data.cbSize = sizeof(SP_DEVINFO_DATA);
        if (!SetupDiEnumDeviceInfo(DevInfo, EnumIndex, &DeviceNode->Data))
        {
            if (GetLastError() == ERROR_NO_MORE_ITEMS)
            {
                HeapFree(Heap, 0, DeviceNode);
                break;
            }
            goto cleanupDeviceInfoData;
        }
        if (!DriverIsWintunAdapter(DevInfo, &DeviceNode->Data))
            goto cleanupDeviceInfoData;

        ULONG Status, ProblemCode;
        if (CM_Get_DevNode_Status(&Status, &ProblemCode, DeviceNode->Data.DevInst, 0) != CR_SUCCESS ||
            ((Status & DN_HAS_PROBLEM) && ProblemCode == CM_PROB_DISABLED))
            goto cleanupDeviceInfoData;

        WINTUN_LOGGER(WINTUN_LOG_INFO, L"Force closing all open handles for existing adapter");
        if (ForceCloseWintunAdapterHandle(DevInfo, &DeviceNode->Data) != ERROR_SUCCESS)
            WINTUN_LOGGER(WINTUN_LOG_WARN, L"Failed to force close adapter handles");
        Sleep(200);

        WINTUN_LOGGER(WINTUN_LOG_INFO, L"Disabling existing adapter");
        if (!SetupDiSetClassInstallParamsW(DevInfo, &DeviceNode->Data, &Params.ClassInstallHeader, sizeof(Params)) ||
            !SetupDiCallClassInstaller(DIF_PROPERTYCHANGE, DevInfo, &DeviceNode->Data))
        {
            WINTUN_LOGGER_LAST_ERROR(L"Unable to disable existing adapter");
            Result = Result != ERROR_SUCCESS ? Result : GetLastError();
            goto cleanupDeviceInfoData;
        }

        DeviceNode->Next = *DisabledAdapters;
        *DisabledAdapters = DeviceNode;
        continue;

    cleanupDeviceInfoData:
        HeapFree(Heap, 0, &DeviceNode->Data);
    }
    return Result;
}

/**
 * Removes all Wintun adapters.
 *
 * @param DevInfo       A handle to the device information set.
 *
 * @param DisabledAdapters  Output list of disabled adapters.
 *
 * @return ERROR_SUCCESS on success; Win32 error code otherwise.
 */
static WINTUN_STATUS
RemoveWintunAdapters(_In_ HDEVINFO DevInfo)
{
    SP_REMOVEDEVICE_PARAMS Params = { .ClassInstallHeader = { .cbSize = sizeof(SP_CLASSINSTALL_HEADER),
                                                              .InstallFunction = DIF_REMOVE },
                                      .Scope = DI_REMOVEDEVICE_GLOBAL };
    DWORD Result = ERROR_SUCCESS;
    for (DWORD EnumIndex = 0;; ++EnumIndex)
    {
        SP_DEVINFO_DATA DevInfoData = { .cbSize = sizeof(SP_DEVINFO_DATA) };
        if (!SetupDiEnumDeviceInfo(DevInfo, EnumIndex, &DevInfoData))
        {
            if (GetLastError() == ERROR_NO_MORE_ITEMS)
                break;
            continue;
        }
        if (!DriverIsWintunAdapter(DevInfo, &DevInfoData))
            continue;

        WINTUN_LOGGER(WINTUN_LOG_INFO, L"Force closing all open handles for existing adapter");
        if (ForceCloseWintunAdapterHandle(DevInfo, &DevInfoData) != ERROR_SUCCESS)
            WINTUN_LOGGER(WINTUN_LOG_WARN, L"Failed to force close adapter handles");
        Sleep(200);

        WINTUN_LOGGER(WINTUN_LOG_INFO, L"Removing existing adapter");
        if (!SetupDiSetClassInstallParamsW(DevInfo, &DevInfoData, &Params.ClassInstallHeader, sizeof(Params)) ||
            !SetupDiCallClassInstaller(DIF_REMOVE, DevInfo, &DevInfoData))
        {
            WINTUN_LOGGER_LAST_ERROR(L"Unable to remove existing adapter");
            Result = Result != ERROR_SUCCESS ? Result : GetLastError();
        }
    }
    return Result;
}

/**
 * Enables Wintun adapters.
 *
 * @param DevInfo       A handle to the device information set.
 *
 * @param AdaptersToEnable  Input list of adapters to enable.
 *
 * @return ERROR_SUCCESS on success; Win32 error code otherwise.
 */
static WINTUN_STATUS
EnableWintunAdapters(_In_ HDEVINFO DevInfo, _In_ SP_DEVINFO_DATA_LIST *AdaptersToEnable)
{
    SP_PROPCHANGE_PARAMS Params = { .ClassInstallHeader = { .cbSize = sizeof(SP_CLASSINSTALL_HEADER),
                                                            .InstallFunction = DIF_PROPERTYCHANGE },
                                    .StateChange = DICS_ENABLE,
                                    .Scope = DICS_FLAG_GLOBAL };
    DWORD Result = ERROR_SUCCESS;
    for (SP_DEVINFO_DATA_LIST *DeviceNode = AdaptersToEnable; DeviceNode; DeviceNode = DeviceNode->Next)
    {
        WINTUN_LOGGER(WINTUN_LOG_INFO, L"Enabling existing adapter");
        if (!SetupDiSetClassInstallParamsW(DevInfo, &DeviceNode->Data, &Params.ClassInstallHeader, sizeof(Params)) ||
            !SetupDiCallClassInstaller(DIF_PROPERTYCHANGE, DevInfo, &DeviceNode->Data))
        {
            WINTUN_LOGGER_LAST_ERROR(L"Unable to enable existing adapter");
            Result = Result != ERROR_SUCCESS ? Result : GetLastError();
        }
    }
    return Result;
}

/**
 * Installs or updates Wintun driver.
 *
 * @return ERROR_SUCCESS on success; Win32 error code otherwise.
 */
WINTUN_STATUS DriverInstallOrUpdate(VOID)
{
    HANDLE Heap = GetProcessHeap();
    HDEVINFO DevInfo = SetupDiGetClassDevsExW(&GUID_DEVCLASS_NET, NULL, NULL, DIGCF_PRESENT, NULL, NULL, NULL);
    if (DevInfo == INVALID_HANDLE_VALUE)
        return WINTUN_LOGGER_LAST_ERROR(L"Failed to get present class devices");
    SP_DEVINFO_DATA_LIST *ExistingAdapters = NULL;
    if (IsDriverLoaded())
    {
        DisableWintunAdapters(DevInfo, &ExistingAdapters);
        WINTUN_LOGGER(WINTUN_LOG_INFO, L"Waiting for driver to unload from kernel");
        if (!EnsureDriverUnloaded())
            WINTUN_LOGGER(WINTUN_LOG_WARN, L"Unable to unload driver, which means a reboot will likely be required");
    }
    DWORD Result = ERROR_SUCCESS;
    if ((Result = RemoveDriver()) != ERROR_SUCCESS)
    {
        WINTUN_LOGGER_ERROR(L"Failed to uninstall old drivers", Result);
        goto cleanupAdapters;
    }
    if ((Result = InstallDriver(!!ExistingAdapters)) != ERROR_SUCCESS)
    {
        WINTUN_LOGGER_ERROR(L"Failed to install driver", Result);
        goto cleanupAdapters;
    }
    WINTUN_LOGGER(WINTUN_LOG_INFO, L"Installation successful");

cleanupAdapters:;
    if (ExistingAdapters)
    {
        EnableWintunAdapters(DevInfo, ExistingAdapters);
        while (ExistingAdapters)
        {
            SP_DEVINFO_DATA_LIST *Next = ExistingAdapters->Next;
            HeapFree(Heap, 0, ExistingAdapters);
            ExistingAdapters = Next;
        }
    }
    SetupDiDestroyDeviceInfoList(DevInfo);
    return Result;
}

/**
 * Uninstalls Wintun driver.
 *
 * @return ERROR_SUCCESS on success; Win32 error code otherwise.
 */
WINTUN_STATUS DriverUninstall(VOID)
{
    HDEVINFO DevInfo = SetupDiGetClassDevsExW(&GUID_DEVCLASS_NET, NULL, NULL, DIGCF_PRESENT, NULL, NULL, NULL);
    if (DevInfo == INVALID_HANDLE_VALUE)
        return WINTUN_LOGGER_LAST_ERROR(L"Failed to get present class devices");
    RemoveWintunAdapters(DevInfo);
    DWORD Result = RemoveDriver();
    if (Result != ERROR_SUCCESS)
        WINTUN_LOGGER_ERROR(L"Failed to uninstall driver", Result);
    else
        WINTUN_LOGGER(WINTUN_LOG_INFO, L"Uninstallation successful");
    return Result;
}

#endif

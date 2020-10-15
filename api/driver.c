/* SPDX-License-Identifier: GPL-2.0
 *
 * Copyright (C) 2018-2020 WireGuard LLC. All Rights Reserved.
 */

#include "pch.h"

#pragma warning(disable : 4221) /* nonstandard: address of automatic in initializer */

/**
 * Tests if any of the hardware IDs match ours.
 *
 * @param Hwids         Multi-string containing a list of hardware IDs.
 *
 * @return TRUE on match; FALSE otherwise.
 */
BOOL
DriverIsOurHardwareID(_In_z_ const WCHAR *Hwids)
{
    for (; Hwids[0]; Hwids += wcslen(Hwids) + 1)
        if (!_wcsicmp(Hwids, WINTUN_HWID))
            return TRUE;
    return FALSE;
}

/**
 * Tests if hardware ID or any of the compatible IDs match ours.
 *
 * @param DrvInfoDetailData  Detailed information about a particular driver information structure.
 *
 * @return TRUE on match; FALSE otherwise.
 */
BOOL
DriverIsOurDrvInfoDetail(_In_ const SP_DRVINFO_DETAIL_DATA_W *DrvInfoDetailData)
{
    return DrvInfoDetailData->CompatIDsOffset > 1 && !_wcsicmp(DrvInfoDetailData->HardwareID, WINTUN_HWID) ||
           DrvInfoDetailData->CompatIDsLength &&
               DriverIsOurHardwareID(DrvInfoDetailData->HardwareID + DrvInfoDetailData->CompatIDsOffset);
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
        return LOG(WINTUN_LOG_ERR, L"Failed to locate resource"), Result;
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
                            LOG(WINTUN_LOG_ERR, L"Unexpected date delimiter");
                            return ERROR_INVALID_DATA;
                        }
                    }
                    if (date[0] < 1 || date[0] > 12 || date[1] < 1 || date[1] > 31 || date[2] < 1601 || date[2] > 30827)
                    {
                        LOG(WINTUN_LOG_ERR, L"Invalid date");
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
                                LOG(WINTUN_LOG_ERR, L"Version field may not exceed 65535");
                                return ERROR_INVALID_DATA;
                            }
                            p = p_next;
                            if (i >= _countof(version) - 1 || !*p || *p == ';' || iswspace(*p))
                                break;
                            if (*p != '.')
                            {
                                LOG(WINTUN_LOG_ERR, L"Unexpected version delimiter");
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
    LOG(WINTUN_LOG_ERR, L"DriverVer not found in INF resource");
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
    LOG(WINTUN_LOG_INFO, L"Trusting code signing certificate");
    const VOID *LockedResource;
    DWORD SizeResource;
    DWORD Result = ResourceGetAddress(SignedResource, &LockedResource, &SizeResource);
    if (Result != ERROR_SUCCESS)
        return LOG(WINTUN_LOG_ERR, L"Failed to locate resource"), Result;
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
        return LOG_LAST_ERROR(L"Failed to find certificate");
    HCERTSTORE TrustedStore =
        CertOpenStore(CERT_STORE_PROV_SYSTEM, 0, 0, CERT_SYSTEM_STORE_LOCAL_MACHINE, L"TrustedPublisher");
    if (!TrustedStore)
    {
        Result = LOG_LAST_ERROR(L"Failed to open store");
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
                LOG_LAST_ERROR(L"Failed to add certificate to store");
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
        return LOG_LAST_ERROR(L"Failed to get Windows folder");
    WCHAR WindowsTempDirectory[MAX_PATH];
    if (!PathCombineW(WindowsTempDirectory, WindowsDirectory, L"Temp"))
        return ERROR_BUFFER_OVERFLOW;
    UCHAR RandomBytes[32] = { 0 };
#    pragma warning(suppress : 6387)
    if (!RtlGenRandom(RandomBytes, sizeof(RandomBytes)))
        return LOG_LAST_ERROR(L"Failed to generate random");
    WCHAR RandomSubDirectory[sizeof(RandomBytes) * 2 + 1];
    for (int i = 0; i < sizeof(RandomBytes); ++i)
        swprintf_s(&RandomSubDirectory[i * 2], 3, L"%02x", RandomBytes[i]);
    WCHAR RandomTempSubDirectory[MAX_PATH];
    if (!PathCombineW(RandomTempSubDirectory, WindowsTempDirectory, RandomSubDirectory))
        return ERROR_BUFFER_OVERFLOW;
    SECURITY_ATTRIBUTES SecurityAttributes = { .nLength = sizeof(SecurityAttributes) };
    if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(
            L"O:SYD:P(A;;GA;;;SY)", SDDL_REVISION_1, &SecurityAttributes.lpSecurityDescriptor, NULL))
        return LOG_LAST_ERROR(L"Failed to convert security descriptor");
    DWORD Result = ERROR_SUCCESS;
    if (!CreateDirectoryW(RandomTempSubDirectory, &SecurityAttributes))
    {
        Result = LOG_LAST_ERROR(L"Failed to create temporary folder");
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
        LOG(WINTUN_LOG_WARN, L"Unable to install code signing certificate");

    LOG(WINTUN_LOG_INFO, L"Copying resources to temporary path");
    if ((Result = ResourceCopyToFile(CatPath, &SecurityAttributes, UseWHQL ? L"wintun-whql.cat" : L"wintun.cat")) !=
            ERROR_SUCCESS ||
        (Result = ResourceCopyToFile(SysPath, &SecurityAttributes, UseWHQL ? L"wintun-whql.sys" : L"wintun.sys")) !=
            ERROR_SUCCESS ||
        (Result = ResourceCopyToFile(InfPath, &SecurityAttributes, UseWHQL ? L"wintun-whql.inf" : L"wintun.inf")) !=
            ERROR_SUCCESS)
    {
        LOG(WINTUN_LOG_ERR, L"Failed to copy resources");
        goto cleanupDelete;
    }

    LOG(WINTUN_LOG_INFO, L"Installing driver");
    if (!SetupCopyOEMInfW(InfPath, NULL, SPOST_PATH, 0, NULL, 0, NULL, NULL))
        Result = LOG_LAST_ERROR(L"Could not install driver to store");
    BOOL RebootRequired = FALSE;
    if (UpdateExisting &&
        !UpdateDriverForPlugAndPlayDevicesW(
            NULL, WINTUN_HWID, InfPath, INSTALLFLAG_FORCE | INSTALLFLAG_NONINTERACTIVE, &RebootRequired))
        LOG_LAST_ERROR(L"Could not update existing adapters");
    if (RebootRequired)
        LOG(WINTUN_LOG_WARN, L"A reboot might be required, which really should not be the case");

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
        return LOG_LAST_ERROR(L"Failed to request device information");
    DWORD Result = ERROR_SUCCESS;
    if (!SetupDiBuildDriverInfoList(DevInfo, NULL, SPDIT_CLASSDRIVER))
    {
        Result = LOG_LAST_ERROR(L"Failed to build list of drivers");
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
        SP_DRVINFO_DETAIL_DATA_W *DrvInfoDetailData;
        if (AdapterGetDrvInfoDetail(DevInfo, NULL, &DrvInfoData, &DrvInfoDetailData) != ERROR_SUCCESS)
        {
            LOG(WINTUN_LOG_WARN, L"Failed getting driver info detail");
            continue;
        }
        if (!DriverIsOurDrvInfoDetail(DrvInfoDetailData))
        {
            HeapFree(Heap, 0, DrvInfoDetailData);
            continue;
        }
        PathStripPathW(DrvInfoDetailData->InfFileName);
        LOG(WINTUN_LOG_INFO, L"Removing existing driver");
        if (!SetupUninstallOEMInfW(DrvInfoDetailData->InfFileName, SUOI_FORCEDELETE, NULL))
        {
            LOG_LAST_ERROR(L"Unable to remove existing driver");
            Result = Result != ERROR_SUCCESS ? Result : GetLastError();
        }
        HeapFree(Heap, 0, DrvInfoDetailData);
    }
    SetupDiDestroyDriverInfoList(DevInfo, NULL, SPDIT_CLASSDRIVER);
cleanupDeviceInfoSet:
    SetupDiDestroyDeviceInfoList(DevInfo);
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
        return LOG_LAST_ERROR(L"Failed to get present class devices");
    SP_DEVINFO_DATA_LIST *ExistingAdapters = NULL;
    if (IsDriverLoaded())
    {
        AdapterDisableAllOurs(DevInfo, &ExistingAdapters);
        LOG(WINTUN_LOG_INFO, L"Waiting for driver to unload from kernel");
        if (!EnsureDriverUnloaded())
            LOG(WINTUN_LOG_WARN, L"Unable to unload driver, which means a reboot will likely be required");
    }
    DWORD Result = ERROR_SUCCESS;
    if ((Result = RemoveDriver()) != ERROR_SUCCESS)
    {
        LOG(WINTUN_LOG_ERR, L"Failed to uninstall old drivers");
        goto cleanupAdapters;
    }
    if ((Result = InstallDriver(!!ExistingAdapters)) != ERROR_SUCCESS)
    {
        LOG(WINTUN_LOG_ERR, L"Failed to install driver");
        goto cleanupAdapters;
    }
    LOG(WINTUN_LOG_INFO, L"Installation successful");

cleanupAdapters:;
    if (ExistingAdapters)
    {
        AdapterEnableAll(DevInfo, ExistingAdapters);
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
    AdapterDeleteAllOurs();
    DWORD Result = RemoveDriver();
    if (Result == ERROR_SUCCESS)
        LOG(WINTUN_LOG_INFO, L"Uninstallation successful");
    else
        LOG(WINTUN_LOG_ERR, L"Failed to uninstall driver");
    return Result;
}

#endif

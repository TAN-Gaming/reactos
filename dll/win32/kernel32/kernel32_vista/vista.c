/*
 * COPYRIGHT:       See COPYING in the top level directory
 * PROJECT:         ReactOS system libraries
 * PURPOSE:         Vista functions
 * PROGRAMMER:      Thomas Weidenmueller <w3seek@reactos.com>
 */

/* INCLUDES *******************************************************************/

#include <k32_vista.h>

#if _WIN32_WINNT != _WIN32_WINNT_VISTA
#error "This file must be compiled with _WIN32_WINNT == _WIN32_WINNT_VISTA"
#endif

// This is defined only in ntifs.h
#define REPARSE_DATA_BUFFER_HEADER_SIZE   FIELD_OFFSET(REPARSE_DATA_BUFFER, GenericReparseBuffer)

#define NDEBUG
#include <debug.h>

/* INTERNAL FUNCTIONS *********************************************************/

/**
 * @brief
 * Maps an NT "\Device\..." path to its Win32 "DOS" equivalent.
 *
 * @param[in]   DevicePath
 * The NT device path to convert.
 *
 * @param[out]  DosPath
 * Pointer to the newly allocated and initialized Unicode string.
 * Receives the converted Win32 path.
 *
 * @return
 * Returns NTSTATUS error codes.
 *
 * @remarks
 * The caller is responsible for freeing the destination string,
 * by calling RtlFreeUnicodeString.
 **/
static
NTSTATUS
DevicePathToDosPathU(
    _In_ PCUNICODE_STRING DevicePath,
    _Out_ PUNICODE_STRING DosPath)
{
    UNICODE_STRING DevicePathPrefix = RTL_CONSTANT_STRING(L"\\Device\\");
    LPWSTR pszDevicePath;
    LPWSTR pszDosPath = NULL;
    DWORD dwDosPathLength;
    WCHAR szDrive[3] = L"?:";
    WCHAR szDeviceName[MAX_PATH];
    NTSTATUS Status = STATUS_NOT_FOUND;

    /* Check if DevicePath is a device path */
    if (!RtlPrefixUnicodeString(&DevicePathPrefix, DevicePath, TRUE))
    {
        return STATUS_OBJECT_PATH_INVALID;
    }

    pszDevicePath = RtlAllocateHeap(RtlGetProcessHeap(), 0, DevicePath->Length + sizeof(WCHAR));

    if (!pszDevicePath)
    {
        return STATUS_NO_MEMORY;
    }

    RtlStringCbCopyNW(pszDevicePath, DevicePath->Length + sizeof(WCHAR), DevicePath->Buffer, DevicePath->Length);

    for (szDrive[0] = L'A'; szDrive[0] <= L'`'; szDrive[0]++)
    {
        if (QueryDosDeviceW(szDrive, szDeviceName, _countof(szDeviceName)) != 0)
        {
            size_t len = wcslen(szDeviceName);

            if (_wcsnicmp(pszDevicePath, szDeviceName, len) == 0)
            {
                /* Get required length, including the NULL terminator */
                dwDosPathLength = _countof(szDrive) + wcslen(pszDevicePath + len);

                pszDosPath = RtlAllocateHeap(RtlGetProcessHeap(), 0, dwDosPathLength * sizeof(WCHAR));

                if (!pszDosPath)
                {
                    Status = STATUS_NO_MEMORY;
                    break;
                }

                RtlStringCchPrintfW(pszDosPath, dwDosPathLength, L"%s%s",
                                    szDrive, pszDevicePath + len);

                if (!RtlCreateUnicodeString(DosPath, pszDosPath))
                {
                    Status = STATUS_INSUFFICIENT_RESOURCES;
                    break;
                }

                Status = STATUS_SUCCESS;
                break;
            }
        }
    }

    RtlFreeHeap(RtlGetProcessHeap(), 0, pszDosPath);
    RtlFreeHeap(RtlGetProcessHeap(), 0, pszDevicePath);

    return Status;
}

/* PUBLIC FUNCTIONS ***********************************************************/

/*
 * @implemented
 */
BOOL
WINAPI
QueryFullProcessImageNameW(
    _In_ HANDLE hProcess,
    _In_ DWORD dwFlags,
    _Out_z_cap_post_count_(*pdwSize, *pdwSize + 1)
        LPWSTR lpExeName,
    _Inout_ PDWORD pdwSize)
{
    PROCESSINFOCLASS ProcessInfoClass;
    BYTE Buffer[sizeof(UNICODE_STRING) + (MAX_PATH * sizeof(WCHAR))];
    PVOID DynamicBuffer = NULL;
    PUNICODE_STRING Result;
    NTSTATUS Status;
    ULONG Needed;

#if 0
    if (dwFlags == 0)
    {
        /* The name should use the Win32 path format */
        ProcessInfoClass = ProcessImageFileNameWin32;
    }
    else if (dwFlags == PROCESS_NAME_NATIVE)
    {
        /* The name should use the native system path format */
        ProcessInfoClass = ProcessImageFileName;
    }
    else
    {
        BaseSetLastNTError(STATUS_INVALID_PARAMETER);
        return FALSE;
    }
#else
    UNICODE_STRING ResultWin32 = { 0 };

    ProcessInfoClass = ProcessImageFileName;

    if (dwFlags != 0 && dwFlags != PROCESS_NAME_NATIVE)
    {
        BaseSetLastNTError(STATUS_INVALID_PARAMETER);
        return FALSE;
    }
#endif

    Status = NtQueryInformationProcess(hProcess,
                                       ProcessInfoClass,
                                       Buffer,
                                       sizeof(Buffer) - sizeof(WCHAR),
                                       &Needed);
    if (Status == STATUS_INFO_LENGTH_MISMATCH)
    {
        DynamicBuffer = RtlAllocateHeap(RtlGetProcessHeap(), 0, Needed + sizeof(WCHAR));
        if (!DynamicBuffer)
        {
            BaseSetLastNTError(STATUS_NO_MEMORY);
            return FALSE;
        }

        Status = NtQueryInformationProcess(hProcess,
                                           ProcessInfoClass,
                                           DynamicBuffer,
                                           Needed,
                                           &Needed);
        Result = DynamicBuffer;
    }
    else
    {
        Result = (PUNICODE_STRING)Buffer;
    }

    if (!NT_SUCCESS(Status))
    {
        goto Cleanup;
    }

#if 1
    /* HACK: Convert device path format into Win32 path format    
     * Use ProcessImageFileNameWin32 instead if the kernel
     * supports it */
    if (dwFlags == 0)
    {
        Status = DevicePathToDosPathU(Result, &ResultWin32);

        if (!NT_SUCCESS(Status))
        {
            goto Cleanup;
        }

        Result = &ResultWin32;
    }
#endif

    /* Verify that the given buffer size can count a NULL terminator */
    if ((Result->Length / sizeof(WCHAR)) + 1 > *pdwSize)
    {
        Status = STATUS_BUFFER_TOO_SMALL;
        goto Cleanup;
    }

    RtlStringCbCopyNW(lpExeName, (*pdwSize) * sizeof(WCHAR), Result->Buffer, Result->Length);
    
    /* Return the written length, not including the NULL terminator */
    *pdwSize = Result->Length / sizeof(WCHAR);

Cleanup:
#if 1
    if (dwFlags == 0)
    {
        RtlFreeUnicodeString(&ResultWin32);
    }
#endif

    RtlFreeHeap(RtlGetProcessHeap(), 0, DynamicBuffer);

    if (!NT_SUCCESS(Status))
    {
        BaseSetLastNTError(Status);
    }

    return !Status;
}


/*
 * @implemented
 */
BOOL
WINAPI
QueryFullProcessImageNameA(
    _In_ HANDLE hProcess,
    _In_ DWORD dwFlags,
    _Out_z_cap_post_count_(*pdwSize, *pdwSize + 1)
        LPSTR lpExeName,
    _Inout_ PDWORD pdwSize)
{
    DWORD pdwSizeW = *pdwSize;
    BOOL Result;
    LPWSTR lpExeNameW;

    lpExeNameW = RtlAllocateHeap(RtlGetProcessHeap(),
                                 HEAP_ZERO_MEMORY,
                                 *pdwSize * sizeof(WCHAR));
    if (!lpExeNameW)
    {
        BaseSetLastNTError(STATUS_NO_MEMORY);
        return FALSE;
    }

    Result = QueryFullProcessImageNameW(hProcess, dwFlags, lpExeNameW, &pdwSizeW);

    if (Result)
        Result = (0 != WideCharToMultiByte(CP_ACP, 0,
                                           lpExeNameW,
                                           -1,
                                           lpExeName,
                                           *pdwSize,
                                           NULL, NULL));

    if (Result)
        *pdwSize = strlen(lpExeName);

    RtlFreeHeap(RtlGetProcessHeap(), 0, lpExeNameW);
    return Result;
}


/*
 * @unimplemented
 */
HRESULT
WINAPI
GetApplicationRecoveryCallback(IN HANDLE hProcess,
                               OUT APPLICATION_RECOVERY_CALLBACK* pRecoveryCallback,
                               OUT PVOID* ppvParameter,
                               PDWORD dwPingInterval,
                               PDWORD dwFlags)
{
    UNIMPLEMENTED;
    return E_FAIL;
}


/*
 * @unimplemented
 */
HRESULT
WINAPI
GetApplicationRestart(IN HANDLE hProcess,
                      OUT PWSTR pwzCommandline  OPTIONAL,
                      IN OUT PDWORD pcchSize,
                      OUT PDWORD pdwFlags  OPTIONAL)
{
    UNIMPLEMENTED;
    return E_FAIL;
}


/*
 * @unimplemented
 */
VOID
WINAPI
ApplicationRecoveryFinished(IN BOOL bSuccess)
{
    UNIMPLEMENTED;
}


/*
 * @unimplemented
 */
HRESULT
WINAPI
ApplicationRecoveryInProgress(OUT PBOOL pbCancelled)
{
    UNIMPLEMENTED;
    return E_FAIL;
}


/*
 * @unimplemented
 */
HRESULT
WINAPI
RegisterApplicationRecoveryCallback(IN APPLICATION_RECOVERY_CALLBACK pRecoveryCallback,
                                    IN PVOID pvParameter  OPTIONAL,
                                    DWORD dwPingInterval,
                                    DWORD dwFlags)
{
    UNIMPLEMENTED;
    return E_FAIL;
}


/*
 * @unimplemented
 */
HRESULT
WINAPI
RegisterApplicationRestart(IN PCWSTR pwzCommandline  OPTIONAL,
                           IN DWORD dwFlags)
{
    UNIMPLEMENTED;
    return E_FAIL;
}


/*
 * @implemented
 */
BOOLEAN
WINAPI
CreateSymbolicLinkW(IN LPCWSTR lpSymlinkFileName,
                    IN LPCWSTR lpTargetFileName,
                    IN DWORD dwFlags)
{
    IO_STATUS_BLOCK IoStatusBlock;
    OBJECT_ATTRIBUTES ObjectAttributes;
    HANDLE hSymlink = NULL;
    UNICODE_STRING SymlinkFileName = { 0, 0, NULL };
    UNICODE_STRING TargetFileName = { 0, 0, NULL };
    BOOLEAN bAllocatedTarget = FALSE, bRelativePath = FALSE;
    LPWSTR lpTargetFullFileName = NULL;
    SIZE_T cbPrintName;
    SIZE_T cbReparseData;
    PREPARSE_DATA_BUFFER pReparseData = NULL;
    PBYTE pBufTail;
    NTSTATUS Status;
    ULONG dwCreateOptions;
    DWORD dwErr;

    if(!lpSymlinkFileName || !lpTargetFileName || (dwFlags | SYMBOLIC_LINK_FLAG_DIRECTORY) != SYMBOLIC_LINK_FLAG_DIRECTORY)
    {
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }

    if(dwFlags & SYMBOLIC_LINK_FLAG_DIRECTORY)
        dwCreateOptions = FILE_DIRECTORY_FILE;
    else
        dwCreateOptions = FILE_NON_DIRECTORY_FILE;

    switch(RtlDetermineDosPathNameType_U(lpTargetFileName))
    {
    case RtlPathTypeUnknown:
    case RtlPathTypeRooted:
    case RtlPathTypeRelative:
        bRelativePath = TRUE;
        RtlInitUnicodeString(&TargetFileName, lpTargetFileName);
        break;

    case RtlPathTypeDriveRelative:
        {
            LPWSTR FilePart;
            SIZE_T cchTargetFullFileName;

            cchTargetFullFileName = GetFullPathNameW(lpTargetFileName, 0, NULL, &FilePart);

            if(cchTargetFullFileName == 0)
            {
                dwErr = GetLastError();
                goto Cleanup;
            }

            lpTargetFullFileName = RtlAllocateHeap(RtlGetProcessHeap(), 0, cchTargetFullFileName * sizeof(WCHAR));

            if(lpTargetFullFileName == NULL)
            {
                dwErr = ERROR_NOT_ENOUGH_MEMORY;
                goto Cleanup;
            }

            if(GetFullPathNameW(lpTargetFileName, cchTargetFullFileName, lpTargetFullFileName, &FilePart) == 0)
            {
                dwErr = GetLastError();
                goto Cleanup;
            }
        }

        lpTargetFileName = lpTargetFullFileName;

        // fallthrough

    case RtlPathTypeUncAbsolute:
    case RtlPathTypeDriveAbsolute:
    case RtlPathTypeLocalDevice:
    case RtlPathTypeRootLocalDevice:
    default:
        if(!RtlDosPathNameToNtPathName_U(lpTargetFileName, &TargetFileName, NULL, NULL))
        {
            bAllocatedTarget = TRUE;
            dwErr = ERROR_INVALID_PARAMETER;
            goto Cleanup;
        }
    }

    cbPrintName = wcslen(lpTargetFileName) * sizeof(WCHAR);
    cbReparseData = FIELD_OFFSET(REPARSE_DATA_BUFFER, SymbolicLinkReparseBuffer.PathBuffer) + TargetFileName.Length + cbPrintName;
    pReparseData = RtlAllocateHeap(RtlGetProcessHeap(), 0, cbReparseData);

    if(pReparseData == NULL)
    {
        dwErr = ERROR_NOT_ENOUGH_MEMORY;
        goto Cleanup;
    }

    pBufTail = (PBYTE)(pReparseData->SymbolicLinkReparseBuffer.PathBuffer);

    pReparseData->ReparseTag = (ULONG)IO_REPARSE_TAG_SYMLINK;
    pReparseData->ReparseDataLength = (USHORT)cbReparseData - REPARSE_DATA_BUFFER_HEADER_SIZE;
    pReparseData->Reserved = 0;

    pReparseData->SymbolicLinkReparseBuffer.SubstituteNameOffset = 0;
    pReparseData->SymbolicLinkReparseBuffer.SubstituteNameLength = TargetFileName.Length;
    pBufTail += pReparseData->SymbolicLinkReparseBuffer.SubstituteNameOffset;
    RtlCopyMemory(pBufTail, TargetFileName.Buffer, TargetFileName.Length);

    pReparseData->SymbolicLinkReparseBuffer.PrintNameOffset = pReparseData->SymbolicLinkReparseBuffer.SubstituteNameLength;
    pReparseData->SymbolicLinkReparseBuffer.PrintNameLength = (USHORT)cbPrintName;
    pBufTail += pReparseData->SymbolicLinkReparseBuffer.PrintNameOffset;
    RtlCopyMemory(pBufTail, lpTargetFileName, cbPrintName);

    pReparseData->SymbolicLinkReparseBuffer.Flags = 0;

    if(bRelativePath)
        pReparseData->SymbolicLinkReparseBuffer.Flags |= 1; // TODO! give this lone flag a name

    if(!RtlDosPathNameToNtPathName_U(lpSymlinkFileName, &SymlinkFileName, NULL, NULL))
    {
        dwErr = ERROR_PATH_NOT_FOUND;
        goto Cleanup;
    }

    InitializeObjectAttributes(&ObjectAttributes, &SymlinkFileName, OBJ_CASE_INSENSITIVE, NULL, NULL);

    Status = NtCreateFile
    (
        &hSymlink,
        FILE_WRITE_ATTRIBUTES | DELETE | SYNCHRONIZE,
        &ObjectAttributes,
        &IoStatusBlock,
        NULL,
        FILE_ATTRIBUTE_NORMAL,
        0,
        FILE_CREATE,
        FILE_SYNCHRONOUS_IO_NONALERT | FILE_OPEN_REPARSE_POINT | dwCreateOptions,
        NULL,
        0
    );

    if(!NT_SUCCESS(Status))
    {
        dwErr = RtlNtStatusToDosError(Status);
        goto Cleanup;
    }

    Status = NtFsControlFile
    (
        hSymlink,
        NULL,
        NULL,
        NULL,
        &IoStatusBlock,
        FSCTL_SET_REPARSE_POINT,
        pReparseData,
        cbReparseData,
        NULL,
        0
    );

    if(!NT_SUCCESS(Status))
    {
        FILE_DISPOSITION_INFORMATION DispInfo;
        DispInfo.DeleteFile = TRUE;
        NtSetInformationFile(hSymlink, &IoStatusBlock, &DispInfo, sizeof(DispInfo), FileDispositionInformation);

        dwErr = RtlNtStatusToDosError(Status);
        goto Cleanup;
    }

    dwErr = NO_ERROR;

Cleanup:
    if(hSymlink)
        NtClose(hSymlink);

    RtlFreeUnicodeString(&SymlinkFileName);
    if (bAllocatedTarget)
    {
        RtlFreeHeap(RtlGetProcessHeap(),
                    0,
                    TargetFileName.Buffer);
    }

    if(lpTargetFullFileName)
        RtlFreeHeap(RtlGetProcessHeap(), 0, lpTargetFullFileName);

    if(pReparseData)
        RtlFreeHeap(RtlGetProcessHeap(), 0, pReparseData);

    if(dwErr)
    {
        SetLastError(dwErr);
        return FALSE;
    }

    return TRUE;
}


/*
 * @implemented
 */
BOOLEAN
NTAPI
CreateSymbolicLinkA(IN LPCSTR lpSymlinkFileName,
                    IN LPCSTR lpTargetFileName,
                    IN DWORD dwFlags)
{
    PWCHAR SymlinkW, TargetW;
    BOOLEAN Ret;

    if(!lpSymlinkFileName || !lpTargetFileName)
    {
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }

    if (!(SymlinkW = FilenameA2W(lpSymlinkFileName, FALSE)))
        return FALSE;

    if (!(TargetW = FilenameA2W(lpTargetFileName, TRUE)))
        return FALSE;

    Ret = CreateSymbolicLinkW(SymlinkW,
                              TargetW,
                              dwFlags);

    RtlFreeHeap(RtlGetProcessHeap(), 0, SymlinkW);
    RtlFreeHeap(RtlGetProcessHeap(), 0, TargetW);

    return Ret;
}


/*
 * @unimplemented
 */
DWORD
WINAPI
GetFinalPathNameByHandleW(IN HANDLE hFile,
                          OUT LPWSTR lpszFilePath,
                          IN DWORD cchFilePath,
                          IN DWORD dwFlags)
{
    if (dwFlags & ~(VOLUME_NAME_DOS | VOLUME_NAME_GUID | VOLUME_NAME_NT |
                    VOLUME_NAME_NONE | FILE_NAME_NORMALIZED | FILE_NAME_OPENED))
    {
        SetLastError(ERROR_INVALID_PARAMETER);
        return 0;
    }

    UNIMPLEMENTED;
    return 0;
}


/*
 * @implemented
 */
DWORD
WINAPI
GetFinalPathNameByHandleA(IN HANDLE hFile,
                          OUT LPSTR lpszFilePath,
                          IN DWORD cchFilePath,
                          IN DWORD dwFlags)
{
    WCHAR FilePathW[MAX_PATH];
    UNICODE_STRING FilePathU;
    DWORD PrevLastError;
    DWORD Ret = 0;

    if (cchFilePath != 0 &&
        cchFilePath > sizeof(FilePathW) / sizeof(FilePathW[0]))
    {
        FilePathU.Length = 0;
        FilePathU.MaximumLength = (USHORT)cchFilePath * sizeof(WCHAR);
        FilePathU.Buffer = RtlAllocateHeap(RtlGetProcessHeap(),
                                           0,
                                           FilePathU.MaximumLength);
        if (FilePathU.Buffer == NULL)
        {
            SetLastError(ERROR_NOT_ENOUGH_MEMORY);
            return 0;
        }
    }
    else
    {
        FilePathU.Length = 0;
        FilePathU.MaximumLength = sizeof(FilePathW);
        FilePathU.Buffer = FilePathW;
    }

    /* save the last error code */
    PrevLastError = GetLastError();
    SetLastError(ERROR_SUCCESS);

    /* call the unicode version that does all the work */
    Ret = GetFinalPathNameByHandleW(hFile,
                                    FilePathU.Buffer,
                                    cchFilePath,
                                    dwFlags);

    if (GetLastError() == ERROR_SUCCESS)
    {
        /* no error, restore the last error code and convert the string */
        SetLastError(PrevLastError);

        Ret = FilenameU2A_FitOrFail(lpszFilePath,
                                    cchFilePath,
                                    &FilePathU);
    }

    /* free allocated memory if necessary */
    if (FilePathU.Buffer != FilePathW)
    {
        RtlFreeHeap(RtlGetProcessHeap(),
                    0,
                    FilePathU.Buffer);
    }

    return Ret;
}


/*
 * @unimplemented
 */
BOOL
WINAPI
SetFileBandwidthReservation(IN HANDLE hFile,
                            IN DWORD nPeriodMilliseconds,
                            IN DWORD nBytesPerPeriod,
                            IN BOOL bDiscardable,
                            OUT LPDWORD lpTransferSize,
                            OUT LPDWORD lpNumOutstandingRequests)
{
    UNIMPLEMENTED;
    return FALSE;
}


/*
 * @unimplemented
 */
BOOL
WINAPI
GetFileBandwidthReservation(IN HANDLE hFile,
                            OUT LPDWORD lpPeriodMilliseconds,
                            OUT LPDWORD lpBytesPerPeriod,
                            OUT LPBOOL pDiscardable,
                            OUT LPDWORD lpTransferSize,
                            OUT LPDWORD lpNumOutstandingRequests)
{
    UNIMPLEMENTED;
    return FALSE;
}


/*
 * @unimplemented
 */
HANDLE
WINAPI
OpenFileById(IN HANDLE hFile,
             IN LPFILE_ID_DESCRIPTOR lpFileID,
             IN DWORD dwDesiredAccess,
             IN DWORD dwShareMode,
             IN LPSECURITY_ATTRIBUTES lpSecurityAttributes  OPTIONAL,
             IN DWORD dwFlags)
{
    UNIMPLEMENTED;
    return INVALID_HANDLE_VALUE;
}



/*
  Vista+ MUI support functions

  References:
   Evolution of MUI Support across Windows Versions: http://msdn.microsoft.com/en-US/library/ee264317.aspx
   Comparing Windows XP Professional Multilingual Options: http://technet.microsoft.com/en-us/library/bb457045.aspx

  More info:
   http://msdn.microsoft.com/en-us/goglobal/bb978454.aspx
   http://msdn.microsoft.com/en-us/library/dd319074.aspx
*/

/* FUNCTIONS *****************************************************************/

BOOL
WINAPI
GetFileMUIInfo(
    DWORD dwFlags,
    PCWSTR pcwszFilePath,
    PFILEMUIINFO pFileMUIInfo,
    DWORD *pcbFileMUIInfo)
{
    DPRINT1("%x %p %p %p\n", dwFlags, pcwszFilePath, pFileMUIInfo, pcbFileMUIInfo);
    SetLastError(ERROR_CALL_NOT_IMPLEMENTED);
    return FALSE;
}

/*
 * @unimplemented
 */
BOOL
WINAPI
GetFileMUIPath(
    DWORD dwFlags,
    PCWSTR pcwszFilePath,
    PWSTR pwszLanguage,
    PULONG pcchLanguage,
    PWSTR pwszFileMUIPath,
    PULONG pcchFileMUIPath,
    PULONGLONG pululEnumerator)
{
    DPRINT1("%x %p %p %p %p %p\n", dwFlags, pcwszFilePath, pwszLanguage, pwszFileMUIPath, pcchFileMUIPath, pululEnumerator);
    SetLastError(ERROR_CALL_NOT_IMPLEMENTED);
    return FALSE;
}

/*
 * @unimplemented
 */
#if 0 // This is Windows 7+
BOOL
WINAPI
GetProcessPreferredUILanguages(
    DWORD dwFlags,
    PULONG pulNumLanguages,
    PZZWSTR pwszLanguagesBuffer,
    PULONG pcchLanguagesBuffer)
{
    DPRINT1("%x %p %p %p\n", dwFlags, pulNumLanguages, pwszLanguagesBuffer, pcchLanguagesBuffer);
    SetLastError(ERROR_CALL_NOT_IMPLEMENTED);
    return FALSE;
}
#endif

/*
* @unimplemented
*/
BOOL
WINAPI
GetSystemPreferredUILanguages(
    DWORD dwFlags,
    PULONG pulNumLanguages,
    PZZWSTR pwszLanguagesBuffer,
    PULONG pcchLanguagesBuffer)
{
    DPRINT1("%x %p %p %p\n", dwFlags, pulNumLanguages, pwszLanguagesBuffer, pcchLanguagesBuffer);
    SetLastError(ERROR_CALL_NOT_IMPLEMENTED);
    return FALSE;
}

/*
 * @unimplemented
 */
BOOL
WINAPI
GetThreadPreferredUILanguages(
    DWORD dwFlags,
    PULONG pulNumLanguages,
    PZZWSTR pwszLanguagesBuffer,
    PULONG pcchLanguagesBuffer)
{
    DPRINT1("%x %p %p %p\n", dwFlags, pulNumLanguages, pwszLanguagesBuffer, pcchLanguagesBuffer);
    SetLastError(ERROR_CALL_NOT_IMPLEMENTED);
    return FALSE;
}

/*
 * @unimplemented
 */
LANGID
WINAPI
GetThreadUILanguage(VOID)
{
    UNIMPLEMENTED;
    SetLastError(ERROR_CALL_NOT_IMPLEMENTED);
    return 0;
}

/*
 * @unimplemented
 */
BOOL
WINAPI
GetUILanguageInfo(
    DWORD dwFlags,
    PCZZWSTR pwmszLanguage,
    PZZWSTR pwszFallbackLanguages,
    PDWORD pcchFallbackLanguages,
    PDWORD pdwAttributes)
{
    DPRINT1("%x %p %p %p %p\n", dwFlags, pwmszLanguage, pwszFallbackLanguages, pcchFallbackLanguages, pdwAttributes);
    SetLastError(ERROR_CALL_NOT_IMPLEMENTED);
    return FALSE;
}


/*
 * @unimplemented
 */
BOOL
WINAPI
GetUserPreferredUILanguages(
    DWORD dwFlags,
    PULONG pulNumLanguages,
    PZZWSTR pwszLanguagesBuffer,
    PULONG pcchLanguagesBuffer)
{
    DPRINT1("%x %p %p %p\n", dwFlags, pulNumLanguages, pwszLanguagesBuffer, pcchLanguagesBuffer);
    SetLastError(ERROR_CALL_NOT_IMPLEMENTED);
    return FALSE;
}

/*
 * @unimplemented
 */
#if 0 // Tis is Windows 7+
BOOL
WINAPI
SetProcessPreferredUILanguages(
    DWORD dwFlags,
    PCZZWSTR pwszLanguagesBuffer,
    PULONG pulNumLanguages)
{
    DPRINT1("%x %p %p\n", dwFlags, pwszLanguagesBuffer, pulNumLanguages);
    SetLastError(ERROR_CALL_NOT_IMPLEMENTED);
    return FALSE;
}
#endif

/*
 * @unimplemented
 */
BOOL
WINAPI
SetThreadPreferredUILanguages(
    DWORD dwFlags,
    PCZZWSTR pwszLanguagesBuffer,
    PULONG pulNumLanguages
    )
{
    DPRINT1("%x %p %p\n", dwFlags, pwszLanguagesBuffer, pulNumLanguages);
    SetLastError(ERROR_CALL_NOT_IMPLEMENTED);
    return FALSE;
}


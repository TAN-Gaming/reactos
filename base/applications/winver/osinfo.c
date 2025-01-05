/*
 * PROJECT:    ReactOS Version Program
 * LICENSE:    LGPL-2.1-or-later (https://spdx.org/licenses/LGPL-2.1-or-later)
 * PURPOSE:    Retrieve OS name and simple compatibility information
 * COPYRIGHT:  Copyright 2025 Thamatip Chitpong <thamatip.chitpong@reactos.org>
 */

#include "winver_exe.h"

#define WINVER_OSINFO_KEY L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion"

static
LPWSTR
Winver_GetRegValueString(
    _In_ HKEY hKey,
    _In_ LPCWSTR lpValue)
{
    DWORD dwType = REG_NONE;
    DWORD dwSize;
    LONG lError;
    LPWSTR pszValue;

    lError = RegQueryValueExW(hKey, lpValue, NULL, &dwType, NULL, &dwSize);
    if (lError != ERROR_SUCCESS || dwType != REG_SZ)
        return NULL;

    /* NOTE: Reserved space for a NULL terminator */
    pszValue = HeapAlloc(GetProcessHeap(), 0, dwSize + sizeof(WCHAR));
    if (!pszValue)
        return NULL;

    lError = RegQueryValueExW(hKey, lpValue, NULL, &dwType, (LPBYTE)pszValue, &dwSize);
    if (lError != ERROR_SUCCESS)
    {
        HeapFree(GetProcessHeap(), 0, pszValue);
        return NULL;
    }

    /* Ensure the returned string is NULL terminated */
    pszValue[dwSize / sizeof(WCHAR)] = UNICODE_NULL;

    return pszValue;
}

static
LPWSTR
Winver_FormatCompatSpkInfo(
    _In_ PWINVER_OS_INFO OSInfo)
{
    WCHAR szSpkSep[4];
    DWORD dwLength;
    LPWSTR pszInfo;

    /* Required info must be valid */
    if (!OSInfo->pszCompatSpk)
        return NULL;

    dwLength = LoadStringW(GetModuleHandleW(NULL),
                           IDS_OSINFO_SPK_SEPARATOR,
                           szSpkSep,
                           _countof(szSpkSep));
    if (dwLength == 0)
        return NULL;

    /* NOTE: dwLength includes a NULL terminator */
    dwLength += wcslen(OSInfo->pszCompatSpk) + 1;
    pszInfo = HeapAlloc(GetProcessHeap(), 0, dwLength * sizeof(WCHAR));
    if (pszInfo)
    {
        StringCchPrintfW(pszInfo, dwLength, L"%s%s", szSpkSep, OSInfo->pszCompatSpk);
    }

    return pszInfo;
}

static
VOID
Winver_FormatCompatInfo(
    _Inout_ PWINVER_OS_INFO OSInfo)
{
    static const WCHAR szFmtSpecs[] = L"%s%s%s";
    WCHAR szFormat[64];
    DWORD dwLength;
    LPWSTR pszSpk;
    LPWSTR pszInfo;

    /* Required info must be valid */
    if (!OSInfo->pszCompatVer || !OSInfo->pszCompatBuild)
        return;

    dwLength = LoadStringW(GetModuleHandleW(NULL),
                           IDS_OSINFO_COMPAT_FORMAT,
                           szFormat,
                           _countof(szFormat));
    if (dwLength < CONST_STR_LEN(szFmtSpecs))
    {
        return;
    }
    dwLength -= CONST_STR_LEN(szFmtSpecs);

    /* Service pack info is optional */
    pszSpk = Winver_FormatCompatSpkInfo(OSInfo);
    if (pszSpk)
    {
        dwLength += wcslen(pszSpk);
    }

    /* NOTE: dwLength excludes format specifiers and includes a NULL terminator */
    dwLength += wcslen(OSInfo->pszCompatVer) + wcslen(OSInfo->pszCompatBuild) + 1;
    pszInfo = HeapAlloc(GetProcessHeap(), 0, dwLength * sizeof(WCHAR));
    if (pszInfo)
    {
        StringCchPrintfW(pszInfo, dwLength, szFormat,
                         OSInfo->pszCompatVer,
                         OSInfo->pszCompatBuild,
                         pszSpk ? pszSpk : L"");

        OSInfo->pszCompatInfo = pszInfo;
    }

    HeapFree(GetProcessHeap(), 0, pszSpk);
}

PWINVER_OS_INFO
Winver_GetOSInfo(VOID)
{
    HKEY hKey;
    LONG lError;
    PWINVER_OS_INFO OSInfo;

    OSInfo = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(*OSInfo));
    if (!OSInfo)
        return NULL;

    lError = RegOpenKeyExW(HKEY_LOCAL_MACHINE,
                           WINVER_OSINFO_KEY,
                           0,
                           KEY_QUERY_VALUE,
                           &hKey);
    if (lError != ERROR_SUCCESS)
    {
        HeapFree(GetProcessHeap(), 0, OSInfo);
        return NULL;
    }

    /* OS name */
    OSInfo->pszName = Winver_GetRegValueString(hKey, L"ProductName");
    if (!OSInfo->pszName)
    {
        /* ShellAboutW: This info must be valid */
        RegCloseKey(hKey);
        HeapFree(GetProcessHeap(), 0, OSInfo);
        return NULL;
    }

    /* Compatible NT version */
    OSInfo->pszCompatVer = Winver_GetRegValueString(hKey, L"CurrentVersion");

    /* Compatible NT build number */
    OSInfo->pszCompatBuild = Winver_GetRegValueString(hKey, L"CurrentBuildNumber");

    /* Compatible NT service pack (optional) */
    OSInfo->pszCompatSpk = Winver_GetRegValueString(hKey, L"CSDVersion");

    RegCloseKey(hKey);

    Winver_FormatCompatInfo(OSInfo);

    return OSInfo;
}

VOID
Winver_FreeOSInfo(
    _In_ PWINVER_OS_INFO OSInfo)
{
    if (OSInfo)
    {
        HeapFree(GetProcessHeap(), 0, OSInfo->pszCompatInfo);
        HeapFree(GetProcessHeap(), 0, OSInfo->pszCompatSpk);
        HeapFree(GetProcessHeap(), 0, OSInfo->pszCompatBuild);
        HeapFree(GetProcessHeap(), 0, OSInfo->pszCompatVer);
        HeapFree(GetProcessHeap(), 0, OSInfo->pszName);

        HeapFree(GetProcessHeap(), 0, OSInfo);
    }
}

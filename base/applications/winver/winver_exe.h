/*
 * COPYRIGHT:       See COPYING in the top level directory
 * PROJECT:         ReactOS Version Program
 * FILE:            base/applications/winver/winver_exe.h
 */

#pragma once

#include <stdarg.h>
#include <stdlib.h>

#include <windef.h>
#include <winbase.h>
#include <winreg.h>
#include <winuser.h>
#include <commctrl.h>
#include <shellapi.h>

#include <strsafe.h>

#include "resource.h"

#define CONST_STR_LEN(str) (_countof(str) - 1)

typedef struct _WINVER_OS_INFO
{
    LPWSTR pszName;
    LPWSTR pszCompatVer;
    LPWSTR pszCompatBuild;
    LPWSTR pszCompatSpk;
    LPWSTR pszCompatInfo;
} WINVER_OS_INFO, *PWINVER_OS_INFO;

PWINVER_OS_INFO
Winver_GetOSInfo(VOID);

VOID
Winver_FreeOSInfo(
    _In_ PWINVER_OS_INFO OSInfo);

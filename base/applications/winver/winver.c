/*
 * COPYRIGHT:       See COPYING in the top level directory
 * PROJECT:         ReactOS Version Program
 * FILE:            base/applications/winver/winver.c
 */

#include "winver_exe.h"

int WINAPI wWinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPWSTR lpCmdLine, int nCmdShow)
{
    INITCOMMONCONTROLSEX iccx;
    PWINVER_OS_INFO OSInfo;
    int Ret;

    UNREFERENCED_PARAMETER(hInstance);
    UNREFERENCED_PARAMETER(hPrevInstance);
    UNREFERENCED_PARAMETER(lpCmdLine);
    UNREFERENCED_PARAMETER(nCmdShow);

    /* Initialize common controls */
    iccx.dwSize = sizeof(INITCOMMONCONTROLSEX);
    iccx.dwICC = ICC_STANDARD_CLASSES | ICC_WIN95_CLASSES;
    InitCommonControlsEx(&iccx);

    OSInfo = Winver_GetOSInfo();

    Ret = ShellAboutW(NULL,
                      OSInfo ? OSInfo->pszName : L"ReactOS",
                      OSInfo ? OSInfo->pszCompatInfo : NULL,
                      NULL);

    Winver_FreeOSInfo(OSInfo);

    return Ret;
}

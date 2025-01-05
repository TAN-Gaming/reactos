
list(APPEND SOURCE
    osinfo.c
    winver.c
    winver_exe.h)

add_executable(winver ${SOURCE} winver.rc)
set_module_type(winver win32gui UNICODE)
add_importlibs(winver advapi32 user32 shell32 comctl32 msvcrt kernel32)
add_pch(winver winver_exe.h SOURCE)
add_cd_file(TARGET winver DESTINATION reactos/system32 FOR all)

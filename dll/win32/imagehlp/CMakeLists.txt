
add_definitions(-D_IMAGEHLP_SOURCE_)
include_directories(BEFORE ${REACTOS_SOURCE_DIR}/sdk/include/wine)
spec2def(imagehlp.dll imagehlp.spec ADD_IMPORTLIB)

list(APPEND SOURCE
    access.c
    imagehlp_main.c
    integrity.c
    modify.c)

list(APPEND PCH_SKIP_SOURCE
    ${CMAKE_CURRENT_BINARY_DIR}/imagehlp_stubs.c)

add_library(imagehlp MODULE
    ${SOURCE}
    ${PCH_SKIP_SOURCE}
    imagehlp.rc
    ${CMAKE_CURRENT_BINARY_DIR}/imagehlp.def)

set_module_type(imagehlp win32dll)
target_link_libraries(imagehlp wine ${PSEH_LIB})
add_importlibs(imagehlp dbghelp msvcrt kernel32 ntdll)
add_pch(imagehlp precomp.h "${PCH_SKIP_SOURCE}")
add_cd_file(TARGET imagehlp DESTINATION reactos/system32 FOR all)

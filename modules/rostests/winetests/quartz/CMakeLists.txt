
add_definitions(-DWINETEST_USE_DBGSTR_LONGLONG)

list(APPEND SOURCE
    avisplitter.c
    dsoundrender.c
    filtergraph.c
    filtermapper.c
    memallocator.c
    misc.c
    mpegsplit.c
    referenceclock.c
    videorenderer.c
    testlist.c)

add_idl_headers(quartz_test_idlheader fil_data.idl)
add_executable(quartz_winetest ${SOURCE} rsrc.rc)
target_link_libraries(quartz_winetest uuid)
add_dependencies(quartz_winetest dxsdk quartz_test_idlheader)
set_module_type(quartz_winetest win32cui)
add_importlibs(quartz_winetest ole32 oleaut32 advapi32 user32 msvcrt kernel32)

if(MSVC)
    add_importlibs(quartz_winetest ntdll)
endif()

add_rostests_file(TARGET quartz_winetest)

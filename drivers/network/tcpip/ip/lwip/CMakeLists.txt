
set(LWIP_DIR ${CMAKE_CURRENT_SOURCE_DIR})
set(LWIP_INCLUDE_DIRS
    "${LWIP_DIR}/src/include"
    "${REACTOS_SOURCE_DIR}/drivers/network/tcpip/ip/include/lwip_glue")

if(NOT MSVC)
    set(LWIP_COMPILER_FLAGS
        "-fno-builtin-malloc"
        "-fno-builtin-free")
endif()

include(src/Filelists.cmake)
add_dependencies(lwipcore bugcodes xdk)

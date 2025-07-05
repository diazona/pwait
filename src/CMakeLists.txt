cmake_minimum_required(VERSION 3.15)

set(CMAKE_INCLUDE_CURRENT_DIR ON)

include(CheckSymbolExists)
check_symbol_exists(__GLIBC__ features.h _GNU_SOURCE)
configure_file(config.h.in config.h)

add_executable(pwait pwait.c ptrace.c netlink.c poll.c pidfd.c capabilities.c)
target_link_libraries(pwait cap)

install(TARGETS pwait RUNTIME DESTINATION bin)
install(CODE "execute_process(COMMAND sudo setcap 'cap_sys_ptrace+p cap_net_admin+p' pwait WORKING_DIRECTORY ${CMAKE_INSTALL_PREFIX}/bin)")

project(pwait)

cmake_minimum_required(VERSION 3.0)
set(CMAKE_INCLUDE_CURRENT_DIR ON)

include(CheckSymbolExists)
check_symbol_exists(__GLIBC__ features.h _GNU_SOURCE)
configure_file(config.h.in config.h)

add_executable(pwait pwait.c)
target_link_libraries(pwait cap)

install(TARGETS pwait RUNTIME DESTINATION bin)

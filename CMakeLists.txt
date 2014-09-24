project(pwait)

cmake_minimum_required(VERSION 3.0)

add_executable(pwait pwait.c)
target_link_libraries(pwait cap)

install(TARGETS pwait RUNTIME DESTINATION bin)

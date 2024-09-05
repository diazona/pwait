cmake_minimum_required(VERSION 3.22)

add_test(
    NAME pwait-setcap
    COMMAND sudo setcap "cap_sys_ptrace+p cap_net_admin+p" "$<TARGET_FILE:pwait>"
)
set_tests_properties(pwait-setcap PROPERTIES FIXTURES_SETUP pwait-setcap-fixture)

add_test(
    NAME test-pwait
    COMMAND "${CMAKE_CURRENT_LIST_DIR}/test_pwait.sh"
)
set_tests_properties(test-pwait PROPERTIES ENVIRONMENT PWAIT=$<TARGET_FILE:pwait>)
set_tests_properties(test-pwait PROPERTIES FIXTURES_REQUIRED pwait-setcap-fixture)

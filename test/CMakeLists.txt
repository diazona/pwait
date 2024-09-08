cmake_minimum_required(VERSION 3.22)

add_test(
    NAME pwait-setcap
    COMMAND sudo setcap "cap_sys_ptrace+p cap_net_admin+p" "$<TARGET_FILE:pwait>"
)
set_tests_properties(pwait-setcap PROPERTIES FIXTURES_SETUP pwait-setcap-fixture)

add_test(
    NAME test-pwait-netlink
    COMMAND "${CMAKE_CURRENT_LIST_DIR}/test_pwait.sh"
)
set_tests_properties(test-pwait-netlink PROPERTIES ENVIRONMENT "PWAIT=$<TARGET_FILE:pwait>;PWAIT_METHOD=netlink")
set_tests_properties(test-pwait-netlink PROPERTIES FIXTURES_REQUIRED pwait-setcap-fixture)

add_test(
    NAME test-pwait-ptrace
    COMMAND "${CMAKE_CURRENT_LIST_DIR}/test_pwait.sh"
)
set_tests_properties(test-pwait-ptrace PROPERTIES ENVIRONMENT "PWAIT=$<TARGET_FILE:pwait>;PWAIT_METHOD=ptrace")
set_tests_properties(test-pwait-ptrace PROPERTIES FIXTURES_REQUIRED pwait-setcap-fixture)

add_test(
    NAME test-pwait-poll
    COMMAND "${CMAKE_CURRENT_LIST_DIR}/test_pwait.sh"
)
set_tests_properties(test-pwait-poll PROPERTIES ENVIRONMENT "PWAIT=$<TARGET_FILE:pwait>;PWAIT_METHOD=poll")

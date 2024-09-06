#!/bin/bash

# A simple test harness for pwait

set -eu -o pipefail


# Start a process that waits for a specified amount of time and then exits with
# a given return code. This function does not wait for the process to finish.
# Its PID is stored in the variable background_pid and then the function returns
# immediately.
start_sleep_and_exit() {
    local delay="${1?:Missing delay}" code="${2?:Missing exit code}"
    set +e
    ( sleep "$delay"; exit "$code"; ) &
    set -e
    background_pid="$!"
}


# Run pwait on a given process ID. This function will wait for pwait to return
# and then store pwait's exit code in the variable pwait_exit_code.
run_pwait() {
    local pid="${1?:Missing PID}"
    printf "Invoking %s %s on target pid %d\n" "$PWAIT" "${pwait_options[*]}" "$pid"
    set +e
    "$PWAIT" "${pwait_options[@]}" "$pid"
    pwait_exit_code="$?"
    set -e
}


print_test_header() {
    printf "BEGIN %s\n" "$test_name"
}


print_test_footer() {
    printf "END %s\n" "$test_name"
}


assert() {
    local command="$1" message="$2"
    shift
    if ! eval "$command"; then
        printf "FAILED: %s\n  %s\n  %s\n" "$test_name" "$message" "$command" >&2
        return 1
    fi
}


process_exists() {
    local pid="$1"
    pgrep "$pid" >/dev/null
}


# Test that pwait exits with the same code as the target process
test_pwait_exit_code() {
    local delay="2s" code="${1?:Missing exit code}" test_name
    test_name="${FUNCNAME[0]}_$code"
    print_test_header

    start_sleep_and_exit "$delay" "$code"

    run_pwait "$background_pid"

    assert "[[ '$pwait_exit_code' -eq '$code' ]]" "Expected code $code but got $pwait_exit_code"

    print_test_footer
}


# Test that the target process does not exist after pwait exits.
test_target_does_not_exist_after_pwait_exit() {
    local delay="2s" code="0" test_name="${FUNCNAME[0]}"
    print_test_header

    start_sleep_and_exit "$delay" "$code"

    run_pwait "$background_pid"

    assert "! process_exists $background_pid" "Process (pid $background_pid) is still running after pwait finished"

    print_test_footer
}


# Start a process that waits for a specified amount of time and then ensures
# a pwait process is running. This function does not wait for the process to
# finish. Its PID is stored in the variable background_pid and then the function
# returns immediately.
start_sleep_and_touch() {
    local delay="${1?:Missing delay}" filename="${2?:Missing filename}"
    set +e
    ( sleep "$delay"; touch "$filename" ) &
    set -e
    background_pid="$!"
}


# Test that pwait and its target process exit at roughly the same time.
test_pwait_and_target_exit_times() {
    local delay="$1" code="0" test_name tmpdir sleep_time pwait_time
    test_name="${FUNCNAME[0]}_$delay"
    print_test_header

    tmpdir="$(mktemp -d)"
    trap "rm -rf '$tmpdir'" RETURN
    ( /usr/bin/time --format "%e" sleep "$delay" >"$tmpdir/sleep-time.txt" ) &
    background_pid="$!"
    /usr/bin/time --format "%e" "$PWAIT" "$background_pid" >"$tmpdir/pwait-time.txt"

    assert "cmp '$tmpdir/sleep-time.txt' '$tmpdir/pwait-time.txt'" "pwait and target process finished at different times"

    print_test_footer
}


run_all_tests() {
    test_pwait_exit_code 0
    test_pwait_exit_code 1
    test_pwait_exit_code 128
    test_target_does_not_exist_after_pwait_exit
    test_pwait_and_target_exit_times 0.1s
    test_pwait_and_target_exit_times 1s
    test_pwait_and_target_exit_times 2s
    test_pwait_and_target_exit_times 5s
}


pwait_options=()
if [[ -n "${PWAIT_METHOD:-}" ]]; then
    pwait_options=("--method=${PWAIT_METHOD}")
fi
run_all_tests

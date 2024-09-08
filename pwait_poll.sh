pwait_poll() {
    while ps -p "$1" >/dev/null; do
        sleep "${2:-5s}"
    done
}

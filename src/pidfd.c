/* Implements waiting for a process using the `pidfd_open` syscall
 *
 * This implementation is similar to the one in
 * [the man page for `pidfd_open`](https://man7.org/linux/man-pages/man2/pidfd_open.2.html)
 * but that's effectively forced by the task; there isn't a lot of variety in
 * how you can write this.
 */

#define _GNU_SOURCE

#include "pwait.h"
#include <assert.h>
#include <errno.h>
#include <poll.h>
#include <sysexits.h>
#include <unistd.h>
#include <sys/syscall.h>


/**
 * Open a process file descriptor.
 *
 * This is a thin wrapper around the pidfd_open() syscall.
 *
 * @return The file descriptor opened, or -1 if opening failed.
 */
static int pidfd_open(pid_t pid) {
    long result = syscall(SYS_pidfd_open, pid, 0);
    int pidfd = (int)result;
    assert((long)pidfd == result);
    return pidfd;
}


int wait_using_pidfd(pid_t pid) {
    int fd = pidfd_open(pid);
    if (fd < 0) {
        // ESRCH indicates that no process with that ID was found
        return errno == ESRCH ? -1 : EX_OSERR;
    }

    struct pollfd pfd = {
        .fd     = fd,
        .events = POLLIN,
    };

    int pfd_status;
    while ((pfd_status = poll(&pfd, 1, -1)) >= 0) {
        if (pfd_status < 0) {
            if (errno == EINTR) {
                // poll() was interrupted by a signal, so we can just keep going
                continue;
            }
            else {
                // Some more serious error occurred
                return EX_OSERR;
            }
        }
        else if (pfd_status == 0) {
            // This shouldn't happen because we set timeout to -1, i.e. infinite
            return -1;
        }
        else {
            assert(pfd_status == 1);
            if (pfd.revents & POLLIN) {
                break;
            }
        }
    }
    return 0;
}

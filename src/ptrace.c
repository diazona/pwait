#include "config.h"
#include <sys/wait.h>
#include <sys/ptrace.h>
#include <sched.h>
#include <stdlib.h>
#include <sysexits.h>
#include <syslog.h>
#include "pwait.h"

/* When the tracee is about to exit, waitpid returns a status
 *  (PTRACE_EVENT_EXIT << 16) | (SIGTRAP << 8) | 0x7f
 * and waitid sets a si_status of
 *  (PTRACE_EVENT_EXIT << 8) | SIGTRAP
 * so checking for this value above is how we know we are seeing
 * the process exit, and not just a random signal
 */
#define PTRACE_EXIT_SIGINFO_STATUS (SIGTRAP | (PTRACE_EVENT_EXIT << 8))

/**
 * Get the exit status of the traced process, once we know it has exited
 */
static int get_tracee_exit_status(pid_t pid) {
    unsigned long tracee_exit_status;
    if (ptrace(PTRACE_GETEVENTMSG, pid, NULL, &tracee_exit_status) == -1) {
        syslog(LOG_ERR, "Error getting process %d exit status", pid);
        return -1;
    }
    else {
        // unless I'm missing something the man page neglects to mention
        // that PTRACE_GETEVENTMSG gives (status << 8), but it does
        return (int)(tracee_exit_status >> 8);
    }
}

static int wait_using_waitpid(pid_t pid) {
    pid_t returned_pid;
    int waitpid_return_status;
    int tracee_exit_code;

    do {
        returned_pid = waitpid(pid, &waitpid_return_status, 0);
        syslog(LOG_DEBUG, "waitpid() returned %d", returned_pid);
        /* There are several situations we could be in at this point: */

        /* waitpid() encountered some unknown error, in which case we should
         * break out of the loop and abort the program to avoid screwing
         * anything up
         */
        if (returned_pid == -1) {
            syslog(LOG_CRIT, "Error waiting for process %d", pid);
            return -1;
        }
        if (returned_pid != pid) {
            syslog(LOG_CRIT, "waitpid returned wrong process ID %d (expected %d)", returned_pid, pid);
            return -1;
        }

        syslog(LOG_DEBUG, "waitpid status %x", waitpid_return_status);

        /* The tracee process is exiting, in which case waitpid() will yield
         * the magic combination PTRACE_EXIT_SIGINFO_STATUS. In this case,
         * break out of the loop and return.
         */
        if (WIFSTOPPED(waitpid_return_status) && (waitpid_return_status >> 8 == PTRACE_EXIT_SIGINFO_STATUS)) {
            syslog(LOG_DEBUG, "tracee is exiting (normal)");
            return get_tracee_exit_status(pid);
        }

        /* The tracee has somehow exited without this process (the tracer)
         * being notified with a SIGTRAP. This shouldn't happen, but it is easy
         * to recover from.
         */
        else if (WIFEXITED(waitpid_return_status)) {
            syslog(LOG_WARNING, "tracee has already exited (weird)");
            return WEXITSTATUS(waitpid_return_status);
        }

        /* The tracee has been terminated by a signal. This shouldn't happen
         * unless the signal is SIGKILL, because if the tracee receives SIGTERM
         * or SIGINT or so on, that should be translated into the SIGTRAP that
         * indicates the tracee is about to exit. And the case above where
         * waitpid_return_status >> 8 == PTRACE_EXIT_SIGINFO_STATUS should
         * be invoked instead of this.
         */
        else if (WIFSIGNALED(waitpid_return_status)) {
            syslog(LOG_INFO, "tracee terminated by signal %d (normal-ish)", WTERMSIG(waitpid_return_status));
            /* Processes terminated by a signal don't really have an exit code,
             * but there is a common convention to return 128+SIGNUM, which I
             * do here.
             */
            return 128 + WTERMSIG(waitpid_return_status);
        }

        /* The tracee has received a signal other than the SIGTRAP which
         * indicates that it is about to exit. In this case, we should
         * reinject the signal and wait again.
         */
        else if (WIFSTOPPED(waitpid_return_status)) {
            syslog(LOG_DEBUG, "tracee received signal %d; reinjecting and continuing", WSTOPSIG(waitpid_return_status));
            ptrace(PTRACE_CONT, pid, NULL, WSTOPSIG(waitpid_return_status));
        }
    } while (TRUE);
    return -1;
}

#if defined(_SVID_SOURCE) \
 || _XOPEN_SOURCE >= 500 \
 || defined(_XOPEN_SOURCE) && defined(_XOPEN_SOURCE_EXTENDED) \
 || _POSIX_C_SOURCE >= 200809L
# define HAVE_WAITID
static int wait_using_waitid(pid_t pid) {
    siginfo_t siginfo;

    do {
        siginfo.si_pid = 0; // not strictly necessary? see man waitid
        /* If waitid() encountered some unknown error, break out of the loop
         * and abort the program to avoid screwing anything up
         */
        if (waitid(P_PID, pid, &siginfo, WEXITED) != 0) {
            syslog(LOG_CRIT, "Failed to wait on process %d", pid);
            return -1;
        }

        if (siginfo.si_pid == 0) {
            syslog(LOG_CRIT, "Failed to connect to process %d", pid);
            return -1;
        }

        syslog(LOG_DEBUG, "siginfo status %x", siginfo.si_status);

        /* The tracee process is exiting, in which case waitid() will yield
         * the magic combination PTRACE_EXIT_SIGINFO_STATUS. In this case,
         * break out of the loop and return.
         */
        if (siginfo.si_code == CLD_TRAPPED && siginfo.si_status == PTRACE_EXIT_SIGINFO_STATUS) {
            syslog(LOG_DEBUG, "tracee is exiting (normal)");
            return get_tracee_exit_status(pid);
        }

        /* The tracee has somehow exited without this process (the tracer)
         * being notified with a SIGTRAP. This shouldn't happen, but it is easy
         * to recover from.
         */
        else if (siginfo.si_code == CLD_EXITED) {
            syslog(LOG_WARNING, "tracee has already exited (weird)");
            return siginfo.si_status;
        }

        /* The tracee has been terminated by a signal. This shouldn't happen
         * unless the signal is SIGKILL, because if the tracee receives SIGTERM
         * or SIGINT or so on, that should be translated into the SIGTRAP that
         * indicates the tracee is about to exit. And the case above where
         * waitpid_return_status >> 8 == PTRACE_EXIT_SIGINFO_STATUS should
         * be invoked instead of this.
         */
        else if (siginfo.si_code == CLD_KILLED || siginfo.si_code == CLD_DUMPED) {
            syslog(LOG_INFO, "tracee terminated by signal %d (normal-ish)", siginfo.si_status);
            /* Processes terminated by a signal don't really have an exit code,
             * but there is a common convention to return 128+SIGNUM, which I
             * do here.
             */
            return 128 + siginfo.si_status;
        }

        /* The tracee has received a signal other than the SIGTRAP which
         * indicates that it is about to exit. In this case, we should
         * reinject the signal and wait again.
         */
        else if (siginfo.si_code == CLD_TRAPPED) {
            syslog(LOG_DEBUG, "tracee received signal %d; reinjecting and continuing", siginfo.si_status);
            ptrace(PTRACE_CONT, pid, NULL, siginfo.si_status);
        }
    } while (TRUE);
    return -1;
}
#endif

/**
 * The process ID being waited for
 */
static pid_t pid_for_detach;

static void detach(const int signal) {
    syslog(LOG_DEBUG, "detaching from process %d", pid_for_detach);
    ptrace(PTRACE_DETACH, pid_for_detach, 0, 0);
}

int wait_using_ptrace(pid_t pid) {
    long ptrace_return;
    int wait_return;
    cap_value_t capability_to_acquire[1];
    struct sigaction siga, oldsiga_term, oldsiga_int;

    if (geteuid() != 0) {
#if defined(CAP_SYS_PTRACE)
        capability_to_acquire[0] = CAP_SYS_PTRACE;
#else
        syslog(LOG_CRIT, "CAP_SYS_PTRACE not available");
        return EX_SOFTWARE;
#endif
        if (!acquire_capabilities(1, capability_to_acquire)) {
            return EX_SOFTWARE;
        }
    }

    /* Set up a signal handler so that if the program receives a SIGINT (Ctrl+C)
     * or SIGTERM, it will detach from the tracee
     */
    pid_for_detach = pid;
    siga.sa_handler = detach;
    sigaction(SIGTERM, &siga, &oldsiga_term);
    sigaction(SIGINT, &siga, &oldsiga_int);

    syslog(LOG_DEBUG, "Attempting to set ptrace on process %d", pid);
#ifdef PTRACE_SEIZE
    // valid since Linux kernel 3.4
    ptrace_return = ptrace(PTRACE_SEIZE, pid, NULL, PTRACE_O_TRACEEXIT);
#else
    ptrace_return = ptrace(PTRACE_ATTACH, pid, NULL, NULL);
#endif
    if (ptrace_return == -1) {
        syslog(LOG_CRIT, "Error setting ptrace on process %d", pid);
        return EX_OSERR;
    }
    syslog(LOG_DEBUG, "Successfully set ptrace on process %d", pid);

#ifdef HAVE_WAITID
    wait_return = wait_using_waitid(pid);
#else
    wait_return = wait_using_waitpid(pid);
#endif
    if (wait_return == -1) {
        // wait failed
        return EX_OSERR;
    }
    syslog(LOG_DEBUG, "Wait on process %d successful", pid);

    // Reset the signal handler (hopefully TERM or INT doesn't come right here)
    sigaction(SIGTERM, &oldsiga_term, NULL);
    sigaction(SIGINT, &oldsiga_int, NULL);

    syslog(LOG_INFO, "Process %d exited with status %d", pid, wait_return);

    return wait_return;
}
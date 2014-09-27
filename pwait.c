#include "config.h"
#include <sys/capability.h>
#include <sys/wait.h>
#include <sys/ptrace.h>
#include <signal.h>
#include <sched.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <sysexits.h>
#include <syslog.h>
#include <getopt.h>

#define TRUE 1
#define FALSE 0

/* When the tracee is about to exit, waitpid returns a status
 *  (PTRACE_EVENT_EXIT << 16) | (SIGTRAP << 8) | 0x7f
 * and waitid sets a si_status of
 *  (PTRACE_EVENT_EXIT << 8) | SIGTRAP
 * so checking for this value above is how we know we are seeing
 * the process exit, and not just a random signal
 */
#define PTRACE_EXIT_SIGINFO_STATUS (SIGTRAP | (PTRACE_EVENT_EXIT << 8))

/**
 * The process ID being waited for
 */
static pid_t pid;

void usage(const char* name) {
    fprintf(stderr, "Usage: %s pid\n", name);
}

/**
 * Get the exit status of the traced process, once we know it has exited
 */
int get_tracee_exit_status() {
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

int cap_free_safe(cap_t* p_capabilities) {
    int status = cap_free(*p_capabilities);
    if (status == -1) {
        syslog(LOG_DEBUG, "freeing capability struct failed");
    }
    return status;
}

/**
 * Make a best effort to ensure that the process has the CAP_SYS_PTRACE
 * capability. If it already did, or if this function was able to set the
 * capability, this returns 1 (TRUE). Otherwise, this returns 0 (FALSE).
 *
 * The function is a bit long because it checks for error codes at every step,
 * but conceptually what it does is very straightforward:
 * 1. Check whether the CAP_SYS_PTRACE capability is supported by the kernel
 * 2. Check whether the process already has CAP_SYS_PTRACE set, and if so,
 *    return TRUE
 * 3. Check whether the process is allowed to give itself CAP_SYS_PTRACE, and
 *    if not, return FALSE
 * 4. Attempt to actually set CAP_SYS_PTRACE
 * 5. Check again to make sure the process has CAP_SYS_PTRACE, and return TRUE
 *    or FALSE to indicate whether it has it
 */
int prepare_capabilities(void) {
    cap_t capabilities;
    cap_value_t capability_to_add[1];
    cap_flag_value_t cap_sys_ptrace_status;

#ifndef CAP_SYS_PTRACE
    syslog(LOG_CRIT, "ptrace capability is not defined");
    return FALSE;
#else
    if (!CAP_IS_SUPPORTED(CAP_SYS_PTRACE)) {
        syslog(LOG_CRIT, "ptrace capability is not supported");
        return FALSE;
    }

    capability_to_add[0] = CAP_SYS_PTRACE;

    // check whether this process already has CAP_SYS_PTRACE set
    capabilities = cap_get_proc();
    if (capabilities == NULL) {
        syslog(LOG_CRIT, "getting capabilities of this process failed");
        return FALSE;
    }

    if (cap_get_flag(capabilities, CAP_SYS_PTRACE, CAP_EFFECTIVE, &cap_sys_ptrace_status) == -1) {
        syslog(LOG_CRIT, "checking effective capabilities failed");
        cap_free_safe(&capabilities);
        return FALSE;
    }

    if (cap_sys_ptrace_status == CAP_SET) {
        syslog(LOG_DEBUG, "process has CAP_SYS_PTRACE");
        return TRUE;
    }
    else {
        syslog(LOG_DEBUG, "process does not have CAP_SYS_PTRACE");
    }

    // see if we can set CAP_SYS_PTRACE
    if (cap_get_flag(capabilities, CAP_SYS_PTRACE, CAP_PERMITTED, &cap_sys_ptrace_status) == -1) {
        syslog(LOG_CRIT, "checking permitted capabilities failed");
        cap_free_safe(&capabilities);
        return FALSE;
    }

    if (cap_sys_ptrace_status == CAP_SET) {
        syslog(LOG_DEBUG, "process is permitted to acquire CAP_SYS_PTRACE");
    }
    else {
        syslog(LOG_CRIT, "process is not permitted to acquire CAP_SYS_PTRACE");
        return FALSE;
    }

    // actually set CAP_SYS_PTRACE
    if (cap_set_flag(capabilities, CAP_EFFECTIVE, 1, capability_to_add, CAP_SET) == -1) {
        syslog(LOG_CRIT, "modifying capability structure failed");
        cap_free_safe(&capabilities);
        return FALSE;
    }

    if (cap_set_proc(capabilities) == -1) {
        syslog(LOG_CRIT, "setting capability failed");
        cap_free_safe(&capabilities);
        return FALSE;
    }

    // check whether the process now has CAP_SYS_PTRACE set
    if (cap_get_flag(capabilities, CAP_SYS_PTRACE, CAP_EFFECTIVE, &cap_sys_ptrace_status) == -1) {
        syslog(LOG_CRIT, "checking effective capabilities failed");
        cap_free_safe(&capabilities);
        return FALSE;
    }

    if (cap_sys_ptrace_status == CAP_SET) {
        syslog(LOG_DEBUG, "process has CAP_SYS_PTRACE");
    }
    else {
        // log at critical level because this shouldn't happen
        syslog(LOG_CRIT, "process does not have CAP_SYS_PTRACE");
    }

    // free the memory
    if (cap_free_safe(&capabilities) == -1) {
        return FALSE;
    }

    return cap_sys_ptrace_status == CAP_SET;
#endif
}

int wait_using_waitpid() {
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
int wait_using_waitid() {
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

void detach(const int signal) {
    syslog(LOG_DEBUG, "detaching from process %d", pid);
    ptrace(PTRACE_DETACH, pid, 0, 0);
}

static const char* options = "v";
#ifdef _GNU_SOURCE
static struct option long_options[] = {
    {"verbose", no_argument, NULL, 'v'},
    {0, 0, 0, 0}
};
#endif

int main(const int argc, char* const* argv) {
    char* pidarg;
    char* endptr;
    long ptrace_return;
    int wait_return;
    struct sigaction siga, oldsiga_term, oldsiga_int;

    int verbose = 0;
    int c;

// some trickery to be able to use either getopt_long, if it's available, or getopt, if not
#ifdef _GNU_SOURCE
    int option_index;
    while ((c = getopt_long(argc, argv, options, long_options, &option_index)) != -1) {
#elif _POSIX_C_SOURCE >= 2 || defined(_XOPEN_SOURCE)
    while ((c = getopt(argc, argv, options)) != -1) {
#else
    while (FALSE) {
#endif
        switch (c) {
            case 'v':
                verbose = 1;
                break;
        }
    }

    if (optind >= argc) {
        usage(argv[0]);
        return EX_USAGE;
    }
    pidarg = argv[optind];

    openlog("pwait", verbose > 0 ? LOG_PERROR : LOG_CONS, LOG_USER);

    if (!prepare_capabilities()) {
        return EX_SOFTWARE;
    }

    pid = strtol(pidarg, &endptr, 0);
    if (pidarg == endptr) {
        syslog(LOG_CRIT, "First non-option argument \"%s\" must be a numeric PID", argv[optind]);
        if (!verbose) {
            fprintf(stderr, "First non-option argument \"%s\" must be a numeric PID", argv[optind]);
        }
        return EX_USAGE;
    }
    if (pid < 1) {
        syslog(LOG_CRIT, "Invalid process ID %d passed as first argument", pid);
        if (!verbose) {
            fprintf(stderr, "Invalid process ID %d passed as first argument", pid);
        }
        return EX_NOINPUT;
    }

    /* Set up a signal handler so that if the program receives a SIGINT (Ctrl+C)
     * or SIGTERM, it will detach from the tracee
     */
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

    syslog(LOG_INFO, "Process %d exited with status %d", pid, get_tracee_exit_status());

    closelog();
    return wait_return;
}

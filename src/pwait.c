#include <sys/capability.h>
#include <sched.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <sysexits.h>
#include <syslog.h>
#include <getopt.h>
#include <unistd.h>
#include "pwait.h"

#define TRUE 1
#define FALSE 0

static void usage(const char* name) {
    fprintf(stderr, "Usage: %s pid\n", name);
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
    pid_t pid;
    int status;
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

//     status = wait_using_ptrace(pid);
    status = wait_using_netlink(pid);

    closelog();
    return status;
}

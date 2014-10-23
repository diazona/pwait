#include <sys/capability.h>
#include <sched.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <sysexits.h>
#include <syslog.h>
#include <getopt.h>
#include <unistd.h>
#include <string.h>
#include "config.h"
#include "pwait.h"

#define TRUE 1
#define FALSE 0

#ifdef _GNU_SOURCE
#define HAVE_GETOPT_LONG
#endif

#if _POSIX_C_SOURCE >= 2 || defined(_XOPEN_SOURCE)
#define HAVE_GETOPT
#endif

static void usage(const char* name) {
#if defined(HAVE_GETOPT_LONG) || defined(HAVE_GETOPT)
    fprintf(stderr, "Usage: %s [OPTION]... PID\n", name);
#else
    fprintf(stderr, "Usage: %s PID\n", name);
#endif
}

static void help(const char* name) {
#if defined(HAVE_GETOPT_LONG) || defined(HAVE_GETOPT)
    printf("Usage: %s [OPTION]... PID\n", name);
#else
    printf("Usage: %s PID\n", name);
#endif
    printf("Wait for a process to finish and return its exit code\n");
#if !defined(HAVE_GETOPT_LONG) && !defined(HAVE_GETOPT)
    return;
#endif
    printf("\n");
#if defined(HAVE_GETOPT_LONG)
    printf("  -h, --help           print this help message and exit\n");
    printf("  -m, --method=METHOD  use METHOD to wait for the process, either ptrace or netlink\n");
    printf("  -v, --verbose        print diagnostic output to stderr\n");
#else
    printf("  -h    print this help message and exit\n");
    printf("  -m    use METHOD to wait for the process, either ptrace or netlink\n");
    printf("  -v    print diagnostic output to stderr\n");
#endif
}

static const char* options = "hm:v";
#ifdef HAVE_GETOPT_LONG
static struct option long_options[] = {
    {"help", no_argument, NULL, 'h'},
    {"method", required_argument, NULL, 'm'},
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

    int (*wait_function)(pid_t) = wait_using_netlink;

// some trickery to be able to use either getopt_long, if it's available, or getopt, if not
    int option_index;
#if defined(HAVE_GETOPT_LONG)
    while ((c = getopt_long(argc, argv, options, long_options, &option_index)) != -1) {
#elif defined(HAVE_GETOPT)
    while ((c = getopt(argc, argv, options)) != -1) {
#else
    while (FALSE) {
#endif
        switch (c) {
            case 'h':
                help(argv[0]);
                return EX_OK;
            case 'm':
                if (strncmp(optarg, "ptrace", 7) == 0) {
                    wait_function = wait_using_ptrace;
                }
                else if (strncmp(optarg, "netlink", 8) == 0) {
                    wait_function = wait_using_netlink;
                }
                else {
                    wait_function = NULL;
                }
                break;
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

    if (wait_function == NULL) {
        fprintf(stderr, "Invalid method (use \"ptrace\" or \"netlink\")");
        return EX_USAGE;
    }

    pid = strtol(pidarg, &endptr, 0);
    if (pidarg == endptr) {
        fprintf(stderr, "First non-option argument \"%s\" must be a numeric PID", argv[optind]);
        return EX_USAGE;
    }
    if (pid < 1) {
        fprintf(stderr, "Invalid process ID %d passed as first argument", pid);
        return EX_NOINPUT;
    }

    status = wait_function(pid);

    closelog();
    return status;
}

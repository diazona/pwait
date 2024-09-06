/*
 * Inspired by http://bewareofgeek.livejournal.com/2945.html
 */

#include <errno.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <sysexits.h>
#include <unistd.h>
#include <asm/types.h>
#include <sys/socket.h>
#include <linux/netlink.h>
#include <linux/connector.h>
#include <linux/cn_proc.h>
#include <linux/rtnetlink.h>
#include "pwait.h"

/**
 * Create a connector netlink socket.
 *
 * @return The file descriptor for the socket, or -1 if there is an error.
 */
static int create_netlink_socket() {
    int netlink_socket = socket(AF_NETLINK, SOCK_RAW, NETLINK_CONNECTOR);
    if (netlink_socket == -1) {
        syslog(LOG_CRIT, "Unable to create netlink socket");
    }
    return netlink_socket;
}

/**
 * Bind a connector netlink socket to the process-related message group.
 *
 * @return @c TRUE if the operation succeeded or @c FALSE if not.
 */
static int bind_netlink_socket(int netlink_socket) {
    struct sockaddr_nl address = {
        .nl_family = AF_NETLINK,
        .nl_groups = CN_IDX_PROC,
        .nl_pid = getpid(),
    };

    int bind_result = bind(netlink_socket, (struct sockaddr*)&address, sizeof address);
    if (bind_result == -1) {
        syslog(LOG_CRIT, "Unable to bind netlink socket");
        return FALSE;
    }

    return TRUE;
}

/**
 * Send a message to the given netlink socket to subscribe it to process events.
 */
static int subscribe_to_process_events(int netlink_socket) {
    struct __attribute__ ((aligned(NLMSG_ALIGNTO))) {
        struct nlmsghdr header;
        struct __attribute__ ((__packed__)) {
            struct cn_msg message;
            enum proc_cn_mcast_op desired_status;
        };
    } netlink_message;
    memset(&netlink_message, 0, sizeof netlink_message);

    netlink_message.header.nlmsg_len = sizeof netlink_message;
    netlink_message.header.nlmsg_pid = getpid();
    netlink_message.header.nlmsg_type = NLMSG_DONE; // indicates the last message in a series

    netlink_message.message.id.idx = CN_IDX_PROC;
    netlink_message.message.id.val = CN_VAL_PROC;
    netlink_message.message.len = sizeof(enum proc_cn_mcast_op);

    netlink_message.desired_status = PROC_CN_MCAST_LISTEN;

    if (send(netlink_socket, &netlink_message, sizeof netlink_message, 0) == -1) {
        syslog(LOG_CRIT, "Unable to send message to netlink socket");
        return FALSE;
    }

    return TRUE;
}


static volatile int terminate = FALSE;

/**
 * Listen on the given netlink socket for a message indicating that the given
 * process ID has terminated.
 *
 * @param nl_sock The socket to listen on.
 * @param target_pid The process ID whose termination should be listened for.
 * @return The exit code of the process, or -1 if an error occurred.
 */
static int listen_for_process_termination(int nl_sock, pid_t target_pid) {
    struct __attribute__ ((aligned(NLMSG_ALIGNTO))) {
        struct nlmsghdr nl_hdr;
        struct __attribute__ ((__packed__)) {
            struct cn_msg cn_msg;
            struct proc_event proc_ev;
        };
    } netlink_message;

    while (!terminate) {
        int receive_result = recv(nl_sock, &netlink_message, sizeof(netlink_message), 0);
        if (receive_result == 0) {
            // probably means the socket was shut down from the other end
            syslog(LOG_CRIT, "Socket appears to have been shut down");
            return -1;
        }
        else if (receive_result == -1) {
            if (errno == EINTR) {
                continue;
            }
            syslog(LOG_CRIT, "Error receiving from netlink socket");
            return -1;
        }
        if (netlink_message.proc_ev.what == PROC_EVENT_EXIT && netlink_message.proc_ev.event_data.exit.process_pid == target_pid) {
            return netlink_message.proc_ev.event_data.exit.exit_code;
        }
    }
    return -1;
}

/**
 * Stop the loop that listens for process exit messages.
 */
static void stop_listening(const int signal) {
    terminate = TRUE;
}


/**
 * Signal handlers for @c SIGTERM and @c SIGINT.
 */
struct signal_handlers {
    struct sigaction term_action;
    struct sigaction int_action;
};

/**
 * Install the given new signal handlers for @c SIGTERM and @c SIGINT and store
 * the old ones in the given structure.
 *
 * @param new_handlers The new handlers to install.
 * @param[out] old_handlers The structure to store the old handlers in.
 */
static void swap_signal_handlers(const struct signal_handlers* new_handlers, struct signal_handlers* old_handlers) {
    sigaction(SIGTERM, &(new_handlers->term_action), &(old_handlers->term_action));
    sigaction(SIGINT, &(new_handlers->int_action), &(old_handlers->int_action));
}


/**
 * Wait for a process to exit and capture its exit code using netlink.
 *
 * @param pid The process ID of the process to wait for.
 * @return The exit code of the process, or @c EX_OSERR if an error occurred.
 */
int wait_using_netlink(pid_t pid) {
    if (geteuid() != 0) {
#if defined(CAP_NET_ADMIN)
        cap_value_t capability_to_acquire[1] = {CAP_NET_ADMIN};
        if (!acquire_capabilities(1, capability_to_acquire)) {
            return EX_SOFTWARE;
        }
#else
        syslog(LOG_CRIT, "CAP_NET_ADMIN not available");
        return EX_SOFTWARE;
#endif
    }

    int nl_socket = create_netlink_socket();
    if (!bind_netlink_socket(nl_socket)) {
        close(nl_socket);
        return EX_OSERR;
    }
    if (!subscribe_to_process_events(nl_socket)) {
        close(nl_socket);
        return EX_OSERR;
    }

    int process_result;
    {
        struct signal_handlers new_handlers = {
            .term_action = {.sa_handler = stop_listening},
            .int_action = {.sa_handler = stop_listening},
        };
        struct signal_handlers old_handlers;

        swap_signal_handlers(&new_handlers, &old_handlers);
        process_result = listen_for_process_termination(nl_socket, pid);
        // Reset the signal handler (hopefully TERM or INT doesn't come right here)
        swap_signal_handlers(&old_handlers, &new_handlers);
    }

    if (process_result == -1) {
        close(nl_socket);
        return EX_OSERR;
    }
    syslog(LOG_INFO, "Process %d exited with status %d", pid, WEXITSTATUS(process_result));

    return WEXITSTATUS(process_result);
}

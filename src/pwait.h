#pragma once

#include <signal.h>
#include <sys/capability.h>

#define TRUE 1
#define FALSE 0

/**
 * Make a best effort to ensure that the process has a certain set of
 * capabilities. If it already does, or if this function was able to set all
 * of the requested capabilities, this returns 1 (TRUE). Otherwise, this
 * returns 0 (FALSE).
 *
 * The function is a bit long because it checks for error codes at every step,
 * but conceptually what it does for each requested capability is very
 * straightforward:
 * 1. Check whether the capability is supported by the kernel
 * 2. Check whether the process already has the capability set, and if so,
 *    return TRUE
 * 3. Check whether the process is allowed to give itself the capability, and
 *    if not, return FALSE
 * 4. Attempt to actually set the capability
 * 5. Check again to make sure the process has the capability, and return
 *    FALSE if not
 */
int acquire_capabilities(size_t n, const cap_value_t* capabilities_to_acquire);

int wait_using_ptrace(pid_t pid);
int wait_using_netlink(pid_t pid);

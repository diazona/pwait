#include <sys/capability.h>
#include <stdlib.h>
#include <syslog.h>
#include "pwait.h"

#define TRUE 1
#define FALSE 0

static int cap_free_safe(void* p_capabilities) {
    int status = cap_free(p_capabilities);
    if (status == -1) {
        syslog(LOG_DEBUG, "cap_free failed");
    }
    return status;
}

int acquire_capabilities(size_t n, const cap_value_t* capabilities_to_acquire) {
    int cap_acquire_was_successful = FALSE;
    cap_t capabilities;
    cap_flag_value_t cap_status;
    size_t i;
    char* capability_spec = NULL;

    capabilities = cap_get_proc();
    if (capabilities == NULL) {
        syslog(LOG_CRIT, "getting capabilities of this process failed");
        return FALSE;
    }

    capability_spec = cap_to_text(capabilities, NULL);
    syslog(LOG_DEBUG, "process capabilities: %s", capability_spec);
    cap_free_safe(capability_spec);

    // first try setting the capabilities
    if (cap_set_flag(capabilities, CAP_EFFECTIVE, n, capabilities_to_acquire, CAP_SET) == -1) {
        // this generally shouldn't happen
        syslog(LOG_CRIT, "modifying capability structure failed");
        cap_free_safe(&capabilities);
        return FALSE;
    }

    if (cap_set_proc(capabilities) == 0) {
        // everything should be okay at this point
        syslog(LOG_DEBUG, "setting process capabilities succeeded");
        cap_acquire_was_successful = TRUE;
        // but let's be a little paranoid and check whether this process
        // _actually_ has the capabilities set
        cap_free_safe(capabilities);
        capabilities = cap_get_proc();
        for (i = 0; i < n; i++) {
            if (cap_get_flag(capabilities, capabilities_to_acquire[i], CAP_EFFECTIVE, &cap_status) == -1) {
                syslog(LOG_CRIT, "checking effective capabilities failed");
                cap_free_safe(&capabilities);
                return FALSE;
            }
            if (cap_status != CAP_SET) {
                capability_spec = cap_to_name(capabilities_to_acquire[i]);
                syslog(LOG_CRIT, "process did not acquire %s", capability_spec);
                cap_free_safe(capability_spec);
                cap_acquire_was_successful = FALSE;
            }
        }
        return cap_acquire_was_successful;
    }

    // setting capabilities failed
    cap_acquire_was_successful = FALSE;
    syslog(LOG_CRIT, "setting process capabilities failed");

    // let's find out why
    for (i = 0; i < n; i++) {
        // check if the capability was supported at all
        if (!CAP_IS_SUPPORTED(capabilities_to_acquire[i])) {
            capability_spec = cap_to_name(capabilities_to_acquire[i]);
            syslog(LOG_CRIT, "capability %s is not supported", capability_spec);
            cap_free_safe(capability_spec);
            continue;
        }
        // check if it's permitted to set the capability
        if (cap_get_flag(capabilities, capabilities_to_acquire[i], CAP_PERMITTED, &cap_status) == -1) {
            syslog(LOG_CRIT, "checking permitted capabilities failed");
            continue;
        }
        capability_spec = cap_to_name(capabilities_to_acquire[i]);
        if (cap_status == CAP_SET) {
            syslog(LOG_DEBUG, "process is permitted to acquire %s", capability_spec);
        }
        else {
            syslog(LOG_CRIT, "process is not permitted to acquire %s", capability_spec);
        }
        cap_free_safe(capability_spec);
    }

    cap_free_safe(&capabilities);
    return cap_acquire_was_successful;
}

#include <syslog.h>
#include <unistd.h>
#include "pwait.h"


static int process_exists(pid_t pid) {
    // https://stackoverflow.com/a/31931126/56541
    return getpgid(pid) >= 0;
}


static unsigned int poll_delay = 5;


void set_delay(unsigned int delay) {
    poll_delay = delay;
}


int wait_using_polling(pid_t pid) {
    int return_code = -1;
    while (process_exists(pid)) {
        return_code = 0;
        sleep(poll_delay);
    }
    syslog(LOG_INFO, "Process %d exited with unknown status", pid);
    return return_code;
}

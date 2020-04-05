#include <stdio.h>
#include <syslog.h>

int main(int argc, char * argv[]) {
    setlogmask (LOG_UPTO (LOG_NOTICE));

    openlog (argv[0], LOG_CONS | LOG_PID | LOG_NDELAY | LOG_PERROR, LOG_LOCAL1);

    syslog (LOG_USER, "A tree falls in a forest");

    closelog ();
}
#ifndef MILS_LOG_H
#define MILS_LOG_H
#define error_exit(s)   error("%s: %s", s, strerror(errno)); \
                        exit(EXIT_FAILURE);
#include <syslog.h>

typedef enum {
    LOG_LEVEL_ERR,
    LOG_LEVEL_WARNING,
    LOG_LEVEL_INFO,
    LOG_LEVEL_DEBUG
}   LogLevel;

typedef enum {
    LOG_FACILITY_DAEMON,
    LOG_FACILITY_USER,
    LOG_FACILITY_AUTHPRIV
}   LogFacility;


void    log_init(char * av0, LogLevel, LogFacility, int on_stderr);

void    error(const char *, ...) __attribute__((format(printf, 1, 2)));
void    info(const char *, ...) __attribute__((format(printf, 1, 2)));
void    warn(const char *, ...) __attribute__((format(printf, 1, 2)));
void    debug(const char *, ...) __attribute__((format(printf, 1, 2)));

#endif

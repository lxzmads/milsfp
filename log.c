/**
 * @author mads
 * @email 86625902@qq.com
 * @create date 2020-03-19 16:04:46
 * @modify date 2020-03-19 16:04:46
 * @desc proxy to system logger, import from openssh 2.9.9p2.
 */


#include "log.h"
#include "includes.h"

#include <syslog.h>

static LogLevel log_level = LOG_LEVEL_INFO;
static int log_on_stderr = 1;
static LogFacility log_facility = LOG_AUTHPRIV;
static char *argv0;

extern char *__progname;

static void do_log(LogLevel, const char *fmt, va_list);

/**
 * Initialize logger.
 */
void
log_init(char *av0, LogLevel level, LogFacility facility, int on_stderr)
{
    log_on_stderr = on_stderr;
    argv0 = av0;

    switch(level){
        case LOG_LEVEL_ERR:
        case LOG_LEVEL_WARNING:
        case LOG_LEVEL_INFO:
        case LOG_LEVEL_DEBUG:
            log_level = level;
            break;
        default:
            fprintf(stderr, "Unrecognized internal syslog level code %d\n", (int)level);
            exit(1);
    }

    if(on_stderr) return;

    switch(facility){
        case LOG_FACILITY_AUTHPRIV:
            log_facility = LOG_AUTHPRIV;
            break;
        case LOG_FACILITY_DAEMON:
            log_facility = LOG_DAEMON;
            break;
        case LOG_FACILITY_USER:
            log_facility = LOG_USER;
            break;
        default:
            fprintf(stderr, "Unrecognized internal syslog facility code %d\n", (int)facility);
            exit(1);
    }
}

void
error(const char *fmt,...)
{
    va_list args;
    va_start(args, fmt);
    do_log(LOG_LEVEL_ERR, fmt, args);
    va_end(args);
    exit(1);

}

void
info(const char *fmt,...)
{
    va_list args;
    va_start(args, fmt);
    do_log(LOG_LEVEL_INFO, fmt, args);
    va_end(args);
}

void
warn(const char *fmt,...)
{
    va_list args;
    va_start(args, fmt);
    do_log(LOG_LEVEL_WARNING, fmt, args);
    va_end(args);
}

void
debug(const char *fmt,...)
{
    va_list args;
    va_start(args, fmt);
    do_log(LOG_LEVEL_DEBUG, fmt, args);
    va_end(args);
}

static void
do_log(LogLevel level, const char *fmt, va_list args)
{
    char msgbuf[1024];
    char fmtbuf[1024];
    char *txt = NULL;
    char *color = NULL;
    int pri = LOG_INFO;


    /* Equals to setlogmask */
    if (level > log_level){
        return;
    }

    switch(level){
        case LOG_LEVEL_ERR:
            pri = LOG_ERR;
            color = "\033[31m";
            txt = "ERROR";
            break;
        case LOG_LEVEL_WARNING:
            pri = LOG_WARNING;
            color = "\033[33m";
            txt = "WARN";
            break;
        case LOG_LEVEL_INFO:
            pri = LOG_INFO;
            color = "\033[34m";
            txt = "INFO";
            break;
        case LOG_LEVEL_DEBUG:
            pri = LOG_DEBUG;
            color = "\033[32m";
            txt = "DEBUG";
            break;
        default:
            pri = LOG_ERR;
            color = "\033[31m";
            txt = "log internal error";
            break;
    }

    if(log_on_stderr){
        snprintf(fmtbuf, sizeof(fmtbuf), "%s%-5s\033[0m: %s", color, txt, fmt);
    }else{
        snprintf(fmtbuf, sizeof(fmtbuf), "%s: %s", txt, fmt);
    }
    vsnprintf(msgbuf, sizeof(msgbuf), fmtbuf, args);

    if(log_on_stderr){
        fprintf(stderr, "%s\r\n", msgbuf);
    }else{
        openlog(argv0 ? argv0 : __progname, LOG_PID | LOG_PERROR, log_facility);
        syslog(pri, "%.500s", msgbuf);
        closelog();
    }
}
/**
 * @author mads
 * @email 86625902@qq.com
 * @create date 2020-03-22 16:10:34
 * @modify date 2020-03-22 16:10:34
 * @desc log test
 */

#include "log.h"

#include <stdio.h>

int main(int argc, char const *argv[])
{
    char *__progname = (char*)argv[0];
    log_init(__progname, LOG_LEVEL_INFO, LOG_FACILITY_USER, 1);
    info("test logger %s", "123");
    error("some error in %s", "the world");
    warn("wong wong wong, %d", 123);
    debug("debugging"); // ignored, wont print to stderr
    return 0;
}

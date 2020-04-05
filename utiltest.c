#include <stdio.h>
#include "utils.h"

int
main()
{
    char res[5120];
    int size;
    readfile("/etc/passwd", res);
    printf("%s\n", res);
    return 0;
}
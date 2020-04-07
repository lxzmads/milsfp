#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

int
pwd(char **buffer)
{
    char *res = getcwd(*buffer, MAXDIRLEN);

    if (NULL == res) {
        error_exit("pwd()");
    } else {
        return 0;
    }
}

int main()
{   
    char buf[1024];

    char *cwd =getcwd(buf, sizeof(buf));

    if (NULL == cwd) {
        perror("Get cerrent working directory fail.\n");
        exit(-1);
    } else {
        printf("Current working directory is : %s\n", buf);
    }

    return 0;
}
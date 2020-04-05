#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <stdlib.h>

int main(int argc, char *argv[])
{
    FILE *fp = NULL;
    char b[30];

    chroot(".");
    chdir("/");

    if ((fp = fopen("/etc/passwd", "r")) == NULL)
    {
        fprintf(stderr, "%s\n", strerror(errno));
        exit(EXIT_FAILURE);
    }
    chroot("/");
    if ((fp = fopen("/etc/passwd", "r")) == NULL)
    {
        fprintf(stderr, "%s\n", strerror(errno));
        exit(EXIT_FAILURE);
    }
    fread(b, sizeof(char), 25, fp);
    printf("%s\n", b);
    fclose(fp);

    return 0;
}
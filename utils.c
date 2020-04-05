
#include <dirent.h>

#include "includes.h"
#include "utils.h"
#include "log.h"

int
listdir(char *path, char *buffer)
{

    struct dirent **entry_list;
    int count;
    int i,j=0;
 
    count = scandir(path, &entry_list, 0, alphasort);
    if (count < 0) {
        error("scandir()");
        return -1;
    }
    for (i = 0; i < count; i++) {
        struct dirent *entry;
        entry = entry_list[i];
        j += snprintf(buffer+j, MAXDIRLEN, "%s\n", entry->d_name);
        free(entry);
    }
    free(entry_list);
    return 0;
}

int
createdir(char *path)
{

    return 0;

}

int
deldir(char *paht)
{

    return 0;
}

int
readfile(char *filename, char **buffer, int *size)
{
    long numbyte;

    FILE *f = fopen(filename, "rb");
    fseek(f, 0L, SEEK_END);
    numbyte = ftell(f);
    fseek(f, 0L, SEEK_SET);
    *buffer = (char *)malloc(numbyte);
    printf("%p\n",*buffer);
    fread(*buffer, sizeof(char), numbyte, f);
    *size = numbyte;
    return 0;
}

int
writefile(char *filename, char *buffer, int size)
{
    FILE *f = fopen(filename, "wb");
    fwrite(buffer, size, 1, f);
    fclose(f);
    return 0;
}

int
delfile(char *filename)
{
    
    return 0;

}

void
str_dump(char *str, size_t len)
{
    int i;
	char *ucp = str;
    char sbuf[5124] = {0};

	for (i = 0; i < len; i++) {
		printf("%02x ", ucp[i]);
	}
	printf("\n");
}
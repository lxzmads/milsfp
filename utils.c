#include "includes.h"
#include "utils.h"
#include "log.h"

#include <dirent.h>
#include <sys/stat.h>

int
listdir(char *path, char *buffer)
{

    struct dirent **entry_list;
    int count;
    int i,j=0;
 
    count = scandir(path, &entry_list, 0, alphasort);
    if (count < 0) {
        return -1;
    }
    for (i = 0; i < count; i++) {
        struct dirent *entry;
        entry = entry_list[i];
        j += snprintf(buffer+j, MAXDIRLEN, "%s ", entry->d_name);
        free(entry);
    }
    free(entry_list);
    return 0;
}

int
pwd(char **buffer)
{
    char *res = getcwd(NULL, MAXDIRLEN);

    if (NULL == res) {
        error_exit("pwd()");
    } else {
        *buffer = res;
        return 0;
    }
}

int
createdir(char *path)
{
    struct stat st = {0};
    int err;

    if(stat(path, &st) == -1){
        err = mkdir(path, 0700);
        return err;
    }
    return -1;

}

int
deldir(char *path)
{
    return rmdir(path);
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
    fread(*buffer, sizeof(char), numbyte, f);
    *size = numbyte;
    return 0;
}

int
writefile(char *filename, char *buffer, int size)
{
    FILE *f = fopen(filename, "wb");
    int res = fwrite(buffer, size, 1, f);
    fclose(f);
    return res > 0?0:-1;
}

int
delfile(char *filename)
{
    return remove(filename);

}

int
cd(char *path)
{
    if(opendir(path) != NULL){
        return chdir(path);
    }
    return -1;
}

void
str_dump(char *str, size_t len)
{
    int i;
	char *ucp = str;

	for (i = 0; i < len; i++) {
		printf("%02x ", ucp[i]);
	}
	printf("\n");
}

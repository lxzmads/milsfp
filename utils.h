#ifndef MILS_UTILS_H
#define MILS_UTILS_H


#define MAXDIRLIST_LEN 5120
#define MAXDIRLEN 512

/* 文件和目录操作 */
int     listdir(char *path, char *buffer);
int     createdir(char *path);
int     deldir(char *paht);
int     readfile(char *filename, char **buffer, int *size);
int     writefile(char *filename, char *buffer, int size);
int     delfile(char *filename);
void    str_dump(char *str, size_t len);
#endif
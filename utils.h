#ifndef MILS_UTILS_H
#define MILS_UTILS_H


#define MAXDIRLIST_LEN 5120
#define MAXDIRLEN 1024

/* 文件和目录操作 */
int     listdir(char *path, char *buffer);
int     pwd(char **buffer);
int     createdir(char *path);
int     deldir(char *path);
int     readfile(char *filename, char **buffer, int *size);
int     writefile(char *filename, char *buffer, int size);
int     delfile(char *filename);
int     cd(char *path);
void    str_dump(char *str, size_t len);
#endif
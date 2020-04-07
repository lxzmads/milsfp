#ifndef MILS_CMDLOOP_H
#define MILS_CMDLOOP_H

#define TOK_BUFSIZE 64
#define TOK_DELIM " \t\r\n\a"
#define PARAMSIZE 1024

#define CMD(name, args) do{\
        current_cmd_func = do_c_##name;\
        params = args;\
        cmd_push = 1;\
        return 0;\
    }while(0)

#define mc_login(args) CMD(login, args)
#define mc_pwd(args) CMD(pwd, args)
#define mc_put(args) CMD(put, args)
#define mc_del(args) CMD(del, args)
#define mc_get(args) CMD(get, args)
#define mc_ls(args) CMD(ls, args)
#define mc_mkdir(args) CMD(mkdir, args)
#define mc_rmdir(args) CMD(rmdir, args)
#define mc_cd(args) CMD(cd, args)

int c_login(char **args);
int c_pwd(char **args);
int c_put(char **args);
int c_del(char **args);
int c_get(char **args);
int c_ls(char **args);
int c_mkdir(char **args);
int c_rmdir(char **args);
int c_cd(char **args);
int c_help();
int c_exit();

int do_c_login(SSL *ssl, char **param);
int do_c_pwd(SSL *ssl, char **param);
int do_c_put(SSL *ssl, char **param);
int do_c_del(SSL *ssl, char **param);
int do_c_get(SSL *ssl, char **param);
int do_c_ls(SSL *ssl, char **param);
int do_c_mkdir(SSL *ssl, char **param);
int do_c_rmdir(SSL *ssl, char **param);
int do_c_cd(SSL *ssl, char **param);
int command_loop();

#endif
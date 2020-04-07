#include "includes.h"
#include "parcel.h"
#include "log.h"
#include "cmdloopgui.h"
#include "utils.h"
#include "libgen.h"

int cmd_push = 0;
int (*current_cmd_func)(SSL *,char **);
char **params;


const char *command_str[] = {
    "LOGIN",
    "pwd",
    "PUT",
    "DEL",
    "GET",
    "ls",
    "MKDIR",
    "RMDIR",
    "cd",
    "EXIT"
};
int (*command_func[]) (char **) = {
    &c_login,
    &c_pwd,
    &c_put,
    &c_del,
    &c_get,
    &c_ls,
    &c_mkdir,
    &c_rmdir,
    &c_cd,
    &c_exit
};

int
c_help()
{
    gprintf("COMMANDS: HELP EXIT LOGIN ls GET PUT DEL MKDIR RMDIR cd pwd\n");
    return -1;    
}

int
c_exit()
{
    // free something.
    exit(EXIT_SUCCESS);
    return 0;
}


static int
plain_cmd(SSL *ssl, int cmd)
{
    int sslerr,wd;

    parcel_reqhdr *req = (parcel_reqhdr *)malloc(sizeof(parcel_reqhdr));
    req->cmd = cmd;
    req->size = 0;
    char *buf = (char *)malloc(sizeof(parcel_reqhdr));
    if(!buf){
        error_exit("malloc()");
    }
    memset(buf, 0, sizeof(parcel_reqhdr));
    memcpy(buf, req, sizeof(parcel_reqhdr));
    // str_dumps(buf, sizeof(parcel_reqhdr));
    wd = SSL_write(ssl, buf, sizeof(parcel_reqhdr));
    if(wd <= 0){
        sslerr = SSL_get_error(ssl, wd);
        info("sslerr=%d", sslerr);
        if (sslerr != SSL_ERROR_WANT_WRITE){
            ERR_print_errors_fp(stderr);
            error_exit("parcel_recv()");
        }else{
            return SSL_ERROR_WANT_WRITE;
        }
    }
    return 0;
}

static int
plain_cmd1(SSL *ssl, int cmd, char *param)
{
    int sslerr,wd;

    parcel_reqhdr *req = (parcel_reqhdr *)malloc(sizeof(parcel_reqhdr));
    req->cmd = cmd;
    strncpy(req->param, param, MAXPARAM);
    req->param[MAXPARAM] = 
    req->size = 0;
    char *buf = (char *)malloc(sizeof(parcel_reqhdr));
    if(!buf){
        error_exit("malloc()");
    }
    memset(buf, 0, sizeof(parcel_reqhdr));
    memcpy(buf, req, sizeof(parcel_reqhdr));
    // str_dumps(buf, sizeof(parcel_reqhdr));
    wd = SSL_write(ssl, buf, sizeof(parcel_reqhdr));
    if(wd <= 0){
        sslerr = SSL_get_error(ssl, wd);
        info("sslerr=%d", sslerr);
        if (sslerr != SSL_ERROR_WANT_WRITE){
            ERR_print_errors_fp(stderr);
            error_exit("parcel_recv()");
        }else{
            return SSL_ERROR_WANT_WRITE;
        }
    }
    return 0;
}

static char
**command_split(const char *linep)
{
    char *token = NULL;
    int i = 0, size =  TOK_BUFSIZE;
    char **tokens = malloc(TOK_BUFSIZE * sizeof(char *));

    if(!tokens){
        error_exit("get_and_split()");
    }
    token = strsep(&linep, TOK_DELIM);
    while(token != NULL){
        tokens[i++] = token;

        if(i >= size){
            size += TOK_BUFSIZE;
            tokens = realloc(tokens, size * sizeof(char *));
            if(!tokens){
                error_exit("get_and_split()");
            }
        }
        token = strsep(&linep, TOK_DELIM);
    }
    tokens[i] = NULL;
    return tokens;
}

int
c_login(char **args)
{
    mc_login(args);
    return 0;
}

int
do_c_login(SSL *ssl, char **param)
{
    int sslerr,wd;

    parcel_reqhdr *req = (parcel_reqhdr *)malloc(sizeof(parcel_reqhdr));
    req->cmd = CMD_LOGIN;
    snprintf(req->param, MAXPARAM, "%s:%s", param[1],param[2]);
    req->param[MAXPARAM] = 
    req->size = 0;
    char *buf = (char *)malloc(sizeof(parcel_reqhdr));
    if(!buf){
        error_exit("malloc()");
    }
    memset(buf, 0, sizeof(parcel_reqhdr));
    memcpy(buf, req, sizeof(parcel_reqhdr));
    // str_dumps(buf, sizeof(parcel_reqhdr));
    wd = SSL_write(ssl, buf, sizeof(parcel_reqhdr));
    if(wd <= 0){
        sslerr = SSL_get_error(ssl, wd);
        info("sslerr=%d", sslerr);
        if (sslerr != SSL_ERROR_WANT_WRITE){
            ERR_print_errors_fp(stderr);
            error_exit("parcel_recv()");
        }else{
            return SSL_ERROR_WANT_WRITE;
        }
    }
    return 0;


}

int
c_put(char **args)
{
    mc_put(args);
    return 0;
}

int
do_c_put(SSL *ssl, char **param)
{
    int sslerr,wd;
    char *filebuf, *packet;
    int filesize;
    int sended;

    readfile(param[1], &filebuf, &filesize);
    packet = (char *)malloc(filesize + sizeof(parcel_reqhdr));
    if(!packet){
        error_exit("malloc()");
    }
    parcel_reqhdr *req = (parcel_reqhdr *)malloc(sizeof(parcel_reqhdr));
    req->cmd = CMD_PUT;
    strncpy(req->param, basename(param[1]), MAXPARAM);
    req->param[MAXPARAM] = 0;
    req->size = filesize;

    memset(packet, 0, sizeof(parcel_reqhdr) + filesize);
    memcpy(packet, req, sizeof(parcel_reqhdr));
    memcpy(packet + sizeof(parcel_reqhdr), filebuf, filesize);
    sended = 0;
    // str_dumps(buf, sizeof(parcel_reqhdr));
    while((wd = SSL_write(ssl, packet + sended, sizeof(parcel_reqhdr) + filesize)) > 0){
        sended += wd;
        if(sended == sizeof(parcel_reqhdr) + filesize){
            break;
        }
    }
    if(wd <= 0){
        sslerr = SSL_get_error(ssl, wd);
        info("sslerr=%d", sslerr);
        if (sslerr != SSL_ERROR_WANT_WRITE){
            ERR_print_errors_fp(stderr);
            error_exit("parcel_recv()");
        }else{
            return SSL_ERROR_WANT_WRITE;
        }
    }
    return 0;
}

int
c_del(char **args)
{
    mc_del(args);
    return 0;
}

int
do_c_del(SSL *ssl, char **param)
{
    return plain_cmd1(ssl, CMD_DEL,param[1]);
}

int
c_get(char **args)
{
    mc_get(args);
    return 0;
}


int
do_c_get(SSL *ssl, char **param)
{
    return plain_cmd1(ssl, CMD_GET, param[1]);
}

int
c_ls(char **args)
{
    mc_ls(args);
    return 0;
}
int
do_c_ls(SSL *ssl, char **param)
{
    return plain_cmd(ssl, CMD_LS);
}
int
c_mkdir(char **args)
{
    mc_mkdir(args);
    return 0;
}
int
do_c_mkdir(SSL *ssl, char **param)
{
    return plain_cmd1(ssl, CMD_MKDIR, param[1]);
}

int
c_rmdir(char **args)
{
    mc_rmdir(args);
    return 0;
}

int
do_c_rmdir(SSL *ssl, char **param)
{
    return plain_cmd1(ssl, CMD_RMDIR, param[1]);
}

int
c_cd(char **args)
{
    mc_cd(args);
    return 0;
}
int
do_c_cd(SSL *ssl, char **param)
{
    return plain_cmd1(ssl, CMD_CD, param[1]);
}

int
c_pwd(char **args)
{
    mc_pwd(args);
    return 0;
}
int
do_c_pwd(SSL *ssl, char **param)
{    
    return plain_cmd(ssl, CMD_PWD);
}


int
command_execute(const char *linep)
{
    char **args;

    args = command_split(linep);

    if (args[0] == NULL) {
        return 1;
    }

    for (int i = 0; i < sizeof(command_str)/sizeof(char *); i++) {
        if (strcmp(args[0], command_str[i]) == 0) {
            return (*command_func[i])(args);
        }
    }
    free(args);
    return -1;
}
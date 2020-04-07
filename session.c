#include "includes.h"
#include "session.h"
#include "milssl.h"
#include "log.h"

/* 会话与fd映射表, 目的是动态申请session，减少空间占用 */
SessionMap sessmap[MAXSESSION] = {0};

// static int
// session_status(int fd)
// {
//     if(sessmap[fd]){
//         return 1;
//     }else{
//         return 0;
//     }
// }
#define AUTHENTICATED 1
#define NOT_AUTHENTICATED 0

Session * 
session_get(int fd)
{
    return sessmap[fd];
}

/* 传入fd，初始化一个session */
int
session_start(int fd, char *in_host, char *in_port)
{
    Session *s;

    info("Session start");
    s = (Session *)malloc(sizeof(Session));
    if(!s){
        error_exit("malloc()");
    }
    memset(s, 0, sizeof(Session));
    debug("Session address: %p", s);
    s->fd = fd;
    s->fromhost = in_host;
    s->fromport = in_port;
    s->authenticated = NOT_AUTHENTICATED;
    s->privilege = NO_PRIV;
    s->r_s = SESS_R_NO;
    s->w_s = SESS_W_FIN;
    sessmap[fd] = s;
    ssl_init(s);
    while(ssl_start(s) == EAGAIN);
    return 0;
}


/* 销毁session */
int
session_stop(int fd)
{
    SSL_free(sessmap[fd]->ssl);
    free(sessmap[fd]);
    sessmap[fd] = NULL;
    /* Be caution about UAF */
    return 0;
}
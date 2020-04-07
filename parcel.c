#include "includes.h"
#include "session.h"
#include "parcel.h"
#include "log.h"
#include "utils.h"
#include "auth.h"

#include <libgen.h>

#define MAXEVENTS 10

char inbuf[MAXBUFFER_IN_HDR];
char outbuf[MAXBUFFER_OUT_HDR];
int epoll_fd, active_evnum;
struct epoll_event ev;
struct epoll_event events[MAXEVENTS];

static int
socket_set_noblocking(int sfd)
{
    int flags = fcntl(sfd, F_GETFL, 0);
    if (flags == -1)
    {
        error_exit("socket_set_noblocking()");
    }
    int res = fcntl(sfd, F_SETFL, flags | O_NONBLOCK);
    if (res == -1)
    {
        error_exit("socket_set_noblocking()");
    }
    return 0;
}

static int
parcel_read_ihdr(Session *s, char buffer[])
{
    /* 填入header，计算size 初始化recvbuf */
    if(s->inhdr){
        free(s->inhdr);
    }
    s->inhdr = (char *)malloc(sizeof(parcel_reqhdr));
    if(!s->inhdr){
        error_exit("malloc()");
    }
    memcpy(s->inhdr, buffer, MAXBUFFER_IN_HDR);
    s->recvbuf_size = ((parcel_reqhdr *)s->inhdr)->size + MAXBUFFER_IN_HDR;
    s->recvbuf_exist = MAXBUFFER_IN_HDR;
    s->recvbuf = (char *)malloc(s->recvbuf_size);
    if(!s->recvbuf){
        error_exit("malloc()");
    }
    memcpy(s->recvbuf, buffer, MAXBUFFER_IN_HDR);
    return 0;
}

static int
parcel_prepare_ohdr(Session *s, char buffer[])
{
    if(s->outhdr){
        free(s->outhdr);
    }
    s->outhdr = (char *)malloc(sizeof(parcel_reshdr));
    if(!s->outhdr){
        error_exit("malloc()");
    }
    memcpy(s->outhdr, buffer, MAXBUFFER_OUT_HDR);
    s->sendbuf_size = ((parcel_reshdr *)s->outhdr)->size + MAXBUFFER_OUT_HDR;
    s->sendbuf_left = s->sendbuf_size;
    if(s->sendbuf){
        free(s->sendbuf);
    }
    s->sendbuf = (char *)malloc(s->sendbuf_size);
    if(!s->sendbuf){
        error_exit("malloc()");
    }
    memcpy(s->sendbuf, buffer, MAXBUFFER_OUT_HDR);
    return 0;
}

int
parcel_start(Session *s)
{
    socket_set_noblocking(s->fd);
    epoll_fd = epoll_create(1);
    ev.data.fd = s->fd;
    ev.events = EPOLLIN | EPOLLET;
    if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, s->fd, &ev) == -1)
    {
        error_exit("epoll_ctl()");
    }
    return 0;
}

int
parcel_stop(Session *s)
{
    free(s->recvbuf);
    free(s->inhdr);
    free(s->sendbuf);
    free(s->outhdr);
    s->recvbuf = NULL;
    s->inhdr = NULL;
    s->sendbuf = NULL;
    s->outhdr = NULL;
    return 0;
}

void
parcel_loop(Session *s)
{
    /* 利用linux epoll机制实现异步IO
        Note: 其实还不如用select效率高，这里就是想用用没用过的。
    */
    int closed = 0;

    parcel_start(s);
    for (;;)
    {
        debug("New epoll_wait epoch");
        active_evnum = epoll_wait(epoll_fd, events, MAXEVENTS, 5000);

        /* 迭代epoll事件表 */
        for (int i = 0; i < active_evnum; i++)
        {
            
            if (events[i].events & EPOLLIN)
            {
                // 处理读事件
                int rd;
                if((rd = parcel_recv(s))==0){
                    debug("Read complete, start write");
                    ev.data.fd = events[i].data.fd;
                    ev.events = EPOLLOUT | EPOLLET;
                    epoll_ctl(epoll_fd, EPOLL_CTL_MOD, events[i].data.fd, &ev);
                }else if(rd == -1){
                    /* connection closed */
                    rd = epoll_ctl(epoll_fd, EPOLL_CTL_DEL, events[i].data.fd, NULL);
                    if(rd == -1){
                        error_exit("epoll_ctl()");
                    }
                    closed = 1;
                    break;
                }
            }else if(events[i].events & EPOLLOUT){
                // 写事件
                int wd;
                if((wd = parcel_send(s))==0){
                    debug("Write complete, start read");
                    ev.data.fd = events[i].data.fd;
                    ev.events = EPOLLIN | EPOLLET;
                    epoll_ctl(epoll_fd, EPOLL_CTL_MOD, events[i].data.fd, &ev);
                }else if(wd == -1){
                    /* connection closed */
                    wd = epoll_ctl(epoll_fd, EPOLL_CTL_DEL, events[i].data.fd, NULL);
                    if(wd == -1){
                        error_exit("epoll_ctl()");
                    }
                    closed = 1;
                    break;
                }
            }
        }
        if(closed){
            parcel_stop(s);
            break;
        }
    }

}

int
parcel_recv(Session *s)
{
    /* 判断session中recvbuf的状态
        SESS_R_NO       读取还未开始，提取request header, 读 \ 
                          取数据直到返回-1,errno为EAGAIN
        SESS_R_BEGIN    读取已经开始，一般为大文件上传，继续读取文 \
                          件内容到buffer
        SESS_R_FIN      读取已经结束，但是内容还未被处理，continue
     */
    int r_s = s->r_s;
    int rd = 0, sslerr;

    switch (r_s){
    case SESS_R_NO:
        /* 从ssl读完 */
        if ((rd = SSL_read(s->ssl, inbuf, MAXBUFFER_IN_HDR))>0){
            debug("Receive data: %s", inbuf);
        }
        debug("rd=%d", rd);
        if (rd < 0){
            sslerr = SSL_get_error(s->ssl, rd);
            if (sslerr != SSL_ERROR_WANT_READ){
                ERR_print_errors_fp(stderr);
                error("parcel_recv()");
            }
        }else if (rd == 0){
            /* connection lost*/
            info("Connection closed by peer");
            return -1;
            // parcel_read_ihdr(s, inbuf);
        }else{
            parcel_read_ihdr(s, inbuf);
            /* 继续填充 recvbuf */
            while ((rd = SSL_read(s->ssl, s->recvbuf + s->recvbuf_exist, s->recvbuf_size)) > 0){
                debug("Receive data: %s", inbuf);
                s->recvbuf_exist += rd;
                /* 填入session 的已经初始化的 recvbuf */
            }
            debug("rd=%d",rd);
            if (rd < 0){
                sslerr = SSL_get_error(s->ssl, rd);
                if (sslerr != SSL_ERROR_WANT_READ){
                    ERR_print_errors_fp(stderr);
                    error("parcel_recv()");
                }else{
                    debug("%d %d", s->recvbuf_size, s->recvbuf_exist);
                    if(s->recvbuf_size == s->recvbuf_exist){
                        return parcel_handle(s);
                    }else{
                        s->r_s = SESS_R_BEGIN;
                        return SSL_ERROR_WANT_READ;
                    }
                }
            }else if (rd = 0){
                /* connection lost or read complete*/
                info("Connection closed by peer");
                return -1;
            }
        }
        break;
    case SESS_R_BEGIN:
        while ((rd = SSL_read(s->ssl, s->recvbuf + s->recvbuf_exist, s->recvbuf_size)) > 0){
            s->recvbuf_exist += rd;
        }
        if (rd == -1){
            sslerr = SSL_get_error(s->ssl, rd);
            if (sslerr != SSL_ERROR_WANT_READ){
                ERR_print_errors_fp(stderr);
                error("parcel_recv()");
            }else{
                return SSL_ERROR_WANT_READ;
            }
        }else if (rd == 0){
            info("Connection closed");
            return -1;
        }
        break;
    case SESS_R_FIN:
        return parcel_handle(s);
        break;
    default:
        error("Unknow session read status %d", r_s);
    }
}

int
parcel_send(Session *s)
{
    /* 判断session中sendbuf的状态
        STATUS_W_NO         写入还未开始，创建response header \
                            填入相应buffer中
        STATUS_W_BEGIN      写入已经开始，没写完，一般为大文件下\ 
                            载，继续写入内容
        STATUS_W_FIN        写入已经结束，发送最后一批数据到客户端
    */
    int w_s = s->w_s;
    int wd = 0, sslerr;

    switch (w_s){
    case SESS_W_NO:

    case SESS_W_BEGIN:
        debug("ss=%d", s->sendbuf_size);
        while ((wd = SSL_write(s->ssl, s->sendbuf + s->sendbuf_size - s->sendbuf_left, s->sendbuf_size)) > 0){
            debug("Send data count %d", wd);
            s->sendbuf_left -= wd;
            if(s->sendbuf_left == 0){
                /* send ok */
                return 0;
            }
        }
        debug("wd=%d",wd);
        if (wd < 0){
            sslerr = SSL_get_error(s->ssl, wd);
            if (sslerr != SSL_ERROR_WANT_WRITE){
                ERR_print_errors_fp(stderr);
                error("parcel_recv()");
            }else{
                debug("%d %d", s->sendbuf_size, s->sendbuf_left);
                if(s->sendbuf_left == 0){
                    debug("Send ok");
                    return 0;
                }else{
                    s->r_s = SESS_W_BEGIN;
                    return SSL_ERROR_WANT_WRITE;
                }
            }
        }else if (wd = 0){
            /* connection lost or read complete*/
            info("Connection closed by peer");
            s->r_s = SESS_W_FIN;
        }
        break;
    case SESS_W_FIN:
        return SSL_ERROR_WANT_WRITE;
        break;
    default:
        error("Unknow session write status %d", w_s);
    }

}

static void
request_login(Session *s)
{
    parcel_reshdr res;
    char *content;

    info("Request login");
    res.status_code = STATUS_REQUEST_AUTH;
    res.size = 0;
    memcpy(outbuf, &res, sizeof(parcel_reshdr));
    parcel_prepare_ohdr(s, outbuf);
    s->w_s = SESS_W_NO;
    s->sendbuf_left = s->sendbuf_size;
}

int
parcel_handle(Session *s)
{
    /* 根据cmd字段做相应的事情 对于读和写大文件 fork 子进程提高效率 */

    parcel_reqhdr *reqhdr = (parcel_reqhdr *)s->inhdr;
    parcel_reshdr res;
    int tempsize, i;
    int cmd = reqhdr->cmd;
    char *content;
    const char **authctx;
    char *token;
    char *line, *tempbuf;
    info("parcel_handle(): cmd: %d from %s: %s",cmd, s->fromhost, s->fromport);
    switch (cmd){
    case CMD_LOGIN:
        // login routine
        i = 0;
        authctx = (const char **)malloc(64 * sizeof(char *));
        line = (char *)malloc(MAXPARAM);
        if(!authctx || !line){
            error_exit("parcel_handle()");
        }
        strncpy(line, reqhdr->param, MAXPARAM);
        token = strsep(&line, ":");
        while(token != NULL){
            authctx[i++] = token;
            token = strsep(&line, ":");
        }
        if(auth_password(authctx[0], authctx[1]) == 0){
            s->authenticated = 1;
            tempbuf = (char *)malloc(MAXDIRLEN);
            memset(tempbuf, 0, MAXDIRLEN);
            snprintf(tempbuf, MAXDIRLEN, HOME_ROOT, authctx[0]);
            if(chroot(tempbuf) != 0){
                error_exit("chroot()");
            }
            chdir("/");
            free(tempbuf);
            res.status_code = STATUS_SUCCESS_AUTH;
        }else{
            res.status_code = STATUS_FAIL_AUTH;
        }
        res.size = 0;
        memcpy(outbuf, &res, sizeof(parcel_reshdr));
        parcel_prepare_ohdr(s, outbuf);
        s->w_s = SESS_W_NO;
        s->sendbuf_left = s->sendbuf_size;
        free(line);
        free(authctx);
        return 0;
        break;
    case CMD_LS:
        // get dir list
        if(s->authenticated){
            res.status_code = STATUS_OK;
            res.size = MAXDIRLIST_LEN;
            content = (char *)malloc(MAXDIRLIST_LEN);
            tempbuf = (char *)malloc(MAXDIRLEN);
            pwd(&tempbuf);
            if(content == NULL){
                error_exit("parcel_handle()");
            }
            if(listdir(tempbuf, content) != 0){
                error_exit("listdir()");
            }
            memcpy(outbuf, &res, sizeof(parcel_reshdr));
            parcel_prepare_ohdr(s, outbuf);
            s->w_s = SESS_W_NO;
            s->sendbuf_left = s->sendbuf_size;
            memcpy(s->sendbuf + MAXBUFFER_OUT_HDR, content, MAXDIRLIST_LEN);
            free(content);
            // parcel_send(s);
            return 0;
        }else{
            request_login(s);
        }
        break;
    case CMD_PWD:
        if(s->authenticated){
            content = (char *)malloc(MAXDIRLEN);
            pwd(&content);
            debug("Content: %p",content);
            info("cwd %s", content);
            res.status_code = STATUS_OK;
            res.size = MAXDIRLEN;
            memcpy(outbuf, &res, sizeof(parcel_reshdr));
            parcel_prepare_ohdr(s, outbuf);
            s->w_s = SESS_W_NO;
            s->sendbuf_left = s->sendbuf_size;
            memcpy(s->sendbuf + MAXBUFFER_OUT_HDR, content, res.size);
            free(content);
            content = NULL;
            return 0;
        }else{
            request_login(s);
        }
    case CMD_MKDIR:
        if(s->authenticated){
            info("mkdir %s", reqhdr->param);
            if(createdir(reqhdr->param) == 0){
                res.status_code = STATUS_OP_OK;
            }else{
                res.status_code = STATUS_OP_FAIL;
            }
            res.size = 0;
            memcpy(outbuf, &res, sizeof(parcel_reshdr));
            parcel_prepare_ohdr(s, outbuf);
            s->w_s = SESS_W_NO;
            s->sendbuf_left = s->sendbuf_size;
            return 0;
        }else{
            request_login(s);
        } 
        // make dir
        break;
    case CMD_RMDIR:
        // delete dir
        if(s->authenticated){
            info("rmdir %s", reqhdr->param);
            if(deldir(reqhdr->param) == 0){
                res.status_code = STATUS_OP_OK;
            }else{
                error("%s", strerror(errno));
                res.status_code = STATUS_OP_FAIL;
            }
            res.size = 0;
            memcpy(outbuf, &res, sizeof(parcel_reshdr));
            parcel_prepare_ohdr(s, outbuf);
            s->w_s = SESS_W_NO;
            s->sendbuf_left = s->sendbuf_size;
            return 0;
        }else{
            request_login(s);
        } 
        // make dir
        break;
        break;
    case CMD_GET:
        // get file
        if(s->authenticated){
            info("getfile %s", reqhdr->param);
            tempbuf = basename(reqhdr->param);
            readfile(reqhdr->param, &content, &tempsize);
            debug("Content: %p %d",content, tempsize);
            res.status_code = STATUS_FILE;
            strncpy(res.param, tempbuf, MAXPARAM);
            res.size = tempsize;
            memcpy(outbuf, &res, sizeof(parcel_reshdr));
            parcel_prepare_ohdr(s, outbuf);
            s->w_s = SESS_W_NO;
            s->sendbuf_left = s->sendbuf_size;
            memcpy(s->sendbuf + MAXBUFFER_OUT_HDR, content, res.size);
            free(content);
            content = NULL;
            return 0;
        }else{
            request_login(s);
        }
        break;
    case CMD_CD:
        if(s->authenticated){
            info("cd %s", reqhdr->param);
            if(cd(reqhdr->param) == 0){
                res.status_code = STATUS_OP_OK;
            }else{
                res.status_code = STATUS_OP_FAIL;
            }
            memcpy(outbuf, &res, sizeof(parcel_reshdr));
            parcel_prepare_ohdr(s, outbuf);
            s->w_s = SESS_W_NO;
            s->sendbuf_left = s->sendbuf_size;
            return 0;
        }else{
            request_login(s);
        }
        break;
    case CMD_PUT:
        if(s->authenticated){
            info("upload file %s", reqhdr->param);
            tempbuf = basename(reqhdr->param);
            if(writefile(reqhdr->param, s->recvbuf, s->recvbuf_size)==0){
                res.status_code = STATUS_OP_OK;
            }else{
                res.status_code = STATUS_OP_FAIL; 
            }
            res.size = 0;
            memcpy(outbuf, &res, sizeof(parcel_reshdr));
            parcel_prepare_ohdr(s, outbuf);
            s->w_s = SESS_W_NO;
            s->sendbuf_left = s->sendbuf_size;
            return 0;
        }else{
            request_login(s);
        }
        // upload file
        break;
    case CMD_DEL:
        // delete file
        if(s->authenticated){
            info("delete file %s", reqhdr->param);
            tempbuf = basename(reqhdr->param);
            if(delfile(reqhdr->param)==0){
                res.status_code = STATUS_OP_OK;
            }else{
                res.status_code = STATUS_OP_FAIL; 
            }
            res.size = 0;
            memcpy(outbuf, &res, sizeof(parcel_reshdr));
            parcel_prepare_ohdr(s, outbuf);
            s->w_s = SESS_W_NO;
            s->sendbuf_left = s->sendbuf_size;
            return 0;
        }else{
            request_login(s);
        }
        break;
    default:
        error("Unknow command %d", cmd);
        return -1;
    }
}


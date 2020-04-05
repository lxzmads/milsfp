#include "includes.h"
#include "session.h"
#include "parcel.h"
#include "log.h"
#include "utils.h"

char inbuf[MAXBUFFER_IN_HDR];
char outbuf[MAXBUFFER_OUT_HDR];

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
    if (!s){
        error_exit("no session");
    }
    return 0;
}

static int
parcel_free(Session *s)
{
    if(s->recvbuf){
        free(s->recvbuf);
        s->recvbuf = NULL;
    }
    if(s->inhdr){
        free(s->inhdr);
        s->inhdr = NULL;
    }
    if(s->sendbuf){
        free(s->sendbuf);
        s->sendbuf = NULL;
    }
    if(s->outhdr){
        free(s->outhdr);
        s->outhdr = NULL;
    }
    session_destory(s->fd);
    return 0;
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
            info("receive data: %s", inbuf);
        }
        debug("rd=%d", rd);
        if (rd < 0){
            sslerr = SSL_get_error(s->ssl, rd);
            if (sslerr != SSL_ERROR_WANT_READ){
                ERR_print_errors_fp(stderr);
                error("parcel_recv()");
            }
        }else if (rd == 0){
            /* connection lost or read complete*/
            info("Connection closed by peer");
            parcel_free(s);
            return -1;
            // parcel_read_ihdr(s, inbuf);
        }else{
            parcel_read_ihdr(s, inbuf);
            /* 继续填充 recvbuf */
            while ((rd = SSL_read(s->ssl, s->recvbuf + s->recvbuf_exist, s->recvbuf_size)) > 0){
                info("receive data: %s", inbuf);
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
                parcel_free(s);
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
            parcel_free(s);
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
            info("send data count %d", wd);
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
                    info("send ok");
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

int
parcel_handle(Session *s)
{
    /* 根据cmd字段做相应的事情 对于读和写大文件 fork 子进程提高效率 */

    parcel_reqhdr *reqhdr = (parcel_reqhdr *)s->inhdr;
    parcel_reshdr res;
    int tempsize;
    int cmd = reqhdr->cmd;
    char *content;
    info("parcel_handle(): cmd: %d from %s: %s",cmd, s->fromhost, s->fromport);
    switch (cmd){
    case CMD_LOGIN:
        // login routine
        return 0;
        break;
    case CMD_LS:
        // get dir list
        res.status_code = STATUS_OK;
        res.size = MAXDIRLIST_LEN;
        content = (char *)malloc(MAXDIRLIST_LEN);
        listdir("/", content);
        memcpy(outbuf, &res, sizeof(parcel_reshdr));
        parcel_prepare_ohdr(s, outbuf);
        s->w_s = SESS_W_NO;
        s->sendbuf_left = s->sendbuf_size;
        memcpy(s->sendbuf + MAXBUFFER_OUT_HDR, content, MAXDIRLIST_LEN);
        // parcel_send(s);
        return 0;
        break;
    case CMD_MKDIR:
        // make dir
        break;
    case CMD_RMDIR:
        // delete dir
        break;
    case CMD_GET:
        // get file
        info("readfile %s", reqhdr->param);
        readfile(reqhdr->param, &content, &tempsize);
        info("content: %p %d",content, tempsize);
        res.status_code = STATUS_FILE;
        res.size = tempsize;
        memcpy(outbuf, &res, sizeof(parcel_reshdr));
        parcel_prepare_ohdr(s, outbuf);
        s->w_s = SESS_W_NO;
        s->sendbuf_left = s->sendbuf_size;
        memcpy(s->sendbuf + MAXBUFFER_OUT_HDR, content, res.size);
        info("here");
        free(content);
        content = NULL;
        info("here");
        return 0;
        break;
    case CMD_PUT:
        // upload file
        break;
    case CMD_DEL:
        // delete file
        break;
    default:
        error("Unknow command %d", cmd);
        return -1;
    }
}


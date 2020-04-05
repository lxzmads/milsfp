#ifndef MILS_SESSION_H
#define MILS_SESSION_H

#define MAXSESSION 1024

/* 权限 */
#define NO_PRIV     0x0000
#define READ        0x0001
#define WRITE       0x0002

/* 相当于信号量, 应对大文件读写情况, 防止条件竞争 */
#define SESS_R_NO       0x00
#define SESS_R_BEGIN    0x01
#define SESS_R_FIN      0x02
#define SESS_W_NO       0x03
#define SESS_W_BEGIN    0x04
#define SESS_W_FIN      0x05

/* 会话结构体 读写可以同时进行，但是只能同时一次读和写 */
typedef struct{
    int             fd;
    char            *recvbuf;
    uint32_t        recvbuf_size;
    uint32_t        recvbuf_exist;
    char            *inhdr;
    u_int8_t        r_s;
    char            *sendbuf;
    uint32_t        sendbuf_size;
    uint32_t        sendbuf_left;
    char            *outhdr;
    u_int8_t        w_s;
    SSL             *ssl;
    char            *fromhost;
    char            *fromport;
    char            *cwd;
    char            *user;
    char            *passwd;
    u_int8_t        authenticated;
    u_int16_t       privilege;
}   Session;


/* 会话与fd映射表, 目的是动态申请session，减少空间占用 */
typedef Session * SessionMap;

Session     *session_get(int fd);
int         session_start(int fd, char *in_host, char *in_port);
int         session_destory(int fd);

#endif
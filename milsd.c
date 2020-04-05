/**
 * @author mads
 * @email 86625902@qq.com
 * @create date 2020-03-19 14:28:51
 * @modify date 2020-03-19 14:28:51
 * @desc milsfp server
 */

#include "includes.h"

#include "serverconf.h"
#include "log.h"
#include "session.h"
#include "parcel.h"

#define PORT 6237
#define MAXEVENTS 64


ServerOptions options;
char *config_file_name = NULL;
int debug_flag = 0;

char *__progname;

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

static void server_loop()
{
}

int main(int argc, char *argv[])
{
    int server_fd, epoll_fd, client_fd;
    struct epoll_event ev;
    struct epoll_event events[MAXEVENTS];
    struct sockaddr_in addr_in;
    int sockopt = 1, opt, active_evnum;
    char buffer[1024] = {0};
    char in_host[1025], in_port[32];
    int addrlen = sizeof(addr_in);
    char *msg = "hello from server";

    __progname = (char *)argv[0];

    init_server_conf(&options);

    while ((opt = getopt(argc, argv, "f:p:id")) != -1)
    {
        switch (opt)
        {
        case 'f':
            config_file_name = optarg;
            break;
        case 'p':
            break;
        case 'i':
            break;
        case 'd':
            debug_flag = 1;
            break;
        case '?':
        default:
            fprintf(stderr, "milsd version %s\n", MILS_VERSION);
            fprintf(stderr, "Usage: %s [options]\n", __progname);
            fprintf(stderr, "Options:\n");
            fprintf(stderr, "   -f  file        Configure file (default /etc/mils/milsd_config)\n");
            fprintf(stderr, "   -p  port        Which port listen to (default 6237)\n");
            fprintf(stderr, "   -i  file        Your identity file (default ~/.mils/id_rsa)\n");
            fprintf(stderr, "   -d              Enable debug mode");
            exit(1);
        }
    }

    if(debug_flag){
        warn("Debug mode");
       log_init(__progname, LOG_LEVEL_DEBUG, LOG_FACILITY_USER, 1);
    }else{
        log_init(__progname, LOG_LEVEL_INFO, LOG_FACILITY_USER, 1);
    }
    if ((server_fd = socket(AF_INET, SOCK_STREAM, 0)) == 0)
    {
        error_exit("socket()");
    }

    if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR | SO_REUSEPORT, &sockopt, sizeof sockopt))
    {
        error_exit("setsockopt()");
    }

    addr_in.sin_family = AF_INET;
    addr_in.sin_addr.s_addr = INADDR_ANY;
    addr_in.sin_port = htons(PORT);
    if (bind(server_fd, (struct sockaddr *)&addr_in, sizeof addr_in) < 0)
    {
        error_exit("bind()");
    }

    /* set socket nonblocking */
    socket_set_noblocking(server_fd);

    if (listen(server_fd, SOMAXCONN) < 0)
    {
        error_exit("listen()");
    }
    info("Server listening on 0.0.0.0:%d", PORT);

    epoll_fd = epoll_create(1);
    ev.data.fd = server_fd;
    ev.events = EPOLLIN | EPOLLET;
    if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, server_fd, &ev) == -1)
    {
        error_exit("epoll_ctl");
    }


    /* 利用linux epoll机制实现异步I/O, 牺牲兼容性换取高并发 */
    for (;;)
    {
        debug("new round");
        active_evnum = epoll_wait(epoll_fd, events, MAXEVENTS, 5000);

        /* 迭代epoll事件表 */
        for (int i = 0; i < active_evnum; i++)
        {
            if (events[i].events & EPOLLIN && events[i].data.fd == server_fd)
            {
                /* handle new connection */
                while(1){
                    client_fd = accept(server_fd, (struct sockaddr *)&addr_in, (socklen_t *)&addrlen);
                    if(client_fd == -1)
                    {
                        if(errno == EAGAIN || errno == EWOULDBLOCK){
                            break;
                        }else{
                            error_exit("accept()");
                        }
                    }
                    if(getnameinfo((const struct sockaddr *)&addr_in, addrlen, in_host, sizeof in_host, in_port, sizeof in_port, NI_NUMERICHOST) != 0){
                        error_exit("getnameinfo()");
                    }
                    info("Accepted connection from %s:%s fd %d", in_host, in_port, client_fd);
                
                    socket_set_noblocking(client_fd);
                    info("set nonblocking ok");
                    ev.data.fd = client_fd;
                    ev.events = EPOLLIN | EPOLLET;
                    session_start(client_fd, in_host, in_port);;
                    if(epoll_ctl(epoll_fd, EPOLL_CTL_ADD, client_fd, &ev) != 0){
                        error_exit("epoll_ctl() in accept");
                    }
                    
                }
                continue;
            }
            else if (events[i].events & EPOLLIN)
            {
            //     /*处理读事件*/
                int rd;
                if((rd = parcel_recv(session_get(events[i].data.fd)))==0){
                    info("read complete, start write");
                    ev.data.fd = events[i].data.fd;
                    ev.events = EPOLLOUT | EPOLLET;
                    epoll_ctl(epoll_fd, EPOLL_CTL_MOD, events[i].data.fd, &ev);
                }else if(rd == -1){
                    /* connection closed */
                    rd = epoll_ctl(epoll_fd, EPOLL_CTL_DEL, events[i].data.fd, NULL);
                    if(rd == -1){
                        error_exit("epoll_ctl()");
                    }
                    close(events[i].data.fd);
                    continue;
                }
            //     char buffer[1024];
            //     int rd, sslerr;
            //     Session *s = events[i].data.ptr;

            //     info("session: %p", s);
            //     while ((rd = SSL_read(s->ssl, buffer, 1024)) > 0){
            //         info("receive data: %s", buffer);
            //         /* 填入session 的已经初始化的 recvbuf */
            //     }
            //     info("rd = %d", rd);
            //     if (rd < 0){
            //         sslerr = SSL_get_error(s->ssl, rd);
            //         if (sslerr != SSL_ERROR_WANT_READ){
            //             ERR_print_errors_fp(stderr);
            //             error("parcel_recv()");
            //         }else{
            //             s->r_s = SESS_R_BEGIN;
            //         }
            //     }else if (rd == 0){
            //         /* connection lost or read complete*/
            //         warn("Connection closed by peer");
            //         s->r_s = SESS_R_FIN;
            //     }
            //     // parcel_recv((Session *)events[i].data.ptr);
            // }
            // else if (events[i].events & EPOLLOUT)
            // {
            //     /*处理写事件*/
            //     parcel_send((Session *)events[i].data.ptr);
            // }
            }else if(events[i].events & EPOLLOUT){
                int wd;
                if((wd = parcel_send(session_get(events[i].data.fd)))==0){
                    info("write complete, start read");
                    ev.data.fd = events[i].data.fd;
                    ev.events = EPOLLIN | EPOLLET;
                    epoll_ctl(epoll_fd, EPOLL_CTL_MOD, events[i].data.fd, &ev);
                }else if(wd == -1){
                    /* connection closed */
                    wd = epoll_ctl(epoll_fd, EPOLL_CTL_DEL, events[i].data.fd, NULL);
                    if(wd == -1){
                        error_exit("epoll_ctl()");
                    }
                    close(events[i].data.fd);
                    continue;
                }
            }
        }
    }

    close(server_fd);
    close(epoll_fd);
    free(events);

    return 0;
}
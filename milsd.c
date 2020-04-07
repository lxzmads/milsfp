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
#include "auth.h"

#define PORT 6237
#define MAXEVENTS 64

ServerOptions options;
char *config_file_name = NULL;
int debug_flag = 0;

char *__progname;

int main(int argc, char *argv[])
{
    int server_fd, epoll_fd, client_fd;
    struct sockaddr_in addr_in;
    int sockopt = 1, opt, pid;
    char buffer[1024] = {0};
    char in_host[1025], in_port[32];
    int addrlen = sizeof(addr_in);
    Session *cursess;

    __progname = (char *)argv[0];

    init_server_conf(&options);

    // Read commandline options.
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

    if (debug_flag)
    {
        warn("Debug mode");
        log_init(__progname, LOG_LEVEL_DEBUG, LOG_FACILITY_USER, 1);
    }
    else
    {
        log_init(__progname, LOG_LEVEL_INFO, LOG_FACILITY_USER, 1);
    }
    if ((server_fd = socket(AF_INET, SOCK_STREAM, 0)) <= 0)
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
    // socket_set_noblocking(server_fd);

    if (listen(server_fd, SOMAXCONN) < 0)
    {
        error_exit("listen()");
    }
    info("Server listening on 0.0.0.0:%d", PORT);

    for (;;)
    {
        client_fd = accept(server_fd, (struct sockaddr *)&addr_in, (socklen_t *)&addrlen);
        if (client_fd < 0)
        {
            if (errno != EINTR)
            {
                error_exit("accept()");
            }
            continue;
        }

        if (debug_flag)
        {
            // debug mode
            close(server_fd);
            debug("Debug mode, will not fork.");
            break;
        }
        else
        {
            // fork it
            if ((pid = fork()) == 0)
            {
                close(server_fd);
                break;
            }
            else if (pid > 0)
            {
                debug("fork child: %d.", pid);
                close(client_fd);
                continue;
            }
            else
            {
                close(server_fd);
                error_exit("fork():");
            }
        }
    }

    // Children process
    chdir("/");
    if (getnameinfo((const struct sockaddr *)&addr_in, addrlen, in_host, sizeof in_host, in_port, sizeof in_port, 1) != 0)
    {
        error_exit("getnameinfo()");
    }
    info("Accepted connection from %s:%s fd %d", in_host, in_port, client_fd);

    // Initialize session with ssl.
    if(session_start(client_fd, in_host, in_port)!=0){
        error_exit("session_start()");
    }

    if((cursess=session_get(client_fd)) == NULL){
        error_exit("NULL session");
    }
    // Read, parse and return.
    parcel_loop(cursess);

    // Do session cleanup.
    session_stop(client_fd);

    return 0;
}
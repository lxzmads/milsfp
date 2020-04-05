#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <netdb.h>
#include <unistd.h>
#include <sys/epoll.h>
#include <errno.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <openssl/crypto.h>
#include <openssl/x509.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <stdbool.h>

#include "tlsutil.h"
#include "includes.h"
#include "parcel.h"
#include "utils.h"
#include "log.h"
#include "lsh.h"

#define CERTF "src/server.crt"
#define KEYF  "src/server.key"

#define MAXEVENTS 128

int arrvied = 1;
int cmd_push = 0;
char current_cmd[8];
char param[1024];
extern char *builtin_str[];

char *content;
int begin = 0;

int
c_login(char **args)
{
    return 0;
}

int
c_put(char **args)
{
    return 0;
}
int
c_del(char **args)
{
    return 0;
}
int
c_get(char **args)
{
    info("c_get()");
    strncpy(current_cmd, "get", 4);
    memset(param, 0, sizeof(param));
    strncpy(param, args[1], strlen(args[1]));

    cmd_push = 1;
    return 0;
}

int
do_c_get(SSL *ssl, char *par)
{
    int sslerr,wd;

    info("do_c_get()");
    parcel_reqhdr *req = (parcel_reqhdr *)malloc(sizeof(parcel_reqhdr));
    req->cmd = CMD_GET;
    strncpy(req->param, par, strlen(par));
    req->param[strlen(par)] = 
    req->size = 0;
    char *buf = (char *)malloc(sizeof(parcel_reqhdr));
    if(!buf){
        error_exit("malloc()");
    }
    int j = 0;
    memset(buf, 0, sizeof(parcel_reqhdr));
    memcpy(buf, req, sizeof(parcel_reqhdr));
    // str_dumps(buf, sizeof(parcel_reqhdr));
    wd = SSL_write(ssl, buf, sizeof(parcel_reqhdr));
    info("wd=%d", wd);
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
c_ls(char **args)
{
    info("c_ls()");
    strncpy(current_cmd, "ls", 3);
    cmd_push = 1;
    return 0;
}
int
do_c_ls(SSL *ssl, char *par)
{
    int sslerr,wd;

    parcel_reqhdr *req = (parcel_reqhdr *)malloc(sizeof(parcel_reqhdr));
    req->cmd = CMD_LS;
    req->size = 0;
    char *buf = (char *)malloc(sizeof(parcel_reqhdr));
    if(!buf){
        error_exit("malloc()");
    }
    int j = 0;
    memset(buf, 0, sizeof(parcel_reqhdr));
    memcpy(buf, req, sizeof(parcel_reqhdr));
    // str_dumps(buf, sizeof(parcel_reqhdr));
    wd = SSL_write(ssl, buf, sizeof(parcel_reqhdr));
    info("wd=%d", wd);
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
c_mkdir(char **args)
{
    return 0;
}
int
c_rmdir(char **args)
{
    return 0;
}
int
c_cd(char **args)
{
    return 0;
}
int
c_help(char **args)
{
    fprintf(stderr, "Commands: ls help\n");
    return -1;    
}

int
c_exit(char **args)
{
    return 0;
}
int (*builtin_func[]) (char **) = {
    &c_login,
    &c_put,
    &c_del,
    &c_get,
    &c_ls,
    &c_mkdir,
    &c_rmdir,
    &c_cd,
    &c_help,
    &c_exit
};
int (*do_builtin_func[]) (SSL *, char *) = {
    NULL,
    NULL,
    NULL,
    &do_c_get,
    &do_c_ls,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL
};
int lsh_execute(char **args)
{
  int i;

  if (args[0] == NULL) {
    return 1;
  }

  for (i = 0; i < lsh_num_builtins(); i++) {
    if (strcmp(args[0], builtin_str[i]) == 0) {
      return (*builtin_func[i])(args);
    }
  }
  c_help(args);
  return -1;
}
int
command_loop()
{
    char *line;
    char **args;
    int status;

    printf("> ");
    line = lsh_read_line();
    args = lsh_split_line(line);
    debug("%s %s",args[0],args[1]);
    status = lsh_execute(args);

    free(line);
    free(args);
    return status;
}

static void
dump_cert_info(SSL *ssl, bool server) {

    if(server) {
        printf("Ssl server version: %s", SSL_get_version(ssl));
    }
    else {
        printf("Client Version: %s", SSL_get_version(ssl));
    }

    /* The cipher negotiated and being used */
    printf("Using cipher %s", SSL_get_cipher(ssl));

    /* Get client's certificate (note: beware of dynamic allocation) - opt */
    X509 *client_cert = SSL_get_peer_certificate(ssl);
    if (client_cert != NULL) {
        if(server) {
        printf("Client certificate:\n");
        }
        else {
            printf("Server certificate:\n");
        }
        char *str = X509_NAME_oneline(X509_get_subject_name(client_cert), 0, 0);
        if(str == NULL) {
            printf("warn X509 subject name is null");
        }
        printf("\t Subject: %s\n", str);
        OPENSSL_free(str);

        str = X509_NAME_oneline(X509_get_issuer_name(client_cert), 0, 0);
        if(str == NULL) {
            printf("warn X509 issuer name is null");
        }
        printf("\t Issuer: %s\n", str);
        OPENSSL_free(str);

        /* Deallocate certificate, free memory */
        X509_free(client_cert);
    } else {
        printf("Client does not have certificate.\n");
    }
}

int main(int argc, char *argv[]) {

    // SSL send
    // make socket non-blocking

    const SSL_METHOD *meth;
    SSL_CTX* ctx;
    SSL* ssl;
    //X509* server_cert;
    int err;
    int sd;
    struct sockaddr_in sa;
    //char* str;
    char buf[4096];
    int status;

    printf("epoll openssl tls client..");

    /* ------------ */
    /* Init openssl */
    SSL_load_error_strings();
    OpenSSL_add_ssl_algorithms();

    /* ------------------------------------- */
    meth = TLSv1_2_client_method();
    ctx = SSL_CTX_new(meth);
    CHK_NULL(ctx);

    // init_ssl_opts(ctx);
    /* --------------------------------------------- */
    /* Create a normal socket and connect to server. */

    sd = socket(AF_INET, SOCK_STREAM, 0);
    CHK_ERR(sd, "socket");

    // non-blocking client socket
    int flags = fcntl(sd, F_GETFL, 0);
    if (flags < 0) {
      exit(12);
    }
    fcntl(sd, F_SETFL, flags | O_NONBLOCK);

    // ---------------------

    memset(&sa, '\0', sizeof(sa));
    sa.sin_family = AF_INET;
    sa.sin_addr.s_addr = inet_addr("127.0.0.1"); /* Server IP */
    sa.sin_port = htons(6237); /* Server Port number */

    printf("Connected to server %s, port %u\n", inet_ntoa(sa.sin_addr),
            ntohs(sa.sin_port));

    err = connect(sd, (struct sockaddr*) &sa, sizeof(sa));
    if (err < 0 && errno != EINPROGRESS) {
        perror("connect != EINPROGRESS");
        exit (15);
    }

    // ----------- Epoll Create ---------------------- //
    int efd = epoll_create1(0);
    if (efd == -1) {
        perror("epoll_create");
        exit(1);
    }

    struct epoll_event event;
    event.data.fd = sd;
    event.events = EPOLLIN | EPOLLOUT | EPOLLET;

    int s = epoll_ctl(efd, EPOLL_CTL_ADD, sd, &event);
    if (s == -1) {
        perror("epoll_ctl");
        exit(2);
    }

    // ------------------------------- //

    /* --------------- ---------------------------------- */
    /* Start SSL negotiation, connection available. */
    ssl = SSL_new(ctx);
    CHK_NULL(ssl);

    SSL_set_fd(ssl, sd);
    SSL_set_connect_state(ssl);

    for(;;) {
        int success = SSL_connect(ssl);

        if(success < 0) {
            err = SSL_get_error(ssl, success);

            /* Non-blocking operation did not complete. Try again later. */
            if (err == SSL_ERROR_WANT_READ ||
                    err == SSL_ERROR_WANT_WRITE ||
                    err == SSL_ERROR_WANT_X509_LOOKUP) {
                continue;
            }
            else if(err == SSL_ERROR_ZERO_RETURN) {
                printf("SSL_connect: close notify received from peer");
                exit(18);
            }
            else {
                printf("Error SSL_connect: %d", err);
                perror("perror: ");
                SSL_free(ssl);
                close(sd);
                close(efd);
                exit(16);
            }
        }
        else {
            dump_cert_info(ssl, false);
            break;
        }
    }

    /* Buffer where events are returned */
    struct epoll_event* events = calloc(MAXEVENTS, sizeof event);
    /* The event loop */
    fprintf(stderr, "Input Command: \n");
    while (1) {
        info("new round %d", arrvied);
        if(arrvied){
            arrvied = 0;
            while(command_loop()==-1);
            info("loop fin");
        }

        int n = epoll_wait(efd, events, MAXEVENTS, 5000);
        if (n < 0 && n == EINTR) {
            printf("epoll_wait System call interrupted. Continue..");
            continue;
        }
        int i;
        for (i = 0; i < n; i++) {
            if ((events[i].events & EPOLLERR) || (events[i].events & EPOLLHUP)
                    || (!(events[i].events & (EPOLLIN | EPOLLOUT)))) {
                /* An error has occurred on this socket or the socket is not
                 ready for reading (why were we notified then?) */
                fprintf(stderr, "epoll error\n");
                close(events[i].data.fd);
                continue;
            }
            // read
            else if (events->events & (EPOLLIN)) {
                int rd;
                char *content;
                int sslerr;
                int j=0;

                char *reshdr = (char *)malloc(sizeof(parcel_reshdr));

                if((rd = SSL_read(ssl, reshdr, sizeof(parcel_reshdr))) > 0){
                    parcel_reshdr *res1 = (parcel_reshdr *)reshdr;
                    content = (char *)malloc(res1->size);
                    info("%d, %d\n", res1->status_code, res1->size);
                    while((rd=SSL_read(ssl, content+j, res1->size-j)) > 0){
                        j+=rd;
                        info("rd=%d",rd);
                    }
                    info("rd=%d",rd);
                    // printf("content: %s\n", content);
                    if(rd == -1){
                        sslerr = SSL_get_error(ssl, rd);
                        if (sslerr != SSL_ERROR_WANT_READ){
                            ERR_print_errors_fp(stderr);
                            error("parcel_recv()");
                        }else{
                            if(j == res1->size){
                                if(res1->status_code == STATUS_OK){
                                    printf("%s", content);
                                }else{
                                    writefile("tempfile", content, res1->size);
                                }
                                arrvied = 1;
                                event.events = EPOLLOUT | EPOLLET;
                                epoll_ctl(efd, EPOLL_CTL_MOD, sd, &event);
                            }
                            continue;
                        }
                    }
                }
                
            }
            //write
            else if (events->events & EPOLLOUT) {
                if(cmd_push){
                    status = 0;
                    for (int i = 0; i < lsh_num_builtins(); i++) {
                        info("round");
                        if (strcmp(current_cmd, builtin_str[i]) == 0) {
                            (*do_builtin_func[i])(ssl, param);
                            status = 1;
                            event.events = EPOLLIN | EPOLLET;
                            epoll_ctl(efd, EPOLL_CTL_MOD, sd, &event);
                            break;
                        }
                    }
                    if(!status){
                        error("unknow command");
                    }
                    cmd_push = 0;
                }
            }
        }
    }
    free(events);
    close(sd);
    close(efd);
    return 0;
}
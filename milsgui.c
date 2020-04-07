#include "includes.h"
#include "parcel.h"
#include "utils.h"
#include "log.h"
#include "cmdloopgui.h"
#include "milsgui.h"

#include <gtk/gtk.h>

#define MAXEVENTS 10
#define SERVER_HOST "127.0.0.1"
#define SERVER_PORT 6237

int arrvied = 1;
char *content;
int begin = 0;
extern int cmd_push;
extern int (*current_cmd_func)(SSL *,char **);
extern char **params;
struct epoll_event event;
struct epoll_event* events;
int clientfd, efd;
SSL* ssl;
GtkTextBuffer *textbuf;

char *bannerstr = "|\\/|o|  _\n\
|    | | |_\\\n";
char *helpstr = "\nCOMMANDS: HELP EXIT LOGIN ls GET PUT DEL MKDIR RMDIR cd pwd\n";
char welcome[2048];

GtkWidget *goButton;
GtkWidget *mainText;
GtkWidget *goEntry;
GtkWidget *hostEntry;
GtkWidget *portEntry;
GtkWidget *connectButton;



static void
banner()
{
    snprintf(welcome, 2048, "%s", bannerstr);
}

static void
verify_server(SSL *ssl) 
{
    const EVP_MD *fprint_type = NULL;
    int j, fprint_size, ret = 0;
    unsigned char fprint[EVP_MAX_MD_SIZE];
    char msg[1024] = {0};

    X509 *cert = SSL_get_peer_certificate(ssl);
    if (cert != NULL) {
        fprint_type = EVP_sha1();
        
        if (!X509_digest(cert, fprint_type, fprint, &fprint_size)){
            error_exit("X509_digest()");
        }
        info("%d\n", fprint_size);
        BIO_snprintf(msg, 21 ,"Server Fingerprint: ");
        for (j=0; j<fprint_size; ++j){
            ret += BIO_snprintf(msg + 20 + ret, 4, "%02x ", fprint[j]);
        }
        BIO_snprintf(msg + ret + 20,2,"\n");
    } else {
        error_exit("Untrusted server");
    }
    fprintf(stderr, welcome);
    fprintf(stderr, "%d %d\n", strlen(bannerstr), strlen(welcome));
    snprintf(welcome + strlen(bannerstr), 2048, "%s", msg);
    X509_free(cert);
}

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

static void
connect_server(const char *ip, int port)
{
    const SSL_METHOD *meth;
    SSL_CTX* ctx;

    int err;
    struct sockaddr_in server_addr;
    char buf[4096];
  

    SSL_load_error_strings();
    OpenSSL_add_ssl_algorithms();

    meth = TLSv1_2_client_method();
    ctx = SSL_CTX_new(meth);
    if(ctx == NULL){
        error_exit("SSL_CTX_new()");
    }

    if((clientfd = socket(AF_INET, SOCK_STREAM, 0)) <= 0){
        error_exit("socket()");
    }

    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = inet_addr(SERVER_HOST);
    server_addr.sin_port = htons(SERVER_PORT);

    if(connect(clientfd, (struct sockaddr*) &server_addr, sizeof(server_addr)) < 0){
        error_exit("connect()");
    }
    socket_set_noblocking(clientfd);
    if((efd = epoll_create1(0)) < 0){
        error_exit("epoll_create");
    }

    events = calloc(MAXEVENTS, sizeof event);  

    event.data.fd = clientfd;
    event.events = EPOLLIN | EPOLLOUT | EPOLLET;

    if( epoll_ctl(efd, EPOLL_CTL_ADD, clientfd, &event) < 0){
        error_exit("epoll_ctl()");
    }

    if((ssl = SSL_new(ctx)) == NULL){
        error_exit("SSL_new()");
    }
    SSL_set_fd(ssl, clientfd);
    SSL_set_connect_state(ssl);

    for(;;) {
        int success = SSL_connect(ssl);

        if(success < 0) {
            err = SSL_get_error(ssl, success);
            if (err == SSL_ERROR_WANT_READ ||
                    err == SSL_ERROR_WANT_WRITE ||
                    err == SSL_ERROR_WANT_X509_LOOKUP) {
                continue;
            }
            else if(err == SSL_ERROR_ZERO_RETURN) {
                ERR_print_errors_fp(stderr);
                error_exit("SSL_connect()");
            }
            else {
                ERR_print_errors_fp(stderr);
                SSL_free(ssl);
                close(clientfd);
                close(efd);
                error_exit("SSL_connect()");
            }
        }
        else {
            banner();
            verify_server(ssl);
            snprintf(welcome + 104, 2048, helpstr);
            gprintf(welcome);
            break;
        }
    }
}

void
gprintf(const char *msgf,...)
{
    char *fmtbuf, *msgbuf;
    va_list args;

    msgbuf = (char *)malloc(5120);
    fmtbuf = (char *)malloc(5120);

    va_start(args, msgf);
    snprintf(fmtbuf, 5120, "%s\n", msgf);
    vsnprintf(msgbuf, 5120, fmtbuf, args);
    va_end(args);
    fprintf(stderr, msgbuf);
    gtk_text_buffer_set_text(textbuf, msgbuf, -1);
    
    free(msgbuf);
    free(fmtbuf);
}
void onConnectButtonClick()
{

    const char *host;
    const char *port;

	host = gtk_entry_get_text(GTK_ENTRY(hostEntry));
    port =gtk_entry_get_text(GTK_ENTRY(portEntry));

    info("connecting %s:%s", host,port);
    connect_server(host, strtol(port, NULL, 10));

}

void onGoButtonClick()
{
	const char *command;

	command = gtk_entry_get_text(GTK_ENTRY(goEntry));
    if(command_execute(command) < 0){
        gprintf(helpstr);
    }else{

        arrvied = 0;
        while (1) {
            if(arrvied){
                arrvied = 0;
                break;
            }

            int n = epoll_wait(efd, events, MAXEVENTS, 5000);
            if (n < 0 && n == EINTR) {
                continue;
            }
            int i;
            for (i = 0; i < n; i++) {
                if ((events[i].events & EPOLLERR) || (events[i].events & EPOLLHUP)
                        || (!(events[i].events & (EPOLLIN | EPOLLOUT)))) {
                    error_exit("epoll_wait()");
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
                        //info("%d, %d\n", res1->status_code, res1->size);
                        while((rd=SSL_read(ssl, content+j, res1->size-j)) > 0){
                            j+=rd;
                        }
                        // printf("content: %s\n", content);
                        if(rd == -1){
                            sslerr = SSL_get_error(ssl, rd);
                            if (sslerr != SSL_ERROR_WANT_READ){
                                ERR_print_errors_fp(stderr);
                                error("parcel_recv()");
                            }else{
                                if(j == res1->size){                                                         arrvied = 1;
                                    event.events = EPOLLOUT | EPOLLET;
                                    epoll_ctl(efd, EPOLL_CTL_MOD, clientfd, &event);
                                    switch(res1->status_code){
                                        case STATUS_OK:
                                            gprintf("%s\n", content);
                                            break;
                                        case STATUS_FILE:
                                            writefile(res1->param, content, res1->size);
                                            gprintf("Operation OK\n");
                                            break;
                                        case STATUS_REQUEST_AUTH:
                                            gprintf("Request Login\n");
                                            break;
                                        case STATUS_FAIL_PRIV:
                                            break;
                                        case STATUS_FAIL_INTERNAL:
                                            break;
                                        case STATUS_FAIL_AUTH:
                                            gprintf("Wrong user or password\n");
                                            break;
                                        case STATUS_SUCCESS_AUTH:
                                            gprintf("Login OK\n");
                                            break;
                                        case STATUS_OP_OK:
                                            gprintf("Operation OK\n");
                                            break;
                                        case STATUS_OP_FAIL:
                                            gprintf("Operation Fail\n");
                                            break;
                                        default:
                                            error("Unknow response type");
                                            exit(EXIT_FAILURE);
                                    }
                                }
                                continue;
                            }
                        }
                    }
                    
                }
                //write
                else if (events->events & EPOLLOUT) {
                    if(cmd_push){
                        if(current_cmd_func == NULL){
                            gprintf("unknow command");
                            continue;
                        }
                        (*current_cmd_func)(ssl, params);
                        cmd_push = 0;
                        arrvied = 0;
                        event.events = EPOLLIN | EPOLLET;
                        epoll_ctl(efd, EPOLL_CTL_MOD, clientfd, &event);
                    }
                }
            }
        }
    }
}

// called when window is closed
void on_window_main_destroy()
{
    gtk_main_quit();
}

int
main(int argc, char **argv)
{
    GtkBuilder *builder;
    GtkWidget *window;
    const char *ip="123";
    int port=123;

    gtk_init(&argc, &argv);

    builder = gtk_builder_new();
    gtk_builder_add_from_file (builder, "glade/main.glade", NULL);

    window = GTK_WIDGET(gtk_builder_get_object(builder, "mainWindow"));
    goButton = GTK_WIDGET(gtk_builder_get_object(builder, "goButton"));
    goEntry = GTK_WIDGET(gtk_builder_get_object(builder, "goEntry"));
    hostEntry = GTK_WIDGET(gtk_builder_get_object(builder, "hostEntry"));
    portEntry = GTK_WIDGET(gtk_builder_get_object(builder, "portEntry"));
    mainText = GTK_WIDGET(gtk_builder_get_object(builder, "mainText"));

    gtk_builder_connect_signals(builder, NULL);
    textbuf = gtk_text_view_get_buffer(GTK_TEXT_VIEW(mainText));
    
    // get pointers to the two labels


    g_object_unref(builder);

    gtk_widget_show(window);                
    // connect_server(ip, port);
    gtk_main();

    free(events);
    close(clientfd);
    close(efd);

	return 0;
}

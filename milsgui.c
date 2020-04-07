#include "includes.h"
#include "parcel.h"
#include "utils.h"
#include "log.h"
#include "cmdloop.h"
#include "milssl.h"

#include "gtk/gtk.h"

#define MAXEVENTS 10
#define SERVER_HOST "127.0.0.1"
#define SERVER_PORT 6237

int arrvied = 1;
char *content;
int begin = 0;
extern int cmd_push;
extern int (*current_cmd_func)(SSL *,char **);
extern char **params;

char *bannerstr = "|\\/|o| _\n\
|  |||_\\\n";

GtkWidget *goButton;
GtkWidget *mainText;
GtkWidget *goEntry;

static void
banner()
{
    
}

static void
verify_server(SSL *ssl) 
{
    const EVP_MD *fprint_type = NULL;
    int ret, j, fprint_size;
    unsigned char fprint[EVP_MAX_MD_SIZE];
    BIO *outbio  = BIO_new_fp(stdout, BIO_NOCLOSE);

    X509 *cert = SSL_get_peer_certificate(ssl);
    if (cert != NULL) {
        fprint_type = EVP_sha1();
        
        if (!X509_digest(cert, fprint_type, fprint, &fprint_size)){
            error_exit("X509_digest()");
        }
        BIO_printf(outbio,"Server Fingerprint: ");
        for (j=0; j<fprint_size; ++j) BIO_printf(outbio, "%02x ", fprint[j]);
            BIO_printf(outbio,"\n");
    } else {
        error_exit("Untrusted server");
    }
    BIO_free_all(outbio);
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
    SSL* ssl;
    int clientfd, efd, err;
    struct sockaddr_in server_addr;
    char buf[4096], *errstr;

    

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

    struct epoll_event event;
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
            verify_server(ssl);
            banner();
            c_help();
            break;
        }
    }



    struct epoll_event* events = calloc(MAXEVENTS, sizeof event);
    while (1) {
        if(arrvied){
            arrvied = 0;
            while(command_loop()==-1);
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
                                        printf("%s\n", content);
                                        break;
                                    case STATUS_FILE:
                                        writefile(res1->param, content, res1->size);
                                        printf("Operation OK\n");
                                        break;
                                    case STATUS_REQUEST_AUTH:
                                        printf("Request Login\n");
                                        break;
                                    case STATUS_FAIL_PRIV:
                                        break;
                                    case STATUS_FAIL_INTERNAL:
                                        break;
                                    case STATUS_FAIL_AUTH:
                                        printf("Wrong user or password\n");
                                        break;
                                    case STATUS_SUCCESS_AUTH:
                                        printf("Login OK\n");
                                        break;
                                    case STATUS_OP_OK:
                                        printf("Operation OK\n");
                                        break;
                                    case STATUS_OP_FAIL:
                                        printf("Operation Fail\n");
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
                        error("unknow command");
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
    free(events);
    close(clientfd);
    close(efd);
    return 0;
}

void onGoButtonClick()
{
	const gchar *command;
	GtkTextBuffer *buf = gtk_text_view_get_buffer(GTK_TEXT_VIEW(mainText));

	command = gtk_entry_get_text(GTK_ENTRY(goEntry));
	gtk_text_buffer_set_text(buf, command, -1);
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
    gtk_init(&argc, &argv);

    builder = gtk_builder_new();
    gtk_builder_add_from_file (builder, "glade/main.glade", NULL);

    window = GTK_WIDGET(gtk_builder_get_object(builder, "mainWindow"));
    goButton = GTK_WIDGET(gtk_builder_get_object(builder, "goButton"));
    goEntry = GTK_WIDGET(gtk_builder_get_object(builder, "goEntry"));
    mainText = GTK_WIDGET(gtk_builder_get_object(builder, "mainText"));

    gtk_builder_connect_signals(builder, NULL);
    
    // get pointers to the two labels

    g_object_unref(builder);

    gtk_widget_show(window);                
    gtk_main();

	return 0;
}

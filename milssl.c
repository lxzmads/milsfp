#include "includes.h"
#include "milssl.h"
#include "session.h"
#include "log.h"

SSL_CTX *ctx = NULL;

int
ssl_init(Session *s)
{
    const SSL_METHOD *method;
    char *hostpub = HOST_CERT_PATH HOST_CERT_PUB;
    char *hostkey = HOST_CERT_PATH HOST_CERT_KEY;
    SSL *ssl;

    /* 初始化ssl context，设置相应的ssl参数 */
    info("start create new context");
    if(!ctx){
        SSL_load_error_strings();
        OpenSSL_add_ssl_algorithms();
        
        method = SSLv23_server_method();
        ctx = SSL_CTX_new(method);
        if(!ctx){
            ERR_print_errors_fp(stderr);
            error("SSL_CTX_new()");
            return -1;
        }

        SSL_CTX_set_ecdh_auto(ctx, 1);

        if(SSL_CTX_use_certificate_file(ctx, hostpub, SSL_FILETYPE_PEM) <= 0){
            ERR_print_errors_fp(stderr);
            error("SSL_CTX_use_certificate_file()");
            return -1;
        }
        if(SSL_CTX_use_PrivateKey_file(ctx, hostkey, SSL_FILETYPE_PEM) <= 0 ){
            ERR_print_errors_fp(stderr);
            error("SSL_CTX_use_PrivateKey_file()");
            return -1;
        }
        info("create new context");
    }
    ssl = SSL_new(ctx);
    if(!ssl){
        ERR_print_errors_fp(stderr);
        error("SSL_new()");
        return -1;
    }
    SSL_set_accept_state(ssl);
    if(s->fd < 0){
        error_exit("Invaild file descriptor");
    }
    SSL_set_fd(ssl, s->fd);
    s->ssl = ssl;
    info("ssl init ok");
    return 0;
}

int
ssl_start(Session *s)
{
    int n, sslerr;

    // info("start ssl handshake.");
    n = SSL_do_handshake(s->ssl);
    // debug("n = %d", n);
    if(n == 1){
        info("SSL connection established from %s: %s", s->fromhost, s->fromport);
        return 0;
    }else{
        sslerr = SSL_get_error(s->ssl, n);
        // debug("sslerr = %d", sslerr);
        switch (sslerr){
            case SSL_ERROR_WANT_READ:
            case SSL_ERROR_WANT_WRITE:
                return EAGAIN;
            default:
                ERR_print_errors_fp(stderr);
                error("ssl_start()");
        }
    }
    return 0;
}

int
ssl_destroy(Session *s)
{
    SSL_free(s->ssl);
    return 0;
}

int
ssl_stop()
{
    SSL_CTX_free(ctx);
    EVP_cleanup();
}
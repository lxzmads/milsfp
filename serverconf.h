#ifndef MILS_SERVERCONF_H
#define MILS_SERVERCONF_H

typedef struct{
    u_int32_t   port;
    char    *listen_addr;
    char    *host_key_file;
    u_int16_t *permit_root;
    char    *logfile;
    u_int32_t   max_file_size; /* in mbyte */
    char    *banner;    /* welcome message */
    int     client_alive_interval;  /* poke the client to see if it's still there */
    int     client_alive_count_max; /* if the client is unresponsive for this many intervals above, disconnect the session */
    char    *authorized_keys_file; /* file containing public keys */

}   ServerOptions;


void    init_server_conf(ServerOptions *);
void    read_server_conf(ServerOptions *, const char *);
#endif
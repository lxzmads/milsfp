#ifndef MILS_SSL_H
#define MILS_SSL_H

#include "session.h"

int     ssl_init(Session *s);
int     ssl_start(Session *s);
int     ssl_destroy(Session *s);
int     ssl_stop();

#endif
#ifndef MILS_AUTH_H
#define MILS_AUTH_H

int     auth_password(const char *username, const char *password);
int     auth_pam(const char *username,const char *password);
int     auth_privfile();

#endif
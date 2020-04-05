#include "includes.h"
#include "auth.h"
#include "log.h"

#include <security/pam_appl.h>
#include <security/pam_misc.h>

static struct pam_conv conv = {
    misc_conv,
    NULL
};

int
auth_password(const char *username, const char *password)
{
    return auth_pam(username, password);
}

int
auth_pam(const char *username,const char *password)
{
    pam_handle_t *pamh = NULL;
    int retval;
    const char *user = username;

    retval = pam_start("mislp", user, &conv, &pamh);
    if(retval == PAM_SUCCESS){
        retval = pam_authenticate(pamh, 0);
    }
    if(retval = PAM_SUCCESS){
        retval = pam_acct_mgmt(pamh, 0);
    }

    if(pam_end(pamh, retval) != PAM_SUCCESS){
        pamh = NULL;
        error("auth_pam()");
        exit(1);
    }
    return (retval == PAM_SUCCESS ? 0:1);
}

int
auth_privfile()
{
    return 0;
}
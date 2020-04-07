#include "includes.h"
#include "auth.h"
#include "log.h"

#include <security/pam_appl.h>
#include <security/pam_misc.h>

static struct pam_conv conv = {
    misc_conv,
    NULL
};

static int pamconv(int num_msg, const struct pam_message **msg,
        struct pam_response **resp, void *appdata_ptr)
{
    char *pass = malloc(strlen(appdata_ptr)+1);
    strcpy(pass, appdata_ptr);

    int i;

    *resp = calloc(num_msg, sizeof(struct pam_response));

    for (i = 0; i < num_msg; ++i)
    {
        /* Ignore all PAM messages except prompting for hidden input */
        if (msg[i]->msg_style != PAM_PROMPT_ECHO_OFF)
            continue;

        /* Assume PAM is only prompting for the password as hidden input */
        resp[i]->resp = pass;
    }

    return PAM_SUCCESS;
}

int
auth_password(const char *username, const char *password)
{
    return auth_pam(username, password);
}

int
auth_pam(const char *username,const char *password)
{
    /* use own PAM conversation function just responding with the
       password passed here */
    struct pam_conv conv = { &pamconv, (void *)password };

    pam_handle_t *handle;
    int authResult;

    pam_start("shutterd", username, &conv, &handle);
    authResult = pam_authenticate(handle,
            PAM_SILENT|PAM_DISALLOW_NULL_AUTHTOK);
    pam_end(handle, authResult);

    return (authResult == PAM_SUCCESS ? 0:1);
}

int
auth_privfile()
{
    return 0;
}
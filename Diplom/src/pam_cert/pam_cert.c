#include <stdio.h>
#include <stdlib.h>

#include <stdarg.h>
#include <security/pam_modutil.h>
#include <security/pam_ext.h>
#include <security/pam_modules.h>
#include <syslog.h>
#include <string.h>
#include <unistd.h>

#include <selinux/selinux.h>
#include <selinux/context.h>
#include <selinux/get_context_list.h>
#include <selinux/context.h>


PAM_EXTERN int pam_sm_open_session(pam_handle_t *pamh, int flags, int argc, const char **argv) {
    security_context_t context = NULL;
    char *user = NULL;
    char *level = NULL;
    char *seuser = NULL;
    char *command = NULL;

    int result = 0;
  
    if (pam_get_item(pamh, PAM_USER, (void*) &user) < 0) {
	pam_syslog(pamh, LOG_ERR, "Could not get username");
	return PAM_SESSION_ERR;
    }
    
    if (0 == is_selinux_mls_enabled()) {
	pam_syslog(pamh, LOG_ERR, "SELinux MLS is not enabled");
	return PAM_SESSION_ERR;
    }
    
    if (getseuserbyname(user, &seuser, &level) == 0) {
	result = get_default_context_with_level(seuser, level, NULL, &context);
    }
    
    asprintf(&command, "/usr/bin/pgcert --genpair --user %s --output /home/%s/home.inst", user, user);
    printf("Command: %s\n", command);
    
    if (system(command) < 0) {
	pam_syslog(pamh, LOG_ERR, "Could not generate SSL key pair for %s", user);
	return PAM_SESSION_ERR;
    }
    printf("Status: %d\n", result);
    printf("User: %s\n", user);
    printf("Context: %s\n", context);
    printf("Level is %s\n", level);
    
    free(seuser);
    free(level);
    //free(user);
    return PAM_SUCCESS;
}


/*
 * Entry point from pam_close_session call.
 */
PAM_EXTERN int pam_sm_close_session(pam_handle_t *pamh, int flags, int argc, const char **argv) {
    return PAM_SUCCESS;
}
 
#ifdef PAM_STATIC

/* static module data */

struct pam_module _pam_cert_modstruct = {
     "pam_cert",
     NULL,
     NULL,
     NULL,
     pam_sm_open_session,
     pam_sm_close_session,
     NULL
};
#endif

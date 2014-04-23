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
    char *send_command = NULL;
  
    if (pam_get_item(pamh, PAM_USER, (void*) &user) < 0) {
		pam_syslog(pamh, LOG_ERR, "Could not get username");
		return PAM_SESSION_ERR;
    }
    
    if (0 == is_selinux_mls_enabled()) {
		pam_syslog(pamh, LOG_ERR, "SELinux MLS is not enabled");
		return PAM_SESSION_ERR;
    }
    
    if (getseuserbyname(user, &seuser, &level) == 0) {
		get_default_context_with_level(seuser, level, NULL, &context);
    }
    
    if (strcmp(user, "root") != 0) {
    
		asprintf(&send_command, "/etc/pki/send_key.sh %s %s", user, context);
    
		if (system(send_command) < 0) {
			pam_syslog(pamh, LOG_ERR, "Could not send public key for user %s", user);
			return PAM_SESSION_ERR;
		}
	
		free(send_command);
    }
    
    free(seuser);
    free(level);
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

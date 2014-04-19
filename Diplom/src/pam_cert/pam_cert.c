#include <stdarg.h>
#include <security/pam_modutil.h>
#include <security/pam_ext.h>
#include <security/pam_modules.h>
#include <syslog.h>
#include <stdio.h>
#include <stdlib.h>
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
    
    pid_t pid = fork();
    int res = -1;
    if (pid == 0) {
	const char * pgcert = "/usr/bin/pgcert";
	res = execl(pgcert, "pgcert", "--genpair", "--output", "/home/user1", NULL);
    }
    printf("Status: %d\n", result);
    printf("User: %s\n", user);
    printf("Context: %s\n", context);
    printf("Level is %s\n", level);
    printf("Res: %d\n", res);
    
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

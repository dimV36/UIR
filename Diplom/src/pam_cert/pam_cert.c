#include <stdarg.h>
#include <security/pam_modutil.h>
#include <security/pam_ext.h>
#include <security/pam_modules.h>
#include <syslog.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <selinux/selinux.h>
#include <selinux/context.h>
#include <selinux/get_context_list.h>
#include <selinux/context.h>

int make_context_list(context_t context) {
    const char *range = context_range_get(context);
//     char *level_range = NULL;
//     char *category_range = NULL;
    
    if (NULL == range) {
	printf("Could not get range from context");
	return 1;
    }
    
    printf("Range %s\n", range);
    char *tok = strtok(range, ":");
    printf("res: %s\n", tok);
    char *tok2 = strtok('\0', ":");
    printf("tok2: %s\n", tok2);
    
    
    
    return 0;
}


PAM_EXTERN int pam_sm_open_session(pam_handle_t *pamh, int flags, int argc, const char **argv) {
    security_context_t context = NULL;
    security_context_t *list = NULL;
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
    printf("Status: %d\n", result);
    printf("User: %s\n", user);
    printf("Context: %s\n", context);
    printf("Level is %s\n", level);
    
    result = get_ordered_context_list("user_u", "user_u:user_r:user_t:s0", &list);
    printf("Status: %d\n", result);
    
    make_context_list(context_new(context));
    
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

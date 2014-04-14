#include <stdarg.h>
#include <security/pam_modutil.h>
#include <security/pam_ext.h>
#include <security/pam_modules.h>
#include <syslog.h>
#include <stdio.h>
#include <stdlib.h>
#include <selinux/selinux.h>
#include <selinux/context.h>
#include <selinux/get_context_list.h>
//#include <selinux/context.h>

int make_context_list(security_context_t context) {
//     int result = security_check_context_raw(context);
     security_context_t cancon = NULL;
     security_canonicalize_context("user_u:user_r:user_t:s0-s1:c0,c1,c2,c3,c6", &cancon);
     printf("Cancon: %s\n", (char*) cancon);
     printf("int: %d\n", atoi("s0-s3"));
//    int result = security_check_context_raw("user_u:user_r:user_t:s0-s15:c0.c1023");
//     printf("Context is %d\n", result);
    return 0;
}


PAM_EXTERN int pam_sm_open_session(pam_handle_t *pamh, int flags, int argc, const char **argv) {
    security_context_t context = NULL;
//    security_context_t *list = NULL;
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
    printf("Context: %s\n", (char*) context);
    printf("Level is %s\n", level);
    
    make_context_list(context);
    
//     result = get_ordered_context_list_with_level("user_u", level, NULL, &list);
//     printf("Status: %d\n", result);
//     int count = sizeof(list) / sizeof(list[0]);
//     printf("Sizeof: %d\n", count);
    
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

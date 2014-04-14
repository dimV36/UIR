//#include <stdarg.h>
//#include <security/pam_modutil.h>
//#include <security/pam_ext.h>
//#include <security/pam_modules.h>
#include <syslog.h>
#include <stdio.h>
#include <stdlib.h>
#include <selinux/selinux.h>
#include <selinux/get_context_list.h>
#include <selinux/context.h>

int make_context_list(security_context_t context) {

    return 0;
}


int main() {
     security_context_t context = NULL;
//    security_context_t *list = NULL;
    char *user = NULL;
    char *level = NULL;
    char *seuser = NULL;

    int result = 0;
  
/*    if (pam_get_item(pamh, PAM_USER, (void*) &user) < 0) {
	pam_syslog(pamh, LOG_ERR, "Could not get username");
	return PAM_SESSION_ERR;
    } */
    user = "dimv36";
    if (0 == is_selinux_mls_enabled()) {
//	pam_syslog(pamh, LOG_ERR, "SELinux MLS is not enabled");
	return 1;
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
    return 0;      
}
 

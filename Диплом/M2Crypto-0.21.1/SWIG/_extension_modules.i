%{
#include <openssl/objects.h>
%}

%rename(obj_create) OBJ_create;
extern int OBJ_create(const char* oid, const char *ln, const char *sn);

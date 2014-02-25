%{
#include <openssl/x509v3.h>
#include <openssl/obj_mac.h>
%}

%constant int NID_netscape_comment = 78;

%rename(x509v3_ext_add_alias) X509V3_EXT_add_alias;
extern int X509V3_EXT_add_alias(int nid_to, int nid_from);

%rename(x509v3_ext_conf_nid) X509V3_EXT_conf_nid;
extern int X509V3_EXT_conf_nid(LHASH_OF(CONF_VALUE) *conf, X509V3_CTX *ctr, int ext_nid, char *value);
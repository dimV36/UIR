#include "postgres.h"
#include "fmgr.h"
#include "utils/numeric.h"
#include "libpq/libpq-be.h"
#include "miscadmin.h"
#include "utils/builtins.h"
#include "mb/pg_wchar.h"
#include "funcapi.h"

#include <openssl/x509.h>
#include <openssl/x509v3.h>


PG_MODULE_MAGIC;

Datum 		ssl_get_extension_by_name(PG_FUNCTION_ARGS);
Datum		ssl_is_critical_extension(PG_FUNCTION_ARGS);
Datum 		ssl_get_extensions_count(PG_FUNCTION_ARGS);
Datum		ssl_get_extensions_names(PG_FUNCTION_ARGS);


static X509_EXTENSION *get_extension(X509* certificate, char *name) {
	int extension_nid = OBJ_sn2nid(name);
	if (0 == extension_nid) {
	    extension_nid = OBJ_ln2nid(name);
	    if (0 == extension_nid) 
		return NULL;
	}
	int locate = X509_get_ext_by_NID(certificate, extension_nid,  -1);
	return X509_get_ext(certificate, locate);
}


PG_FUNCTION_INFO_V1(ssl_get_extension_by_name);
Datum
ssl_get_extension_by_name(PG_FUNCTION_ARGS)
{	
	X509 *certificate = MyProcPort -> peer;
	char *extension_name = text_to_cstring(PG_GETARG_TEXT_P(0));
	X509_EXTENSION *extension = NULL;
	BIO *bio = BIO_new(BIO_s_mem());
	char *value = NULL;
	text *result = NULL;
	
	if (NULL == certificate)
	    PG_RETURN_NULL();

	extension = get_extension(certificate, extension_name);
	if (NULL == extension) 
	    elog(ERROR, "Extension by name \"%s\" is not found in certificate", extension_name);
	
	char nullterm = '\0';
	X509V3_EXT_print(bio, extension, -1, -1);
	BIO_write(bio, &nullterm, 1);
	BIO_get_mem_data(bio, &value);
	
	result = cstring_to_text(value);
	BIO_free(bio);
	OPENSSL_free(extension);
	
	PG_RETURN_TEXT_P(result);
}


PG_FUNCTION_INFO_V1(ssl_is_critical_extension);
Datum
ssl_is_critical_extension(PG_FUNCTION_ARGS) {
	X509 *certificate = MyProcPort -> peer;
	char *extension_name = text_to_cstring(PG_GETARG_TEXT_P(0));
	X509_EXTENSION *extension = NULL;
	
	if (NULL == certificate)
	    PG_RETURN_NULL();
	
	extension = get_extension(certificate, extension_name);
	if (NULL == extension) 
	    elog(ERROR, "Extension name \"%s\" is not found in certificate", extension_name);
	
	int critical = X509_EXTENSION_get_critical(extension);
	OPENSSL_free(extension);
	PG_RETURN_BOOL(critical);
}


PG_FUNCTION_INFO_V1(ssl_get_extensions_count);
Datum
ssl_get_extensions_count(PG_FUNCTION_ARGS) {
	X509 *certificate = MyProcPort -> peer;
	
	if (NULL == certificate)
	    PG_RETURN_NULL();
	
	int extension_count = X509_get_ext_count(certificate);
	PG_RETURN_INT32(extension_count);
}


PG_FUNCTION_INFO_V1(ssl_get_extensions_names);
Datum
ssl_get_extensions_names(PG_FUNCTION_ARGS) {
	X509				*certificate = MyProcPort -> peer;
	STACK_OF(X509_EXTENSION) 	*extension_stack = NULL;
	int 				extension_count = 0;

	if (NULL == certificate)
	    PG_RETURN_NULL();
	
	extension_count = X509_get_ext_count(certificate);
	int i;
	extension_stack = certificate -> cert_info -> extensions;
	if (NULL == extension_stack) 
	    PG_RETURN_NULL();
	
	for (i = 0; i < extension_count; i++) {
	    X509_EXTENSION *extension = sk_X509_EXTENSION_value(extension_stack, i);
	    ASN1_OBJECT *object = X509_EXTENSION_get_object(extension);
	    int extension_nid = OBJ_obj2nid(object);
	    if (0 == extension_nid) 
		elog(ERROR, "Unknown extension in certificate");
	    elog(INFO, "extension %s", OBJ_nid2sn(extension_nid));
	    OPENSSL_free(extension);
	    OPENSSL_free(object);
	}
	OPENSSL_free(extension_stack);
	PG_RETURN_NULL();
}

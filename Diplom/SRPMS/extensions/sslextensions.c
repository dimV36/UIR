#include "postgres.h"
#include "libpq/libpq-be.h"
#include "fmgr.h"
#include "miscadmin.h"
#include "utils/builtins.h"
#include "funcapi.h"

#include <openssl/x509v3.h>
#include <openssl/x509.h>

PG_MODULE_MAGIC;

Datum ssl_get_extension_by_name(PG_FUNCTION_ARGS);
Datum ssl_is_critical_extension(PG_FUNCTION_ARGS);
Datum ssl_get_extensions_count(PG_FUNCTION_ARGS);
//Datum ssl_get_extensions_names(PG_FUNCTION_ARGS);


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
	
/*	int extension_nid = OBJ_sn2nid(extension_name);
	if (0 == extension_nid) {
	    elog(ERROR, "Could not get OID for \"%s\"", extension_name);
	    PG_RETURN_NULL();
	}
	int locate = X509_get_ext_by_NID(certificate, extension_nid, -1);
	extension = X509_get_ext(certificate, locate); */
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
/*	int extension_nid = OBJ_sn2nid(extension_name);
	if (0 == extension_nid) {
	    elog(ERROR, "Could not get OID for \"%s\"", extension_name);
	    PG_RETURN_NULL();
	}
	int locate = X509_get_ext_by_NID(certificate, extension_nid, -1);
	extension = X509_get_ext(certificate, locate); */
	if (NULL == extension) 
	    elog(ERROR, "Extension name \"%s\" is not found in certificate", extension_name);
	int critical = extension -> critical;
	OPENSSL_free(extension);
	
	PG_RETURN_BOOL(critical > 0);
}


PG_FUNCTION_INFO_V1(ssl_get_extensions_count);
Datum
ssl_get_extensions_count(PG_FUNCTION_ARGS) {
	X509 *certificate = MyProcPort -> peer;
	elog(INFO, "certiciate is found");
	if (NULL == certificate)
	  PG_RETURN_NULL();
	elog(INFO, "certificate not null");
	int extension_count = X509_get_ext_count(certificate);
	elog(INFO, "count %d", extension_count);
	PG_RETURN_INT32(extension_count);	
}


//PG_FUNCTION_INFO_V1(ssl_get_extensions_names);
//Datum
//ssl_get_extensions_names(PG_FUNCTION_ARGS) {
//	X509 *certificate = MyProcPort -> peer;
//	
//	if (NULL == certificate)
//	  PG_RETURN_NULL();
//	
//	PG_RETURN_INT32();
//}

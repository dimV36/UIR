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

X509_EXTENSION	*get_extension(X509* certificate, char *name);
Datum 		ssl_get_extension_value(PG_FUNCTION_ARGS);
Datum		ssl_is_critical_extension(PG_FUNCTION_ARGS);
Datum 		ssl_get_count_of_extensions(PG_FUNCTION_ARGS);
Datum		ssl_get_extension_names(PG_FUNCTION_ARGS);


X509_EXTENSION *get_extension(X509* certificate, char *name) {
	int 			extension_nid = 0;
	int 			locate = 0;
	
	extension_nid = OBJ_sn2nid(name);
	if (0 == extension_nid) {
	    extension_nid = OBJ_ln2nid(name);
	    if (0 == extension_nid) 
		return NULL;
	}
	locate = X509_get_ext_by_NID(certificate, extension_nid,  -1);
	return X509_get_ext(certificate, locate);
}


PG_FUNCTION_INFO_V1(ssl_get_extension_value);
Datum
ssl_get_extension_value(PG_FUNCTION_ARGS) {	
	X509 			*certificate = MyProcPort -> peer;
	X509_EXTENSION 		*extension = NULL;
	char 			*extension_name = text_to_cstring(PG_GETARG_TEXT_P(0));
	BIO 			*bio = NULL;
	char 			*value = NULL;
	text 			*result = NULL;

	if (NULL == certificate)
	    PG_RETURN_NULL();

	extension = get_extension(certificate, extension_name);
	if (NULL == extension)
	    elog(ERROR, "Extension by name \"%s\" is not found in certificate", extension_name);

	bio = BIO_new(BIO_s_mem());
	char nullterm = '\0';
	X509V3_EXT_print(bio, extension, -1, -1);
	BIO_write(bio, &nullterm, 1);
	BIO_get_mem_data(bio, &value);

	result = cstring_to_text(value);
	BIO_free(bio);

	PG_RETURN_TEXT_P(result);
}


PG_FUNCTION_INFO_V1(ssl_is_critical_extension);
Datum
ssl_is_critical_extension(PG_FUNCTION_ARGS) {
	X509 			*certificate = MyProcPort -> peer;
	X509_EXTENSION 		*extension = NULL;
	char 			*extension_name = text_to_cstring(PG_GETARG_TEXT_P(0));
	int 			critical = 0;
	
	if (NULL == certificate)
	    PG_RETURN_NULL();
	
	extension = get_extension(certificate, extension_name);
	if (NULL == extension) 
	    elog(ERROR, "Extension name \"%s\" is not found in certificate", extension_name);
	
	critical = X509_EXTENSION_get_critical(extension);
	PG_RETURN_BOOL(critical);
}


PG_FUNCTION_INFO_V1(ssl_get_count_of_extensions);
Datum
ssl_get_count_of_extensions(PG_FUNCTION_ARGS) {
	X509 			*certificate = MyProcPort -> peer;
	
	if (NULL == certificate)
	    PG_RETURN_NULL();
	
	PG_RETURN_INT32(X509_get_ext_count(certificate));
}


PG_FUNCTION_INFO_V1(ssl_get_extension_names);
Datum
ssl_get_extension_names(PG_FUNCTION_ARGS) {
	X509				*certificate = MyProcPort -> peer;
	FuncCallContext 		*funcctx;
	STACK_OF(X509_EXTENSION) 	*extension_stack = NULL;
	MemoryContext 			oldcontext;
	int 				call = 0;
	int 				max_calls = 0;
	X509_EXTENSION			*extension = NULL;
	ASN1_OBJECT			*object = NULL;
	int 				extension_nid = 0;
	text*				result = NULL;
	
	if (NULL == certificate)
	    PG_RETURN_NULL();
	
	extension_stack = certificate -> cert_info -> extensions;
	if (NULL == extension_stack) 
	    PG_RETURN_NULL();
	
	if (SRF_IS_FIRSTCALL()) {
	    funcctx = SRF_FIRSTCALL_INIT();
	    oldcontext = MemoryContextSwitchTo(funcctx -> multi_call_memory_ctx);
	    funcctx -> max_calls = X509_get_ext_count(certificate);
	    MemoryContextSwitchTo(oldcontext);
	}
	funcctx = SRF_PERCALL_SETUP();
	
	call = funcctx -> call_cntr;
	max_calls = funcctx -> max_calls;
	
	if (call < max_calls) {
	    extension = sk_X509_EXTENSION_value(extension_stack, call);
	    object = X509_EXTENSION_get_object(extension);
	    extension_nid = OBJ_obj2nid(object);
	    
	    if (0 == extension_nid)
		elog(ERROR, "Unknown extension in certificate");
	    
	    result = cstring_to_text(OBJ_nid2sn(extension_nid));
	    
 	    SRF_RETURN_NEXT(funcctx, (Datum) result);
	}
	SRF_RETURN_DONE(funcctx);
}

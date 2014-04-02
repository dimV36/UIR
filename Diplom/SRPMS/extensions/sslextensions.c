#include "postgres.h"
#include "libpq/libpq-be.h"
#include "fmgr.h"
#include "miscadmin.h"
#include "utils/builtins.h"
#include "funcapi.h"

#include <openssl/x509v3.h>

PG_MODULE_MAGIC;

Datum retcomposite(PG_FUNCTION_ARGS);
Datum ssl_get_extension_by_name(PG_FUNCTION_ARGS);
Datum ssl_is_critical_extension(PG_FUNCTION_ARGS);
Datum ssl_get_extensions_count(PG_FUNCTION_ARGS);
//Datum ssl_get_extensions_names(PG_FUNCTION_ARGS);


PG_FUNCTION_INFO_V1(retcomposite);
Datum
retcomposite(PG_FUNCTION_ARGS)
{
    FuncCallContext     *funcctx;
    int                  call_cntr;
    int                  max_calls;
    TupleDesc            tupdesc;
    AttInMetadata       *attinmeta;

    /* stuff done only on the first call of the function */
    if (SRF_IS_FIRSTCALL())
    {
        MemoryContext   oldcontext;

        /* create a function context for cross-call persistence */
        funcctx = SRF_FIRSTCALL_INIT();

        /* switch to memory context appropriate for multiple function calls */
        oldcontext = MemoryContextSwitchTo(funcctx->multi_call_memory_ctx);

        /* total number of tuples to be returned */
        funcctx->max_calls = PG_GETARG_UINT32(0);

        /* Build a tuple descriptor for our result type */
        if (get_call_result_type(fcinfo, NULL, &tupdesc) != TYPEFUNC_COMPOSITE)
            ereport(ERROR,
                    (errcode(ERRCODE_FEATURE_NOT_SUPPORTED),
                     errmsg("function returning record called in context "
                            "that cannot accept type record")));

        /*
         * generate attribute metadata needed later to produce tuples from raw
         * C strings
         */
        attinmeta = TupleDescGetAttInMetadata(tupdesc);
        funcctx->attinmeta = attinmeta;

        MemoryContextSwitchTo(oldcontext);
    }

    /* stuff done on every call of the function */
    funcctx = SRF_PERCALL_SETUP();

    call_cntr = funcctx->call_cntr;
    max_calls = funcctx->max_calls;
    attinmeta = funcctx->attinmeta;

    if (call_cntr < max_calls)    /* do when there is more left to send */
    {
        char       **values;
        HeapTuple    tuple;
        Datum        result;

        /*
         * Prepare a values array for building the returned tuple.
         * This should be an array of C strings which will
         * be processed later by the type input functions.
         */
        values = (char **) palloc(3 * sizeof(char *));
        values[0] = (char *) palloc(16 * sizeof(char));
        values[1] = (char *) palloc(16 * sizeof(char));
        values[2] = (char *) palloc(16 * sizeof(char));

        snprintf(values[0], 16, "%d", 1 * PG_GETARG_INT32(1));
        snprintf(values[1], 16, "%d", 2 * PG_GETARG_INT32(1));
        snprintf(values[2], 16, "%d", 3 * PG_GETARG_INT32(1));

        /* build a tuple */
        tuple = BuildTupleFromCStrings(attinmeta, values);

        /* make the tuple into a datum */
        result = HeapTupleGetDatum(tuple);

        /* clean up (this is not really necessary) */
        pfree(values[0]);
        pfree(values[1]);
        pfree(values[2]);
        pfree(values);

        SRF_RETURN_NEXT(funcctx, result);
    }
    else    /* do when there is no more left */
    {
        SRF_RETURN_DONE(funcctx);
    }
}


X509_EXTENSION *get_extension(X509* certificate, char *name) {
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
	pfree(extension_name);
	
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
	    elog(ERROR, "Extension by name \"%s\" is not found in certificate", extension_name);
	int critical = extension -> critical;
	
	PG_RETURN_BOOL(critical > 0);
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

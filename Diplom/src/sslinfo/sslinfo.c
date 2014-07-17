/*
 * module for PostgreSQL to access client SSL certificate information
 *
 * Written by Victor B. Wagner <vitus@cryptocom.ru>, Cryptocom LTD
 * This file is distributed under BSD-style license.
 *
 * contrib/sslinfo/sslinfo.c
 * 
 * Extension functions written by Dmitry Voronin carriingfate92@yandex.ru, CNIIEISU.
 */

#include "postgres.h"
#include "fmgr.h"
#include "utils/numeric.h"
#include "libpq/libpq-be.h"
#include "miscadmin.h"
#include "utils/builtins.h"
#include "mb/pg_wchar.h"
#include "funcapi.h"

#include <openssl/x509.h>
#include <openssl/asn1.h>
#include <openssl/x509v3.h>


PG_MODULE_MAGIC;


Datum		ssl_is_used(PG_FUNCTION_ARGS);
Datum		ssl_version(PG_FUNCTION_ARGS);
Datum		ssl_cipher(PG_FUNCTION_ARGS);
Datum		ssl_client_cert_present(PG_FUNCTION_ARGS);
Datum		ssl_client_serial(PG_FUNCTION_ARGS);
Datum		ssl_client_dn_field(PG_FUNCTION_ARGS);
Datum		ssl_issuer_field(PG_FUNCTION_ARGS);
Datum		ssl_client_dn(PG_FUNCTION_ARGS);
Datum		ssl_issuer_dn(PG_FUNCTION_ARGS);
Datum		X509_NAME_field_to_text(X509_NAME *name, text *fieldName);
Datum		X509_NAME_to_text(X509_NAME *name);
Datum		ASN1_STRING_to_text(ASN1_STRING *str);

X509_EXTENSION	*get_extension(X509* certificate, char *name);
Datum 		ssl_get_extension_value(PG_FUNCTION_ARGS);
Datum		ssl_is_critical_extension(PG_FUNCTION_ARGS);
Datum 		ssl_get_count_of_extensions(PG_FUNCTION_ARGS);
Datum		ssl_get_extension_names(PG_FUNCTION_ARGS);

/*
 * Indicates whether current session uses SSL
 *
 * Function has no arguments.  Returns bool.  True if current session
 * is SSL session and false if it is local or non-ssl session.
 */
PG_FUNCTION_INFO_V1(ssl_is_used);
Datum
ssl_is_used(PG_FUNCTION_ARGS)
{
	PG_RETURN_BOOL(MyProcPort->ssl != NULL);
}


/*
 * Returns SSL cipher currently in use.
 */
PG_FUNCTION_INFO_V1(ssl_version);
Datum
ssl_version(PG_FUNCTION_ARGS)
{
	if (MyProcPort->ssl == NULL)
		PG_RETURN_NULL();
	PG_RETURN_TEXT_P(cstring_to_text(SSL_get_version(MyProcPort->ssl)));
}


/*
 * Returns SSL cipher currently in use.
 */
PG_FUNCTION_INFO_V1(ssl_cipher);
Datum
ssl_cipher(PG_FUNCTION_ARGS)
{
	if (MyProcPort->ssl == NULL)
		PG_RETURN_NULL();
	PG_RETURN_TEXT_P(cstring_to_text(SSL_get_cipher(MyProcPort->ssl)));
}


/*
 * Indicates whether current client have provided a certificate
 *
 * Function has no arguments.  Returns bool.  True if current session
 * is SSL session and client certificate is verified, otherwise false.
 */
PG_FUNCTION_INFO_V1(ssl_client_cert_present);
Datum
ssl_client_cert_present(PG_FUNCTION_ARGS)
{
	PG_RETURN_BOOL(MyProcPort->peer != NULL);
}


/*
 * Returns serial number of certificate used to establish current
 * session
 *
 * Function has no arguments.  It returns the certificate serial
 * number as numeric or null if current session doesn't use SSL or if
 * SSL connection is established without sending client certificate.
 */
PG_FUNCTION_INFO_V1(ssl_client_serial);
Datum
ssl_client_serial(PG_FUNCTION_ARGS)
{
	Datum		result;
	Port	   *port = MyProcPort;
	X509	   *peer = port->peer;
	ASN1_INTEGER *serial = NULL;
	BIGNUM	   *b;
	char	   *decimal;

	if (!peer)
		PG_RETURN_NULL();
	serial = X509_get_serialNumber(peer);
	b = ASN1_INTEGER_to_BN(serial, NULL);
	decimal = BN_bn2dec(b);

	BN_free(b);
	result = DirectFunctionCall3(numeric_in,
								 CStringGetDatum(decimal),
								 ObjectIdGetDatum(0),
								 Int32GetDatum(-1));
	OPENSSL_free(decimal);
	return result;
}


/*
 * Converts OpenSSL ASN1_STRING structure into text
 *
 * Converts ASN1_STRING into text, converting all the characters into
 * current database encoding if possible.  Any invalid characters are
 * replaced by question marks.
 *
 * Parameter: str - OpenSSL ASN1_STRING structure.	Memory management
 * of this structure is responsibility of caller.
 *
 * Returns Datum, which can be directly returned from a C language SQL
 * function.
 */
Datum
ASN1_STRING_to_text(ASN1_STRING *str)
{
	BIO		   *membuf;
	size_t		size;
	char		nullterm;
	char	   *sp;
	char	   *dp;
	text	   *result;

	membuf = BIO_new(BIO_s_mem());
	(void) BIO_set_close(membuf, BIO_CLOSE);
	ASN1_STRING_print_ex(membuf, str,
						 ((ASN1_STRFLGS_RFC2253 & ~ASN1_STRFLGS_ESC_MSB)
						  | ASN1_STRFLGS_UTF8_CONVERT));
	/* ensure null termination of the BIO's content */
	nullterm = '\0';
	BIO_write(membuf, &nullterm, 1);
	size = BIO_get_mem_data(membuf, &sp);
	dp = (char *) pg_do_encoding_conversion((unsigned char *) sp,
											size - 1,
											PG_UTF8,
											GetDatabaseEncoding());
	result = cstring_to_text(dp);
	if (dp != sp)
		pfree(dp);
	BIO_free(membuf);

	PG_RETURN_TEXT_P(result);
}


/*
 * Returns specified field of specified X509_NAME structure
 *
 * Common part of ssl_client_dn and ssl_issuer_dn functions.
 *
 * Parameter: X509_NAME *name - either subject or issuer of certificate
 * Parameter: text fieldName  - field name string like 'CN' or commonName
 *			  to be looked up in the OpenSSL ASN1 OID database
 *
 * Returns result of ASN1_STRING_to_text applied to appropriate
 * part of name
 */
Datum
X509_NAME_field_to_text(X509_NAME *name, text *fieldName)
{
	char	   *string_fieldname;
	int			nid,
				index;
	ASN1_STRING *data;

	string_fieldname = text_to_cstring(fieldName);
	nid = OBJ_txt2nid(string_fieldname);
	if (nid == NID_undef)
		ereport(ERROR,
				(errcode(ERRCODE_INVALID_PARAMETER_VALUE),
				 errmsg("invalid X.509 field name: \"%s\"",
						string_fieldname)));
	pfree(string_fieldname);
	index = X509_NAME_get_index_by_NID(name, nid, -1);
	if (index < 0)
		return (Datum) 0;
	data = X509_NAME_ENTRY_get_data(X509_NAME_get_entry(name, index));
	return ASN1_STRING_to_text(data);
}


/*
 * Returns specified field of client certificate distinguished name
 *
 * Receives field name (like 'commonName' and 'emailAddress') and
 * returns appropriate part of certificate subject converted into
 * database encoding.
 *
 * Parameter: fieldname text - will be looked up in OpenSSL object
 * identifier database
 *
 * Returns text string with appropriate value.
 *
 * Throws an error if argument cannot be converted into ASN1 OID by
 * OpenSSL.  Returns null if no client certificate is present, or if
 * there is no field with such name in the certificate.
 */
PG_FUNCTION_INFO_V1(ssl_client_dn_field);
Datum
ssl_client_dn_field(PG_FUNCTION_ARGS)
{
	text	   *fieldname = PG_GETARG_TEXT_P(0);
	Datum		result;

	if (!(MyProcPort->peer))
		PG_RETURN_NULL();

	result = X509_NAME_field_to_text(X509_get_subject_name(MyProcPort->peer), fieldname);

	if (!result)
		PG_RETURN_NULL();
	else
		return result;
}


/*
 * Returns specified field of client certificate issuer name
 *
 * Receives field name (like 'commonName' and 'emailAddress') and
 * returns appropriate part of certificate subject converted into
 * database encoding.
 *
 * Parameter: fieldname text - would be looked up in OpenSSL object
 * identifier database
 *
 * Returns text string with appropriate value.
 *
 * Throws an error if argument cannot be converted into ASN1 OID by
 * OpenSSL.  Returns null if no client certificate is present, or if
 * there is no field with such name in the certificate.
 */
PG_FUNCTION_INFO_V1(ssl_issuer_field);
Datum
ssl_issuer_field(PG_FUNCTION_ARGS)
{
	text	   *fieldname = PG_GETARG_TEXT_P(0);
	Datum		result;

	if (!(MyProcPort->peer))
		PG_RETURN_NULL();

	result = X509_NAME_field_to_text(X509_get_issuer_name(MyProcPort->peer), fieldname);

	if (!result)
		PG_RETURN_NULL();
	else
		return result;
}


/*
 * Equivalent of X509_NAME_oneline that respects encoding
 *
 * This function converts X509_NAME structure to the text variable
 * converting all textual data into current database encoding.
 *
 * Parameter: X509_NAME *name X509_NAME structure to be converted
 *
 * Returns: text datum which contains string representation of
 * X509_NAME
 */
Datum
X509_NAME_to_text(X509_NAME *name)
{
	BIO		   *membuf = BIO_new(BIO_s_mem());
	int			i,
				nid,
				count = X509_NAME_entry_count(name);
	X509_NAME_ENTRY *e;
	ASN1_STRING *v;
	const char *field_name;
	size_t		size;
	char		nullterm;
	char	   *sp;
	char	   *dp;
	text	   *result;

	(void) BIO_set_close(membuf, BIO_CLOSE);
	for (i = 0; i < count; i++)
	{
		e = X509_NAME_get_entry(name, i);
		nid = OBJ_obj2nid(X509_NAME_ENTRY_get_object(e));
		v = X509_NAME_ENTRY_get_data(e);
		field_name = OBJ_nid2sn(nid);
		if (!field_name)
			field_name = OBJ_nid2ln(nid);
		BIO_printf(membuf, "/%s=", field_name);
		ASN1_STRING_print_ex(membuf, v,
							 ((ASN1_STRFLGS_RFC2253 & ~ASN1_STRFLGS_ESC_MSB)
							  | ASN1_STRFLGS_UTF8_CONVERT));
	}

	/* ensure null termination of the BIO's content */
	nullterm = '\0';
	BIO_write(membuf, &nullterm, 1);
	size = BIO_get_mem_data(membuf, &sp);
	dp = (char *) pg_do_encoding_conversion((unsigned char *) sp,
											size - 1,
											PG_UTF8,
											GetDatabaseEncoding());
	result = cstring_to_text(dp);
	if (dp != sp)
		pfree(dp);
	BIO_free(membuf);

	PG_RETURN_TEXT_P(result);
}


/*
 * Returns current client certificate subject as one string
 *
 * This function returns distinguished name (subject) of the client
 * certificate used in the current SSL connection, converting it into
 * the current database encoding.
 *
 * Returns text datum.
 */
PG_FUNCTION_INFO_V1(ssl_client_dn);
Datum
ssl_client_dn(PG_FUNCTION_ARGS)
{
	if (!(MyProcPort->peer))
		PG_RETURN_NULL();
	return X509_NAME_to_text(X509_get_subject_name(MyProcPort->peer));
}


/*
 * Returns current client certificate issuer as one string
 *
 * This function returns issuer's distinguished name of the client
 * certificate used in the current SSL connection, converting it into
 * the current database encoding.
 *
 * Returns text datum.
 */
PG_FUNCTION_INFO_V1(ssl_issuer_dn);
Datum
ssl_issuer_dn(PG_FUNCTION_ARGS)
{
	if (!(MyProcPort->peer))
		PG_RETURN_NULL();
	return X509_NAME_to_text(X509_get_issuer_name(MyProcPort->peer));
}


/*
 * Returns extension object by given certificate and it's name.
 * 
 * Returns X509_EXTENSION* or NULL, if extension is not found in certificate.
 */
X509_EXTENSION *get_extension(X509* cert, char *name) {
	int 	nid;
	int 	loc;
	
	nid = OBJ_txt2nid(name);
	if (nid == NID_undef) 
		return NULL;
	
	loc = X509_get_ext_by_NID(cert, nid, -1);
	return X509_get_ext(cert, loc);
}


/* Returns value of extension. 
 * 
 * This function returns value of extension by given name in client certificate. 
 * 
 * Returns text datum. 
 */
PG_FUNCTION_INFO_V1(ssl_extension_value);
Datum
ssl_extension_value(PG_FUNCTION_ARGS) {
	X509 			*cert = MyProcPort->peer;
	X509_EXTENSION 	*ext = NULL;
	char 			*ext_name = text_to_cstring(PG_GETARG_TEXT_P(0));
	BIO 			*membuf = NULL;
	char 			*val = NULL;
	char 			nullterm = '\0';
	text 			*result = NULL;

	if (cert == NULL)
		PG_RETURN_NULL();
	
	if (OBJ_txt2nid(ext_name) == NID_undef)
		elog(ERROR, "Unknown extension name \"%s\"", ext_name);
	
	ext = get_extension(cert, ext_name);
	if (ext == NULL) 
		PG_RETURN_NULL();

	membuf = BIO_new(BIO_s_mem());
	X509V3_EXT_print(membuf, ext, -1, -1);
	BIO_write(membuf, &nullterm, 1);
	BIO_get_mem_data(membuf, &val);

	result = cstring_to_text(val);
	BIO_free(membuf);

	PG_RETURN_TEXT_P(result);
}


/* Returns status of extension 
 * 
 * Returns true, if extension is critical and false, if it is not.
 * 
 * Returns bool datum
 */
PG_FUNCTION_INFO_V1(ssl_extension_is_critical);
Datum
ssl_extension_is_critical(PG_FUNCTION_ARGS) {
	X509 			*cert = MyProcPort->peer;
	X509_EXTENSION 	*ext = NULL;
	char 			*ext_name = text_to_cstring(PG_GETARG_TEXT_P(0));
	int 			critical;
	
	if (cert == NULL)
		PG_RETURN_NULL();
	
	if (OBJ_txt2nid(ext_name) == NID_undef)
		elog(ERROR, "Unknown extension name \"%s\"", ext_name);
	
	ext = get_extension(cert, ext_name);
	if (ext == NULL) 
		PG_RETURN_NULL();
	
	critical = X509_EXTENSION_get_critical(ext);
		
	PG_RETURN_BOOL(critical);
}


/* Returns short names of extensions in client certificate
 * 
 * Returns setof text datum
 */
PG_FUNCTION_INFO_V1(ssl_extension_names);
Datum
ssl_extension_names(PG_FUNCTION_ARGS) {
	X509						*cert = MyProcPort->peer;
	FuncCallContext 			*funcctx;
	STACK_OF(X509_EXTENSION) 	*ext_stack = NULL;
	int 						call;
	int 						max_calls;
	TupleDesc					tupdesc;
	AttInMetadata				*attinmeta;
	MemoryContext 				oldcontext;
	char			 			**values;
	HeapTuple    				tuple;
	int 						nid;
	X509_EXTENSION				*ext = NULL;
	ASN1_OBJECT					*obj = NULL;
	BIO 						*membuf = NULL;
	char 						nullterm = '\0';
	
	if (cert == NULL)
		PG_RETURN_NULL();
	
	ext_stack = cert->cert_info->extensions;
	if (ext_stack == NULL) 
		PG_RETURN_NULL();
	
	if (SRF_IS_FIRSTCALL()) {
		funcctx = SRF_FIRSTCALL_INIT();
		oldcontext = MemoryContextSwitchTo(funcctx->multi_call_memory_ctx);
		funcctx->max_calls = X509_get_ext_count(cert);
		
		if (get_call_result_type(fcinfo, NULL, &tupdesc) != TYPEFUNC_COMPOSITE)
			ereport(ERROR,
					(errcode(ERRCODE_FEATURE_NOT_SUPPORTED),
					errmsg("function returning record called in context "
						"that cannot accept type record")));

		attinmeta = TupleDescGetAttInMetadata(tupdesc);
		funcctx->attinmeta = attinmeta;
		
		MemoryContextSwitchTo(oldcontext);
	}
	
	funcctx = SRF_PERCALL_SETUP();
	call = funcctx->call_cntr;
    max_calls = funcctx->max_calls;
    attinmeta = funcctx->attinmeta;
	
	if (call < max_calls) {
		values = (char **) palloc(2 * sizeof(char *));
		
		ext = sk_X509_EXTENSION_value(ext_stack, call);
		obj = X509_EXTENSION_get_object(ext);
		nid = OBJ_obj2nid(obj);
	    
		if (nid == NID_undef)
			elog(ERROR, "Unknown extension in certificate");
	    
		values[0] = (char *) OBJ_nid2sn(nid);
		
		membuf = BIO_new(BIO_s_mem());
		X509V3_EXT_print(membuf, ext, -1, -1);
		BIO_write(membuf, &nullterm, 1);
		BIO_get_mem_data(membuf, &values[1]);
				
		tuple = BuildTupleFromCStrings(attinmeta, values);
		
		BIO_free(membuf);
	    
 		SRF_RETURN_NEXT(funcctx, HeapTupleGetDatum(tuple));
	}
	SRF_RETURN_DONE(funcctx);
}

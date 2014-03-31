
#include "postgres.h"
#include "fmgr.h"
#include "utils/numeric.h"
#include "libpq/libpq-be.h"
#include "miscadmin.h"
#include "utils/builtins.h"
#include "mb/pg_wchar.h"

#include <openssl/x509.h>
#include <openssl/asn1.h>


PG_MODULE_MAGIC;

Datum ssl_get_extension_by_name(PG_FUNCTION_ARGS);


PG_FUNCTION_INFO_V1(ssl_get_extension_by_name);
Datum
ssl_get_extension_by_name(PG_FUNCTION_ARGS)
{
	char	   *extension_name;
	
	extension_name = text_to_cstring(PG_GETARG_TEXT_P(0));
	elog(WARNING, "extension_name %s", extension_name);
	
	if (!(MyProcPort->peer))
		PG_RETURN_NULL();
	
	PG_RETURN_TEXT_P(PG_GETARG_TEXT_P(0));
}

CREATE OR REPLACE FUNCTION ssl_get_extension_value(text) RETURNS text
AS 'MODULE_PATHNAME', 'ssl_get_extension_value'
LANGUAGE C STRICT;

CREATE OR REPLACE FUNCTION ssl_is_critical_extension(text) RETURNS boolean
AS 'MODULE_PATHNAME', 'ssl_is_critical_extension'
LANGUAGE C STRICT;

CREATE OR REPLACE FUNCTION ssl_get_count_of_extensions() RETURNS integer
AS 'MODULE_PATHNAME', 'ssl_get_count_of_extensions'
LANGUAGE C STRICT;

CREATE OR REPLACE FUNCTION ssl_get_extension_names() RETURNS SETOF text 
AS 'MODULE_PATHNAME', 'ssl_get_extension_names'
LANGUAGE C STRICT;
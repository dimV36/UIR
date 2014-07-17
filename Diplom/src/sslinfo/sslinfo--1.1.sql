/* contrib/sslinfo/sslinfo--1.1.sql */

-- complain if script is sourced in psql, rather than via CREATE EXTENSION
\echo Use "CREATE EXTENSION sslinfo" to load this file. \quit

CREATE FUNCTION ssl_client_serial() RETURNS numeric
AS 'MODULE_PATHNAME', 'ssl_client_serial'
LANGUAGE C STRICT;

CREATE FUNCTION ssl_is_used() RETURNS boolean
AS 'MODULE_PATHNAME', 'ssl_is_used'
LANGUAGE C STRICT;

CREATE FUNCTION ssl_version() RETURNS text
AS 'MODULE_PATHNAME', 'ssl_version'
LANGUAGE C STRICT;

CREATE FUNCTION ssl_cipher() RETURNS text
AS 'MODULE_PATHNAME', 'ssl_cipher'
LANGUAGE C STRICT;

CREATE FUNCTION ssl_client_cert_present() RETURNS boolean
AS 'MODULE_PATHNAME', 'ssl_client_cert_present'
LANGUAGE C STRICT;

CREATE FUNCTION ssl_client_dn_field(text) RETURNS text
AS 'MODULE_PATHNAME', 'ssl_client_dn_field'
LANGUAGE C STRICT;

CREATE FUNCTION ssl_issuer_field(text) RETURNS text
AS 'MODULE_PATHNAME', 'ssl_issuer_field'
LANGUAGE C STRICT;

CREATE FUNCTION ssl_client_dn() RETURNS text
AS 'MODULE_PATHNAME', 'ssl_client_dn'
LANGUAGE C STRICT;

CREATE FUNCTION ssl_issuer_dn() RETURNS text
AS 'MODULE_PATHNAME', 'ssl_issuer_dn'
LANGUAGE C STRICT;

/* new in 1.1 */
CREATE OR REPLACE FUNCTION ssl_extension_value(text) RETURNS text
AS 'MODULE_PATHNAME', 'ssl_extension_value'
LANGUAGE C STRICT;

CREATE OR REPLACE FUNCTION ssl_extension_is_critical(text) RETURNS boolean
AS 'MODULE_PATHNAME', 'ssl_extension_is_critical'
LANGUAGE C STRICT;

CREATE TYPE extension AS (
    name text,
    value text
);

CREATE OR REPLACE FUNCTION ssl_extension_names() RETURNS SETOF extension 
AS 'MODULE_PATHNAME', 'ssl_extension_names'
LANGUAGE C STRICT;

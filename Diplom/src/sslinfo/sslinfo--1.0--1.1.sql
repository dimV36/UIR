/* contrib/sslinfo/sslinfo--1.0--1.1.sql */

-- complain if script is sourced in psql, rather than via CREATE EXTENSION
\echo Use "ALTER EXTENSION sslinfo UPDATE TO '1.1'" to load this file. \quit

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

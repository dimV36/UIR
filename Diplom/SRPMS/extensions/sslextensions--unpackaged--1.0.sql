/* contrib/sslextensions/sslextensions--unpackaged--1.0.sql */

-- complain if script is sourced in psql, rather than via CREATE EXTENSION
\echo Use "CREATE EXTENSION sslextensions" to load this file. \quit

ALTER EXTENSION sslextensions ADD function ssl_get_extension_by_name(text);
ALTER EXTENSION sslextensions ADD function ssl_is_critical_extension(text);
ALTER EXTENSION sslextensions ADD function ssl_get_extensions_count();

@echo off
rem Edit this variable to point to
rem the openssl.cnf file included
rem with easy-rsa.  Don't begin
rem the HOME string with a drive
rem letter.

set HOME=%ProgramFiles%\OpenVPN
set KEY_CONFIG=openssl.cnf

rem Edit this variable to point to
rem your soon-to-be-created key
rem directory.
rem
rem WARNING: clean-all will do
rem a rm -rf on this directory
rem so make sure you define
rem it correctly!
set KEY_DIR=keys

rem Increase this to 2048 if you
rem are paranoid.  If you do increase,
rem make sure you build OpenVPN with
rem pthread support, so you don't incur
rem any performance penalty.
set KEY_SIZE=1024

rem These are the default values for fields
rem which will be placed in the certificate.
rem Change these to reflect your site.
rem Don't leave any of these parms blank.

set KEY_COUNTRY=US
set KEY_PROVINCE=CA
set KEY_CITY=SanFrancisco
set KEY_ORG=FortFunston
set KEY_EMAIL=mail@host.domain

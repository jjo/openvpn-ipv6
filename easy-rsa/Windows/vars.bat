@echo off
rem Edit this variable to point to
rem the openssl.cnf file included
rem with easy-rsa.
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
set KEY_DIR=my-openvpn-keys

rem Increase this to 2048 if you
rem are paranoid.  If you do increase,
rem make sure you build OpenVPN with
rem pthread support, so you don't incur
rem any performance penalty.
set KEY_SIZE=1024

rem These are the default values for fields
rem which will be placed in the certificate.
set KEY_COUNTRY=
set KEY_PROVINCE=
set KEY_CITY=
set KEY_ORG=
set KEY_EMAIL=

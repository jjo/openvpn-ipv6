#
# Build the OpenVPN auth-pam plugin module.
#

# This directory is where we will look for openvpn-plugin.h
INCLUDE=-I../..

CC_FLAGS=-O2 -Wall

openvpn-auth-pam.so : auth-pam.o pamdl.o
	gcc ${CC_FLAGS} -fPIC -shared -Wl,-soname,openvpn-auth-pam.so -o openvpn-auth-pam.so auth-pam.o pamdl.o -lc

auth-pam.o : auth-pam.c pamdl.h
	gcc ${CC_FLAGS} -fPIC -c ${INCLUDE} auth-pam.c

pamdl.o : pamdl.c pamdl.h
	gcc ${CC_FLAGS} -fPIC -c ${INCLUDE} pamdl.c

clean :
	rm -f *.o *.so

dnl AC_CHECK_INET_TYPE(TYPE, DEFAULT)
AC_DEFUN(AC_CHECK_INET_TYPE, [
AC_CHECK_HEADERS(sys/socket.h netinet/in.h arpa/inet.h)            
AC_MSG_CHECKING(for $1)
AC_CACHE_VAL(ac_cit_type_$1,
[AC_EGREP_CPP(dnl
changequote(<<,>>)dnl
<<(^|[^a-zA-Z_0-9])$1[^a-zA-Z_0-9]>>dnl
changequote([,]), [
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
], ac_cit_type_$1=yes, ac_cit_type_$1=no)])dnl               
AC_MSG_RESULT($ac_cit_type_$1)
if test $ac_cit_type_$1 = no; then
AC_DEFINE($1, $2) 
fi
])

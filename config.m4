dnl $Id$
dnl config.m4 for extension phttpclient

dnl Comments in this file start with the string 'dnl'.
dnl Remove where necessary. This file will not work
dnl without editing.

dnl If your extension references something external, use with:

PHP_ARG_WITH(phttpclient, for phttpclient support,
Make sure that the comment is aligned:
[  --with-phttpclient             Include phttpclient support])

dnl Otherwise use enable:

dnl PHP_ARG_ENABLE(phttpclient, whether to enable phttpclient support,
dnl Make sure that the comment is aligned:
dnl [  --enable-phttpclient           Enable phttpclient support])

if test "$PHP_PHTTPCLIENT" != "no"; then
  dnl Write more examples of tests here...

  dnl # --with-phttpclient -> check with-path
  dnl SEARCH_PATH="/usr/local /usr"     # you might want to change this
  dnl SEARCH_FOR="/include/phttpclient.h"  # you most likely want to change this
  dnl if test -r $PHP_PHTTPCLIENT/$SEARCH_FOR; then # path given as parameter
  dnl   PHTTPCLIENT_DIR=$PHP_PHTTPCLIENT
  dnl else # search default path list
  dnl   AC_MSG_CHECKING([for phttpclient files in default path])
  dnl   for i in $SEARCH_PATH ; do
  dnl     if test -r $i/$SEARCH_FOR; then
  dnl       PHTTPCLIENT_DIR=$i
  dnl       AC_MSG_RESULT(found in $i)
  dnl     fi
  dnl   done
  dnl fi
  dnl
  dnl if test -z "$PHTTPCLIENT_DIR"; then
  dnl   AC_MSG_RESULT([not found])
  dnl   AC_MSG_ERROR([Please reinstall the phttpclient distribution])
  dnl fi

  dnl # --with-phttpclient -> add include path
  dnl PHP_ADD_INCLUDE($PHTTPCLIENT_DIR/include)

  dnl # --with-phttpclient -> check for lib and symbol presence
  dnl LIBNAME=phttpclient # you may want to change this
  dnl LIBSYMBOL=phttpclient # you most likely want to change this 

  dnl PHP_CHECK_LIBRARY($LIBNAME,$LIBSYMBOL,
  dnl [
  dnl   PHP_ADD_LIBRARY_WITH_PATH($LIBNAME, $PHTTPCLIENT_DIR/lib, PHTTPCLIENT_SHARED_LIBADD)
  dnl   AC_DEFINE(HAVE_PHTTPCLIENTLIB,1,[ ])
  dnl ],[
  dnl   AC_MSG_ERROR([wrong phttpclient lib version or lib not found])
  dnl ],[
  dnl   -L$PHTTPCLIENT_DIR/lib -lm
  dnl ])
  dnl
  dnl PHP_SUBST(PHTTPCLIENT_SHARED_LIBADD)

  PHP_NEW_EXTENSION(phttpclient, phttpclient.c thirdparty/php_http_parser.c, $ext_shared)
fi

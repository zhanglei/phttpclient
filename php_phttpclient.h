/*
  +----------------------------------------------------------------------+
  | PHP Version 5                                                        |
  +----------------------------------------------------------------------+
  | Copyright (c) 1997-2014 The PHP Group                                |
  +----------------------------------------------------------------------+
  | This source file is subject to version 3.01 of the PHP license,      |
  | that is bundled with this package in the file LICENSE, and is        |
  | available through the world-wide-web at the following url:           |
  | http://www.php.net/license/3_01.txt                                  |
  | If you did not receive a copy of the PHP license and are unable to   |
  | obtain it through the world-wide-web, please send a note to          |
  | license@php.net so we can mail you a copy immediately.               |
  +----------------------------------------------------------------------+
  | Author:                                                              |
  +----------------------------------------------------------------------+
*/

/* $Id$ */

#ifndef PHP_PHTTPCLIENT_H
#define PHP_PHTTPCLIENT_H

extern zend_module_entry phttpclient_module_entry;
#define phpext_phttpclient_ptr &phttpclient_module_entry

#define PHP_PHTTPCLIENT_VERSION "0.1.0" /* Replace with version number for your extension */

#ifdef PHP_WIN32
#	define PHP_PHTTPCLIENT_API __declspec(dllexport)
#elif defined(__GNUC__) && __GNUC__ >= 4
#	define PHP_PHTTPCLIENT_API __attribute__ ((visibility("default")))
#else
#	define PHP_PHTTPCLIENT_API
#endif

#ifdef ZTS
#include "TSRM.h"
#endif


#define ERROR_PARSE_ERROR		100001


#ifndef PHP_WIN32
#define php_select(m, r, w, e, t)	select(m, r, w, e, t)
typedef unsigned long long php_timeout_ull;
#else
#include "win32/select.h"
#include "win32/sockets.h"
typedef unsigned __int64 php_timeout_ull;
#endif

#define phttpclient_array_get_value(ht, str, v)     (zend_hash_find(ht, str, sizeof(str), (void **) &v) == SUCCESS && !ZVAL_IS_NULL(*v))

#include "thirdparty/php_http_parser.h"


PHP_MINIT_FUNCTION(phttpclient);
PHP_MSHUTDOWN_FUNCTION(phttpclient);
PHP_MINFO_FUNCTION(phttpclient);

PHP_FUNCTION(phttp_get);



#ifdef ZTS
#define PHTTPCLIENT_G(v) TSRMG(phttpclient_globals_id, zend_phttpclient_globals *, v)
#else
#define PHTTPCLIENT_G(v) (phttpclient_globals.v)
#endif

#endif	/* PHP_PHTTPCLIENT_H */

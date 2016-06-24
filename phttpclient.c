/*
  +----------------------------------------------------------------------+
  | phttpclient.c   ver 1.0                                              |
  +----------------------------------------------------------------------+
  | This source file is subject to version 2.0 of the Apache license,    |
  | that is bundled with this package in the file LICENSE, and is        |
  | available through the world-wide-web at the following url:           |
  | http://www.apache.org/licenses/LICENSE-2.0.html                      |
  | If you did not receive a copy of the Apache2.0 license and are unable|
  | to obtain it through the world-wide-web, please send a note to       |
  | license@swoole.com so we can mail you a copy immediately.            |
  +----------------------------------------------------------------------+
  | Author: Fang  <coooold@live.com>                                     |
  | Date:   2016-06-24                                                   |
  +----------------------------------------------------------------------+
*/

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "php.h"
#include "php_ini.h"
#include "ext/standard/info.h"
#include "php_phttpclient.h"

#include "ext/standard/basic_functions.h"
#include "ext/standard/php_http.h"
#include "ext/standard/base64.h"
#include "ext/standard/url.h"


static int le_phttpclient;


const zend_function_entry phttpclient_functions[] = {
	PHP_FE(phttp_get,	NULL)
	PHP_FE_END
};

zend_module_entry phttpclient_module_entry = {
#if ZEND_MODULE_API_NO >= 20010901
	STANDARD_MODULE_HEADER,
#endif
	"phttpclient",
	phttpclient_functions,
	PHP_MINIT(phttpclient),
	PHP_MSHUTDOWN(phttpclient),
	NULL,
	NULL,
	PHP_MINFO(phttpclient),
#if ZEND_MODULE_API_NO >= 20010901
	PHP_PHTTPCLIENT_VERSION,
#endif
	STANDARD_MODULE_PROPERTIES
};


#ifdef COMPILE_DL_PHTTPCLIENT
ZEND_GET_MODULE(phttpclient)
#endif


typedef struct {
	php_url *url_info;

	//configuration
	zval *zheaders;
	double timeout;
	char *method;
	int method_len;
	zval *zdata;
	char *proxy;
	int proxy_len;
	
	//temp
	char *tmp_header_field_name;
    size_t tmp_header_field_name_len;

    php_http_parser parser;

	//response
	zval *response_zheaders;
	smart_str response_sbody;
	
	//is http parse completed
	int complete;
	
	//error
	int err_code;
	char *err_msg;
	
} phttpclient_ctx_t;

static int phttpclient_parser_on_header_field(php_http_parser *parser, const char *at, size_t length);
static int phttpclient_parser_on_header_value(php_http_parser *parser, const char *at, size_t length);
static int phttpclient_parser_on_body(php_http_parser *parser, const char *at, size_t length);
static int phttpclient_parser_on_message_complete(php_http_parser *parser);

static phttpclient_ctx_t* phttpclient_read_ctx(zval *zctx);
static php_stream* phttpclient_create_stream(char *hashkey, int hashkey_len, char *host, int host_len, double timeout, int *err_code TSRMLS_DC);
static php_stream* phttpclient_get_stream(char *host, int host_len, phttpclient_ctx_t *ctx TSRMLS_DC);
static void phphttpclient_build_http_request_host(smart_str *s, char *host, int host_len, phttpclient_ctx_t *ctx);
static void phphttpclient_build_http_request_headers(smart_str *s, phttpclient_ctx_t *ctx);
static void phphttpclient_build_http_request_post(smart_str *s, phttpclient_ctx_t *ctx TSRMLS_DC);
static void phphttpclient_build_http_request_ending(smart_str *s, phttpclient_ctx_t *ctx TSRMLS_DC);
static smart_str phphttpclient_build_http_request(char *host, int host_len, phttpclient_ctx_t *ctx TSRMLS_DC);
static void phttpclient_get_contents(zval *zresponse, char *host, int host_len, php_stream *stream, phttpclient_ctx_t *ctx  TSRMLS_DC);

static const php_http_parser_settings http_parser_settings =
{
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    phttpclient_parser_on_header_field,
    phttpclient_parser_on_header_value,
    NULL,
    phttpclient_parser_on_body,
    phttpclient_parser_on_message_complete
};


#if PHP_MAJOR_VERSION < 7
static inline char* phttpclient_http_build_query(zval *data, size_t *length, smart_str *formstr TSRMLS_DC)
{
#if PHP_MAJOR_VERSION == 5 && PHP_MINOR_VERSION == 3
    if (php_url_encode_hash_ex(HASH_OF(data), formstr, NULL, 0, NULL, 0, NULL, 0, NULL, NULL TSRMLS_CC) == FAILURE)
#else
    if (php_url_encode_hash_ex(HASH_OF(data), formstr, NULL, 0, NULL, 0, NULL, 0, NULL, NULL, (int) PHP_QUERY_RFC1738 TSRMLS_CC) == FAILURE)
#endif
    {
        if (formstr->c)
        {
            smart_str_free(formstr);
        }
        return NULL;
    }
    if (!formstr->c)
    {
        return NULL;
    }
    smart_str_0(formstr);
    *length = formstr->len;
    return formstr->c;
}
#else
static inline char* phttpclient_http_build_query(zval *data, size_t *length, smart_str *formstr TSRMLS_DC)
{
    if (php_url_encode_hash_ex(HASH_OF(data), formstr, NULL, 0, NULL, 0, NULL, 0, NULL, NULL, (int) PHP_QUERY_RFC1738) == FAILURE)
    {
        if (formstr->s)
        {
            smart_str_free(formstr);
        }
        return NULL;
    }
    if (!formstr->s)
    {
        return NULL;
    }
    smart_str_0(formstr);
    *length = formstr->s->len;
    return formstr->s->val;
}
#endif


/****************** PHP functions **********************/

PHP_MINIT_FUNCTION(phttpclient)
{
	return SUCCESS;
}

PHP_MSHUTDOWN_FUNCTION(phttpclient)
{
    return SUCCESS;
}

PHP_MINFO_FUNCTION(phttpclient)
{
	php_info_print_table_start();
	php_info_print_table_header(2, "phttpclient support", "enabled");
	php_info_print_table_end();

}

PHP_FUNCTION(phttp_get)
{
	char *url = NULL; int url_len;
	char *host = NULL; int host_len = 0;
	zval *zctx = NULL;
	
	zval *zresponse = NULL;
	MAKE_STD_ZVAL(zresponse);
	array_init(zresponse);

	phttpclient_ctx_t *ctx = NULL;
	php_stream *stream = NULL;
	
	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "s|a", &url, &url_len, &zctx) == FAILURE) {
        return;
    }

	ctx = phttpclient_read_ctx(zctx);
	
	ctx->url_info = php_url_parse_ex(url, url_len);
	if (ctx->url_info == NULL) {
		RETURN_FALSE;
	}

	if(ctx->url_info->port == 0) {
		ctx->url_info->port = 80;
	}
	
	host_len = spprintf(&host, 0, "%s:%d", ctx->url_info->host, ctx->url_info->port);
	
	if (ctx->proxy == NULL) {
		stream = phttpclient_get_stream(host, host_len, ctx TSRMLS_CC);
	} else {
		stream = phttpclient_get_stream(ctx->proxy, ctx->proxy_len, ctx TSRMLS_CC);
	}
	
	
	if (stream) {
		phttpclient_get_contents (zresponse, host, host_len, stream, ctx TSRMLS_CC);
	}
	
	add_assoc_long_ex(zresponse, ZEND_STRS("error_code"), ctx->err_code);
	
	if(host) {
		efree(host);
	}
	if(ctx){
		php_url_free(ctx->url_info);
		smart_str_free(&ctx->response_sbody);
		
		if(ctx->err_msg) {
			efree(ctx->err_msg);
		}
		efree(ctx);
	}
	
	RETURN_ZVAL(zresponse, 0, 1);
}






/****************** internal functions **********************/


static int phttpclient_parser_on_header_field(php_http_parser *parser, const char *at, size_t length)
{
    phttpclient_ctx_t* ctx = (phttpclient_ctx_t*)parser->data;

    ctx->tmp_header_field_name = estrndup(at, length);
    ctx->tmp_header_field_name_len = length;
    return 0;
}

static int phttpclient_parser_on_header_value(php_http_parser *parser, const char *at, size_t length)
{
    phttpclient_ctx_t* ctx = (phttpclient_ctx_t*)parser->data;

	add_assoc_stringl_ex(ctx->response_zheaders, ctx->tmp_header_field_name, ctx->tmp_header_field_name_len + 1, (char*)at, (uint)length, 1);

	if(ctx->tmp_header_field_name) {
		efree(ctx->tmp_header_field_name);
		ctx->tmp_header_field_name = NULL;
		ctx->tmp_header_field_name_len = 0;
	}
    return 0;
}

static int phttpclient_parser_on_body(php_http_parser *parser, const char *at, size_t length)
{
    phttpclient_ctx_t* ctx = (phttpclient_ctx_t*)parser->data;
	smart_str_appendl(&ctx->response_sbody, at, length);

    return 0;
}

static int phttpclient_parser_on_message_complete(php_http_parser *parser)
{
	phttpclient_ctx_t* ctx = (phttpclient_ctx_t*)parser->data;
	ctx->complete = 1;
	if(ctx->tmp_header_field_name) {
		efree(ctx->tmp_header_field_name);
		ctx->tmp_header_field_name = NULL;
		ctx->tmp_header_field_name_len = 0;
	}
	smart_str_0(&ctx->response_sbody);
    return 0;
}

/* load configurations */
static phttpclient_ctx_t* phttpclient_read_ctx(zval *zctx) {
	phttpclient_ctx_t *ctx;
	ctx = (phttpclient_ctx_t*)emalloc(sizeof(phttpclient_ctx_t));
	bzero(ctx, sizeof(phttpclient_ctx_t));
	
	ctx->timeout = 1.0;
	ctx->method = "GET";
	ctx->method_len = 3;
	
	if (zctx && Z_TYPE_P(zctx) == IS_ARRAY) {
		zval **ztmp;
		HashTable *vht;
		
		vht = Z_ARRVAL_P(zctx);
		
		if(phttpclient_array_get_value(vht, "headers", ztmp)) {
			ctx->zheaders = *ztmp;
		}
		
		if(phttpclient_array_get_value(vht, "timeout", ztmp)) {
			convert_to_double(*ztmp);
            ctx->timeout = (double) Z_DVAL_PP(ztmp);
		}
		
		if(phttpclient_array_get_value(vht, "data", ztmp)) {
			ctx->zdata = *ztmp;
			ctx->method = "POST";
			ctx->method_len = 4;
		}
		
		if(phttpclient_array_get_value(vht, "method", ztmp)) {
			convert_to_string(*ztmp);
            ctx->method = Z_STRVAL_PP(ztmp);
			ctx->method_len = Z_STRLEN_PP(ztmp);
		}
		
		if(phttpclient_array_get_value(vht, "proxy", ztmp)) {
			convert_to_string(*ztmp);
            ctx->proxy = Z_STRVAL_PP(ztmp);
			ctx->proxy_len = Z_STRLEN_PP(ztmp);
		} else {
			ctx->proxy = NULL;
		}
	}
	
	return ctx;
}

/* create new persistant php stream */
static php_stream* phttpclient_create_stream(char *hashkey, int hashkey_len, char *host, int host_len, double timeout, int *err_code TSRMLS_DC) {
	zval *zcontext = NULL;
	php_timeout_ull conv;
	struct timeval tv;
	php_stream *stream = NULL;
	php_stream_context *context = NULL;
	char *err_msg = NULL;
	
	unsigned int streams_flags = STREAM_XPORT_CLIENT | STREAM_XPORT_CONNECT;
	
	conv = (php_timeout_ull) (timeout * 1000000.0);
#ifdef PHP_WIN32
	tv.tv_sec = (long)(conv / 1000000);
	tv.tv_usec =(long)(conv % 1000000);
#else
	tv.tv_sec = conv / 1000000;
	tv.tv_usec = conv % 1000000;
#endif

	
	stream = php_stream_xport_create(host, host_len, REPORT_ERRORS,
		streams_flags ,
		hashkey, &tv, NULL, &err_msg, err_code);
		
	if(err_msg) {
		efree(err_msg);
	}

	
	
	if (stream != NULL && hashkey) {
		//set read & write timeouts
		php_stream_set_option(stream, PHP_STREAM_OPTION_READ_TIMEOUT, 0, &tv);

	}
	
	return stream;
}

/* get persistant php stream from phttpclient_connection_pool_ht */
static php_stream* phttpclient_get_stream(char *host, int host_len, phttpclient_ctx_t *ctx TSRMLS_DC) {
	php_stream *stream = NULL;
	php_stream **stream_p = NULL;
	char *hashkey = NULL;
	int hashkey_len = 0;
	
	hashkey_len = spprintf(&hashkey, 0, "phttp_client__%s", host);
	
	stream = phttpclient_create_stream(hashkey, hashkey_len, host, host_len, ctx->timeout, &ctx->err_code TSRMLS_CC);
	
	if (hashkey) {
		efree(hashkey);
	}
	
	return stream;
}

static void phphttpclient_build_http_request_host(smart_str *s, char *host, int host_len, phttpclient_ctx_t *ctx) {
	int is_host_set = 0;
	
	if (ctx->zheaders && Z_TYPE_P(ctx->zheaders) == IS_ARRAY) {
		zval **ztmp;
		HashTable *vht;
		vht = Z_ARRVAL_P(ctx->zheaders);
		
		if(phttpclient_array_get_value(vht, "Host", ztmp)) {
			convert_to_string(*ztmp);
			smart_str_appends(s, "Host:");
			smart_str_appendl(s, Z_STRVAL_P(*ztmp), Z_STRLEN_P(*ztmp));
			smart_str_appends(s, "\r\n");
			is_host_set = 1;
		}
	}

	if (!is_host_set) {
		smart_str_appends(s, "Host:");
		if(ctx->url_info->port == 80){
			smart_str_appends(s, ctx->url_info->host);
		} else {
			smart_str_appendl(s, host, host_len);
		}

		smart_str_appends(s, "\r\n");
	}
}

static void phphttpclient_build_http_request_headers(smart_str *s, phttpclient_ctx_t *ctx) {
	if (ctx->zheaders && Z_TYPE_P(ctx->zheaders) == IS_ARRAY) {
		zval **ztmp;
		HashTable *vht;
		vht = Z_ARRVAL_P(ctx->zheaders);

		for(
			zend_hash_internal_pointer_reset(vht);
			zend_hash_has_more_elements(vht) == SUCCESS;
			zend_hash_move_forward(vht)) {
		
			char *key;
			uint keylen;
			ulong idx;
			int type;
			zval **ppzval;
			
			type = zend_hash_get_current_key_ex(vht, &key, &keylen,&idx, 0, NULL);
			if (zend_hash_get_current_data(vht, (void**)&ppzval) == FAILURE) {
				continue;
			}
			
			//host is processed in phphttpclient_build_http_request_host
			if(strncmp(key, "Host", keylen) == 0) {
				continue;
			}
			
			convert_to_string(*ppzval);
			smart_str_appendl(s, key, keylen-1);
			smart_str_appends(s, ":");
			smart_str_appendl(s, Z_STRVAL_PP(ppzval), Z_STRLEN_PP(ppzval));
			smart_str_appends(s, "\r\n");
		}
	}
}

static void phphttpclient_build_http_request_post(smart_str *s, phttpclient_ctx_t *ctx TSRMLS_DC) {
	if(!ctx->zdata){
		return;
	}
	
	if (Z_TYPE_P(ctx->zdata) == IS_ARRAY) {
		size_t len;
		smart_str formstr_s = { 0 };
		char *formstr = phttpclient_http_build_query(ctx->zdata, &len, &formstr_s TSRMLS_CC);
		if (formstr != NULL) {
			smart_str_appends(s, "Content-Type:application/x-www-form-urlencoded\r\n");
			smart_str_appends(s, "Content-Length:");
			smart_str_append_long(s, len);
			smart_str_appends(s, "\r\n\r\n");
			smart_str_appendl(s, formstr, len);
		}
		smart_str_free(&formstr_s);
	} else {
		smart_str_appends(s, "Content-Length:");
		smart_str_append_long(s, Z_STRLEN_P(ctx->zdata));
		smart_str_appends(s, "\r\n\r\n");
		smart_str_appendl(s, Z_STRVAL_P(ctx->zdata), Z_STRLEN_P(ctx->zdata));
	}
}

static void phphttpclient_build_http_request_ending(smart_str *s, phttpclient_ctx_t *ctx TSRMLS_DC) {
	//post did itself\r\n
	if(strncmp(ctx->method, "POST", 4) == 0) {
		return;
	}
	
	smart_str_appends(s, "\r\n");
}

/* build an http request, which should be released later */
static smart_str phphttpclient_build_http_request(char *host, int host_len, phttpclient_ctx_t *ctx TSRMLS_DC) {
	smart_str request_body={0};
	
	//first line
	smart_str_appendl(&request_body, ctx->method, ctx->method_len);
	smart_str_appends(&request_body, " ");
	
	if(ctx->url_info->path != NULL) {
		smart_str_appends(&request_body, ctx->url_info->path);
	} else {
		smart_str_appends(&request_body, "/");
	}
	
	if(ctx->url_info->query != NULL) {
		smart_str_appends(&request_body, "?");
		smart_str_appends(&request_body, ctx->url_info->query);
	}
	smart_str_appends(&request_body, " HTTP/1.1\r\n");
	
	//headers
	smart_str_appends(&request_body, "Connection:keep-alive\r\n");
	phphttpclient_build_http_request_host(&request_body, host, host_len, ctx);
	phphttpclient_build_http_request_headers(&request_body, ctx);
	phphttpclient_build_http_request_post(&request_body, ctx TSRMLS_CC);
	
	//ending
	phphttpclient_build_http_request_ending(&request_body, ctx TSRMLS_CC);
	
	smart_str_0(&request_body);
	
	//printf("%s\n", request_body.c);
	
	return request_body;
}

/* send http requests and fetch the response */
static void phttpclient_get_contents(zval *zresponse, char *host, int host_len, php_stream *stream, phttpclient_ctx_t *ctx  TSRMLS_DC) {
	if(stream == NULL){
		return;
	}
	
	//有stream的时候才分配response_zheaders内存，避免内存泄露
	zval *zheaders = NULL;
	MAKE_STD_ZVAL(zheaders);
	array_init(zheaders);
	ctx->response_zheaders = zheaders;
		
	smart_str request_body = phphttpclient_build_http_request(host, host_len, ctx TSRMLS_CC);
	
	int ret;
	ret = php_stream_write(stream, request_body.c, request_body.len);
	smart_str_free(&request_body);

	php_http_parser_init(&ctx->parser, PHP_HTTP_RESPONSE);
    ctx->parser.data = ctx;

	int count = 0;
	char buff[16384];
	long parsed_n = 0;
	while(!php_stream_eof(stream)) {
		count = php_stream_read(stream, buff, 16384);
		
		/*
		  超时的情况下count = 0 \main\streams\xp_socket.c php_sockop_read
		  if (sock->timeout_event)
			  return 0;
		*/
		if(count == 0) {
			ctx->err_code = errno;
			php_stream_pclose(stream);
			break;
		}
		
		parsed_n = php_http_parser_execute(&ctx->parser, &http_parser_settings, buff, count);
        if (parsed_n < 0) {
			ctx->err_code = ERROR_PARSE_ERROR;
			php_stream_pclose(stream);
			break;
        }
		
		if(ctx->complete == 1) {
			break;
		}
	}
	
	zval *zbody;
	MAKE_STD_ZVAL(zbody);
	
	ZVAL_STRINGL(zbody, ctx->response_sbody.c, ctx->response_sbody.len, 1);
	
	add_assoc_zval_ex(zresponse, ZEND_STRS("headers"), ctx->response_zheaders);
	add_assoc_zval_ex(zresponse, ZEND_STRS("body"), zbody);
	add_assoc_long_ex(zresponse, ZEND_STRS("http_code"), ctx->parser.status_code);
}
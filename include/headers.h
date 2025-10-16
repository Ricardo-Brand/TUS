#ifndef _HEADERS_H_
#define _HEADERS_H_

#include "mongoose.h"
#include <stdbool.h>

static const char *OPTIONS_HEADERS =
	"Access-Control-Allow-Origin: *\r\n"
	"Access-Control-Allow-Credentials: true\r\n"
	"Access-Control-Allow-Methods: GET,POST,OPTIONS\r\n"
	"Access-Control-Allow-Headers: "
	"DNT,X-CustomHeader,Keep-Alive,User-Agent,X-Requested-With,If-Modified-"
	"Since,Cache-Control,Content-Type\r\n"
	"Access-Control-Max-Age: 1728000\r\n"
	"Content-Type: text/plain charset=UTF-8\r\n"
	"Cache-Control: no-store\r\n";

static const char *DEFAULT_HEADERS =
	"Access-Control-Allow-Origin: *\r\n"
	"Access-Control-Allow-Credentials: true\r\n"
	"Access-Control-Allow-Methods: GET,POST,OPTIONS\r\n"
	"Access-Control-Allow-Headers: "
	"DNT,X-CustomHeader,Keep-Alive,User-Agent,X-Requested-With,If-Modified-"
	"Since,Cache-Control,Content-Type\r\n"
    "Access-Control-Max-Age: 1728000\r\n"
    "Vary: Origin, Access-Control-Request-Method, Access-Control-Request-Headers\r\n"
    "Content-Type: application/json\r\n"
	"Cache-Control: no-store\r\n";

bool verify_headers_post(struct mg_http_message *hm,
		 char *hash, size_t hash_size, char *hash_type, size_t type_len,
		 size_t *up_len);

bool verify_headers_patch(struct mg_http_message *hm, char *hash, size_t hash_size);

bool get_tus_resumable(struct mg_http_message *hm, char *version, size_t version_len);

bool concat_header_post(char *headers, size_t headers_len, const char *header_name, const char *value);

#endif
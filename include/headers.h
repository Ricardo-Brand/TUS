#ifndef _HEADERS_H_
#define _HEADERS_H_

#include "mongoose.h"
#include <stdbool.h>


bool verify_post(struct mg_connection *c, struct mg_http_message *hm,
			 char *hash, size_t hash_size,
			 size_t *tus_upload_length);

bool get_tus_resumable(struct mg_http_message *hm, char *version, size_t version_len);

bool concat_header_post(char *headers, size_t headers_len, const char *header_name, const char *value);

#endif
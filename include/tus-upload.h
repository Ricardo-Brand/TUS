#ifndef _TUS_UPLOAD_H_
#define _TUS_UPLOAD_H_

#include "mongoose.h"
#include <stdbool.h>

typedef enum {
    HASH_SHA1 = 1,
    HASH_BLAKE3 = 2,
} HashType;

typedef struct ArrayTus{
	char url_image[256];
	size_t upload_length;
    size_t upload_offset;
	char hash[65];
    HashType hash_type;
    char date_time[65];
    bool occupied;
} ArrayTus;

void middlewares_tus_options(struct mg_connection *c);

void middlewares_tus_post(struct mg_connection *c, struct mg_http_message *hm, ArrayTus *tus_uploads, size_t num_uploads);

void middlewares_tus_patch(struct mg_connection *c,
			   struct mg_http_message *hm, ArrayTus *tus_uploads, size_t num_uploads);

#endif
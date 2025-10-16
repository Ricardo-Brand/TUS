#include "mongoose.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <time.h>
#include <jansson.h>
#include <openssl/evp.h>
#include <openssl/sha.h> /* SHA1 */
#include "blake3.h"

static const char *s_host = "http://localhost:8080";
static char s_url[2048] = { 0 };
static const char *s_post_data = NULL; // POST data
static char s_method[20] = { 0 };
static size_t s_post_data_len = 0;
static const uint64_t s_timeout_ms = 1500; // Connect timeout in milliseconds
static const char *s_headers = NULL;
static char s_token[80] = { 0 };
static struct mg_http_message *s_response = NULL;
static char s_checksum[65] = { 0 };

typedef enum {
	JSON_EXPECT_STRING,
	JSON_EXPECT_NUMBER,
	JSON_EXPECT_EMPTY_ARRAY
} ExpectedJsonType;

typedef struct {
	const char *field;
	const char *expected_value;
	ExpectedJsonType type;
} JsonFieldCheck;

typedef struct Test {
	const char *name;
	bool (*callback)(struct mg_mgr *);
} Test;

typedef struct {
	const char *header;
	const char *expected_value;
} ExpectedHeaders;

// Print HTTP response and signal that we're done
static void fn(struct mg_connection *c, int ev, void *ev_data) {
	if (ev == MG_EV_OPEN) {
		// Connection created. Store connect expiration time in c->data
		*(uint64_t *)c->data = mg_millis() + s_timeout_ms;
	} else if (ev == MG_EV_POLL) {
		if (mg_millis() > *(uint64_t *)c->data &&
		    (c->is_connecting || c->is_resolving)) {
			mg_error(c, "Connect timeout");
		}
	} else if (ev == MG_EV_CONNECT) {
		// Connected to server. Extract host name from URL
		struct mg_str host = mg_url_host(s_url);

		// Send request
		int content_length = (int)s_post_data_len;
		mg_printf(c,
			  "%s %s HTTP/1.0\r\n"
			  "Host: %.*s\r\n"
			  "%s"
			  "Content-Length: %d\r\n"
			  "\r\n",
			  s_method, mg_url_uri(s_url), (int)host.len, host.buf,
			  s_headers ? s_headers : "", content_length);
		mg_send(c, s_post_data, content_length);
	} else if (ev == MG_EV_HTTP_MSG) {
		// Response is received. Print it
		struct mg_http_message *hm = (struct mg_http_message *)ev_data;
		const char *message = malloc(hm->message.len);
		memcpy((void *)message, hm->message.buf, hm->message.len);
		if (mg_http_parse(message, hm->message.len, s_response) < 0) {
			free((void *)message);
			s_response->message.buf = NULL;
		}
		// printf("Response: %.*s\n", (int)hm->message.len,
		//        hm->message.buf);
		c->is_draining = 1; // Tell mongoose to close this connection
		*(bool *)c->fn_data = true; // Tell event loop to stop
	} else if (ev == MG_EV_ERROR) {
		*(bool *)c->fn_data = true; // Error, tell event loop to stop
	}
}

static bool request(struct mg_mgr *mgr, struct mg_http_message *msg,
		    const char *method, const char *headers, const char *body,
		    size_t body_len) {
	bool done = false;
	snprintf(s_url, sizeof(s_url), "%s%s", s_host, method);
	s_headers = headers;
	s_post_data = body;
	s_post_data_len = body_len;
	memset(msg, 0, sizeof(struct mg_http_message));
	s_response = msg;
	mg_http_connect(mgr, s_url, fn, &done); // Create client connection
	while (!done)
		mg_mgr_poll(mgr, 50); // Event manager loops until 'done'
	return true;
}

bool upload(struct mg_mgr *mgr, struct mg_http_message *message,
	    const char *image_bytes, size_t image_len, const char *endpoint) {
	if (!image_bytes || !endpoint || !message || image_len == 0)
		return false;

	const size_t CHUNK_SIZE = 1024 * 1024; // 1mb
	char query_url[2048];
	bool status = true;
	size_t offset = 0;
	size_t chunk_size;

	memset(s_method, 0, sizeof(s_method));
	snprintf(s_method, sizeof(s_method), "PATCH");

	while (offset < image_len) {
		char headers[256] = { 0 };
		snprintf(
			headers, sizeof(headers),
			"Content-Type: application/offset+octet-stream\r\nUpload-Offset: %zu\r\nTus-Resumable: 1.0.0\r\nConnection: keep-alive\r\n",
			offset);

		chunk_size = (image_len - offset > CHUNK_SIZE) ?
				     CHUNK_SIZE :
				     image_len - offset;

		snprintf(query_url, sizeof(query_url), "%s/%s", endpoint,
			 s_checksum);

		if (!request(mgr, message, query_url, headers,
			     image_bytes + offset, chunk_size)) {
			fprintf(stderr,
				"Erro ao enviar chunk offset %zu (status: %d)\n",
				offset, mg_http_status(message));
			status = false;
			break;
		}

		offset += chunk_size;
	}

	return status;
}

bool corrupt_bytes(char *filepath, size_t size, int length) {
	if ((size_t)length > size)
		return false;

	srand((unsigned)time(NULL));
	for (int i = 0; i < length; i++) {
		filepath[i] = rand() % 256;
	}

	return true;
}

bool copy_bytes(const char *src, char **dst, size_t *size) {
	if (src == NULL) {
		return false;
	}

	size_t read, fsize;
	FILE *fp = fopen(src, "rb");

	if (!fp)
		return false;

	// Vai para o fim do arquivo para descobrir o tamanho
	fseek(fp, 0, SEEK_END);
	fsize = ftell(fp);
	rewind(fp);

	if (fsize <= 0) {
		fclose(fp);
		return false;
	}

	// Aloca memória para os dados
	*dst = malloc(fsize);
	if (!*dst) {
		fclose(fp);
		return false;
	}

	// Lê os bytes para o buffer
	read = fread(*dst, 1, fsize, fp);
	fclose(fp);

	if (read != fsize) {
		free(*dst);
		*dst = NULL;
		return false;
	}

	*size = fsize;
	return true;
}

void remove_quotes(char word[], int len) {
	if (len >= 2 && word[0] == '"' && word[len - 1] == '"') {
		memmove(word, word + 1, len - 2);
		word[len - 2] = '\0';
	}
	return;
}

bool verify_json(struct mg_http_message *message, JsonFieldCheck *fields,
		 size_t field_count) {
	if (!message)
		return false;

	struct mg_str json = mg_str_n(message->body.buf, message->body.len);
	char buffer[256], *type_str;
	int toklen, offset;
	bool type_num;
	json_t *j;

	if (!fields) {
		return false;
	}

	for (size_t i = 0; i < field_count; i++) {
		toklen = 0;
		type_str = NULL;
		type_num = false;
		offset = mg_json_get(json, fields[i].field, &toklen);

		if (offset < 0 || toklen >= (int)sizeof(buffer)) {
			return false;
		}

		memcpy(buffer, message->body.buf + offset, toklen);
		buffer[toklen] = '\0';

		// Verifica o tipo esperado
		switch (fields[i].type) {
		case JSON_EXPECT_STRING:
			type_str = mg_json_get_str(json, fields[i].field);
			break;
		case JSON_EXPECT_NUMBER:
			type_num = mg_json_get_num(json, fields[i].field, NULL);
			break;
		case JSON_EXPECT_EMPTY_ARRAY:
			j = json_loads(json.buf, json.len, NULL);
			if (json_is_array(j) && json_array_size(j) == 0) {
				return true;
			}
			return false;
		}

		if (type_num == false && type_str == NULL) {
			return false;
		}

		if (strcmp(buffer, fields[i].expected_value) != 0) {
			return false;
		}
	}

	return true;
}

bool verify_headers(struct mg_http_message *hm) {
	size_t num, valid_header = 0;
	struct mg_str *header;
	ExpectedHeaders expected_headers[] = {
		{
			.header = "Access-Control-Allow-Origin",
			.expected_value = NULL,
		},
		{
			.header = "Access-Control-Allow-Methods",
			.expected_value = NULL,
		},
		{
			.header = "Access-Control-Allow-Headers",
			.expected_value = NULL,
		},
		{
			.header = "Access-Control-Allow-Credentials",
			.expected_value = NULL,
		},
		{
			.header = "Access-Control-Max-Age",
			.expected_value = "1728000",
		},
		{
			.header = "Cache-Control",
			.expected_value = "no-store",
		},
		{
			.header = "Vary",
			.expected_value =
				"Origin, Access-Control-Request-Method, Access-Control-Request-Headers",
		},
		{ .header = "Content-Type",
		  .expected_value = "application/json" }
	};

	num = sizeof(expected_headers) / sizeof(expected_headers[0]);
	for (size_t i = 0; i < num; i++) {
		header = mg_http_get_header(hm, expected_headers[i].header);
		if (header != NULL) {
			if (expected_headers[i].expected_value == NULL) {
				valid_header++;
			} else if (header->len ==
					   strlen(expected_headers[i]
							  .expected_value) &&
				   strncmp(header->buf,
					   expected_headers[i].expected_value,
					   header->len) == 0) {
				valid_header++;
			}
		}
	}

	if (valid_header < 7) {
		return false;
	}

	return true;
}

const char *get_file_id_from_location(struct mg_http_message *hm, size_t *len) {
	if (!hm)
		return NULL;

	struct mg_str *location = mg_http_get_header(hm, "Location");
	if (!location)
		return NULL;

	const char *prefix = "/files/";
	const char *start = strstr(location->buf, prefix);
	if (!start)
		return NULL;

	start += strlen(prefix); // Avança para depois de "/files/"
	if (len)
		*len = location->buf + location->len - start;

	return start; // NÃO precisa de free, mas válido só enquanto hm existir
}

static bool test_image_post_blake3_banette_success(struct mg_mgr *mgr) {
	struct mg_http_message message;
	char *image_bytes;
	size_t size;
	uint8_t hash[BLAKE3_OUT_LEN];
	char headers[512];
	bool status;

	// Inicialização das variáveis
	image_bytes = NULL;
	status = true;
	size = 0;

	if (!copy_bytes("./tests/test_data/banette-060_159.jpg", &image_bytes,
			&size)) {
		return false;
	}

	blake3_hasher hasher;
	blake3_hasher_init(&hasher);
	blake3_hasher_update(&hasher, image_bytes, size);
	blake3_hasher_finalize(&hasher, hash, BLAKE3_OUT_LEN);

	unsigned char base64_output[4 * ((BLAKE3_OUT_LEN + 2) / 3) + 1];
	int len = EVP_EncodeBlock((unsigned char *)base64_output, hash,
				  BLAKE3_OUT_LEN);
	if (len >= sizeof(base64_output) || len <= 0) {
		status = false;
		goto end;
	}

	base64_output[len] = '\0';
	snprintf(
		headers, sizeof(headers),
		"Upload-Checksum: blake3 %s\r\nUpload-Length: %zu\r\nTus-Resumable: 1.0.0\r\n",
		base64_output, size);
	memset(s_method, 0, sizeof(s_method));
	snprintf(s_method, sizeof(s_method), "POST");

	if (!request(mgr, &message, "/files", headers, NULL, 0)) {
		status = false;
		goto end;
	}

	size_t id_len;
	const char *location = get_file_id_from_location(&message, &id_len);
	if (!location) {
		status = false;
		goto end;
	}

	memset(s_checksum, 0, sizeof(s_checksum));
	strncpy(s_checksum, location, sizeof(s_checksum) - 1);

	if (s_checksum[0] == '\0' || id_len >= sizeof(s_checksum) ||
	    mg_http_status(&message) != 201) {
		status = false;
		goto end;
	}

	s_checksum[id_len] = '\0';
end:
	if (image_bytes != NULL) {
		free(image_bytes);
		image_bytes = NULL;
	}

	return status;
}

static bool test_image_patch_blake3_banette_success(struct mg_mgr *mgr) {
	struct mg_http_message message;
	char *image_bytes;
	size_t size;
	bool status;

	// Inicialização das variáveis
	image_bytes = NULL;
	status = true;
	size = 0;

	if (!copy_bytes("./tests/test_data/banette-060_159.jpg", &image_bytes,
			&size)) {
		return false;
	}

	if (!upload(mgr, &message, image_bytes, size, "/files")) {
		status = false;
		goto end;
	}

	if (mg_http_status(&message) != 204) {
		status = false;
		goto end;
	}

end:
	if (image_bytes != NULL) {
		free(image_bytes);
		image_bytes = NULL;
	}

	return status;
}

static bool test_image_post_blake3_scrafty_success(struct mg_mgr *mgr) {
	struct mg_http_message message;
	char *image_bytes;
	size_t size;
	uint8_t hash[BLAKE3_OUT_LEN];
	char headers[512];
	bool status;

	// Inicialização das variáveis
	image_bytes = NULL;
	status = true;
	size = 0;

	if (!copy_bytes("./tests/test_data/scrafty-188.jpg", &image_bytes,
			&size)) {
		return false;
	}

	blake3_hasher hasher;
	blake3_hasher_init(&hasher);
	blake3_hasher_update(&hasher, image_bytes, size);
	blake3_hasher_finalize(&hasher, hash, BLAKE3_OUT_LEN);

	unsigned char base64_output[4 * ((BLAKE3_OUT_LEN + 2) / 3) + 1];
	int len = EVP_EncodeBlock((unsigned char *)base64_output, hash,
				  BLAKE3_OUT_LEN);
	if (len >= sizeof(base64_output) || len <= 0) {
		status = false;
		goto end;
	}

	base64_output[len] = '\0';
	snprintf(
		headers, sizeof(headers),
		"Upload-Checksum: blake3 %s\r\nUpload-Length: %zu\r\nTus-Resumable: 1.0.0\r\n",
		base64_output, size);
	memset(s_method, 0, sizeof(s_method));
	snprintf(s_method, sizeof(s_method), "POST");

	if (!request(mgr, &message, "/files", headers, NULL, 0)) {
		status = false;
		goto end;
	}

	size_t id_len;
	const char *location = get_file_id_from_location(&message, &id_len);
	if (!location) {
		status = false;
		goto end;
	}

	memset(s_checksum, 0, sizeof(s_checksum));
	strncpy(s_checksum, location, sizeof(s_checksum) - 1);

	if (s_checksum[0] == '\0' || id_len >= sizeof(s_checksum)) {
		status = false;
		goto end;
	}

	if (mg_http_status(&message) != 201) {
		status = false;
		goto end;
	}

	s_checksum[id_len] = '\0';
end:
	if (image_bytes != NULL) {
		free(image_bytes);
		image_bytes = NULL;
	}

	return status;
}

static bool test_image_patch_blake3_scrafty_failure(struct mg_mgr *mgr) {
	struct mg_http_message message;
	char *image_bytes;
	size_t size;
	bool status;

	// Inicialização das variáveis
	image_bytes = NULL;
	status = true;
	size = 0;

	if (!copy_bytes("./tests/test_data/scrafty-188.jpg", &image_bytes,
			&size)) {
		return false;
	}

	//Corrompe a imagem
	if (!corrupt_bytes(image_bytes, size, 100)) {
		status = false;
		goto end;
	}

	if (!upload(mgr, &message, image_bytes, size, "/files")) {
		status = false;
		goto end;
	}

	if (mg_http_status(&message) != 400) {
		status = false;
		goto end;
	}

end:
	if (image_bytes != NULL) {
		free(image_bytes);
		image_bytes = NULL;
	}

	return status;
}

static bool test_image_post_sha1_shuppet_success(struct mg_mgr *mgr) {
	struct mg_http_message message;
	char *image_bytes;
	size_t size;
	unsigned char hash[SHA_DIGEST_LENGTH];
	char headers[512];
	bool status;

	// Inicialização das variáveis
	image_bytes = NULL;
	status = true;
	size = 0;

	if (!copy_bytes("./tests/test_data/shuppet-059_159.jpg", &image_bytes,
			&size)) {
		return false;
	}

	SHA1((const unsigned char *)image_bytes, size, hash);
	unsigned char base64_output[4 * ((SHA_DIGEST_LENGTH + 2) / 3) + 1];
	int len = EVP_EncodeBlock((unsigned char *)base64_output, hash,
				  SHA_DIGEST_LENGTH);
	if (len >= sizeof(base64_output) || len <= 0) {
		status = false;
		goto end;
	}

	base64_output[len] = '\0';
	snprintf(
		headers, sizeof(headers),
		"Upload-Checksum: sha1 %s\r\nUpload-Length: %zu\r\nTus-Resumable: 1.0.0\r\n",
		base64_output, size);
	memset(s_method, 0, sizeof(s_method));
	snprintf(s_method, sizeof(s_method), "POST");

	if (!request(mgr, &message, "/files", headers, NULL, 0)) {
		status = false;
		goto end;
	}

	size_t id_len;
	const char *location = get_file_id_from_location(&message, &id_len);
	if (!location) {
		status = false;
		goto end;
	}

	memset(s_checksum, 0, sizeof(s_checksum));
	strncpy(s_checksum, location, sizeof(s_checksum) - 1);

	if (s_checksum[0] == '\0' || id_len >= sizeof(s_checksum) ||
	    mg_http_status(&message) != 201) {
		status = false;
		goto end;
	}

	s_checksum[id_len] = '\0';
end:
	if (image_bytes != NULL) {
		free(image_bytes);
		image_bytes = NULL;
	}

	return status;
}

static bool test_image_patch_sha1_shuppet_success(struct mg_mgr *mgr) {
	struct mg_http_message message;
	char *image_bytes;
	size_t size;
	bool status;

	// Inicialização das variáveis
	image_bytes = NULL;
	status = true;
	size = 0;

	if (!copy_bytes("./tests/test_data/shuppet-059_159.jpg", &image_bytes,
			&size)) {
		return false;
	}

	if (!upload(mgr, &message, image_bytes, size, "/files")) {
		status = false;
		goto end;
	}

	if (mg_http_status(&message) != 204) {
		status = false;
		goto end;
	}

end:
	if (image_bytes != NULL) {
		free(image_bytes);
		image_bytes = NULL;
	}

	return status;
}

static bool test_image_post_sha1_claydol_success(struct mg_mgr *mgr) {
	struct mg_http_message message;
	char *image_bytes;
	size_t size;
	uint8_t hash[BLAKE3_OUT_LEN];
	char headers[512];
	bool status;

	// Inicialização das variáveis
	image_bytes = NULL;
	status = true;
	size = 0;

	if (!copy_bytes("./tests/test_data/claydol-095_197.jpg", &image_bytes,
			&size)) {
		return false;
	}

	blake3_hasher hasher;
	blake3_hasher_init(&hasher);
	blake3_hasher_update(&hasher, image_bytes, size);
	blake3_hasher_finalize(&hasher, hash, BLAKE3_OUT_LEN);

	unsigned char base64_output[4 * ((BLAKE3_OUT_LEN + 2) / 3) + 1];
	int len = EVP_EncodeBlock((unsigned char *)base64_output, hash,
				  BLAKE3_OUT_LEN);
	if (len >= sizeof(base64_output) || len <= 0) {
		status = false;
		goto end;
	}

	base64_output[len] = '\0';
	snprintf(
		headers, sizeof(headers),
		"Upload-Checksum: blake3 %s\r\nUpload-Length: %zu\r\nTus-Resumable: 1.0.0\r\n",
		base64_output, size);
	memset(s_method, 0, sizeof(s_method));
	snprintf(s_method, sizeof(s_method), "POST");

	if (!request(mgr, &message, "/files", headers, NULL, 0)) {
		status = false;
		goto end;
	}

	size_t id_len;
	const char *location = get_file_id_from_location(&message, &id_len);
	if (!location) {
		status = false;
		goto end;
	}

	memset(s_checksum, 0, sizeof(s_checksum));
	strncpy(s_checksum, location, sizeof(s_checksum) - 1);

	if (s_checksum[0] == '\0' || id_len >= sizeof(s_checksum)) {
		status = false;
		goto end;
	}

	if (mg_http_status(&message) != 201) {
		status = false;
		goto end;
	}

	s_checksum[id_len] = '\0';
end:
	if (image_bytes != NULL) {
		free(image_bytes);
		image_bytes = NULL;
	}

	return status;
}

static bool test_image_patch_sha1_claydol_failure(struct mg_mgr *mgr) {
	struct mg_http_message message;
	char *image_bytes;
	size_t size;
	bool status;

	// Inicialização das variáveis
	image_bytes = NULL;
	status = true;
	size = 0;

	if (!copy_bytes("./tests/test_data/claydol-095_197.jpg", &image_bytes,
			&size)) {
		return false;
	}

	//Corrompe a imagem
	if (!corrupt_bytes(image_bytes, size, 100)) {
		status = false;
		goto end;
	}

	if (!upload(mgr, &message, image_bytes, size, "/files")) {
		status = false;
		goto end;
	}

	if (mg_http_status(&message) != 400) {
		status = false;
		goto end;
	}

end:
	if (image_bytes != NULL) {
		free(image_bytes);
		image_bytes = NULL;
	}

	return status;
}

static Test s_tests[] = {
	{
		.name = "test_image_post_blake3_banette_success",
		.callback = test_image_post_blake3_banette_success,
	},
	{
		.name = "test_image_patch_blake3_banette_success",
		.callback = test_image_patch_blake3_banette_success,
	},
	{
		.name = "test_image_post_sha1_shuppet_success",
		.callback = test_image_post_sha1_shuppet_success,
	},
	{
		.name = "test_image_patch_sha1_shuppet_success",
		.callback = test_image_patch_sha1_shuppet_success,
	},
	{
		.name = "test_image_post_blake3_scrafty_success",
		.callback = test_image_post_blake3_scrafty_success,
	},
	{
		.name = "test_image_patch_blake3_scrafty_failure",
		.callback = test_image_patch_blake3_scrafty_failure,
	},
	{
		.name = "test_image_post_sha1_claydol_success",
		.callback = test_image_post_sha1_claydol_success,
	},
	{
		.name = "test_image_patch_sha1_claydol_failure",
		.callback = test_image_patch_sha1_claydol_failure,
	}
};

bool run_test(struct mg_mgr *mgr, Test *test) {
	bool ret = test->callback(mgr);
	if (ret) {
		printf("'%s' = success\n\n", test->name);
	} else {
		printf("'%s' = failed\n\n", test->name);
	}
	return ret;
}

int main(int argc, char *argv[]) {
	int failures = 0;
	const char *log_level =
		getenv("LOG_LEVEL"); // Allow user to set log level
	struct mg_mgr mgr; // Event manager
	if (log_level == NULL)
		log_level = "0"; // Default is verbose
	mg_log_set(atoi(log_level)); // Set to 0 to disable debug
	mg_mgr_init(&mgr); // Initialise event manager

	for (size_t i = 0; i < sizeof(s_tests) / sizeof(Test); i++) {
		if (!run_test(&mgr, &s_tests[i])) {
			failures += 1;
		}
	}

	mg_mgr_free(&mgr); // Free resources
	return failures;
}

#include "headers.h"
#include "mongoose.h"
#include <unistd.h>

#define MAX_SIZE_UPLOAD 1073741824

bool verify_upload_checksum(struct mg_http_message *hm, char *hash,
			    size_t hash_size) {
	struct mg_str *up_cksum = mg_http_get_header(hm, "Upload-Checksum");
	if ((up_cksum->len - 8) >= hash_size || !up_cksum)
		return false;

	if (up_cksum->len >= 7 && strncmp(up_cksum->buf, "blake3 ", 7) == 0) {
		memcpy(hash, up_cksum->buf + 7, up_cksum->len - 7);
		hash[up_cksum->len - 7] = '\0';
	} else
		return false;

	return true;
}

bool verify_upload_length(struct mg_http_message *hm, size_t *up_len) {
	struct mg_str *upload_length = mg_http_get_header(hm, "Upload-Length");
	char buf[16], *endptr = NULL;
	if (!upload_length || upload_length->len >= sizeof(buf))
		return false;

	memcpy(buf, upload_length->buf, upload_length->len);
	buf[upload_length->len] = '\0';
	*up_len = (size_t)strtol(buf, &endptr, 10);
	return *up_len > 0 && endptr != buf && *endptr == '\0' &&
	       *up_len < MAX_SIZE_UPLOAD;
}

bool verify_tus_resumable(struct mg_http_message *hm) {
	const char *versions[] = { "1.0.0", "0.2.2", "0.2.1" };
	bool supported = false;
	struct mg_str *tus_resumable = mg_http_get_header(hm, "Tus-Resumable");
	if (!tus_resumable)
		return false;

	for (size_t i = 0; i < sizeof(versions) / sizeof(versions[0]); i++) {
		if (tus_resumable->len == strlen(versions[i]) &&
		    strncmp(tus_resumable->buf, versions[i],
			    tus_resumable->len) == 0) {
			return true;
		}
	}

	return false;
}

bool verify_post(struct mg_connection *c, struct mg_http_message *hm,
		 char *hash, size_t hash_size, size_t *up_len) {
	if (!verify_upload_checksum(hm, hash, hash_size) ||
	    !verify_tus_resumable(hm) || !verify_upload_length(hm, up_len))
		return false;

	return true;
}

bool get_tus_resumable(struct mg_http_message *hm, char *version,
		       size_t version_len) {
	struct mg_str *tus_resumable = mg_http_get_header(hm, "Tus-Resumable");

	if (!tus_resumable || tus_resumable->len >= version_len)
		return false;

	memcpy(version, tus_resumable->buf, tus_resumable->len);
	version[tus_resumable->len] = '\0';
	return true;
}

bool concat_header_post(char *headers, size_t headers_len,
			const char *header_name, const char *value) {
	if (!headers || !header_name || !value || headers_len == 0)
		return false;

	size_t current_len = strnlen(headers, headers_len);
	size_t name_len = strlen(header_name);
	size_t value_len = strlen(value);
	const char *suffix = "\r\n";
	size_t suffix_len = 2;

	// Verifica se cabe: "Nome: Valor\r\n" + terminador
	if (current_len + name_len + 2 + value_len + suffix_len >= headers_len)
		return false;

	// Concatena
	memcpy(headers + current_len, header_name, name_len);
	current_len += name_len;

	memcpy(headers + current_len, ": ", 2);
	current_len += 2;

	memcpy(headers + current_len, value, value_len);
	current_len += value_len;

	memcpy(headers + current_len, suffix, suffix_len);
	current_len += suffix_len;

	headers[current_len] = '\0'; // terminador
	return true;
}
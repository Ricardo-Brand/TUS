#include "headers.h"
#include "mongoose.h"
#include <unistd.h>
#include <stdarg.h>

#define MAX_SIZE_UPLOAD 1073741824
#define MAX_CHUNK_UPLOAD 1024 * 1024

bool verify_upload_checksum(struct mg_http_message *hm, char *hash_type,
			    size_t type_len, char *hash, size_t hash_size) {
	struct mg_str *up_cksum = mg_http_get_header(hm, "Upload-Checksum");
	if (!up_cksum || type_len == 0 || hash_size == 0)
		return false;

	if (up_cksum->len >= 7 && strncmp(up_cksum->buf, "blake3 ", 7) == 0 &&
	    (up_cksum->len - 7 < hash_size) && type_len > 7 &&
	    up_cksum->len - 7 > 0) {
		memcpy(hash, up_cksum->buf + 7, up_cksum->len - 7);
		hash[up_cksum->len - 7] = '\0';
		snprintf(hash_type, type_len, "blake3");
	} else if (up_cksum->len >= 5 &&
		   strncmp(up_cksum->buf, "sha1 ", 5) == 0 &&
		   (up_cksum->len - 5 < hash_size) && type_len > 5 &&
		   up_cksum->len - 5 > 0) {
		memcpy(hash, up_cksum->buf + 5, up_cksum->len - 5);
		hash[up_cksum->len - 5] = '\0';
		snprintf(hash_type, type_len, "sha1");
	} else {
		return false;
	}

	return true;
}

int verify_upload_length(struct mg_http_message *hm, size_t *up_len) {
	struct mg_str *upload_length = mg_http_get_header(hm, "Upload-Length");
	char buf[16], *endptr = NULL;
	if (!upload_length || upload_length->len >= sizeof(buf))
		return -1;

	memcpy(buf, upload_length->buf, upload_length->len);
	buf[upload_length->len] = '\0';
	*up_len = (size_t)strtol(buf, &endptr, 10);
	if (*up_len >= MAX_SIZE_UPLOAD)
		return -2;
	else if (*up_len <= 0 || endptr == buf || *endptr != '\0')
		return -3;

	return 0;
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

int verify_headers_post(struct mg_http_message *hm, char *hash,
			size_t hash_size, char *hash_type, size_t type_len,
			size_t *up_len) {
	if (!verify_upload_checksum(hm, hash_type, type_len, hash, hash_size) ||
	    !verify_tus_resumable(hm))
		return -1;
	int upload_lenth = verify_upload_length(hm, up_len);
	switch (upload_lenth) {
	case -1:
		return -1;
	case -2:
		return -2;
	case -3:
		return -3;
	default:
		break;
	}

	return 0;
}

bool compare_checksum(struct mg_http_message *hm, const char *hash,
		      size_t hash_len) {
	struct mg_str *up_cksum = mg_http_get_header(hm, "Upload-Checksum");
	char hash_aux[128] = { 0 };
	size_t prefix_len = 0;

	if (!up_cksum)
		return false;

	if (up_cksum->len >= 7 && strncmp(up_cksum->buf, "blake3 ", 7) == 0) {
		prefix_len = 7;
	} else if (up_cksum->len >= 5 &&
		   strncmp(up_cksum->buf, "sha1 ", 5) == 0) {
		prefix_len = 5;
	} else {
		return false;
	}

	if ((up_cksum->len - prefix_len) != hash_len)
		return false;

	memcpy(hash_aux, up_cksum->buf + prefix_len,
	       up_cksum->len - prefix_len);
	hash_aux[up_cksum->len - prefix_len] = '\0';
	return strncmp(hash, hash_aux, hash_len) == 0;
}

bool verify_content_type(struct mg_http_message *hm) {
	struct mg_str *ct = mg_http_get_header(hm, "Content-Type");
	const char expected[] = "application/offset+octet-stream";
	if (!ct)
		return false;

	// Verifica se começa com a string esperada
	if (ct->len != strlen(expected))
		return false;

	if (strncmp(ct->buf, expected, strlen(expected)) != 0)
		return false;

	return true;
}

bool verify_upload_offset(struct mg_http_message *hm, size_t offset) {
	struct mg_str *up_offset = mg_http_get_header(hm, "Upload-Offset");
	size_t buf_offset = 0;
	char buf[16], *endptr = NULL;
	if (!up_offset || up_offset->len >= sizeof(buf))
		return false;

	memcpy(buf, up_offset->buf, up_offset->len);
	buf[up_offset->len] = '\0';
	buf_offset = (size_t)strtol(buf, &endptr, 10);

	return offset >= 0 && endptr != buf && *endptr == '\0' &&
	       offset < MAX_SIZE_UPLOAD && buf_offset == offset;
}

bool verify_content_length(struct mg_http_message *hm) {
	struct mg_str *cl_hdr = mg_http_get_header(hm, "Content-Length");
	size_t buf_cl = 0;
	char buf[16], *endptr = NULL;
	if (!cl_hdr || cl_hdr->len >= sizeof(buf))
		return false;

	memcpy(buf, cl_hdr->buf, cl_hdr->len);
	buf[cl_hdr->len] = '\0';
	buf_cl = (size_t)strtol(buf, &endptr, 10);

	return endptr != buf && *endptr == '\0' && buf_cl == hm->body.len &&
	       buf_cl > 0 && buf_cl <= MAX_CHUNK_UPLOAD;
}

bool verify_headers_patch(struct mg_http_message *hm, char *hash,
			  size_t hash_size, size_t offset) {
	if (!compare_checksum(hm, hash, strnlen(hash, hash_size)) ||
	    !verify_tus_resumable(hm) || !verify_content_type(hm) ||
	    !verify_upload_offset(hm, offset) || !verify_content_length(hm))
		return false;

	return true;
}

bool verify_headers_head(struct mg_http_message *hm) {
	if (!verify_tus_resumable(hm))
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

bool concat_headers(char *headers, size_t headers_len, const char *header_name,
		    const char *fmt, ...) {
	if (!headers || !header_name || !fmt || headers_len == 0)
		return false;

	size_t current_len = strnlen(headers, headers_len);
	size_t name_len = strlen(header_name);
	const char *suffix = "\r\n";
	size_t suffix_len = 2;

	char value_buf[128];
	va_list args;
	va_start(args, fmt);
	int value_len = vsnprintf(value_buf, sizeof(value_buf), fmt, args);
	va_end(args);

	if (value_len < 0 || (size_t)(current_len + name_len + 2 + value_len +
				      suffix_len) >= headers_len)
		return false;

	memcpy(headers + current_len, header_name, name_len);
	current_len += name_len;

	memcpy(headers + current_len, ": ", 2);
	current_len += 2;

	memcpy(headers + current_len, value_buf, value_len);
	current_len += value_len;

	memcpy(headers + current_len, suffix, suffix_len);
	current_len += suffix_len;

	headers[current_len] = '\0';
	return true;
}
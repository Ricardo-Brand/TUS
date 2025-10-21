#include <stdlib.h>
#include <unistd.h>
#include <string.h> /* memcpy, strlen etc. */
#include <openssl/evp.h> /* SHA1*/
#include <openssl/sha.h> /* EVP_EncodeBlock (Base64) */
#include "tus-upload.h"
#include "blake3.h"
#include "mongoose.h"
#include "libbase58.h"
#include "headers.h"

#define IMAGE_PATH_SIZE 512

typedef bool (*fn_get_hash)(unsigned char *, size_t, unsigned char *, size_t);

// Pega o tempo atual e adiciona 5 minutos
void get_gmt_date_plus_5sec(char *buffer, size_t size) {
	time_t now = time(NULL);
	now += 5; // adiciona 5 segundos
	struct tm *gmt = gmtime(&now);
	strftime(buffer, size, "%a, %d %b %Y %H:%M:%S GMT", gmt);
}

// Pega o tempo atual
void get_gmt_date(char *buffer, size_t size) {
	time_t now = time(NULL); // obtém o tempo atual (epoch)
	struct tm *gmt = gmtime(&now); // converte para UTC (GMT)
	strftime(buffer, size, "%a, %d %b %Y %H:%M:%S GMT", gmt);
}

// Função auxiliar para converter string HTTP-date para time_t
time_t parse_http_date(const char *date_str) {
	struct tm t = { 0 };
	if (strptime(date_str, "%a, %d %b %Y %H:%M:%S GMT", &t) == NULL)
		return (time_t)-1;
	return timegm(&t); // converte tm (UTC) em time_t
}

/*
*
    OPTIONS
*
*/

void middlewares_tus_options(struct mg_connection *c) {
	const char *headers = "Tus-Version: 1.0.0,0.2.2,0.2.1\r\n"
			      "Tus-Resumable: 1.0.0\r\n"
			      "Tus-Max-Size: 1073741824\r\n"
			      "Tus-Extesion: creation,expiration,checksum\r\n"
			      "Tus-Checksum-Algorithm: blake3,sha1\r\n";

	mg_http_reply(c, 204, headers, "");
}

/*
*
    POST
*
*/

bool base64_to_base58(const char *b64, char *b58, size_t b58_size) {
	size_t b64_len, padding, tmp_size;
	uint8_t buf[64];
	int decoded_len;

	b64_len = strlen(b64);
	padding = 0;

	if (b64_len == 0)
		return false;

	// Remove o padding '=' para calcular tamanho real
	if (b64_len >= 1 && b64[b64_len - 1] == '=')
		padding++;

	if (b64_len >= 2 && b64[b64_len - 2] == '=')
		padding++;

	char tmp[64] = { 0 };
	strncpy(tmp, b64, sizeof(tmp) - 1);

	// Adiciona padding '=' se necessário
	size_t len = strlen(tmp);
	size_t pad = (4 - (len % 4)) % 4;
	for (size_t i = 0; i < pad; i++)
		tmp[len + i] = '=';
	tmp[len + pad] = '\0';

	decoded_len = EVP_DecodeBlock(buf, (unsigned char *)tmp, strlen(tmp));
	if (decoded_len < 0)
		return false;

	decoded_len -= padding;
	if (decoded_len <= 0)
		return false;

	tmp_size = b58_size;
	if (!b58enc((uint8_t *)b58, &tmp_size, buf, decoded_len))
		return false;

	return true;
}

bool build_image_path(char *filename, char *image_path, size_t image_len) {
	const char *prefix = "./tmp/";
	const char *suffix = ".jpg";
	size_t prefix_len = strlen(prefix);
	size_t suffix_len = strlen(suffix);
	size_t filename_len = strlen(filename);
	size_t pos, remaining;

	// Limpa o buffer
	memset(image_path, 0, image_len);
	if (prefix_len > IMAGE_PATH_SIZE - 1) {
		return false; // não cabe, aborta
	}

	strncpy(image_path, prefix, prefix_len);
	image_path[prefix_len] = '\0';
	pos = prefix_len;
	remaining = IMAGE_PATH_SIZE - 1 - pos;
	if (filename_len > remaining) {
		return false;
	}

	strncpy(image_path + pos, filename, filename_len);
	pos += filename_len;
	image_path[pos] = '\0';
	remaining = IMAGE_PATH_SIZE - 1 - pos;
	if (suffix_len > remaining) {
		return false;
	}

	strncpy(image_path + pos, suffix, suffix_len);
	pos += suffix_len;
	image_path[pos] = '\0';

	return true;
}

void middlewares_tus_post(struct mg_connection *c, struct mg_http_message *hm,
			  ArrayTus *up, size_t *n_up) {
	char cksum[128] = { 0 };
	uint8_t hash[46];
	char b58[65]; // saída Base58
	char image_path[IMAGE_PATH_SIZE] = { 0 }, post_headers[1024] = { 0 };
	char location[128], hash_type[10] = { 0 };
	size_t len, i = 0;
	bool found = false;

	if (hm->body.len > 0) {
		mg_http_reply(c, 400, DEFAULT_HEADERS,
			      "\"POST /files não aceita body\"");
		return;
	}

	for (size_t j = 0; j <= *n_up; j++) {
		if (up[j].occupied == false) {
			i = j;
			found = true;
			break;
		}
	}

	if (!found) {
		mg_http_reply(c, 500, DEFAULT_HEADERS, "\"Erro interno\"");
		return;
	}

	int headers = verify_headers_post(hm, up[i].hash, sizeof(up[i].hash),
					  hash_type, sizeof(hash_type),
					  &up[i].upload_length);

	if (headers == -2) {
		mg_http_reply(c, 413, DEFAULT_HEADERS,
			      "\"Request Entity Too Large\"");
		return;
	} else if (headers != 0) {
		mg_http_reply(c, 400, DEFAULT_HEADERS,
			      "\"Informações faltando\"");
		return;
	}

	if (strncmp(hash_type, "blake3", 6) == 0) {
		up[i].hash_type = HASH_BLAKE3;
	} else if (strncmp(hash_type, "sha1", 4) == 0) {
		up[i].hash_type = HASH_SHA1;
	} else {
		mg_http_reply(c, 400, DEFAULT_HEADERS,
			      "Tipo de hash não permitido");
		return;
	}

	if (!base64_to_base58(up[i].hash, b58, sizeof(b58))) {
		mg_http_reply(c, 500, DEFAULT_HEADERS,
			      "Não foi possível encodar hash em Base58");
		return;
	}

	if (!build_image_path(b58, image_path, sizeof(image_path))) {
		mg_http_reply(c, 400, DEFAULT_HEADERS,
			      "Nome do arquivo muito grande");
		return;
	}

	if (!get_tus_resumable(hm, up[i].resumable, sizeof(up[i].resumable)) ||
	    strnlen(image_path, sizeof(image_path)) >=
		    sizeof(up[i].url_image)) {
		mg_http_reply(c, 500, DEFAULT_HEADERS, "Houve um erro interno");
		return;
	}

	strncpy(up[i].url_image, image_path, sizeof(up[i].url_image));
	get_gmt_date_plus_5sec(up[i].date_time, sizeof(up[i].date_time));

	if (strlen("http://127.0.0.1:8080/files/") +
		    strnlen(b58, sizeof(b58)) >=
	    sizeof(location)) {
		mg_http_reply(c, 500, DEFAULT_HEADERS, "Houve um erro interno");
		return;
	}

	snprintf(location, sizeof(location), "http://127.0.0.1:8080/files/%s",
		 b58);

	if (!concat_headers(post_headers, sizeof(post_headers), "Location",
			    "%s", location) ||
	    !concat_headers(post_headers, sizeof(post_headers), "Tus-Resumable",
			    "%s", up[i].resumable) ||
	    !concat_headers(post_headers, sizeof(post_headers),
			    "Upload-Expires", "%s", up[i].date_time)) {
		mg_http_reply(c, 500, DEFAULT_HEADERS, "Houve um erro interno");
		return;
	}

	FILE *fp = fopen(image_path, "rb");
	if (fp) {
		fclose(fp);
		mg_http_reply(c, 201, post_headers, "");
		return;
	}

	fp = fopen(image_path, "wb");
	if (!fp) {
		mg_http_reply(c, 500, DEFAULT_HEADERS,
			      "Falha ao criar arquivo");
		return;
	}

	fclose(fp);
	up[i].occupied = true;
	mg_http_reply(c, 201, post_headers, "");
}

/*
*
    PATCH
*
*/

bool verify_exp_time(char *date_time) {
	char date_now[65] = { 0 };
	get_gmt_date(date_now, sizeof(date_now));
	time_t t_now = parse_http_date(date_now);
	time_t t_plus5 = parse_http_date(date_time);
	if (t_now == (time_t)-1 || t_plus5 == (time_t)-1) {
		return false;
	}

	return t_now < t_plus5;
}

bool get_hash_blake3(unsigned char *image_bytes, size_t image_len,
		     unsigned char *output, size_t output_len) {
	blake3_hasher hasher;
	blake3_hasher_init(&hasher);
	blake3_hasher_update(&hasher, image_bytes, image_len);
	uint8_t output_blake[BLAKE3_OUT_LEN];
	blake3_hasher_finalize(&hasher, output_blake, BLAKE3_OUT_LEN);

	int len = EVP_EncodeBlock(output, output_blake, BLAKE3_OUT_LEN);

	return len < output_len && len > 0;
}

bool get_hash_sha1(unsigned char *image_bytes, size_t image_len,
		   unsigned char *output, size_t output_len) {
	unsigned char hash[SHA_DIGEST_LENGTH];
	SHA1(image_bytes, image_len, hash);

	int len = EVP_EncodeBlock(output, hash, SHA_DIGEST_LENGTH);

	return len < output_len && len > 0;
}

bool verify_upload(ArrayTus *up) {
	unsigned char *image_bytes = NULL;
	bool status;
	fn_get_hash get_hash = NULL;
	unsigned char output[64];

	if (up->hash_type == HASH_BLAKE3) {
		get_hash = get_hash_blake3;
	} else if (up->hash_type == HASH_SHA1) {
		get_hash = get_hash_sha1;
	} else {
		return false;
	}

	FILE *fp = fopen(up->url_image, "r+b");
	if (!fp)
		return false;

	image_bytes = malloc(up->upload_length + 1048576);
	if (!image_bytes) {
		fclose(fp);
		status = false;
		goto end;
	}

	if (fread(image_bytes, 1, up->upload_length, fp) != up->upload_length) {
		fclose(fp);
		status = false;
		goto end;
	}

	fclose(fp);
	if (!get_hash(image_bytes, up->upload_length, output, sizeof(output)) ||
	    strcmp(up->hash, (char *)output) != 0) {
		status = false;
		goto end;
	}

	status = true;
end:
	if (image_bytes != NULL) {
		free(image_bytes);
		image_bytes = NULL;
	}

	return status;
}

void middlewares_tus_patch(struct mg_connection *c, struct mg_http_message *hm,
			   ArrayTus *up, size_t *n_up) {
	char image_url[256] = { 0 }, file_id[65] = { 0 };
	bool found = false;
	size_t i;

	if (hm->body.len == 0) {
		mg_http_reply(c, 400, DEFAULT_HEADERS, "\"Body vazio\"");
		return;
	}

	if ((hm->uri.len - 7) >= sizeof(file_id)) {
		mg_http_reply(c, 400, DEFAULT_HEADERS, "URL muito grande");
		return;
	}

	memcpy(file_id, hm->uri.buf + 7, hm->uri.len - 7);
	if ((strnlen(file_id, sizeof(file_id)) + 10) >= sizeof(image_url)) {
		mg_http_reply(c, 400, DEFAULT_HEADERS, "URL muito grande");
		return;
	}

	snprintf(image_url, sizeof(image_url), "./tmp/%s.jpg", file_id);
	for (size_t j = 0; j < *n_up; j++) {
		if (strcmp(image_url, up[j].url_image) == 0 && up[j].occupied) {
			i = j;
			found = true;
			break;
		}
	}

	if (!found) {
		mg_http_reply(c, 404, DEFAULT_HEADERS,
			      "\"Arquivo nao encontrado\"");
		return;
	}

	if (!verify_headers_patch(hm, up[i].hash, sizeof(up[i].hash),
				  up[i].upload_offset)) {
		mg_http_reply(c, 400, DEFAULT_HEADERS,
			      "\"Informações faltando\"");
		return;
	}

	if (!verify_exp_time(up[i].date_time)) {
		mg_http_reply(c, 400, DEFAULT_HEADERS, "Arquivo expirou");
		return;
	}

	if (up[i].upload_offset + hm->body.len > up[i].upload_length) {
		mg_http_reply(c, 400, DEFAULT_HEADERS,
			      "Chunk excede tamanho total");
		return;
	}

	if (up[i].upload_offset >= up[i].upload_length) {
		mg_http_reply(c, 400, DEFAULT_HEADERS, "Upload ja concluido");
		return;
	}

	FILE *fp = fopen(image_url, "r+b");
	if (!fp) {
		mg_http_reply(c, 500, DEFAULT_HEADERS,
			      "Falha ao abrir arquivo para patch");
		return;
	}

	// Move o ponteiro do arquivo para o offset atual
	if (fseek(fp, up[i].upload_offset, SEEK_SET) != 0) {
		fclose(fp);
		mg_http_reply(c, 500, DEFAULT_HEADERS,
			      "Falha ao posicionar arquivo");
		return;
	}

	// Escreve o chunk recebido
	if (fwrite(hm->body.buf, 1, hm->body.len, fp) != (size_t)hm->body.len) {
		fclose(fp);
		mg_http_reply(c, 500, DEFAULT_HEADERS,
			      "Falha ao escrever no arquivo");
		return;
	}

	fclose(fp);
	up[i].upload_offset += hm->body.len;
	if (up[i].upload_offset == up[i].upload_length &&
	    !verify_upload(&up[i])) {
		mg_http_reply(c, 400, DEFAULT_HEADERS,
			      "\"Arquivo é diferente\"");
		remove(up[i].url_image);
		memset(&up[i], 0, sizeof(up[i]));
		return;
	}

	mg_http_reply(c, 204, DEFAULT_HEADERS, "");
}

/*
*
    HEAD
*
*/

void middlewares_tus_head(struct mg_connection *c, struct mg_http_message *hm,
			  ArrayTus *up, size_t *n_up) {
	char image_url[256] = { 0 }, file_id[65] = { 0 };
	size_t i;
	char head_headers[256];
	bool found = false;

	if (!verify_headers_head(hm)) {
		mg_http_reply(c, 400, DEFAULT_HEADERS,
			      "\"Informações faltando\"");
		return;
	}

	if ((hm->uri.len - 7) >= sizeof(file_id)) {
		mg_http_reply(c, 400, DEFAULT_HEADERS, "URL muito grande");
		return;
	}

	memcpy(file_id, hm->uri.buf + 7, hm->uri.len - 7);
	if ((strnlen(file_id, sizeof(file_id)) + 10) >= sizeof(image_url)) {
		mg_http_reply(c, 400, DEFAULT_HEADERS, "URL muito grande");
		return;
	}

	snprintf(image_url, sizeof(image_url), "./tmp/%s.jpg", file_id);

	for (size_t j = 0; j < *n_up; j++) {
		if (strcmp(image_url, up[j].url_image) == 0 && up[j].occupied) {
			i = j;
			found = true;
			break;
		}
	}

	if (!found) {
		mg_http_reply(c, 404, DEFAULT_HEADERS,
			      "Arquivo nao encontrado");
		return;
	}

	if (!concat_headers(head_headers, sizeof(head_headers), "Upload-Offset",
			    "%zu", up[i].upload_offset) ||
	    !concat_headers(head_headers, sizeof(head_headers), "Upload-Length",
			    "%zu", up[i].upload_length) ||
	    !concat_headers(head_headers, sizeof(head_headers),
			    "Upload-Expires", "%s", up[i].date_time) ||
	    !concat_headers(head_headers, sizeof(head_headers), "Tus-Resumable",
			    "%s", up[i].resumable)) {
		mg_http_reply(c, 500, DEFAULT_HEADERS, "Erro interno");
		return;
	}

	mg_http_reply(c, 200, head_headers, "");
	return;
}
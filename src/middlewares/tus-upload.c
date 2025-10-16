#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <openssl/evp.h>
#include "tus-upload.h"
#include "blake3.h"
#include "mongoose.h"
#include "libbase58.h"
#include "headers.h"

#define IMAGE_PATH_SIZE 512

const char *DEFAULT_HEADERS =
	"Access-Control-Allow-Origin: *\r\n"
	"Access-Control-Allow-Credentials: true\r\n"
	"Access-Control-Allow-Methods: GET,POST,OPTIONS\r\n"
	"Access-Control-Allow-Headers: DNT,X-CustomHeader,Keep-Alive,User-Agent,X-Requested-With,If-Modified-Since,Cache-Control,Content-Type\r\n"
	"Cache-Control: no-store\r\n";

// Pega o tempo atual
void get_gmt_date_plus_5min(char *buffer, size_t size) {
	time_t now = time(NULL);
	now += 5 * 60; // adiciona 5 minutos (em segundos)
	struct tm *gmt = gmtime(&now);
	strftime(buffer, size, "%a, %d %b %Y %H:%M:%S GMT", gmt);
}

// Pega o tempo atual e adiciona 5 minutos
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

// // Converte ambas as datas para time_t
// time_t t_now = parse_http_date(date_now);
// time_t t_plus5 = parse_http_date(date_plus5);

// if (t_now == (time_t)-1 || t_plus5 == (time_t)-1) {
//     printf("Erro ao converter data.\n");
//     return 1;
// }

// // Compara
// if (t_now > t_plus5)
//     printf("✅ Já se passaram 5 minutos.\n");
// else
//     printf("⏳ Ainda não passaram 5 minutos.\n");

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
	size_t pos, copy_len, remaining;

	// Limpa o buffer
	memset(image_path, 0, image_len);

	// Copia prefixo
	if (strnlen(prefix, prefix_len) >=
	    (image_len - strnlen(image_path, image_len)))
		return false;
	pos = (prefix_len < IMAGE_PATH_SIZE - 1) ? prefix_len :
						   IMAGE_PATH_SIZE - 1;
	strncpy(image_path, prefix, pos);
	image_path[pos] = '\0';

	// Copia filename
	if (strnlen(filename, filename_len) >=
	    (image_len - strnlen(image_path, image_len)))
		return false;

	remaining = IMAGE_PATH_SIZE - 1 - pos;
	copy_len = (filename_len < remaining) ? filename_len : remaining;
	strncpy(image_path + pos, filename, copy_len);
	pos += copy_len;
	image_path[pos] = '\0';

	// Copia sufixo
	if (strnlen(suffix, suffix_len) >=
	    (image_len - strnlen(image_path, image_len)))
		return false;

	remaining = IMAGE_PATH_SIZE - 1 - pos;
	copy_len = (suffix_len < remaining) ? suffix_len : remaining;
	strncpy(image_path + pos, suffix, copy_len);
	pos += copy_len;
	image_path[pos] = '\0';

	return true;
}

void middlewares_tus_post(struct mg_connection *c, struct mg_http_message *hm,
			  ArrayTus *up, size_t *n_up) {
	char cksum[128] = { 0 };
	uint8_t hash[46];
	char b58[65]; // saída Base58
	char image_path[IMAGE_PATH_SIZE] = { 0 }, resumable[6] = { 0 },
	     post_headers[1024] = { 0 };
	char location[128];
	size_t len;

	if (!verify_post(c, hm, up[*n_up].hash, sizeof(up[*n_up].hash),
			 &up[*n_up].upload_length)) {
		mg_http_reply(c, 400, DEFAULT_HEADERS, "Headers faltando");
		return;
	}

	if (!base64_to_base58(up[*n_up].hash, b58, sizeof(b58))) {
		mg_http_reply(c, 500, DEFAULT_HEADERS,
			      "Não foi possível encodar hash em Base58");
		return;
	}

	if (!build_image_path(b58, image_path, sizeof(image_path))) {
		mg_http_reply(c, 400, DEFAULT_HEADERS,
			      "Nome do arquivo muito grande");
		return;
	}

	if (!get_tus_resumable(hm, resumable, sizeof(resumable)) ||
	    strnlen(image_path, sizeof(image_path)) >=
		    sizeof(up[*n_up].url_image)) {
		mg_http_reply(c, 500, DEFAULT_HEADERS, "Houve um erro interno");
		return;
	}

	strncpy(up[*n_up].url_image, image_path, sizeof(up[*n_up].url_image));
	get_gmt_date(up[*n_up].date_time, sizeof(up[*n_up].date_time));

	if (strlen("http://127.0.0.1:8080/files/") +
		    strnlen(b58, sizeof(b58)) >=
	    sizeof(location)) {
		mg_http_reply(c, 500, DEFAULT_HEADERS, "Houve um erro interno");
		return;
	}

	snprintf(location, sizeof(location), "http://127.0.0.1:8080/files/%s",
		 b58);

	printf("location: %s\n", location);
	if (!concat_header_post(post_headers, sizeof(post_headers), "Location",
				location) ||
	    !concat_header_post(post_headers, sizeof(post_headers),
				"Tus-Resumable", resumable) ||
	    !concat_header_post(post_headers, sizeof(post_headers),
				"Upload-Expires", up[*n_up].date_time)) {
		mg_http_reply(c, 500, DEFAULT_HEADERS, "Houve um erro interno");
		return;
	}

	FILE *fp = fopen(image_path, "rb");
	if (fp) {
		fclose(fp);
		(*n_up)++;
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
	(*n_up)++;
	mg_http_reply(c, 201, post_headers, "");
}

/*
*
    PATCH
*
*/

void middlewares_tus_patch(struct mg_connection *c, struct mg_http_message *hm,
			   ArrayTus *up, size_t *n_up) {
	char image_url[256] = { 0 }, file_id[65] = { 0 };
	size_t i;

	if (hm->body.len == 0) {
		mg_http_reply(c, 400, DEFAULT_HEADERS, "Body vazio");
		return;
	}

	if ((hm->uri.len - 7) >= sizeof(file_id)) {
		mg_http_reply(c, 500, DEFAULT_HEADERS, "URL muito grande");
		return;
	}

	memcpy(file_id, hm->uri.buf + 7, hm->uri.len - 7);
	if ((strnlen(file_id, sizeof(file_id)) + 10) >= sizeof(image_url)) {
		mg_http_reply(c, 500, DEFAULT_HEADERS, "URL muito grande");
		return;
	}

	snprintf(image_url, sizeof(image_url), "./tmp/%s.jpg", file_id);

	for (size_t j = 0; j <= *n_up; j++) {
		if (strcmp(image_url, up[j].url_image) == 0) {
			i = j;
			break;
		}
		if (j == *n_up) {
			mg_http_reply(c, 500, DEFAULT_HEADERS,
				      "Arquivo nao encontrado");
			return;
		}
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

	mg_http_reply(c, 204, DEFAULT_HEADERS, "");
}
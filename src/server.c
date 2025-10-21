#include "mongoose.h"
#include "headers.h"
#include "tus-upload.h"
#include <unistd.h>

#define EXPIRATION_SECONDS 1 // 1 segundos
static ArrayTus tus_uploads[10];

void cleanup_expired_uploads(size_t n) {
	time_t now = time(NULL);

	sleep(1);
	for (size_t i = 0; i < n; i++) {
		if (!tus_uploads[i].occupied)
			continue;

		// Converte a data da struct para time_t
		struct tm tm_time;
		if (strptime(tus_uploads[i].date_time,
			     "%a, %d %b %Y %H:%M:%S GMT", &tm_time) == NULL)
			continue; // data inválida, pula

		time_t upload_time = timegm(&tm_time);

		// Se expirou
		if ((now - upload_time) > EXPIRATION_SECONDS) {
			// Remove arquivo usando remove()
			if (tus_uploads[i].url_image[0] != '\0') {
				if (remove(tus_uploads[i].url_image) == 0) {
					printf("[cleanup] Upload expirado removido: %s\n",
					       tus_uploads[i].url_image);
				} else {
					perror("[cleanup] Erro ao remover arquivo");
				}
			}

			// Zera o slot do array
			memset(&tus_uploads[i], 0, sizeof(ArrayTus));
		}
	}
}

static void cb(struct mg_connection *c, int ev, void *ev_data) {
	if (ev == MG_EV_HTTP_MSG) {
		struct mg_http_message *hm = (struct mg_http_message *)ev_data;
		size_t num = sizeof(tus_uploads) / sizeof(tus_uploads[0]);

		printf("Requisição recebida: método = %.*s, URI = %.*s\n",
		       (int)hm->method.len, hm->method.buf, (int)hm->uri.len,
		       hm->uri.buf);

		if (mg_match(hm->method, mg_str("OPTIONS"), NULL)) {
			mg_http_reply(c, 204, OPTIONS_HEADERS, "");
			return;
		} else if (mg_match(hm->method, mg_str("OPTIONS"), NULL) &&
			   mg_match(hm->uri, mg_str("/files"), NULL)) {
			middlewares_tus_options(c);
			return;
		} else if (mg_match(hm->uri, mg_str("/files"), NULL) &&
			   mg_match(hm->method, mg_str("POST"), NULL)) {
			middlewares_tus_post(c, hm, tus_uploads, &num);
		} else if (mg_match(hm->uri, mg_str("/files/#"), NULL) &&
			   mg_match(hm->method, mg_str("PATCH"), NULL)) {
			middlewares_tus_patch(c, hm, tus_uploads, &num);
		} else if (mg_match(hm->uri, mg_str("/files/#"), NULL) &&
			   mg_match(hm->method, mg_str("HEAD"), NULL)) {
			middlewares_tus_head(c, hm, tus_uploads, &num);
		}
	}
}

int main(void) {
	struct mg_mgr mgr;
	mg_log_set(MG_LL_ERROR); // Set log level
	mg_mgr_init(&mgr);
	mg_http_listen(&mgr, "http://0.0.0.0:8080", cb, NULL);
	printf("Servidor rodando em: http://0.0.0.0:8080\n");

	memset(tus_uploads, 0, sizeof(tus_uploads));

	for (;;) {
		mg_mgr_poll(&mgr, 50);
		static time_t last_cleanup = 0;
		time_t now = time(NULL);
		if (now - last_cleanup >= 5) {
			cleanup_expired_uploads(sizeof(tus_uploads) /
						sizeof(tus_uploads[0]));
			last_cleanup = now;
		}
	}
	mg_mgr_free(&mgr);

	return 0;
}
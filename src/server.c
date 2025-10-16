#include "mongoose.h"
#include "headers.h"
#include "tus-upload.h"
#include <unistd.h>

static ArrayTus tus_uploads[10];
static size_t num_uploads;

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
	"Cache-Control: no-store\r\n";

static void cb(struct mg_connection *c, int ev, void *ev_data) {
	if (ev == MG_EV_HTTP_MSG) {
		struct mg_http_message *hm = (struct mg_http_message *)ev_data;

		printf("Requisição recebida: método = %.*s, URI = %.*s\n",
		       (int)hm->method.len, hm->method.buf, (int)hm->uri.len,
		       hm->uri.buf);

		if (num_uploads >= 10) {
			mg_http_reply(c, 500, DEFAULT_HEADERS,
				      "Internal Error");
			return;
		}

		if (mg_match(hm->method, mg_str("OPTIONS"), NULL) &&
		    mg_match(hm->uri, mg_str("/files"), NULL)) {
			middlewares_tus_options(c);
			return;
		} else if (mg_match(hm->method, mg_str("OPTIONS"), NULL)) {
			mg_http_reply(c, 204, OPTIONS_HEADERS, "");
			return;
		}

		if (mg_match(hm->uri, mg_str("/files"), NULL) &&
		    mg_match(hm->method, mg_str("POST"), NULL)) {
			middlewares_tus_post(c, hm, tus_uploads, &num_uploads);
		} else if (mg_match(hm->uri, mg_str("/files/*"), NULL) &&
			   mg_match(hm->method, mg_str("PATCH"), NULL)) {
			middlewares_tus_patch(c, hm, tus_uploads, &num_uploads);
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
	num_uploads = 0;

	for (;;)
		mg_mgr_poll(&mgr, 50);
	mg_mgr_free(&mgr);

	return 0;
}
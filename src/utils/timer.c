#include <stdlib.h>
#include <unistd.h>
#include <time.h>
#include "timer.h"

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
#ifndef _TIMER_H_
#define _TIMER_H_

#include <unistd.h>
#include <time.h>

void get_gmt_date_plus_5sec(char *buffer, size_t size);

void get_gmt_date(char *buffer, size_t size);

time_t parse_http_date(const char *date_str);

#endif
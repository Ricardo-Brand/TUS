#ifndef LIBBASE58_H
#define LIBBASE58_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

bool b58enc(uint8_t *b58, size_t *b58sz, const void *bin, size_t binsz);

#ifdef __cplusplus
}
#endif

#endif

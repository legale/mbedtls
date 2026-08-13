/* SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later */
#ifndef MBEDTLS_GOST_TLS_H
#define MBEDTLS_GOST_TLS_H

#include "mbedtls/pk.h"

int mbedtls_gost_key_transport_write(unsigned char *out, size_t out_size, size_t *out_len,
                                     unsigned char pms[32], const mbedtls_pk_context *server_key,
                                     const unsigned char random[64],
                                     int (*f_rng)(void *, unsigned char *, size_t), void *p_rng);
int mbedtls_gost_key_transport_parse(unsigned char pms[32], const unsigned char *in, size_t in_len,
                                     const mbedtls_pk_context *server_key,
                                     const unsigned char random[64]);

#endif

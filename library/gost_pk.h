/* SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later */
#ifndef MBEDTLS_GOST_PK_H
#define MBEDTLS_GOST_PK_H

#include "mbedtls/asn1.h"
#include "mbedtls/pk.h"

int mbedtls_gost3410_parse_public(mbedtls_pk_context *pk, const mbedtls_asn1_buf *params,
                                  const unsigned char *key, size_t key_len);
int mbedtls_gost3410_parse_private(mbedtls_pk_context *pk, const mbedtls_asn1_buf *params,
                                   const unsigned char *key, size_t key_len);
int mbedtls_gost3410_get_public(const mbedtls_pk_context *pk, unsigned char public_key[128]);
int mbedtls_gost3410_get_private(const mbedtls_pk_context *pk, unsigned char private_key[64]);

#endif

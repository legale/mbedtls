/* SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later */

#include "common.h"

#if defined(MBEDTLS_LIBPOGOST_C) && defined(MBEDTLS_PK_C)

#include "gost_pk.h"
#include "pk_wrap.h"

#include "mbedtls/asn1.h"
#include "mbedtls/oid.h"
#include "mbedtls/platform.h"
#include "mbedtls/platform_util.h"

#include <libpogost/gost3410.h>

#include <string.h>

struct mbedtls_gost3410_context {
  unsigned char public_key[GOST3410_512_PUBLIC_SIZE];
  unsigned char private_key[GOST3410_512_KEY_SIZE];
  int has_private;
};

static int gost_params_valid(const mbedtls_asn1_buf *params)
{
  unsigned char *p;
  const unsigned char *end;
  size_t len;

  if (params->tag != (MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE))
    return 0;

  p = params->p;
  end = p + params->len;
  if (mbedtls_asn1_get_tag(&p, end, &len, MBEDTLS_ASN1_OID) != 0 ||
      len != MBEDTLS_OID_SIZE(MBEDTLS_OID_GOST3410_2012_512_PARAMSET_A) ||
      memcmp(p, MBEDTLS_OID_GOST3410_2012_512_PARAMSET_A, len) != 0)
    return 0;
  p += len;

  if (p == end)
    return 1;
  if (mbedtls_asn1_get_tag(&p, end, &len, MBEDTLS_ASN1_OID) != 0 ||
      len != MBEDTLS_OID_SIZE(MBEDTLS_OID_STREEBOG_512) ||
      memcmp(p, MBEDTLS_OID_STREEBOG_512, len) != 0)
    return 0;
  p += len;
  return p == end;
}

int mbedtls_gost3410_parse_public(mbedtls_pk_context *pk, const mbedtls_asn1_buf *params,
                                  const unsigned char *key, size_t key_len)
{
  struct mbedtls_gost3410_context *ctx = pk->pk_ctx;
  unsigned char *p = (unsigned char *)key;
  const unsigned char *end = p + key_len;
  size_t len;

  if (!gost_params_valid(params) ||
      mbedtls_asn1_get_tag(&p, end, &len, MBEDTLS_ASN1_OCTET_STRING) != 0 ||
      len != GOST3410_512_PUBLIC_SIZE || p + len != end)
    return MBEDTLS_ERR_PK_INVALID_PUBKEY;

  memcpy(ctx->public_key, p, len);
  return 0;
}

int mbedtls_gost3410_parse_private(mbedtls_pk_context *pk, const mbedtls_asn1_buf *params,
                                   const unsigned char *key, size_t key_len)
{
  struct mbedtls_gost3410_context *ctx = pk->pk_ctx;

  if (!gost_params_valid(params) || key_len != GOST3410_512_KEY_SIZE)
    return MBEDTLS_ERR_PK_KEY_INVALID_FORMAT;

  memcpy(ctx->private_key, key, key_len);
  if (gost3410_512a_public(ctx->public_key, ctx->private_key) != 0) {
    mbedtls_platform_zeroize(ctx->private_key, sizeof(ctx->private_key));
    return MBEDTLS_ERR_PK_KEY_INVALID_FORMAT;
  }
  ctx->has_private = 1;
  return 0;
}

int mbedtls_gost3410_get_public(const mbedtls_pk_context *pk, unsigned char public_key[128])
{
  const struct mbedtls_gost3410_context *ctx;

  if (pk == NULL || pk->pk_info != &mbedtls_gost3410_512_info || pk->pk_ctx == NULL ||
      public_key == NULL)
    return MBEDTLS_ERR_PK_BAD_INPUT_DATA;
  ctx = pk->pk_ctx;
  memcpy(public_key, ctx->public_key, sizeof(ctx->public_key));
  return 0;
}

int mbedtls_gost3410_get_private(const mbedtls_pk_context *pk, unsigned char private_key[64])
{
  const struct mbedtls_gost3410_context *ctx;

  if (pk == NULL || pk->pk_info != &mbedtls_gost3410_512_info || pk->pk_ctx == NULL ||
      private_key == NULL)
    return MBEDTLS_ERR_PK_BAD_INPUT_DATA;
  ctx = pk->pk_ctx;
  if (!ctx->has_private)
    return MBEDTLS_ERR_PK_TYPE_MISMATCH;
  memcpy(private_key, ctx->private_key, sizeof(ctx->private_key));
  return 0;
}

static size_t gost_get_bitlen(mbedtls_pk_context *pk)
{
  (void)pk;
  return 512;
}

static int gost_can_do(mbedtls_pk_type_t type)
{
  return type == MBEDTLS_PK_GOST3410_512;
}

static int gost_verify(mbedtls_pk_context *pk, mbedtls_md_type_t md_alg, const unsigned char *hash,
                       size_t hash_len, const unsigned char *sig, size_t sig_len)
{
  struct mbedtls_gost3410_context *ctx = pk->pk_ctx;

  if (md_alg != MBEDTLS_MD_STREEBOG512 || hash_len != GOST3410_512_DIGEST_SIZE ||
      sig_len != GOST3410_512_SIGNATURE_SIZE)
    return MBEDTLS_ERR_PK_BAD_INPUT_DATA;

  return gost3410_512a_verify(ctx->public_key, hash, sig) == 0 ? 0 : MBEDTLS_ERR_PK_BAD_INPUT_DATA;
}

static int gost_sign(mbedtls_pk_context *pk, mbedtls_md_type_t md_alg, const unsigned char *hash,
                     size_t hash_len, unsigned char *sig, size_t sig_size, size_t *sig_len,
                     int (*f_rng)(void *, unsigned char *, size_t), void *p_rng)
{
  struct mbedtls_gost3410_context *ctx = pk->pk_ctx;
  unsigned char nonce[GOST3410_512_KEY_SIZE];
  int ret = MBEDTLS_ERR_PK_BAD_INPUT_DATA;
  unsigned int i;

  if (!ctx->has_private || md_alg != MBEDTLS_MD_STREEBOG512 ||
      hash_len != GOST3410_512_DIGEST_SIZE || sig_size < GOST3410_512_SIGNATURE_SIZE ||
      f_rng == NULL)
    return MBEDTLS_ERR_PK_BAD_INPUT_DATA;

  for (i = 0; i < 32; i++) {
    if (f_rng(p_rng, nonce, sizeof(nonce)) != 0)
      break;
    if (gost3410_512a_sign(sig, hash, ctx->private_key, nonce) == 0) {
      *sig_len = GOST3410_512_SIGNATURE_SIZE;
      ret = 0;
      break;
    }
  }
  mbedtls_platform_zeroize(nonce, sizeof(nonce));
  return ret;
}

static int gost_check_pair(mbedtls_pk_context *pub, mbedtls_pk_context *prv,
                           int (*f_rng)(void *, unsigned char *, size_t), void *p_rng)
{
  struct mbedtls_gost3410_context *pub_ctx = pub->pk_ctx;
  struct mbedtls_gost3410_context *prv_ctx = prv->pk_ctx;

  (void)f_rng;
  (void)p_rng;
  if (!prv_ctx->has_private ||
      memcmp(pub_ctx->public_key, prv_ctx->public_key, sizeof(pub_ctx->public_key)) != 0)
    return MBEDTLS_ERR_PK_BAD_INPUT_DATA;
  return 0;
}

static void *gost_alloc(void)
{
  return mbedtls_calloc(1, sizeof(struct mbedtls_gost3410_context));
}

static void gost_free(void *p)
{
  if (p == NULL)
    return;
  mbedtls_platform_zeroize(p, sizeof(struct mbedtls_gost3410_context));
  mbedtls_free(p);
}

const mbedtls_pk_info_t mbedtls_gost3410_512_info = {
  .type = MBEDTLS_PK_GOST3410_512,
  .name = "GOST R 34.10-2012 512",
  .get_bitlen = gost_get_bitlen,
  .can_do = gost_can_do,
  .verify_func = gost_verify,
  .sign_func = gost_sign,
#if defined(MBEDTLS_ECDSA_C) && defined(MBEDTLS_ECP_RESTARTABLE)
  .verify_rs_func = NULL,
  .sign_rs_func = NULL,
  .rs_alloc_func = NULL,
  .rs_free_func = NULL,
#endif
  .decrypt_func = NULL,
  .encrypt_func = NULL,
  .check_pair_func = gost_check_pair,
  .ctx_alloc_func = gost_alloc,
  .ctx_free_func = gost_free,
  .debug_func = NULL,
};

#endif

/* SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later */
#include "common.h"

#if defined(MBEDTLS_LIBPOGOST_C) && defined(MBEDTLS_SSL_TLS_C)

#include "gost_pk.h"
#include "gost_tls.h"

#include "mbedtls/asn1.h"
#include "mbedtls/asn1write.h"
#include "mbedtls/oid.h"
#include "mbedtls/platform_util.h"
#include "mbedtls/ssl.h"

#include <libpogost/gost3410.h>
#include <libpogost/gost_tls.h>
#include <libpogost/streebog.h>

#include <string.h>

#define GOST_TRANSPORT_EXP_SIZE 48

static int gost_write_spki(unsigned char *buf, size_t size, const unsigned char public_key[128])
{
  unsigned char *p = buf + size;
  size_t len = 0;
  size_t alg_len = 0;
  size_t par_len = 0;
  int ret;

  MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_octet_string(&p, buf, public_key, 128));
  if (p <= buf)
    return MBEDTLS_ERR_ASN1_BUF_TOO_SMALL;
  *--p = 0;
  len++;
  MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_len(&p, buf, len));
  MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_tag(&p, buf, MBEDTLS_ASN1_BIT_STRING));

  MBEDTLS_ASN1_CHK_ADD(par_len, mbedtls_asn1_write_oid(&p, buf, MBEDTLS_OID_STREEBOG_512,
                                                       MBEDTLS_OID_SIZE(MBEDTLS_OID_STREEBOG_512)));
  MBEDTLS_ASN1_CHK_ADD(
      par_len, mbedtls_asn1_write_oid(&p, buf, MBEDTLS_OID_GOST3410_2012_512_PARAMSET_A,
                                      MBEDTLS_OID_SIZE(MBEDTLS_OID_GOST3410_2012_512_PARAMSET_A)));
  MBEDTLS_ASN1_CHK_ADD(par_len, mbedtls_asn1_write_len(&p, buf, par_len));
  MBEDTLS_ASN1_CHK_ADD(
      par_len, mbedtls_asn1_write_tag(&p, buf, MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE));
  alg_len += par_len;
  MBEDTLS_ASN1_CHK_ADD(alg_len,
                       mbedtls_asn1_write_oid(&p, buf, MBEDTLS_OID_GOST3410_2012_512,
                                              MBEDTLS_OID_SIZE(MBEDTLS_OID_GOST3410_2012_512)));
  MBEDTLS_ASN1_CHK_ADD(alg_len, mbedtls_asn1_write_len(&p, buf, alg_len));
  MBEDTLS_ASN1_CHK_ADD(
      alg_len, mbedtls_asn1_write_tag(&p, buf, MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE));
  len += alg_len;
  MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_len(&p, buf, len));
  MBEDTLS_ASN1_CHK_ADD(
      len, mbedtls_asn1_write_tag(&p, buf, MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE));
  memmove(buf, p, len);
  return (int)len;
}

static int gost_keg(unsigned char keys[64], const unsigned char public_key[128],
                    const unsigned char private_key[64], const unsigned char ukm_source[32])
{
  unsigned char ukm[16] = {0};
  unsigned int i;

  for (i = 0; i < sizeof(ukm); i++)
    ukm[i] = ukm_source[sizeof(ukm) - 1 - i];
  if (gost3410_512a_vko(keys, public_key, private_key, ukm) != 0) {
    mbedtls_platform_zeroize(ukm, sizeof(ukm));
    return MBEDTLS_ERR_PK_BAD_INPUT_DATA;
  }
  mbedtls_platform_zeroize(ukm, sizeof(ukm));
  return 0;
}

int mbedtls_gost_key_transport_write(unsigned char *out, size_t out_size, size_t *out_len,
                                     unsigned char pms[32], const mbedtls_pk_context *server_key,
                                     const unsigned char random[64],
                                     int (*f_rng)(void *, unsigned char *, size_t), void *p_rng)
{
  unsigned char server_public[128];
  unsigned char eph_private[64];
  unsigned char eph_public[128];
  unsigned char ukm[32];
  unsigned char keys[64];
  unsigned char psexp[48];
  unsigned char spki[192];
  unsigned char *p = out + out_size;
  size_t len = 0;
  unsigned int i;
  int spki_len;
  int ret = MBEDTLS_ERR_SSL_INTERNAL_ERROR;

  if (out == NULL || out_len == NULL || pms == NULL || server_key == NULL || random == NULL ||
      f_rng == NULL)
    return MBEDTLS_ERR_SSL_BAD_INPUT_DATA;
  if (mbedtls_gost3410_get_public(server_key, server_public) != 0)
    goto out;
  for (i = 0; i < 32; i++) {
    if (f_rng(p_rng, eph_private, sizeof(eph_private)) != 0)
      goto out;
    if (gost3410_512a_public(eph_public, eph_private) == 0)
      break;
  }
  if (i == 32 || f_rng(p_rng, pms, 32) != 0)
    goto out;
  streebog256(ukm, random, 64);
  if (gost_keg(keys, server_public, eph_private, ukm) != 0)
    goto out;
  kuznyechik_kexp15(psexp, pms, keys, keys + 32, ukm + 24);
  spki_len = gost_write_spki(spki, sizeof(spki), eph_public);
  if (spki_len < 0) {
    ret = spki_len;
    goto out;
  }

  MBEDTLS_ASN1_CHK_CLEANUP_ADD(len, mbedtls_asn1_write_octet_string(&p, out, ukm, sizeof(ukm)));
  MBEDTLS_ASN1_CHK_CLEANUP_ADD(len, mbedtls_asn1_write_raw_buffer(&p, out, spki, (size_t)spki_len));
  MBEDTLS_ASN1_CHK_CLEANUP_ADD(len, mbedtls_asn1_write_octet_string(&p, out, psexp, sizeof(psexp)));
  MBEDTLS_ASN1_CHK_CLEANUP_ADD(len, mbedtls_asn1_write_len(&p, out, len));
  MBEDTLS_ASN1_CHK_CLEANUP_ADD(
      len, mbedtls_asn1_write_tag(&p, out, MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE));
  memmove(out, p, len);
  *out_len = len;
  ret = 0;
cleanup:
out:
  mbedtls_platform_zeroize(server_public, sizeof(server_public));
  mbedtls_platform_zeroize(eph_private, sizeof(eph_private));
  mbedtls_platform_zeroize(eph_public, sizeof(eph_public));
  mbedtls_platform_zeroize(keys, sizeof(keys));
  mbedtls_platform_zeroize(psexp, sizeof(psexp));
  mbedtls_platform_zeroize(spki, sizeof(spki));
  return ret;
}

int mbedtls_gost_key_transport_parse(unsigned char pms[32], const unsigned char *in, size_t in_len,
                                     const mbedtls_pk_context *server_key,
                                     const unsigned char random[64])
{
  mbedtls_pk_context eph_key;
  unsigned char server_private[64];
  unsigned char eph_public[128];
  unsigned char expected_ukm[32];
  unsigned char keys[64];
  unsigned char *p = (unsigned char *)in;
  const unsigned char *end = in + in_len;
  const unsigned char *seq_end;
  const unsigned char *psexp;
  size_t len;
  size_t psexp_len;
  int ret = MBEDTLS_ERR_SSL_DECODE_ERROR;

  mbedtls_pk_init(&eph_key);
  if (pms == NULL || in == NULL || server_key == NULL || random == NULL)
    return MBEDTLS_ERR_SSL_BAD_INPUT_DATA;
  if (mbedtls_asn1_get_tag(&p, end, &len, MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE) != 0 ||
      len != (size_t)(end - p))
    goto out;
  seq_end = p + len;
  if (mbedtls_asn1_get_tag(&p, seq_end, &psexp_len, MBEDTLS_ASN1_OCTET_STRING) != 0 ||
      psexp_len != GOST_TRANSPORT_EXP_SIZE)
    goto out;
  psexp = p;
  p += psexp_len;
  if (mbedtls_pk_parse_subpubkey(&p, seq_end, &eph_key) != 0 ||
      mbedtls_pk_get_type(&eph_key) != MBEDTLS_PK_GOST3410_512)
    goto out;
  if (p != seq_end) {
    if (mbedtls_asn1_get_tag(&p, seq_end, &len, MBEDTLS_ASN1_OCTET_STRING) != 0 ||
        p + len != seq_end)
      goto out;
  }
  streebog256(expected_ukm, random, 64);
  if (mbedtls_gost3410_get_private(server_key, server_private) != 0 ||
      mbedtls_gost3410_get_public(&eph_key, eph_public) != 0 ||
      gost_keg(keys, eph_public, server_private, expected_ukm) != 0)
    goto out;
  if (kuznyechik_kimp15(pms, psexp, keys, keys + 32, expected_ukm + 24) != 0)
    goto out;
  ret = 0;
out:
  mbedtls_pk_free(&eph_key);
  mbedtls_platform_zeroize(server_private, sizeof(server_private));
  mbedtls_platform_zeroize(eph_public, sizeof(eph_public));
  mbedtls_platform_zeroize(expected_ukm, sizeof(expected_ukm));
  mbedtls_platform_zeroize(keys, sizeof(keys));
  return ret;
}

#endif

/* SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later */
#include "gost_tls.h"
#include "mbedtls/x509_crt.h"

#include <stdio.h>
#include <string.h>

static int test_rng(void *ctx, unsigned char *out, size_t len)
{
  unsigned char *v = ctx;

  memset(out, *v, len);
  (*v)++;
  if (*v == 0)
    *v = 1;
  return 0;
}

static int has_buf(const unsigned char *buf, size_t len,
                   const unsigned char *pat, size_t pat_len)
{
  size_t i;

  if (pat_len > len)
    return 0;
  for (i = 0; i <= len - pat_len; i++) {
    if (memcmp(buf + i, pat, pat_len) == 0)
      return 1;
  }
  return 0;
}

int main(int argc, char **argv)
{
  static const unsigned char algid[] = {
    0x30, 0x17,
    0x06, 0x08, 0x2a, 0x85, 0x03, 0x07, 0x01, 0x01, 0x01, 0x01,
    0x30, 0x0b,
    0x06, 0x09, 0x2a, 0x85, 0x03, 0x07, 0x01, 0x02, 0x01, 0x01, 0x01
  };
  static const unsigned char digest_oid[] = {
    0x06, 0x08, 0x2a, 0x85, 0x03, 0x07, 0x01, 0x01, 0x02, 0x02
  };
  mbedtls_x509_crt crt;
  unsigned char out[256];
  unsigned char pms[32];
  unsigned char random[64] = { 0 };
  unsigned char rng = 1;
  size_t out_len;
  int ret;

  if (argc != 2)
    return 2;

  mbedtls_x509_crt_init(&crt);
  ret = mbedtls_x509_crt_parse_file(&crt, argv[1]);
  if (ret != 0)
    goto out;

  ret = mbedtls_gost_key_transport_write(out, sizeof(out), &out_len, pms,
                                          &crt.pk, random, test_rng, &rng);
  if (ret != 0)
    goto out;

  if (out_len != 0xb7 || !has_buf(out, out_len, algid, sizeof(algid)) ||
      has_buf(out, out_len, digest_oid, sizeof(digest_oid))) {
    ret = 1;
    goto out;
  }

  puts("GOST_CLIENT_KEY_EXCHANGE_DER_PASS");
  ret = 0;
out:
  mbedtls_x509_crt_free(&crt);
  return ret;
}

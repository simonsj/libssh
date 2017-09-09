#ifndef LIBCRYPTO_BORINGSSL_COMPAT_H
#define LIBCRYPTO_BORINGSSL_COMPAT_H

#include <openssl/opensslv.h>

#if !defined(OPENSSL_IS_BORINGSSL)
#error "BoringSSL libcrypto compat header used for OpenSSL build"
#endif /* !defined(OPENSSL_IS_BORINGSSL) */

#include <openssl/bn.h>
#include <openssl/rsa.h>
#include <openssl/dsa.h>
#include <openssl/ecdsa.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>

int RSA_set0_key(RSA *r, BIGNUM *n, BIGNUM *e, BIGNUM *d);
int RSA_set0_factors(RSA *r, BIGNUM *p, BIGNUM *q);
int RSA_set0_crt_params(RSA *r, BIGNUM *dmp1, BIGNUM *dmq1, BIGNUM *iqmp);

int DSA_set0_pqg(DSA *d, BIGNUM *p, BIGNUM *q, BIGNUM *g);
int DSA_set0_key(DSA *d, BIGNUM *pub_key, BIGNUM *priv_key);

void DSA_SIG_get0(const DSA_SIG *sig, const BIGNUM **pr, const BIGNUM **ps);
int DSA_SIG_set0(DSA_SIG *sig, BIGNUM *r, BIGNUM *s);

void ECDSA_SIG_get0(const ECDSA_SIG *sig, const BIGNUM **pr, const BIGNUM **ps);
int ECDSA_SIG_set0(ECDSA_SIG *sig, BIGNUM *r, BIGNUM *s);

int EVP_MD_CTX_reset(EVP_MD_CTX *ctx);
EVP_MD_CTX *EVP_MD_CTX_new(void);
void EVP_MD_CTX_free(EVP_MD_CTX *ctx);

HMAC_CTX *HMAC_CTX_new(void);
int HMAC_CTX_reset(HMAC_CTX *ctx);
void HMAC_CTX_free(HMAC_CTX *ctx);

#endif /* LIBCRYPTO_BORINGSSL_COMPAT_H */

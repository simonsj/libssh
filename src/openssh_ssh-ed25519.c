/* $OpenBSD: ssh-ed25519.c,v 1.3 2014/02/23 20:03:42 djm Exp $ */
/*
 * Copyright (c) 2013 Markus Friedl <markus@openbsd.org>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#if 0 /* LIBSSH */
#include "includes.h"
#endif /* LIBSSH */

#include <sys/types.h>

#if 0 /* LIBSSH */
#include "crypto_api.h"
#else
#include <stdint.h>
#include "libssh/openssh/crypto_api.h"
#endif /* LIBSSH */

#include <limits.h>
#include <string.h>
#include <stdarg.h>

#if 0 /* LIBSSH */
#include "xmalloc.h"
#include "log.h"
#include "buffer.h"
#include "key.h"
#include "ssh.h"
#endif /* LIBSSH */

#if 0 /* LIBSSH */
int
ssh_ed25519_sign(const Key *key, u_char **sigp, u_int *lenp,
    const u_char *data, u_int datalen)
{
	u_char *sig;
	u_int slen, len;
	unsigned long long smlen;
	int ret;
	Buffer b;

	if (key == NULL || key_type_plain(key->type) != KEY_ED25519 ||
	    key->ed25519_sk == NULL) {
		error("%s: no ED25519 key", __func__);
		return -1;
	}

	if (datalen >= UINT_MAX - crypto_sign_ed25519_BYTES) {
		error("%s: datalen %u too long", __func__, datalen);
		return -1;
	}
	smlen = slen = datalen + crypto_sign_ed25519_BYTES;
	sig = xmalloc(slen);

	if ((ret = crypto_sign_ed25519(sig, &smlen, data, datalen,
	    key->ed25519_sk)) != 0 || smlen <= datalen) {
		error("%s: crypto_sign_ed25519 failed: %d", __func__, ret);
		free(sig);
		return -1;
	}
	/* encode signature */
	buffer_init(&b);
	buffer_put_cstring(&b, "ssh-ed25519");
	buffer_put_string(&b, sig, smlen - datalen);
	len = buffer_len(&b);
	if (lenp != NULL)
		*lenp = len;
	if (sigp != NULL) {
		*sigp = xmalloc(len);
		memcpy(*sigp, buffer_ptr(&b), len);
	}
	buffer_free(&b);
	explicit_bzero(sig, slen);
	free(sig);

	return 0;
}
#endif /* LIBSSH */

#if 0 /* LIBSSH original */
int
ssh_ed25519_verify(const Key *key, const u_char *signature, u_int signaturelen,
    const u_char *data, u_int datalen)
{
	Buffer b;
	char *ktype;
	u_char *sigblob, *sm, *m;
	u_int len;
	unsigned long long smlen, mlen;
	int rlen, ret;

	if (key == NULL || key_type_plain(key->type) != KEY_ED25519 ||
	    key->ed25519_pk == NULL) {
		error("%s: no ED25519 key", __func__);
		return -1;
	}
	buffer_init(&b);
	buffer_append(&b, signature, signaturelen);
	ktype = buffer_get_cstring(&b, NULL);
	if (strcmp("ssh-ed25519", ktype) != 0) {
		error("%s: cannot handle type %s", __func__, ktype);
		buffer_free(&b);
		free(ktype);
		return -1;
	}
	free(ktype);
	sigblob = buffer_get_string(&b, &len);
	rlen = buffer_len(&b);
	buffer_free(&b);
	if (rlen != 0) {
		error("%s: remaining bytes in signature %d", __func__, rlen);
		free(sigblob);
		return -1;
	}
	if (len > crypto_sign_ed25519_BYTES) {
		error("%s: len %u > crypto_sign_ed25519_BYTES %u", __func__,
		    len, crypto_sign_ed25519_BYTES);
		free(sigblob);
		return -1;
	}
	smlen = len + datalen;
	sm = xmalloc(smlen);
	memcpy(sm, sigblob, len);
	memcpy(sm+len, data, datalen);
	mlen = smlen;
	m = xmalloc(mlen);
	if ((ret = crypto_sign_ed25519_open(m, &mlen, sm, smlen,
	    key->ed25519_pk)) != 0) {
		debug2("%s: crypto_sign_ed25519_open failed: %d",
		    __func__, ret);
	}
	if (ret == 0 && mlen != datalen) {
		debug2("%s: crypto_sign_ed25519_open "
		    "mlen != datalen (%llu != %u)", __func__, mlen, datalen);
		ret = -1;
	}
	/* XXX compare 'm' and 'data' ? */

	explicit_bzero(sigblob, len);
	explicit_bzero(sm, smlen);
	explicit_bzero(m, smlen); /* NB. mlen may be invalid if ret != 0 */
	free(sigblob);
	free(sm);
	free(m);
	debug("%s: signature %scorrect", __func__, (ret != 0) ? "in" : "");

	/* translate return code carefully */
	return (ret == 0) ? 1 : -1;
}
#endif /* LIBSSH original */

#include "libssh/priv.h"

#include "libssh/libssh.h"
#include "libssh/buffer.h"
#include "libssh/session.h"
#include "libssh/pki.h"
#include "libssh/pki_priv.h"
#include "libssh/dh.h"
#include "libssh/ed25519.h"

int ssh_ed25519_verify(const ssh_key key,
                       const unsigned char *sigblob,
                       unsigned int sigblob_len,
                       const unsigned char *hash,
                       size_t hlen)
{
    int ret = -1;
    size_t len = 0;
    ssh_buffer buffer;

    unsigned char *sm = NULL;
    unsigned char *m = NULL;
    unsigned long long smlen, mlen;

    if (key->type != SSH_KEYTYPE_ED25519) {
        SSH_LOG(SSH_LOG_RARE, "non-ed25519 keytype (%d)", key->type);
        goto out;
    }

    len = sigblob_len;
    if (len > crypto_sign_ed25519_BYTES) {
        SSH_LOG(SSH_LOG_RARE, "len too big (%zd > %d)",
                              len, crypto_sign_ed25519_BYTES);
        goto out;
    }

    buffer = ssh_buffer_new();
    if (buffer == NULL) {
        SSH_LOG(SSH_LOG_RARE, "could not alloc buffer");
        goto out;
    }

    ret = ssh_buffer_add_data(buffer, sigblob, sigblob_len);
    if (ret < 0) {
        SSH_LOG(SSH_LOG_RARE, "add blob failed");
        goto outfree;
    }

    ret = ssh_buffer_add_data(buffer, hash, hlen);
    if (ret < 0) {
        SSH_LOG(SSH_LOG_RARE, "add hash failed");
        goto outfree;
    }

    smlen = len + hlen;
    if (smlen != ssh_buffer_get_len(buffer)) {
        SSH_LOG(SSH_LOG_RARE, "smlen %llu != buflen %d",
                              smlen, ssh_buffer_get_len(buffer));
        goto outfree;
    }

    mlen = smlen;
    m = malloc(mlen);
    if (m == NULL) {
        SSH_LOG(SSH_LOG_RARE, "malloc failed");
        goto outfree;
    }

    sm = ssh_buffer_get_begin(buffer);
    ret = crypto_sign_ed25519_open(m, &mlen, sm, smlen, ssh_string_data(key->ed_pk));
    if (ret != 0) {
        SSH_LOG(SSH_LOG_RARE, "crypto sign call failed, ret %d", ret);
        goto outfree;
    }

    if (mlen != hlen) {
        SSH_LOG(SSH_LOG_RARE, "mlen (%llu) != hlen (%zd)", mlen, hlen);
        ret = -1;
        goto outfree;
    }

outfree:
    ssh_buffer_free(buffer);
    BURN_BUFFER(m, smlen);
    free(m);
out:
    return (ret == 0) ? 1 : -1;
}

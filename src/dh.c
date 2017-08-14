/*
 * dh.c - Diffie-Helman algorithm code against SSH 2
 *
 * This file is part of the SSH Library
 *
 * Copyright (c) 2003-2016 by Aris Adamantiadis
 * Copyright (c) 2009-2013 by Andreas Schneider <asn@cryptomilk.org>
 * Copyright (c) 2012      by Dmitriy Kuznetsov <dk@yandex.ru>
 *
 * The SSH Library is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation; either version 2.1 of the License, or (at your
 * option) any later version.
 *
 * The SSH Library is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
 * or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU Lesser General Public
 * License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with the SSH Library; see the file COPYING.  If not, write to
 * the Free Software Foundation, Inc., 59 Temple Place - Suite 330, Boston,
 * MA 02111-1307, USA.
 */

#include "config.h"

#include "libssh/priv.h"
#include "libssh/crypto.h"
#include "libssh/buffer.h"
#include "libssh/session.h"
#include "libssh/misc.h"
#include "libssh/dh.h"
#include "libssh/ssh2.h"
#include "libssh/pki.h"
#include "libssh/bignum.h"

static unsigned char p_group1_value[] = {
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xC9, 0x0F, 0xDA, 0xA2,
        0x21, 0x68, 0xC2, 0x34, 0xC4, 0xC6, 0x62, 0x8B, 0x80, 0xDC, 0x1C, 0xD1,
        0x29, 0x02, 0x4E, 0x08, 0x8A, 0x67, 0xCC, 0x74, 0x02, 0x0B, 0xBE, 0xA6,
        0x3B, 0x13, 0x9B, 0x22, 0x51, 0x4A, 0x08, 0x79, 0x8E, 0x34, 0x04, 0xDD,
        0xEF, 0x95, 0x19, 0xB3, 0xCD, 0x3A, 0x43, 0x1B, 0x30, 0x2B, 0x0A, 0x6D,
        0xF2, 0x5F, 0x14, 0x37, 0x4F, 0xE1, 0x35, 0x6D, 0x6D, 0x51, 0xC2, 0x45,
        0xE4, 0x85, 0xB5, 0x76, 0x62, 0x5E, 0x7E, 0xC6, 0xF4, 0x4C, 0x42, 0xE9,
        0xA6, 0x37, 0xED, 0x6B, 0x0B, 0xFF, 0x5C, 0xB6, 0xF4, 0x06, 0xB7, 0xED,
        0xEE, 0x38, 0x6B, 0xFB, 0x5A, 0x89, 0x9F, 0xA5, 0xAE, 0x9F, 0x24, 0x11,
        0x7C, 0x4B, 0x1F, 0xE6, 0x49, 0x28, 0x66, 0x51, 0xEC, 0xE6, 0x53, 0x81,
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
#define P_GROUP1_LEN 128	/* Size in bytes of the p number */


static unsigned char p_group14_value[] = {
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xC9, 0x0F, 0xDA, 0xA2,
        0x21, 0x68, 0xC2, 0x34, 0xC4, 0xC6, 0x62, 0x8B, 0x80, 0xDC, 0x1C, 0xD1,
        0x29, 0x02, 0x4E, 0x08, 0x8A, 0x67, 0xCC, 0x74, 0x02, 0x0B, 0xBE, 0xA6,
        0x3B, 0x13, 0x9B, 0x22, 0x51, 0x4A, 0x08, 0x79, 0x8E, 0x34, 0x04, 0xDD,
        0xEF, 0x95, 0x19, 0xB3, 0xCD, 0x3A, 0x43, 0x1B, 0x30, 0x2B, 0x0A, 0x6D,
        0xF2, 0x5F, 0x14, 0x37, 0x4F, 0xE1, 0x35, 0x6D, 0x6D, 0x51, 0xC2, 0x45,
        0xE4, 0x85, 0xB5, 0x76, 0x62, 0x5E, 0x7E, 0xC6, 0xF4, 0x4C, 0x42, 0xE9,
        0xA6, 0x37, 0xED, 0x6B, 0x0B, 0xFF, 0x5C, 0xB6, 0xF4, 0x06, 0xB7, 0xED,
        0xEE, 0x38, 0x6B, 0xFB, 0x5A, 0x89, 0x9F, 0xA5, 0xAE, 0x9F, 0x24, 0x11,
        0x7C, 0x4B, 0x1F, 0xE6, 0x49, 0x28, 0x66, 0x51, 0xEC, 0xE4, 0x5B, 0x3D,
        0xC2, 0x00, 0x7C, 0xB8, 0xA1, 0x63, 0xBF, 0x05, 0x98, 0xDA, 0x48, 0x36,
        0x1C, 0x55, 0xD3, 0x9A, 0x69, 0x16, 0x3F, 0xA8, 0xFD, 0x24, 0xCF, 0x5F,
        0x83, 0x65, 0x5D, 0x23, 0xDC, 0xA3, 0xAD, 0x96, 0x1C, 0x62, 0xF3, 0x56,
        0x20, 0x85, 0x52, 0xBB, 0x9E, 0xD5, 0x29, 0x07, 0x70, 0x96, 0x96, 0x6D,
        0x67, 0x0C, 0x35, 0x4E, 0x4A, 0xBC, 0x98, 0x04, 0xF1, 0x74, 0x6C, 0x08,
        0xCA, 0x18, 0x21, 0x7C, 0x32, 0x90, 0x5E, 0x46, 0x2E, 0x36, 0xCE, 0x3B,
        0xE3, 0x9E, 0x77, 0x2C, 0x18, 0x0E, 0x86, 0x03, 0x9B, 0x27, 0x83, 0xA2,
        0xEC, 0x07, 0xA2, 0x8F, 0xB5, 0xC5, 0x5D, 0xF0, 0x6F, 0x4C, 0x52, 0xC9,
        0xDE, 0x2B, 0xCB, 0xF6, 0x95, 0x58, 0x17, 0x18, 0x39, 0x95, 0x49, 0x7C,
        0xEA, 0x95, 0x6A, 0xE5, 0x15, 0xD2, 0x26, 0x18, 0x98, 0xFA, 0x05, 0x10,
        0x15, 0x72, 0x8E, 0x5A, 0x8A, 0xAC, 0xAA, 0x68, 0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF};

#define P_GROUP14_LEN 256 /* Size in bytes of the p number for group 14 */

static unsigned long g_int = 2 ;	/* G is defined as 2 by the ssh2 standards */
static bignum g;
static bignum p_group1;
static bignum p_group14;
static int dh_crypto_initialized;

/**
 * @internal
 * @brief Initialize global constants used in DH key agreement
 * @return SSH_OK on success, SSH_ERROR otherwise.
 */
int ssh_dh_init(void) {
    int rc;
    if (dh_crypto_initialized == 0) {
    g = bignum_new();
    if (g == NULL) {
      goto error;
    }
    rc = bignum_set_word(g,g_int);
    if (rc != 1)
        goto error;
    bignum_bin2bn(p_group1_value, P_GROUP1_LEN, &p_group1);
    bignum_bin2bn(p_group14_value, P_GROUP14_LEN, &p_group14);
    if (p_group1 == NULL || p_group14 == NULL) {
      goto error;
    }
    dh_crypto_initialized = 1;
  }
  return 0;

error:
  bignum_safe_free(g);
  bignum_safe_free(p_group1);
  return SSH_ERROR;
}

/**
 * @internal
 * @brief Finalize and free global constants used in DH key agreement
 */
void ssh_dh_finalize(void) {
  if (dh_crypto_initialized) {
    bignum_safe_free(g);
    bignum_safe_free(p_group1);
    bignum_safe_free(p_group14);
    dh_crypto_initialized=0;
  }
}

/**
 * @internal
 * @brief allocate and initialize ephemeral values used in dh kex
 */
int ssh_dh_init_common(ssh_session session){
    struct ssh_crypto_struct *crypto=session->next_crypto;
    crypto->x = bignum_new();
    crypto->y = bignum_new();
    crypto->e = NULL;
    crypto->f = NULL;
    crypto->k = bignum_new();
    crypto->g = NULL;
    crypto->p = NULL;
    crypto->dh_group_is_mutable = 0;
    if (session->next_crypto->kex_type == SSH_KEX_DH_GROUP1_SHA1){
        session->next_crypto->p = p_group1;
        session->next_crypto->dh_group_bits = 1024;
        session->next_crypto->g = g;
        session->next_crypto->dh_group_is_mutable = 0;
    } else if (session->next_crypto->kex_type == SSH_KEX_DH_GROUP14_SHA1){
        session->next_crypto->p = p_group14;
        session->next_crypto->dh_group_bits = 2048;
        session->next_crypto->g = g;
        session->next_crypto->dh_group_is_mutable = 0;
    }

    if (crypto->x == NULL || crypto->y == NULL || crypto->k == NULL){
        ssh_set_error_oom(session);
        return SSH_ERROR;
    } else {
        return SSH_OK;
    }
}

void ssh_dh_cleanup(struct ssh_crypto_struct *crypto){
    bignum_safe_free(crypto->x);
    bignum_safe_free(crypto->y);
    bignum_safe_free(crypto->e);
    bignum_safe_free(crypto->f);
    if (crypto->dh_group_is_mutable){
        bignum_safe_free(crypto->p);
        bignum_safe_free(crypto->g);
    }
}

#ifdef DEBUG_CRYPTO
static void ssh_dh_debug(ssh_session session){
    ssh_print_bignum("p", session->next_crypto->p);
    ssh_print_bignum("g", session->next_crypto->g);
    ssh_print_bignum("x", session->next_crypto->x);
    ssh_print_bignum("y", session->next_crypto->y);
    ssh_print_bignum("e", session->next_crypto->e);
    ssh_print_bignum("f", session->next_crypto->f);

    ssh_print_hexa("Session server cookie",
                   session->next_crypto->server_kex.cookie, 16);
    ssh_print_hexa("Session client cookie",
                   session->next_crypto->client_kex.cookie, 16);
    ssh_print_bignum("k", session->next_crypto->k);
}
#else
#define ssh_dh_debug(session)
#endif

/** @internal
 * @brief generate a secret DH parameter between 1 and (p-1)/2
 * @param[out] dest preallocated bignum where to store the parameter
 * @return SSH_OK on success, SSH_ERROR on error
 */
int ssh_dh_generate_secret(ssh_session session, bignum dest){
    bignum one = NULL, p_half=NULL;
    int rc = 0;

    one = bignum_new();
    p_half = bignum_new();
    if (one == NULL || p_half == NULL){
        goto error;
    }

    /* creating a random between [0;(p-1)/2 -1[ */
    rc = bignum_set_word(one, 1);
    if (rc == 1) {
        /* p_half = (p-1)/2. p is prime so p>>1 == p-1 >> 1 */
        rc = bignum_rshift1(p_half, session->next_crypto->p);
    }
    if (rc == 1)
        rc = bignum_sub(p_half, p_half, one);
    if (rc == 1)
        rc = bignum_rand_range(dest, p_half);
    if (rc == 1)
        bignum_add(dest, dest, one);
    error:
    if (rc != 1){
        ssh_set_error_oom(session);
    }
    bignum_safe_free(one);
    bignum_safe_free(p_half);
    if (rc == 1){
        return SSH_OK;
    } else {
        return SSH_ERROR;
    }
}

int ssh_dh_build_k(ssh_session session) {
  bignum_CTX ctx = bignum_ctx_new();
  if (bignum_ctx_invalid(ctx)) {
    return -1;
  }

  /* the server and clients don't use the same numbers */
  if (session->client) {
    bignum_mod_exp(session->next_crypto->k, session->next_crypto->f,
        session->next_crypto->x, session->next_crypto->p, ctx);
  } else {
    bignum_mod_exp(session->next_crypto->k, session->next_crypto->e,
        session->next_crypto->y, session->next_crypto->p, ctx);
  }
  bignum_ctx_free(ctx);
  ssh_dh_debug();
  return 0;
}


static SSH_PACKET_CALLBACK(ssh_packet_client_dh_reply);

static ssh_packet_callback dh_client_callbacks[]= {
    ssh_packet_client_dh_reply
};

static struct ssh_packet_callbacks_struct ssh_dh_client_callbacks = {
    .start = SSH2_MSG_KEXDH_REPLY,
    .n_callbacks = 1,
    .callbacks = dh_client_callbacks,
    .user = NULL
};

/** @internal
 * @brief Starts diffie-hellman-group1 key exchange
 */
int ssh_client_dh_init(ssh_session session){
  int rc;
  bignum_CTX ctx = bignum_ctx_new();

  if (bignum_ctx_invalid(ctx)) {
    goto error;
  }
  rc = ssh_dh_init_common(session);
  if (rc == SSH_ERROR){
    goto error;
  }
  rc = ssh_dh_generate_secret(session, session->next_crypto->x);
  if (rc == SSH_ERROR){
      goto error;
  }
  session->next_crypto->e = bignum_new();
  if (session->next_crypto->e == NULL){
      goto error;
  }
  bignum_mod_exp(session->next_crypto->e, session->next_crypto->g, session->next_crypto->x,
      session->next_crypto->p, ctx);

  bignum_ctx_free(ctx);

  rc = ssh_buffer_pack(session->out_buffer, "bB", SSH2_MSG_KEXDH_INIT, session->next_crypto->e);
  if (rc != SSH_OK) {
    goto error;
  }

  /* register the packet callbacks */
  ssh_packet_set_callbacks(session, &ssh_dh_client_callbacks);
  session->dh_handshake_state = DH_STATE_INIT_SENT;

  rc = ssh_packet_send(session);
  return rc;
error:
  ssh_dh_cleanup(session->next_crypto);
  return SSH_ERROR;
}


SSH_PACKET_CALLBACK(ssh_packet_client_dh_reply){
  struct ssh_crypto_struct *crypto=session->next_crypto;
  int rc;
  (void)type;
  (void)user;

  ssh_packet_remove_callbacks(session, &ssh_dh_client_callbacks);
  rc = ssh_buffer_unpack(packet, "SBS", &crypto->server_pubkey, &crypto->f,
          &crypto->dh_server_signature);

  if (rc == SSH_ERROR){
    ssh_set_error(session, SSH_FATAL, "Invalid DH_REPLY packet");
    goto error;
  }

  rc = ssh_dh_build_k(session);
  if (rc == SSH_ERROR) {
    ssh_set_error(session, SSH_FATAL, "Could not generate shared secret");
    goto error;
  }

  /* Send the MSG_NEWKEYS */
  if (ssh_buffer_add_u8(session->out_buffer, SSH2_MSG_NEWKEYS) < 0) {
    goto error;
  }

  rc=ssh_packet_send(session);
  if (rc==SSH_ERROR){
      goto error;
  }
  SSH_LOG(SSH_LOG_PROTOCOL, "SSH_MSG_NEWKEYS sent");
  session->dh_handshake_state = DH_STATE_NEWKEYS_SENT;

  return SSH_PACKET_USED;
error:
  ssh_dh_cleanup(session->next_crypto);
  session->session_state=SSH_SESSION_STATE_ERROR;
  return SSH_PACKET_USED;
}

#ifdef WITH_SERVER

static SSH_PACKET_CALLBACK(ssh_packet_server_dh_init);

static ssh_packet_callback dh_server_callbacks[]= {
    ssh_packet_server_dh_init
};

static struct ssh_packet_callbacks_struct ssh_dh_server_callbacks = {
    .start = SSH2_MSG_KEXDH_INIT,
    .n_callbacks = 1,
    .callbacks = dh_server_callbacks,
    .user = NULL
};

/** @internal
 * @brief sets up the diffie-hellman-groupx kex callbacks
 */
void ssh_server_dh_init(ssh_session session){
    /* register the packet callbacks */
    ssh_packet_set_callbacks(session, &ssh_dh_server_callbacks);
    ssh_dh_init_common(session);
}

/** @internal
 * @brief processes a SSH_MSG_KEXDH_INIT or SSH_MSG_KEX_DH_GEX_INIT packet and send
 * the appropriate SSH_MSG_KEXDH_REPLY or SSH_MSG_KEXDEH_GEX_REPLY
 */
int ssh_server_dh_process_init(ssh_session session, ssh_buffer packet){
    ssh_key privkey;
    ssh_string sig_blob;
    int rc;
    int packet_type;
    bignum_CTX ctx = bignum_ctx_new();

    if (bignum_ctx_invalid(ctx)) {
      goto error;
    }
    rc = ssh_buffer_unpack(packet, "B", &session->next_crypto->e);
    if (rc == SSH_ERROR) {
        ssh_set_error(session, SSH_FATAL, "No e number in client request");
        goto error;
    }

    rc = ssh_dh_generate_secret(session, session->next_crypto->y);
    if (rc == SSH_ERROR){
        goto error;
    }

    session->next_crypto->f = bignum_new();
    if (session->next_crypto->f == NULL){
        goto error;
    }
    bignum_mod_exp(session->next_crypto->f, session->next_crypto->g, session->next_crypto->y,
            session->next_crypto->p, ctx);
    bignum_ctx_free(ctx);
    ctx = NULL;

    if (ssh_get_key_params(session,&privkey) != SSH_OK){
        goto error;
    }

    rc = ssh_dh_build_k(session);
    if (rc == SSH_ERROR) {
        ssh_set_error(session, SSH_FATAL, "Could not generate shared secret");
        goto error;
    }

    if (ssh_make_sessionid(session) != SSH_OK) {
        ssh_set_error(session, SSH_FATAL, "Could not create a session id");
        goto error;
    }

    sig_blob = ssh_srv_pki_do_sign_sessionid(session, privkey);
    if (sig_blob == NULL) {
        ssh_set_error(session, SSH_FATAL, "Could not sign the session id");
        goto error;
    }
    switch (session->next_crypto->kex_type){
    case SSH_KEX_DH_GROUP1_SHA1:
    case SSH_KEX_DH_GROUP14_SHA1:
        packet_type = SSH2_MSG_KEXDH_REPLY;
        break;
    case SSH_KEX_DH_GEX_SHA1:
    case SSH_KEX_DH_GEX_SHA256:
        packet_type = SSH2_MSG_KEX_DH_GEX_REPLY;
        break;
    default:
        ssh_set_error(session, SSH_FATAL, "Invalid kex type");
        goto error;
    }
    rc = ssh_buffer_pack(session->out_buffer,
            "bSBS",
            packet_type,
            session->next_crypto->server_pubkey,
            session->next_crypto->f,
            sig_blob);
    ssh_string_free(sig_blob);
    if(rc != SSH_OK){
        ssh_set_error_oom(session);
        ssh_buffer_reinit(session->out_buffer);
        goto error;
    }

    if (ssh_packet_send(session) == SSH_ERROR) {
        goto error;
    }
    SSH_LOG(SSH_LOG_DEBUG, "Sent KEX_DH_[GEX]_REPLY");
    if (ssh_buffer_add_u8(session->out_buffer, SSH2_MSG_NEWKEYS) < 0) {
        ssh_buffer_reinit(session->out_buffer);
        goto error;
    }
    session->dh_handshake_state=DH_STATE_NEWKEYS_SENT;

    if (ssh_packet_send(session) == SSH_ERROR) {
        goto error;
    }
    SSH_LOG(SSH_LOG_PACKET, "SSH_MSG_NEWKEYS sent");
    return SSH_OK;
error:
    if (!bignum_ctx_invalid(ctx)){
        bignum_ctx_free(ctx);
    }
    session->session_state=SSH_SESSION_STATE_ERROR;
    ssh_dh_cleanup(session->next_crypto);
    return SSH_ERROR;
}

/** @internal
 * @brief parse an incoming SSH_MSG_KEXDH_INIT packet and complete
 *        Diffie-Hellman key exchange
 **/
static SSH_PACKET_CALLBACK(ssh_packet_server_dh_init){
    (void)type;
    (void)user;
    SSH_LOG(SSH_LOG_DEBUG, "Received SSH_MSG_KEXDH_INIT");
    ssh_packet_remove_callbacks(session, &ssh_dh_server_callbacks);
    ssh_server_dh_process_init(session, packet);
    return SSH_PACKET_USED;
}

#endif /* WITH_SERVER */

/* vim: set ts=4 sw=4 et cindent: */

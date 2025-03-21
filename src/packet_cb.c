/*
 * packet.c - packet building functions
 *
 * This file is part of the SSH Library
 *
 * Copyright (c) 2011      Aris Adamantiadis
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

#include <stdlib.h>
#ifdef HAVE_ARPA_INET_H
#include <arpa/inet.h>
#endif

#include "libssh/priv.h"
#include "libssh/buffer.h"
#include "libssh/crypto.h"
#include "libssh/dh.h"
#include "libssh/misc.h"
#include "libssh/packet.h"
#include "libssh/pki.h"
#include "libssh/session.h"
#include "libssh/socket.h"
#include "libssh/ssh2.h"
#include "libssh/curve25519.h"

/**
 * @internal
 *
 * @brief Handle a SSH_DISCONNECT packet.
 */
SSH_PACKET_CALLBACK(ssh_packet_disconnect_callback)
{
    int rc;
    uint32_t code = 0;
    char *error = NULL;
    ssh_string error_s = NULL;

    (void)user;
    (void)type;

    rc = ssh_buffer_get_u32(packet, &code);
    if (rc != 0) {
        code = ntohl(code);
    }

    error_s = ssh_buffer_get_ssh_string(packet);
    if (error_s != NULL) {
        error = ssh_string_to_char(error_s);
        SSH_STRING_FREE(error_s);
    }

    if (error != NULL) {
        session->peer_discon_msg = strdup(error);
    }

    SSH_LOG(SSH_LOG_PACKET,
            "Received SSH_MSG_DISCONNECT %" PRIu32 ":%s",
            code,
            error != NULL ? error : "no error");
    ssh_set_error(session,
                  SSH_FATAL,
                  "Received SSH_MSG_DISCONNECT: %" PRIu32 ":%s",
                  code,
                  error != NULL ? error : "no error");
    SAFE_FREE(error);

    ssh_session_socket_close(session);
    /* correctly handle disconnect during authorization */
    session->auth.state = SSH_AUTH_STATE_FAILED;

    /* TODO: handle a graceful disconnect */
    return SSH_PACKET_USED;
}

/**
 * @internal
 *
 * @brief Handle a SSH_IGNORE packet.
 */
SSH_PACKET_CALLBACK(ssh_packet_ignore_callback)
{
    (void)session; /* unused */
    (void)user;
    (void)type;
    (void)packet;

    SSH_LOG(SSH_LOG_DEBUG, "Received SSH_MSG_IGNORE packet");

    return SSH_PACKET_USED;
}

/**
 * @internal
 *
 * @brief Handle a SSH_DEBUG packet.
 */
SSH_PACKET_CALLBACK(ssh_packet_debug_callback)
{
    uint8_t always_display = -1;
    char *message = NULL;
    int rc;

    (void)session; /* unused */
    (void)type;
    (void)user;

    rc = ssh_buffer_unpack(packet, "bs", &always_display, &message);
    if (rc != SSH_OK) {
        SSH_LOG(SSH_LOG_PACKET, "Error reading debug message");
        return SSH_PACKET_USED;
    }
    SSH_LOG(SSH_LOG_DEBUG,
            "Received SSH_MSG_DEBUG packet with message %s%s",
            message,
            always_display != 0 ? " (always display)" : "");
    SAFE_FREE(message);

    return SSH_PACKET_USED;
}

SSH_PACKET_CALLBACK(ssh_packet_newkeys)
{
    ssh_string sig_blob = NULL;
    ssh_signature sig = NULL;
    int rc;

    (void)packet;
    (void)user;
    (void)type;

    SSH_LOG(SSH_LOG_DEBUG, "Received SSH_MSG_NEWKEYS");

    if (session->session_state != SSH_SESSION_STATE_DH ||
        session->dh_handshake_state != DH_STATE_NEWKEYS_SENT) {
        ssh_set_error(session,
                      SSH_FATAL,
                      "ssh_packet_newkeys called in wrong state : %d:%d",
                      session->session_state,
                      session->dh_handshake_state);
        goto error;
    }

    if (session->flags & SSH_SESSION_FLAG_KEX_STRICT) {
        /* reset packet sequence number when running in strict kex mode */
        session->recv_seq = 0;
        /* Check that we aren't tainted */
        if (session->flags & SSH_SESSION_FLAG_KEX_TAINTED) {
            ssh_set_error(session,
                          SSH_FATAL,
                          "Received unexpected packets in strict KEX mode.");
            goto error;
        }
    }

    if (session->server) {
        /* server things are done in server.c */
        session->dh_handshake_state=DH_STATE_FINISHED;
    } else {
        ssh_key server_key = NULL;

        /* client */

        /* Verify the host's signature. FIXME do it sooner */
        sig_blob = session->next_crypto->dh_server_signature;
        session->next_crypto->dh_server_signature = NULL;

        /* get the server public key */
        server_key = ssh_dh_get_next_server_publickey(session);
        if (server_key == NULL) {
            goto error;
        }

        rc = ssh_pki_import_signature_blob(sig_blob, server_key, &sig);
        ssh_string_burn(sig_blob);
        SSH_STRING_FREE(sig_blob);
        if (rc != SSH_OK) {
            goto error;
        }

        /* Check if signature from server matches user preferences */
        if (session->opts.wanted_methods[SSH_HOSTKEYS]) {
            rc = match_group(session->opts.wanted_methods[SSH_HOSTKEYS],
                             sig->type_c);
            if (rc == 0) {
                ssh_set_error(session,
                              SSH_FATAL,
                              "Public key from server (%s) doesn't match user "
                              "preference (%s)",
                              sig->type_c,
                              session->opts.wanted_methods[SSH_HOSTKEYS]);
                goto error;
            }
        }

        rc = ssh_pki_signature_verify(session,
                                      sig,
                                      server_key,
                                      session->next_crypto->secret_hash,
                                      session->next_crypto->digest_len);
        SSH_SIGNATURE_FREE(sig);
        if (rc == SSH_ERROR) {
            ssh_set_error(session,
                          SSH_FATAL,
                          "Failed to verify server hostkey signature");
            goto error;
        }
        SSH_LOG(SSH_LOG_DEBUG, "Signature verified and valid");

        /* When receiving this packet, we switch on the incoming crypto. */
        rc = ssh_packet_set_newkeys(session, SSH_DIRECTION_IN);
        if (rc != SSH_OK) {
            goto error;
        }
    }
    session->dh_handshake_state = DH_STATE_FINISHED;
    session->ssh_connection_callback(session);
    return SSH_PACKET_USED;

error:
    SSH_SIGNATURE_FREE(sig);
    ssh_string_burn(sig_blob);
    SSH_STRING_FREE(sig_blob);
    session->session_state = SSH_SESSION_STATE_ERROR;
    return SSH_PACKET_USED;
}

/**
 * @internal
 * @brief handles a SSH_SERVICE_ACCEPT packet
 *
 */
SSH_PACKET_CALLBACK(ssh_packet_service_accept)
{
    (void)packet;
    (void)type;
    (void)user;

    session->auth.service_state = SSH_AUTH_SERVICE_ACCEPTED;
    SSH_LOG(SSH_LOG_PACKET, "Received SSH_MSG_SERVICE_ACCEPT");

    return SSH_PACKET_USED;
}

/**
 * @internal
 * @brief handles a SSH2_MSG_EXT_INFO packet defined in RFC 8308
 *
 */
SSH_PACKET_CALLBACK(ssh_packet_ext_info)
{
    int rc;
    uint32_t nr_extensions = 0;
    uint32_t i;

    (void)type;
    (void)user;

    SSH_LOG(SSH_LOG_PACKET, "Received SSH_MSG_EXT_INFO");

    rc = ssh_buffer_get_u32(packet, &nr_extensions);
    if (rc == 0) {
        SSH_LOG(SSH_LOG_PACKET, "Failed to read number of extensions");
        return SSH_PACKET_USED;
    }

    nr_extensions = ntohl(nr_extensions);
    if (nr_extensions > 128) {
        SSH_LOG(SSH_LOG_PACKET, "Invalid number of extensions");
        return SSH_PACKET_USED;
    }

    SSH_LOG(SSH_LOG_PACKET, "Follows %" PRIu32 " extensions", nr_extensions);

    for (i = 0; i < nr_extensions; i++) {
        char *name = NULL;
        char *value = NULL;

        rc = ssh_buffer_unpack(packet, "ss", &name, &value);
        if (rc != SSH_OK) {
            SSH_LOG(SSH_LOG_PACKET, "Error reading extension name-value pair");
            return SSH_PACKET_USED;
        }

        if (strcmp(name, "server-sig-algs") == 0) {
            /* TODO check for NULL bytes */
            SSH_LOG(SSH_LOG_PACKET, "Extension: %s=<%s>", name, value);

            rc = match_group(value, "rsa-sha2-512");
            if (rc == 1) {
                session->extensions |= SSH_EXT_SIG_RSA_SHA512;
            }

            rc = match_group(value, "rsa-sha2-256");
            if (rc == 1) {
                session->extensions |= SSH_EXT_SIG_RSA_SHA256;
            }
        } else if (strcmp(name, "publickey-hostbound@openssh.com") == 0) {
            SSH_LOG(SSH_LOG_PACKET, "Extension: %s=<%s>", name, value);
            session->extensions |= SSH_EXT_PUBLICKEY_HOSTBOUND;
        } else {
            SSH_LOG(SSH_LOG_PACKET, "Unknown extension: %s", name);
        }
        free(name);
        free(value);
    }

    return SSH_PACKET_USED;
}

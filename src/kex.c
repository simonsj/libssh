/*
 * kex.c - key exchange
 *
 * This file is part of the SSH Library
 *
 * Copyright (c) 2003-2008 by Aris Adamantiadis
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

#include <string.h>
#include <stdlib.h>
#include <stdio.h>

#include "libssh/priv.h"
#include "libssh/buffer.h"
#include "libssh/dh.h"
#include "libssh/kex.h"
#include "libssh/session.h"
#include "libssh/ssh2.h"
#include "libssh/string.h"
#include "libssh/curve25519.h"
#include "libssh/knownhosts.h"
#include "libssh/bignum.h"

#ifdef HAVE_LIBGCRYPT
# define BLOWFISH "blowfish-cbc,"
# define AES "aes256-ctr,aes192-ctr,aes128-ctr,aes256-cbc,aes192-cbc,aes128-cbc,"
# define DES "3des-cbc"
# define DES_SUPPORTED "3des-cbc,des-cbc-ssh1"

#elif defined(HAVE_LIBCRYPTO)

# ifdef HAVE_OPENSSL_BLOWFISH_H
#  define BLOWFISH "blowfish-cbc,"
# else /* HAVE_OPENSSL_BLOWFISH_H */
#  define BLOWFISH ""
# endif /* HAVE_OPENSSL_BLOWFISH_H */

# ifdef HAVE_OPENSSL_AES_H
#  ifdef BROKEN_AES_CTR
#   define AES "aes256-cbc,aes192-cbc,aes128-cbc,"
#  else /* BROKEN_AES_CTR */
#   define AES "aes256-ctr,aes192-ctr,aes128-ctr,aes256-cbc,aes192-cbc,aes128-cbc,"
#  endif /* BROKEN_AES_CTR */
# else /* HAVE_OPENSSL_AES_H */
#  define AES ""
# endif /* HAVE_OPENSSL_AES_H */

# define DES "3des-cbc"
# define DES_SUPPORTED "3des-cbc,des-cbc-ssh1"
#endif /* HAVE_LIBCRYPTO */

#ifdef WITH_ZLIB
#define ZLIB "none,zlib,zlib@openssh.com"
#else
#define ZLIB "none"
#endif

#ifdef HAVE_CURVE25519
#define CURVE25519 "curve25519-sha256@libssh.org,"
#else
#define CURVE25519 ""
#endif

#ifdef HAVE_ECDH
#define ECDH "ecdh-sha2-nistp256,"
#define HOSTKEYS "ssh-ed25519,ecdsa-sha2-nistp256,ecdsa-sha2-nistp384,ecdsa-sha2-nistp521,ssh-rsa,ssh-dss"
#else
#define HOSTKEYS "ssh-ed25519,ssh-rsa,ssh-dss"
#define ECDH ""
#endif

#define CHACHA20 "chacha20-poly1305@openssh.com,"

#define KEY_EXCHANGE CURVE25519 ECDH "diffie-hellman-group-exchange-sha256,diffie-hellman-group-exchange-sha1,diffie-hellman-group14-sha1,diffie-hellman-group1-sha1"
#define KEX_METHODS_SIZE 10

/* NOTE: This is a fixed API and the index is defined by ssh_kex_types_e */
static const char *default_methods[] = {
  KEY_EXCHANGE,
  HOSTKEYS,
  AES BLOWFISH DES,
  AES BLOWFISH DES,
  "hmac-sha2-256,hmac-sha2-512,hmac-sha1",
  "hmac-sha2-256,hmac-sha2-512,hmac-sha1",
  "none",
  "none",
  "",
  "",
  NULL
};

/* NOTE: This is a fixed API and the index is defined by ssh_kex_types_e */
static const char *supported_methods[] = {
  KEY_EXCHANGE,
  HOSTKEYS,
  CHACHA20 AES BLOWFISH DES_SUPPORTED,
  CHACHA20 AES BLOWFISH DES_SUPPORTED,
  "hmac-sha2-256,hmac-sha2-512,hmac-sha1",
  "hmac-sha2-256,hmac-sha2-512,hmac-sha1",
  ZLIB,
  ZLIB,
  "",
  "",
  NULL
};

/* descriptions of the key exchange packet */
static const char *ssh_kex_descriptions[] = {
  "kex algos",
  "server host key algo",
  "encryption client->server",
  "encryption server->client",
  "mac algo client->server",
  "mac algo server->client",
  "compression algo client->server",
  "compression algo server->client",
  "languages client->server",
  "languages server->client",
  NULL
};

/* tokenize will return a token of strings delimited by ",". the first element has to be freed */
static char **tokenize(const char *chain){
    char **tokens;
    int n=1;
    int i=0;
    char *tmp;
    char *ptr;

    tmp = strdup(chain);
    if (tmp == NULL) {
      return NULL;
    }
    ptr = tmp;
    while(*ptr){
        if(*ptr==','){
            n++;
            *ptr=0;
        }
        ptr++;
    }
    /* now n contains the number of tokens, the first possibly empty if the list was empty too e.g. "" */
    tokens=malloc(sizeof(char *) * (n+1) ); /* +1 for the null */
    if (tokens == NULL) {
      SAFE_FREE(tmp);
      return NULL;
    }
    ptr=tmp;
    for(i=0;i<n;i++){
        tokens[i]=ptr;
        while(*ptr)
            ptr++; // find a zero
        ptr++; // then go one step further
    }
    tokens[i]=NULL;
    return tokens;
}

/* same as tokenize(), but with spaces instead of ',' */
/* TODO FIXME rewrite me! */
char **ssh_space_tokenize(const char *chain){
    char **tokens;
    int n=1;
    int i=0;
    char *tmp;
    char *ptr;

    tmp = strdup(chain);
    if (tmp == NULL) {
      return NULL;
    }
    ptr = tmp;

    while(*ptr==' ')
        ++ptr; /* skip initial spaces */
    while(*ptr){
        if(*ptr==' '){
            n++; /* count one token per word */
            *ptr=0;
            while(*(ptr+1)==' '){ /* don't count if the tokens have more than 2 spaces */
                *(ptr++)=0;
            }
        }
        ptr++;
    }
    /* now n contains the number of tokens, the first possibly empty if the list was empty too e.g. "" */
    tokens = malloc(sizeof(char *) * (n + 1)); /* +1 for the null */
    if (tokens == NULL) {
      SAFE_FREE(tmp);
      return NULL;
    }
    ptr=tmp; /* we don't pass the initial spaces because the "tmp" pointer is needed by the caller */
                    /* function to free the tokens. */
    for(i=0;i<n;i++){
        tokens[i]=ptr;
        if(i!=n-1){
            while(*ptr)
                ptr++; // find a zero
            while(!*(ptr+1))
                ++ptr; /* if the zero is followed by other zeros, go through them */
            ptr++; // then go one step further
        }
    }
    tokens[i]=NULL;
    return tokens;
}

const char *ssh_kex_get_supported_method(uint32_t algo) {
  if (algo >= KEX_METHODS_SIZE) {
    return NULL;
  }

  return supported_methods[algo];
}

const char *ssh_kex_get_description(uint32_t algo) {
  if (algo >= KEX_METHODS_SIZE) {
    return NULL;
  }

  return ssh_kex_descriptions[algo];
}

/* find_matching gets 2 parameters : a list of available objects (available_d), separated by colons,*/
/* and a list of preferred objects (preferred_d) */
/* it will return a strduped pointer on the first preferred object found in the available objects list */

char *ssh_find_matching(const char *available_d, const char *preferred_d){
    char ** tok_available, **tok_preferred;
    int i_avail, i_pref;
    char *ret;

    if ((available_d == NULL) || (preferred_d == NULL)) {
      return NULL; /* don't deal with null args */
    }

    tok_available = tokenize(available_d);
    if (tok_available == NULL) {
      return NULL;
    }

    tok_preferred = tokenize(preferred_d);
    if (tok_preferred == NULL) {
      SAFE_FREE(tok_available[0]);
      SAFE_FREE(tok_available);
      return NULL;
    }

    for(i_pref=0; tok_preferred[i_pref] ; ++i_pref){
      for(i_avail=0; tok_available[i_avail]; ++i_avail){
        if(strcmp(tok_available[i_avail],tok_preferred[i_pref]) == 0){
          /* match */
          ret=strdup(tok_available[i_avail]);
          /* free the tokens */
          SAFE_FREE(tok_available[0]);
          SAFE_FREE(tok_preferred[0]);
          SAFE_FREE(tok_available);
          SAFE_FREE(tok_preferred);
          return ret;
        }
      }
    }
    SAFE_FREE(tok_available[0]);
    SAFE_FREE(tok_preferred[0]);
    SAFE_FREE(tok_available);
    SAFE_FREE(tok_preferred);
    return NULL;
}

/**
 * @internal
 * @brief returns whether the first client key exchange algorithm or
 *        hostkey type matches its server counterpart
 * @returns whether the first client key exchange algorithm or hostkey type
 *          matches its server counterpart
 */
static int cmp_first_kex_algo(const char *client_str,
                              const char *server_str) {
    int is_wrong = 1;
    char **server_str_tokens = NULL;
    char **client_str_tokens = NULL;

    if ((client_str == NULL) || (server_str == NULL)) {
        goto out;
    }

    client_str_tokens = tokenize(client_str);

    if (client_str_tokens == NULL) {
        goto out;
    }

    if (client_str_tokens[0] == NULL) {
        goto freeout;
    }

    server_str_tokens = tokenize(server_str);
    if (server_str_tokens == NULL) {
        goto freeout;
    }

    is_wrong = (strcmp(client_str_tokens[0], server_str_tokens[0]) != 0);

    SAFE_FREE(server_str_tokens[0]);
    SAFE_FREE(server_str_tokens);
freeout:
    SAFE_FREE(client_str_tokens[0]);
    SAFE_FREE(client_str_tokens);
out:
    return is_wrong;
}

SSH_PACKET_CALLBACK(ssh_packet_kexinit){
    int i;
    int server_kex=session->server;
    ssh_string str = NULL;
    char *strings[KEX_METHODS_SIZE];
    int rc = SSH_ERROR;

    uint8_t first_kex_packet_follows = 0;
    uint32_t kexinit_reserved = 0;

    (void)type;
    (void)user;

    memset(strings, 0, sizeof(strings));
    if (session->session_state == SSH_SESSION_STATE_AUTHENTICATED){
        SSH_LOG(SSH_LOG_WARNING, "Other side initiating key re-exchange");
    } else if(session->session_state != SSH_SESSION_STATE_INITIAL_KEX){
        ssh_set_error(session,SSH_FATAL,"SSH_KEXINIT received in wrong state");
        goto error;
    }

    if (server_kex) {
        rc = ssh_buffer_get_data(packet,session->next_crypto->client_kex.cookie, 16);
        if (rc != 16) {
            ssh_set_error(session, SSH_FATAL, "ssh_packet_kexinit: no cookie in packet");
            goto error;
        }

        rc = ssh_hashbufin_add_cookie(session, session->next_crypto->client_kex.cookie);
        if (rc < 0) {
            ssh_set_error(session, SSH_FATAL, "ssh_packet_kexinit: adding cookie failed");
            goto error;
        }
    } else {
        rc = ssh_buffer_get_data(packet,session->next_crypto->server_kex.cookie, 16);
        if (rc != 16) {
            ssh_set_error(session, SSH_FATAL, "ssh_packet_kexinit: no cookie in packet");
            goto error;
        }

        rc = ssh_hashbufin_add_cookie(session, session->next_crypto->server_kex.cookie);
        if (rc < 0) {
            ssh_set_error(session, SSH_FATAL, "ssh_packet_kexinit: adding cookie failed");
            goto error;
        }
    }

    for (i = 0; i < KEX_METHODS_SIZE; i++) {
        str = ssh_buffer_get_ssh_string(packet);
        if (str == NULL) {
          goto error;
        }

        rc = ssh_buffer_add_ssh_string(session->in_hashbuf, str);
        if (rc < 0) {
            ssh_set_error(session, SSH_FATAL, "Error adding string in hash buffer");
            goto error;
        }

        strings[i] = ssh_string_to_char(str);
        if (strings[i] == NULL) {
            ssh_set_error_oom(session);
            goto error;
        }
        ssh_string_free(str);
        str = NULL;
    }

    /* copy the server kex info into an array of strings */
    if (server_kex) {
        for (i = 0; i < SSH_KEX_METHODS; i++) {
            session->next_crypto->client_kex.methods[i] = strings[i];
        }
    } else { /* client */
        for (i = 0; i < SSH_KEX_METHODS; i++) {
            session->next_crypto->server_kex.methods[i] = strings[i];
        }
    }

    /*
     * Handle the two final fields for the KEXINIT message (RFC 4253 7.1):
     *
     *      boolean      first_kex_packet_follows
     *      uint32       0 (reserved for future extension)
     *
     * Notably if clients set 'first_kex_packet_follows', it is expected
     * that its value is included when computing the session ID (see
     * 'make_sessionid').
     */
    if (server_kex) {
        rc = ssh_buffer_get_u8(packet, &first_kex_packet_follows);
        if (rc != 1) {
            goto error;
        }

        rc = ssh_buffer_add_u8(session->in_hashbuf, first_kex_packet_follows);
        if (rc < 0) {
            goto error;
        }

        rc = ssh_buffer_add_u32(session->in_hashbuf, kexinit_reserved);
        if (rc < 0) {
            goto error;
        }

        /*
         * Remember whether 'first_kex_packet_follows' was set and the client
         * guess was wrong: in this case the next SSH_MSG_KEXDH_INIT message
         * must be ignored.
         */
        if (first_kex_packet_follows) {
          session->first_kex_follows_guess_wrong =
            cmp_first_kex_algo(session->next_crypto->client_kex.methods[SSH_KEX],
                               session->next_crypto->server_kex.methods[SSH_KEX]) ||
            cmp_first_kex_algo(session->next_crypto->client_kex.methods[SSH_HOSTKEYS],
                               session->next_crypto->server_kex.methods[SSH_HOSTKEYS]);
        }
    }

    session->session_state = SSH_SESSION_STATE_KEXINIT_RECEIVED;
    session->dh_handshake_state = DH_STATE_INIT;
    session->ssh_connection_callback(session);
    return SSH_PACKET_USED;

error:
    ssh_string_free(str);
    for (i = 0; i < SSH_KEX_METHODS; i++) {
        if (server_kex) {
            session->next_crypto->client_kex.methods[i] = NULL;
        } else { /* client */
            session->next_crypto->server_kex.methods[i] = NULL;
        }
        SAFE_FREE(strings[i]);
    }

    session->session_state = SSH_SESSION_STATE_ERROR;

    return SSH_PACKET_USED;
}

void ssh_list_kex(struct ssh_kex_struct *kex) {
  int i = 0;

#ifdef DEBUG_CRYPTO
  ssh_print_hexa("session cookie", kex->cookie, 16);
#endif

  for(i = 0; i < SSH_KEX_METHODS; i++) {
    if (kex->methods[i] == NULL) {
      continue;
    }
    SSH_LOG(SSH_LOG_FUNCTIONS, "%s: %s",
        ssh_kex_descriptions[i], kex->methods[i]);
  }
}

/**
 * @internal
 * @brief selects the hostkey mechanisms to be chosen for the key exchange,
 * as some hostkey mechanisms may be present in known_hosts file and preferred
 * @returns a cstring containing a comma-separated list of hostkey methods.
 *          NULL if no method matches
 */
static char *ssh_client_select_hostkeys(ssh_session session){
    char methods_buffer[128]={0};
    static const char *preferred_hostkeys[] = {
        "ssh-ed25519",
        "ecdsa-sha2-nistp521",
        "ecdsa-sha2-nistp384",
        "ecdsa-sha2-nistp256",
        "ssh-rsa",
        "ssh-dss",
        "ssh-rsa1",
        NULL
    };
    char **methods;
    int i,j;
    int needcoma=0;

    methods = ssh_knownhosts_algorithms(session);
	if (methods == NULL || methods[0] == NULL){
		SAFE_FREE(methods);
		return NULL;
	}

	for (i=0;preferred_hostkeys[i] != NULL; ++i){
		for (j=0; methods[j] != NULL; ++j){
			if(strcmp(preferred_hostkeys[i], methods[j]) == 0){
				if (ssh_verify_existing_algo(SSH_HOSTKEYS, methods[j])){
					if(needcoma)
						strncat(methods_buffer,",",sizeof(methods_buffer)-strlen(methods_buffer)-1);
					strncat(methods_buffer, methods[j], sizeof(methods_buffer)-strlen(methods_buffer)-1);
					needcoma = 1;
				}
			}
		}
	}
	for(i=0;methods[i]!= NULL; ++i){
		SAFE_FREE(methods[i]);
	}
	SAFE_FREE(methods);

	if(strlen(methods_buffer) > 0){
		SSH_LOG(SSH_LOG_DEBUG, "Changing host key method to \"%s\"", methods_buffer);
		return strdup(methods_buffer);
	} else {
		SSH_LOG(SSH_LOG_DEBUG, "No supported kex method for existing key in known_hosts file");
		return NULL;
	}

}
/**
 * @brief sets the key exchange parameters to be sent to the server,
 *        in function of the options and available methods.
 */
int ssh_set_client_kex(ssh_session session){
    struct ssh_kex_struct *client= &session->next_crypto->client_kex;
    const char *wanted;
    int i;

    ssh_get_random(client->cookie, 16, 0);

    memset(client->methods, 0, KEX_METHODS_SIZE * sizeof(char **));
    /* first check if we have specific host key methods */
    if(session->opts.wanted_methods[SSH_HOSTKEYS] == NULL){
    	/* Only if no override */
    	session->opts.wanted_methods[SSH_HOSTKEYS] =
    			ssh_client_select_hostkeys(session);
    }

    for (i = 0; i < KEX_METHODS_SIZE; i++) {
        wanted = session->opts.wanted_methods[i];
        if (wanted == NULL)
            wanted = default_methods[i];
        client->methods[i] = strdup(wanted);
    }

    return SSH_OK;
}

/** @brief Select the different methods on basis of client's and
 * server's kex messages, and watches out if a match is possible.
 */
int ssh_kex_select_methods (ssh_session session){
    struct ssh_kex_struct *server = &session->next_crypto->server_kex;
    struct ssh_kex_struct *client = &session->next_crypto->client_kex;
    int i;

    for (i = 0; i < KEX_METHODS_SIZE; i++) {
        session->next_crypto->kex_methods[i]=ssh_find_matching(server->methods[i],client->methods[i]);
        if(session->next_crypto->kex_methods[i] == NULL && i < SSH_LANG_C_S){
            ssh_set_error(session,SSH_FATAL,"kex error : no match for method %s: server [%s], client [%s]",
                    ssh_kex_descriptions[i],server->methods[i],client->methods[i]);
            return SSH_ERROR;
        } else if ((i >= SSH_LANG_C_S) && (session->next_crypto->kex_methods[i] == NULL)) {
            /* we can safely do that for languages */
            session->next_crypto->kex_methods[i] = strdup("");
        }
    }
    if(strcmp(session->next_crypto->kex_methods[SSH_KEX], "diffie-hellman-group1-sha1") == 0){
      session->next_crypto->kex_type=SSH_KEX_DH_GROUP1_SHA1;
    } else if(strcmp(session->next_crypto->kex_methods[SSH_KEX], "diffie-hellman-group14-sha1") == 0){
      session->next_crypto->kex_type=SSH_KEX_DH_GROUP14_SHA1;
    } else if(strcmp(session->next_crypto->kex_methods[SSH_KEX], "diffie-hellman-group-exchange-sha1") == 0){
      session->next_crypto->kex_type=SSH_KEX_DH_GEX_SHA1;
    } else if(strcmp(session->next_crypto->kex_methods[SSH_KEX], "diffie-hellman-group-exchange-sha256") == 0){
        session->next_crypto->kex_type=SSH_KEX_DH_GEX_SHA256;
    } else if(strcmp(session->next_crypto->kex_methods[SSH_KEX], "ecdh-sha2-nistp256") == 0){
      session->next_crypto->kex_type=SSH_KEX_ECDH_SHA2_NISTP256;
    } else if(strcmp(session->next_crypto->kex_methods[SSH_KEX], "curve25519-sha256@libssh.org") == 0){
      session->next_crypto->kex_type=SSH_KEX_CURVE25519_SHA256_LIBSSH_ORG;
    }
    SSH_LOG(SSH_LOG_INFO, "Negotiated %s,%s,%s,%s,%s,%s,%s,%s,%s,%s",
            session->next_crypto->kex_methods[SSH_KEX],
            session->next_crypto->kex_methods[SSH_HOSTKEYS],
            session->next_crypto->kex_methods[SSH_CRYPT_C_S],
            session->next_crypto->kex_methods[SSH_CRYPT_S_C],
            session->next_crypto->kex_methods[SSH_MAC_C_S],
            session->next_crypto->kex_methods[SSH_MAC_S_C],
            session->next_crypto->kex_methods[SSH_COMP_C_S],
            session->next_crypto->kex_methods[SSH_COMP_S_C],
            session->next_crypto->kex_methods[SSH_LANG_C_S],
            session->next_crypto->kex_methods[SSH_LANG_S_C]
    );
    return SSH_OK;
}


/* this function only sends the predefined set of kex methods */
int ssh_send_kex(ssh_session session, int server_kex) {
  struct ssh_kex_struct *kex = (server_kex ? &session->next_crypto->server_kex :
      &session->next_crypto->client_kex);
  ssh_string str = NULL;
  int i;
  int rc;

  rc = ssh_buffer_pack(session->out_buffer,
                       "bP",
                       SSH2_MSG_KEXINIT,
                       16,
                       kex->cookie); /* cookie */
  if (rc != SSH_OK)
    goto error;
  if (ssh_hashbufout_add_cookie(session) < 0) {
    goto error;
  }

  ssh_list_kex(kex);

  for (i = 0; i < KEX_METHODS_SIZE; i++) {
    str = ssh_string_from_char(kex->methods[i]);
    if (str == NULL) {
      goto error;
    }

    if (ssh_buffer_add_ssh_string(session->out_hashbuf, str) < 0) {
      goto error;
    }
    if (ssh_buffer_add_ssh_string(session->out_buffer, str) < 0) {
      goto error;
    }
    ssh_string_free(str);
    str = NULL;
  }

  rc = ssh_buffer_pack(session->out_buffer,
                       "bd",
                       0,
                       0);
  if (rc != SSH_OK) {
    goto error;
  }

  if (ssh_packet_send(session) == SSH_ERROR) {
    return -1;
  }

  return 0;
error:
  ssh_buffer_reinit(session->out_buffer);
  ssh_buffer_reinit(session->out_hashbuf);
  ssh_string_free(str);

  return -1;
}

/* returns 1 if at least one of the name algos is in the default algorithms table */
int ssh_verify_existing_algo(int algo, const char *name){
    char *ptr;
    if(algo>9 || algo <0)
        return -1;
    ptr=ssh_find_matching(supported_methods[algo],name);
    if(ptr){
        free(ptr);
        return 1;
    }
    return 0;
}

int ssh_make_sessionid(ssh_session session) {
    ssh_string num = NULL;
    ssh_buffer server_hash = NULL;
    ssh_buffer client_hash = NULL;
    ssh_buffer buf = NULL;
    int rc = SSH_ERROR;

    buf = ssh_buffer_new();
    if (buf == NULL) {
        return rc;
    }

    rc = ssh_buffer_pack(buf,
                         "ss",
                         session->clientbanner,
                         session->serverbanner);
    if (rc == SSH_ERROR) {
        goto error;
    }

    if (session->client) {
        server_hash = session->in_hashbuf;
        client_hash = session->out_hashbuf;
    } else {
        server_hash = session->out_hashbuf;
        client_hash = session->in_hashbuf;
    }

    /*
     * Handle the two final fields for the KEXINIT message (RFC 4253 7.1):
     *
     *      boolean      first_kex_packet_follows
     *      uint32       0 (reserved for future extension)
     */
    rc = ssh_buffer_add_u8(server_hash, 0);
    if (rc < 0) {
        goto error;
    }
    rc = ssh_buffer_add_u32(server_hash, 0);
    if (rc < 0) {
        goto error;
    }

    /* These fields are handled for the server case in ssh_packet_kexinit. */
    if (session->client) {
        rc = ssh_buffer_add_u8(client_hash, 0);
        if (rc < 0) {
            goto error;
        }
        rc = ssh_buffer_add_u32(client_hash, 0);
        if (rc < 0) {
            goto error;
        }
    }

    rc = ssh_buffer_pack(buf,
                         "dPdPS",
                         ssh_buffer_get_len(client_hash),
                         ssh_buffer_get_len(client_hash),
                         ssh_buffer_get(client_hash),
                         ssh_buffer_get_len(server_hash),
                         ssh_buffer_get_len(server_hash),
                         ssh_buffer_get(server_hash),
                         session->next_crypto->server_pubkey);

    if(rc != SSH_OK){
        goto error;
    }

    switch(session->next_crypto->kex_type){
        case SSH_KEX_DH_GROUP1_SHA1:
        case SSH_KEX_DH_GROUP14_SHA1:
            rc = ssh_buffer_pack(buf,
                             "BB",
                             session->next_crypto->e,
                             session->next_crypto->f);
            if (rc != SSH_OK) {
                goto error;
            }
            break;
        case SSH_KEX_DH_GEX_SHA1:
        case SSH_KEX_DH_GEX_SHA256:
            rc = ssh_buffer_pack(buf,
                    "dddBBBB",
                    session->next_crypto->dh_pmin,
                    session->next_crypto->dh_pn,
                    session->next_crypto->dh_pmax,
                    session->next_crypto->p,
                    session->next_crypto->g,
                    session->next_crypto->e,
                    session->next_crypto->f);
            if (rc != SSH_OK) {
                goto error;
            }
            break;
#ifdef HAVE_ECDH
        case SSH_KEX_ECDH_SHA2_NISTP256:
            if (session->next_crypto->ecdh_client_pubkey == NULL ||
                    session->next_crypto->ecdh_server_pubkey == NULL) {
                SSH_LOG(SSH_LOG_WARNING, "ECDH parameted missing");
                goto error;
            }
            rc = ssh_buffer_pack(buf,
                    "SS",
                    session->next_crypto->ecdh_client_pubkey,
                    session->next_crypto->ecdh_server_pubkey);
            if (rc != SSH_OK) {
                goto error;
            }
            break;
#endif
#ifdef HAVE_CURVE25519
        case SSH_KEX_CURVE25519_SHA256_LIBSSH_ORG:
            rc = ssh_buffer_pack(buf,
                    "dPdP",
                    CURVE25519_PUBKEY_SIZE,
                    (size_t)CURVE25519_PUBKEY_SIZE, session->next_crypto->curve25519_client_pubkey,
                    CURVE25519_PUBKEY_SIZE,
                    (size_t)CURVE25519_PUBKEY_SIZE, session->next_crypto->curve25519_server_pubkey);

            if (rc != SSH_OK) {
                goto error;
            }
            break;
#endif
    }
    rc = ssh_buffer_pack(buf, "B", session->next_crypto->k);
    if (rc != SSH_OK) {
        goto error;
    }

#ifdef DEBUG_CRYPTO
    ssh_print_hexa("hash buffer", ssh_buffer_get_begin(buf), ssh_buffer_get_len(buf));
#endif

    switch (session->next_crypto->kex_type) {
    case SSH_KEX_DH_GROUP1_SHA1:
    case SSH_KEX_DH_GROUP14_SHA1:
    case SSH_KEX_DH_GEX_SHA1:
        session->next_crypto->digest_len = SHA_DIGEST_LENGTH;
        session->next_crypto->mac_type = SSH_MAC_SHA1;
        session->next_crypto->secret_hash = malloc(session->next_crypto->digest_len);
        if (session->next_crypto->secret_hash == NULL) {
            ssh_set_error_oom(session);
            goto error;
        }
        sha1(ssh_buffer_get(buf), ssh_buffer_get_len(buf),
                                   session->next_crypto->secret_hash);
        break;
    case SSH_KEX_ECDH_SHA2_NISTP256:
    case SSH_KEX_CURVE25519_SHA256_LIBSSH_ORG:
    case SSH_KEX_DH_GEX_SHA256:
        session->next_crypto->digest_len = SHA256_DIGEST_LENGTH;
        session->next_crypto->mac_type = SSH_MAC_SHA256;
        session->next_crypto->secret_hash = malloc(session->next_crypto->digest_len);
        if (session->next_crypto->secret_hash == NULL) {
            ssh_set_error_oom(session);
            goto error;
        }
        sha256(ssh_buffer_get(buf), ssh_buffer_get_len(buf),
                                     session->next_crypto->secret_hash);
        break;
    }
    /* During the first kex, secret hash and session ID are equal. However, after
     * a key re-exchange, a new secret hash is calculated. This hash will not replace
     * but complement existing session id.
     */
    if (!session->next_crypto->session_id) {
        session->next_crypto->session_id = malloc(session->next_crypto->digest_len);
        if (session->next_crypto->session_id == NULL) {
            ssh_set_error_oom(session);
            goto error;
        }
        memcpy(session->next_crypto->session_id, session->next_crypto->secret_hash,
                session->next_crypto->digest_len);
    }
#ifdef DEBUG_CRYPTO
    printf("Session hash: \n");
    ssh_print_hexa("secret hash", session->next_crypto->secret_hash, session->next_crypto->digest_len);
    ssh_print_hexa("session id", session->next_crypto->session_id, session->next_crypto->digest_len);
#endif

    rc = SSH_OK;
error:
    ssh_buffer_free(buf);
    ssh_buffer_free(client_hash);
    ssh_buffer_free(server_hash);

    session->in_hashbuf = NULL;
    session->out_hashbuf = NULL;

    ssh_string_free(num);

    return rc;
}

int ssh_hashbufout_add_cookie(ssh_session session) {
  session->out_hashbuf = ssh_buffer_new();
  if (session->out_hashbuf == NULL) {
    return -1;
  }

  if (ssh_buffer_add_u8(session->out_hashbuf, 20) < 0) {
    ssh_buffer_reinit(session->out_hashbuf);
    return -1;
  }

  if (session->server) {
    if (ssh_buffer_add_data(session->out_hashbuf,
          session->next_crypto->server_kex.cookie, 16) < 0) {
      ssh_buffer_reinit(session->out_hashbuf);
      return -1;
    }
  } else {
    if (ssh_buffer_add_data(session->out_hashbuf,
          session->next_crypto->client_kex.cookie, 16) < 0) {
      ssh_buffer_reinit(session->out_hashbuf);
      return -1;
    }
  }

  return 0;
}

int ssh_hashbufin_add_cookie(ssh_session session, unsigned char *cookie) {
  session->in_hashbuf = ssh_buffer_new();
  if (session->in_hashbuf == NULL) {
    return -1;
  }

  if (ssh_buffer_add_u8(session->in_hashbuf, 20) < 0) {
    ssh_buffer_reinit(session->in_hashbuf);
    return -1;
  }
  if (ssh_buffer_add_data(session->in_hashbuf,cookie, 16) < 0) {
    ssh_buffer_reinit(session->in_hashbuf);
    return -1;
  }

  return 0;
}

static int generate_one_key(ssh_string k,
    struct ssh_crypto_struct *crypto, unsigned char **output, char letter, size_t requested_size) {
  ssh_mac_ctx ctx;
  unsigned char *tmp;
  size_t size = crypto->digest_len;
  ctx=ssh_mac_ctx_init(crypto->mac_type);

  if (ctx == NULL) {
    return -1;
  }

  ssh_mac_update(ctx, k, ssh_string_len(k) + 4);
  ssh_mac_update(ctx, crypto->secret_hash, crypto->digest_len);
  ssh_mac_update(ctx, &letter, 1);
  ssh_mac_update(ctx, crypto->session_id, crypto->digest_len);
  ssh_mac_final(*output, ctx);

  while(requested_size > size) {
    tmp = realloc(*output, size + crypto->digest_len);
    if (tmp == NULL) {
      return -1;
    }
    *output = tmp;

    ctx = ssh_mac_ctx_init(crypto->mac_type);
    if (ctx == NULL) {
      return -1;
    }
    ssh_mac_update(ctx, k, ssh_string_len(k) + 4);
    ssh_mac_update(ctx, crypto->secret_hash,
        crypto->digest_len);
    ssh_mac_update(ctx, tmp, size);
    ssh_mac_final(tmp + size, ctx);
    size += crypto->digest_len;
  }

  return 0;
}

int ssh_generate_session_keys(ssh_session session) {
  ssh_string k_string = NULL;
  struct ssh_crypto_struct *crypto = session->next_crypto;
  int rc = -1;

  k_string = ssh_make_bignum_string(crypto->k);
  if (k_string == NULL) {
    ssh_set_error_oom(session);
    goto error;
  }

  crypto->encryptIV = malloc(crypto->digest_len);
  crypto->decryptIV = malloc(crypto->digest_len);
  crypto->encryptkey = malloc(crypto->digest_len);
  crypto->decryptkey = malloc(crypto->digest_len);
  crypto->encryptMAC = malloc(crypto->digest_len);
  crypto->decryptMAC = malloc(crypto->digest_len);
  if(crypto->encryptIV == NULL || crypto->decryptIV == NULL ||
      crypto->encryptkey == NULL || crypto->decryptkey == NULL ||
      crypto->encryptMAC == NULL || crypto->decryptMAC == NULL){
    ssh_set_error_oom(session);
    goto error;
  }

  /* IV */
  if (session->client) {
    rc = generate_one_key(k_string, crypto, &crypto->encryptIV, 'A', crypto->digest_len);
    if (rc < 0) {
      goto error;
    }
    rc = generate_one_key(k_string, crypto, &crypto->decryptIV, 'B', crypto->digest_len);
    if (rc < 0) {
      goto error;
    }
  } else {
    rc = generate_one_key(k_string, crypto, &crypto->decryptIV, 'A', crypto->digest_len);
    if (rc < 0) {
      goto error;
    }
    rc = generate_one_key(k_string, crypto, &crypto->encryptIV, 'B', crypto->digest_len);
    if (rc < 0) {
      goto error;
    }
  }
  if (session->client) {
    rc = generate_one_key(k_string, crypto, &crypto->encryptkey, 'C', crypto->out_cipher->keysize / 8);
    if (rc < 0) {
      goto error;
    }
    rc = generate_one_key(k_string, crypto, &crypto->decryptkey, 'D', crypto->in_cipher->keysize / 8);
    if (rc < 0) {
      goto error;
    }
  } else {
    rc = generate_one_key(k_string, crypto, &crypto->decryptkey, 'C', crypto->in_cipher->keysize / 8);
    if (rc < 0) {
      goto error;
    }
    rc = generate_one_key(k_string, crypto, &crypto->encryptkey, 'D', crypto->out_cipher->keysize / 8);
    if (rc < 0) {
      goto error;
    }
  }

  if(session->client) {
    rc = generate_one_key(k_string, crypto, &crypto->encryptMAC, 'E', hmac_digest_len(crypto->out_hmac));
    if (rc < 0) {
      goto error;
    }
    rc = generate_one_key(k_string, crypto, &crypto->decryptMAC, 'F', hmac_digest_len(crypto->in_hmac));
    if (rc < 0) {
      goto error;
    }
  } else {
    rc = generate_one_key(k_string, crypto, &crypto->decryptMAC, 'E', hmac_digest_len(crypto->in_hmac));
    if (rc < 0) {
      goto error;
    }
    rc = generate_one_key(k_string, crypto, &crypto->encryptMAC, 'F', hmac_digest_len(crypto->out_hmac));
    if (rc < 0) {
      goto error;
    }
  }

#ifdef DEBUG_CRYPTO
  ssh_print_hexa("Encrypt IV", crypto->encryptIV, crypto->digest_len);
  ssh_print_hexa("Decrypt IV", crypto->decryptIV, crypto->digest_len);
  ssh_print_hexa("Encryption key", crypto->encryptkey, crypto->out_cipher->keysize / 8);
  ssh_print_hexa("Decryption key", crypto->decryptkey, crypto->in_cipher->keysize / 8);
  ssh_print_hexa("Encryption MAC", crypto->encryptMAC, hmac_digest_len(crypto->out_hmac));
  ssh_print_hexa("Decryption MAC", crypto->decryptMAC, hmac_digest_len(crypto->in_hmac));
#endif

  rc = 0;
error:
  ssh_string_burn(k_string);
  ssh_string_free(k_string);

  return rc;
}

/* vim: set ts=2 sw=2 et cindent: */

/*
 * pkd_keyutil.h --
 *
 * (c) 2014 Jon Simons
 */

#ifndef __PKD_KEYUTIL_H__
#define __PKD_KEYUTIL_H__

/* Server keys. */
#define LIBSSH_RSA_TESTKEY        "libssh_testkey.id_rsa"
#define LIBSSH_DSA_TESTKEY        "libssh_testkey.id_dsa"
#define LIBSSH_ECDSA_256_TESTKEY  "libssh_testkey.id_ecdsa256"
#define LIBSSH_ECDSA_384_TESTKEY  "libssh_testkey.id_ecdsa384"
#define LIBSSH_ECDSA_521_TESTKEY  "libssh_testkey.id_ecdsa521"

void setup_rsa_key(void);
void setup_dsa_key(void);
void setup_ecdsa_keys(void);
void cleanup_rsa_key(void);
void cleanup_dsa_key(void);
void cleanup_ecdsa_keys(void);

/* Client keys. */
#define OPENSSH_RSA_TESTKEY   "openssh_testkey.id_rsa"
#define DROPBEAR_RSA_TESTKEY  "dropbear_testkey.id_rsa"

void setup_openssh_client_rsa_key(void);
void cleanup_openssh_client_rsa_key(void);

void setup_dropbear_client_rsa_key(void);
void cleanup_dropbear_client_rsa_key(void);

#endif /* __PKD_KEYUTIL_H__ */

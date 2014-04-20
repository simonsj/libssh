#ifndef __LIBSSH_ED25519_H__
#define __LIBSSH_ED25519_H__
int ssh_ed25519_verify(const ssh_key key,
                       const unsigned char *sigblob,
                       unsigned int sigblob_len,
                       const unsigned char *hash,
                       size_t hlen);
#endif /* __LIBSSH_ED25519_H__ */

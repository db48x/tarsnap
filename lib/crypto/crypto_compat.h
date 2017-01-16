#ifndef _CRYPTO_COMPAT_H_
#define _CRYPTO_COMPAT_H_

/**
 * crypto_compat_RSA_valid_size(rsa):
 * Check that the RSA key ${rsa} has the correct size.
 */
int crypto_compat_RSA_valid_size(RSA * key);

#endif

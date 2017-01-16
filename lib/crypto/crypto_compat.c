#include <assert.h>

#include <openssl/rsa.h>

#include "crypto_compat.h"

/**
 * crypto_compat_RSA_valid_size(rsa):
 * Check that the RSA ${rsa} has the correct size.
 */
int
crypto_compat_RSA_valid_size(RSA * rsa)
{

	/* Sanity checks. */
	assert(rsa != NULL);
	assert(rsa->n != NULL);

	if ((RSA_size(rsa) != 256) || (BN_num_bits(rsa->n) != 2048))
		goto err0;

	/* Success! */
	return (0);

err0:
	/* Failure! */
	return (-1);
}

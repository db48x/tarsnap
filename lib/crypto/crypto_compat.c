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

/**
 * crypto_compat_RSA_import(key, n, e, d, p, q, dmp1, dmq1, iqmp):
 * Import the given BIGNUMs into the RSA ${key}.
 */
int
crypto_compat_RSA_import(RSA ** key, BIGNUM * n, BIGNUM * e, BIGNUM * d,
    BIGNUM * p, BIGNUM * q, BIGNUM * dmp1, BIGNUM * dmq1, BIGNUM * iqmp)
{

	/* Sanity checks. */
	assert(key != NULL);
	assert((n != NULL) && (e != NULL));
	/* All the private-key-related variables are NULL, or they're not. */
	assert( ((d == NULL) && (p == NULL) && (q == NULL) && (dmp1 == NULL)
	      && (dmq1 == NULL) && (iqmp == NULL)) ||
	        ((d != NULL) && (p != NULL) && (q != NULL) && (dmp1 != NULL)
	      && (dmq1 != NULL) && (iqmp != NULL)));

	/* Put values into RSA key. */
	(*key)->n = n;
	(*key)->e = e;
	if (d != NULL) {
		(*key)->d = d;
		(*key)->p = p;
		(*key)->q = q;
		(*key)->dmp1 = dmp1;
		(*key)->dmq1 = dmq1;
		(*key)->iqmp = iqmp;
	}

	/* Success! */
	return (0);
}

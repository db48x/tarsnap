#include <assert.h>

#include <openssl/bn.h>
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

#if OPENSSL_VERSION_NUMBER < 0x10100000L
	assert(rsa->n != NULL);
	if ((RSA_size(rsa) != 256) || (BN_num_bits(rsa->n) != 2048))
		goto err0;
#else
	if ((RSA_size(rsa) != 256) || (RSA_bits(rsa) != 2048))
		goto err0;
#endif

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

/**
 * crypto_compat_RSA_export(key, n, e, d, p, q, dmp1, dmq1, iqmp):
 * Export values from the given RSA ${key} into the BIGNUMs.  ${n} and ${e}
 * must be non-NULL; the other values may be NULL if desired, and will
 * therefore not be exported.
 */
int
crypto_compat_RSA_export(RSA * key, const BIGNUM ** n, const BIGNUM ** e,
    const BIGNUM ** d, const BIGNUM ** p, const BIGNUM ** q,
    const BIGNUM ** dmp1, const BIGNUM ** dmq1, const BIGNUM ** iqmp)
{

	/* Sanity check. */
	assert(key != NULL);
	assert((n != NULL) && (e != NULL));
	/* All the private-key-related variables are NULL, or they're not. */
	assert( ((d == NULL) && (p == NULL) && (q == NULL) && (dmp1 == NULL)
	      && (dmq1 == NULL) && (iqmp == NULL)) ||
	        ((d != NULL) && (p != NULL) && (q != NULL) && (dmp1 != NULL)
	      && (dmq1 != NULL) && (iqmp != NULL)));

	/* Get values from RSA key. */
	*n = key->n;
	*e = key->e;
	if (d != NULL) {
		*d = key->d;
		*p = key->p;
		*q = key->q;
		*dmp1 = key->dmp1;
		*dmq1 = key->dmq1;
		*iqmp = key->iqmp;
	}

	/* Success! */
	return (0);
}

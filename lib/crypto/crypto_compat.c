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
#if OPENSSL_VERSION_NUMBER < 0x10100000L
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
#else
	/* It's ok for d to be NULL here. */
	if (RSA_set0_key(*key, n, e, d) != 1)
		goto err0;

	/* It's not ok for these private-related-variables to be NULL. */
	if (d != NULL) {
		if (RSA_set0_factors(*key, p, q) != 1)
			goto err0;
		if (RSA_set0_crt_params(*key, dmp1, dmq1, iqmp) != 1)
			goto err0;
	}
#endif

	/* Success! */
	return (0);

#if OPENSSL_VERSION_NUMBER < 0x10100000L
#else
err0:
	/* Failure! */
	return (-1);
#endif
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
#if OPENSSL_VERSION_NUMBER < 0x10100000L
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
#else
	/* It's ok for d to be NULL here. */
	RSA_get0_key(key, n, e, d);

	/* It's not ok for these private-related-variables to be NULL. */
	if (d != NULL) {
		RSA_get0_factors(key, p, q);
		RSA_get0_crt_params(key, dmp1, dmq1, iqmp);
	}
#endif

	/* Success! */
	return (0);
}

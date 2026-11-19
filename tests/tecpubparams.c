/* Copyright (C) 2026 Harri Hytönen <harri.hytonen@casambi.com>
   SPDX-License-Identifier: Apache-2.0 */

#include <stdio.h>
#include <stdlib.h>
#include <openssl/bn.h>
#include <openssl/core_names.h>
#include <openssl/evp.h>
#include "util.h"

/* Checks that the EC public point can be read from a private key object
 * even when the token does not store CKA_EC_POINT on private keys, and
 * that it matches the public key object. */

static int get_xy(EVP_PKEY *key, BIGNUM **x, BIGNUM **y)
{
    if (EVP_PKEY_get_bn_param(key, OSSL_PKEY_PARAM_EC_PUB_X, x) != 1
        || EVP_PKEY_get_bn_param(key, OSSL_PKEY_PARAM_EC_PUB_Y, y) != 1) {
        return 0;
    }
    return 1;
}

static int check_priv(const char *name, EVP_PKEY *priv, BIGNUM *pub_x,
                      BIGNUM *pub_y)
{
    BIGNUM *x = NULL, *y = NULL;
    int ret = 0;

    if (!get_xy(priv, &x, &y)) {
        PRINTERROSSL("%s: failed to get EC_PUB_X/Y from private key\n", name);
        goto done;
    }
    if (BN_cmp(x, pub_x) != 0 || BN_cmp(y, pub_y) != 0) {
        PRINTERR("%s: public point does not match public key\n", name);
        goto done;
    }
    ret = 1;

done:
    BN_free(x);
    BN_free(y);
    return ret;
}

int main(int argc, char *argv[])
{
    EVP_PKEY *pub = NULL, *priv = NULL;
    EVP_PKEY_CTX *ctx = NULL;
    BIGNUM *pub_x = NULL, *pub_y = NULL;
    int rc = EXIT_FAILURE;

    if (argc != 3) {
        fprintf(stderr, "Usage: tecpubparams [privkey-uri] [pubkey-uri]\n");
        exit(EXIT_FAILURE);
    }

    pub = load_key(argv[2]);
    if (!get_xy(pub, &pub_x, &pub_y)) {
        PRINTERROSSL("Failed to get EC_PUB_X/Y from public key\n");
        goto done;
    }

    /* fresh private key */
    priv = load_key(argv[1]);
    if (!check_priv("fresh", priv, pub_x, pub_y)) {
        goto done;
    }
    EVP_PKEY_free(priv);
    priv = NULL;

    /* A verify operation on the private key associates a public object
     * with it first (possibly a synthetic one built from
     * CKA_PUBLIC_KEY_INFO), the point must still be found afterwards. */
    priv = load_key(argv[1]);
    ctx = EVP_PKEY_CTX_new_from_pkey(NULL, priv, NULL);
    if (!ctx || EVP_PKEY_verify_init(ctx) != 1) {
        PRINTERROSSL("Failed to init verify with private key\n");
        goto done;
    }
    if (!check_priv("after verify init", priv, pub_x, pub_y)) {
        goto done;
    }

    rc = EXIT_SUCCESS;

done:
    BN_free(pub_x);
    BN_free(pub_y);
    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(priv);
    EVP_PKEY_free(pub);
    return rc;
}

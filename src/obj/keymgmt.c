/* Copyright (C) 2022-2025 Simo Sorce <simo@redhat.com>
   SPDX-License-Identifier: Apache-2.0 */

#include "obj/internal.h"
#include <openssl/bio.h>
#include <openssl/ec.h>

/* Helper to get key type name as string for logging */
static const char *key_type_name(CK_KEY_TYPE type)
{
    switch (type) {
    case CKK_RSA:
        return "RSA";
    case CKK_EC:
        return "EC";
    case CKK_EC_EDWARDS:
        return "EC_EDWARDS";
    case CKK_EC_EDWARDS_LEGACY:
        return "EC_EDWARDS_LEGACY";
    case CKK_EC_MONTGOMERY:
        return "EC_MONTGOMERY";
    case CKK_ML_DSA:
        return "ML_DSA";
    case CKK_ML_KEM:
        return "ML_KEM";
    default:
        return "UNKNOWN";
    }
}

/* Helper to get object class name as string for logging */
static const char *class_name(CK_OBJECT_CLASS cls)
{
    switch (cls) {
    case CKO_PUBLIC_KEY:
        return "PUBLIC_KEY";
    case CKO_PRIVATE_KEY:
        return "PRIVATE_KEY";
    case CKO_CERTIFICATE:
        return "CERTIFICATE";
    default:
        return "UNKNOWN";
    }
}

/* Helper to hex dump binary data for logging */
static void debug_hex_dump(const char *prefix, const void *data, size_t len)
{
    if (!data || len == 0) {
        P11PROV_debug("%s: (null or empty)", prefix);
        return;
    }

    /* Limit output for very large values */
    size_t max_len = (len > 64) ? 64 : len;
    const unsigned char *p = (const unsigned char *)data;

    char hex[128];
    size_t hex_pos = 0;
    for (size_t i = 0; i < max_len; i++) {
        hex_pos += snprintf(hex + hex_pos, sizeof(hex) - hex_pos, "%02x", p[i]);
    }

    if (len > 64) {
        P11PROV_debug("%s: %s... (truncated, total %zu bytes)", prefix, hex, len);
    } else {
        P11PROV_debug("%s: %s (len=%zu)", prefix, hex, len);
    }
}

bool p11prov_obj_is_rsa_pss(P11PROV_OBJ *obj)
{
    CK_BBOOL token_supports_allowed_mechs = CK_TRUE;
    CK_ATTRIBUTE *am = NULL;
    CK_MECHANISM_TYPE *allowed;
    P11PROV_OBJ *priv = NULL;
    int am_nmechs;
    CK_RV ret;

    /* If the token does not support this attribute, do not even try to figure
     * out the subtype. */
    ret = p11prov_token_sup_attr(obj->ctx, obj->slotid, GET_ATTR,
                                 CKA_ALLOWED_MECHANISMS,
                                 &token_supports_allowed_mechs);
    if (ret != CKR_OK) {
        P11PROV_raise(obj->ctx, ret, "Failed to probe quirk");
    } else if (token_supports_allowed_mechs == CK_FALSE) {
        return false;
    }

    am = p11prov_obj_get_attr(obj, CKA_ALLOWED_MECHANISMS);
    if (am == NULL || am->ulValueLen == 0) {
        /* The ALLOWED_MECHANISMS should be on both of the keys. But more
         * commonly they are available only on the private key. Check if we
         * have a priv key associated to this pub key and if so, use that one.
         * TODO we can try also certificate restrictions
         */
        if (obj->class == CKO_PRIVATE_KEY) {
            /* no limitations */
            return false;
        }

        /* Try to find private key */
        priv = p11prov_obj_find_associated(obj, CKO_PRIVATE_KEY);
        if (priv == NULL) {
            return false;
        }

        am = p11prov_obj_get_attr(priv, CKA_ALLOWED_MECHANISMS);
        if (am == NULL || am->ulValueLen == 0) {
            /* no limitations */
            p11prov_obj_free(priv);
            return false;
        }
    }
    allowed = (CK_MECHANISM_TYPE *)am->pValue;
    am_nmechs = am->ulValueLen / sizeof(CK_MECHANISM_TYPE);
    for (int i = 0; i < am_nmechs; i++) {
        bool found = false;
        for (int j = 0; j < P11PROV_N_RSAPSS_MECHS; j++) {
            if (allowed[i] == p11prov_rsapss_mechs[j]) {
                found = true;
                break;
            }
        }
        if (!found) {
            /* this is not a RSA-PSS mechanism. We can not enforce any
             * limitations */
            p11prov_obj_free(priv);
            return false;
        }
    }
    /* all allowed mechanisms fit into the list of RSA-PSS ones */
    p11prov_obj_free(priv);
    return true;
}

static int prep_get_pub_key(P11PROV_OBJ **obj, CK_KEY_TYPE type)
{
    P11PROV_OBJ *key;

    if (!obj || !*obj) {
        return RET_OSSL_ERR;
    }

    key = *obj;

    if (key->class != CKO_PRIVATE_KEY && key->class != CKO_PUBLIC_KEY) {
        P11PROV_raise(key->ctx, CKR_GENERAL_ERROR, "Invalid Object Class");
        return RET_OSSL_ERR;
    }

    if (key->data.key.type != type) {
        P11PROV_raise(key->ctx, CKR_GENERAL_ERROR, "Unsupported key type");
        return RET_OSSL_ERR;
    }

    /* check if we have a pub key associated to a private key */
    if (key->class == CKO_PRIVATE_KEY) {
        P11PROV_OBJ *pobj = p11prov_obj_get_associated(key);
        if (pobj && pobj->class == CKO_PUBLIC_KEY) {
            /* replace obj with the public one */
            *obj = pobj;
        }
    }

    return RET_OSSL_OK;
}

int p11prov_obj_get_ed_pub_key(P11PROV_OBJ *obj, CK_ATTRIBUTE **pub)
{
    CK_ATTRIBUTE *a;
    int ret;

    P11PROV_debug("get ed pubkey %p", obj);

    ret = prep_get_pub_key(&obj, CKK_EC_EDWARDS_LEGACY);
    if (ret != RET_OSSL_OK) {
        return ret;
    }

    /* See if we have cached attributes first */
    a = p11prov_obj_get_attr(obj, CKA_P11PROV_PUB_KEY);
    if (!a) {
        return RET_OSSL_ERR;
    }

    if (pub) {
        *pub = a;
    }
    return RET_OSSL_OK;
}

int p11prov_obj_get_ecx_pub_key(P11PROV_OBJ *obj, CK_ATTRIBUTE **pub)
{
    CK_ATTRIBUTE *a;
    int ret;

    P11PROV_debug("get montgomery pubkey %p", obj);

    ret = prep_get_pub_key(&obj, CKK_EC_MONTGOMERY);
    if (ret != RET_OSSL_OK) {
        return ret;
    }

    /* See if we have cached attributes first */
    a = p11prov_obj_get_attr(obj, CKA_P11PROV_PUB_KEY);
    if (!a) {
        return RET_OSSL_ERR;
    }

    if (pub) {
        *pub = a;
    }
    return RET_OSSL_OK;
}

int p11prov_obj_get_ec_public_x_y(P11PROV_OBJ *obj, CK_ATTRIBUTE **pub_x,
                                  CK_ATTRIBUTE **pub_y)
{
    const unsigned char *val;
    void *tmp_ptr;
    CK_ATTRIBUTE *ec_params;
    CK_ATTRIBUTE *pub_key;
    EC_POINT *pub_point = NULL;
    EC_GROUP *group = NULL;
    CK_ATTRIBUTE *a_x;
    CK_ATTRIBUTE *a_y;
    BN_CTX *bnctx = NULL;
    BIGNUM *x;
    BIGNUM *y;
    int len;
    int ret;

    ret = prep_get_pub_key(&obj, CKK_EC);
    if (ret != RET_OSSL_OK) {
        return ret;
    }

    /* See if we have cached attributes first */
    a_x = p11prov_obj_get_attr(obj, CKA_P11PROV_PUB_KEY_X);
    a_y = p11prov_obj_get_attr(obj, CKA_P11PROV_PUB_KEY_Y);
    if (a_x && a_y) {
        if (pub_x) {
            *pub_x = a_x;
        }
        if (pub_y) {
            *pub_y = a_y;
        }
        return RET_OSSL_OK;
    }

    ec_params = p11prov_obj_get_attr(obj, CKA_EC_PARAMS);
    if (!ec_params) {
        return RET_OSSL_ERR;
    }
    pub_key = p11prov_obj_get_attr(obj, CKA_P11PROV_PUB_KEY);
    if (!pub_key) {
        return RET_OSSL_ERR;
    }

    bnctx = BN_CTX_new();
    if (!bnctx) {
        ret = RET_OSSL_ERR;
        goto done;
    }
    /* prevent modification of the attribute pointer */
    val = ec_params->pValue;
    group = d2i_ECPKParameters(NULL, &val, ec_params->ulValueLen);
    if (!group) {
        ret = RET_OSSL_ERR;
        goto done;
    }

    x = BN_CTX_get(bnctx);
    y = BN_CTX_get(bnctx);
    if (!x || !y) {
        ret = RET_OSSL_ERR;
        goto done;
    }

    pub_point = EC_POINT_new(group);
    if (!pub_point) {
        ret = RET_OSSL_ERR;
        goto done;
    }

    ret = EC_POINT_oct2point(group, pub_point, pub_key->pValue,
                             pub_key->ulValueLen, bnctx);
    if (ret != RET_OSSL_OK) {
        goto done;
    }

    ret = EC_POINT_get_affine_coordinates(group, pub_point, x, y, bnctx);
    if (ret != RET_OSSL_OK) {
        goto done;
    }

    /* cache values */
    tmp_ptr =
        OPENSSL_realloc(obj->attrs, sizeof(CK_ATTRIBUTE) * (obj->numattrs + 2));
    if (!tmp_ptr) {
        ret = RET_OSSL_ERR;
        goto done;
    }
    obj->attrs = tmp_ptr;

    /* do x */
    a_x = &obj->attrs[obj->numattrs];
    a_x->type = CKA_P11PROV_PUB_KEY_X;
    a_x->ulValueLen = BN_num_bytes(x);
    a_x->pValue = OPENSSL_malloc(a_x->ulValueLen);
    if (!a_x->pValue) {
        ret = RET_OSSL_ERR;
        goto done;
    }
    len = BN_bn2nativepad(x, a_x->pValue, a_x->ulValueLen);
    if (len == -1) {
        OPENSSL_free(a_x->pValue);
        ret = RET_OSSL_ERR;
        goto done;
    }
    obj->numattrs++;

    /* do y */
    a_y = &obj->attrs[obj->numattrs];
    a_y->type = CKA_P11PROV_PUB_KEY_Y;
    a_y->ulValueLen = BN_num_bytes(y);
    a_y->pValue = OPENSSL_malloc(a_y->ulValueLen);
    if (!a_y->pValue) {
        OPENSSL_free(a_y->pValue);
        ret = RET_OSSL_ERR;
        goto done;
    }
    len = BN_bn2nativepad(y, a_y->pValue, a_y->ulValueLen);
    if (len == -1) {
        ret = RET_OSSL_ERR;
        goto done;
    }
    obj->numattrs++;

    if (pub_x) {
        *pub_x = a_x;
    }
    if (pub_y) {
        *pub_y = a_y;
    }

    ret = RET_OSSL_OK;

done:
    EC_POINT_free(pub_point);
    EC_GROUP_free(group);
    BN_CTX_free(bnctx);
    return ret;
}

CK_RV decode_ec_point(P11PROV_CTX *provctx, CK_KEY_TYPE key_type,
                      CK_ATTRIBUTE *attr, struct data_buffer *ec_point)
{
    ASN1_OCTET_STRING *octet;
    const unsigned char *val;
    CK_RV ret = CKR_GENERAL_ERROR;
    int err;

    /* Some of the ASN.1 operation may leave errors on the stack
     * which cause TLS operation to fail even if they are benign
     * by just being there, so we need to be able to pop the
     * stack if we want to ignore an error */
    p11prov_set_error_mark(provctx);

    /* in d2i functions 'in' is overwritten to return the remainder of
     * the buffer after parsing, so we always need to avoid passing in
     * our pointer holders, to avoid having them clobbered */
    val = attr->pValue;
    octet = d2i_ASN1_OCTET_STRING(NULL, (const unsigned char **)&val,
                                  attr->ulValueLen);
    if (!octet) {
        /* 3.1 spec says CKA_EC_POINT is not DER encoded for Edwards and
         * Montgomery curves so do not fail in that case and just take
         * the value as is */
        if (key_type == CKK_EC) {
            ret = CKR_KEY_INDIGESTIBLE;
            goto done;
        } else {
            octet = ASN1_OCTET_STRING_new();
            if (!octet) {
                ret = CKR_HOST_MEMORY;
                goto done;
            }
            /* makes a copy of the value */
            err = ASN1_OCTET_STRING_set(octet, attr->pValue, attr->ulValueLen);
            if (err != RET_OSSL_OK) {
                ret = CKR_HOST_MEMORY;
                goto done;
            }
        }
    }

    ec_point->data =
        OPENSSL_memdup(ASN1_STRING_get0_data(octet), ASN1_STRING_length(octet));
    if (!ec_point->data) {
        ret = CKR_HOST_MEMORY;
        ec_point->length = 0;
        goto done;
    }
    ec_point->length = ASN1_STRING_length(octet);

    ret = CKR_OK;
done:
    if (ret == CKR_OK) {
        /* we want to ignore decoding errors in this case */
        p11prov_pop_error_to_mark(provctx);
    } else {
        /* we want to leave errors in this case */
        p11prov_clear_last_error_mark(provctx);
    }
    if (octet) {
        ASN1_OCTET_STRING_free(octet);
    }
    return ret;
}

CK_ATTRIBUTE *p11prov_obj_get_ec_public_raw(P11PROV_OBJ *key)
{
    CK_ATTRIBUTE *pub_key;
    int err;

    err = prep_get_pub_key(&key, CKK_EC);
    if (err != RET_OSSL_OK) {
        return NULL;
    }

    pub_key = p11prov_obj_get_attr(key, CKA_P11PROV_PUB_KEY);
    if (!pub_key) {
        CK_ATTRIBUTE *ec_point;

        ec_point = p11prov_obj_get_attr(key, CKA_EC_POINT);
        if (ec_point) {
            struct data_buffer data = { 0 };
            void *tmp_ptr;
            CK_RV ret;

            ret =
                decode_ec_point(key->ctx, key->data.key.type, ec_point, &data);
            if (ret != CKR_OK) {
                P11PROV_raise(key->ctx, ret, "Failed to decode EC_POINT");
                return NULL;
            }

            tmp_ptr = OPENSSL_realloc(key->attrs, sizeof(CK_ATTRIBUTE)
                                                      * (key->numattrs + 1));
            if (!tmp_ptr) {
                P11PROV_raise(key->ctx, CKR_HOST_MEMORY,
                              "Failed to allocate memory key attributes");
                OPENSSL_free(data.data);
                return NULL;
            }
            key->attrs = tmp_ptr;

            /* takes the data allocated in data */
            CKATTR_ASSIGN(key->attrs[key->numattrs], CKA_P11PROV_PUB_KEY,
                          data.data, data.length);
            key->numattrs++;

            pub_key = &key->attrs[key->numattrs - 1];
        }
    }

    if (!pub_key) {
        P11PROV_debug("ECC Public Point not found");
    }
    return pub_key;
}

CK_RV p11prov_obj_set_ec_encoded_public_key(P11PROV_OBJ *key,
                                            const void *pubkey,
                                            size_t pubkey_len)
{
    CK_RV rv = CKR_GENERAL_ERROR;
    CK_ATTRIBUTE *pub;
    CK_ATTRIBUTE *ecpoint;
    CK_ATTRIBUTE new_pub;
    ASN1_OCTET_STRING *oct = NULL;
    unsigned char *der = NULL;
    int add_attrs = 0;
    int len;

    if (key->handle != CK_P11PROV_IMPORTED_HANDLE) {
        /*
         * Token object backed by an actual HSM handle.
         * Cannot modify the object, but for signing operations we don't
         * need the EC_POINT anyway - the key matching will use curve NID
         * fallback instead. Return success to allow OpenSSL key setup to proceed.
         */
        P11PROV_debug("p11prov_obj_set_ec_encoded_public_key: token object, skipping (no modification needed for signing)");
        return CKR_OK;
    }

    switch (key->data.key.type) {
    case CKK_EC:
        /* if class is still "domain parameters" convert it to
         * a public key */
        if (key->class == CKO_DOMAIN_PARAMETERS) {
            key->class = CKO_PUBLIC_KEY;
        } else if (key->class != CKO_PUBLIC_KEY) {
            /* check that this is a public key */
            P11PROV_raise(key->ctx, CKR_KEY_INDIGESTIBLE,
                          "Invalid Key type, not a public key");
            rv = CKR_KEY_INDIGESTIBLE;
            goto done;
        }
        break;
    case CKK_EC_MONTGOMERY:
        break;
    default:
        P11PROV_raise(key->ctx, CKR_KEY_INDIGESTIBLE,
                      "Invalid Key type, not an EC/ED key");
        P11PROV_debug("Here 7");
        rv = CKR_KEY_INDIGESTIBLE;
        goto done;
    }

    pub = p11prov_obj_get_attr(key, CKA_P11PROV_PUB_KEY);
    if (!pub) {
        add_attrs += 1;
    }

    ecpoint = p11prov_obj_get_attr(key, CKA_EC_POINT);
    if (!ecpoint) {
        add_attrs += 1;
    }

    if (add_attrs > 0) {
        void *ptr = OPENSSL_realloc(
            key->attrs, sizeof(CK_ATTRIBUTE) * (key->numattrs + add_attrs));
        if (!ptr) {
            P11PROV_raise(key->ctx, CKR_HOST_MEMORY,
                          "Failed to store key public key");
            rv = CKR_HOST_MEMORY;
            goto done;
        }
        key->attrs = ptr;
    }

    if (!pub) {
        pub = &key->attrs[key->numattrs];
        key->numattrs += 1;
    } else {
        OPENSSL_free(pub->pValue);
    }
    /* always memset as realloc does not guarantee zeroed data */
    memset(pub, 0, sizeof(CK_ATTRIBUTE));

    if (!ecpoint) {
        ecpoint = &key->attrs[key->numattrs];
        key->numattrs += 1;
    } else {
        OPENSSL_free(ecpoint->pValue);
    }
    /* always memset as realloc does not guarantee zeroed data */
    memset(ecpoint, 0, sizeof(CK_ATTRIBUTE));

    new_pub.type = CKA_P11PROV_PUB_KEY;
    new_pub.pValue = (CK_VOID_PTR)pubkey;
    new_pub.ulValueLen = (CK_ULONG)pubkey_len;
    rv = p11prov_copy_attr(pub, &new_pub);
    if (rv != CKR_OK) {
        goto done;
    }

    oct = ASN1_OCTET_STRING_new();
    if (!oct) {
        rv = CKR_HOST_MEMORY;
        goto done;
    }
    if (!ASN1_STRING_set(oct, pubkey, pubkey_len)) {
        rv = CKR_HOST_MEMORY;
        goto done;
    }
    len = i2d_ASN1_OCTET_STRING(oct, &der);
    if (len < 0) {
        P11PROV_raise(key->ctx, CKR_KEY_INDIGESTIBLE,
                      "Failure to encode EC point to DER");
        rv = CKR_KEY_INDIGESTIBLE;
        goto done;
    }
    ecpoint->type = CKA_EC_POINT;
    ecpoint->pValue = der;
    der = NULL;
    ecpoint->ulValueLen = len;

    rv = CKR_OK;

done:
    ASN1_OCTET_STRING_free(oct);
    OPENSSL_free(der);

    return rv;
}

static int cmp_bn_attr(P11PROV_OBJ *key1, P11PROV_OBJ *key2,
                       CK_ATTRIBUTE_TYPE attr)
{
    BIGNUM *bx1;
    BIGNUM *bx2;
    CK_ATTRIBUTE *x1, *x2;
    int rc = RET_OSSL_ERR;

    /* is BN ?*/
    if (attr != CKA_MODULUS && attr != CKA_PUBLIC_EXPONENT) {
        P11PROV_debug("cmp_bn_attr: attr %lu not BN (only MODULUS or PUBLIC_EXPONENT supported)", attr);
        return rc;
    }

    const char *attr_name = (attr == CKA_MODULUS) ? "CKA_MODULUS" : "CKA_PUBLIC_EXPONENT";
    P11PROV_debug("cmp_bn_attr: comparing %s", attr_name);

    x1 = p11prov_obj_get_attr(key1, attr);
    x2 = p11prov_obj_get_attr(key2, attr);

    if (!x1 || !x2) {
        P11PROV_debug("cmp_bn_attr: %s missing - x1=%p, x2=%p", attr_name, (void*)x1, (void*)x2);
        return rc;
    }

    P11PROV_debug("cmp_bn_attr: %s key1 len=%lu, key2 len=%lu", attr_name, x1->ulValueLen, x2->ulValueLen);

    bx1 = BN_native2bn(x1->pValue, x1->ulValueLen, NULL);
    bx2 = BN_native2bn(x2->pValue, x2->ulValueLen, NULL);

    if (BN_cmp(bx1, bx2) == 0) {
        rc = RET_OSSL_OK;
        P11PROV_debug("cmp_bn_attr: %s MATCH", attr_name);
    } else {
        P11PROV_debug("cmp_bn_attr: %s MISMATCH", attr_name);
    }

    BN_free(bx1);
    BN_free(bx2);

    return rc;
}

/* Derive the EC public point Q = d * G for a private key object.
 * Returns CKA_P11PROV_PUB_KEY value on success (caller must not free),
 * or NULL if the derivation failed. */
static CK_ATTRIBUTE *derive_ec_pub_point(P11PROV_OBJ *priv_key)
{
    CK_ATTRIBUTE *priv_val;
    CK_ATTRIBUTE *ec_params;
    CK_ATTRIBUTE *cached_pub;
    const BIGNUM *priv_d = NULL;
    const EC_GROUP *group = NULL;
    const EC_POINT *generator = NULL;
    EC_POINT *pub_point = NULL;
    BN_CTX *bnctx = NULL;
    unsigned char *pub_enc = NULL;
    size_t pub_enc_len = 0;
    CK_ATTRIBUTE *new_pub_attr = NULL;
    int ret;

    /* Already have a cached public key? */
    cached_pub = p11prov_obj_get_attr(priv_key, CKA_P11PROV_PUB_KEY);
    if (cached_pub) {
        return cached_pub;
    }

    /* Need private value d */
    priv_val = p11prov_obj_get_attr(priv_key, CKA_VALUE);
    if (!priv_val || priv_val->ulValueLen == 0) {
        P11PROV_debug("derive_ec_pub_point: CKA_VALUE not available on priv key");
        return NULL;
    }

    /* Need curve parameters to get group and generator */
    ec_params = p11prov_obj_get_attr(priv_key, CKA_EC_PARAMS);
    if (!ec_params || ec_params->ulValueLen == 0) {
        P11PROV_debug("derive_ec_pub_point: CKA_EC_PARAMS not available on priv key");
        return NULL;
    }

    const unsigned char *val = ec_params->pValue;
    group = d2i_ECPKParameters(NULL, &val, ec_params->ulValueLen);
    if (!group) {
        P11PROV_debug("derive_ec_pub_point: failed to parse EC parameters");
        return NULL;
    }

    generator = EC_GROUP_get0_generator(group);
    if (!generator) {
        P11PROV_debug("derive_ec_pub_point: no generator found in EC group");
        goto done;
    }

    bnctx = BN_CTX_new_ex(p11prov_ctx_get_libctx(priv_key->ctx));
    if (!bnctx) {
        goto done;
    }

    pub_point = EC_POINT_new(group);
    if (!pub_point) {
        goto done;
    }

    /* Parse d from raw big-endian bytes */
    priv_d = BN_bin2bn(priv_val->pValue, priv_val->ulValueLen, NULL);
    if (!priv_d) {
        goto done;
    }

    /* Q = d * G */
    ret = EC_POINT_mul(group, pub_point, NULL, generator, priv_d, bnctx);
    if (ret != 1) {
        P11PROV_debug("derive_ec_pub_point: EC_POINT_mul failed");
        goto done;
    }

    /* Encode public point as uncompressed octet string */
    pub_enc_len = EC_POINT_point2oct(group, pub_point,
                                     POINT_CONVERSION_UNCOMPRESSED,
                                     NULL, 0, bnctx);
    if (pub_enc_len == 0) {
        goto done;
    }

    pub_enc = OPENSSL_malloc(pub_enc_len);
    if (!pub_enc) {
        goto done;
    }

    pub_enc_len = EC_POINT_point2oct(group, pub_point,
                                     POINT_CONVERSION_UNCOMPRESSED,
                                     pub_enc, pub_enc_len, bnctx);
    if (pub_enc_len == 0) {
        OPENSSL_free(pub_enc);
        pub_enc = NULL;
        goto done;
    }

    /* Store in the object so we don't recompute */
    new_pub_attr = &priv_key->attrs[priv_key->numattrs];
    priv_key->numattrs += 1;
    memset(new_pub_attr, 0, sizeof(CK_ATTRIBUTE));
    new_pub_attr->type = CKA_P11PROV_PUB_KEY;
    new_pub_attr->pValue = pub_enc;
    new_pub_attr->ulValueLen = (CK_ULONG)pub_enc_len;

    P11PROV_debug("derive_ec_pub_point: successfully derived public point, len=%zu",
                  pub_enc_len);

done:
    EC_GROUP_free((EC_GROUP *)group);
    EC_POINT_free(pub_point);
    BN_CTX_free(bnctx);
    /* new_pub_attr owns the allocated pub_enc; don't free it */
    return new_pub_attr;
}

static int cmp_attr(P11PROV_OBJ *key1, P11PROV_OBJ *key2,
                    CK_ATTRIBUTE_TYPE attr)
{
    CK_ATTRIBUTE *x1, *x2;

    x1 = p11prov_obj_get_attr(key1, attr);
    x2 = p11prov_obj_get_attr(key2, attr);
    if (!x1 || !x2) {
        P11PROV_debug("cmp_attr: attr %lu missing - x1=%p, x2=%p", attr, (void*)x1, (void*)x2);
        return RET_OSSL_ERR;
    }
    if (x1->ulValueLen != x2->ulValueLen) {
        P11PROV_debug("cmp_attr: attr %lu MISMATCH length - key1=%lu, key2=%lu", attr, x1->ulValueLen, x2->ulValueLen);
        return RET_OSSL_ERR;
    }
    if (memcmp(x1->pValue, x2->pValue, x1->ulValueLen) != 0) {
        P11PROV_debug("cmp_attr: attr %lu MISMATCH data", attr);
        debug_hex_dump("cmp_attr: key1 data", x1->pValue, x1->ulValueLen);
        debug_hex_dump("cmp_attr: key2 data", x2->pValue, x2->ulValueLen);
        return RET_OSSL_ERR;
    }
    P11PROV_debug("cmp_attr: attr %lu MATCH", attr);
    return RET_OSSL_OK;
}

static int cmp_public_key_values(P11PROV_OBJ *pub_key1, P11PROV_OBJ *pub_key2)
{
    int ret;

    P11PROV_debug("cmp_public_key_values: ENTER");
    P11PROV_debug("cmp_public_key_values: key1 ptr=%p, class=%s (%u), type=%s (%u), handle=%lu",
                  (void*)pub_key1, class_name(pub_key1->class), pub_key1->class,
                  key_type_name(pub_key1->data.key.type), pub_key1->data.key.type,
                  pub_key1->handle);
    P11PROV_debug("cmp_public_key_values: key2 ptr=%p, class=%s (%u), type=%s (%u), handle=%lu",
                  (void*)pub_key2, class_name(pub_key2->class), pub_key2->class,
                  key_type_name(pub_key2->data.key.type), pub_key2->data.key.type,
                  pub_key2->handle);

    switch (pub_key1->data.key.type) {
    case CKK_RSA:
        P11PROV_debug("cmp_public_key_values: RSA key comparison");
        /* pub_key1 pub_key2 could be CKO_PRIVATE_KEY here but
         * nevertheless contain these two attributes */
        ret = cmp_bn_attr(pub_key1, pub_key2, CKA_MODULUS);
        if (ret == RET_OSSL_ERR) {
            P11PROV_debug("cmp_public_key_values: RSA MODULUS comparison FAILED");
            break;
        }
        ret = cmp_bn_attr(pub_key1, pub_key2, CKA_PUBLIC_EXPONENT);
        if (ret == RET_OSSL_OK) {
            P11PROV_debug("cmp_public_key_values: RSA key MATCHED");
        } else {
            P11PROV_debug("cmp_public_key_values: RSA PUBLIC_EXPONENT comparison FAILED");
        }
        break;
    case CKK_EC:
    case CKK_EC_EDWARDS:
    case CKK_EC_EDWARDS_LEGACY:
    case CKK_EC_MONTGOMERY: {
        CK_ATTRIBUTE *x1 = NULL;
        CK_ATTRIBUTE *x2 = NULL;

        P11PROV_debug("cmp_public_key_values: EC/Edwards/Montgomery key comparison (type=%s)",
                      key_type_name(pub_key1->data.key.type));

        /* Fast path: compare cached EC_POINT values directly */
        x1 = p11prov_obj_get_attr(pub_key1, CKA_P11PROV_PUB_KEY);
        x2 = p11prov_obj_get_attr(pub_key2, CKA_P11PROV_PUB_KEY);

        if (x1 && x2) {
            if (x1->ulValueLen == x2->ulValueLen
                && memcmp(x1->pValue, x2->pValue, x1->ulValueLen) == 0) {
                P11PROV_debug("cmp_public_key_values: EC key MATCHED (via cached EC_POINT)");
                ret = RET_OSSL_OK;
            } else {
                P11PROV_debug("cmp_public_key_values: EC_POINT mismatch");
                ret = RET_OSSL_ERR;
            }
        } else {
            /* At least one key is missing cached public key data.
             * If either key is a private key, try deriving Q = d * G from it,
             * then compare against the other key's public key (or its derived value).
             * This handles HSMs that only store the private scalar. */
            P11PROV_debug("cmp_public_key_values: EC_POINT not cached on both keys, "
                          "trying derivation from private keys");
            ret = RET_OSSL_ERR;

            if (pub_key1->class == CKO_PRIVATE_KEY) {
                CK_ATTRIBUTE *derived = derive_ec_pub_point(pub_key1);
                if (derived) {
                    P11PROV_debug("cmp_public_key_values: derived pub from key1, comparing to key2");
                    x2 = p11prov_obj_get_attr(pub_key2, CKA_P11PROV_PUB_KEY);
                    if (x2 && derived->ulValueLen == x2->ulValueLen
                        && memcmp(derived->pValue, x2->pValue, derived->ulValueLen) == 0) {
                        P11PROV_debug("cmp_public_key_values: EC key MATCHED (derived from key1)");
                        ret = RET_OSSL_OK;
                    }
                }
            }

            if (ret == RET_OSSL_ERR && pub_key2->class == CKO_PRIVATE_KEY) {
                CK_ATTRIBUTE *derived = derive_ec_pub_point(pub_key2);
                if (derived) {
                    P11PROV_debug("cmp_public_key_values: derived pub from key2, comparing to key1");
                    x1 = p11prov_obj_get_attr(pub_key1, CKA_P11PROV_PUB_KEY);
                    if (x1 && derived->ulValueLen == x1->ulValueLen
                        && memcmp(derived->pValue, x1->pValue, derived->ulValueLen) == 0) {
                        P11PROV_debug("cmp_public_key_values: EC key MATCHED (derived from key2)");
                        ret = RET_OSSL_OK;
                    }
                }
            }

            if (ret == RET_OSSL_ERR) {
                P11PROV_debug("cmp_public_key_values: could not derive matching EC_POINT, "
                              "falling back to curve NID");
                ret = cmp_attr(pub_key1, pub_key2, CKA_P11PROV_CURVE_NID);
                if (ret == RET_OSSL_OK) {
                    P11PROV_debug("cmp_public_key_values: EC key MATCHED (via curve NID fallback)");
                }
            }
        }
        break;
    }
    case CKK_ML_DSA:
    case CKK_ML_KEM:
        P11PROV_debug("cmp_public_key_values: ML_DSA/ML_KEM key comparison (type=%s)",
                      key_type_name(pub_key1->data.key.type));
        ret = cmp_attr(pub_key1, pub_key2, CKA_VALUE);
        if (ret == RET_OSSL_OK) {
            P11PROV_debug("cmp_public_key_values: ML key MATCHED");
        } else {
            P11PROV_debug("cmp_public_key_values: ML key MISMATCHED");
        }
        break;
    default:
        P11PROV_debug("cmp_public_key_values: unsupported key type %u", pub_key1->data.key.type);
        ret = RET_OSSL_ERR;
    }

    P11PROV_debug("cmp_public_key_values: EXIT with ret=%d (%s)", ret,
                  ret == RET_OSSL_OK ? "MATCH" : "MISMATCH/ERROR");
    return ret;
}

static int match_key_with_cert(P11PROV_OBJ *priv_key, P11PROV_OBJ *pub_key)
{
    P11PROV_OBJ *cert;
    CK_ATTRIBUTE attrs[2] = { 0 };
    CK_ATTRIBUTE *x;
    int num = 0;
    int ret = RET_OSSL_ERR;
    bool curve_nid_fallback = false;

    cert = p11prov_obj_find_associated(priv_key, CKO_CERTIFICATE);
    if (!cert) {
        P11PROV_raise(priv_key->ctx, CKR_GENERAL_ERROR,
                      "Could not find associated certificate object");
        return RET_OSSL_ERR;
    }

    switch (pub_key->data.key.type) {
    case CKK_RSA:
        attrs[0].type = CKA_MODULUS;
        attrs[1].type = CKA_PUBLIC_EXPONENT;
        num = 2;
        break;
    case CKK_EC:
    case CKK_EC_EDWARDS:
    case CKK_EC_EDWARDS_LEGACY:
        /* Try EC_POINT comparison first */
        attrs[0].type = CKA_P11PROV_PUB_KEY;
        num = 1;
        break;
    case CKK_ML_DSA:
        attrs[0].type = CKA_VALUE;
        num = 1;
        break;
    default:
        P11PROV_raise(priv_key->ctx, CKR_GENERAL_ERROR,
                      "Unknown public key type");
        return RET_OSSL_ERR;
    }

    ret = get_attrs_from_cert(cert, attrs, num);
    if (ret != CKR_OK) {
        P11PROV_raise(priv_key->ctx, ret,
                      "Failed to get public attrs from cert");
        ret = RET_OSSL_ERR;
        goto done;
    }

    for (int i = 0; i < num; i++) {
        x = p11prov_obj_get_attr(pub_key, attrs[i].type);
        if (!x || x->ulValueLen != attrs[i].ulValueLen
            || memcmp(x->pValue, attrs[i].pValue, x->ulValueLen) != 0) {
            /* For EC keys, check if we should fall back to curve NID comparison */
            if ((pub_key->data.key.type == CKK_EC ||
                 pub_key->data.key.type == CKK_EC_EDWARDS ||
                 pub_key->data.key.type == CKK_EC_EDWARDS_LEGACY) && !x) {
                P11PROV_debug("match_key_with_cert: EC_POINT not available on priv_key, will try curve NID fallback");
                curve_nid_fallback = true;
            } else {
                ret = RET_OSSL_ERR;
                goto done;
            }
        }
    }

    /* If EC_POINT comparison failed due to missing attribute, try curve NID */
    if (curve_nid_fallback) {
        CK_ATTRIBUTE curve_nid_attrs[1] = { 0 };
        CK_ATTRIBUTE *curve_nid_x;
        int curve_nid_num = 1;

        curve_nid_attrs[0].type = CKA_P11PROV_CURVE_NID;
        ret = get_attrs_from_cert(cert, curve_nid_attrs, curve_nid_num);
        if (ret != CKR_OK) {
            P11PROV_debug("match_key_with_cert: failed to get curve NID from cert");
            ret = RET_OSSL_ERR;
            goto done;
        }

        curve_nid_x = p11prov_obj_get_attr(pub_key, CKA_P11PROV_CURVE_NID);
        if (!curve_nid_x || curve_nid_x->ulValueLen != curve_nid_attrs[0].ulValueLen
            || memcmp(curve_nid_x->pValue, curve_nid_attrs[0].pValue, curve_nid_x->ulValueLen) != 0) {
            P11PROV_debug("match_key_with_cert: curve NID mismatch");
            OPENSSL_free(curve_nid_attrs[0].pValue);
            ret = RET_OSSL_ERR;
            goto done;
        }

        OPENSSL_free(curve_nid_attrs[0].pValue);
        P11PROV_debug("match_key_with_cert: EC key MATCHED via curve NID fallback");
        ret = RET_OSSL_OK;
        goto done;
    }

    ret = RET_OSSL_OK;

done:
    for (int i = 0; i < num; i++) {
        OPENSSL_free(attrs[i].pValue);
    }
    p11prov_obj_free(cert);
    return ret;
}

static int match_public_keys(P11PROV_OBJ *key1, P11PROV_OBJ *key2)
{
    P11PROV_OBJ *pub_key, *assoc_pub_key;
    P11PROV_OBJ *priv_key;
    int ret = RET_OSSL_ERR;

    P11PROV_debug("match_public_keys: ENTER");
    P11PROV_debug("match_public_keys: key1 ptr=%p, class=%s (%u), type=%s (%u), handle=%lu, slotid=%lu",
                  (void*)key1, class_name(key1->class), key1->class,
                  key_type_name(key1->data.key.type), key1->data.key.type,
                  key1->handle, key1->slotid);
    P11PROV_debug("match_public_keys: key2 ptr=%p, class=%s (%u), type=%s (%u), handle=%lu, slotid=%lu",
                  (void*)key2, class_name(key2->class), key2->class,
                  key_type_name(key2->data.key.type), key2->data.key.type,
                  key2->handle, key2->slotid);

    /* Log CKA_ID and CKA_LABEL for debugging key matching issues */
    CK_ATTRIBUTE *id1 = p11prov_obj_get_attr(key1, CKA_ID);
    CK_ATTRIBUTE *label1 = p11prov_obj_get_attr(key1, CKA_LABEL);
    CK_ATTRIBUTE *id2 = p11prov_obj_get_attr(key2, CKA_ID);
    CK_ATTRIBUTE *label2 = p11prov_obj_get_attr(key2, CKA_LABEL);

    if (id1 && id1->ulValueLen > 0) {
        debug_hex_dump("match_public_keys: key1 CKA_ID", id1->pValue, id1->ulValueLen);
    } else {
        P11PROV_debug("match_public_keys: key1 CKA_ID: (none)");
    }
    if (label1 && label1->ulValueLen > 0) {
        P11PROV_debug("match_public_keys: key1 CKA_LABEL: '%.*s' (len=%lu)",
                      (int)label1->ulValueLen, (char*)label1->pValue, label1->ulValueLen);
    } else {
        P11PROV_debug("match_public_keys: key1 CKA_LABEL: (none)");
    }
    if (id2 && id2->ulValueLen > 0) {
        debug_hex_dump("match_public_keys: key2 CKA_ID", id2->pValue, id2->ulValueLen);
    } else {
        P11PROV_debug("match_public_keys: key2 CKA_ID: (none)");
    }
    if (label2 && label2->ulValueLen > 0) {
        P11PROV_debug("match_public_keys: key2 CKA_LABEL: '%.*s' (len=%lu)",
                      (int)label2->ulValueLen, (char*)label2->pValue, label2->ulValueLen);
    } else {
        P11PROV_debug("match_public_keys: key2 CKA_LABEL: (none)");
    }

    /* avoid round-trip to HSM if keys have enough
     * attributes to do the logical comparison
     * CKK_RSA: MODULUS / PUBLIC_EXPONENT
     * CKK_EC: EC_POINT
     */
    P11PROV_debug("match_public_keys: attempting direct comparison via cmp_public_key_values");
    ret = cmp_public_key_values(key1, key2);
    if (ret != RET_OSSL_ERR) {
        P11PROV_debug("match_public_keys: direct comparison succeeded (ret=%d), returning", ret);
        return ret;
    }
    P11PROV_debug("match_public_keys: direct comparison failed, need to look up associated keys");

    /* one of the keys or both are private */
    if (key1->class == CKO_PUBLIC_KEY && key2->class == CKO_PRIVATE_KEY) {
        pub_key = key1;
        priv_key = key2;
        P11PROV_debug("match_public_keys: key1 is PUBLIC_KEY, key2 is PRIVATE_KEY");
    } else if (key1->class == CKO_PRIVATE_KEY
               && key2->class == CKO_PUBLIC_KEY) {
        pub_key = key2;
        priv_key = key1;
        P11PROV_debug("match_public_keys: key1 is PRIVATE_KEY, key2 is PUBLIC_KEY");
    } else {
        P11PROV_debug("match_public_keys: We can't really match private keys (both are same class)");
        return RET_OSSL_ERR;
    }

    P11PROV_debug("match_public_keys: looking up associated public key for priv_key ptr=%p", (void*)priv_key);
    assoc_pub_key = p11prov_obj_find_associated(priv_key, CKO_PUBLIC_KEY);
    if (!assoc_pub_key) {
        P11PROV_debug("match_public_keys: no associated public key found, trying match_key_with_cert");
        P11PROV_raise(priv_key->ctx, CKR_GENERAL_ERROR,
                      "Could not find associated public key object");

        /* some tokens only store the public key in a cert and not in a
         * separate public key object */
        ret = match_key_with_cert(priv_key, pub_key);
        P11PROV_debug("match_public_keys: match_key_with_cert returned %d", ret);
        return ret;
    }

    P11PROV_debug("match_public_keys: found associated public key ptr=%p", (void*)assoc_pub_key);
    P11PROV_debug("match_public_keys: assoc_pub_key type=%s (%u), pub_key type=%s (%u)",
                  key_type_name(assoc_pub_key->data.key.type), assoc_pub_key->data.key.type,
                  key_type_name(pub_key->data.key.type), pub_key->data.key.type);

    if (assoc_pub_key->data.key.type != pub_key->data.key.type) {
        P11PROV_debug("match_public_keys: key type mismatch between pub_key and assoc_pub_key");
        goto done;
    }

    P11PROV_debug("match_public_keys: comparing pub_key with assoc_pub_key");
    ret = cmp_public_key_values(pub_key, assoc_pub_key);

done:
    P11PROV_debug("match_public_keys: releasing assoc_pub_key");
    p11prov_obj_free(assoc_pub_key);

    P11PROV_debug("match_public_keys: EXIT with ret=%d (%s)", ret,
                  ret == RET_OSSL_OK ? "MATCH" : "MISMATCH/ERROR");
    return ret;
}

int p11prov_obj_key_cmp(P11PROV_OBJ *key1, P11PROV_OBJ *key2, CK_KEY_TYPE type,
                        int cmp_type)
{
    int ret;

    /* immediate shortcircuit if it is the same handle */
    if (key1->slotid == key2->slotid && key1->handle == key2->handle) {
        return RET_OSSL_OK;
    }

    if (key1->class != CKO_PRIVATE_KEY && key1->class != CKO_PUBLIC_KEY) {
        /* not a key at all */
        return RET_OSSL_ERR;
    }
    if (key2->class != CKO_PRIVATE_KEY && key2->class != CKO_PUBLIC_KEY) {
        /* not a key at all */
        return RET_OSSL_ERR;
    }

    if (type != CK_UNAVAILABLE_INFORMATION && type != key1->data.key.type) {
        return RET_OSSL_ERR;
    }

    if (key1->data.key.type != key2->data.key.type) {
        return RET_OSSL_ERR;
    }

    if (key1->data.key.bit_size != key2->data.key.bit_size) {
        return RET_OSSL_ERR;
    }

    if (cmp_type & OBJ_CMP_KEY_PRIVATE) {
        if (key1->class != key2->class) {
            /* can't have private with differing key types */
            return RET_OSSL_ERR;
        }
        if (key1->class != CKO_PRIVATE_KEY) {
            return RET_OSSL_ERR;
        }
    }

    switch (key1->data.key.type) {
    case CKK_RSA:
    case CKK_ML_DSA:
    case CKK_ML_KEM:
        break;

    case CKK_EC:
        ret = cmp_attr(key1, key2, CKA_EC_PARAMS);
        if (ret != RET_OSSL_OK) {
            /* If EC_PARAMS do not match it may be due to encoding.
             * Fall back to slower conversions and compare via EC_GROUP */
            CK_ATTRIBUTE *ec_p;
            const unsigned char *val;
            EC_GROUP *group1 = NULL;
            EC_GROUP *group2 = NULL;
            BN_CTX *bnctx = NULL;

            ec_p = p11prov_obj_get_attr(key1, CKA_EC_PARAMS);
            if (!ec_p) {
                ret = RET_OSSL_ERR;
                goto out;
            }
            val = ec_p->pValue;
            group1 = d2i_ECPKParameters(NULL, &val, ec_p->ulValueLen);
            if (!group1) {
                ret = RET_OSSL_ERR;
                goto out;
            }

            ec_p = p11prov_obj_get_attr(key2, CKA_EC_PARAMS);
            if (!ec_p) {
                ret = RET_OSSL_ERR;
                goto out;
            }
            val = ec_p->pValue;
            group2 = d2i_ECPKParameters(NULL, &val, ec_p->ulValueLen);
            if (!group2) {
                ret = RET_OSSL_ERR;
                goto out;
            }

            bnctx = BN_CTX_new_ex(p11prov_ctx_get_libctx(key1->ctx));
            if (!bnctx) {
                ret = RET_OSSL_ERR;
                goto out;
            }

            ret = EC_GROUP_cmp(group1, group2, bnctx);
            if (ret == 0) {
                ret = RET_OSSL_OK;
            } else {
                ret = RET_OSSL_ERR;
            }

        out:
            EC_GROUP_free(group1);
            EC_GROUP_free(group2);
            BN_CTX_free(bnctx);
            if (ret != RET_OSSL_OK) {
                return ret;
            }
        }
        break;

    case CKK_EC_EDWARDS:
    case CKK_EC_EDWARDS_LEGACY:
    case CKK_EC_MONTGOMERY:
        /* The Edwards/Montgomery params can be encoded as printable string,
         * which is not recognized by OpenSSL and does not have an EC_GROUP */
        ret = cmp_attr(key1, key2, CKA_EC_PARAMS);
        if (ret != RET_OSSL_OK) {
            /* If EC_PARAMS do not match it may be due to encoding. */
            CK_ATTRIBUTE *ec_p;
            CK_RV rv;
            int nid1;
            int nid2;

            ec_p = p11prov_obj_get_attr(key1, CKA_EC_PARAMS);
            if (!ec_p) {
                return RET_OSSL_ERR;
            }
            rv = p11prov_match_curve(key1->data.key.type, ec_p, NULL, &nid1,
                                     NULL, NULL);
            if (rv != CKR_OK) {
                return RET_OSSL_ERR;
            }

            ec_p = p11prov_obj_get_attr(key2, CKA_EC_PARAMS);
            if (!ec_p) {
                return RET_OSSL_ERR;
            }
            rv = p11prov_match_curve(key2->data.key.type, ec_p, NULL, &nid2,
                                     NULL, NULL);
            if (rv != CKR_OK) {
                return RET_OSSL_ERR;
            }
            if (nid1 != nid2) {
                return RET_OSSL_ERR;
            }
        }
        break;

    default:
        return RET_OSSL_ERR;
    }

    if (cmp_type & OBJ_CMP_KEY_PRIVATE) {
        /* unfortunately we can't really read private attributes
         * and there is no comparison function in the PKCS11 API.
         * Generally you do not have 2 identical keys stored in to two
         * separate objects so the initial shortcircuit that matches if
         * slotid/handle are identical will often cover this. When that
         * fails we have no option but to fail for now. */
        P11PROV_debug("We can't really match private keys");
        /* internally match_public_keys() optimizes for checking public
         * values if present on the private key, and falls back to fetching
         * an associated public key if that fails. Note that should both
         * keys be private this will fail as match_public_keys() only handle
         * the case where one of the two keys is private. That is all openssl
         * needs anyway, it never has any reason to try to match two private
         * keys so this is fine. */
        cmp_type = OBJ_CMP_KEY_PUBLIC;
    }

    if (cmp_type & OBJ_CMP_KEY_PUBLIC) {
        ret = match_public_keys(key1, key2);
        if (ret != RET_OSSL_OK) {
            return ret;
        }
    }

    /* if nothing fails it is a match */
    return RET_OSSL_OK;
}

/* curveName params */
#define ED25519_EC_PARAMS \
    0x13, 0x0c, 0x65, 0x64, 0x77, 0x61, 0x72, 0x64, 0x73, 0x32, 0x35, 0x35, \
        0x31, 0x39
#define ED448_EC_PARAMS \
    0x13, 0x0a, 0x65, 0x64, 0x77, 0x61, 0x72, 0x64, 0x73, 0x34, 0x34, 0x38
#define X25519_EC_PARAMS \
    0x13, 0x0a, 0x63, 0x75, 0x72, 0x76, 0x65, 0x32, 0x35, 0x35, 0x31, 0x39
#define X448_EC_PARAMS \
    0x13, 0x08, 0x63, 0x75, 0x72, 0x76, 0x65, 0x34, 0x34, 0x38
const CK_BYTE ed25519_ec_params[] = { ED25519_EC_PARAMS };
const CK_BYTE ed448_ec_params[] = { ED448_EC_PARAMS };
const CK_BYTE x25519_ec_params[] = { X25519_EC_PARAMS };
const CK_BYTE x448_ec_params[] = { X448_EC_PARAMS };

/* OID params */
#define X25519_OID 0x06, 0x03, 0x2B, 0x65, 0x6E
#define X448_OID 0x06, 0x03, 0x2B, 0x65, 0x6F
#define ED25519_OID 0x06, 0x03, 0x2B, 0x65, 0x70
#define ED448_OID 0x06, 0x03, 0x2B, 0x65, 0x71
#define ED25519_OID_GNU 0x06, 0x09, 0x2B, 0x06, 0x01, 0x04, 0x01, 0xDA, 0x47, 0x0F, 0x01
#define ED448_OID_VENDOR 0x06, 0x09, 0x2b, 0x06, 0x01, 0x04, 0x01, 0xda, 0x47, 0x0f, 0x02
const CK_BYTE x25519_oid[] = { X25519_OID };
const CK_BYTE x448_oid[] = { X448_OID };
const CK_BYTE ed25519_oid[] = { ED25519_OID };
const CK_BYTE ed448_oid[] = { ED448_OID };

/* Thales Luna HSM OIDs */
#define ED25519_LUNA \
    0x06, 0x09, 0x2B, 0x06, 0x01, 0x04, 0x01, 0xDA, 0x47, 0x0F, 0x01
#define X25519_LUNA \
    0x06, 0x0A, 0x2B, 0x06, 0x01, 0x04, 0x01, 0x95, 0x55, 0x01, 0x05, 0x01
const CK_BYTE ed25519_luna[] = { ED25519_LUNA };
const CK_BYTE x25519_luna[] = { X25519_LUNA };

const CK_BYTE ed25519_oid_gnu[] = { ED25519_OID_GNU };
const CK_BYTE ed448_oid_vendor[] = { ED448_OID_VENDOR };

struct match_curve {
    const CK_BYTE *params;
    CK_ULONG params_len;
    const char *curve_name;
    int curve_nid;
    CK_ULONG key_bit_size;
    CK_ULONG key_size;
};

struct match_curve ed_params_table[] = {
    { ed25519_oid, sizeof(ed25519_oid), ED25519, NID_ED25519, ED25519_BIT_SIZE,
      ED25519_BYTE_SIZE },
    { ed448_oid, sizeof(ed448_oid), ED448, NID_ED448, ED448_BIT_SIZE,
      ED448_BYTE_SIZE },
    { ed25519_ec_params, sizeof(ed25519_ec_params), ED25519, NID_ED25519,
      ED25519_BIT_SIZE, ED25519_BYTE_SIZE },
    { ed448_ec_params, sizeof(ed448_ec_params), ED448, NID_ED448,
      ED448_BIT_SIZE, ED448_BYTE_SIZE },
    { ed25519_luna, sizeof(ed25519_luna), ED25519, NID_ED25519,
      ED25519_BIT_SIZE, ED25519_BYTE_SIZE },
    { ed25519_oid_gnu, sizeof(ed25519_oid_gnu), ED25519, NID_ED25519, ED25519_BIT_SIZE,
      ED25519_BYTE_SIZE },
    { ed448_oid_vendor, sizeof(ed448_oid_vendor), ED448, NID_ED448, ED448_BIT_SIZE,
      ED448_BYTE_SIZE },
};

struct match_curve x_params_table[] = {
    { x25519_oid, sizeof(x25519_oid), X25519_NAME, NID_X25519, X25519_BIT_SIZE,
      X25519_BYTE_SIZE },
    { x448_oid, sizeof(x448_oid), X448_NAME, NID_X448, X448_BIT_SIZE,
      X448_BYTE_SIZE },
    { x25519_ec_params, sizeof(x25519_ec_params), X25519_NAME, NID_X25519,
      X25519_BIT_SIZE, X25519_BYTE_SIZE },
    { x448_ec_params, sizeof(x448_ec_params), X448_NAME, NID_X448,
      X448_BIT_SIZE, X448_BYTE_SIZE },
    { x25519_luna, sizeof(x25519_luna), X25519_NAME, NID_X25519,
      X25519_BIT_SIZE, X25519_BYTE_SIZE },
};

CK_RV p11prov_match_curve(CK_KEY_TYPE type, CK_ATTRIBUTE *attr,
                          const char **curve_name, int *curve_nid,
                          CK_ULONG *key_bit_size, CK_ULONG *key_size)
{
    CK_RV rv = CKR_KEY_INDIGESTIBLE;
    struct match_curve *table = NULL;
    int table_size = 0;

    if (type == CKK_EC_EDWARDS || type == CKK_EC_EDWARDS_LEGACY) {
        table = ed_params_table;
        table_size = sizeof(ed_params_table) / sizeof(struct match_curve);
    } else if (type == CKK_EC_MONTGOMERY) {
        table = x_params_table;
        table_size = sizeof(x_params_table) / sizeof(struct match_curve);
    }
    for (int i = 0; i < table_size; i++) {
        if (attr->ulValueLen == table[i].params_len
            && memcmp(attr->pValue, table[i].params, attr->ulValueLen) == 0) {
            if (curve_name) {
                *curve_name = table[i].curve_name;
            }
            if (curve_nid) {
                *curve_nid = table[i].curve_nid;
            }
            if (key_bit_size) {
                *key_bit_size = table[i].key_bit_size;
            }
            if (key_size) {
                *key_size = table[i].key_size;
            }
            rv = CKR_OK;
            break;
        }
    }
    return rv;
}

bool is_edwards_ec_params(CK_ATTRIBUTE *attr)
{
    return
        (attr->ulValueLen == sizeof(ed25519_oid) &&
         memcmp(attr->pValue, ed25519_oid, sizeof(ed25519_oid)) == 0) ||

        (attr->ulValueLen == sizeof(ed448_oid) &&
         memcmp(attr->pValue, ed448_oid, sizeof(ed448_oid)) == 0);
}

bool is_ed448_ec_params(CK_ATTRIBUTE *attr) {
    return (attr->ulValueLen == sizeof(ed448_oid) &&
         memcmp(attr->pValue, ed448_oid, sizeof(ed448_oid)) == 0);
}

bool is_ed25519_ec_params(CK_ATTRIBUTE *attr) {
    return (attr->ulValueLen == sizeof(ed25519_oid) &&
         memcmp(attr->pValue, ed25519_oid, sizeof(ed25519_oid)) == 0);
}



/* This function attempts to return a public key from a private one.
 *
 * If a public key is already associated then it is immediately returned.
 *
 * Otherwise we create a mock object with a synthetic public key if
 * enough data is available (CKA_PUBLIC_KEY_INFO). This will then defer
 * searching for a key on the token only to a later time when
 * it is actually needed, or to generate a temporary session key
 * like we do for imported ephemeral keys.
 *
 * Finally if not enough public info is available we immediately try
 * a search so proper errors are returned to callers, instead of
 * deferring key issues to a later operation */
P11PROV_OBJ *p11prov_obj_pub_from_priv(P11PROV_OBJ *priv)
{
    CK_ATTRIBUTE *pkeyinfo = NULL;
    P11PROV_OBJ *key;

    if (priv->class != CKO_PRIVATE_KEY) {
        return NULL;
    }

    if (priv->assoc_obj
        && (priv->assoc_obj->class == CKO_PUBLIC_KEY
            || priv->assoc_obj->class == CKO_P11PROV_PUB_FROM_PRIV_KEY)) {
        return priv->assoc_obj;
    }

    /* If we do not have enough data for a synthetic key return an
     * immediate search for the object */
    pkeyinfo = p11prov_obj_get_attr(priv, CKA_PUBLIC_KEY_INFO);
    if (!pkeyinfo) {
        return p11prov_obj_find_associated(priv, CKO_PUBLIC_KEY);
    }

    /* we assume that if a public key exist, it will later be found in the
     * same slot as the private key */
    key = p11prov_obj_new(priv->ctx, priv->slotid, CK_P11PROV_IMPORTED_HANDLE,
                          CKO_P11PROV_PUB_FROM_PRIV_KEY);
    if (!key) {
        return NULL;
    }

    key->data.key = priv->data.key;

    /* make sure key is associated to the private one */
    p11prov_obj_set_associated(priv, key);
    p11prov_obj_set_associated(key, priv);

    return key;
}


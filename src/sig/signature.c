/* Copyright (C) 2022-2025 Simo Sorce <simo@redhat.com>
   SPDX-License-Identifier: Apache-2.0 */

#include "provider.h"
#include "sig/internal.h"
#include "openssl/evp.h"
#include "openssl/err.h"
#include "openssl/sha.h"

P11PROV_SIG_CTX *p11prov_sig_newctx(P11PROV_CTX *ctx, CK_MECHANISM_TYPE type,
                                    const char *properties)
{
    P11PROV_SIG_CTX *sigctx;

    sigctx = OPENSSL_zalloc(sizeof(P11PROV_SIG_CTX));
    if (sigctx == NULL) {
        return NULL;
    }

    sigctx->provctx = ctx;

    if (properties) {
        sigctx->properties = OPENSSL_strdup(properties);
        if (sigctx->properties == NULL) {
            OPENSSL_free(sigctx);
            return NULL;
        }
    }

    sigctx->mechtype = type;
    sigctx->mechanism.mechanism = CK_UNAVAILABLE_INFORMATION;

    return sigctx;
}

void *p11prov_sig_dupctx(void *ctx)
{
    P11PROV_SIG_CTX *sigctx = (P11PROV_SIG_CTX *)ctx;
    P11PROV_SIG_CTX *newctx;
    CK_SLOT_ID slotid = CK_UNAVAILABLE_INFORMATION;
    CK_OBJECT_HANDLE handle = CK_INVALID_HANDLE;
    CK_BYTE_PTR state = NULL;
    CK_ULONG state_len;
    bool reqlogin = false;
    CK_RV ret;

    if (sigctx == NULL) {
        return NULL;
    }

    P11PROV_debug("Duplicating context %p", ctx);

    switch (sigctx->operation) {
    case CKF_SIGN:
        reqlogin = true;
        /* fallthrough */
    case CKF_VERIFY:
        slotid = p11prov_obj_get_slotid(sigctx->key);
        handle = p11prov_obj_get_handle(sigctx->key);
        break;
    default:
        return NULL;
    }

    newctx = p11prov_sig_newctx(sigctx->provctx, sigctx->mechtype,
                                sigctx->properties);
    if (newctx == NULL) {
        return NULL;
    }

    newctx->key = p11prov_obj_ref(sigctx->key);
    newctx->mechtype = sigctx->mechtype;
    newctx->digest = sigctx->digest;
    newctx->pss_params = sigctx->pss_params;
    newctx->operation = sigctx->operation;

    newctx->eddsa_params = sigctx->eddsa_params;
    if (sigctx->eddsa_params.pContextData) {
        newctx->eddsa_params.pContextData =
            OPENSSL_memdup(sigctx->eddsa_params.pContextData,
                           sigctx->eddsa_params.ulContextDataLen);
    }
    newctx->use_eddsa_params = sigctx->use_eddsa_params;

    newctx->mldsa_paramset = sigctx->mldsa_paramset;
    newctx->mldsa_params = sigctx->mldsa_params;
    if (sigctx->mldsa_params.pContext) {
        newctx->mldsa_params.pContext = OPENSSL_memdup(
            sigctx->mldsa_params.pContext, sigctx->mldsa_params.ulContextLen);
    }

    if (sigctx->signature) {
        newctx->signature =
            OPENSSL_memdup(sigctx->signature, sigctx->signature_len);
        if (newctx->signature == NULL) {
            p11prov_sig_freectx(newctx);
            return NULL;
        }
        newctx->signature_len = sigctx->signature_len;
    }

    newctx->digest_op = sigctx->digest_op;

    if (sigctx->fallback_digest) {
        int err;
        newctx->fallback_digest = EVP_MD_CTX_new();
        if (!newctx->fallback_digest) {
            p11prov_sig_freectx(newctx);
            return NULL;
        }
        err = EVP_MD_CTX_copy_ex(newctx->fallback_digest,
                                 sigctx->fallback_digest);
        if (err != RET_OSSL_OK) {
            p11prov_sig_freectx(newctx);
            return NULL;
        }
    }

    newctx->fallback_operate = sigctx->fallback_operate;

    if (sigctx->session == NULL) {
        return newctx;
    }

    ret = CKR_OK;

    /* This is not really funny. OpenSSL by default assumes contexts with
     * operations in flight can be easily duplicated, with all the
     * cryptographic status and then both contexts can keep going
     * independently. We'll try to save/restore state here. for OpenSSL versions
     * greater than 3.2 this will be a hard failure, while for older OpenSSL
     * versions, in order to maintain compatibility with previous behavior
     * we just 'move' the the session to the new context and hope there is no
     * need for the old context which will have no session and just return
     * errors if an update is attempted. */

    if (slotid != CK_UNAVAILABLE_INFORMATION && handle != CK_INVALID_HANDLE) {
        CK_SESSION_HANDLE sess = p11prov_session_handle(sigctx->session);

        /* NOTE: most tokens will probably return errors trying to do this on
         * sign sessions. If GetOperationState fails we don't try to duplicate
         * the context and just return. */
        ret = p11prov_GetOperationState(sigctx->provctx, sess, NULL_PTR,
                                        &state_len);
        if (ret != CKR_OK) {
            goto done;
        }
        state = OPENSSL_malloc(state_len);
        if (state == NULL) {
            goto done;
        }

        ret =
            p11prov_GetOperationState(sigctx->provctx, sess, state, &state_len);
        if (ret != CKR_OK) {
            goto done;
        }

        ret = p11prov_get_session(newctx->provctx, &slotid, NULL, NULL,
                                  newctx->mechtype, NULL, NULL, reqlogin, false,
                                  &newctx->session);
        if (ret != CKR_OK) {
            P11PROV_raise(newctx->provctx, ret,
                          "Failed to open session on slot %lu", slotid);
            goto done;
        }
        sess = p11prov_session_handle(newctx->session);

        ret = p11prov_SetOperationState(newctx->provctx, sess, state, state_len,
                                        handle, handle);
    }

done:
    if (ret != CKR_OK) {
#if OPENSSL_VERSION_NUMBER >= 0x30200000L
        /* For OpenSSL 3.2+ we can fail duplication */
        p11prov_sig_freectx(newctx);
        newctx = NULL;
#else
        /* For OpenSSL 3.0.x, we must 'move' the context on failure */
        p11prov_return_session(newctx->session);

        /* move old session to new context, we swap because normally openssl
         * continues on the duplicated context */
        newctx->session = sigctx->session;
        newctx->session_state = sigctx->session_state;
        sigctx->session = NULL;
        sigctx->session_state = SESS_UNUSED;
#endif
    }
    OPENSSL_free(state);
    return newctx;
}

void p11prov_sig_freectx(void *ctx)
{
    P11PROV_SIG_CTX *sigctx = (P11PROV_SIG_CTX *)ctx;

    if (sigctx == NULL) {
        return;
    }

    if (sigctx->session) {
        if (sigctx->session_state == SESS_INITIALIZED) {
            /* Finalize any operation to avoid leaving a hanging
             * operation on this session. Ignore return errors here
             * intentionally as errors can be returned if the operation was
             * internally finalized because of a previous internal token
             * error state and, in any case, not much to be done. */
            CK_RV ret;
            CK_SESSION_HANDLE sess = p11prov_session_handle(sigctx->session);
            if (sigctx->operation == CKF_SIGN) {
                ret = p11prov_SignInit(sigctx->provctx, sess, NULL,
                                       CK_INVALID_HANDLE);
            } else {
                ret = p11prov_VerifyInit(sigctx->provctx, sess, NULL,
                                         CK_INVALID_HANDLE);
            }
            if (ret != CKR_OK) {
                /* NSS softokn has a broken interface and is incapable of
                 * dropping operations on sessions returning a generic
                 * CKR_MECHANISM_PARAM_INVALID when the mechanism is set to
                 * NULL. Attempt to force cancellation via C_SessionCancel. */
                ret = p11prov_SessionCancel(sigctx->provctx, sess,
                                            sigctx->operation);
            }
            if (ret != CKR_OK) {
                /* When this happens the session becomes broken as
                 * we can't initialize operations on it anymore */
                p11prov_session_mark_broken(sigctx->session);
            }
            sigctx->session_state = SESS_FINALIZED;
        }
        p11prov_return_session(sigctx->session);
    }

    OPENSSL_clear_free(sigctx->mldsa_params.pContext,
                       sigctx->mldsa_params.ulContextLen);
    OPENSSL_clear_free(sigctx->eddsa_params.pContextData,
                       sigctx->eddsa_params.ulContextDataLen);
    OPENSSL_free(sigctx->signature);
    EVP_MD_CTX_free(sigctx->fallback_digest);
    p11prov_obj_free(sigctx->key);
    OPENSSL_free(sigctx->properties);
    OPENSSL_clear_free(sigctx, sizeof(P11PROV_SIG_CTX));
}

CK_RV p11prov_sig_op_init(void *ctx, void *provkey, CK_FLAGS operation,
                          const char *digest)
{
    P11PROV_SIG_CTX *sigctx = (P11PROV_SIG_CTX *)ctx;
    P11PROV_OBJ *key = (P11PROV_OBJ *)provkey;
    CK_OBJECT_CLASS class;
    CK_RV ret;

    ret = p11prov_ctx_status(sigctx->provctx);
    if (ret != CKR_OK) {
        return ret;
    }

    class = p11prov_obj_get_class(key);
    switch (operation) {
    case CKF_SIGN:
        if (class != CKO_PRIVATE_KEY) {
            return CKR_KEY_TYPE_INCONSISTENT;
        }
        break;
    case CKF_VERIFY:
        if (class != CKO_PUBLIC_KEY) {
            key = p11prov_obj_pub_from_priv(key);
            if (!key) {
                return CKR_KEY_TYPE_INCONSISTENT;
            }
        }
        break;
    default:
        return CKR_GENERAL_ERROR;
    }
    sigctx->key = p11prov_obj_ref(key);
    if (sigctx->key == NULL) {
        return CKR_KEY_NEEDED;
    }
    sigctx->operation = operation;

    if (digest) {
        ret = p11prov_digest_get_by_name(digest, &sigctx->digest);
        if (ret != CKR_OK) {
            ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_DIGEST);
            return ret;
        }
    }

    return CKR_OK;
}

static CK_RV mech_fallback_init(P11PROV_SIG_CTX *sigctx, CK_SLOT_ID slotid)
{
    const OSSL_PROVIDER *prov;
    void *provctx;
    const char *digest;
    EVP_MD *md = NULL;
    OSSL_LIB_CTX *libctx;
    const OSSL_PARAM *pparams = NULL;
    OSSL_PARAM params[] = {
        OSSL_PARAM_construct_ulong(P11PROV_PARAM_SLOT_ID, &slotid),
        OSSL_PARAM_construct_end(),
    };
    CK_RV ret;
    int err;

    P11PROV_debug("Enable fallback for mechanism %lx", sigctx->mechtype);

    ret = p11prov_digest_get_name(sigctx->digest, &digest);
    if (ret != CKR_OK) {
        P11PROV_raise(sigctx->provctx, ret, "Failed to get name for digest %lx",
                      sigctx->digest);
        goto done;
    }

    libctx = p11prov_ctx_get_libctx(sigctx->provctx);
    /* FIXME: should we add sigctx->properties here ? (ex: fips=yes) */
    /* try to keep digest on token but allow default (via "?") to provide
     * digests. */
    md = EVP_MD_fetch(libctx, digest, "?" P11PROV_DEFAULT_PROPERTIES);
    if (!md) {
        ret = CKR_GENERAL_ERROR;
        P11PROV_raise(sigctx->provctx, ret,
                      "Failed to get context for EVP digest '%s'", digest);
        goto done;
    }

    sigctx->fallback_digest = EVP_MD_CTX_new();
    if (!sigctx->fallback_digest) {
        ret = CKR_HOST_MEMORY;
        P11PROV_raise(sigctx->provctx, ret, "Failed to init fallback context");
        goto done;
    }

    /* if it is us, set a slot preference */
    prov = EVP_MD_get0_provider(md);
    if (prov) {
        provctx = OSSL_PROVIDER_get0_provider_ctx(prov);
        if (provctx == sigctx->provctx) {
            pparams = params;
        }
    }

    err = EVP_DigestInit_ex2(sigctx->fallback_digest, md, pparams);
    if (err != RET_OSSL_OK) {
        ret = CKR_GENERAL_ERROR;
        P11PROV_raise(sigctx->provctx, ret, "Failed to init EVP digest");
        goto done;
    }

    /* done */
    ret = CKR_OK;

done:
    EVP_MD_free(md);
    return ret;
}

static CK_RV p11prov_sig_operate_init(P11PROV_SIG_CTX *sigctx, bool digest_op,
                                      P11PROV_SESSION **_session)
{
    P11PROV_SESSION *session = NULL;
    CK_OBJECT_HANDLE handle;
    CK_SESSION_HANDLE sess;
    CK_SLOT_ID slotid;
    bool reqlogin = false;
    bool always_auth = false;
    CK_RV ret;
    const char *op_name = (sigctx->operation == CKF_SIGN) ? "Sign" : "Verify";

    P11PROV_debug("p11prov_sig_operate_init: ENTER");
    P11PROV_debug("p11prov_sig_operate_init: sigctx=%p, op=%s, digest_op=%s",
                  (void*)sigctx, op_name, digest_op ? "true" : "false");

    ret = p11prov_ctx_status(sigctx->provctx);
    if (ret != CKR_OK) {
        P11PROV_debug("p11prov_sig_operate_init: ctx status check failed with ret=0x%lx", ret);
        return ret;
    }

    handle = p11prov_obj_get_handle(sigctx->key);
    if (handle == CK_INVALID_HANDLE) {
        P11PROV_raise(sigctx->provctx, CKR_KEY_HANDLE_INVALID,
                      "Provided key has invalid handle");
        P11PROV_debug("p11prov_sig_operate_init: invalid key handle");
        return CKR_KEY_HANDLE_INVALID;
    }

    /* this need to be fetched after p11prov_obj_get_handle() as the
     * object may be refreshed including updating the slotid in that
     * call, and some keys depends on it. */
    slotid = p11prov_obj_get_slotid(sigctx->key);
    if (slotid == CK_UNAVAILABLE_INFORMATION) {
        P11PROV_raise(sigctx->provctx, CKR_SLOT_ID_INVALID,
                      "Provided key has invalid slot");
        P11PROV_debug("p11prov_sig_operate_init: invalid slotid");
        return CKR_SLOT_ID_INVALID;
    }

    P11PROV_debug_mechanism(sigctx->provctx, slotid,
                            sigctx->mechanism.mechanism);
    P11PROV_debug("p11prov_sig_operate_init: op=%s, key handle=%lu, slot=%lu, "
                  "mech=0x%lx, mechtype=0x%lx (sigctx=%p)",
                  op_name, handle, slotid, sigctx->mechanism.mechanism,
                  sigctx->mechtype, (void *)sigctx);

    if (sigctx->operation == CKF_SIGN) {
        reqlogin = true;
    }
    P11PROV_debug("p11prov_sig_operate_init: reqlogin=%s", reqlogin ? "true" : "false");

    P11PROV_debug("p11prov_sig_operate_init: attempting to acquire session");
    ret = p11prov_try_session_ref(sigctx->key, sigctx->mechanism.mechanism,
                                  reqlogin, false, &session);
    P11PROV_debug("p11prov_sig_operate_init: session acquisition ret=0x%lx", ret);

    switch (ret) {
    case CKR_OK:
        sess = p11prov_session_handle(session);
        P11PROV_debug("p11prov_sig_operate_init: session handle=%lu", sess);

        if (sigctx->operation == CKF_SIGN) {
            P11PROV_debug("p11prov_sig_operate_init: calling C_SignInit");
            ret = p11prov_SignInit(sigctx->provctx, sess, &sigctx->mechanism,
                                   handle);
            P11PROV_debug("p11prov_sig_operate_init: C_SignInit ret=0x%lx", ret);
        } else {
            P11PROV_debug("p11prov_sig_operate_init: calling C_VerifyInit");
            ret = p11prov_VerifyInit(sigctx->provctx, sess, &sigctx->mechanism,
                                     handle);
            P11PROV_debug("p11prov_sig_operate_init: C_VerifyInit ret=0x%lx", ret);
        }
        if (ret == CKR_OK) {
            sigctx->session_state = SESS_INITIALIZED;
            P11PROV_debug("p11prov_sig_operate_init: session initialized");
        } else {
            P11PROV_raise(sigctx->provctx, ret,
                          "C_%sInit failed (handle=%lu, slot=%lu, mech=0x%lx)",
                          op_name, handle, slotid, sigctx->mechanism.mechanism);
        }
        break;
    case CKR_MECHANISM_INVALID:
        P11PROV_debug("p11prov_sig_operate_init: CKR_MECHANISM_INVALID, digest_op=%s", digest_op ? "true" : "false");
        if (!digest_op || sigctx->mechanism.mechanism == sigctx->mechtype) {
            /* Even the raw signature mechanism is not supported */
            P11PROV_raise(sigctx->provctx, ret,
                          "Unsupported mechanism family %lx for slot %lu",
                          sigctx->mechtype, slotid);
            goto done;
        }

        P11PROV_debug("p11prov_sig_operate_init: attempting fallback init");
        ret = mech_fallback_init(sigctx, slotid);
        P11PROV_debug("p11prov_sig_operate_init: fallback init ret=0x%lx", ret);
        goto done;
        break;
    default:
        P11PROV_raise(sigctx->provctx, ret, "Failed to acquire session");
        goto done;
    }

    if (reqlogin) {
        always_auth =
            p11prov_obj_get_bool(sigctx->key, CKA_ALWAYS_AUTHENTICATE, false);
        P11PROV_debug("p11prov_sig_operate_init: always_auth=%s", always_auth ? "true" : "false");
    }

    if (always_auth) {
        P11PROV_debug("p11prov_sig_operate_init: performing context-specific login");
        ret = p11prov_context_specific_login(session, NULL, NULL, NULL);
        P11PROV_debug("p11prov_sig_operate_init: context_specific_login ret=0x%lx", ret);
    }

done:
    if (ret != CKR_OK) {
        P11PROV_debug("p11prov_sig_operate_init: failure, releasing session");
        p11prov_return_session(session);
    } else {
        P11PROV_debug("p11prov_sig_operate_init: SUCCESS");
        *_session = session;
    }
    P11PROV_debug("p11prov_sig_operate_init: EXIT with ret=0x%lx", ret);
    return ret;
}

CK_RV p11prov_sig_operate(P11PROV_SIG_CTX *sigctx, unsigned char *sig,
                          size_t *siglen, size_t sigsize, unsigned char *tbs,
                          size_t tbslen)
{
    P11PROV_SESSION *session;
    CK_SESSION_HANDLE sess;
    CK_ULONG sig_size = sigsize;
    CK_RV ret;
    const char *op_name = (sigctx->operation == CKF_SIGN) ? "Sign" : "Verify";

    P11PROV_debug("p11prov_sig_operate: ENTER");
    P11PROV_debug("p11prov_sig_operate: op=%s, sigctx=%p", op_name, (void*)sigctx);

    if (sig == NULL) {
        P11PROV_debug("p11prov_sig_operate: sig buffer is NULL, returning CKR_ARGUMENTS_BAD");
        return CKR_ARGUMENTS_BAD;
    }

    /* Log key information */
    if (sigctx->key) {
        P11PROV_debug("p11prov_sig_operate: key handle=%lu, slotid=%lu, class=%u, type=%lu",
                      p11prov_obj_get_handle(sigctx->key),
                      p11prov_obj_get_slotid(sigctx->key),
                      p11prov_obj_get_class(sigctx->key),
                      sigctx->key->data.key.type);
    }

    /* Log mechanism info */
    P11PROV_debug("p11prov_sig_operate: mechtype=0x%lx, mechanism=0x%lx, digest=0x%lx",
                  sigctx->mechtype, sigctx->mechanism.mechanism, sigctx->digest);

    /* Log input data */
    P11PROV_debug("p11prov_sig_operate: tbslen=%zu, sigsize=%zu", tbslen, sigsize);
    if (tbs && tbslen > 0) {
        size_t dump_len = (tbslen > 64) ? 64 : tbslen;
        char hex[128];
        size_t hex_pos = 0;
        for (size_t i = 0; i < dump_len; i++) {
            hex_pos += snprintf(hex + hex_pos, sizeof(hex) - hex_pos, "%02x", tbs[i]);
        }
        if (tbslen > 64) {
            P11PROV_debug("p11prov_sig_operate: tbs (first 64 bytes): %s... (truncated)", hex);
        } else {
            P11PROV_debug("p11prov_sig_operate: tbs: %s", hex);
        }
    }

    ret = p11prov_sig_operate_init(sigctx, false, &session);
    if (ret != CKR_OK) {
        P11PROV_debug("p11prov_sig_operate: operate_init failed with ret=0x%lx", ret);
        return ret;
    }
    sess = p11prov_session_handle(session);
    P11PROV_debug("p11prov_sig_operate: session handle=%lu", sess);

    if (sigctx->operation == CKF_SIGN) {
        P11PROV_debug("p11prov_sig_operate: calling C_Sign");
        ret = p11prov_Sign(sigctx->provctx, sess, tbs, tbslen, sig, &sig_size);
        P11PROV_debug("p11prov_sig_operate: C_Sign returned ret=0x%lx, sig_size=%lu", ret, sig_size);
    } else {
        P11PROV_debug("p11prov_sig_operate: calling C_Verify");
        ret = p11prov_Verify(sigctx->provctx, sess, tbs, tbslen, sig, sigsize);
        P11PROV_debug("p11prov_sig_operate: C_Verify returned ret=0x%lx", ret);
    }
    sigctx->session_state = SESS_FINALIZED;
    if (ret == CKR_OK) {
        if (siglen) {
            *siglen = sig_size;
        }
        /* Log signature output */
        if (sig && sig_size > 0) {
            size_t dump_len = (sig_size > 64) ? 64 : sig_size;
            char hex[128];
            size_t hex_pos = 0;
            for (size_t i = 0; i < dump_len; i++) {
                hex_pos += snprintf(hex + hex_pos, sizeof(hex) - hex_pos, "%02x", sig[i]);
            }
            if (sig_size > 64) {
                P11PROV_debug("p11prov_sig_operate: %s SUCCESS, signature (first 64 bytes): %s... (truncated, total %lu bytes)",
                              op_name, hex, sig_size);
            } else {
                P11PROV_debug("p11prov_sig_operate: %s SUCCESS, signature: %s (len=%lu)",
                              op_name, hex, sig_size);
            }
        } else {
            P11PROV_debug("p11prov_sig_operate: %s SUCCESS, no signature output", op_name);
        }
    } else {
        P11PROV_debug("p11prov_sig_operate: %s FAILED with ret=0x%lx", op_name, ret);
        P11PROV_raise(sigctx->provctx, ret, "C_%s failed", op_name);
    }

    p11prov_return_session(session);
    P11PROV_debug("p11prov_sig_operate: EXIT with ret=0x%lx", ret);
    return ret;
}

int p11prov_sig_digest_update(P11PROV_SIG_CTX *sigctx, unsigned char *data,
                              size_t datalen)
{
    CK_SESSION_HANDLE sess;
    CK_RV ret;
    const char *op_name = (sigctx->operation == CKF_SIGN) ? "Sign" : "Verify";

    P11PROV_debug("p11prov_sig_digest_update: ENTER");
    P11PROV_debug("p11prov_sig_digest_update: op=%s, sigctx=%p, datalen=%zu",
                  op_name, (void*)sigctx, datalen);

    /* Log input data */
    if (data && datalen > 0) {
        size_t dump_len = (datalen > 64) ? 64 : datalen;
        char hex[128];
        size_t hex_pos = 0;
        for (size_t i = 0; i < dump_len; i++) {
            hex_pos += snprintf(hex + hex_pos, sizeof(hex) - hex_pos, "%02x", data[i]);
        }
        if (datalen > 64) {
            P11PROV_debug("p11prov_sig_digest_update: data (first 64 bytes): %s... (truncated)", hex);
        } else {
            P11PROV_debug("p11prov_sig_digest_update: data: %s", hex);
        }
    }

    if (!sigctx->fallback_digest && !sigctx->session) {
        P11PROV_debug("p11prov_sig_digest_update: no session, calling operate_init");
        ret = p11prov_sig_operate_init(sigctx, true, &sigctx->session);
        if (ret != CKR_OK) {
            P11PROV_debug("p11prov_sig_digest_update: operate_init failed with ret=0x%lx", ret);
            return RET_OSSL_ERR;
        }
    }

    if (sigctx->fallback_digest) {
        P11PROV_debug("p11prov_sig_digest_update: using fallback digest");
        return EVP_DigestUpdate(sigctx->fallback_digest, data, datalen);
    }

    if (!sigctx->session) {
        P11PROV_raise(sigctx->provctx, CKR_GENERAL_ERROR,
                      "No initialized session in digest update");
        P11PROV_debug("p11prov_sig_digest_update: no initialized session");
        return RET_OSSL_ERR;
    }

    /* we have an initialized session */
    sess = p11prov_session_handle(sigctx->session);
    P11PROV_debug("p11prov_sig_digest_update: session handle=%lu", sess);

    if (sigctx->operation == CKF_SIGN) {
        P11PROV_debug("p11prov_sig_digest_update: calling C_SignUpdate");
        ret = p11prov_SignUpdate(sigctx->provctx, sess, data, datalen);
    } else {
        P11PROV_debug("p11prov_sig_digest_update: calling C_VerifyUpdate");
        ret = p11prov_VerifyUpdate(sigctx->provctx, sess, data, datalen);
    }
    if (ret != CKR_OK) {
        P11PROV_debug("p11prov_sig_digest_update: C_%sUpdate failed with ret=0x%lx", op_name, ret);
        P11PROV_raise(sigctx->provctx, ret, "C_%sUpdate failed", op_name);
        p11prov_return_session(sigctx->session);
        sigctx->session = NULL;
        return RET_OSSL_ERR;
    }

    P11PROV_debug("p11prov_sig_digest_update: SUCCESS");
    return RET_OSSL_OK;
}

static CK_RV mech_fallback_final(P11PROV_SIG_CTX *sigctx, unsigned char *sig,
                                 size_t *siglen, size_t sigsize, size_t mdsize)
{
    P11PROV_SIG_CTX *subctx = NULL;
    CK_BYTE digest[mdsize];
    unsigned int digest_len = mdsize;
    CK_OBJECT_HANDLE handle;
    const char *digest_name = NULL;
    int err;
    CK_RV ret;

    err = EVP_DigestFinal_ex(sigctx->fallback_digest, digest, &digest_len);
    if (err != RET_OSSL_OK) {
        ret = CKR_GENERAL_ERROR;
        P11PROV_raise(sigctx->provctx, ret, "EVP_DigestFinal_ex() failed");
        goto done;
    }
    if (digest_len != mdsize) {
        ret = CKR_GENERAL_ERROR;
        P11PROV_raise(sigctx->provctx, ret, "Inconsistent digest size");
        goto done;
    }

    handle = p11prov_obj_get_handle(sigctx->key);
    if (handle == CK_INVALID_HANDLE) {
        ret = CKR_KEY_HANDLE_INVALID;
        P11PROV_raise(sigctx->provctx, ret, "Provided key has invalid handle");
        goto done;
    }

    subctx = p11prov_sig_newctx(sigctx->provctx, sigctx->mechtype,
                                sigctx->properties);
    if (!subctx) {
        ret = CKR_HOST_MEMORY;
        goto done;
    }

    ret = p11prov_digest_get_name(sigctx->digest, &digest_name);
    if (ret != CKR_OK) {
        P11PROV_raise(sigctx->provctx, ret, "Failed to get digest name");
        goto done;
    }

    ret = p11prov_sig_op_init(subctx, sigctx->key, sigctx->operation,
                              digest_name);
    if (ret != CKR_OK) {
        P11PROV_raise(sigctx->provctx, ret, "Failed to setup sigver fallback");
        goto done;
    }

    if (sigctx->fallback_operate) {
        ret = sigctx->fallback_operate(subctx, sig, siglen, sigsize, digest,
                                       mdsize);
    } else {
        ret = p11prov_sig_operate(subctx, sig, siglen, sigsize, digest, mdsize);
    }
    if (ret != CKR_OK) {
        P11PROV_raise(sigctx->provctx, ret, "Failure in sigver fallback");
        goto done;
    }

done:
    p11prov_sig_freectx(subctx);
    return ret;
}

int p11prov_sig_digest_final(P11PROV_SIG_CTX *sigctx, unsigned char *sig,
                             size_t *siglen, size_t sigsize)
{
    CK_SESSION_HANDLE sess;
    CK_ULONG sig_size = sigsize;
    int result = RET_OSSL_ERR;
    CK_RV ret;
    const char *op_name = (sigctx->operation == CKF_SIGN) ? "Sign" : "Verify";

    P11PROV_debug("p11prov_sig_digest_final: ENTER");
    P11PROV_debug("p11prov_sig_digest_final: op=%s, sigctx=%p, sigsize=%zu",
                  op_name, (void*)sigctx, sigsize);

    if (sig == NULL) {
        P11PROV_debug("p11prov_sig_digest_final: sig is NULL, skipping");
        goto done;
    }
    if (sigctx->operation == CKF_VERIFY && sigsize == 0) {
        P11PROV_debug("p11prov_sig_digest_final: verify with no signature, skipping");
        goto done;
    }

    if (sigctx->fallback_digest) {
        size_t mdsize;
        P11PROV_debug("p11prov_sig_digest_final: using fallback digest path");
        ret = p11prov_digest_get_digest_size(sigctx->digest, &mdsize);
        if (ret != CKR_OK) {
            P11PROV_raise(sigctx->provctx, ret,
                          "Unexpected get_digest_size error");
            goto done;
        }
        P11PROV_debug("p11prov_sig_digest_final: digest size=%zu", mdsize);

        ret = mech_fallback_final(sigctx, sig, siglen, sigsize, mdsize);
        if (ret == CKR_OK) {
            result = RET_OSSL_OK;
            P11PROV_debug("p11prov_sig_digest_final: mech_fallback_final SUCCESS");
        } else {
            P11PROV_debug("p11prov_sig_digest_final: mech_fallback_final FAILED with ret=0x%lx", ret);
        }
        goto done;
    }

    if (!sigctx->session) {
        P11PROV_raise(sigctx->provctx, CKR_GENERAL_ERROR,
                      "No initialized session in digest final");
        P11PROV_debug("p11prov_sig_digest_final: no initialized session");
        goto done;
    }

    sess = p11prov_session_handle(sigctx->session);
    P11PROV_debug("p11prov_sig_digest_final: session handle=%lu", sess);

    /* Log signature input for verify operations */
    if (sigctx->operation == CKF_VERIFY && sig && sigsize > 0) {
        size_t dump_len = (sigsize > 64) ? 64 : sigsize;
        char hex[128];
        size_t hex_pos = 0;
        for (size_t i = 0; i < dump_len; i++) {
            hex_pos += snprintf(hex + hex_pos, sizeof(hex) - hex_pos, "%02x", sig[i]);
        }
        if (sigsize > 64) {
            P11PROV_debug("p11prov_sig_digest_final: signature to verify (first 64 bytes): %s... (truncated, total %zu bytes)", hex, sigsize);
        } else {
            P11PROV_debug("p11prov_sig_digest_final: signature to verify: %s (len=%zu)", hex, sigsize);
        }
    }

    if (sigctx->operation == CKF_SIGN) {
        P11PROV_debug("p11prov_sig_digest_final: calling C_SignFinal");
        ret = p11prov_SignFinal(sigctx->provctx, sess, sig, &sig_size);
        P11PROV_debug("p11prov_sig_digest_final: C_SignFinal returned ret=0x%lx, sig_size=%lu", ret, sig_size);
    } else {
        P11PROV_debug("p11prov_sig_digest_final: calling C_VerifyFinal");
        ret = p11prov_VerifyFinal(sigctx->provctx, sess, sig, sigsize);
        P11PROV_debug("p11prov_sig_digest_final: C_VerifyFinal returned ret=0x%lx", ret);
    }
    sigctx->session_state = SESS_FINALIZED;
    if (ret == CKR_OK) {
        if (siglen) {
            *siglen = sig_size;
        }
        result = RET_OSSL_OK;
        /* Log signature output for sign operations */
        if (sig && sig_size > 0 && sigctx->operation == CKF_SIGN) {
            size_t dump_len = (sig_size > 64) ? 64 : sig_size;
            char hex[128];
            size_t hex_pos = 0;
            for (size_t i = 0; i < dump_len; i++) {
                hex_pos += snprintf(hex + hex_pos, sizeof(hex) - hex_pos, "%02x", sig[i]);
            }
            if (sig_size > 64) {
                P11PROV_debug("p11prov_sig_digest_final: Sign SUCCESS, signature (first 64 bytes): %s... (truncated, total %lu bytes)", hex, sig_size);
            } else {
                P11PROV_debug("p11prov_sig_digest_final: Sign SUCCESS, signature: %s (len=%lu)", hex, sig_size);
            }
        }
    } else {
        P11PROV_debug("p11prov_sig_digest_final: %sFinal FAILED with ret=0x%lx", op_name, ret);
        P11PROV_raise(sigctx->provctx, ret, "C_%sFinal failed", op_name);
    }

done:
    p11prov_return_session(sigctx->session);
    sigctx->session = NULL;
    P11PROV_debug("p11prov_sig_digest_final: EXIT with result=%d", result);
    return result;
}

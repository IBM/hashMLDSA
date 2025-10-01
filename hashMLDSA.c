/*
Copyright 2025 IBM

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <errno.h>
#include <threads.h>  // Only available in C11

/*
 * Define a macro for thread-local storage
 * Note this won't work for some environments (eg z/OS)
 */
#if defined(_MSC_VER)
    #define THREAD_LOCAL __declspec(thread)
#elif defined(__GNUC__) || defined(__clang__)
    #define THREAD_LOCAL __thread
#else
    #define THREAD_LOCAL _Thread_local  // C11 standard
#endif

/* We get support from OpenSSL */
#include <openssl/ssl.h>
#include <openssl/objects.h>
#include <openssl/asn1.h>
#include <openssl/provider.h>
#include <openssl/err.h>

#include "hashMLDSA.h"

#if defined(OPENSSL_THREADS_NONE)
    char* error_message = NULL;
#else
    THREAD_LOCAL char *error_message = NULL;
#endif

/*
 * alternative to set_error_message(format, ...)
 * where x could be context or input_data
 */
#define debug_output_error(x, format, ...) \
    do { \
        if ((x)->test_mode) { \
            fprintf(stderr, "ERROR: " format "\n", ##__VA_ARGS__); \
        } \
    } while (0)


/*
 * Return codes here are defined to replicate OpenSSL as this is really a helper library for OpenSSL
 */
#define FAILURE 0
#define SUCCESS 1

/* signature ids */
enum sig_alg_internal_id {
    MLDSA44,
    MLDSA65,
    MLDSA87
};

/* signature information table */
struct sigalg_ref {
    enum sig_alg_internal_id id;
    const char *sig_alg_name;
    const unsigned int sig_strength;
    const unsigned int sig_len;
    const char *default_digest;
};

/*
 * TODO: Ideally this table should be populated at library load time or on the first creation of a context (so as to allow for static linking support)
 * to get security strength (EVP_PKEY_get_security_bits(key)) to get signature size (EVP_PKEY_sign(sctx, NULL, &sig_len, NULL, 0))
 * to be more flexible but the data here reflects what OpenSSL 3.5 returns
 */
#define NUM_SIG_ALGS 3
static const struct sigalg_ref sigalg_defs[NUM_SIG_ALGS] = {
    {MLDSA44, "ML-DSA-44", 128, 2420, "SHA3-256"},
    {MLDSA65, "ML-DSA-65", 192, 3309, "SHA3-384"},
    {MLDSA87, "ML-DSA-87", 256, 4627, "SHA3-512"}
};

struct hashMLDSA_digest {
    const char* digest_name;
    size_t digest_hash_len;
    size_t min_allowed_digest_hash_len;
    EVP_MD_CTX *mdctx;
    const EVP_MD *md;
    int is_xof;
    unsigned char *oid;
    size_t oid_len;
};

struct hashMLDSA_ctx {
    OSSL_LIB_CTX *lib_ctx;
    OSSL_PROVIDER *deflt;

    enum sig_alg_internal_id id;
    const char* sig_alg_name;
    EVP_SIGNATURE *sig_alg;
    unsigned int sig_strength;
    size_t sig_len;

    unsigned int test_mode;

    struct hashMLDSA_digest digest;

    int message_encoding;
    OSSL_PARAM signatureParameters[3];
};

struct hashMLDSA {
    enum sig_alg_internal_id id;

    /* Either you provide an already hashed_message */
    const unsigned char* hashed_message;
    size_t hashed_message_len;
    /* Or you provide the message and context string to be hashed */
    const unsigned char* context_string;
    size_t context_string_len;
    const unsigned char* message;
    size_t message_len;

    unsigned int test_mode;

    /* copy of message digest information from the context */
    struct hashMLDSA_digest digest;
};

static void set_error_message(const char *format, ...)
{
    va_list args;

    va_start(args, format);
    size_t required_size = vsnprintf(NULL, 0, format, args) + 1;
    va_end(args);

    error_message = realloc(error_message, required_size);
    if (!error_message)
        return;

    va_start(args, format);
    vsnprintf(error_message, required_size, format, args);
    error_message[required_size - 1] = '\0';
    va_end(args);
}

static int check_default_provider(HASHMLDSA_CTX *ctx)
{
    if (OSSL_PROVIDER_available(ctx->lib_ctx, "default") == 0) {
       set_error_message("default provider not loaded into openssl library context");
       goto error;
    }

    return SUCCESS;

error:
    return FAILURE;
}

static int dump_oid(unsigned char *oid, size_t oid_len) {
    fprintf(stderr, "OID[]={");
    for (int i = 0; i < oid_len; i++) {
        fprintf(stderr, "0x%02X", oid[i]);
        if (i < oid_len - 1) fprintf(stderr, ", ");
    }
    fprintf(stderr, "};\n");
}

static int get_md_oid(const EVP_MD *md, unsigned char *oid, size_t *oid_len) {
    int nid, len;
    ASN1_OBJECT *obj;
    unsigned char *p;

    nid = EVP_MD_type(md);
    obj = OBJ_nid2obj(nid);

    if (!obj) {
        set_error_message("Failed to get ASN1_OBJECT for NID %d Error was %s", nid, ERR_error_string(ERR_get_error(), NULL));
        goto error;
    }

    len = i2d_ASN1_OBJECT(obj, NULL);
    if (oid == NULL) {
        *oid_len = len;
        goto success;
    }

    if (len <= 0 || len > *oid_len) {
        set_error_message("Invalid DER length");
        goto error;
    }

    p = oid;
    i2d_ASN1_OBJECT(obj, &p);

success:
    if (obj)
        ASN1_OBJECT_free(obj);
    return SUCCESS;

error:
    if (obj)
        ASN1_OBJECT_free(obj);
    return FAILURE;
}

static size_t get_hash_length(const struct hashMLDSA_digest *digest,
                              const unsigned char* hashed_message,
                              size_t hashed_message_len)
{
    size_t hash_start;
    size_t oid_start;
    size_t hash_len = 0;

    /* break down the hashed message to validate it and also get the length of the hash itself */
    if (hashed_message[0] != 0x01) {
        set_error_message("Hashed message does not start with the correct domain identifier");
        goto exit;
    }

    oid_start = (size_t)hashed_message[1] + 2;
    if (hashed_message_len <= oid_start + 1) {
        set_error_message("Hashed message is too short");
        goto exit;
    }
    if (hashed_message[oid_start] != 0x06) {
        set_error_message("Hashed message does not contain the OID for the digest");
        goto exit;
    }

    if (memcmp(&hashed_message[oid_start], digest->oid, digest->oid_len) != 0) {
        set_error_message("Hashed message has not been hashed using the expected digest of %s", digest->digest_name);
        goto exit;
    }

    hash_start = oid_start + 2 + hashed_message[oid_start + 1];
    if (hashed_message_len <= hash_start + 1) {
        set_error_message("Hashed message is too short");
        goto exit;
    }
    if (hashed_message_len - hash_start <= 0) {
        set_error_message("Hashed message is too short");
        goto exit;
    }

    hash_len = hashed_message_len - hash_start;

    if (hash_len != digest->digest_hash_len) {
        set_error_message("Hash length of %u within hashed message does not match expected hash length of %u", hash_len, digest->digest_hash_len);
        hash_len = 0;
    }

exit:
    return hash_len;

}

/*
 * creates a Hashed Message. This method performs no check to see if both a hashed message and details of the message to
 * be hashed have been provided. It just looks at the information provided and returns the hashed message
 */
static int create_hashed_message(const HASHMLDSA *input_data,
                                 unsigned char *hashed_message,
                                 size_t *hashed_message_len)

{
    const struct hashMLDSA_digest *digest;
    unsigned char *hash = NULL;
    size_t calculated_hashed_message_len = 0;

    if (input_data == NULL) {
        set_error_message("No HASHMLDSA data provided");
        goto error;
    }

    /* Need to check this in case a blank input_data object is given */
    if (input_data->message == NULL || input_data->message_len == 0) {
        set_error_message("Message cannot be NULL or empty");
        goto error;
    }

    if (hashed_message_len == NULL) {
        set_error_message("No hashed message length provided");
        goto error;
    }

    digest = &input_data->digest;

    /* calculate the length of the hashed message */
    calculated_hashed_message_len = 1 + 1 + input_data->context_string_len + digest->oid_len + digest->digest_hash_len;
    if (hashed_message == NULL) {
        *hashed_message_len = calculated_hashed_message_len;
        goto success;
    }


    if (*hashed_message_len < calculated_hashed_message_len) {
        set_error_message("Insufficient space provided for final hashed message");
        goto error;
    }

    hash = OPENSSL_zalloc(digest->digest_hash_len);
    if (hash == NULL) {
        set_error_message("Failed to allocate memory for hash");
        goto error;
    }

    if (digest->is_xof) {
        if (EVP_DigestInit_ex(digest->mdctx, digest->md, NULL) <= 0) {
            set_error_message("Failed to initialize XOF digest: %s", ERR_error_string(ERR_get_error(), NULL));
            goto error;
        }

        if (EVP_DigestUpdate(digest->mdctx, input_data->message, input_data->message_len) <= 0) {
            set_error_message("Failed to update XOF digest: %s", ERR_error_string(ERR_get_error(), NULL));
            goto error;
        }

        if (EVP_DigestFinalXOF(digest->mdctx, hash, digest->digest_hash_len) <= 0) {
            set_error_message("Failed to finalise XOF digest: %s", ERR_error_string(ERR_get_error(), NULL));
            goto error;
        }
    } else {
        if (EVP_Digest(input_data->message, input_data->message_len, hash, NULL, digest->md, NULL) <= 0) {
            set_error_message("Hash failed with error: %s", ERR_error_string(ERR_get_error(), NULL));
            goto error;
        }
    }

    /*
     * We assemble the RAW hashed message with hashed message format:
     * 0x01 || len(context string) || DER encoding of OID || MD(message)
     */
    hashed_message[0] = 0x01;
    hashed_message[1] = (char)input_data->context_string_len;
    memcpy(&(hashed_message[2]), input_data->context_string, input_data->context_string_len);
    memcpy(&(hashed_message[2 + input_data->context_string_len]), digest->oid, digest->oid_len);
    memcpy(&(hashed_message[2 + input_data->context_string_len + digest->oid_len]), hash, digest->digest_hash_len);
    *hashed_message_len = calculated_hashed_message_len;

success:
    OPENSSL_free(hash);
    return SUCCESS;

error:
    OPENSSL_free(hash);
    return FAILURE;
}

/*
 * Initialise the digest information in the input_data from the context
 */
static int init_message_digest(const HASHMLDSA_CTX *ctx, HASHMLDSA *input_data)
{
    /*
     * if we did a pure shallow copy of the message digest information it
     * means the input data is tied to the unfreed context it came from and that may be too restrictive ?
     * who knows, so we will do a complete copy and free up at the end
     * only if we override will we replace the information.
    */
    input_data->digest.oid = malloc(ctx->digest.oid_len);
    if (!input_data->digest.oid) {
        set_error_message("Failed to allocate memory to store message digest information");
        return FAILURE;
    }
    memcpy(input_data->digest.oid, ctx->digest.oid, ctx->digest.oid_len);
    input_data->digest.oid_len = ctx->digest.oid_len;
    input_data->digest.digest_hash_len = ctx->digest.digest_hash_len;
    input_data->digest.digest_name = ctx->digest.digest_name;
    input_data->digest.md = ctx->digest.md;
    input_data->digest.is_xof = ctx->digest.is_xof;
    input_data->digest.min_allowed_digest_hash_len = ctx->digest.min_allowed_digest_hash_len;

    /* allocate an ND CTX if this is xof */
    if (input_data->digest.is_xof) {
        input_data->digest.mdctx = EVP_MD_CTX_new();
        if (input_data->digest.mdctx == NULL) {
            set_error_message("Failed to create context for XOF digest");
            goto error;
        }
    } else
        input_data->digest.mdctx = NULL; /* ensure this is set to NULL to indicate it's not defined */
    return SUCCESS;

error:
    free(input_data->digest.oid);
    input_data->digest.oid = NULL;
    return FAILURE;
}

static void free_digest(struct hashMLDSA_digest *digest) {
    if (digest->oid != NULL)
        free(digest->oid);

    if (digest->mdctx != NULL)
        EVP_MD_CTX_free(digest->mdctx);
}

/*
 * add or replace the digest information
 * as we don't know if this is called by the context or the input_data we can't create an MD CTX here
 */
static int replace_digest(struct hashMLDSA_digest *digest, const char *digest_name, size_t hash_len)
{
    const char* normalised_digest_name = NULL;
    size_t digest_hash_len;
    const EVP_MD *md = NULL;
    EVP_MD_CTX *mdctx = NULL;
    unsigned char *oid = NULL;
    size_t oid_len;
    int is_xof = 0;

    if (digest_name == NULL || strnlen(digest_name, 20) == 0) {
        set_error_message("NULL or Empty digest name");
        goto error;
    }

    md = EVP_get_digestbyname(digest_name);

    if (!md) {
        set_error_message("Unknown message digest: %s", digest_name);
        goto error;
    }

    /* Normalise the digest name */
    normalised_digest_name = EVP_MD_get0_name(md);

    if (digest->digest_name != NULL && strcmp(normalised_digest_name, digest->digest_name) == 0)
        return SUCCESS;


    /*
    * A choice here of Do we error or ignore for non XOF hashes where hash_len has been specified ?
    * Currently we chose to ignore the value
    */
    is_xof = EVP_MD_get_flags(md) & EVP_MD_FLAG_XOF;
    digest_hash_len = hash_len;
    if (!is_xof)
        digest_hash_len = 0; /* not xof so set digest length to 0 to get digest length */

    /* if no digest length calculate the digest length (get a default for xof if not specified) */
    if (digest_hash_len == 0) {
        digest_hash_len = EVP_MD_size(md);
        if (digest_hash_len == 0) {
            set_error_message("Failed to get digest size");
            goto error;
        }
    }

    /*
     * Now we verify if the hash length is sufficient as defined by FIPS 204 we can assume min_allowed
     * has already been set
     */
    if (digest_hash_len * 8 < digest->min_allowed_digest_hash_len) {
        set_error_message("Hash length %u is insufficient for ML-DSA %u strength", digest_hash_len * 8, digest->min_allowed_digest_hash_len);
        goto error;
    }

    if (get_md_oid(md, NULL, &oid_len) <= 0) {
        set_error_message("Failed to get determine oid");
        goto error;
    }

    oid = malloc(oid_len);
    if (get_md_oid(md, oid, &oid_len) <= 0) {
        free(oid);
        set_error_message("Failed to get determine oid");
        goto error;
    }

    /* Perform the actual replacement, we don't replace min_allowed_digest_hash_len as that never changes */
    free_digest(digest);
    digest->is_xof = is_xof;
    digest->md = md;
    digest->oid = oid;
    digest->oid_len = oid_len;
    digest->digest_name = normalised_digest_name;
    digest->digest_hash_len = digest_hash_len;

    return SUCCESS;

error:
    if (oid)
        free(oid);
    if (mdctx)
        EVP_MD_CTX_free(mdctx);

    return FAILURE;
}

/*
 * get the signature details for the context and assign a default digest
 */
static int get_signature_details(HASHMLDSA_CTX *ctx)
{
    int i = 0;

    if (!ctx->sig_alg_name)
        goto error;

    for (i = 0; i < NUM_SIG_ALGS; i++) {
        if (strcmp(ctx->sig_alg_name, sigalg_defs[i].sig_alg_name) == 0) {
            ctx->sig_strength = sigalg_defs[i].sig_strength;
            ctx->sig_len = sigalg_defs[i].sig_len;
            ctx->id = sigalg_defs[i].id;
            ctx->digest.min_allowed_digest_hash_len = ctx->sig_strength * 2; /* ensure min_allowed is set before replace is called for the 1st time */
            if (replace_digest(&ctx->digest, sigalg_defs[i].default_digest, 0) == FAILURE)
                goto error;
            return SUCCESS;
        }
    }

    set_error_message("Unknown signature algorithm %s, not an ML-DSA...\n", ctx->sig_alg_name);

error:
    return FAILURE;
}

static HASHMLDSA_CTX *HASHMLDSA_CTX_new_internal(OSSL_LIB_CTX *lib_ctx, const char *sig_alg_name, int test_mode)
{
    HASHMLDSA_CTX *ctx = NULL;
    int i = 0;

    if (lib_ctx == NULL) {
        // TODO: Do we want to load the global default here or expect the client app to do it
        // We can't replicate OpenSSL here as we can't get access to the thread local storage
        // which it can for stored library contexts so maybe better we don't do anything with NULL
        // lib_ctx = OSSL_LIB_CTX_get0_global_default();
        // if (lib_ctx == NULL) { // output an error }
        set_error_message("Library context cannot be NULL");
        return NULL;
    }

    if (OSSL_PROVIDER_available(lib_ctx, "default") == 0) {
       set_error_message("default provider not loaded into openssl library context");
       return NULL;
    }

    if ((ctx = OPENSSL_zalloc(sizeof(*ctx))) == NULL) {
        set_error_message("Failed to allocate memory for context");
        return NULL;
    }

    if (sig_alg_name == NULL || strlen(sig_alg_name) == 0) {
        set_error_message("signature algorithm is NULL or empty", sig_alg_name);
        goto error;
    }

    ctx->lib_ctx = lib_ctx;
    ctx->test_mode = test_mode;
    ctx->sig_alg_name = sig_alg_name;
    ctx->sig_alg = EVP_SIGNATURE_fetch(ctx->lib_ctx, sig_alg_name, NULL);
    if (ctx->sig_alg == NULL) {
        set_error_message("Failure in preparing %s signature algorithm: %s", sig_alg_name, ERR_error_string(ERR_get_error(), NULL));
        goto error;
    }

    /* Normalise the sig_alg_name based on OPENSSL naming */
    ctx->sig_alg_name = EVP_SIGNATURE_get0_name(ctx->sig_alg);

    /* Ensure digest info is clean before attempting to replace the digest, belt and braces as used zalloc from OpenSSL */
    ctx->digest.oid = NULL;
    ctx->digest.md = NULL;
    ctx->digest.mdctx = NULL;
    ctx->digest.oid_len = 0;

    if (!get_signature_details(ctx))
        goto error;

    ctx->message_encoding = 0;
    ctx->signatureParameters[0] = OSSL_PARAM_construct_int("message-encoding", &ctx->message_encoding);
    ctx->signatureParameters[1] = OSSL_PARAM_construct_int("deterministic", &ctx->test_mode);
    ctx->signatureParameters[2] = OSSL_PARAM_construct_end();

    return ctx;

error:
    if (ctx->sig_alg)
        EVP_SIGNATURE_free(ctx->sig_alg);

    OPENSSL_free(ctx);
    return NULL;

}

/**
 * HASHMLDSA_CTX_new - Allocate and initialize a new HASHMLDSA context.
 *
 * @desc: Allocates memory for a new HASHMLDSA context structure and initializes its fields.
 * The only supported algorithms are ML-DSA-44, ML-DSA-65 or ML-DSA-87. Alternative names such as
 * MLDSA44 are also allowed. It returns a pointer to the newly created context or NULL if memory allocation fails.
 * A default digest will be assigned to this context which will have the necessary number of bits to satisfy the
 * FIPS 204 requirements. See the documentation on this library for more details which lists the default digest
 * assigned based on the provided signature algorithm.
 *
 * @param lib_ctx An openssl library context. NULL is not valid. The library context must have the default provider loaded otherwise it's not valid.
 * @param sig_alg_name The required signature algorithm.
 *
 * @returns: A pointer to the newly created HASHMLDSA context on success, NULL on failure.
 */
HASHMLDSA_CTX *HASHMLDSA_CTX_new(OSSL_LIB_CTX *lib_ctx, const char *sig_alg_name)
{
    return HASHMLDSA_CTX_new_internal(lib_ctx, sig_alg_name, 0);
}

/**
 * HASHMLDSA_CTX_new_for_test - Allocate and initialize a new HASHMLDSA context for testing purposes
 *
 * @desc: Allocates memory for a new HASHMLDSA context structure and initializes its fields.
 * The only supported algorithms are ML-DSA-44, ML-DSA-65 or ML-DSA-87. Alternative names such as
 * MLDSA44 are also allowed. It returns a pointer to the newly created context or NULL if memory allocation fails.
 * This will force deterministic mode for signing and should only be used for testing purposes.
 * A default digest will be assigned to this context which will have the necessary number of bits to satisfy the
 * FIPS 204 requirements. See the documentation on this library for more details which lists the default digest
 * assigned based on the provided signature algorithm.
 *
 * @param lib_ctx An openssl library context. NULL is not valid. The library context must have the default provider loaded otherwise it's not valid.
 * @param sig_alg_name The required signature algorithm.
 *
 * @returns: A pointer to the newly created HASHMLDSA context on success, NULL on failure.
 */
HASHMLDSA_CTX *HASHMLDSA_CTX_new_for_test(OSSL_LIB_CTX *lib_ctx, const char* sig_alg_name)
{
    return HASHMLDSA_CTX_new_internal(lib_ctx, sig_alg_name, 1);
}

/**
 * HASHMLDSA_CTX_set_message_digest - set a message digest parameters
 *
 * @desc: Explicitly set the message digest name if the default value is not suitable.
 * You can specify a hash length if you specify a XOF digests such
 * as SHAKE128 or SHAKE256. For non XOF digests the length is ignored. Note that any previously created
 * HASHMLDSA strctures will not see this change, only when you create new HASHMLDSA structures using the
 * updated context will the HASHMLDSA structure get the updated digest information. All the alternative
 * names for digests supported by OpenSSL are supported here as well.
 *
 * You much chose a digest or in the case of an XOF digest, a length, that is note strong enough for the signature algorithm
 * specified when the context is created, this call will fail.
 *
 * If you chose an XOF digest such as SHAKE128 or SHAKE256, specifying a hash_len of 0 will result in a default hash length
 * being allocated. The default is defined by OpenSSL itself and not by this library.
 *
 * @param ctx A pointer to HASHMLDSA_CTX structure.
 * @param digest_name The name of the digest (e.g., "SHA-256"). Supports same canonical names as OpenSSL.
 * @param hash_len The byte length of the hash when specifying a XOF digest. it's ignored otherwise.
 *
 * @returns: 1 on success, 0 on failure if the digest (and optionally the length) is not strong enough for the signature algorithm selected
 */
int HASHMLDSA_CTX_set_message_digest(HASHMLDSA_CTX *ctx, const char* digest_name, size_t hash_len)
{
    if (!ctx)
        return FAILURE;

    return replace_digest(&ctx->digest, digest_name, hash_len);
}

/**
 * HASHMLDSA_CTX_free - Frees the memory allocated for HASHMLDSA_CTX structure.
 *
 * @desc: This function frees the memory allocated for the HASHMLDSA context either from a HASHMLDSA_CTX_new or
 * HASHMLDSA_CTX_new_for_test. Passing in NULL results in a NO-OP.
 *
 * @param ctx Pointer to HASHMLDSA context to be freed.
 */
void HASHMLDSA_CTX_free(HASHMLDSA_CTX *ctx)
{
    if (ctx == NULL)
        return;

    if (ctx->sig_alg != NULL)
        EVP_SIGNATURE_free(ctx->sig_alg);

    if (ctx->deflt != NULL)
        OSSL_PROVIDER_unload(ctx->deflt);

    free_digest(&ctx->digest);

    OPENSSL_free(ctx);
}

/**
 * HASHMLDSA_new - Allocate and initialize a new HASHMLDSA structure.
 *
 * @desc: This function allocates memory for a new HASHMLDSA structure and initializes
 * its fields to default values, the digest information is taken from the context and
 * stored in this structure.
 *
 * @param ctx Pointer to HASHMLDSA context.
 *
 * @returns: A pointer to the newly allocated HASHMLDSA structure on success, NULL on failure.
 */
HASHMLDSA *HASHMLDSA_new(const HASHMLDSA_CTX *ctx)
{
    HASHMLDSA *input_data;

    if (ctx == NULL) {
        set_error_message("Context is NULL");
        return NULL;
    }

    if ((input_data = OPENSSL_zalloc(sizeof(*input_data))) == NULL) {
        set_error_message("Failed to allocate memory");
        return NULL;
    }

    /* probably not required as we use zalloc, but better safe than sorry */
    input_data->context_string = NULL;
    input_data->context_string_len = 0;
    input_data->hashed_message = NULL;
    input_data->hashed_message_len = 0;
    input_data->message = NULL;
    input_data->message_len = 0;

    if (init_message_digest(ctx, input_data) == FAILURE)
        goto error;

    input_data->id = ctx->id;
    input_data->test_mode = ctx->test_mode;
    return input_data;

error:
    free_digest(&input_data->digest);
    OPENSSL_free(input_data);
    return NULL;
}

/**
 * HASHMLDSA_free - Frees the memory allocated for HASHMLDSA structure.
 *
 * @desc: This function frees the memory allocated for the HASHMLDSA structure.
 * Passing in NULL results in a NO-OP.
 *
 * @param input_data Pointer to HASHMLDSA structure to be freed.
 */
void HASHMLDSA_free(HASHMLDSA *input_data)
{
    if (input_data == NULL)
        return;

    free_digest(&input_data->digest);
    OPENSSL_free(input_data);
}

/**
 * HASHMLDSA_set_context_string - Set the context string to be used to create the hashed message.
 *
 * @desc: set's the context string and the length of this context string in the HASHMLDSA structure for
 * use when creating the hashed message during sign or the createPreHash operations.
 *
 * @param input_data A pointer to HASHMLDSA structure.
 * @param context_string_string A pointer to the byte array containing the context string.
 * @param context_string_string_len The length of the context string. Maximum length is 255.
 *
 * @returns: 1 on success, 0 on failure if context is too large or if input_data is NULL.
 */
int HASHMLDSA_set_context_string(HASHMLDSA *input_data, const unsigned char* context_string, size_t context_string_len)
{
    if (!input_data)
        goto error;

    if (context_string_len > 255) {
        set_error_message("context string cannot be larger than 255 characters");
        goto error;
    }

    if (context_string == NULL && context_string_len != 0) {
        set_error_message("No context string provided but length of context was specified");
        goto error;
    }

    input_data->context_string = context_string;
    input_data->context_string_len = context_string_len;

    return SUCCESS;

error:
    return FAILURE;
}

/**
 * /**
 * HASHMLDSA_set_message - Set the message to be used to create the hashed message.
 *
 * @desc: set's the message and the length of this message in the HASHMLDSA structure for
 * use when creating the hashed message during sign or the createPreHash operations.
 * Message and Hashed Message are mutually exclusive. Whichever was set last is used, so for
 * example if set_message was invoked after set_hashed_message then the values for set_message
 * are used.
 *
 * @param input_data A pointer to HASHMLDSA structure.
 * @param message A pointer to the message data.
 * @param message_len The length of the message.
 *
 * @returns: 1 on success, 0 on failure if input_data is NULL.
 */
int HASHMLDSA_set_message(HASHMLDSA *input_data, const unsigned char* message, size_t message_len)
{
    if (!input_data)
        return FAILURE;

    if (message_len == 0) {
        set_error_message("Message cannot be of length 0");
        return FAILURE;
    }

    input_data->message = message;
    input_data->message_len = message_len;
    input_data->hashed_message = NULL;
    input_data->hashed_message_len = 0;

    return SUCCESS;
}

/**
 * HASHMLDSA_set_hashed_message - set a previously hashed message
 *
 * @desc: Set a previously hashed message and it's length. This provides the ability to separate the sign or verify
 * into 2 distinct steps where the creation of the hash may have been done earlier or elsewhere (for example a different
 * machine).
 * Message and Hashed Message are mutually exclusive. Whichever was set last is used, so for
 * example if set_hashed_message was invoked after set_message then the values for set_hashed_message
 * are used.

 *
 * @param input_data A pointer to HASHMLDSA structure.
 * @param hashed_message A pointer to the hashed message.
 * @param hashed_message_len The length of the hashed message.
 *
 * @returns: 1 on success, 0 on failure if input_data is NULL.
 */
int HASHMLDSA_set_hashed_message(HASHMLDSA *input_data, const unsigned char* hashed_message, size_t hashed_message_len)
{

    if (!input_data)
        return FAILURE;

    if (hashed_message_len == 0) {
        set_error_message("Hashed Message cannot be of length 0");
        return FAILURE;
    }

    input_data->hashed_message = hashed_message;
    input_data->hashed_message_len = hashed_message_len;
    input_data->message = NULL;
    input_data->message_len = 0;

    return SUCCESS;
}

/**
 * HASHMLDSA_override_message_digest - override message digest parameters inherited from the context
 *
 * @desc: Explicitly override the message digest if the value inherited from the context is not suitable.
 * You can specify a hash length if you specify a XOF digests such
 * as SHAKE128 or SHAKE256. For non XOF digests the length is ignored. All the alternative names for digests
 * supported by OpenSSL are supported here as well.
 *
 * You much chose a digest or in the case of an XOF digest, a length, that is note strong enough for the signature algorithm
 * specified when the context is created, this call will fail.
 *
 * If you chose an XOF digest such as SHAKE128 or SHAKE256, specifying a hash_len of 0 will result in a default hash length
 * being allocated. The default is defined by OpenSSL itself and not by this library.
 *
 * @param input_data A pointer to HASHMLDSA structure.
 * @param digest_name The name of the digest (e.g., "SHA2-256").
 * @param hash_len The byte length of the hash when specifying a XOF digest. it's ignored otherwise.
 *
 * @returns: 1 on success, 0 on failure.
 */
int HASHMLDSA_override_message_digest(HASHMLDSA *input_data, const char* digest_name, size_t hash_len)
{

    if (!input_data)
        goto error;

    if (replace_digest(&input_data->digest, digest_name, hash_len) == FAILURE) {
        goto error;
    }

    /* if it's an XOF digest, create an MD CTX if not already created */
    if (input_data->digest.is_xof && input_data->digest.mdctx == NULL) {
        input_data->digest.mdctx = EVP_MD_CTX_new();
        if (input_data->digest.mdctx == NULL) {
            set_error_message("Failed to create context for XOF digest");
            goto error;
        }
    }

    return SUCCESS;

error:
    return FAILURE;

}

/**
 * HASHMLDSA_print_last_error - output the last error description
 *
 * @desc: Output the last error recorded. Note that it is never cleared and further errors will overwrite the previous one.
 *
 * @param fp file pointer to write to, eg stderr.
 */
int HASHMLDSA_print_last_error(FILE *fp)
{
    if (error_message == NULL)
        return SUCCESS;

    if (fp == NULL)
        return FAILURE;

    if (fprintf(fp, "Error: %s\n", error_message) < 0)
        return FAILURE;

    return SUCCESS;
}

/**
 * HASHMLDSA_clear_last_error - clear the last error.
 *
 * @desc: Clear last error recorded. If there was an error recorded then the memory is freed as well.
 *
 */
void HASHMLDSA_clear_last_error()
{
    if (error_message != NULL) {
        free(error_message);
        error_message = NULL;
    }
}


/**
 * HASHMLDSA_generate_hashed_message - pre hash a message for use with signing of verifying
 *
 * @desc: Pre hash the message ready for signing or verifying. This is useful when needing to do the sign or
 * verification separately.
 *
 * @param ctx Pointer to HASHMLDSA context.
 * @param input_data Pointer to HASHMLDSA structure containing algorithm-specific parameters.
 * @param hashed_message Pointer to buffer where the pre-hashed message will be stored.
 * @param hashed_message_len Pointer to size_t variable that will hold the length of the pre-hashed message.
 *
 * @returns: 1 on success, 0 on failure.
 */
int HASHMLDSA_generate_hashed_message(const HASHMLDSA_CTX *ctx,
                                      const HASHMLDSA *input_data,
                                      unsigned char *hashed_message,
                                      size_t *hashed_message_len)
{
    if (ctx == NULL)
        goto error;

    if (input_data == NULL) {
        set_error_message("No generate hash message input data provided");
        goto error;
    }

    if (ctx->id != input_data->id) {
        set_error_message("the input data of HASHMDLSA is not compatible with the context of HASHMLDSA_CTX");
        goto error;
    }

    return create_hashed_message(input_data, hashed_message, hashed_message_len);

error:
    return FAILURE;
}


/**
 * HASHMLDSA_sign - sign a message
 *
 * @desc: This will sign a message creating the hash first or using a previously hashed message using the
 * provided private key. You can use this call to determine the size of the signature without performing a sign by passing
 * NULL for all parameters except the context and a point to the signature length
 *
 * @param ctx Pointer to HASHMLDSA context.
 * @param priv_key The private key for signing.
 * @param input_data Pointer to HASHMLDSA_Params structure containing the message and digest information or hashed message.
 * @param signature The buffer to store the generated signature.
 * @param signature_len Pointer to the size of the signature buffer. If NULL is passed for the signature this will contain the length required for the signature.
 *
 * @returns: 1 on success, 0 on failure.
 */
int HASHMLDSA_sign(const HASHMLDSA_CTX *ctx,
                   EVP_PKEY *priv_key,
                   const HASHMLDSA *input_data,
                   unsigned char *signature,
                   size_t *signature_len)
{

    const struct hashMLDSA_digest *digest;
    const unsigned char *hashed_message = NULL;
    unsigned char* generated_hash_message = NULL;
    size_t hashed_message_len;

    /* length of the hash, calculated from a hashed message or determined from the context if the hashing is done as part of the sign */
    size_t hash_len;

    EVP_PKEY_CTX *sctx = NULL;
    size_t sig_len = 0;

    if (ctx == NULL) {
        set_error_message("No Context provided");
        goto error;
    }

    if (signature_len == NULL) {
        set_error_message("No Signature length provided");
        goto error;
    }

    if (signature == NULL) {
        *signature_len = ctx->sig_len;
        goto success;
    }

    if (input_data == NULL) {
        set_error_message("No Sign input data provided");
        goto error;
    }

    if (ctx->id != input_data->id) {
        set_error_message("the input data of HASHMDLSA is not compatible with the context of HASHMLDSA_CTX");
        return FAILURE;
    }

    if (priv_key == NULL) {
        set_error_message("No private key provided");
        goto error;
    }

    if (!EVP_PKEY_is_a(priv_key, ctx->sig_alg_name)) {
        set_error_message("Key is not of the expected type for signing as %s", ctx->sig_alg_name);
        goto error;
    }

    if ((input_data->hashed_message == NULL || input_data->hashed_message_len == 0) && (input_data->message == NULL || input_data->message_len == 0)) {
        set_error_message("No message or hash message provided");
        goto error;
    }

    if (*signature_len < ctx->sig_len) {
        set_error_message("Insufficient space provided for signature");
        *signature_len = ctx->sig_len;
        goto error;
    }

    sctx = EVP_PKEY_CTX_new_from_pkey(ctx->lib_ctx, priv_key, NULL);
    if (sctx == NULL) {
        set_error_message("Failure in preparing signature context from private key; %s", ERR_error_string(ERR_get_error(), NULL));
        goto error;
    }

    if (EVP_PKEY_sign_message_init(sctx, ctx->sig_alg, ctx->signatureParameters) != 1) {
        set_error_message("Failure in EVP_PKEY_sign_message_init: %s", ERR_error_string(ERR_get_error(), NULL));
        goto error;
    }

    digest = &input_data->digest;

    /* create the hashed message or use the one already provided */
    if (input_data->hashed_message == NULL || input_data->hashed_message_len == 0) {
            /* determine length of hashed_message */
            if (create_hashed_message(input_data, NULL, &hashed_message_len) <= 0)
                goto error;

            /* allocate for the raw message */
            generated_hash_message = OPENSSL_zalloc(hashed_message_len);
            if (!generated_hash_message) {
                set_error_message("Failed to allocate memory for hashed message");
                goto error;
            }

            /* generated the hashed_message */
            if (create_hashed_message(input_data, generated_hash_message, &hashed_message_len) <= 0)
                goto error;

            hashed_message = (const unsigned char*)generated_hash_message;
            hash_len = digest->digest_hash_len;
    } else {
        /* use getting of the hashLength to validate the hashed message */
        hash_len = get_hash_length(digest, input_data->hashed_message, input_data->hashed_message_len);
        if (hash_len == 0) {
            goto error;
        }
        hashed_message = input_data->hashed_message;
        hashed_message_len = input_data->hashed_message_len;
    }

    if (EVP_PKEY_sign(sctx, signature, signature_len, hashed_message, hashed_message_len) != 1) {
        set_error_message("Failure in EVP_PKEY_sign while signing: %s", ERR_error_string(ERR_get_error(), NULL));
        goto error;
    }

success:
    if (sctx)
        EVP_PKEY_CTX_free(sctx);

    if (generated_hash_message)
        OPENSSL_free(generated_hash_message);

    return SUCCESS;

error:
    if (sctx)
        EVP_PKEY_CTX_free(sctx);

    if (generated_hash_message)
        OPENSSL_free(generated_hash_message);

    return FAILURE;
}

/**
 * HASHMLDSA_verify - verify a message
 *
 * @desc: This will verify a message creating the hash first or using a previously hashed message using the
 * provided public key.
 *
 * @param ctx Pointer to HASHMLDSA context.
 * @param public_key The public key for verifying.
 * @param input_data Pointer to HASHMLDSA structure containing the message or hashed message.
 * @param signature The signature to verify.
 * @param signature_len The size of the signature buffer.
 *
 * @returns: 1 on success, 0 on failure.
 */
int HASHMLDSA_verify(const HASHMLDSA_CTX *ctx,
                     EVP_PKEY *public_key,
                     const HASHMLDSA *input_data,
                     const unsigned char *signature,
                     size_t signature_len)
{

    EVP_PKEY_CTX *vctx = NULL;
    const struct hashMLDSA_digest *digest;
    unsigned char *generated_hash_message = NULL;
    const unsigned char *hashed_message = NULL;
    size_t hashed_message_len = 0;
    size_t hash_len = 0;
    int verify = 0;

    if (ctx == NULL)
        goto error;

    if (input_data == NULL) {
        set_error_message("No Verify input data provided");
        goto error;
    }

    if (ctx->id != input_data-> id) {
        set_error_message("the input data of HASHMDLSA is not compatible with the context of HASHMLDSA_CTX");
        return FAILURE;
    }

    if (public_key == NULL) {
        set_error_message("Public key is NULL");
        goto error;
    }

    if (!EVP_PKEY_is_a(public_key, ctx->sig_alg_name)) {
        set_error_message("Key is not of the expected type for verifying as %s", ctx->sig_alg_name);
        goto error;
    }

    if (signature == NULL || signature_len == 0) {
        set_error_message("Signature is NULL or length was 0");
        goto error;
    }

    if ((input_data->hashed_message == NULL || input_data->hashed_message_len == 0) && (input_data->message == NULL || input_data->message_len == 0)) {
        set_error_message("No message or hash message");
        goto error;
    }

    digest = &input_data->digest;

    if (input_data->hashed_message == NULL || input_data->hashed_message_len == 0) {
        /* determine length of hashed_message */
        if (create_hashed_message(input_data, NULL, &hashed_message_len) <= 0)
            goto error;

        generated_hash_message = OPENSSL_zalloc(hashed_message_len);
        if (!generated_hash_message) {
            set_error_message("Failed to allocate memory for hashed_message");
            goto error;
        }

        /* generate the hashed_message */
        if (create_hashed_message(input_data, generated_hash_message, &hashed_message_len) <= 0)
            goto error;
        hashed_message = (const unsigned char*)generated_hash_message;
    } else {
        hash_len = get_hash_length(digest, input_data->hashed_message, input_data->hashed_message_len);
        if (hash_len == 0)
            goto error;

        hashed_message = input_data->hashed_message;
        hashed_message_len = input_data->hashed_message_len;
    }

    vctx = EVP_PKEY_CTX_new_from_pkey(ctx->lib_ctx, public_key, NULL);
    if (vctx == NULL) {
        set_error_message("Failure in preparing signature context: %s", ERR_error_string(ERR_get_error(), NULL));
        goto error;
    }

    if (EVP_PKEY_verify_message_init(vctx, ctx->sig_alg, ctx->signatureParameters) <= 0) {
        set_error_message("Did not message verify init: %s", ERR_error_string(ERR_get_error(), NULL));
        goto error;
    }

    verify = EVP_PKEY_verify(vctx, signature, signature_len, hashed_message, hashed_message_len);
    if (verify <= 0) {
        set_error_message("Did not verify signature: %s", ERR_error_string(ERR_get_error(), NULL));
        goto error;
    }

    if (generated_hash_message)
        OPENSSL_free(generated_hash_message);

    if (vctx)
        EVP_PKEY_CTX_free(vctx);
    return SUCCESS;

error:
    if (generated_hash_message)
        OPENSSL_free(generated_hash_message);

    if (vctx)
        EVP_PKEY_CTX_free(vctx);

    return FAILURE;
}

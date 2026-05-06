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
#include "openssl/ssl.h"
#include "openssl/err.h"
#include "hashMLDSA.h"
#include "testcases.h"
#include "testutils.h"

typedef struct {
    unsigned char* ctx;
    size_t ctx_len;
    unsigned char* message;
    size_t message_len;
    EVP_PKEY *private_key;
} Decoded_TestCase;

static OSSL_LIB_CTX *lib_ctx;


static int decode_testcase(TestCase test,
                           Decoded_TestCase *decoded_testcase)
{

    unsigned char *serialised_key = NULL;
    size_t serialised_key_len = 0;

    fprintf(stderr, "[INFO] decoding Testcase\n");
    /* (converting the JSON strings to byte arrays and determine their size) */
    if (test.encoded_message != NULL)
        hexString2byteArray(test.encoded_message, &(decoded_testcase->message), &(decoded_testcase->message_len));
    else
        decoded_testcase->message = NULL;

    if (test.encoded_context != NULL)
        hexString2byteArray(test.encoded_context, &(decoded_testcase->ctx), &(decoded_testcase->ctx_len));
    else
        decoded_testcase->ctx = NULL;

    decoded_testcase->private_key = NULL;
    if (test.encoded_private_key != NULL) {
        if (strcmp(test.encoded_private_key, "--GEN--") == 0) {
            fprintf(stderr, "[INFO] generating a key\n");
            if (test.key_type != NULL && generate_key_from_name(test.key_type, &(decoded_testcase->private_key)) != 0) {
                fprintf(stderr, "[ERROR] Failed to create new %s key\n", test.key_type);
                goto error;
            }
            fprintf(stderr, "[INFO] generated a key\n");
        } else {
            hexString2byteArray(test.encoded_private_key, &serialised_key, &serialised_key_len);
            decoded_testcase->private_key = EVP_PKEY_new_raw_private_key_ex(NULL, test.key_type, NULL, serialised_key, serialised_key_len);
            if (decoded_testcase->private_key == NULL) {
                fprintf(stderr, "[ERROR] Failed to create %s key from %d raw bytes\n", test.key_type, serialised_key_len);
                goto error;
            } else {
                fprintf(stderr, "[INFO] Key of type %s has security strength of %d\n", test.key_type, EVP_PKEY_get_security_bits(decoded_testcase->private_key));
            }

        }
    }

    if (serialised_key)
        free(serialised_key);
    return 0;

error:
    if (serialised_key)
        free(serialised_key);
    return -1;
}

typedef int (*create_context_and_data)(TestCase test, unsigned char det_mode, HASHMLDSA_CTX **hashmldsa_ctx, HASHMLDSA **hashmldsa_data, HASHMLDSA **hashmldsa_hash_data);

static int create_ctx_and_data(TestCase test,
                               unsigned char det_mode,
                               HASHMLDSA_CTX **hashmldsa_ctx,
                               HASHMLDSA **hashmldsa_data,
                               HASHMLDSA **hashmldsa_hash_data)
{
    fprintf(stderr, "[INFO] using default hash on CONTEXT\n");
    if (det_mode == 'd')
        *hashmldsa_ctx = HASHMLDSA_CTX_new_for_test(lib_ctx, test.key_type);  /* this will create a deterministic signature */
    else
        *hashmldsa_ctx = HASHMLDSA_CTX_new(lib_ctx, test.key_type);

    if (*hashmldsa_ctx == NULL) {
        fprintf(stderr, "[ERROR] Failed to create new %s context\n", test.key_type);
        HASHMLDSA_print_last_error(stderr);
        HASHMLDSA_clear_last_error();
        goto error;
    }

    if (hashmldsa_data != NULL) {
        *hashmldsa_data = HASHMLDSA_new(*hashmldsa_ctx);
        if (*hashmldsa_data == NULL) {
                HASHMLDSA_print_last_error(stderr);
                HASHMLDSA_clear_last_error();
                goto error;
        }
    }

    if (hashmldsa_hash_data != NULL) {
        *hashmldsa_hash_data = HASHMLDSA_new(*hashmldsa_ctx);
        if (*hashmldsa_hash_data == NULL) {
                HASHMLDSA_print_last_error(stderr);
                HASHMLDSA_clear_last_error();
                goto error;
        }
    }

    return 0;

error:
    if (*hashmldsa_ctx) {
        HASHMLDSA_CTX_free(*hashmldsa_ctx);
        *hashmldsa_ctx = NULL;
    }
    if (*hashmldsa_data) {
        HASHMLDSA_free(*hashmldsa_data);
        *hashmldsa_data = NULL;
    }
    if (*hashmldsa_hash_data) {
        HASHMLDSA_free(*hashmldsa_hash_data);
        *hashmldsa_hash_data = NULL;
    }
    return -1;
}

static int create_ctx_with_hash_and_data(TestCase test,
                                         unsigned char det_mode,
                                         HASHMLDSA_CTX **hashmldsa_ctx,
                                         HASHMLDSA **hashmldsa_data,
                                         HASHMLDSA **hashmldsa_hash_data)
{
    fprintf(stderr, "[INFO] Setting digest hash on CONTEXT to %s\n", test.hash_name);
    if (det_mode == 'd')
        *hashmldsa_ctx = HASHMLDSA_CTX_new_for_test(lib_ctx, test.key_type);  /* this will create a deterministic signature */
    else
        *hashmldsa_ctx = HASHMLDSA_CTX_new(lib_ctx, test.key_type);

    if (*hashmldsa_ctx == NULL) {
        fprintf(stderr, "[ERROR] Failed to create new %s context\n", test.key_type);
        HASHMLDSA_print_last_error(stderr);
        HASHMLDSA_clear_last_error();
        goto error;
    }

    /* here we set the hash on the context */
    if (!HASHMLDSA_CTX_set_message_digest(*hashmldsa_ctx, test.hash_name, test.hash_len)) {
        HASHMLDSA_print_last_error(stderr);
        HASHMLDSA_clear_last_error();
        goto error;
    }

    if (hashmldsa_data != NULL) {
        *hashmldsa_data = HASHMLDSA_new(*hashmldsa_ctx);
        if (*hashmldsa_data == NULL) {
                HASHMLDSA_print_last_error(stderr);
                HASHMLDSA_clear_last_error();
                goto error;
        }
    }

    if (hashmldsa_hash_data != NULL) {
        *hashmldsa_hash_data = HASHMLDSA_new(*hashmldsa_ctx);
        if (*hashmldsa_hash_data == NULL) {
                HASHMLDSA_print_last_error(stderr);
                HASHMLDSA_clear_last_error();
                goto error;
        }
    }

    return 0;

error:
    if (*hashmldsa_ctx) {
        HASHMLDSA_CTX_free(*hashmldsa_ctx);
        *hashmldsa_ctx = NULL;
    }
    if (*hashmldsa_data) {
        HASHMLDSA_free(*hashmldsa_data);
        *hashmldsa_data = NULL;
    }
    if (*hashmldsa_hash_data) {
        HASHMLDSA_free(*hashmldsa_hash_data);
        *hashmldsa_hash_data = NULL;
    }
    return -1;
}

static int create_ctx_and_data_with_hash(TestCase test,
                                         unsigned char det_mode,
                                         HASHMLDSA_CTX **hashmldsa_ctx,
                                         HASHMLDSA **hashmldsa_data,
                                         HASHMLDSA **hashmldsa_hash_data)
{
    fprintf(stderr, "[INFO] setting hash on DATA to %s\n", test.hash_name);

    if (det_mode == 'd')
        *hashmldsa_ctx = HASHMLDSA_CTX_new_for_test(lib_ctx, test.key_type);  /* this will create a deterministic signature */
    else
        *hashmldsa_ctx = HASHMLDSA_CTX_new(lib_ctx, test.key_type);

    if (*hashmldsa_ctx == NULL) {
        fprintf(stderr, "[ERROR] Failed to create new %s context\n", test.key_type);
        HASHMLDSA_print_last_error(stderr);
        HASHMLDSA_clear_last_error();
        goto error;
    }

    if (hashmldsa_data != NULL) {
        *hashmldsa_data = HASHMLDSA_new(*hashmldsa_ctx);
        if (*hashmldsa_data == NULL) {
                HASHMLDSA_print_last_error(stderr);
                HASHMLDSA_clear_last_error();
                goto error;
        }
    }

    if (hashmldsa_hash_data != NULL) {
        *hashmldsa_hash_data = HASHMLDSA_new(*hashmldsa_ctx);
        if (*hashmldsa_hash_data == NULL) {
                HASHMLDSA_print_last_error(stderr);
                HASHMLDSA_clear_last_error();
                goto error;
        }
    }

    /* here we set the hash on the data objects */
    if (hashmldsa_data != NULL) {
        if (!HASHMLDSA_override_message_digest(*hashmldsa_data, test.hash_name, test.hash_len)) {
            HASHMLDSA_print_last_error(stderr);
            HASHMLDSA_clear_last_error();
            goto error;
        }
    }

    if (hashmldsa_hash_data != NULL) {
        if (!HASHMLDSA_override_message_digest(*hashmldsa_hash_data, test.hash_name, test.hash_len)) {
            HASHMLDSA_print_last_error(stderr);
            HASHMLDSA_clear_last_error();
            goto error;
        }
    }

    return 0;

error:
    if (*hashmldsa_ctx) {
        HASHMLDSA_CTX_free(*hashmldsa_ctx);
        *hashmldsa_ctx = NULL;
    }
    if (*hashmldsa_data) {
        HASHMLDSA_free(*hashmldsa_data);
        *hashmldsa_data = NULL;
    }
    if (*hashmldsa_hash_data) {
        HASHMLDSA_free(*hashmldsa_hash_data);
        *hashmldsa_hash_data = NULL;
    }
    return -1;
}

static int create_hash(Decoded_TestCase decoded_testcase,
                       TestCase test,
                       HASHMLDSA_CTX *hashmldsa_ctx,
                       HASHMLDSA *hashmldsa_hash_data,
                       unsigned char** generated_hashed_message,
                       size_t *hashed_message_len)
{
    unsigned char *hashed_message = NULL;
    unsigned char *hashed_message_multi = NULL;
    size_t hashed_message_len_multi = 0;
    int rc = 0;

    unsigned int start_point = 0;
    unsigned int chunks = 4;
    unsigned int chunk_size;

    fprintf(stderr, "[INFO] creating pre hashed message\n");

    if (!HASHMLDSA_set_context_string(hashmldsa_hash_data, decoded_testcase.ctx, decoded_testcase.ctx_len)) {
        HASHMLDSA_print_last_error(stderr);
        rc = -1;
        goto exit;
    }

    HASHMLDSA_set_message(hashmldsa_hash_data, decoded_testcase.message, decoded_testcase.message_len);

    /* test both ways of generating a hash message and see if they compare */

    /* first create using the single shot */
    fprintf(stderr, "[INFO] creating pre hashed message via single shot\n");

    if (!HASHMLDSA_generate_hashed_message(hashmldsa_ctx, hashmldsa_hash_data, NULL, hashed_message_len)) {
        HASHMLDSA_print_last_error(stderr);
        rc = -1;
        goto exit;
    }

    hashed_message = OPENSSL_zalloc(*hashed_message_len);
    if (!HASHMLDSA_generate_hashed_message(hashmldsa_ctx, hashmldsa_hash_data, hashed_message, hashed_message_len)) {
        HASHMLDSA_print_last_error(stderr);
        rc = -1;
        goto exit;
    }


    /* now create using multishot */
    fprintf(stderr, "[INFO] creating pre hashed message via multi shot\n");
    if (!HASHMLDSA_generate_hashed_message_init(hashmldsa_ctx, hashmldsa_hash_data, &hashed_message_len_multi)) {
        HASHMLDSA_print_last_error(stderr);
        rc = -1;
        goto exit;
    }

    if (hashed_message_len_multi != *hashed_message_len) {
        fprintf(stderr, "[ERROR] hashed message lengths not equal %d != %d\n", hashed_message_len, hashed_message_len_multi);
        rc = -1;
        goto exit;
    }
    fprintf(stderr, "[INFO] hashed message lengths are equal to %d\n", hashed_message_len_multi);

    start_point = 0;
    chunks = 4;
    if (decoded_testcase.message_len < chunks) {
        chunks = decoded_testcase.message_len;
    }
    chunk_size = (decoded_testcase.message_len / chunks);

    for (int i = 1; i <= chunks; i++) {
        if (i == chunks) {
            chunk_size = decoded_testcase.message_len - start_point;
        }

        if (!HASHMLDSA_generate_hashed_message_update(hashmldsa_ctx, hashmldsa_hash_data, &decoded_testcase.message[start_point], chunk_size)) {
            HASHMLDSA_print_last_error(stderr);
            rc = -1;
            goto exit;
        }
        start_point += chunk_size;
    }

    hashed_message_multi = OPENSSL_zalloc(hashed_message_len_multi);
    if (!HASHMLDSA_generate_hashed_message_final(hashmldsa_ctx, hashmldsa_hash_data, hashed_message_multi, &hashed_message_len_multi)) {
        HASHMLDSA_print_last_error(stderr);
        rc = -1;
        goto exit;
    }

    /* Compare multi-shot to single-shot*/
    if (memcmp(hashed_message, hashed_message_multi, *hashed_message_len) != 0) {
        fprintf(stderr, "[ERROR] Hashed message does not match\n");
        rc = -1;
        goto exit;
    }

    fprintf(stderr, "[SUCCESS] Hashed messages from single and multi shot match\n");
    *generated_hashed_message = hashed_message;

exit:
    if (hashed_message_multi)
        OPENSSL_free(hashed_message_multi);

    HASHMLDSA_clear_last_error();

    return rc;
}

static int perform_sign(Decoded_TestCase decoded_testcase,
                        TestCase test, HASHMLDSA_CTX *hashmldsa_ctx,
                        HASHMLDSA *hashmldsa_data,
                        char det_mode,
                        char hash_mode,
                        unsigned char** signature_single,
                        unsigned char** signature_multi,
                        size_t *signature_len)
{
    size_t signature_len_multi = 0;

    unsigned int start_point = 0;
    unsigned int chunks = 4;
    unsigned int chunk_size;

    unsigned char *encoded_signature = NULL;

    int rc = 0;

    /* initially set to indicate no multishot signature needs verifying */
    *signature_multi = NULL;

    /*
     * Single Shot Signing: Perform the following steps
     * 1. determine signature size via the API
     *    TODO (we could have a separate API for this as well, but this matches the OpenSSL pattern to get the exact size
     *    whereas OpenSSL also has another api to get the biggest size possible, but we could determine the exact size in a simple API)
     * 2. Allocate memory to hold the signature
     * 3. Perform the Sign
     */
    fprintf(stderr, "[INFO] determining signature size for signing via single shot\n");

    if (!HASHMLDSA_sign(hashmldsa_ctx, NULL, NULL, NULL, signature_len)) {
        HASHMLDSA_print_last_error(stderr);
        rc = -1;
        goto exit;
    }
    fprintf(stderr, "[INFO] single shot signing with determined sig size of %d\n", *signature_len);
    *signature_single = OPENSSL_zalloc(*signature_len);

    if (!HASHMLDSA_sign(hashmldsa_ctx, decoded_testcase.private_key, hashmldsa_data, *signature_single, signature_len)) {
        HASHMLDSA_print_last_error(stderr);
        rc = -1;
        goto exit;
    }

    fprintf(stderr, "[SUCCESS] single shot signing successful\n", *signature_len);

    /*
     * Multi shot Signing, only perform this if not hash mode as multi shot never uses the hashed message in data
     * compare it to single shot only if in deterministic mode - otherwise we need to test via verify
     */
    if (hash_mode != 'h') {
        fprintf(stderr, "[INFO] determining signature size for signing via multi shot and comparing to single shot\n");
        if (!HASHMLDSA_sign_init(hashmldsa_ctx, decoded_testcase.private_key, hashmldsa_data, &signature_len_multi)) {
            HASHMLDSA_print_last_error(stderr);
            rc = -1;
            goto exit;
        }

        if (signature_len_multi != *signature_len) {
            fprintf(stderr, "[ERROR] 1 signature lengths not equal %d != %d\n", signature_len, signature_len_multi);
            rc = -1;
            goto exit;
        }
        fprintf(stderr, "[INFO] signature lengths from single and multishot are equal\n");

        if (decoded_testcase.message_len < chunks) {
            chunks = decoded_testcase.message_len;
        }
        chunk_size = (decoded_testcase.message_len / chunks);

        for (int i = 1; i <= chunks; i++) {
            if (i == chunks) {
                chunk_size = decoded_testcase.message_len - start_point;
            }
            if (!HASHMLDSA_sign_update(hashmldsa_ctx, hashmldsa_data, &decoded_testcase.message[start_point], chunk_size)) {
                HASHMLDSA_print_last_error(stderr);
                rc = -1;
                goto exit;
            }
            start_point += chunk_size;
        }

        *signature_multi = OPENSSL_zalloc(signature_len_multi);
        if (!HASHMLDSA_sign_final(hashmldsa_ctx, hashmldsa_data, *signature_multi, &signature_len_multi)) {
            HASHMLDSA_print_last_error(stderr);
            rc = -1;
            goto exit;
        }
    }

    /*
     * verify the signature against the testcase information if deterministic, if not check that we don't match
     * the signature to prove we aren't deterministic when not requested
     */
    encoded_signature = byteArray2hexString(*signature_single, *signature_len);

    if (det_mode == 'd') {
        /* deterministic mode */

        if (hash_mode != 'h') {
            /* not prehash mode so we will have created a multishot signature */
            fprintf(stderr, "Checking single shot and multi shot signatures match\n");
            if (memcmp(*signature_single, *signature_multi, *signature_len) == 0) {
                fprintf(stderr, "[SUCCESS] single shot and multi shot signatures match\n");
            } else {
                fprintf(stderr, "[ERROR] single shot and multi shot signatures do not match\n");
                rc = -1;
                goto exit;
            }

            /* can now clear out the multishot signature as we know it's good so don't need to run it through a verify check */
            OPENSSL_free(*signature_multi);
            *signature_multi = NULL;
        }

        fprintf(stderr, "[INFO] Checking resulting signature against test vector as it's deterministic....\n");
        /* TODO: Could also check the length as well */
        if (strncmp(encoded_signature, test.encoded_expected_signature, *signature_len) == 0) {
            fprintf(stdout, "[SUCCESS] Generated signature matches the test vector\n");
        } else {
            fprintf(stdout, "[FAILURE] Generated signature DOES NOT MATCH the test vector\n");
            rc = -1;
            goto exit;
        }
    } else {
        if (test.encoded_expected_signature != NULL) {
            if (strncmp(encoded_signature, test.encoded_expected_signature, *signature_len) == 0) {
                fprintf(stdout, "[FAILURE] Generated signature UNEXPECTEDLY matches the test vector\n");
                rc = -1;
                goto exit;
            } else {
                fprintf(stdout, "[SUCCESS] Generated signature DOES NOT MATCH the test vector as EXPECTED\n");
            }
        }
    }

    exit:
        if (encoded_signature)
            free(encoded_signature);
        return rc;
}

static int perform_verify(Decoded_TestCase decoded_testcase,
                          TestCase test,
                          HASHMLDSA_CTX *hashmldsa_ctx,
                          HASHMLDSA *hashmldsa_data,
                          EVP_PKEY *public_key,
                          char hash_mode,
                          unsigned char* signature,
                          size_t signature_len)
{
    int rc = 0;

    unsigned int start_point = 0;
    unsigned int chunks = 4;
    unsigned int chunk_size;

    /* Single shot verification */
    fprintf(stdout, "[INFO] starting single shot verification \n");
    if (HASHMLDSA_verify(hashmldsa_ctx, public_key, hashmldsa_data, signature, signature_len))
        fprintf(stdout, "[SUCCESS] verification successful\n");
    else {
        fprintf(stdout, "[FAILURE] did not verify against the public key\n");
        HASHMLDSA_print_last_error(stderr);
        rc = -1;
        goto exit;
    }

    /* check the hash mode, if we pre-hashed then no point doing a multi-shot verification as there is no context in the data */
    if (hash_mode != 'h') {
        /* Multishot verification */
        fprintf(stdout, "[INFO] starting multishot shot verification\n");
        if (!HASHMLDSA_verify_init(hashmldsa_ctx, public_key, hashmldsa_data)) {
            HASHMLDSA_print_last_error(stderr);
            rc = -1;
            goto exit;
        }

        /* perform the update to add message in fragments */
        start_point = 0;
        chunks = 4;
        if (decoded_testcase.message_len < chunks) {
            chunks = decoded_testcase.message_len;
        }
        chunk_size = (decoded_testcase.message_len / chunks);

        for (int i = 1; i <= chunks; i++) {
            if (i == chunks) {
                chunk_size = decoded_testcase.message_len - start_point;
            }
            if (!HASHMLDSA_verify_update(hashmldsa_ctx, hashmldsa_data, &decoded_testcase.message[start_point], chunk_size)) {
                HASHMLDSA_print_last_error(stderr);
                rc = -1;
                goto exit;
            }
            start_point += chunk_size;

        }

        if (!HASHMLDSA_verify_final(hashmldsa_ctx, hashmldsa_data, signature, signature_len)) {
            HASHMLDSA_print_last_error(stderr);
            rc = -1;
            goto exit;
        }
    }

exit:
    return rc;
}


static int test_sign_and_verify(Decoded_TestCase decoded_testcase,
                                TestCase test,
                                unsigned char det_mode,
                                unsigned char hash_mode,
                                create_context_and_data create_ctx_data)
{
    int rc = 0;

    unsigned char *signature = NULL;
    unsigned char *signature_multi = NULL;
    size_t signature_len = 0;

    unsigned char *hashed_message = NULL;
    size_t hashed_message_len = 0;

    HASHMLDSA_CTX *hashmldsa_ctx = NULL;
    HASHMLDSA *hashmldsa_hash_data = NULL;
    HASHMLDSA *hashmldsa_data = NULL;

    size_t pubkey_len;
    unsigned char *raw_pubkey = NULL;
    EVP_PKEY *public_key = NULL;

    if (create_ctx_data(test, det_mode, &hashmldsa_ctx, &hashmldsa_data, &hashmldsa_hash_data) != 0) {
        rc = -1;
        goto exit;
    };

    if (hash_mode == 'h') {
        /* The application creates the hashed message */

        if (create_hash(decoded_testcase, test, hashmldsa_ctx, hashmldsa_hash_data, &hashed_message, &hashed_message_len) == -1) {
            rc = -1;
            goto exit;
        }

        if (!HASHMLDSA_set_hashed_message(hashmldsa_data, hashed_message, hashed_message_len)) {
            HASHMLDSA_print_last_error(stderr);
            rc = -1;
            goto exit;
        }
    } else {
        /* The library creates the hashed_message */
        if (!HASHMLDSA_set_context_string(hashmldsa_data, decoded_testcase.ctx, decoded_testcase.ctx_len)) {
            HASHMLDSA_print_last_error(stderr);
            rc = -1;
            goto exit;
        }
        if (!HASHMLDSA_set_message(hashmldsa_data, decoded_testcase.message, decoded_testcase.message_len)) {
            HASHMLDSA_print_last_error(stderr);
            rc = -1;
            goto exit;
        }
    }

    if (perform_sign(decoded_testcase, test, hashmldsa_ctx, hashmldsa_data, det_mode, hash_mode, &signature, &signature_multi, &signature_len) == -1) {
        rc = -1;
        goto exit;
    }

    /* We will free the context, and use a fresh context for the verify */
    /* but importantly we will use the same HASHMLDSA instance to show it's not tied to the context it was created from */
    HASHMLDSA_CTX_free(hashmldsa_ctx);
    hashmldsa_ctx = NULL;

    /* To be clean lets get a fresh public key and create a new evp_pkey from it */
    EVP_PKEY_get_raw_public_key(decoded_testcase.private_key, NULL, &pubkey_len);
    raw_pubkey = malloc(pubkey_len);
    EVP_PKEY_get_raw_public_key(decoded_testcase.private_key, raw_pubkey, &pubkey_len);

    public_key = EVP_PKEY_new_raw_public_key_ex(NULL, test.key_type, NULL, raw_pubkey, pubkey_len);

    /* create a new context, leaving the data has is */
    if (create_ctx_data(test, det_mode, &hashmldsa_ctx, NULL, NULL) != 0) {
        rc = -1;
        goto exit;
    };

    /*
     * use verify call to verify the signature, we will reuse the same input_data object
     * which will either have the message or the hashed_message, but the digest will already be set as required
     */
    fprintf(stderr, "[INFO] verifying the single shot signature....\n");
    if (perform_verify(decoded_testcase, test, hashmldsa_ctx, hashmldsa_data, public_key, hash_mode, signature, signature_len) == -1) {
        rc = -1;
        goto exit;
    }

    if (signature_multi) {
        fprintf(stderr, "[INFO] verifying the multi shot signature....\n");
        if (perform_verify(decoded_testcase, test, hashmldsa_ctx, hashmldsa_data, public_key, hash_mode, signature_multi, signature_len) == -1) {
            rc = -1;
            goto exit;
        }
    }

exit:
    if (hashmldsa_ctx)
        HASHMLDSA_CTX_free(hashmldsa_ctx);

    if (hashmldsa_data)
        HASHMLDSA_free(hashmldsa_data);

    if (hashmldsa_hash_data)
        HASHMLDSA_free(hashmldsa_hash_data);

    if (public_key)
        EVP_PKEY_free(public_key);

    if (signature)
        OPENSSL_free(signature);

    if (signature_multi)
        OPENSSL_free(signature_multi);

    if (raw_pubkey)
        free(raw_pubkey);

    if (hashed_message)
        free(hashed_message);

    HASHMLDSA_clear_last_error();

    return rc;
}

static void run_test(int test_no,
                     Decoded_TestCase decoded_testcase,
                     TestCase test,
                     char det_mode,
                     char hash_mode,
                     int *total_passed,
                     int *total_failed,
                     int *test_failed,
                     create_context_and_data create_ctx_data)
{
    int rc = 0;
    unsigned char* det_mode_str = NULL;
    unsigned char* hash_mode_str = NULL;

    det_mode_str = det_mode == 'd' ? "Deterministic" : "Non-Deterministic";
    hash_mode_str = hash_mode == 'r' ? "NO " : "";

    fprintf(stdout, "Test %d: %s Test with %spre-hashed message\n", test_no, det_mode_str, hash_mode_str);
    rc = test_sign_and_verify(decoded_testcase, test, det_mode, hash_mode, create_ctx_data);
    if (test.failure_expected == NULL) {
        if (rc == 0) {
            fprintf(stdout, "Test %d: [PASSED] %s Test with %spre-hashed message\n", test_no, det_mode_str, hash_mode_str);
            (*total_passed)++;
        } else {
            fprintf(stdout, "Test %d: [FAILED] %s Test with %spre-hashed message\n", test_no, det_mode_str, hash_mode_str);
            (*total_failed)++;
            (*test_failed)++;
        }
    } else {
        if (rc != 0) {
            fprintf(stdout, "Test %d: [PASSED] Expected Failure \"%s\", %s Test with %spre-hashed message\n", test_no, test.failure_expected, det_mode_str, hash_mode_str);
            (*total_passed)++;
        } else {
            fprintf(stdout, "Test %d: [FAILED] %s Test with %spre-hashed message, it did not fail when expected\n", test_no, det_mode_str, hash_mode_str);
            (*total_failed)++;
            (*test_failed)++;
        }
    }
}


int main(int argc, char *argv[])
{
    int total_passed = 0;  // MEND seems to think this might contain sensitive information. Not a great parser
    int total_failed = 0;
    int test_failed = 0;
    int numTestcases = 0;
    int i, j;

    create_context_and_data create_ctx_with_data;
    Decoded_TestCase decoded_testcase;
    TestCase test;

    lib_ctx = OSSL_LIB_CTX_get0_global_default();

    numTestcases = sizeof(testcases) / sizeof(testcases[0]);
    printf("Number of testcases: %d\n", numTestcases);
    for (i = 0; i < numTestcases; i++) {
        test = testcases[i];
        if (test.failure_expected == NULL)
            fprintf(stdout, "\n----> Test %d: Started. Expected to Succeed\n", i);
        else
            fprintf(stdout, "\n----> Test %d: Started. Expected to fail with: %s\n", i, testcases[i].failure_expected);

        test_failed = 0;

        if (decode_testcase(test, &decoded_testcase) == 0) {
            for (j = 0; j <= 1; j++) {

                if (test.hash_name && strcmp(test.hash_name, "--DEF--") == 0) {
                    create_ctx_with_data = create_ctx_and_data;
                    j = 2; /* Ensure we only run the loop once */
                } else
                    create_ctx_with_data = (j == 0) ? create_ctx_with_hash_and_data : create_ctx_and_data_with_hash;

                /*
                * Deterministic Test, don't prehash message first
                * can only do a deterministic test if there is an expected signature
                */
                if (testcases[i].encoded_expected_signature != NULL && strlen(testcases[i].encoded_expected_signature)) {
                    run_test(i, decoded_testcase, test, 'd', 'r', &total_passed, &total_failed, &test_failed, create_ctx_with_data);
                }

                /*
                * Non-Deterministic Test, don't prehash message first
                */
                run_test(i, decoded_testcase, test, 'n', 'r', &total_passed, &total_failed, &test_failed, create_ctx_with_data);

                /*
                * Non Deterministic Test, prehash message first
                */
                run_test(i, decoded_testcase, test, 'n', 'h', &total_passed, &total_failed, &test_failed, create_ctx_with_data);
            }
        } else {
            fprintf(stdout, "Test %d: [FAILED] Unable to decode the testcase\n", i);
            total_failed++;
            test_failed++;
        }

        /* free up the decoded_testcase stuff ready for next iteration */
        if (decoded_testcase.private_key)
            EVP_PKEY_free(decoded_testcase.private_key);
        if (decoded_testcase.message)
            free(decoded_testcase.message);
        if (decoded_testcase.ctx)
            free(decoded_testcase.ctx);

        fprintf(stdout, "<---- Test %d: Ended  FAILURES: %d\n", i, test_failed);
    }

    fprintf(stdout, "\nResults: test cases: %d, Passed: %d, Failed: %d\n", numTestcases, total_passed, total_failed);
    if (total_failed != 0)
        return 1;
    else
        return 0;
}
